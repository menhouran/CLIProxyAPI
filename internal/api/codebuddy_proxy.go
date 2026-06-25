package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codebuddy"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// setupCodeBuddyRoutes registers the CodeBuddy reverse proxy (/copilot/*)
// and browser login endpoint (/auth/codebuddy).
func (s *Server) setupCodeBuddyRoutes() {
	target, _ := url.Parse(codebuddy.BaseURL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/copilot")
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
			req.URL.RawPath = ""
		},
		Transport: &http.Transport{
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
		ModifyResponse: func(resp *http.Response) error {
			s.interceptCodeBuddyTokenResponse(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Errorf("codebuddy proxy: %v", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	s.engine.Any("/copilot/*path", func(c *gin.Context) {
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	s.engine.GET("/auth/codebuddy", s.handleCodeBuddyAuthLogin)
	s.engine.GET("/auth/codebuddy/status", s.handleCodeBuddyAuthStatus)
}

// pendingCodeBuddyLogins tracks in-progress browser login flows keyed by state.
var pendingCodeBuddyLogins = make(map[string]*pendingLogin)

type pendingLogin struct {
	authURL string
	done    bool
	err     string
	userID  string
	file    string
}

// handleCodeBuddyAuthLogin starts the OAuth polling flow (reuses codebuddy.NewCodeBuddyAuth)
// and returns an HTML page that polls for completion.
func (s *Server) handleCodeBuddyAuthLogin(c *gin.Context) {
	authSvc := codebuddy.NewCodeBuddyAuth(s.cfg)

	authState, err := authSvc.FetchAuthState(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	pendingCodeBuddyLogins[authState.State] = &pendingLogin{authURL: authState.AuthURL}

	go func() {
		storage, pollErr := authSvc.PollForToken(context.Background(), authState.State)

		ls := pendingCodeBuddyLogins[authState.State]
		if ls == nil {
			return
		}

		if pollErr != nil {
			ls.done = true
			ls.err = pollErr.Error()
			return
		}

		authID := fmt.Sprintf("codebuddy-%s.json", storage.UserID)
		authFilePath := fmt.Sprintf("%s/%s", s.cfg.AuthDir, authID)
		if errSave := storage.SaveTokenToFile(authFilePath); errSave != nil {
			ls.done = true
			ls.err = errSave.Error()
			return
		}

		ls.done = true
		ls.userID = storage.UserID
		ls.file = authID
		log.Infof("codebuddy auth: saved %s", authFilePath)
	}()

	if browser.IsAvailable() {
		_ = browser.OpenURL(authState.AuthURL)
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, codeBuddyLoginHTML, authState.State, authState.AuthURL)
}

// handleCodeBuddyAuthStatus is polled by the login page JS.
func (s *Server) handleCodeBuddyAuthStatus(c *gin.Context) {
	state := c.Query("state")
	ls := pendingCodeBuddyLogins[state]
	if ls == nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "unknown state"})
		return
	}
	if !ls.done {
		c.JSON(http.StatusOK, gin.H{"status": "pending"})
		return
	}
	if ls.err != "" {
		c.JSON(http.StatusOK, gin.H{"status": "error", "error": ls.err})
		delete(pendingCodeBuddyLogins, state)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "user_id": ls.userID, "file": ls.file})
	delete(pendingCodeBuddyLogins, state)
}

// interceptCodeBuddyTokenResponse watches token refresh/poll responses passing
// through the proxy and saves auth files automatically.
func (s *Server) interceptCodeBuddyTokenResponse(resp *http.Response) {
	if resp == nil || resp.Request == nil || resp.StatusCode != http.StatusOK {
		return
	}
	path := resp.Request.URL.Path
	if !strings.Contains(path, "/auth/token") {
		return
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	if gjson.GetBytes(body, "code").Int() != 0 {
		return
	}
	accessToken := gjson.GetBytes(body, "data.accessToken").String()
	if accessToken == "" {
		return
	}

	userID := gjson.GetBytes(body, "data.userId").String()
	if userID == "" {
		authSvc := codebuddy.NewCodeBuddyAuth(s.cfg)
		userID, _ = authSvc.DecodeUserID(accessToken)
	}
	if userID == "" {
		return
	}

	domain := gjson.GetBytes(body, "data.domain").String()
	if domain == "" {
		domain = codebuddy.DefaultDomain
	}

	storage := &codebuddy.CodeBuddyTokenStorage{
		AccessToken:  accessToken,
		RefreshToken: gjson.GetBytes(body, "data.refreshToken").String(),
		ExpiresIn:    gjson.GetBytes(body, "data.expiresIn").Int(),
		TokenType:    gjson.GetBytes(body, "data.tokenType").String(),
		Domain:       domain,
		UserID:       userID,
		Type:         "codebuddy",
	}

	authID := fmt.Sprintf("codebuddy-%s.json", userID)
	authFilePath := fmt.Sprintf("%s/%s", s.cfg.AuthDir, authID)
	if errSave := storage.SaveTokenToFile(authFilePath); errSave != nil {
		log.Errorf("codebuddy proxy: save intercepted token: %v", errSave)
		return
	}
	log.Infof("codebuddy proxy: intercepted token for %s -> %s", userID, authID)
}

const codeBuddyLoginHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CodeBuddy Login</title>
<style>body{font-family:sans-serif;max-width:600px;margin:80px auto;text-align:center}
.s{margin:20px;padding:15px;border-radius:8px;background:#f0f0f0}
.ok{background:#d4edda;color:#155724}.err{background:#f8d7da;color:#721c24}
a{color:#007bff}</style>
<script>
var st=%q,iv=setInterval(function(){
fetch('/auth/codebuddy/status?state='+st).then(r=>r.json()).then(d=>{
var e=document.getElementById('s');
if(d.status==='success'){e.className='s ok';e.innerHTML='Login OK: '+d.user_id+'<br>'+d.file;clearInterval(iv)}
else if(d.status==='error'){e.className='s err';e.innerHTML='Failed: '+d.error;clearInterval(iv)}
}).catch(()=>{})},2000);
</script></head><body>
<h1>CodeBuddy Login</h1>
<p>Complete auth in the opened browser window.</p>
<p><a href="%s" target="_blank">Click here if browser didn't open</a></p>
<div id="s" class="s">Waiting for authorization...</div>
</body></html>`
