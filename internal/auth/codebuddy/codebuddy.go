package codebuddy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	BaseURL       = "https://copilot.tencent.com"
	DefaultDomain = "www.codebuddy.cn"
	UserAgent     = "CLI/2.63.2 CodeBuddy/2.63.2"

	statePath   = "/v2/plugin/auth/state"
	tokenPath   = "/v2/plugin/auth/token"
	refreshPath = "/v2/plugin/auth/token/refresh"

	pollInterval     = 5 * time.Second
	maxPollDuration  = 5 * time.Minute
	codeLoginPending = 11217
	codeSuccess      = 0
)

type Auth struct {
	httpClient *http.Client
	baseURL    string
}

type AuthState struct {
	State   string
	AuthURL string
}

func NewCodeBuddyAuth(cfg *config.Config) *Auth {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	return &Auth{httpClient: client, baseURL: BaseURL}
}

func (a *Auth) FetchAuthState(ctx context.Context) (*AuthState, error) {
	stateURL := a.baseURL + statePath + "?platform=CLI"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stateURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("codebuddy: create auth state request: %w", err)
	}
	requestID := uuid.NewString()
	setCommonHeaders(req, false, "")
	req.Header.Set("X-Request-ID", requestID)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("codebuddy: auth state request failed: %w", err)
	}
	defer closeBody("codebuddy auth state", resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("codebuddy: read auth state response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codebuddy: auth state status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data *struct {
			State   string `json:"state"`
			AuthURL string `json:"authUrl"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("codebuddy: parse auth state response: %w", err)
	}
	if out.Code != codeSuccess {
		return nil, fmt.Errorf("codebuddy: auth state code %d: %s", out.Code, out.Msg)
	}
	if out.Data == nil || out.Data.State == "" || out.Data.AuthURL == "" {
		return nil, fmt.Errorf("codebuddy: auth state response missing state or authUrl")
	}
	return &AuthState{State: out.Data.State, AuthURL: out.Data.AuthURL}, nil
}

func (a *Auth) WaitForToken(ctx context.Context, state string) (*TokenStorage, error) {
	deadline := time.NewTimer(maxPollDuration)
	defer deadline.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		storage, pending, err := a.pollToken(ctx, state)
		if err != nil {
			return nil, err
		}
		if !pending {
			return storage, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("codebuddy: authentication timed out")
		case <-ticker.C:
		}
	}
}

func (a *Auth) pollToken(ctx context.Context, state string) (*TokenStorage, bool, error) {
	pollURL := a.baseURL + tokenPath + "?" + url.Values{"state": {state}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("codebuddy: create token poll request: %w", err)
	}
	setCommonHeaders(req, false, "")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("codebuddy: token poll failed: %w", err)
	}
	defer closeBody("codebuddy token poll", resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("codebuddy: read token poll response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("codebuddy: token poll status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data *struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresIn    int64  `json:"expiresIn"`
			TokenType    string `json:"tokenType"`
			Domain       string `json:"domain"`
			UserID       string `json:"userId"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &out); err != nil {
		return nil, false, fmt.Errorf("codebuddy: parse token poll response: %w", err)
	}
	if out.Code == codeLoginPending {
		return nil, true, nil
	}
	if out.Code != codeSuccess {
		return nil, false, fmt.Errorf("codebuddy: token poll code %d: %s", out.Code, out.Msg)
	}
	if out.Data == nil || out.Data.AccessToken == "" {
		return nil, false, fmt.Errorf("codebuddy: token poll missing access token")
	}
	return tokenStorageFromData(out.Data.AccessToken, out.Data.RefreshToken, out.Data.TokenType, out.Data.Domain, out.Data.UserID, out.Data.ExpiresIn), false, nil
}

func (a *Auth) RefreshToken(ctx context.Context, accessToken, refreshToken, userID, domain string) (*TokenStorage, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("codebuddy: missing refresh token")
	}
	payload, _ := json.Marshal(map[string]string{"refreshToken": refreshToken})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+refreshPath, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("codebuddy: create refresh request: %w", err)
	}
	setCommonHeaders(req, true, accessToken)
	if userID != "" {
		req.Header.Set("X-User-Id", userID)
	}
	if domain == "" {
		domain = DefaultDomain
	}
	req.Header.Set("X-Domain", domain)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("codebuddy: refresh request failed: %w", err)
	}
	defer closeBody("codebuddy refresh", resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("codebuddy: read refresh response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("codebuddy: refresh status %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data *struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresIn    int64  `json:"expiresIn"`
			TokenType    string `json:"tokenType"`
			Domain       string `json:"domain"`
			UserID       string `json:"userId"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("codebuddy: parse refresh response: %w", err)
	}
	if out.Code != codeSuccess {
		return nil, fmt.Errorf("codebuddy: refresh code %d: %s", out.Code, out.Msg)
	}
	if out.Data == nil || out.Data.AccessToken == "" {
		return nil, fmt.Errorf("codebuddy: refresh missing access token")
	}
	return tokenStorageFromData(out.Data.AccessToken, out.Data.RefreshToken, out.Data.TokenType, out.Data.Domain, out.Data.UserID, out.Data.ExpiresIn), nil
}

func tokenStorageFromData(access, refresh, typ, domain, userID string, expiresIn int64) *TokenStorage {
	if domain == "" {
		domain = DefaultDomain
	}
	storage := &TokenStorage{Type: "codebuddy", AccessToken: access, RefreshToken: refresh, TokenType: typ, Domain: domain, UserID: userID, ExpiresIn: expiresIn}
	if expiresIn > 0 {
		storage.Expired = time.Now().Add(time.Duration(expiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	return storage
}

func setCommonHeaders(req *http.Request, authorized bool, token string) {
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-Product", "SaaS")
	if authorized && token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-No-Authorization", "true")
	}
	req.Header.Set("X-No-Enterprise-Id", "true")
	req.Header.Set("X-No-Department-Info", "true")
	req.Header.Set("X-Domain", "copilot.tencent.com")
}

func DecodeJWTSubject(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(data, &claims) != nil {
		return ""
	}
	for _, key := range []string{"sub", "user_id", "uid"} {
		if v, ok := claims[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func closeBody(prefix string, body io.Closer) {
	if err := body.Close(); err != nil {
		log.Errorf("%s: close body error: %v", prefix, err)
	}
}
