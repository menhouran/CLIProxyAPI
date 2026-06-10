package executor

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	qoderauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// QoderExecutor routes Qoder auth records through the OpenAI-compatible executor
// while preserving Qoder-specific authentication headers. The Qoder native chat
// API still requires signed COSY envelopes; this executor supports saved bearer
// credentials and custom base_url overrides for deployments that expose the
// current Qoder-compatible OpenAI surface.
type QoderExecutor struct {
	*OpenAICompatExecutor
	cfg *config.Config
}

func NewQoderExecutor(cfg *config.Config) *QoderExecutor {
	return &QoderExecutor{OpenAICompatExecutor: NewOpenAICompatExecutor("qoder", cfg), cfg: cfg}
}

func (e *QoderExecutor) Identifier() string { return "qoder" }

func (e *QoderExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	token := qoderBearerToken(auth)
	if token == "" {
		return fmt.Errorf("qoder: missing token/access_token")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "qodercli/0.2.16 CLIProxyAPI")
	req.Header.Set("Cosy-Version", qoderauth.QoderIDEVersion)
	req.Header.Set("Cosy-Clienttype", qoderauth.QoderClientType)
	req.Header.Set("Cosy-Data-Policy", qoderauth.QoderDataPolicy)
	req.Header.Set("Login-Version", qoderauth.QoderLoginVersion)
	return nil
}

func (e *QoderExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	ensureQoderBaseURL(auth)
	return e.OpenAICompatExecutor.Execute(ctx, auth, req, opts)
}

func (e *QoderExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	ensureQoderBaseURL(auth)
	return e.OpenAICompatExecutor.ExecuteStream(ctx, auth, req, opts)
}

func (e *QoderExecutor) Refresh(_ context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	return auth, nil
}

func (e *QoderExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	ensureQoderBaseURL(auth)
	return e.OpenAICompatExecutor.CountTokens(ctx, auth, req, opts)
}

func ensureQoderBaseURL(auth *cliproxyauth.Auth) {
	if auth == nil {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = map[string]string{}
	}
	if strings.TrimSpace(auth.Attributes["base_url"]) == "" {
		auth.Attributes["base_url"] = qoderauth.QoderChatBase + "/v1"
	}
	if strings.TrimSpace(auth.Attributes["api_key"]) == "" {
		auth.Attributes["api_key"] = qoderBearerToken(auth)
	}
}

func qoderBearerToken(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	for _, key := range []string{"token", "access_token"} {
		if value := metaStringValue(auth.Metadata, key); value != "" {
			return value
		}
	}
	if auth.Attributes != nil {
		for _, key := range []string{"token", "api_key", "access_token"} {
			if value := strings.TrimSpace(auth.Attributes[key]); value != "" {
				return value
			}
		}
	}
	if storage, ok := auth.Storage.(*qoderauth.TokenStorage); ok {
		return storage.BearerToken()
	}
	return ""
}
