package auth

import (
	"context"
	"fmt"
	"time"

	codebuddyauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codebuddy"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var codeBuddyRefreshLead = 5 * time.Minute

type CodeBuddyAuthenticator struct{}

func NewCodeBuddyAuthenticator() Authenticator { return &CodeBuddyAuthenticator{} }

func (CodeBuddyAuthenticator) Provider() string { return "codebuddy" }

func (CodeBuddyAuthenticator) RefreshLead() *time.Duration { return &codeBuddyRefreshLead }

func (a CodeBuddyAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	authSvc := codebuddyauth.NewCodeBuddyAuth(cfg)
	state, err := authSvc.FetchAuthState(ctx)
	if err != nil {
		return nil, err
	}
	fmt.Printf("\nTo authenticate CodeBuddy, please visit:\n%s\n\n", state.AuthURL)
	if !opts.NoBrowser && browser.IsAvailable() {
		if errOpen := browser.OpenURL(state.AuthURL); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
		} else {
			fmt.Println("Browser opened automatically.")
		}
	}
	fmt.Println("Waiting for CodeBuddy authorization...")
	storage, err := authSvc.WaitForToken(ctx, state.State)
	if err != nil {
		return nil, err
	}
	if storage.UserID == "" {
		storage.UserID = codebuddyauth.DecodeJWTSubject(storage.AccessToken)
	}
	fileName := codebuddyauth.CredentialFileName(storage.UserID)
	metadata := map[string]any{
		"type":          "codebuddy",
		"access_token":  storage.AccessToken,
		"refresh_token": storage.RefreshToken,
		"expires_in":    storage.ExpiresIn,
		"token_type":    storage.TokenType,
		"domain":        storage.Domain,
		"user_id":       storage.UserID,
		"timestamp":     time.Now().UnixMilli(),
	}
	if storage.Expired != "" {
		metadata["expired"] = storage.Expired
	}
	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    "CodeBuddy User",
		Storage:  storage,
		Metadata: metadata,
	}, nil
}
