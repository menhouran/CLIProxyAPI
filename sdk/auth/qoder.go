package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	qoderauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type QoderAuthenticator struct{}

func NewQoderAuthenticator() Authenticator { return &QoderAuthenticator{} }

func (QoderAuthenticator) Provider() string { return "qoder" }

func (QoderAuthenticator) RefreshLead() *time.Duration { return nil }

func (a QoderAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cliproxy auth: configuration is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	authSvc := qoderauth.NewQoderAuth()
	flow, err := authSvc.StartDeviceFlow(ctx)
	if err != nil {
		return nil, err
	}
	fmt.Printf("\nTo authenticate Qoder, please visit:\n%s\n\n", flow.VerificationURIComplete)
	if !opts.NoBrowser && browser.IsAvailable() {
		if errOpen := browser.OpenURL(flow.VerificationURIComplete); errOpen != nil {
			log.Warnf("Failed to open browser automatically: %v", errOpen)
		} else {
			fmt.Println("Browser opened automatically.")
		}
	}
	if opts.Prompt == nil {
		return nil, fmt.Errorf("qoder: paste a Qoder token/auth JSON through an interactive prompt or create a qoder auth JSON in the configured auth directory")
	}
	input, err := opts.Prompt("Paste Qoder token or auth JSON: ")
	if err != nil {
		return nil, err
	}
	storage, err := parseQoderAuthInput(input, flow.MachineID)
	if err != nil {
		return nil, err
	}
	fileName := qoderauth.CredentialFileName(storage.Email, storage.UserID)
	metadata := map[string]any{
		"type":       "qoder",
		"token":      storage.BearerToken(),
		"user_id":    storage.UserID,
		"email":      storage.Email,
		"name":       storage.Name,
		"machine_id": storage.MachineID,
		"timestamp":  time.Now().UnixMilli(),
	}
	if storage.AccessToken != "" {
		metadata["access_token"] = storage.AccessToken
	}
	if storage.RefreshToken != "" {
		metadata["refresh_token"] = storage.RefreshToken
	}
	if storage.ExpireTime > 0 {
		metadata["expire_time"] = storage.ExpireTime
	}
	return &coreauth.Auth{ID: fileName, Provider: a.Provider(), FileName: fileName, Label: qoderLabel(storage), Storage: storage, Metadata: metadata}, nil
}

func parseQoderAuthInput(input, defaultMachineID string) (*qoderauth.TokenStorage, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("qoder: empty token input")
	}
	var storage qoderauth.TokenStorage
	if strings.HasPrefix(input, "{") {
		if err := json.Unmarshal([]byte(input), &storage); err != nil {
			return nil, fmt.Errorf("qoder: parse auth JSON: %w", err)
		}
	} else {
		storage.Token = input
	}
	if storage.BearerToken() == "" {
		return nil, fmt.Errorf("qoder: auth input missing token/access_token")
	}
	if storage.MachineID == "" {
		storage.MachineID = defaultMachineID
	}
	storage.Type = "qoder"
	return &storage, nil
}

func qoderLabel(storage *qoderauth.TokenStorage) string {
	if storage == nil {
		return "Qoder User"
	}
	for _, value := range []string{storage.Email, storage.Name, storage.UserID} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return "Qoder User"
}
