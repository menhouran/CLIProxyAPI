package qoder

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

const (
	QoderOpenAPIBase          = "https://openapi.qoder.sh"
	QoderCenterBase           = "https://center.qoder.sh"
	QoderChatBase             = "https://api3.qoder.sh"
	QoderLoginURL             = "https://qoder.com/device/selectAccounts"
	QoderOAuthTokenEndpoint   = QoderOpenAPIBase + "/api/v1/deviceToken/poll"
	QoderRefreshTokenEndpoint = QoderCenterBase + "/algo/api/v3/user/refresh_token"
	QoderChatURL              = QoderChatBase + "/algo/api/v3/chat/stream"
	QoderChatURLEncoded       = QoderChatURL + "?Encode=1"
	QoderIDEVersion           = "1.0.0"
	QoderClientType           = "5"
	QoderDataPolicy           = "disagree"
	QoderLoginVersion         = "v2"
	QoderMachineOS            = "x86_64_windows"
	QoderMachineTypeMagic     = "5"
)

var ModelMap = map[string]string{
	"auto":              "auto",
	"qoder/auto":        "auto",
	"claude-sonnet-4.5": "claude-sonnet-4.5",
	"gpt-5":             "gpt-5",
	"glm-4.6":           "glm-4.6",
	"glm-5.1":           "glm-5.1",
}

type TokenStorage struct {
	Type         string         `json:"type"`
	Token        string         `json:"token,omitempty"`
	AccessToken  string         `json:"access_token,omitempty"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	ExpireTime   int64          `json:"expire_time,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	Name         string         `json:"name,omitempty"`
	Email        string         `json:"email,omitempty"`
	MachineID    string         `json:"machine_id,omitempty"`
	MachineToken string         `json:"machineToken,omitempty"`
	MachineType  string         `json:"machineType,omitempty"`
	Metadata     map[string]any `json:"-"`
}

func (ts *TokenStorage) SetMetadata(meta map[string]any) { ts.Metadata = meta }

func (ts *TokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "qoder"
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0o700); err != nil {
		return fmt.Errorf("qoder token storage: create directory: %w", err)
	}
	data, err := misc.MergeMetadata(ts, ts.Metadata)
	if err != nil {
		return fmt.Errorf("qoder token storage: merge metadata: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(authFilePath), ".tmp-qoder-*")
	if err != nil {
		return fmt.Errorf("qoder token storage: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err = enc.Encode(data); err != nil {
		return fmt.Errorf("qoder token storage: write temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("qoder token storage: close temp file: %w", err)
	}
	if err = os.Rename(tmpName, authFilePath); err != nil {
		return fmt.Errorf("qoder token storage: commit token file: %w", err)
	}
	cleanup = false
	return nil
}

func (ts *TokenStorage) BearerToken() string {
	if strings.TrimSpace(ts.Token) != "" {
		return strings.TrimSpace(ts.Token)
	}
	return strings.TrimSpace(ts.AccessToken)
}

type DeviceFlowResponse struct {
	VerificationURIComplete string
	CodeVerifier            string
	Nonce                   string
	MachineID               string
}

type Auth struct{}

func NewQoderAuth() *Auth { return &Auth{} }

func (a *Auth) StartDeviceFlow(_ context.Context) (*DeviceFlowResponse, error) {
	verifier, err := randomBase64URL(48)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBase64URL(24)
	if err != nil {
		return nil, err
	}
	machineID, err := randomBase64URL(24)
	if err != nil {
		return nil, err
	}
	challenge := pkceChallenge(verifier)
	values := url.Values{}
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	values.Set("nonce", nonce)
	values.Set("machine_id", machineID)
	values.Set("login_version", QoderLoginVersion)
	return &DeviceFlowResponse{VerificationURIComplete: QoderLoginURL + "?" + values.Encode(), CodeVerifier: verifier, Nonce: nonce, MachineID: machineID}, nil
}

func (a *Auth) WaitForAuthorization(ctx context.Context, flow *DeviceFlowResponse) (*TokenStorage, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("qoder: device polling is not available in this build: %w", ctx.Err())
}

func CredentialFileName(email, userID string) string {
	if s := sanitize(email); s != "" {
		return fmt.Sprintf("qoder-%s.json", s)
	}
	if s := sanitize(userID); s != "" {
		return fmt.Sprintf("qoder-%s.json", s)
	}
	return fmt.Sprintf("qoder-%d.json", time.Now().UnixMilli())
}

func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("qoder: random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func sanitize(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '@', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
