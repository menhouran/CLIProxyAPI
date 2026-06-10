package codebuddy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// TokenStorage stores CodeBuddy OAuth credentials.
type TokenStorage struct {
	Type         string         `json:"type"`
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	ExpiresIn    int64          `json:"expires_in,omitempty"`
	TokenType    string         `json:"token_type,omitempty"`
	Domain       string         `json:"domain,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	Expired      string         `json:"expired,omitempty"`
	Metadata     map[string]any `json:"-"`
}

func (ts *TokenStorage) SetMetadata(meta map[string]any) { ts.Metadata = meta }

func (ts *TokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "codebuddy"
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0o700); err != nil {
		return fmt.Errorf("codebuddy token storage: create directory: %w", err)
	}
	data, err := misc.MergeMetadata(ts, ts.Metadata)
	if err != nil {
		return fmt.Errorf("codebuddy token storage: merge metadata: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(authFilePath), ".tmp-codebuddy-*")
	if err != nil {
		return fmt.Errorf("codebuddy token storage: create temp file: %w", err)
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
		return fmt.Errorf("codebuddy token storage: write temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("codebuddy token storage: close temp file: %w", err)
	}
	if err = os.Rename(tmpName, authFilePath); err != nil {
		return fmt.Errorf("codebuddy token storage: commit token file: %w", err)
	}
	cleanup = false
	return nil
}

func CredentialFileName(userID string) string {
	userID = sanitizeFileSegment(userID)
	if userID != "" {
		return fmt.Sprintf("codebuddy-%s.json", userID)
	}
	return fmt.Sprintf("codebuddy-%d.json", time.Now().UnixMilli())
}

func sanitizeFileSegment(value string) string {
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
