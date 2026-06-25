// Package codebuddy provides authentication and token management functionality
// for CodeBuddy AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the CodeBuddy API.
package codebuddy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
)

// CodeBuddyTokenStorage stores OAuth token information for CodeBuddy API authentication.
type CodeBuddyTokenStorage struct {
	// AccessToken is the OAuth2 access token used for authenticating API requests.
	AccessToken string `json:"access_token"`
	// RefreshToken is the OAuth2 refresh token used to obtain new access tokens.
	RefreshToken string `json:"refresh_token"`
	// ExpiresIn is the number of seconds until the access token expires.
	ExpiresIn int64 `json:"expires_in"`
	// RefreshExpiresIn is the number of seconds until the refresh token expires.
	RefreshExpiresIn int64 `json:"refresh_expires_in,omitempty"`
	// TokenType is the type of token, typically "bearer".
	TokenType string `json:"token_type"`
	// Domain is the CodeBuddy service domain/region.
	Domain string `json:"domain"`
	// UserID is the user ID associated with this token.
	UserID string `json:"user_id"`
	// Type indicates the authentication provider type, always "codebuddy" for this storage.
	Type string `json:"type"`
	// Metadata holds arbitrary key-value pairs injected via hooks (e.g. "disabled").
	// Merged into the JSON file by SaveTokenToFile so file-watcher reloads see them.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (s *CodeBuddyTokenStorage) SetMetadata(meta map[string]any) {
	s.Metadata = meta
}

// SaveTokenToFile serializes the CodeBuddy token storage to a JSON file.
func (s *CodeBuddyTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	s.Type = "codebuddy"

	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, errMerge := misc.MergeMetadata(s, s.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	// Atomically write via temp file + rename to avoid partial writes
	tmp, err := os.CreateTemp(filepath.Dir(authFilePath), ".tmp-codebuddy-*")
	if err != nil {
		return fmt.Errorf("failed to create temp token file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err = json.NewEncoder(tmp).Encode(data); err != nil {
		return fmt.Errorf("failed to write token to temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err = os.Rename(tmpName, authFilePath); err != nil {
		return fmt.Errorf("failed to commit token file: %w", err)
	}
	cleanup = false
	return nil
}
