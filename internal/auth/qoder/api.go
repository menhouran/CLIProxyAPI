package qoder

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

const (
	// QoderInferURL is the base URL for Qoder inference (chat / model list).
	// Aligned with Veria v1.3.7's reverse-engineering: api3.qoder.sh.
	QoderInferURL = QoderChatBase
	// QoderSigPath is the relative path of the streaming chat endpoint
	// without the /algo prefix; used both for URL construction and for
	// the Cosy-Sigpath header.
	QoderSigPath = "/api/v2/service/pro/sse/agent_chat_generation"
	// QoderChatURL is the full URL for the streaming chat endpoint.
	QoderChatURL = QoderInferURL + "/algo" + QoderSigPath + "?FetchKeys=llm_model_result&AgentId=agent_common"
	// QoderChatURLEncoded is the chat URL with Encode=1, used when the request
	// body is encoded with QoderEncodeBody to bypass WAF pattern matching.
	QoderChatURLEncoded = QoderChatURL + "&Encode=1"
	// QoderModelListURL is the full URL for /algo/api/v2/model/list on the
	// inference host. The endpoint uses COSY signing; pass an empty body.
	QoderModelListURL = QoderInferURL + "/algo/api/v2/model/list?Encode=1"
)

// ModelMap is the canonical set of model identifiers the Qoder platform accepts.
// Verified against live API (qoder.com & qoder.com.cn /api/v1/remote/environments).
//
// The map is identity (key == value) for server keys; alias entries map
// human-friendly names to the server's internal key so users can request
// e.g. "qoder/qwen3.7-max" instead of "qoder/qmodel_latest".
var ModelMap = map[string]string{
	// ── Tier models (international only — not available on domestic qoder.com.cn) ──
	"auto":        "auto",        // both platforms
	"ultimate":    "ultimate",    // international: 1.6x
	"performance": "performance", // international: 1.1x
	"efficient":   "efficient",   // international: 0.3x

	// ── Frontier models — pin a specific backing model ──
	"qmodel":        "qmodel",        // Qwen 3.7 Plus     (both)
	"qmodel_latest": "qmodel_latest", // Qwen 3.7 Max      (both, default on intl)
	"q36fmodel":     "q36fmodel",     // Qwen 3.6 Flash    (domestic only)
	"dmodel":        "dmodel",        // DeepSeek V4 Pro   (both)
	"dfmodel":       "dfmodel",       // DeepSeek V4 Flash (both)
	"gm51model":     "gm51model",     // GLM 5.1           (both)
	"kmodel":        "kmodel",        // Kimi K2.6         (both)
	"mmodel":        "mmodel",        // MiniMax M3 (intl) / M2.7 (domestic)

	// ── Backward-compatible aliases ──
	"qmaxmodel": "qmodel_latest", // legacy key → qmodel_latest

	// ── Human-friendly aliases → server key ──
	"qwen3.7-plus":      "qmodel",
	"qwen3.7-max":       "qmodel_latest",
	"qwen3.6-flash":     "q36fmodel",
	"deepseek-v4-pro":   "dmodel",
	"deepseek-v4-flash": "dfmodel",
	"glm-5.1":           "gm51model",
	"kimi-k2.6":         "kmodel",
	"minimax-m3":        "mmodel",
}

// doRefreshToken performs a token refresh and persists the result to authFilePath.
// When authFilePath is empty, it falls back to AuthDir/qoder-<email>.json for
// backward compatibility with auth records that lack a recorded path.
func doRefreshToken(ctx context.Context, cfg *config.Config, storage *QoderTokenStorage, authFilePath string) error {
	auth := NewQoderAuth(cfg)

	tokenData, err := auth.RefreshTokens(ctx, storage.Token, storage.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	auth.UpdateTokenStorage(storage, tokenData)

	if authFilePath == "" {
		if storage.Email == "" {
			return fmt.Errorf("cannot save token: email is empty and no file path provided")
		}
		fileName := fmt.Sprintf("qoder-%s.json", storage.Email)
		authFilePath = filepath.Join(cfg.AuthDir, fileName)
	}
	return storage.SaveTokenToFile(authFilePath)
}

// RefreshTokenIfNeeded refreshes the access token when the remaining lifetime
// drops below bufferSeconds. authFilePath is the on-disk location of the auth
// record; an empty value triggers the email-derived fallback path.
func RefreshTokenIfNeeded(ctx context.Context, cfg *config.Config, storage *QoderTokenStorage, bufferSeconds int64, authFilePath string) error {
	if storage.ExpireTime == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	bufferMs := bufferSeconds * 1000

	if storage.ExpireTime-now-bufferMs <= 0 {
		return doRefreshToken(ctx, cfg, storage, authFilePath)
	}

	return nil
}
