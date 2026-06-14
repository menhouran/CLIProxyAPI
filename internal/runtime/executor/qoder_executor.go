package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	qoderauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/qoder"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// Package-level model config and usage caches, keyed by auth ID.
// Replaces QoderTokenStorage.ModelConfigs / UsageInfo so the executor
// never needs a Storage type assertion (upstream Ve-ria-Plus pattern).
var (
	qoderModelConfigCache   = make(map[string]map[string]json.RawMessage) // authID → modelKey → raw config
	qoderModelConfigCacheMu sync.RWMutex
	qoderUsageCache         = make(map[string]*qoderauth.QoderUsageInfo) // authID → usage
	qoderUsageCacheMu       sync.RWMutex
)

// QoderExecutor executes requests against the Qoder API with COSY authentication
type QoderExecutor struct {
	cfg *config.Config
}

// NewQoderExecutor creates a new Qoder executor
func NewQoderExecutor(cfg *config.Config) *QoderExecutor {
	return &QoderExecutor{
		cfg: cfg,
	}
}

// Identifier returns the provider identifier
func (e *QoderExecutor) Identifier() string {
	return "qoder"
}

// qoderCredentials holds the extracted credentials for Qoder COSY auth.
// Mirrors Ve-ria-Plus qoder_executor.go — reads from auth.Metadata directly,
// never touches auth.Storage (which may be a pluginTokenStorage or nil).
type qoderCredentials struct {
	accessToken string
	uid         string
	name        string
	email       string
	machineID   string
}

// qoderCreds extracts Qoder credentials from the auth record's Metadata map.
// Metadata is populated by both the device-flow login (filestore.go reads the
// raw token file JSON into Metadata) and the Ve-ria-Plus PKCE login (which
// writes access_token/uid/name/email/machine_id directly).
//
// Field-name fallback handles the two naming conventions:
//   - Ve-ria-Plus PKCE login: access_token, uid
//   - CLIProxyAPI device flow token file: token, user_id
func qoderCreds(a *cliproxyauth.Auth) qoderCredentials {
	var creds qoderCredentials
	if a == nil {
		return creds
	}
	if a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok {
			creds.accessToken = v
		} else if v, ok := a.Metadata["token"].(string); ok {
			creds.accessToken = v
		}
		if v, ok := a.Metadata["uid"].(string); ok {
			creds.uid = v
		} else if v, ok := a.Metadata["user_id"].(string); ok {
			creds.uid = v
		}
		if v, ok := a.Metadata["name"].(string); ok {
			creds.name = v
		}
		if v, ok := a.Metadata["email"].(string); ok {
			creds.email = v
		}
		if v, ok := a.Metadata["machine_id"].(string); ok {
			creds.machineID = v
		}
	}
	// Attributes fallback (Ve-ria-Plus pattern)
	if a.Attributes != nil {
		if creds.accessToken == "" {
			if v := a.Attributes["access_token"]; v != "" {
				creds.accessToken = v
			}
		}
		if creds.uid == "" {
			if v := a.Attributes["uid"]; v != "" {
				creds.uid = v
			}
		}
	}
	return creds
}

// ExecuteStream executes a streaming request against Qoder API
func (e *QoderExecutor) ExecuteStream(ctx context.Context, authRecord *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	// Extract credentials from auth metadata (upstream Ve-ria-Plus pattern).
	// No Storage type assertion needed — works with pluginTokenStorage, nil, etc.
	creds := qoderCreds(authRecord)
	if creds.accessToken == "" {
		return nil, fmt.Errorf("qoder executor: missing access token in auth metadata")
	}

	// Note: Qoder device tokens are long-lived (~30 days) and the upstream
	// /algo/api/v3/user/refresh_token endpoint returns 403 for them — see
	// QoderExecutor.Refresh's no-op rationale. We deliberately do not call
	// RefreshTokenIfNeeded per request: it would just produce a 403 in the
	// log on every chat call. Token expiry is handled by the user re-running
	// --qoder-login.

	// Usage reporter mirrors the codebuddy executor pattern.
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, authRecord)

	// Translate non-openai formats to chat completions before extracting messages
	payload := req.Payload
	if opts.SourceFormat != "" && opts.SourceFormat != sdktranslator.FormatOpenAI {
		payload = sdktranslator.TranslateRequest(opts.SourceFormat, sdktranslator.FormatOpenAI, req.Model, payload, false)
	}

	// Parse request to get model and messages
	var chatReq map[string]interface{}
	if err := json.Unmarshal(payload, &chatReq); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	// Map model name — strip provider prefix so qoder/auto → auto
	model, _ := chatReq["model"].(string)
	qoderModel := strings.TrimPrefix(model, "qoder/")
	if mapped, ok := qoderauth.ModelMap[qoderModel]; ok {
		qoderModel = mapped
	} else {
		return nil, fmt.Errorf("unsupported qoder model: %q (received %q)", qoderModel, model)
	}

	// Extract messages and tools from the OpenAI-format request body.
	messagesRaw, _ := chatReq["messages"].([]interface{})
	normalized, systemText := normalizeQoderMessages(messagesRaw)
	toolsRaw := chatReq["tools"]

	// Resolve the per-model server-side metadata (is_vl, is_reasoning,
	// max_input_tokens, ...). Failing here is a hard error — sending the
	// wrong block silently downgrades to a different model.
	modelConfig, err := buildQoderModelConfig(authRecord, qoderModel)
	if err != nil {
		return nil, err
	}

	isReasoning, _ := modelConfig["is_reasoning"].(bool)
	maxOutputTokens, _ := modelConfig["max_output_tokens"].(float64)

	// Last user message text — used by Qoder for the chat_context "current
	// turn" preview slot. The full conversation still goes through `messages`.
	lastUser := lastUserText(normalized)

	sessionID := uuid.New().String()
	recordID := uuid.New().String()

	// Start with the model's maximum output tokens, then clamp to
	// any user-requested limit so callers can cap cost/latency/UI.
	maxTokens := 32768
	if maxOutputTokens > 0 {
		maxTokens = int(maxOutputTokens)
	}
	if userMax, ok := chatReq["max_tokens"].(float64); ok && userMax > 0 {
		if int(userMax) < maxTokens {
			maxTokens = int(userMax)
		}
	}
	if userMax, ok := chatReq["max_completion_tokens"].(float64); ok && userMax > 0 {
		if int(userMax) < maxTokens {
			maxTokens = int(userMax)
		}
	}

	reqBody := map[string]interface{}{
		"request_id":     uuid.New().String(),
		"request_set_id": recordID,
		"chat_record_id": recordID,
		"session_id":     sessionID,
		"stream":         true,
		"chat_task":      "FREE_INPUT",
		"is_reply":       false,
		"is_retry":       false,
		"source":         1,
		"version":        "3",
		"session_type":   "qodercli",
		"agent_id":       "agent_common",
		"task_id":        "common",
		"code_language":  "",
		"chat_prompt":    "",
		"system":         systemText,
		"messages":       normalized,
		"tools":          []interface{}{},
		"parameters":     map[string]interface{}{"max_tokens": maxTokens},
		"chat_context": map[string]interface{}{
			"chatPrompt": "",
			"extra": map[string]interface{}{
				"context":         []interface{}{},
				"modelConfig":     map[string]interface{}{"key": qoderModel, "is_reasoning": isReasoning},
				"originalContent": map[string]interface{}{"type": "text", "text": lastUser},
			},
			"features": []interface{}{},
			"text":     map[string]interface{}{"type": "text", "text": lastUser},
		},
		"model_config": modelConfig,
		"business": map[string]interface{}{
			"id":       uuid.New().String(),
			"type":     "agent_chat_generation",
			"name":     "",
			"begin_at": time.Now().UnixMilli(),
		},
	}
	if toolsRaw != nil {
		reqBody["tools"] = toolsRaw
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	// Encode the body to bypass Alibaba Cloud WAF pattern matching.
	// The server decodes when &Encode=1 is present in the URL.
	encodedBytes := []byte(helps.QoderEncodeBody(bodyBytes))

	headers, err := qoderauth.BuildAuthHeaders(
		encodedBytes,
		qoderauth.QoderChatURLEncoded,
		qoderauth.CosyCredentials{
			UserID:    creds.uid,
			AuthToken: creds.accessToken,
			Name:      creds.name,
			Email:     creds.email,
			MachineID: creds.machineID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build COSY auth: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", qoderauth.QoderChatURLEncoded, bytes.NewReader(encodedBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")
	headers.Apply(httpReq)
	modelSource, _ := modelConfig["source"].(string)
	if modelSource == "" {
		modelSource = "system"
	}
	httpReq.Header.Set("X-Model-Key", qoderModel)
	httpReq.Header.Set("X-Model-Source", modelSource)
	// Disable automatic gzip — Accept-Encoding: gzip triggers signature
	// validation on the Qoder upstream and causes 403 Signature invalid.
	httpReq.Header.Set("Accept-Encoding", "identity")

	// Log upstream request via shared helpers.
	var logAuthID, logAuthLabel, logAuthType, logAuthValue string
	if authRecord != nil {
		logAuthID = authRecord.ID
		logAuthLabel = authRecord.Label
		logAuthType, logAuthValue = authRecord.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       qoderauth.QoderChatURLEncoded,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      bodyBytes,
		Provider:  "qoder",
		AuthID:    logAuthID,
		AuthLabel: logAuthLabel,
		AuthType:  logAuthType,
		AuthValue: logAuthValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, authRecord, 0)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		defer func() { _ = httpResp.Body.Close() }()
		body, _ := io.ReadAll(httpResp.Body)
		allow := httpResp.Header.Get("Allow")
		server := httpResp.Header.Get("Server")
		bodyPreview := truncate(string(body), 500)
		log.WithFields(log.Fields{
			"url":            qoderauth.QoderChatURLEncoded,
			"server":         server,
			"content_type":   httpResp.Header.Get("Content-Type"),
			"x_request_id":   httpResp.Header.Get("X-Request-Id"),
			"x_eagleeye_id":  httpResp.Header.Get("Eagleeye-Traceid"),
			"x_oss_request":  httpResp.Header.Get("X-Oss-Request-Id"),
			"allow":          allow,
			"body_truncated": bodyPreview,
		}).Warnf("qoder: upstream %d allow=%q server=%q body=%q", httpResp.StatusCode, allow, server, bodyPreview)
		helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
		helps.AppendAPIResponseChunk(ctx, e.cfg, body)
		statusForRetry := httpResp.StatusCode
		if statusForRetry == http.StatusMethodNotAllowed {
			statusForRetry = http.StatusTooManyRequests
		}
		return nil, newQoderStatusError(statusForRetry, string(body))
	}

	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())

	// Create streaming channel
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() { _ = httpResp.Body.Close() }()
		defer reporter.EnsurePublished(ctx)

		// Shared across all TranslateStream calls in this stream — the
		// translator carries open-block / sequence state through it; a
		// per-chunk var would re-emit message_start on every delta.
		var streamParam any

		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 52_428_800) // 50MB max line

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			// Skip non-data lines
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}

			data := bytes.TrimPrefix(line, []byte("data:"))
			data = bytes.TrimPrefix(data, []byte(" "))
			if bytes.Equal(data, []byte("[DONE]")) {
				emitDone(ctx, out, opts.SourceFormat, req.Model, opts.OriginalRequest, payload, &streamParam)
				return
			}

			// Parse Qoder response envelope
			var event map[string]interface{}
			if err := json.Unmarshal(data, &event); err != nil {
				continue
			}
			statusVal := 200
			if rawStatus, ok := event["statusCodeValue"]; ok {
				switch v := rawStatus.(type) {
				case float64:
					statusVal = int(v)
				case int:
					statusVal = v
				}
			}
			innerStr, _ := event["body"].(string)
			if statusVal != http.StatusOK {
				msg := innerStr
				if msg == "" {
					msg = fmt.Sprintf("upstream status %d", statusVal)
				}
				out <- cliproxyexecutor.StreamChunk{Err: newQoderStatusError(statusVal, msg)}
				return
			}
			if innerStr == "" {
				continue
			}
			if innerStr == "[DONE]" {
				emitDone(ctx, out, opts.SourceFormat, req.Model, opts.OriginalRequest, payload, &streamParam)
				return
			}
			var inner map[string]interface{}
			if err := json.Unmarshal([]byte(innerStr), &inner); err != nil {
				continue
			}
			chunkBytes, err := buildOpenAIChunk(inner, model)
			if err != nil {
				continue
			}
			// Reconstruct an OpenAI-compatible SSE line ("data: {chunk}").
			// Qoder's upstream nests OpenAI chunks inside a
			// {statusCodeValue, body} envelope so unlike kimi/openai-compat/
			// codebuddy we can't forward the raw upstream line — we have to
			// rebuild the SSE frame here. The format matches what those
			// other executors feed into TranslateStream so the translators'
			// "expects data: prefix" assumption holds.
			ssePayload := append([]byte("data: "), chunkBytes...)

			// Record every upstream chunk for request-log body capture.
			helps.AppendAPIResponseChunk(ctx, e.cfg, ssePayload)

			// Always run through TranslateStream. When source==target
			// (OpenAI client) it strips the "data:" prefix and returns
			// raw JSON; the OpenAI handler then re-adds the SSE framing.
			// For cross-format clients (Anthropic/Gemini) it emits the
			// format-specific stream events (message_start /
			// content_block_delta / ...) directly as fully framed bytes
			// because those handlers write chunks verbatim.
			to := sdktranslator.FormatOpenAI
			from := opts.SourceFormat
			if from == "" {
				from = to
			}
			frames := sdktranslator.TranslateStream(ctx, to, from,
				req.Model, opts.OriginalRequest, payload, ssePayload, &streamParam)
			for _, frame := range frames {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: frame}:
				case <-ctx.Done():
					return
				}
			}
		}
		// Scanner loop exited naturally (EOF). Emit a terminating
		// "data: [DONE]" / Anthropic message_stop frame so the client
		// closes the stream cleanly.
		emitDone(ctx, out, opts.SourceFormat, req.Model, opts.OriginalRequest, payload, &streamParam)
		// Check for scanner errors
		if err := scanner.Err(); err != nil {
			out <- cliproxyexecutor.StreamChunk{Err: fmt.Errorf("scanner error: %w", err)}
		}
	}()

	return &cliproxyexecutor.StreamResult{
		Headers: httpResp.Header.Clone(),
		Chunks:  out,
	}, nil
}

// lastUserText returns the text of the last user message in the (already
// normalized) message list, or empty when there isn't one. Qoder uses this
// for the chat_context "current turn" preview slot; the full conversation
// still travels through the messages array.
func lastUserText(messages []interface{}) string {
	for i := len(messages) - 1; i >= 0; i-- {
		msgMap, ok := messages[i].(map[string]interface{})
		if !ok {
			continue
		}
		if role, _ := msgMap["role"].(string); role != "user" {
			continue
		}
		if s, ok := msgMap["content"].(string); ok {
			return s
		}
		return extractContentGeneric(msgMap["content"])
	}
	return ""
}

// extractContentGeneric extracts text content from message content field
func extractContentGeneric(content interface{}) string {
	switch v := content.(type) {
	case string:
		return v
	case []interface{}:
		var parts []string
		for _, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				if itemMap["type"] == "text" {
					if text, ok := itemMap["text"].(string); ok {
						parts = append(parts, text)
					}
					continue
				}
				if text, ok := itemMap["text"].(string); ok {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		if content == nil {
			return ""
		}
		return fmt.Sprintf("%v", content)
	}
}

// normalizeQoderMessages clones each message and applies sanitizations
// required by Qoder's upstream:
//
//  1. Flatten content: Anthropic/OpenAI multipart content arrays
//     ([{type:"text",text:"..."}]) are collapsed to plain strings.
//
//  2. Drop system messages: Qoder rejects role="system"; they are silently
//     removed. The system prompt is already embedded in the first user turn
//     by the Claude Code client, so context is not lost.
//
//  3. Clear tool_call arguments: Qoder's upstream sits behind Alibaba Cloud
//     WAF which blocks requests containing shell metacharacter sequences
//     (e.g. "2>/dev/null || echo") anywhere in the body. Historical bash
//     tool_calls accumulate these patterns; clearing the entire arguments
//     string prevents WAF 405 rejections without affecting the model's
//     ability to understand the conversation history.
//
//  4. Strip control characters: non-printable bytes (U+0000–U+001F except
//     tab/LF/CR) in message content cause Qoder to return 500; they are
//     removed from all string fields.
func normalizeQoderMessages(messages []interface{}) (normalized []interface{}, systemText string) {
	if len(messages) == 0 {
		return nil, ""
	}
	out := make([]interface{}, 0, len(messages))
	var systemParts []string
	for _, msg := range messages {
		msgMap, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}
		// Drop system messages — Qoder does not accept role="system".
		if role, _ := msgMap["role"].(string); role == "system" {
			if text := stripControlChars(extractContentGeneric(msgMap["content"])); text != "" {
				systemParts = append(systemParts, text)
			}
			continue
		}
		cloned := make(map[string]interface{}, len(msgMap))
		for k, v := range msgMap {
			cloned[k] = v
		}
		cloned["content"] = stripControlChars(extractContentGeneric(msgMap["content"]))
		// Clear tool_call arguments to avoid triggering WAF command-injection rules.
		if toolCalls, ok := cloned["tool_calls"].([]interface{}); ok {
			sanitized := make([]interface{}, 0, len(toolCalls))
			for _, tc := range toolCalls {
				tcMap, ok := tc.(map[string]interface{})
				if !ok {
					sanitized = append(sanitized, tc)
					continue
				}
				tcCloned := make(map[string]interface{}, len(tcMap))
				for k, v := range tcMap {
					tcCloned[k] = v
				}
				if fn, ok := tcCloned["function"].(map[string]interface{}); ok {
					fnCloned := make(map[string]interface{}, len(fn))
					for k, v := range fn {
						if k == "arguments" {
							fnCloned[k] = "{}"
						} else {
							fnCloned[k] = v
						}
					}
					tcCloned["function"] = fnCloned
				}
				sanitized = append(sanitized, tcCloned)
			}
			cloned["tool_calls"] = sanitized
		}
		out = append(out, cloned)
	}
	return out, strings.Join(systemParts, "\n\n")
}

// stripControlChars removes non-printable characters (U+0000–U+001F)
// except tab, LF, and CR from the input string.
func stripControlChars(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
			// Found a control char — need to rebuild
			b := make([]byte, 0, len(s))
			b = append(b, s[:i]...)
			for j := i; j < len(s); j++ {
				if s[j] < 0x20 && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' {
					continue
				}
				b = append(b, s[j])
			}
			return string(b)
		}
	}
	return s
}

func buildOpenAIChunk(inner map[string]interface{}, model string) ([]byte, error) {
	if inner == nil {
		return nil, fmt.Errorf("empty inner payload")
	}
	if _, ok := inner["model"]; !ok || inner["model"] == "" {
		inner["model"] = model
	}
	if choices, ok := inner["choices"].([]interface{}); ok {
		if len(choices) == 0 {
			if inner["finish_reason"] != nil || inner["stop"] != nil {
				inner["choices"] = []map[string]interface{}{{
					"index":         0,
					"delta":         map[string]interface{}{},
					"finish_reason": "stop",
				}}
			}
		}
	}
	return json.Marshal(inner)
}

// emitDone publishes the terminating SSE frame(s) for the stream. The
// upstream "[DONE]" sentinel is fed through TranslateStream so the
// client's SourceFormat dictates the actual wire bytes — "data: [DONE]\n\n"
// for OpenAI, "event: message_stop\ndata: {...}\n\n" for Anthropic, and
// the equivalent format-specific terminators for Gemini etc. This mirrors
// the pattern used by kimi_executor.
//
// param must be the same pointer the per-chunk TranslateStream calls used
// — the Anthropic translator (and others) need the carried state to know
// which content_block indices to close, the running token count, etc.
func emitDone(ctx context.Context, out chan<- cliproxyexecutor.StreamChunk,
	sourceFormat sdktranslator.Format, reqModel string, originalReq, body []byte, param *any) {
	to := sdktranslator.FormatOpenAI
	from := sourceFormat
	if from == "" {
		from = to
	}
	frames := sdktranslator.TranslateStream(ctx, to, from,
		reqModel, originalReq, body, []byte("[DONE]"), param)
	for _, frame := range frames {
		select {
		case out <- cliproxyexecutor.StreamChunk{Payload: frame}:
		case <-ctx.Done():
			return
		}
	}
}

// qoderStatusError implements StatusError for Qoder API errors
type qoderStatusError struct {
	status  int
	message string
}

func newQoderStatusError(status int, message string) *qoderStatusError {
	return &qoderStatusError{status: status, message: message}
}

func (e *qoderStatusError) Error() string {
	return fmt.Sprintf("Qoder API error %d: %s", e.status, e.message)
}

func (e *qoderStatusError) StatusCode() int {
	return e.status
}

// CountTokens estimates token count for the request (placeholder implementation)
func (e *QoderExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	// Translate non-openai formats before extracting messages
	payload := req.Payload
	if opts.SourceFormat != "" && opts.SourceFormat != sdktranslator.FormatOpenAI {
		payload = sdktranslator.TranslateRequest(opts.SourceFormat, sdktranslator.FormatOpenAI, req.Model, payload, false)
	}

	// Simple estimation: 1 token ≈ 4 characters
	var chatReq map[string]interface{}
	if err := json.Unmarshal(payload, &chatReq); err != nil {
		return cliproxyexecutor.Response{}, err
	}

	messagesRaw, _ := chatReq["messages"].([]interface{})
	totalChars := 0
	for _, msg := range messagesRaw {
		if msgMap, ok := msg.(map[string]interface{}); ok {
			content := extractContentGeneric(msgMap["content"])
			totalChars += len(content)
		}
	}

	estimatedTokens := totalChars / 4
	if estimatedTokens < 1 {
		estimatedTokens = 1
	}

	response := map[string]interface{}{
		"usage": map[string]int{
			"prompt_tokens":     estimatedTokens,
			"completion_tokens": 0,
			"total_tokens":      estimatedTokens,
		},
	}

	responseBytes, _ := json.Marshal(response)
	return cliproxyexecutor.Response{
		Payload: responseBytes,
	}, nil
}

// Execute executes a non-streaming request against Qoder API
func (e *QoderExecutor) Execute(ctx context.Context, authRecord *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	// We need ExecuteStream to:
	//   1. Translate the request payload from the client's SourceFormat
	//      (Anthropic/Gemini/etc) into OpenAI before sending to Qoder.
	//   2. Emit raw OpenAI chunks so we can accumulate choices[0].delta.
	//
	// (1) requires opts.SourceFormat to stay as the original; (2) requires
	// it to be OpenAI. Resolve by translating the payload up-front, then
	// passing FormatOpenAI for both directions to ExecuteStream.
	internalReq := req
	internalOpts := opts
	if opts.SourceFormat != "" && opts.SourceFormat != sdktranslator.FormatOpenAI {
		internalReq.Payload = sdktranslator.TranslateRequest(
			opts.SourceFormat, sdktranslator.FormatOpenAI,
			req.Model, req.Payload, false)
	}
	internalOpts.SourceFormat = sdktranslator.FormatOpenAI

	streamResult, err := e.ExecuteStream(ctx, authRecord, internalReq, internalOpts)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	// Accumulate all chunks
	var content strings.Builder
	var finishReason string
	type pendingToolCall struct {
		ID        string
		Name      string
		Arguments string
	}
	pendingToolCalls := make(map[int]*pendingToolCall)

	for chunk := range streamResult.Chunks {
		if chunk.Err != nil {
			return cliproxyexecutor.Response{}, chunk.Err
		}

		// ExecuteStream was called with SourceFormat=FormatOpenAI so
		// TranslateStream strips the "data:" prefix and returns raw JSON.
		// Skip empty or [DONE] payloads.
		raw := chunk.Payload
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("[DONE]")) {
			continue
		}

		var oiChunk map[string]interface{}
		if err := json.Unmarshal(raw, &oiChunk); err == nil {
			if choices, ok := oiChunk["choices"].([]interface{}); ok && len(choices) > 0 {
				if choice, ok := choices[0].(map[string]interface{}); ok {
					if delta, ok := choice["delta"].(map[string]interface{}); ok {
						if toolCalls, ok := delta["tool_calls"].([]interface{}); ok {
							for _, call := range toolCalls {
								callMap, ok := call.(map[string]interface{})
								if !ok {
									continue
								}
								idx := 0
								if rawIdx, ok := callMap["index"].(float64); ok {
									idx = int(rawIdx)
								}
								entry := pendingToolCalls[idx]
								if entry == nil {
									entry = &pendingToolCall{}
									pendingToolCalls[idx] = entry
								}
								if id, ok := callMap["id"].(string); ok && id != "" {
									entry.ID = id
								}
								if fn, ok := callMap["function"].(map[string]interface{}); ok {
									if name, ok := fn["name"].(string); ok && name != "" {
										entry.Name = name
									}
									if args, ok := fn["arguments"].(string); ok && args != "" {
										entry.Arguments += args
									}
								}
							}
						}
						if contentStr, ok := delta["content"].(string); ok {
							content.WriteString(contentStr)
						}
					}
					if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
						finishReason = fr
					}
				}
			}
		}
	}

	var toolCalls []map[string]interface{}
	if finishReason == "tool_calls" && len(pendingToolCalls) > 0 {
		for i := 0; i < len(pendingToolCalls); i++ {
			entry, ok := pendingToolCalls[i]
			if !ok || entry == nil {
				continue
			}
			id := entry.ID
			if id == "" {
				id = fmt.Sprintf("call_%d", time.Now().UnixNano())
			}
			args := entry.Arguments
			if strings.TrimSpace(args) == "" {
				args = "{}"
			}
			toolCalls = append(toolCalls, map[string]interface{}{
				"id":   id,
				"type": "function",
				"function": map[string]interface{}{
					"name":      entry.Name,
					"arguments": args,
				},
			})
		}
	}

	// Build final response
	message := map[string]interface{}{
		"role":    "assistant",
		"content": content.String(),
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	response := map[string]interface{}{
		"id":      fmt.Sprintf("qoder-%d", time.Now().UnixNano()),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   req.Model,
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"message":       message,
				"finish_reason": finishReason,
			},
		},
	}

	responseBytes, _ := json.Marshal(response)

	// Translate the Qoder OpenAI-format response back to the client's
	// expected SourceFormat. Reuse internalReq.Payload — that's already
	// the OpenAI-translated payload we computed above before calling
	// ExecuteStream, so we don't need to re-translate.
	var param any
	out := sdktranslator.TranslateNonStream(ctx, sdktranslator.FormatOpenAI, opts.SourceFormat, req.Model, opts.OriginalRequest, internalReq.Payload, responseBytes, &param)
	responseBytes = out

	return cliproxyexecutor.Response{
		Payload: responseBytes,
		Headers: streamResult.Headers,
	}, nil
}

// Refresh is a no-op for Qoder.
//
// Qoder's device-flow token (the "dt-..." string) is already long-lived
// (~30 days for the access token, ~360 days for the refresh token per
// the deviceToken/poll response). The upstream does not expose the
// classic OAuth refresh dance — every endpoint we've observed (cubk1's
// qoder2api, Veria, the official @qoder-ai/qodercli) either skips
// refresh entirely or routes through a different /jobToken exchange
// flow that requires personalToken (we don't have one).
//
// Hitting /algo/api/v3/user/refresh_token with our device token returns
// 403 "Forbidden" / errorCode=Forbidden — the endpoint is not for our
// flow. Mark the auth refreshed-now and keep going; if a real expiry
// happens the user re-runs --qoder-login.
func (e *QoderExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("qoder executor: auth is nil")
	}
	return auth, nil
}

// HttpRequest injects Qoder COSY authentication into the HTTP request and executes it
func (e *QoderExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	creds := qoderCreds(auth)
	if creds.accessToken == "" {
		return nil, fmt.Errorf("qoder executor: missing access token in auth metadata")
	}

	// Read request body for COSY signing
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	headers, err := qoderauth.BuildAuthHeaders(
		bodyBytes,
		req.URL.String(),
		qoderauth.CosyCredentials{
			UserID:    creds.uid,
			AuthToken: creds.accessToken,
			Name:      creds.name,
			Email:     creds.email,
			MachineID: creds.machineID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build COSY auth: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	headers.Apply(req)

	req = req.WithContext(ctx)
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(req)
}

// buildQoderModelConfig returns the model_config block for a chat request.
// It checks three sources in order:
//  1. QoderTokenStorage cache (when auth.Storage happens to be the right type)
//  2. Package-level cache populated by FetchQoderModels
//  3. A sensible default config (matches upstream Ve-ria-Plus behavior)
//
// The default fallback ensures chat requests work even before the model list
// has been fetched — Ve-ria-Plus never validates model_config at all.
func buildQoderModelConfig(auth *cliproxyauth.Auth, modelKey string) (map[string]interface{}, error) {
	// 1. Try QoderTokenStorage if available (works for filestore-loaded auths)
	if auth != nil {
		if storage, ok := auth.Storage.(*qoderauth.QoderTokenStorage); ok && storage != nil {
			if raw, found := storage.GetModelConfig(modelKey); found && len(raw) > 0 {
				var cfg map[string]interface{}
				if err := json.Unmarshal(raw, &cfg); err == nil && cfg != nil {
					cfg["key"] = modelKey
					return cfg, nil
				}
			}
		}
	}

	// 2. Try package-level cache (keyed by display_name; falls back to server key scan)
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	qoderModelConfigCacheMu.RLock()
	if authConfigs, ok := qoderModelConfigCache[authID]; ok {
		// Direct lookup (display_name) then server key scan
		raw, found := authConfigs[modelKey]
		if !found || len(raw) == 0 {
			raw, found = qoderauth.FindConfigByServerKey(authConfigs, modelKey)
		}
		qoderModelConfigCacheMu.RUnlock()
		if found && len(raw) > 0 {
			var cfg map[string]interface{}
			if err := json.Unmarshal(raw, &cfg); err == nil && cfg != nil {
				cfg["key"] = modelKey
				return cfg, nil
			}
		}
	} else {
		qoderModelConfigCacheMu.RUnlock()
	}

	// 3. Return a default config (upstream Ve-ria-Plus sends hardcoded defaults)
	return map[string]interface{}{
		"key":              modelKey,
		"display_name":     modelKey,
		"model":            "",
		"format":           "openai",
		"is_vl":            true,
		"is_reasoning":     false,
		"api_key":          "",
		"url":              "",
		"source":           "system",
		"max_input_tokens": 180000,
	}, nil
}

// FetchQoderModels retrieves the live model list from Qoder's
// /algo/api/v2/model/list endpoint and converts it into ModelInfo entries.
// Falls back to the static registry if the auth lacks credentials, the request
// fails, or the response is malformed. Mirrors the FetchKiloModels /
// FetchCursorModels pattern used by other dynamic providers.
func FetchQoderModels(ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) []*registry.ModelInfo {
	creds := qoderCreds(auth)
	if creds.accessToken == "" {
		log.Debug("qoder: no token, returning static models")
		return registry.GetQoderModels()
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	headers, err := qoderauth.BuildAuthHeaders(nil, qoderauth.QoderModelListURL, qoderauth.CosyCredentials{
		UserID:    creds.uid,
		AuthToken: creds.accessToken,
		Name:      creds.name,
		Email:     creds.email,
		MachineID: creds.machineID,
	})
	if err != nil {
		log.Warnf("qoder: build cosy headers for model list: %v", err)
		return registry.GetQoderModels()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, qoderauth.QoderModelListURL, nil)
	if err != nil {
		log.Warnf("qoder: build model list request: %v", err)
		return registry.GetQoderModels()
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	headers.Apply(req)

	httpClient := helps.NewProxyAwareHTTPClient(ctx, cfg, auth, 0)
	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Warnf("qoder: model list fetch canceled: %v", err)
		} else {
			log.Warnf("qoder: model list fetch failed: %v", err)
		}
		return registry.GetQoderModels()
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Warnf("qoder: read model list response: %v", err)
		return registry.GetQoderModels()
	}
	if resp.StatusCode != http.StatusOK {
		log.Warnf("qoder: model list returned %d: %s", resp.StatusCode, truncate(string(body), 300))
		return registry.GetQoderModels()
	}

	log.Debugf("qoder: model list response (%d bytes): %.500s", len(body), string(body))

	// The server returns a scene-keyed object, e.g.:
	//   {"assistant": [...models...], "code": [...models...], ...}
	// We iterate every top-level key whose value is an array and merge
	// all models across scenes, deduplicating by model key.
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		log.Warnf("qoder: model list response is not a JSON object, got %s", truncate(string(body), 200))
		return registry.GetQoderModels()
	}

	now := time.Now().Unix()
	models := make([]*registry.ModelInfo, 0, 16)
	configs := make(map[string]json.RawMessage, 16)
	seenKeys := make(map[string]bool, 16)
	root.ForEach(func(sceneKey, sceneVal gjson.Result) bool {
		if !sceneVal.IsArray() {
			return true // skip non-array top-level keys
		}
		sceneVal.ForEach(func(_, entry gjson.Result) bool {
			key := entry.Get("key").String()
			if key == "" {
				return true
			}
			if !entry.Get("enable").Bool() {
				return true
			}
			if seenKeys[key] {
				return true // deduplicate across scenes
			}
			seenKeys[key] = true

			display := entry.Get("display_name").String()
			if display == "" {
				display = key
			}
			ctxLen := int(entry.Get("max_input_tokens").Int())
			isVL := entry.Get("is_vl").Bool()

			// Cache the raw upstream JSON for this model so ExecuteStream can
			// forward the exact model_config the server published (per-model
			// is_vl / is_reasoning / max_input_tokens / price_factor / ...).
			// Keyed by display_name for human-readable auth files; server key
			// lookup is handled by FindConfigByServerKey.
			configs[display] = json.RawMessage(entry.Raw)

			mi := &registry.ModelInfo{
				ID:            "qoder/" + key,
				Object:        "model",
				Created:       now,
				OwnedBy:       "qoder",
				Type:          "qoder",
				DisplayName:   display,
				Description:   fmt.Sprintf("%s via Qoder", display),
				ContextLength: ctxLen,
			}
			if isVL {
				mi.SupportedInputModalities = []string{"TEXT", "IMAGE"}
			}
			// Parse thinking_config from upstream. Qoder returns per-model
			// effort levels (e.g. dmodel has only high/max, ultimate has
			// low/medium/high/max/xhigh) and a disabled key to indicate
			// whether reasoning can be turned off. Models without
			// thinking_config but with is_reasoning=true still get a
			// basic Thinking marker (no predefined levels).
			if tc := entry.Get("thinking_config"); tc.Exists() {
				ts := &registry.ThinkingSupport{}
				if tc.Get("disabled").Exists() {
					ts.ZeroAllowed = true
				}
				efforts := tc.Get("enabled.efforts")
				if efforts.Exists() && efforts.IsObject() {
					levels := make([]string, 0, 5)
					efforts.ForEach(func(key, _ gjson.Result) bool {
						levels = append(levels, key.String())
						return true
					})
					ts.Levels = levels
				}
				mi.Thinking = ts
			} else if entry.Get("is_reasoning").Bool() {
				mi.Thinking = &registry.ThinkingSupport{}
			}
			models = append(models, mi)
			return true
		})
		return true
	})

	if len(models) == 0 {
		log.Warn("qoder: model list returned no enabled models, falling back to static")
		return registry.GetQoderModels()
	}

	// Cache model configs at package level (no Storage dependency)
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	qoderModelConfigCacheMu.Lock()
	qoderModelConfigCache[authID] = configs
	qoderModelConfigCacheMu.Unlock()

	// Also update QoderTokenStorage if available (for backward compat)
	if storage, ok := auth.Storage.(*qoderauth.QoderTokenStorage); ok && storage != nil {
		storage.SetModelConfigs(configs)
	}

	log.Infof("qoder: fetched %d models from /algo/api/v2/model/list", len(models))
	// Log server keys for debugging (verify which keys the server actually uses)
	serverKeys := make([]string, 0, len(models))
	for _, mi := range models {
		serverKeys = append(serverKeys, strings.TrimPrefix(mi.ID, "qoder/"))
	}
	log.Infof("qoder: server keys: %v", serverKeys)

	// Fetch usage alongside models so the management UI has fresh credit data.
	// Use context.Background() so the goroutine outlives the caller's context.
	go FetchQoderUsage(context.Background(), auth, cfg)

	return models
}

// stableHash returns a deterministic hex identifier from the given inputs.
func stableHash(prefix string, inputs ...string) string {
	h := sha256.New()
	h.Write([]byte(prefix))
	for _, in := range inputs {
		h.Write([]byte{0})
		h.Write([]byte(in))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// stableChatRecordID produces a deterministic chat_record_id from the
// request payload so retries with identical content hit upstream caches.
func stableChatRecordID(model string, messages []interface{}, toolsRaw interface{}, maxTokens int) string {
	h := sha256.New()
	h.Write([]byte("qoder-record"))
	h.Write([]byte{0})
	h.Write([]byte(model))
	for _, msg := range messages {
		m, _ := msg.(map[string]interface{})
		if m == nil {
			continue
		}
		if role, _ := m["role"].(string); role != "" {
			h.Write([]byte{0})
			h.Write([]byte(role))
		}
		if content, _ := m["content"].(string); content != "" {
			h.Write([]byte{0})
			h.Write([]byte(content))
		}
	}
	if toolsRaw != nil {
		toolsJSON, _ := json.Marshal(toolsRaw)
		h.Write([]byte{0})
		h.Write(toolsJSON)
	}
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("mt=%d", maxTokens)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// FetchQoderUsage fetches the current quota usage from /api/v2/quota/usage
// and caches the result in the package-level usage cache. It is called
// opportunistically alongside FetchQoderModels so the management UI can
// display credit balance without a separate round-trip.
func FetchQoderUsage(ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) *qoderauth.QoderUsageInfo {
	creds := qoderCreds(auth)
	if creds.accessToken == "" {
		return nil
	}

	const usageURL = "https://openapi.qoder.sh/api/v2/quota/usage"
	log.Debugf("qoder: fetching usage for user %s (token len=%d)", creds.uid, len(creds.accessToken))
	req, err := http.NewRequest(http.MethodGet, usageURL, nil)
	if err != nil {
		log.Debugf("qoder: build usage request: %v", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+creds.accessToken)
	req.Header.Set("Accept", "application/json")

	httpClient := helps.NewProxyAwareHTTPClient(ctx, cfg, auth, 15*time.Second)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Debugf("qoder: usage fetch failed: %v", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		log.Debugf("qoder: usage fetch returned %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("qoder: read usage response: %v", err)
		return nil
	}

	var info qoderauth.QoderUsageInfo
	if err := json.Unmarshal(body, &info); err != nil {
		log.Debugf("qoder: parse usage response: %v", err)
		return nil
	}

	// Cache at package level
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	qoderUsageCacheMu.Lock()
	qoderUsageCache[authID] = &info
	qoderUsageCacheMu.Unlock()

	// Also update QoderTokenStorage if available (for backward compat)
	if storage, ok := auth.Storage.(*qoderauth.QoderTokenStorage); ok && storage != nil {
		storage.SetUsageInfo(&info)
	}

	log.Debugf("qoder: usage fetched — %.0f/%.0f %s used (%.1f%%)",
		info.UserQuota.Used, info.UserQuota.Total, info.UserQuota.Unit,
		info.TotalUsagePercentage*100)
	return &info
}
