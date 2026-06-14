package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codebuddy"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const codeBuddyChatPath = "/v2/chat/completions"

type CodeBuddyExecutor struct{ cfg *config.Config }

func NewCodeBuddyExecutor(cfg *config.Config) *CodeBuddyExecutor { return &CodeBuddyExecutor{cfg: cfg} }
func (e *CodeBuddyExecutor) Identifier() string                  { return "codebuddy" }

func codeBuddyCredentials(auth *cliproxyauth.Auth) (accessToken, refreshToken, userID, domain string) {
	if auth == nil {
		return
	}
	accessToken = metaStringValue(auth.Metadata, "access_token")
	refreshToken = metaStringValue(auth.Metadata, "refresh_token")
	userID = metaStringValue(auth.Metadata, "user_id")
	domain = metaStringValue(auth.Metadata, "domain")
	if domain == "" {
		domain = codebuddy.DefaultDomain
	}
	return
}

func (e *CodeBuddyExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	accessToken, _, userID, domain := codeBuddyCredentials(auth)
	if accessToken == "" {
		return fmt.Errorf("codebuddy: missing access token")
	}
	e.applyHeaders(req, accessToken, userID, domain)
	return nil
}

func (e *CodeBuddyExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("codebuddy executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	return helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
}

func (e *CodeBuddyExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	body, baseModel, from, to, err := e.preparePayload(req, opts, true)
	if err != nil {
		return resp, err
	}
	// CodeBuddy rejects non-streaming (stream:false) with HTTP 400
	// code 400001 "Invalid request parameters". Force SSE and aggregate.
	body, err = sjson.SetBytes(body, "stream", true)
	if err != nil {
		return resp, err
	}
	body, err = sjson.SetBytes(body, "stream_options.include_usage", true)
	if err != nil {
		return resp, err
	}
	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)
	data, headers, err := e.do(ctx, auth, body, true)
	if err != nil {
		return resp, err
	}
	aggregated, usageDetail, err := aggregateOpenAIChatCompletionStream(data)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	reporter.Publish(ctx, usageDetail)
	reporter.EnsurePublished(ctx)
	var param any
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, opts.OriginalRequest, body, aggregated, &param)
	return cliproxyexecutor.Response{Payload: out, Headers: headers}, nil
}

func (e *CodeBuddyExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	body, baseModel, from, to, err := e.preparePayload(req, opts, true)
	if err != nil {
		return nil, err
	}
	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)
	body, err = sjson.SetBytes(body, "stream_options.include_usage", true)
	if err != nil {
		return nil, err
	}
	resp, err := e.doRequest(ctx, auth, body, true)
	if err != nil {
		return nil, err
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := resp.Body.Close(); errClose != nil {
				log.Errorf("codebuddy executor: close stream body error: %v", errClose)
			}
		}()
		var param any
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(nil, 52_428_800)
		for scanner.Scan() {
			line := bytes.Clone(scanner.Bytes())
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			if detail, ok := helps.ParseOpenAIStreamUsage(line); ok {
				reporter.Publish(ctx, detail)
			}
			if len(line) == 0 {
				continue
			}
			if cleaned := cleanDeltaChunk(line); cleaned == nil {
				continue
			} else {
				line = cleaned
			}
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, opts.OriginalRequest, body, line, &param)
			for _, chunk := range chunks {
				out <- cliproxyexecutor.StreamChunk{Payload: chunk}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx)
			out <- cliproxyexecutor.StreamChunk{Err: errScan}
		}
		reporter.EnsurePublished(ctx)
	}()
	return &cliproxyexecutor.StreamResult{Headers: resp.Header.Clone(), Chunks: out}, nil
}

func (e *CodeBuddyExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if auth == nil {
		return nil, fmt.Errorf("codebuddy: missing auth")
	}
	accessToken, refreshToken, userID, domain := codeBuddyCredentials(auth)
	if refreshToken == "" {
		return auth, nil
	}
	storage, err := codebuddy.NewCodeBuddyAuth(e.cfg).RefreshToken(ctx, accessToken, refreshToken, userID, domain)
	if err != nil {
		return nil, fmt.Errorf("codebuddy: token refresh failed: %w", err)
	}
	updated := auth.Clone()
	updated.Metadata["access_token"] = storage.AccessToken
	updated.Metadata["refresh_token"] = storage.RefreshToken
	updated.Metadata["expires_in"] = storage.ExpiresIn
	updated.Metadata["domain"] = storage.Domain
	updated.Metadata["user_id"] = storage.UserID
	now := time.Now()
	updated.UpdatedAt = now
	updated.LastRefreshedAt = now
	return updated, nil
}

func (e *CodeBuddyExecutor) CountTokens(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, fmt.Errorf("codebuddy: count tokens not supported")
}

func (e *CodeBuddyExecutor) preparePayload(req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) ([]byte, string, sdktranslator.Format, sdktranslator.Format, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName
	from := opts.SourceFormat
	to := sdktranslator.FormatOpenAI
	original := req.Payload
	if len(opts.OriginalRequest) > 0 {
		original = opts.OriginalRequest
	}
	originalTranslated := sdktranslator.TranslateRequest(from, to, baseModel, bytes.Clone(original), stream)
	body := sdktranslator.TranslateRequest(from, to, baseModel, bytes.Clone(req.Payload), stream)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, helps.PayloadRequestedModel(opts, req.Model), helps.PayloadRequestPath(opts), opts.Headers)
	var err error
	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	return body, baseModel, from, to, err
}

func (e *CodeBuddyExecutor) do(ctx context.Context, auth *cliproxyauth.Auth, body []byte, stream bool) ([]byte, http.Header, error) {
	resp, err := e.doRequest(ctx, auth, body, stream)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("codebuddy executor: close body error: %v", errClose)
		}
	}()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, nil, err
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, data)
	return data, resp.Header.Clone(), nil
}

func (e *CodeBuddyExecutor) doRequest(ctx context.Context, auth *cliproxyauth.Auth, body []byte, stream bool) (*http.Response, error) {
	accessToken, _, userID, domain := codeBuddyCredentials(auth)
	if accessToken == "" {
		return nil, fmt.Errorf("codebuddy: missing access token")
	}
	url := codebuddy.BaseURL + codeBuddyChatPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	e.applyHeaders(httpReq, accessToken, userID, domain)
	if stream {
		httpReq.Header.Set("Accept", "text/event-stream")
		httpReq.Header.Set("Cache-Control", "no-cache")
	}
	helpRecordRequest(ctx, e.cfg, e.Identifier(), auth, url, body, httpReq.Header)
	resp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, resp.StatusCode, resp.Header.Clone())
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		return nil, statusErr{code: resp.StatusCode, msg: string(b)}
	}
	return resp, nil
}

func (e *CodeBuddyExecutor) applyHeaders(req *http.Request, accessToken, userID, domain string) {
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", codebuddy.UserAgent)
	req.Header.Set("X-User-Id", userID)
	if domain == "" {
		domain = codebuddy.DefaultDomain
	}
	req.Header.Set("X-Domain", domain)
	req.Header.Set("X-Product", "SaaS")
	req.Header.Set("X-IDE-Type", "CodeBuddyIDE")
	req.Header.Set("X-IDE-Name", "CodeBuddyIDE")
	req.Header.Set("X-IDE-Version", "4.9.7")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
}

func helpRecordRequest(ctx context.Context, cfg *config.Config, provider string, auth *cliproxyauth.Auth, url string, body []byte, headers http.Header) {
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   headers.Clone(),
		Body:      body,
		Provider:  provider,
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
}

// ---------------------------------------------------------------------------
// Streaming helpers: delta cleaning and SSE aggregation
// ---------------------------------------------------------------------------

// cleanDeltaChunk processes a single SSE JSON chunk for CodeBuddy streaming.
// It returns:
//   - nil: chunk should be dropped (no meaningful content)
//   - modified bytes: chunk cleaned up (e.g. empty reasoning_content removed)
//   - original bytes: chunk passed through as-is
//
// The CodeBuddy upstream sends reasoning_content:"" alongside non-empty content
// during the thinking-to-content transition.  Many clients interpret
// reasoning_content:"" as "thinking ended", then see the next chunk's
// reasoning_content:"" again and think "thinking restarted".  By stripping the
// empty reasoning_content field, the client never sees spurious thinking
// transitions.
func cleanDeltaChunk(raw []byte) []byte {
	delta := gjson.GetBytes(raw, "choices.0.delta")
	if !delta.Exists() {
		return raw
	}
	finishReason := gjson.GetBytes(raw, "choices.0.finish_reason").String()
	if finishReason == "stop" || finishReason == "tool_calls" {
		return raw
	}
	content := delta.Get("content").String()
	reasoning := delta.Get("reasoning_content").String()
	hasRole := delta.Get("role").Exists()
	toolCalls := delta.Get("tool_calls")
	hasToolCalls := toolCalls.Exists() && len(toolCalls.Array()) > 0
	if content == "" && reasoning == "" && !hasRole && !hasToolCalls {
		return nil
	}
	if reasoning == "" && content != "" {
		if cleaned, err := sjson.DeleteBytes(raw, "choices.0.delta.reasoning_content"); err == nil {
			return cleaned
		}
	}
	return raw
}

type openAIChatStreamChoiceAccumulator struct {
	Role             string
	ContentParts     []string
	ReasoningParts   []string
	FinishReason     string
	NativeFinishReason any
	ToolCalls        map[int]*openAIChatStreamToolCallAccumulator
	ToolCallOrder    []int
}

type openAIChatStreamToolCallAccumulator struct {
	ID        string
	Type      string
	Name      string
	Arguments strings.Builder
}

// aggregateOpenAIChatCompletionStream takes raw SSE stream bytes and produces
// a single chat.completion JSON response.  This is used by the non-streaming
// Execute path which sends stream:true upstream and aggregates the result.
func aggregateOpenAIChatCompletionStream(raw []byte) ([]byte, usage.Detail, error) {
	lines := bytes.Split(raw, []byte("\n"))
	var (
		responseID  string
		model       string
		created     int64
		serviceTier string
		systemFP    string
		usageDetail usage.Detail
		choices     = map[int]*openAIChatStreamChoiceAccumulator{}
		choiceOrder []int
	)

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[5:])
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		if !gjson.ValidBytes(payload) {
			continue
		}

		root := gjson.ParseBytes(payload)
		if responseID == "" {
			responseID = root.Get("id").String()
		}
		if model == "" {
			model = root.Get("model").String()
		}
		if created == 0 {
			created = root.Get("created").Int()
		}
		if serviceTier == "" {
			serviceTier = root.Get("service_tier").String()
		}
		if systemFP == "" {
			systemFP = root.Get("system_fingerprint").String()
		}
		if detail, ok := helps.ParseOpenAIStreamUsage(line); ok {
			usageDetail = detail
		}

		for _, choiceResult := range root.Get("choices").Array() {
			idx := int(choiceResult.Get("index").Int())
			choice := choices[idx]
			if choice == nil {
				choice = &openAIChatStreamChoiceAccumulator{ToolCalls: map[int]*openAIChatStreamToolCallAccumulator{}}
				choices[idx] = choice
				choiceOrder = append(choiceOrder, idx)
			}

			delta := choiceResult.Get("delta")
			if role := delta.Get("role").String(); role != "" {
				choice.Role = role
			}
			if content := delta.Get("content").String(); content != "" {
				choice.ContentParts = append(choice.ContentParts, content)
			}
			if reasoning := delta.Get("reasoning_content").String(); reasoning != "" {
				choice.ReasoningParts = append(choice.ReasoningParts, reasoning)
			}
			if finishReason := choiceResult.Get("finish_reason").String(); finishReason != "" {
				choice.FinishReason = finishReason
			}
			if nativeFinishReason := choiceResult.Get("native_finish_reason"); nativeFinishReason.Exists() {
				choice.NativeFinishReason = nativeFinishReason.Value()
			}

			for _, toolCallResult := range delta.Get("tool_calls").Array() {
				toolIdx := int(toolCallResult.Get("index").Int())
				toolCall := choice.ToolCalls[toolIdx]
				if toolCall == nil {
					toolCall = &openAIChatStreamToolCallAccumulator{}
					choice.ToolCalls[toolIdx] = toolCall
					choice.ToolCallOrder = append(choice.ToolCallOrder, toolIdx)
				}
				if id := toolCallResult.Get("id").String(); id != "" {
					toolCall.ID = id
				}
				if typ := toolCallResult.Get("type").String(); typ != "" {
					toolCall.Type = typ
				}
				if name := toolCallResult.Get("function.name").String(); name != "" {
					toolCall.Name = name
				}
				if args := toolCallResult.Get("function.arguments").String(); args != "" {
					toolCall.Arguments.WriteString(args)
				}
			}
		}
	}

	if responseID == "" && model == "" && len(choiceOrder) == 0 {
		return nil, usageDetail, fmt.Errorf("codebuddy: streaming response did not contain any chat completion chunks")
	}

	response := map[string]any{
		"id":      responseID,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": make([]map[string]any, 0, len(choiceOrder)),
		"usage": map[string]any{
			"prompt_tokens":     usageDetail.InputTokens,
			"completion_tokens": usageDetail.OutputTokens,
			"total_tokens":      usageDetail.TotalTokens,
		},
	}
	if serviceTier != "" {
		response["service_tier"] = serviceTier
	}
	if systemFP != "" {
		response["system_fingerprint"] = systemFP
	}

	for _, idx := range choiceOrder {
		choice := choices[idx]
		message := map[string]any{
			"role":    choice.Role,
			"content": strings.Join(choice.ContentParts, ""),
		}
		if message["role"] == "" {
			message["role"] = "assistant"
		}
		if len(choice.ReasoningParts) > 0 {
			message["reasoning_content"] = strings.Join(choice.ReasoningParts, "")
		}
		if len(choice.ToolCallOrder) > 0 {
			toolCalls := make([]map[string]any, 0, len(choice.ToolCallOrder))
			for _, toolIdx := range choice.ToolCallOrder {
				toolCall := choice.ToolCalls[toolIdx]
				toolCallType := toolCall.Type
				if toolCallType == "" {
					toolCallType = "function"
				}
				arguments := toolCall.Arguments.String()
				if arguments == "" {
					arguments = "{}"
				}
				toolCalls = append(toolCalls, map[string]any{
					"id":   toolCall.ID,
					"type": toolCallType,
					"function": map[string]any{
						"name":      toolCall.Name,
						"arguments": arguments,
					},
				})
			}
			message["tool_calls"] = toolCalls
		}

		finishReason := choice.FinishReason
		if finishReason == "" {
			finishReason = "stop"
		}
		choicePayload := map[string]any{
			"index":         idx,
			"message":       message,
			"finish_reason": finishReason,
		}
		if choice.NativeFinishReason != nil {
			choicePayload["native_finish_reason"] = choice.NativeFinishReason
		}
		response["choices"] = append(response["choices"].([]map[string]any), choicePayload)
	}

	out, err := json.Marshal(response)
	if err != nil {
		return nil, usageDetail, fmt.Errorf("codebuddy: failed to encode aggregated response: %w", err)
	}
	return out, usageDetail, nil
}

// ---------------------------------------------------------------------------
// Dynamic model fetching from CodeBuddy config API
// ---------------------------------------------------------------------------

// codeBuddyInternalModelPrefixes are model ID prefixes that correspond to
// internal / platform models that should not be exposed to end users.
var codeBuddyInternalModelPrefixes = []string{
	"completion-",
	"codewise-",
	"hunyuan-3b",
	"hunyuan-7b",
	"nes-",
	"default-",
	"chat-",
	"hunyuan-image-",
}

// codeBuddyAllowedInternalModels is an allowlist of internal-prefixed models
// that are still useful when exposed through the proxy.
var codeBuddyAllowedInternalModels = map[string]bool{
	"deepseek-r1-0528":                 true,
	"deepseek-r1-0528-lkeap":           true,
	"deepseek-v3-0324":                 true,
	"deepseek-v3-0324-lkeap":           true,
	"deepseek-v3-0324-taco-completion": true,
	"hunyuan-2.0-instruct":             true,
	"hunyuan-chat":                     true,
	"glm-4.6":                          true,
	"glm-4.6v":                         true,
	"glm-4.7":                          true,
	"glm-5.0":                          true,
	"deepseek-v3-1":                    true,
	"deepseek-v3-1-lkeap":              true,
	"deepseek-v3-1-volc":               true,
	"kimi-k2-instruct-taiji":           true,
	"kimi-k2-thinking":                 true,
	"minimax-m2.5":                     true,
}

func isCodeBuddyInternalModel(id string) bool {
	for _, prefix := range codeBuddyInternalModelPrefixes {
		if strings.HasPrefix(id, prefix) {
			return !codeBuddyAllowedInternalModels[id]
		}
	}
	return false
}

// FetchCodeBuddyModels tries to retrieve the current model catalogue from the
// CodeBuddy config API (/v3/config).  On any failure it falls back to the
// static models embedded in the binary via registry.GetCodeBuddyModels().
func FetchCodeBuddyModels(ctx context.Context, auth *cliproxyauth.Auth, cfg *config.Config) []*registry.ModelInfo {
	accessToken, _, userID, domain := codeBuddyCredentials(auth)
	if accessToken == "" {
		log.Infof("codebuddy: no access token found, using static model list")
		return registry.GetCodeBuddyModels()
	}

	log.Debugf("codebuddy: fetching dynamic models from config API")

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	httpClient := helps.NewProxyAwareHTTPClient(ctx, cfg, auth, 0)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, codebuddy.BaseURL+"/v3/config", nil)
	if err != nil {
		log.Warnf("codebuddy: failed to create config request: %v", err)
		return registry.GetCodeBuddyModels()
	}

	req.Header.Set("User-Agent", codebuddy.UserAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-IDE-Type", "CodeBuddyIDE")
	req.Header.Set("X-IDE-Name", "CodeBuddyIDE")
	req.Header.Set("X-IDE-Version", "4.9.7")
	req.Header.Set("X-Product-Version", "4.9.7")
	req.Header.Set("X-Env-ID", "production")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-User-Id", userID)
	req.Header.Set("X-Domain", domain)
	req.Header.Set("X-Product", "SaaS")
	req.Header.Set("Connection", "close")

	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Warnf("codebuddy: fetch models canceled: %v", err)
		} else {
			log.Warnf("codebuddy: using static models (config API fetch failed: %v)", err)
		}
		return registry.GetCodeBuddyModels()
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("codebuddy: close config response body error: %v", errClose)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Warnf("codebuddy: failed to read config response: %v", err)
		return registry.GetCodeBuddyModels()
	}

	if resp.StatusCode != http.StatusOK {
		log.Warnf("codebuddy: config API returned status %d", resp.StatusCode)
		return registry.GetCodeBuddyModels()
	}

	modelsResult := gjson.GetBytes(body, "data.models")
	if !modelsResult.Exists() || !modelsResult.IsArray() {
		log.Warn("codebuddy: config API response missing data.models array")
		return registry.GetCodeBuddyModels()
	}

	var dynamicModels []*registry.ModelInfo
	now := time.Now().Unix()
	count := 0

	modelsResult.ForEach(func(_, value gjson.Result) bool {
		id := value.Get("id").String()
		if id == "" {
			return true
		}

		if isCodeBuddyInternalModel(id) {
			return true
		}

		name := value.Get("name").String()
		if name == "" {
			name = id
		}

		descZh := value.Get("descriptionZh").String()
		descEn := value.Get("descriptionEn").String()
		desc := descEn
		if desc == "" {
			desc = descZh
		}
		if desc == "" {
			desc = name + " via CodeBuddy"
		}

		maxInputTokens := int(value.Get("maxInputTokens").Int())
		maxOutputTokens := int(value.Get("maxOutputTokens").Int())
		maxAllowedSize := int(value.Get("maxAllowedSize").Int())

		contextLength := maxInputTokens
		if contextLength <= 0 && maxAllowedSize > 0 {
			contextLength = maxAllowedSize
		}
		if contextLength <= 0 {
			contextLength = 128000
		}
		if maxOutputTokens <= 0 {
			maxOutputTokens = 32768
		}

		supportsReasoning := value.Get("supportsReasoning").Bool()
		onlyReasoning := value.Get("onlyReasoning").Bool()

		supportedModalities := []string{"TEXT"}
		if value.Get("supportsImages").Bool() && !value.Get("disabledMultimodal").Bool() {
			supportedModalities = append(supportedModalities, "IMAGE")
		}

		var thinkingSupport *registry.ThinkingSupport
		if supportsReasoning || onlyReasoning {
			thinkingSupport = &registry.ThinkingSupport{ZeroAllowed: true}
			reasoningEffort := value.Get("reasoning.effort").String()
			if reasoningEffort == "medium" || reasoningEffort == "high" {
				thinkingSupport.DynamicAllowed = true
			}
		}

		dynamicModels = append(dynamicModels, &registry.ModelInfo{
			ID:                       id,
			Object:                   "model",
			Created:                  now,
			OwnedBy:                  "tencent",
			Type:                     "codebuddy",
			DisplayName:              name,
			Description:              desc,
			ContextLength:            contextLength,
			MaxCompletionTokens:      maxOutputTokens,
			Thinking:                 thinkingSupport,
			SupportedInputModalities: supportedModalities,
		})
		count++
		return true
	})

	log.Infof("codebuddy: fetched %d models from config API", count)
	if count == 0 {
		log.Warn("codebuddy: no models parsed from config API, using static fallback")
		return registry.GetCodeBuddyModels()
	}

	return dynamicModels
}
