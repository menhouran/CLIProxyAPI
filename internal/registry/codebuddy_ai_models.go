package registry

// GetCodeBuddyAIModels returns the available models for CodeBuddy AI (www.codebuddy.ai, 国外版).
// This is a static fallback; the dynamic config API provides the full up-to-date list.
func GetCodeBuddyAIModels() []*ModelInfo {
	now := int64(1748044800)
	return []*ModelInfo{
		{
			ID: "default-model", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Default", Description: "Default model via CodeBuddy AI",
			ContextLength: 128000, MaxCompletionTokens: 32768, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gemini-3.1-pro", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Gemini-3.1-Pro", Description: "Gemini 3.1 Pro via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 65536, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gemini-3.0-flash", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Gemini-3.0-Flash", Description: "Gemini 3.0 Flash via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 65536, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gemini-3.5-flash", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Gemini-3.5-Flash", Description: "Gemini 3.5 Flash via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 65536, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gemini-2.5-pro", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Gemini-2.5-Pro", Description: "Gemini 2.5 Pro via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 65536, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gemini-2.5-flash", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Gemini-2.5-Flash", Description: "Gemini 2.5 Flash via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 65536, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gemini-3.1-flash-lite", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Gemini-3.1-Flash-Lite", Description: "Gemini 3.1 Flash Lite via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 65536, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gpt-5.5", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "GPT-5.5", Description: "GPT-5.5 via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 32768, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gpt-5.4", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "GPT-5.4", Description: "GPT-5.4 via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 32768, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gpt-5.3-codex", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "GPT-5.3-Codex", Description: "GPT-5.3 Codex via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 32768, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gpt-5.1-codex", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "GPT-5.1-Codex", Description: "GPT-5.1 Codex via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 32768, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "gpt-5.1-codex-mini", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "GPT-5.1-Codex-Mini", Description: "GPT-5.1 Codex Mini via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 16384, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "deepseek-v3-2-volc", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "DeepSeek-V3.2", Description: "DeepSeek V3.2 via CodeBuddy AI",
			ContextLength: 128000, MaxCompletionTokens: 32768, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "glm-5.0", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "GLM-5.0", Description: "GLM 5.0 via CodeBuddy AI",
			ContextLength: 200000, MaxCompletionTokens: 48000, SupportedEndpoints: []string{"/chat/completions"},
		},
		{
			ID: "kimi-k2.5", Object: "model", Created: now, OwnedBy: "codebuddy-ai",
			Type: "codebuddy-ai", DisplayName: "Kimi-K2.5", Description: "Kimi K2.5 via CodeBuddy AI",
			ContextLength: 256000, MaxCompletionTokens: 32768, SupportedEndpoints: []string{"/chat/completions"},
		},
	}
}
