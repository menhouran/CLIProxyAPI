package auth

// ProviderInfo describes an OAuth provider for the management UI.
type ProviderInfo struct {
	Key             string   `json:"key"`
	DisplayName     string   `json:"display_name"`
	FlowType        string   `json:"flow_type"`
	AuthURLEndpoint string   `json:"auth_url_endpoint"`
	Aliases         []string `json:"aliases,omitempty"`
	Configured      bool     `json:"configured"`
}

// providerMetadata is the canonical list of known OAuth providers.
// It is consulted by ListProviders to serve GET /v0/management/oauth-providers.
// Add new providers here so the management SPA can show their model-disable-list UI.
var providerMetadata = map[string]ProviderInfo{
	"claude": {
		Key:             "claude",
		DisplayName:     "Claude (Anthropic)",
		FlowType:        "authorization_code_pkce",
		AuthURLEndpoint: "/anthropic-auth-url",
		Aliases:         []string{"anthropic"},
	},
	"codex": {
		Key:             "codex",
		DisplayName:     "Codex (OpenAI)",
		FlowType:        "authorization_code_pkce",
		AuthURLEndpoint: "/codex-auth-url",
		Aliases:         []string{"openai"},
	},
	"gemini": {
		Key:             "gemini",
		DisplayName:     "Gemini CLI",
		FlowType:        "google_oauth2",
		AuthURLEndpoint: "/gemini-cli-auth-url",
		Aliases:         []string{"google"},
	},
	"antigravity": {
		Key:             "antigravity",
		DisplayName:     "Antigravity",
		FlowType:        "google_oauth2",
		AuthURLEndpoint: "/antigravity-auth-url",
		Aliases:         []string{"anti-gravity"},
	},
	"kimi": {
		Key:             "kimi",
		DisplayName:     "Kimi",
		FlowType:        "device_code",
		AuthURLEndpoint: "/kimi-auth-url",
	},
	"xai": {
		Key:             "xai",
		DisplayName:     "X AI (Grok)",
		FlowType:        "authorization_code_pkce",
		AuthURLEndpoint: "/xai-auth-url",
		Aliases:         []string{"grok", "x-ai", "x.ai"},
	},
	"codebuddy": {
		Key:             "codebuddy",
		DisplayName:     "CodeBuddy",
		FlowType:        "token",
		AuthURLEndpoint: "",
	},
	"codebuddy-ai": {
		Key:             "codebuddy-ai",
		DisplayName:     "CodeBuddy AI",
		FlowType:        "token",
		AuthURLEndpoint: "",
	},
	"qoder": {
		Key:             "qoder",
		DisplayName:     "Qoder",
		FlowType:        "pkce_custom_uri",
		AuthURLEndpoint: "/qoder-auth-url",
	},
}
