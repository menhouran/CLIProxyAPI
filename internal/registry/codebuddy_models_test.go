package registry

import "testing"

func TestGetCodeBuddyModelsIncludesVerifiedBuiltIns(t *testing.T) {
	models := GetCodeBuddyModels()
	byID := make(map[string]*ModelInfo, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		if _, exists := byID[model.ID]; exists {
			t.Fatalf("duplicate CodeBuddy model ID %q", model.ID)
		}
		byID[model.ID] = model
	}

	// All models from the live /v3/config catalog (excluding image models and "default")
	expected := []string{
		"auto", "glm-5.2", "deepseek-v4-pro", "deepseek-v4-flash",
		"deepseek-v3-2-volc", "minimax-m3", "minimax-m2.7", "minimax-m2.5",
		"kimi-k2.7", "kimi-k2.6", "kimi-k2.5", "kimi-k2-thinking",
		"hy3-preview", "hunyuan-chat",
	}
	for _, id := range expected {
		if byID[id] == nil {
			t.Fatalf("expected CodeBuddy model %q to be registered", id)
		}
	}

	// These models should advertise thinking support
	thinkingModels := []string{
		"glm-5.2", "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v3-2-volc",
		"minimax-m3", "minimax-m2.7", "minimax-m2.5",
		"kimi-k2.7", "kimi-k2.6", "kimi-k2.5", "kimi-k2-thinking",
		"hy3-preview",
	}
	for _, id := range thinkingModels {
		if byID[id] != nil && byID[id].Thinking == nil {
			t.Fatalf("expected %s to advertise thinking support", id)
		}
	}
}
