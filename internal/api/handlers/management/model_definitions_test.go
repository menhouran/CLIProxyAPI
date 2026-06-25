package management

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

func TestApplyModelAlias_Scenarios(t *testing.T) {
	cfg := &config.Config{
		OAuthModelAlias: map[string][]config.OAuthModelAlias{
			"codebuddy": {
				{Name: "minimax-m3", Alias: "deepseek-v4-flash"},
			},
			"qoder": {
				{Name: "qoder/qmodel_latest", Alias: "qwen3.7-max"},
			},
		},
	}

	t.Run("codebuddy hide original", func(t *testing.T) {
		models := []*registry.ModelInfo{
			{ID: "minimax-m3", DisplayName: "MiniMax M3"},
			{ID: "other-model", DisplayName: "Other"},
		}
		result := applyModelAlias(cfg, "codebuddy", models)
		if len(result) != 2 {
			t.Fatalf("expected 2 models, got %d", len(result))
		}
		foundAlias := false
		foundOriginal := false
		for _, m := range result {
			if m.ID == "deepseek-v4-flash" {
				foundAlias = true
			}
			if m.ID == "minimax-m3" {
				foundOriginal = true
			}
		}
		if !foundAlias {
			t.Error("alias deepseek-v4-flash not found")
		}
		if foundOriginal {
			t.Error("original minimax-m3 should be hidden")
		}
	})

	t.Run("qoder hide original", func(t *testing.T) {
		models := []*registry.ModelInfo{
			{ID: "qoder/qmodel_latest", DisplayName: "Qwen3.7 Max"},
		}
		result := applyModelAlias(cfg, "qoder", models)
		if len(result) != 1 {
			t.Fatalf("expected 1 model, got %d", len(result))
		}
		if result[0].ID != "qwen3.7-max" {
			t.Errorf("expected id qwen3.7-max, got %s", result[0].ID)
		}
	})

	t.Run("codebuddy alias target already exists in list", func(t *testing.T) {
		// User aliases minimax-m3 -> deepseek-v4-flash, but deepseek-v4-flash
		// is already a separate entry. Expected: minimax-m3 is hidden, only
		// the existing deepseek-v4-flash remains (no duplicate).
		models := []*registry.ModelInfo{
			{ID: "auto", DisplayName: "Auto"},
			{ID: "deepseek-v4-pro", DisplayName: "DeepSeek V4 Pro"},
			{ID: "deepseek-v4-flash", DisplayName: "DeepSeek V4 Flash"},
			{ID: "minimax-m3", DisplayName: "MiniMax M3"},
			{ID: "glm-5.1", DisplayName: "GLM-5.1"},
		}
		result := applyModelAlias(cfg, "codebuddy", models)
		countByID := make(map[string]int)
		for _, m := range result {
			countByID[m.ID]++
		}
		if countByID["minimax-m3"] != 0 {
			t.Errorf("minimax-m3 should be hidden, got count %d", countByID["minimax-m3"])
		}
		if countByID["deepseek-v4-flash"] != 1 {
			t.Errorf("deepseek-v4-flash should appear exactly once, got %d", countByID["deepseek-v4-flash"])
		}
		// Other untouched models still present
		if countByID["auto"] != 1 || countByID["glm-5.1"] != 1 {
			t.Errorf("untouched models should remain, got %v", countByID)
		}
	})

	t.Run("qoder fork preserves both", func(t *testing.T) {
		cfgFork := &config.Config{
			OAuthModelAlias: map[string][]config.OAuthModelAlias{
				"qoder": {
					{Name: "qoder/qmodel_latest", Alias: "qwen3.7-max", Fork: true},
				},
			},
		}
		models := []*registry.ModelInfo{
			{ID: "qoder/qmodel_latest", DisplayName: "Qwen3.7 Max"},
		}
		result := applyModelAlias(cfgFork, "qoder", models)
		if len(result) != 2 {
			t.Fatalf("expected 2 models, got %d", len(result))
		}
	})
}
