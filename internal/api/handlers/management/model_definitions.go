package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

// GetStaticModelDefinitions returns static model metadata for a given channel,
// with OAuthModelAlias applied so configured aliases replace (or fork) originals.
func (h *Handler) GetStaticModelDefinitions(c *gin.Context) {
	channel := strings.TrimSpace(c.Param("channel"))
	if channel == "" {
		channel = strings.TrimSpace(c.Query("channel"))
	}
	if channel == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "channel is required"})
		return
	}

	models := registry.GetStaticModelDefinitionsByChannel(channel)
	if models == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown channel", "channel": channel})
		return
	}

	models = applyModelAlias(h.cfg, channel, models)

	c.JSON(http.StatusOK, gin.H{
		"channel": strings.ToLower(strings.TrimSpace(channel)),
		"models":  models,
	})
}

// applyModelAlias applies OAuthModelAlias name replacements to a model list.
// When fork=true the original model is kept and the alias is added alongside;
// when fork=false (default) the original is replaced by the alias.
func applyModelAlias(cfg *config.Config, channel string, models []*registry.ModelInfo) []*registry.ModelInfo {
	if cfg == nil || len(cfg.OAuthModelAlias) == 0 || len(models) == 0 {
		return models
	}
	channel = strings.ToLower(strings.TrimSpace(channel))
	aliases := cfg.OAuthModelAlias[channel]
	if len(aliases) == 0 {
		return models
	}

	type aliasEntry struct {
		alias string
		fork  bool
	}

	forward := make(map[string][]aliasEntry, len(aliases))
	for _, a := range aliases {
		name := strings.ToLower(strings.TrimSpace(a.Name))
		alias := strings.TrimSpace(a.Alias)
		if name == "" || alias == "" || name == strings.ToLower(alias) {
			continue
		}
		forward[name] = append(forward[name], aliasEntry{alias: alias, fork: a.Fork})
	}
	if len(forward) == 0 {
		return models
	}

	out := make([]*registry.ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		id := strings.TrimSpace(model.ID)
		if id == "" {
			continue
		}
		key := strings.ToLower(id)
		entries := forward[key]
		if len(entries) == 0 {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, model)
			continue
		}

		keepOriginal := false
		for _, entry := range entries {
			if entry.fork {
				keepOriginal = true
				break
			}
		}
		if keepOriginal {
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				out = append(out, model)
			}
		}

		addedAlias := false
		for _, entry := range entries {
			mappedID := strings.TrimSpace(entry.alias)
			if mappedID == "" || strings.EqualFold(mappedID, id) {
				continue
			}
			aliasKey := strings.ToLower(mappedID)
			if _, exists := seen[aliasKey]; exists {
				continue
			}
			seen[aliasKey] = struct{}{}
			clone := *model
			clone.ID = mappedID
			out = append(out, &clone)
			addedAlias = true
		}

		if !keepOriginal && !addedAlias {
			// fork=false and alias already exists as separate model:
			// skip the original — user explicitly asked to replace it.
			continue
		}
	}
	return out
}
