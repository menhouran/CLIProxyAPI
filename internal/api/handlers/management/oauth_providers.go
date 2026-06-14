package management

import (
	"github.com/gin-gonic/gin"
)

// GetOAuthProviders returns the list of known OAuth providers with metadata.
// The management SPA uses this to determine which providers support features
// such as the model-disable-list (oauth-excluded-models) UI.
func (h *Handler) GetOAuthProviders(c *gin.Context) {
	if h == nil || h.sdkAuthManager == nil {
		c.JSON(200, gin.H{"providers": []struct{}{}})
		return
	}
	providers := h.sdkAuthManager.ListProviders()
	c.JSON(200, gin.H{"providers": providers})
}
