package cmd

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	log "github.com/sirupsen/logrus"
)

func DoQoderLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}
	_, _, err := newAuthManager().Login(context.Background(), "qoder", cfg, &sdkAuth.LoginOptions{NoBrowser: options.NoBrowser, Metadata: map[string]string{}, Prompt: options.Prompt})
	if err != nil {
		log.Errorf("Qoder authentication failed: %v", err)
	}
}
