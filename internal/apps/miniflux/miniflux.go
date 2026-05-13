// Package miniflux is the nass app module for Miniflux.
package miniflux

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

func init() {
	apps.Register(apps.Spec{
		Name:             "miniflux",
		DisplayName:      "Miniflux",
		Description:      "Minimalist RSS reader",
		Icon:             "📰",
		Subdomain:        "miniflux",
		BackendPort:      18070,
		PreserveHost:     true,
		NeedsOIDC:        true,
		OIDCGate:         false,
		OIDCRedirectURIs: redirectURIs,
		ComposeTemplate:  composeTemplate,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	return []string{ic.PublicURL() + "/oauth2/oidc/callback"}
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/healthcheck", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for miniflux: %w", err)
	}
	return nil
}
