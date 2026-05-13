// Package linkwarden is the nass app module for Linkwarden.
package linkwarden

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const providerName = "keycloak"

func init() {
	apps.Register(apps.Spec{
		Name:             "linkwarden",
		DisplayName:      "Linkwarden",
		Description:      "Bookmark and web archive manager",
		Icon:             "🔖",
		Subdomain:        "linkwarden",
		BackendPort:      13001,
		PreserveHost:     true,
		NeedsOIDC:        true,
		OIDCGate:         false,
		OIDCRedirectURIs: redirectURIs,
		ComposeTemplate:  composeTemplate,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	return []string{ic.PublicURL() + "/api/v1/auth/callback/" + providerName}
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for linkwarden: %w", err)
	}
	return nil
}
