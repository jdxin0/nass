// Package vaultwarden is the nass app module for Vaultwarden.
//
// Vaultwarden's upstream gained native OIDC SSO support; nass wires the
// built-in IdP into it via SSO_AUTHORITY/CLIENT_ID/CLIENT_SECRET. The
// callback URL is hardcoded by Vaultwarden to {DOMAIN}/identity/connect/
// oidc-signin, so we register exactly that.
package vaultwarden

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
		Name:             "vaultwarden",
		DisplayName:      "Vaultwarden",
		Description:      "Bitwarden-compatible password manager",
		Icon:             "🔐",
		Subdomain:        "vault",
		BackendPort:      18050,
		PreserveHost:     true,
		NeedsOIDC:        true,
		OIDCGate:         false,
		OIDCRedirectURIs: redirectURIs,
		ComposeTemplate:  composeTemplate,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	return []string{ic.PublicURL() + "/identity/connect/oidc-signin"}
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/alive", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for vaultwarden: %w", err)
	}
	return nil
}
