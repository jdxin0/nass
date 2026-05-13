// Package paperless is the nass app module for Paperless-ngx.
//
// Paperless-ngx ships django-allauth as an optional app; enabling its
// openid_connect provider gives us a one-click "Sign in with nass" button.
// The provider config is passed through PAPERLESS_SOCIALACCOUNT_PROVIDERS
// as a JSON blob, and PAPERLESS_APPS toggles the allauth provider on.
package paperless

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const providerID = "nass"

func init() {
	apps.Register(apps.Spec{
		Name:             "paperless",
		DisplayName:      "Paperless-ngx",
		Description:      "Document management for scanned paper",
		Icon:             "📄",
		Subdomain:        "paperless",
		BackendPort:      18040,
		PreserveHost:     true,
		NeedsOIDC:        true,
		OIDCGate:         false,
		OIDCRedirectURIs: redirectURIs,
		ComposeTemplate:  composeTemplate,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	return []string{ic.PublicURL() + "/accounts/oidc/" + providerID + "/login/callback/"}
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for paperless: %w", err)
	}
	return nil
}
