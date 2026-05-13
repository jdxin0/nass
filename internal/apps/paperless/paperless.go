// Package paperless is the nass app module for Paperless-ngx.
//
// Paperless-ngx ships django-allauth as an optional app; enabling its
// openid_connect provider gives us a one-click "Sign in with nass" button.
// The provider config is passed through PAPERLESS_SOCIALACCOUNT_PROVIDERS
// as a JSON blob, and PAPERLESS_APPS toggles the allauth provider on.
//
// We also inject a tiny Django app (nass_sso) into the container that
// listens for allauth's user_signed_up signal and promotes new SSO users
// to superuser. Without it, Paperless's RBAC leaves them with no
// document permissions on first login.
package paperless

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

//go:embed nass_sso/__init__.py
var pyInit []byte

//go:embed nass_sso/apps.py
var pyApps []byte

//go:embed nass_sso/signals.py
var pySignals []byte

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
		PreUp:            preUp,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	return []string{ic.PublicURL() + "/accounts/oidc/" + providerID + "/login/callback/"}
}

func preUp(ctx context.Context, ic *apps.InstallContext) error {
	dir := filepath.Join(ic.DataRoot, "nass_sso")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir nass_sso: %w", err)
	}
	for name, body := range map[string][]byte{
		"__init__.py": pyInit,
		"apps.py":     pyApps,
		"signals.py":  pySignals,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			return fmt.Errorf("write nass_sso/%s: %w", name, err)
		}
	}
	return nil
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
