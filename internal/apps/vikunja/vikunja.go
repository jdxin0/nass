// Package vikunja is the nass app module for Vikunja.
package vikunja

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

const providerID = "nass"

func init() {
	apps.Register(apps.Spec{
		Name:             "vikunja",
		DisplayName:      "Vikunja",
		Description:      "Task and project management",
		Icon:             "✅",
		Subdomain:        "vikunja",
		BackendPort:      18095,
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
	return []string{ic.PublicURL() + "/auth/openid/" + providerID}
}

func preUp(ctx context.Context, ic *apps.InstallContext) error {
	for _, dir := range []string{
		filepath.Join(ic.DataRoot, "files"),
		filepath.Join(ic.DataRoot, "db"),
	} {
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}

	config := fmt.Sprintf(`service:
  publicurl: %q
  enableregistration: false
  timezone: UTC
files:
  basepath: /app/vikunja/files
database:
  type: sqlite
  path: /db/vikunja.db
auth:
  local:
    enabled: false
  openid:
    enabled: true
    providers:
      %s:
        name: nass
        authurl: %q
        clientid: %q
        clientsecret: %q
        scope: openid profile email
`, ic.PublicURL(), providerID, ic.OIDCIssuer, ic.OIDCClientID, ic.OIDCClientSecret)

	if err := os.WriteFile(filepath.Join(ic.DataRoot, "config.yml"), []byte(config), 0o644); err != nil {
		return fmt.Errorf("write config.yml: %w", err)
	}
	return nil
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for vikunja: %w", err)
	}
	return nil
}
