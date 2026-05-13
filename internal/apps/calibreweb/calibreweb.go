// Package calibreweb is the nass app module for Calibre-Web Automated.
//
// Calibre-Web Automated supports a generic OAuth/OIDC provider. nass provisions
// an OIDC client, seeds CWA's app.db after first boot, and restarts the stack so
// the generic OAuth blueprint is registered with the new settings.
package calibreweb

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jdxin0/nass/internal/apps"
	_ "modernc.org/sqlite"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const (
	cwaLoginOAuth = 2
	providerName  = "generic"
)

func init() {
	apps.Register(apps.Spec{
		Name:             "calibreweb",
		DisplayName:      "Calibre-Web Automated",
		Description:      "Automated e-book library manager",
		Icon:             "📚",
		Subdomain:        "calibre",
		BackendPort:      18083,
		PreserveHost:     true,
		NeedsOIDC:        true,
		OIDCGate:         false,
		OIDCRedirectURIs: redirectURIs,
		ComposeTemplate:  composeTemplate,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	return []string{ic.PublicURL() + "/login/" + providerName + "/authorized"}
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	target := fmt.Sprintf("http://127.0.0.1:%d", ic.BackendPort)
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for calibre-web automated: %w", err)
	}

	dbPath := filepath.Join(ic.DataRoot, "config", "app.db")
	if err := waitForFile(ctx, dbPath, 2*time.Minute); err != nil {
		return fmt.Errorf("wait for app.db: %w", err)
	}
	if err := seedOIDCConfig(dbPath, ic); err != nil {
		return fmt.Errorf("seed calibre-web automated oidc config: %w", err)
	}

	if _, err := ic.Orchestrator.Restart(ctx, ic.ComposeFile); err != nil {
		return fmt.Errorf("restart calibre-web automated: %w", err)
	}

	upCtx, cancel2 := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel2()
	return apps.WaitFor(upCtx, target, 2*time.Second)
}

func seedOIDCConfig(dbPath string, ic *apps.InstallContext) error {
	d, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	if _, err := d.Exec(`UPDATE settings SET config_login_type = ?, config_oauth_redirect_host = ?`, cwaLoginOAuth, ic.PublicURL()); err != nil {
		return fmt.Errorf("update settings: %w", err)
	}
	if _, err := d.Exec(`
		UPDATE oauthProvider
		SET oauth_client_id = ?,
		    oauth_client_secret = ?,
		    metadata_url = ?,
		    scope = ?,
		    username_mapper = ?,
		    email_mapper = ?,
		    login_button = ?,
		    oauth_admin_group = ?,
		    active = 1
		WHERE provider_name = ?`,
		ic.OIDCClientID,
		ic.OIDCClientSecret,
		ic.OIDCDiscoveryURL(),
		"openid profile email groups",
		"preferred_username",
		"email",
		"nass",
		"admin",
		providerName,
	); err != nil {
		return fmt.Errorf("update generic oauth provider: %w", err)
	}
	if _, err := d.Exec(`
		INSERT INTO oauthProvider (
			provider_name, oauth_client_id, oauth_client_secret, metadata_url, scope,
			username_mapper, email_mapper, login_button, oauth_admin_group, active
		)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 1
		WHERE NOT EXISTS (SELECT 1 FROM oauthProvider WHERE provider_name = ?)`,
		providerName,
		ic.OIDCClientID,
		ic.OIDCClientSecret,
		ic.OIDCDiscoveryURL(),
		"openid profile email groups",
		"preferred_username",
		"email",
		"nass",
		"admin",
		providerName,
	); err != nil {
		return fmt.Errorf("insert generic oauth provider: %w", err)
	}
	return nil
}

func waitForFile(ctx context.Context, path string, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-deadline.Done():
			return deadline.Err()
		case <-time.After(time.Second):
		}
	}
}
