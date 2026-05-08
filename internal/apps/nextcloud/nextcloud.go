// Package nextcloud is the nass app module for Nextcloud.
//
// PostUp wires user_oidc against our OIDC issuer, mirroring the bash
// post-compose-up.sh from nass-simple/nextcloud/.
package nextcloud

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const (
	occ            = "/var/www/html/occ"
	configFile     = "/var/www/html/config/config.php"
	providerName   = "nass"
	providerScopes = "openid profile email"
)

func init() {
	apps.Register(apps.Spec{
		Name:            "nextcloud",
		DisplayName:     "Nextcloud",
		Description:     "Files, calendar, contacts",
		Icon:            "☁️",
		Subdomain:         "nextcloud",
		BackendPort:       18080,
		PreserveHost:      true,
		NeedsOIDC:         true,
		OIDCGate:          false,
		OIDCRedirectURIs: func(ic *apps.InstallContext) []string {
			return []string{ic.PublicURL() + "/apps/user_oidc/code"}
		},
		ComposeTemplate: composeTemplate,
		PostUp:          postUp,
	})
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	// 1. Wait for nextcloud to start serving.
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/status.php", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for nextcloud: %w", err)
	}

	// 2. Allow nextcloud to call back to the OIDC issuer (which is on the
	// docker host). This must come before we register the provider, since
	// `user_oidc:provider` does a discovery fetch.
	if err := ensureLocalRemoteServers(ctx, ic); err != nil {
		return fmt.Errorf("patch config.php: %w", err)
	}

	// 3. Install the user_oidc app. occ is idempotent — re-running on an
	// already-installed app prints a warning but exits 0.
	if _, err := ic.Orchestrator.ExecAsUser(ctx, ic.ComposeFile, "nextcloud", "www-data",
		"php", occ, "app:install", "user_oidc"); err != nil {
		// Tolerate "already installed" by retrying with app:enable.
		if _, err2 := ic.Orchestrator.ExecAsUser(ctx, ic.ComposeFile, "nextcloud", "www-data",
			"php", occ, "app:enable", "user_oidc"); err2 != nil {
			return fmt.Errorf("install/enable user_oidc: %w (initial: %v)", err2, err)
		}
	}

	// 4. Register us as the OIDC provider. The user_oidc:provider command is
	// also idempotent (it updates if the provider already exists by name).
	args := []string{
		"php", occ, "user_oidc:provider", providerName,
		"-d", ic.OIDCDiscoveryURL(),
		"-c", ic.OIDCClientID,
		"-s", ic.OIDCClientSecret,
		"--scope", providerScopes,
		"--unique-uid=0",
	}
	if _, err := ic.Orchestrator.ExecAsUser(ctx, ic.ComposeFile, "nextcloud", "www-data", args...); err != nil {
		return fmt.Errorf("register user_oidc provider: %w", err)
	}
	return nil
}

// ensureLocalRemoteServers patches /var/www/html/config/config.php to add
// 'allow_local_remote_servers' => true so nextcloud can fetch the OIDC
// discovery doc from the host (which it would otherwise refuse as "local").
//
// Mirrors nass-simple's fix_config in post-compose-up.sh.
func ensureLocalRemoteServers(ctx context.Context, ic *apps.InstallContext) error {
	// Check if the key is already there.
	out, err := ic.Orchestrator.Exec(ctx, ic.ComposeFile, "nextcloud", "cat", configFile)
	if err != nil {
		return fmt.Errorf("read config.php: %w", err)
	}
	if strings.Contains(out, "allow_local_remote_servers") {
		return nil
	}
	// Inject after line 4 (right after `<?php $CONFIG = array (`).
	if _, err := ic.Orchestrator.Exec(ctx, ic.ComposeFile, "nextcloud",
		"sed", "-i", "4i\\  'allow_local_remote_servers' => true,", configFile); err != nil {
		return fmt.Errorf("sed config.php: %w", err)
	}
	if _, err := ic.Orchestrator.Restart(ctx, ic.ComposeFile); err != nil {
		return fmt.Errorf("restart after config.php patch: %w", err)
	}
	// After restart, wait for nextcloud to come back up before subsequent occ calls.
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/status.php", ic.BackendPort)
	return apps.WaitFor(waitCtx, target, 2*time.Second)
}
