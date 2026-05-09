// Package gitea is the nass app module for Gitea.
package gitea

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
	providerName   = "nass"
	providerScopes = "email profile groups"
	serviceName    = "gitea"
	serviceUser    = "git"
)

func init() {
	apps.Register(apps.Spec{
		Name:         "gitea",
		DisplayName:  "Gitea",
		Description:  "Lightweight Git hosting",
		Icon:         "🐙",
		Subdomain:    "gitea",
		BackendPort:  13000,
		PreserveHost: true,
		NeedsOIDC:    true,
		OIDCGate:     false,
		OIDCRedirectURIs: func(ic *apps.InstallContext) []string {
			return []string{ic.PublicURL() + "/user/oauth2/" + providerName + "/callback"}
		},
		ComposeTemplate: composeTemplate,
		PostUp:          postUp,
	})
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for gitea: %w", err)
	}

	if err := createAdminUser(ctx, ic); err != nil {
		return err
	}
	if err := addOIDCProvider(ctx, ic); err != nil {
		return err
	}
	return nil
}

func createAdminUser(ctx context.Context, ic *apps.InstallContext) error {
	email := "admin@" + ic.BaseHost
	args := []string{
		"gitea", "admin", "user", "create",
		"--username", "admin",
		"--password", ic.AdminPassword,
		"--email", email,
		"--admin",
		"--must-change-password=false",
	}
	out, err := ic.Orchestrator.ExecAsUser(ctx, ic.ComposeFile, serviceName, serviceUser, args...)
	if err != nil && !isAlreadyExists(out, err) {
		return fmt.Errorf("create gitea admin user: %w", err)
	}
	return nil
}

func addOIDCProvider(ctx context.Context, ic *apps.InstallContext) error {
	args := []string{
		"gitea", "admin", "auth", "add-oauth",
		"--name", providerName,
		"--provider", "openidConnect",
		"--key", ic.OIDCClientID,
		"--secret", ic.OIDCClientSecret,
		"--auto-discover-url", ic.OIDCDiscoveryURL(),
		"--scopes", providerScopes,
		"--group-claim-name", "groups",
		"--admin-group", "admin",
		"--skip-local-2fa",
	}
	out, err := ic.Orchestrator.ExecAsUser(ctx, ic.ComposeFile, serviceName, serviceUser, args...)
	if err != nil && !isAlreadyExists(out, err) {
		return fmt.Errorf("add gitea OIDC provider: %w", err)
	}
	return nil
}

func isAlreadyExists(out string, err error) bool {
	text := strings.ToLower(out)
	if err != nil {
		text += "\n" + strings.ToLower(err.Error())
	}
	return strings.Contains(text, "already exist") ||
		strings.Contains(text, "already been taken") ||
		strings.Contains(text, "duplicate")
}
