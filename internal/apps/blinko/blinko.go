// Package blinko is the nass app module for Blinko.
//
// Blinko supports custom OAuth2/OIDC providers from its settings UI. We seed
// that same config table after first boot so Blinko signs users in with the
// nass OIDC provider without requiring manual setup.
package blinko

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const providerID = "nass"

func init() {
	apps.Register(apps.Spec{
		Name:             "blinko",
		DisplayName:      "Blinko",
		Description:      "AI note-taking",
		Icon:             "📝",
		Subdomain:        "blinko",
		BackendPort:      11111,
		PreserveHost:     true,
		NeedsOIDC:        true,
		OIDCGate:         false,
		OIDCRedirectURIs: redirectURIs,
		ComposeTemplate:  composeTemplate,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	return []string{ic.PublicURL() + "/api/auth/callback/" + providerID}
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	target := fmt.Sprintf("http://127.0.0.1:%d", ic.BackendPort)
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for blinko: %w", err)
	}

	sql, err := oauthProviderSQL(ic)
	if err != nil {
		return fmt.Errorf("build blinko oauth config: %w", err)
	}
	if _, err := ic.Orchestrator.Exec(ctx, ic.ComposeFile, "postgres", "psql", "-U", "postgres", "-d", "postgres", "-c", sql); err != nil {
		return fmt.Errorf("seed blinko oauth config: %w", err)
	}

	if _, err := ic.Orchestrator.Restart(ctx, ic.ComposeFile); err != nil {
		return fmt.Errorf("restart blinko: %w", err)
	}

	upCtx, cancel2 := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel2()
	return apps.WaitFor(upCtx, target, 2*time.Second)
}

func oauthProviderSQL(ic *apps.InstallContext) (string, error) {
	provider := oauthProvider{
		ID:           providerID,
		Name:         "nass",
		Icon:         "tabler:server",
		WellKnown:    ic.OIDCDiscoveryURL(),
		Scope:        "openid profile email",
		ClientID:     ic.OIDCClientID,
		ClientSecret: ic.OIDCClientSecret,
	}
	value := configValue{
		Type:  "object",
		Value: []oauthProvider{provider},
	}
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	quoted := strings.ReplaceAll(string(body), "'", "''")
	return "DELETE FROM config WHERE key = 'oauth2Providers'; INSERT INTO config (key, config) VALUES ('oauth2Providers', '" + quoted + "');", nil
}

type configValue struct {
	Type  string          `json:"type"`
	Value []oauthProvider `json:"value"`
}

type oauthProvider struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Icon             string `json:"icon"`
	WellKnown        string `json:"wellKnown"`
	Scope            string `json:"scope"`
	AuthorizationURL string `json:"authorizationUrl"`
	TokenURL         string `json:"tokenUrl"`
	UserinfoURL      string `json:"userinfoUrl"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret"`
}
