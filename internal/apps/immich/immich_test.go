package immich

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestRenderConfig_PopulatesOIDCAndExternalDomain(t *testing.T) {
	ic := &apps.InstallContext{
		Subdomain:        "immich",
		BaseHost:         "nass.local",
		PublicScheme:     "https",
		PublicPort:       ":8443",
		OIDCClientID:     "client-abc",
		OIDCClientSecret: "secret-xyz",
		OIDCIssuer:       "https://auth.nass.local",
	}
	body, err := renderConfig(ic)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got immichConfig
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, body)
	}
	if got.OAuth.ClientID != "client-abc" {
		t.Errorf("ClientID: %q", got.OAuth.ClientID)
	}
	if got.OAuth.ClientSecret != "secret-xyz" {
		t.Errorf("ClientSecret: %q", got.OAuth.ClientSecret)
	}
	if got.OAuth.IssuerURL != "https://auth.nass.local/.well-known/openid-configuration" {
		t.Errorf("IssuerURL: %q", got.OAuth.IssuerURL)
	}
	if got.OAuth.SigningAlgorithm != "RS256" {
		t.Errorf("SigningAlgorithm: got %q want RS256", got.OAuth.SigningAlgorithm)
	}
	if !got.OAuth.Enabled {
		t.Errorf("OAuth.Enabled should be true")
	}
	if got.Server.ExternalDomain != "https://immich.nass.local:8443" {
		t.Errorf("ExternalDomain: %q", got.Server.ExternalDomain)
	}
}

// renderConfig must produce JSON that's robust to special characters in the
// OIDC client_secret. The struct-based marshalling escapes them for free —
// this test exists so a future refactor to template-based rendering would
// fail loudly instead of silently producing broken JSON.
func TestRenderConfig_EscapesSpecialCharsInSecret(t *testing.T) {
	ic := &apps.InstallContext{
		OIDCClientID:     "cid",
		OIDCClientSecret: `quote"and\backslash`,
		OIDCIssuer:       "https://auth.nass.local",
	}
	body, err := renderConfig(ic)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got immichConfig
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, body)
	}
	if got.OAuth.ClientSecret != `quote"and\backslash` {
		t.Errorf("secret was mangled in round-trip: %q", got.OAuth.ClientSecret)
	}
	// Raw bytes must contain escapes, not the literal chars.
	if !strings.Contains(string(body), `\"`) || !strings.Contains(string(body), `\\`) {
		t.Errorf("expected JSON-escaped quote and backslash in body:\n%s", body)
	}
}
