package vaultwarden

import (
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestRedirectURIsUsesOIDCSigninCallback(t *testing.T) {
	ic := &apps.InstallContext{
		Subdomain:    "vault",
		BaseHost:     "nass.local",
		PublicScheme: "https",
		PublicPort:   ":8443",
	}
	got := redirectURIs(ic)
	want := "https://vault.nass.local:8443/identity/connect/oidc-signin"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("redirect URIs: got %v want [%s]", got, want)
	}
}
