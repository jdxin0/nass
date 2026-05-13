package miniflux

import (
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestRedirectURIsUsesMinifluxOIDCCallback(t *testing.T) {
	ic := &apps.InstallContext{
		Subdomain:    "rss",
		BaseHost:     "nass.local",
		PublicScheme: "https",
		PublicPort:   ":8443",
	}

	got := redirectURIs(ic)
	want := "https://rss.nass.local:8443/oauth2/oidc/callback"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("redirect URIs: got %v want [%s]", got, want)
	}
}
