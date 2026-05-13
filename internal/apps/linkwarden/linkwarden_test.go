package linkwarden

import (
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestRedirectURIsUsesLinkwardenAutheliaCallback(t *testing.T) {
	ic := &apps.InstallContext{
		Subdomain:    "links",
		BaseHost:     "nass.local",
		PublicScheme: "https",
		PublicPort:   ":8443",
	}

	got := redirectURIs(ic)
	want := "https://links.nass.local:8443/api/v1/auth/callback/authelia"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("redirect URIs: got %v want [%s]", got, want)
	}
}
