package paperless

import (
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestRedirectURIsUsesAllauthCallback(t *testing.T) {
	ic := &apps.InstallContext{
		Subdomain:    "paperless",
		BaseHost:     "nass.local",
		PublicScheme: "https",
		PublicPort:   ":8443",
	}
	got := redirectURIs(ic)
	want := "https://paperless.nass.local:8443/accounts/oidc/nass/login/callback/"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("redirect URIs: got %v want [%s]", got, want)
	}
}
