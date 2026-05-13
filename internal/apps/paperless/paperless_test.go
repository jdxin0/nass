package paperless

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestPreUpWritesNassSSOApp(t *testing.T) {
	ic := &apps.InstallContext{DataRoot: t.TempDir()}
	if err := preUp(context.Background(), ic); err != nil {
		t.Fatalf("preUp: %v", err)
	}
	dir := filepath.Join(ic.DataRoot, "nass_sso")
	for _, name := range []string{"__init__.py", "apps.py", "signals.py"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if len(body) == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
	signals, _ := os.ReadFile(filepath.Join(dir, "signals.py"))
	// Guard against an accidental rewrite that drops the promotion logic.
	for _, want := range []string{"user_signed_up", "is_superuser", "is_staff"} {
		if !strings.Contains(string(signals), want) {
			t.Errorf("signals.py missing %q", want)
		}
	}
}
