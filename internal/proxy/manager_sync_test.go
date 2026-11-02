package proxy_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/db"
	"github.com/jdxin0/nass/internal/proxy"
)

func newManagerFixture(t *testing.T) (*proxy.RouteManager, *proxy.Server, func(name string, s proxy.AppSettings)) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	router := proxy.New()
	mgr := proxy.NewRouteManager(d, router, "example.com", nil)
	save := func(name string, s proxy.AppSettings) {
		t.Helper()
		if err := proxy.SaveSettings(context.Background(), d, name, s); err != nil {
			t.Fatal(err)
		}
	}
	return mgr, router, save
}

func hosts(s *proxy.Server) string {
	h := s.Hosts()
	sort.Strings(h)
	return strings.Join(h, ",")
}

func TestSyncSkipsBadAppButServesTheRest(t *testing.T) {
	mgr, router, save := newManagerFixture(t)
	save("good", proxy.AppSettings{Subdomain: "good", Backend: "http://127.0.0.1:1"})
	save("bad", proxy.AppSettings{Subdomain: "bad", Backend: "127.0.0.1:2"})                            // missing scheme
	save("gated", proxy.AppSettings{Subdomain: "gated", Backend: "http://127.0.0.1:3", OIDCGate: true}) // no gate wired

	err := mgr.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "app bad") || !strings.Contains(err.Error(), "app gated") {
		t.Fatalf("Sync error should name the skipped apps, got %v", err)
	}
	if got := hosts(router); got != "good.example.com" {
		t.Fatalf("routes = %q, want only good.example.com", got)
	}

	// A later fix to the bad app is picked up, and removed apps are dropped.
	save("bad", proxy.AppSettings{Subdomain: "bad", Backend: "http://127.0.0.1:2"})
	save("gated", proxy.AppSettings{Subdomain: "", Backend: "http://127.0.0.1:3"})
	if err := mgr.Sync(context.Background()); err == nil {
		t.Fatal("empty subdomain should still be reported")
	}
	if got := hosts(router); got != "bad.example.com,good.example.com" {
		t.Fatalf("routes = %q", got)
	}
}

func TestSyncRefusesReservedHosts(t *testing.T) {
	mgr, router, save := newManagerFixture(t)
	idp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "idp") })
	router.AddRoute("auth.example.com", idp)
	mgr.Reserve("auth.example.com", "example.com")

	save("sneaky", proxy.AppSettings{Subdomain: "AUTH", Backend: "http://127.0.0.1:1"})
	err := mgr.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved-host error, got %v", err)
	}

	// Removing the app must not take the IdP route with it.
	save("sneaky", proxy.AppSettings{Subdomain: "other", Backend: "http://127.0.0.1:1"})
	if err := mgr.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := hosts(router); got != "auth.example.com,other.example.com" {
		t.Fatalf("routes = %q", got)
	}
	req := httptest.NewRequest("GET", "http://auth.example.com/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Body.String() != "idp" {
		t.Fatalf("auth host now serves %q, want the IdP", rec.Body.String())
	}
}

func TestSyncHostMovingBetweenApps(t *testing.T) {
	mgr, router, save := newManagerFixture(t)
	save("a", proxy.AppSettings{Subdomain: "shared", Backend: "http://127.0.0.1:1"})
	if err := mgr.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	// In one sync, a gives up the host and b takes it.
	save("a", proxy.AppSettings{Subdomain: "a2", Backend: "http://127.0.0.1:1"})
	save("b", proxy.AppSettings{Subdomain: "shared", Backend: "http://127.0.0.1:2"})
	if err := mgr.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := hosts(router); got != "a2.example.com,shared.example.com" {
		t.Fatalf("routes = %q", got)
	}

	// Two apps claiming one host: the first (by name) wins, the other is reported.
	save("c", proxy.AppSettings{Subdomain: "shared", Backend: "http://127.0.0.1:3"})
	err := mgr.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already used by app b") {
		t.Fatalf("expected duplicate-host error, got %v", err)
	}
}
