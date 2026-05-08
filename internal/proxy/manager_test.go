package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/jdxin0/nass/internal/db"
	"github.com/jdxin0/nass/internal/proxy"
)

func TestRouteManagerSyncAddsRemovesUpdates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer d.Close()

	router := proxy.New()

	// Pre-register a fixed route (e.g. simulating OIDC). Sync must never touch it.
	router.AddRoute("auth.example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "auth")
	}))

	mgr := proxy.NewRouteManager(d, router, "example.com", nil)

	ctx := context.Background()

	// Round 1: empty DB, nothing to do.
	if err := mgr.Sync(ctx); err != nil {
		t.Fatalf("sync empty: %v", err)
	}
	if len(mgr.ManagedHosts()) != 0 {
		t.Fatalf("expected 0 managed hosts, got %v", mgr.ManagedHosts())
	}

	// Add an app via SaveSettings.
	if err := proxy.SaveSettings(ctx, d, "nextcloud", proxy.AppSettings{
		Subdomain: "nextcloud", Backend: "http://127.0.0.1:18080",
	}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Sync(ctx); err != nil {
		t.Fatalf("sync add: %v", err)
	}
	if got := mgr.ManagedHosts(); !slices.Equal(sortStrings(got), []string{"nextcloud.example.com"}) {
		t.Fatalf("after add: %v", got)
	}

	// Add a second.
	if err := proxy.SaveSettings(ctx, d, "files", proxy.AppSettings{
		Subdomain: "files", Backend: "http://127.0.0.1:9100",
	}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Sync(ctx); err != nil {
		t.Fatalf("sync second: %v", err)
	}
	if got := sortStrings(mgr.ManagedHosts()); !slices.Equal(got, []string{"files.example.com", "nextcloud.example.com"}) {
		t.Fatalf("after second: %v", got)
	}

	// Disable the first.
	if _, err := d.Exec(`UPDATE apps SET enabled = 0 WHERE name = ?`, "nextcloud"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Sync(ctx); err != nil {
		t.Fatalf("sync disable: %v", err)
	}
	if got := mgr.ManagedHosts(); !slices.Equal(got, []string{"files.example.com"}) {
		t.Fatalf("after disable: %v", got)
	}
	// And the fixed route survives.
	if !slices.Contains(router.Hosts(), "auth.example.com") {
		t.Fatalf("auth route was removed by Sync")
	}

	// Change the subdomain on the remaining app: old host should drop, new host should appear.
	if err := proxy.SaveSettings(ctx, d, "files", proxy.AppSettings{
		Subdomain: "files2", Backend: "http://127.0.0.1:9100",
	}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Sync(ctx); err != nil {
		t.Fatalf("sync subdomain change: %v", err)
	}
	hosts := router.Hosts()
	if slices.Contains(hosts, "files.example.com") {
		t.Fatalf("old host not removed: %v", hosts)
	}
	if !slices.Contains(hosts, "files2.example.com") {
		t.Fatalf("new host not added: %v", hosts)
	}
}

func TestSyncMakesRouteImmediatelyServeable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer d.Close()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "served")
	}))
	defer backend.Close()

	router := proxy.New()
	front := httptest.NewServer(router)
	defer front.Close()

	mgr := proxy.NewRouteManager(d, router, "example.com", nil)
	if err := proxy.SaveSettings(context.Background(), d, "x", proxy.AppSettings{
		Subdomain: "x", Backend: backend.URL,
	}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest("GET", front.URL+"/", nil)
	req.Host = "x.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "served" {
		t.Fatalf("body: %q", body)
	}
}

func sortStrings(s []string) []string {
	cp := append([]string(nil), s...)
	sort.Strings(cp)
	return cp
}
