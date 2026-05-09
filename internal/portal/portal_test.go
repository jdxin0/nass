package portal_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
	"github.com/jdxin0/nass/internal/auth"
	"github.com/jdxin0/nass/internal/db"
	"github.com/jdxin0/nass/internal/orchestrator"
	"github.com/jdxin0/nass/internal/portal"
	"github.com/jdxin0/nass/internal/proxy"

	_ "github.com/jdxin0/nass/internal/apps/nextcloud"
)

type fixture struct {
	portal   *portal.Portal
	sessions *portal.SessionStore
	server   *httptest.Server
	db       *sql.DB
	users    *auth.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	users := auth.NewStore(d)
	if _, err := users.Create(context.Background(), "admin", "", "supersecretpw", true); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if _, err := users.Create(context.Background(), "alice", "alice@example.com", "alicepassword", false); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ss := portal.NewSessionStore(d, users, "" /* no domain in tests */)
	ss.Insecure = true
	root := t.TempDir()
	orch := orchestrator.New(filepath.Join(root, "compose"), "")
	p, err := portal.New(d, users, ss, orch, "test.local", "Test Portal", false)
	if err != nil {
		t.Fatalf("portal: %v", err)
	}
	p.AppDataRoot = filepath.Join(root, "data")
	p.OIDCIssuer = "http://auth.test.local"
	mux := http.NewServeMux()
	p.Mount(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(func() {
		ts.Close()
		d.Close()
	})
	return &fixture{portal: p, sessions: ss, server: ts, db: d, users: users}
}

func TestDashboardRequiresSession(t *testing.T) {
	f := newFixture(t)

	hc := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := hc.Get(f.server.URL + "/")
	if err != nil {
		t.Fatalf("get /: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "/portal/login") {
		t.Fatalf("redirect: %q", resp.Header.Get("Location"))
	}
}

func TestLoginSuccessLandsOnDashboard(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}

	resp, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"alice"}, "password": {"alicepassword"}, "next": {"/"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "Apps") {
		t.Fatalf("dashboard didn't render: %s", body)
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	f := newFixture(t)

	resp, err := http.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"alice"}, "password": {"wrong"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "invalid username or password") {
		t.Fatalf("expected error: %s", body)
	}
}

func TestAdminRequiresAdmin(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}

	if _, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"alice"}, "password": {"alicepassword"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Get(f.server.URL + "/portal/admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice should get 403, got %d", resp.StatusCode)
	}
}

func TestAdminAddAppPersists(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	f.portal.InstallApp = func(ctx context.Context, ic *apps.InstallContext) (*apps.Result, error) {
		settings := proxy.AppSettings{
			Subdomain:    ic.Subdomain,
			Backend:      "http://127.0.0.1:18080",
			PreserveHost: true,
			DisplayName:  ic.Spec.DisplayName,
			Description:  ic.Spec.Description,
		}
		if err := proxy.SaveSettings(ctx, ic.DB, ic.Name, settings); err != nil {
			return nil, err
		}
		return &apps.Result{AppName: ic.Name}, nil
	}

	if _, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"admin"}, "password": {"supersecretpw"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := hc.PostForm(f.server.URL+"/portal/admin/apps", url.Values{
		"name": {"nextcloud"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/portal/admin" {
		t.Fatalf("expected /portal/admin, got %s", resp.Request.URL)
	}

	got, err := proxy.LoadEnabled(context.Background(), f.db, "test.local")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 || got[0].Name != "nextcloud" || got[0].Settings.Backend != "http://127.0.0.1:18080" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestGateRedirectsUnauthenticated(t *testing.T) {
	f := newFixture(t)

	gate := portal.NewGate(f.sessions, f.server.URL)
	gated := gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secret")
	}))
	gateSrv := httptest.NewServer(gated)
	defer gateSrv.Close()

	hc := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := hc.Get(gateSrv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "/portal/login?next=") {
		t.Fatalf("redirect: %q", resp.Header.Get("Location"))
	}
}

func TestGateAllowsAuthenticated(t *testing.T) {
	f := newFixture(t)

	// Issue a session out-of-band by signing in via the portal, capturing the cookie.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	if _, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"alice"}, "password": {"alicepassword"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}
	pURL, _ := url.Parse(f.server.URL)
	cookies := jar.Cookies(pURL)

	gate := portal.NewGate(f.sessions, f.server.URL)
	gated := gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secret")
	}))
	gateSrv := httptest.NewServer(gated)
	defer gateSrv.Close()

	gURL, _ := url.Parse(gateSrv.URL)
	jar.SetCookies(gURL, cookies)

	resp, err := hc.Get(gateSrv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "secret" {
		t.Fatalf("expected 200/secret, got %d/%s", resp.StatusCode, body)
	}
}
