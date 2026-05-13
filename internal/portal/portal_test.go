package portal_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jdxin0/nass/internal/apps"
	"github.com/jdxin0/nass/internal/auth"
	"github.com/jdxin0/nass/internal/db"
	"github.com/jdxin0/nass/internal/orchestrator"
	"github.com/jdxin0/nass/internal/portal"
	"github.com/jdxin0/nass/internal/proxy"

	_ "github.com/jdxin0/nass/internal/apps/blinko"
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

	var got []proxy.AppRoute
	waitFor(t, func() bool {
		var err error
		got, err = proxy.LoadEnabled(context.Background(), f.db, "test.local")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return len(got) == 1
	})
	if len(got) != 1 || got[0].Name != "nextcloud" || got[0].Settings.Backend != "http://127.0.0.1:18080" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestAdminAddAppLogsBackgroundFailure(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	var logs bytes.Buffer
	f.portal.JobLog = &logs
	f.portal.InstallApp = func(ctx context.Context, ic *apps.InstallContext) (*apps.Result, error) {
		return nil, errors.New("post-up: seed blinko oauth config: relation config does not exist")
	}

	if _, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"admin"}, "password": {"supersecretpw"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := hc.PostForm(f.server.URL+"/portal/admin/apps", url.Values{
		"name": {"blinko"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	waitFor(t, func() bool {
		return strings.Contains(logs.String(), "post-up: seed blinko oauth config")
	})
	got := logs.String()
	for _, want := range []string{
		"app job failed",
		"action=install",
		"app=blinko",
		"post-up: seed blinko oauth config: relation config does not exist",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log missing %q in:\n%s", want, got)
		}
	}
}

func TestAdminUninstallAppRunsInBackground(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}

	if err := proxy.SaveSettings(context.Background(), f.db, "nextcloud", proxy.AppSettings{
		Subdomain: "nextcloud",
		Backend:   "http://127.0.0.1:18080",
	}); err != nil {
		t.Fatalf("save app: %v", err)
	}
	if _, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"admin"}, "password": {"supersecretpw"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := hc.PostForm(f.server.URL+"/portal/admin/apps/nextcloud/uninstall", nil)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	resp.Body.Close()

	waitFor(t, func() bool {
		got, err := proxy.LoadEnabled(context.Background(), f.db, "test.local")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return len(got) == 0
	})
}

func TestAdminUninstallCleansFailedInstallEvenWhenComposeDownFails(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	f.portal.Orchestrator = orchestrator.New(t.TempDir(), "false")

	if err := proxy.SaveSettings(context.Background(), f.db, "blinko", proxy.AppSettings{
		Subdomain:   "blinko",
		Backend:     "http://127.0.0.1:11111",
		ComposeFile: filepath.Join(t.TempDir(), "docker-compose.yaml"),
	}); err != nil {
		t.Fatalf("save app: %v", err)
	}
	if _, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"admin"}, "password": {"supersecretpw"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := hc.PostForm(f.server.URL+"/portal/admin/apps/blinko/uninstall", nil)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	resp.Body.Close()

	waitFor(t, func() bool {
		got, err := proxy.LoadEnabled(context.Background(), f.db, "test.local")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return len(got) == 0
	})

	resp, err = hc.Get(f.server.URL + "/portal/admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `name="name" value="blinko"`) {
		t.Fatalf("blinko install button should be shown after cleanup:\n%s", body)
	}
}

func TestAdminUserManagement(t *testing.T) {
	f := newFixture(t)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}

	if _, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {"admin"}, "password": {"supersecretpw"}, "next": {"/"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := hc.PostForm(f.server.URL+"/portal/admin/users", url.Values{
		"username": {"bob"},
		"email":    {"bob@example.com"},
		"password": {"bobpassword"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	resp.Body.Close()
	bob, err := f.users.GetByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatalf("load bob: %v", err)
	}
	if bob.IsAdmin {
		t.Fatalf("bob should not start as admin")
	}

	resp, err = hc.PostForm(f.server.URL+"/portal/admin/users/"+strconv.FormatInt(bob.ID, 10), url.Values{
		"email":    {"bob2@example.com"},
		"is_admin": {"1"},
	})
	if err != nil {
		t.Fatalf("update user: %v", err)
	}
	resp.Body.Close()
	bob, err = f.users.GetByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatalf("reload bob: %v", err)
	}
	if bob.Email != "bob2@example.com" || !bob.IsAdmin {
		t.Fatalf("unexpected bob after update: %+v", bob)
	}

	resp, err = hc.PostForm(f.server.URL+"/portal/admin/users/"+strconv.FormatInt(bob.ID, 10)+"/password", url.Values{
		"password": {"newbobpassword"},
	})
	if err != nil {
		t.Fatalf("set password: %v", err)
	}
	resp.Body.Close()
	if _, err := f.users.Verify(context.Background(), "bob", "newbobpassword"); err != nil {
		t.Fatalf("verify new password: %v", err)
	}

	resp, err = hc.PostForm(f.server.URL+"/portal/admin/users/"+strconv.FormatInt(bob.ID, 10)+"/delete", nil)
	if err != nil {
		t.Fatalf("delete user: %v", err)
	}
	resp.Body.Close()
	if _, err := f.users.GetByUsername(context.Background(), "bob"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("bob should be deleted, got %v", err)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met before timeout")
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
