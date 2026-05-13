package proxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/db"
	"github.com/jdxin0/nass/internal/proxy"
)

func TestServerHostRouting(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "from-a:"+r.URL.Path)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "from-b:"+r.URL.Path)
	}))
	defer b.Close()

	router := proxy.New()
	router.AddRoute("a.example.com", proxy.NewReverseProxy(proxy.BackendOptions{Backend: mustURL(t, a.URL)}))
	router.AddRoute("b.example.com", proxy.NewReverseProxy(proxy.BackendOptions{Backend: mustURL(t, b.URL)}))

	front := httptest.NewServer(router)
	defer front.Close()

	cases := []struct {
		host string
		want string
		code int
	}{
		{"a.example.com", "from-a:/x", http.StatusOK},
		{"A.EXAMPLE.COM", "from-a:/x", http.StatusOK},
		{"a.example.com:8443", "from-a:/x", http.StatusOK},
		{"b.example.com", "from-b:/x", http.StatusOK},
		{"unknown.example.com", "no route for host unknown.example.com", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			req, _ := http.NewRequest("GET", front.URL+"/x", nil)
			req.Host = tc.host
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.code {
				t.Fatalf("status: got %d want %d (body=%q)", resp.StatusCode, tc.code, body)
			}
			if !strings.Contains(string(body), tc.want) {
				t.Fatalf("body: got %q want substring %q", body, tc.want)
			}
		})
	}
}

func TestForwardedHeaders(t *testing.T) {
	got := map[string]string{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got["X-Forwarded-Proto"] = r.Header.Get("X-Forwarded-Proto")
		got["X-Forwarded-For"] = r.Header.Get("X-Forwarded-For")
		got["X-Forwarded-Host"] = r.Header.Get("X-Forwarded-Host")
		got["Host"] = r.Host
	}))
	defer backend.Close()

	router := proxy.New()
	router.AddRoute("app.example.com", proxy.NewReverseProxy(proxy.BackendOptions{
		Backend:      mustURL(t, backend.URL),
		PreserveHost: true,
	}))
	front := httptest.NewServer(router)
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/", nil)
	req.Host = "app.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if got["X-Forwarded-Host"] != "app.example.com" {
		t.Errorf("X-Forwarded-Host: got %q", got["X-Forwarded-Host"])
	}
	if got["X-Forwarded-Proto"] != "http" {
		t.Errorf("X-Forwarded-Proto: got %q", got["X-Forwarded-Proto"])
	}
	if got["X-Forwarded-For"] == "" {
		t.Error("X-Forwarded-For empty")
	}
	if got["Host"] != "app.example.com" {
		t.Errorf("preserved Host: got %q", got["Host"])
	}
}

// TestWebsocketPassThrough verifies the proxy passes through Upgrade/Connection
// headers and bidirectionally streams once the upgrade succeeds. Uses a raw
// hijacked TCP backend to avoid pulling in a websocket dependency.
func TestWebsocketPassThrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected Upgrade: websocket", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer conn.Close()
		// Send a 101 + an echo of one line.
		fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\n")
		fmt.Fprintf(brw, "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		brw.Flush()

		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		brw.WriteString("echo: " + line)
		brw.Flush()
	}))
	defer backend.Close()

	router := proxy.New()
	router.AddRoute("ws.example.com", proxy.NewReverseProxy(proxy.BackendOptions{Backend: mustURL(t, backend.URL)}))
	front := httptest.NewServer(router)
	defer front.Close()

	frontURL, _ := url.Parse(front.URL)
	conn, err := net.Dial("tcp", frontURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status: got %d want 101", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("Upgrade header: got %q", resp.Header.Get("Upgrade"))
	}

	fmt.Fprintf(conn, "hello\n")
	echo, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !strings.HasPrefix(echo, "echo: hello") {
		t.Fatalf("unexpected echo: %q", echo)
	}
}

// TestServerStripsRemoteIdentityHeaders verifies that a client cannot smuggle
// the trusted Remote-* headers past the front-door router. Backends that read
// these (Firefly's remote_user_guard) must only see them when set by the gate.
func TestServerStripsRemoteIdentityHeaders(t *testing.T) {
	var seen http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	defer backend.Close()

	router := proxy.New()
	router.AddRoute("app.example.com", proxy.NewReverseProxy(proxy.BackendOptions{Backend: mustURL(t, backend.URL)}))
	front := httptest.NewServer(router)
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/", nil)
	req.Host = "app.example.com"
	req.Header.Set("Remote-User", "evil")
	req.Header.Set("Remote-Email", "evil@example.com")
	req.Header.Set("Remote-Name", "evil")
	req.Header.Set("Remote-Groups", "admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	for _, h := range []string{"Remote-User", "Remote-Email", "Remote-Name", "Remote-Groups"} {
		if got := seen.Get(h); got != "" {
			t.Errorf("%s should have been stripped, got %q", h, got)
		}
	}
}

func TestLoadEnabled(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	if err := proxy.SaveSettings(ctx, d, "nextcloud", proxy.AppSettings{
		Subdomain: "nextcloud", Backend: "http://127.0.0.1:18080", PreserveHost: true,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := proxy.SaveSettings(ctx, d, "qb", proxy.AppSettings{
		Subdomain: "qb", Backend: "http://127.0.0.1:18100", OIDCGate: true,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}

	routes, err := proxy.LoadEnabled(ctx, d, "example.com")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	if routes[0].Host != "nextcloud.example.com" {
		t.Errorf("first route host: got %q", routes[0].Host)
	}
	if !routes[1].Settings.OIDCGate {
		t.Errorf("qb should have oidc gate")
	}

	// HandlerFor without gate but oidc_gate=true must error.
	if _, err := proxy.HandlerFor(routes[1], nil); err == nil {
		t.Errorf("expected error when oidc_gate=true and no gate provided")
	}
}

func TestLoadEnabledRejectsMissingFields(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	if _, err := d.Exec(`INSERT INTO apps(name, enabled, settings_json) VALUES ('broken', 1, '{}')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := proxy.LoadEnabled(context.Background(), d, "example.com"); err == nil {
		t.Fatalf("expected error for missing subdomain/backend")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return u
}
