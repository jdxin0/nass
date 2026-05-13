package apps_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
	_ "github.com/jdxin0/nass/internal/apps/blinko"
	_ "github.com/jdxin0/nass/internal/apps/firefly"
	_ "github.com/jdxin0/nass/internal/apps/gitea"
	_ "github.com/jdxin0/nass/internal/apps/immich"
	_ "github.com/jdxin0/nass/internal/apps/jellyfin"
	_ "github.com/jdxin0/nass/internal/apps/linkwarden"
	_ "github.com/jdxin0/nass/internal/apps/nextcloud"
	_ "github.com/jdxin0/nass/internal/apps/paperless"
	_ "github.com/jdxin0/nass/internal/apps/qbittorrent"
	"github.com/jdxin0/nass/internal/db"
	"github.com/jdxin0/nass/internal/orchestrator"
)

func TestRegistryHasNextcloud(t *testing.T) {
	s, ok := apps.Get("nextcloud")
	if !ok {
		t.Fatalf("nextcloud not registered")
	}
	if s.Name != "nextcloud" || s.BackendPort == 0 || !s.NeedsOIDC {
		t.Fatalf("unexpected spec: %+v", s)
	}
}

func TestAllSorted(t *testing.T) {
	all := apps.All()
	for i := 1; i < len(all); i++ {
		if all[i-1].Name > all[i].Name {
			t.Fatalf("not sorted: %v", names(all))
		}
	}
}

func TestPublicURLAndDiscovery(t *testing.T) {
	ic := &apps.InstallContext{
		Name:         "x",
		Subdomain:    "x",
		BaseHost:     "nass.local",
		PublicScheme: "https",
		PublicPort:   ":8443",
		OIDCIssuer:   "https://auth.nass.local",
	}
	if got := ic.PublicHost(); got != "x.nass.local:8443" {
		t.Errorf("PublicHost: %q", got)
	}
	if got := ic.PublicURL(); got != "https://x.nass.local:8443" {
		t.Errorf("PublicURL: %q", got)
	}
	if got := ic.OIDCDiscoveryURL(); got != "https://auth.nass.local/.well-known/openid-configuration" {
		t.Errorf("OIDCDiscoveryURL: %q", got)
	}
}

// TestInstallRendersComposeWithoutRunning verifies that the installer renders
// the compose file and persists settings for an app whose hooks are no-ops
// and whose Spec.NeedsOIDC is false. This covers everything except the
// orchestrator + OIDC client provisioning.
func TestInstallRendersComposeNoOIDC(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer d.Close()

	root := t.TempDir()
	composeFile := filepath.Join(root, "compose", "x", "docker-compose.yaml")
	dataRoot := filepath.Join(root, "data", "x")
	tmpl := []byte("services:\n  x:\n    image: nginx\n    ports:\n      - {{.BackendPort}}:80\n    volumes:\n      - {{.DataRoot}}:/srv\n")
	spec := apps.Spec{
		Name: "noop", DisplayName: "Noop", Subdomain: "noop", BackendPort: 9999,
		PreserveHost:    true,
		NeedsOIDC:       false,
		ComposeTemplate: tmpl,
	}
	// Use a fake orchestrator that intercepts compose up. In tests, "true"
	// is a benign command that always exits 0.
	orch := orchestrator.New(filepath.Join(root, "compose"), "true")

	ic := &apps.InstallContext{
		Spec: &spec, Name: spec.Name, Subdomain: spec.Subdomain, BaseHost: "test.local",
		PublicScheme: "https", BackendPort: spec.BackendPort,
		DataRoot: dataRoot, ComposeFile: composeFile,
		DB: d, Orchestrator: orch,
	}
	res, err := apps.Install(context.Background(), ic)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.AppName != "noop" {
		t.Fatalf("res: %+v", res)
	}
	if res.BackendPort != spec.BackendPort {
		t.Fatalf("backend port: got %d want %d", res.BackendPort, spec.BackendPort)
	}
	body, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	if !strings.Contains(string(body), "9999:80") || !strings.Contains(string(body), dataRoot) {
		t.Fatalf("compose template not rendered properly:\n%s", body)
	}
	if _, err := os.Stat(dataRoot); err != nil {
		t.Fatalf("data root not created: %v", err)
	}
	if res.OIDCClientID != "" {
		t.Fatalf("expected no OIDC creds for NeedsOIDC=false, got %q", res.OIDCClientID)
	}
}

func TestInstallFallsBackToFreeBackendPortWhenDefaultIsBusy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer d.Close()

	busy := occupyLocalPort(t)
	fallback := freeLocalPort(t)
	root := t.TempDir()
	composeFile := filepath.Join(root, "compose", "x", "docker-compose.yaml")
	dataRoot := filepath.Join(root, "data", "x")
	tmpl := []byte("services:\n  x:\n    image: nginx\n    ports:\n      - \"127.0.0.1:{{.BackendPort}}:80\"\n")
	spec := apps.Spec{
		Name: "porttest", DisplayName: "Port Test", Subdomain: "porttest", BackendPort: busy,
		PreserveHost:    true,
		ComposeTemplate: tmpl,
	}
	orch := orchestrator.New(filepath.Join(root, "compose"), "true")

	ic := &apps.InstallContext{
		Spec: &spec, Name: spec.Name, Subdomain: spec.Subdomain, BaseHost: "test.local",
		PublicScheme: "https", BackendPort: spec.BackendPort, BackendPortRange: fmt.Sprintf("%d-%d", fallback, fallback),
		DataRoot: dataRoot, ComposeFile: composeFile,
		DB: d, Orchestrator: orch,
	}
	res, err := apps.Install(context.Background(), ic)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	body, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	if !strings.Contains(string(body), fmt.Sprintf("127.0.0.1:%d:80", fallback)) {
		t.Fatalf("compose did not use fallback port %d:\n%s", fallback, body)
	}
	if ic.BackendPort != fallback {
		t.Fatalf("context backend port: got %d want %d", ic.BackendPort, fallback)
	}
	if res.BackendPort != fallback {
		t.Fatalf("result backend port: got %d want %d", res.BackendPort, fallback)
	}
}

func TestNextcloudComposeRenders(t *testing.T) {
	s, _ := apps.Get("nextcloud")
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:         "/srv/nass/data/nextcloud",
		AdminPassword:    "abcd1234",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	// Render via the same template the installer uses by writing manually.
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: nextcloud:",
		"OVERWRITEHOST: nextcloud.nass.local",
		"OVERWRITECLIURL: https://nextcloud.nass.local",
		"NEXTCLOUD_ADMIN_PASSWORD: abcd1234",
		"127.0.0.1:18080:80",
		"/srv/nass/data/nextcloud:/var/www/html",
		"auth.nass.local:host-gateway",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestImmichComposeRenders(t *testing.T) {
	s, ok := apps.Get("immich")
	if !ok {
		t.Fatalf("immich not registered")
	}
	if !s.NeedsOIDC {
		t.Fatalf("immich should need OIDC: %+v", s)
	}
	if s.OIDCGate {
		t.Fatalf("immich uses native OIDC, not the proxy gate: %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:         "/srv/nass/data/immich",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: ghcr.io/immich-app/immich-server:",
		"image: ghcr.io/immich-app/immich-machine-learning:",
		"127.0.0.1:18283:2283",
		"/srv/nass/data/immich/upload:/usr/src/app/upload",
		"/srv/nass/data/immich/ml-cache:/cache",
		"/srv/nass/data/immich/postgres:/var/lib/postgresql/data",
		"./immich-config.json:/immich-config.json",
		"DB_HOSTNAME: immich_postgres",
		"REDIS_HOSTNAME: immich_redis",
		"auth.nass.local:host-gateway",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestBlinkoComposeRenders(t *testing.T) {
	s, ok := apps.Get("blinko")
	if !ok {
		t.Fatalf("blinko not registered")
	}
	if !s.NeedsOIDC {
		t.Fatalf("blinko should need OIDC: %+v", s)
	}
	if s.OIDCGate {
		t.Fatalf("blinko uses native OIDC, not the proxy gate: %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:         "/srv/nass/data/blinko",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	if got := s.OIDCRedirectURIs(ic); len(got) != 1 || got[0] != "https://blinko.nass.local/api/auth/callback/nass" {
		t.Fatalf("redirect URIs: got %v", got)
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: blinkospace/blinko:",
		"image: postgres:14",
		"127.0.0.1:11111:1111",
		"/srv/nass/data/blinko/app:/app/.blinko",
		"/srv/nass/data/blinko/postgres:/var/lib/postgresql/data",
		"NEXTAUTH_URL: https://blinko.nass.local",
		"NEXT_PUBLIC_BASE_URL: https://blinko.nass.local",
		"DATABASE_URL: postgresql://postgres:postgres@blinko_postgres:5432/postgres",
		"auth.nass.local:host-gateway",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestGiteaComposeRenders(t *testing.T) {
	s, ok := apps.Get("gitea")
	if !ok {
		t.Fatalf("gitea not registered")
	}
	if !s.NeedsOIDC {
		t.Fatalf("gitea should need OIDC: %+v", s)
	}
	if s.OIDCGate {
		t.Fatalf("gitea uses native OIDC, not the proxy gate: %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:         "/srv/nass/data/gitea",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	if got := s.OIDCRedirectURIs(ic); len(got) != 1 || got[0] != "https://gitea.nass.local/user/oauth2/nass/callback" {
		t.Fatalf("redirect URIs: got %v", got)
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: docker.gitea.com/gitea:",
		"127.0.0.1:13000:3000",
		"/srv/nass/data/gitea:/data",
		"GITEA__server__DOMAIN: gitea.nass.local",
		"GITEA__server__ROOT_URL: https://gitea.nass.local/",
		"GITEA__oauth2_client__ENABLE_AUTO_REGISTRATION: \"true\"",
		"GITEA__oauth2_client__USERNAME: preferred_username",
		"auth.nass.local:host-gateway",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestLinkwardenComposeRenders(t *testing.T) {
	s, ok := apps.Get("linkwarden")
	if !ok {
		t.Fatalf("linkwarden not registered")
	}
	if !s.NeedsOIDC {
		t.Fatalf("linkwarden should need OIDC: %+v", s)
	}
	if s.OIDCGate {
		t.Fatalf("linkwarden uses native OIDC, not the proxy gate: %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:         "/srv/nass/data/linkwarden",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	if got := s.OIDCRedirectURIs(ic); len(got) != 1 || got[0] != "https://linkwarden.nass.local/api/v1/auth/callback/authelia" {
		t.Fatalf("redirect URIs: got %v", got)
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: ghcr.io/linkwarden/linkwarden:",
		"image: postgres:16-alpine",
		"image: getmeili/meilisearch:",
		"127.0.0.1:13001:3000",
		"/srv/nass/data/linkwarden/data:/data/data",
		"/srv/nass/data/linkwarden/postgres:/var/lib/postgresql/data",
		"/srv/nass/data/linkwarden/meili:/meili_data",
		"NEXTAUTH_URL: https://linkwarden.nass.local/api/v1/auth",
		"BASE_URL: https://linkwarden.nass.local",
		"DATABASE_URL: postgresql://postgres:",
		"@postgres:5432/postgres",
		"MEILI_HOST: http://meilisearch:7700",
		"NEXT_PUBLIC_AUTHELIA_ENABLED: \"true\"",
		"AUTHELIA_WELLKNOWN_URL: https://auth.nass.local/.well-known/openid-configuration",
		"AUTHELIA_CLIENT_ID: cid",
		"AUTHELIA_CLIENT_SECRET: sec",
		"NEXT_PUBLIC_CREDENTIALS_ENABLED: \"false\"",
		"auth.nass.local:host-gateway",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestJellyfinComposeRenders(t *testing.T) {
	s, ok := apps.Get("jellyfin")
	if !ok {
		t.Fatalf("jellyfin not registered")
	}
	if !s.NeedsOIDC {
		t.Fatalf("jellyfin should need OIDC: %+v", s)
	}
	if s.OIDCGate {
		t.Fatalf("jellyfin uses native SSO plugin, not the proxy gate: %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:         "/srv/nass/data/jellyfin",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: jellyfin/jellyfin:",
		"127.0.0.1:18096:8096",
		"/srv/nass/data/jellyfin/config:/config",
		"/srv/nass/data/jellyfin/cache:/cache",
		"JELLYFIN_PublishedServerUrl: https://jellyfin.nass.local",
		"auth.nass.local:host-gateway",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestPaperlessComposeRenders(t *testing.T) {
	s, ok := apps.Get("paperless")
	if !ok {
		t.Fatalf("paperless not registered")
	}
	if !s.NeedsOIDC {
		t.Fatalf("paperless should need OIDC: %+v", s)
	}
	if s.OIDCGate {
		t.Fatalf("paperless uses native OIDC, not the proxy gate: %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:         "/srv/nass/data/paperless",
		AdminPassword:    "abcd1234",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	if got := s.OIDCRedirectURIs(ic); len(got) != 1 || got[0] != "https://paperless.nass.local/accounts/oidc/nass/login/callback/" {
		t.Fatalf("redirect URIs: got %v", got)
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: ghcr.io/paperless-ngx/paperless-ngx:",
		"image: postgres:16-alpine",
		"image: redis:7-alpine",
		"127.0.0.1:18040:8000",
		"/srv/nass/data/paperless/data:/usr/src/paperless/data",
		"/srv/nass/data/paperless/media:/usr/src/paperless/media",
		"/srv/nass/data/paperless/consume:/usr/src/paperless/consume",
		"/srv/nass/data/paperless/postgres:/var/lib/postgresql/data",
		"/srv/nass/data/paperless/redis:/data",
		"PAPERLESS_URL: https://paperless.nass.local",
		`PAPERLESS_ALLOWED_HOSTS: "paperless.nass.local"`,
		"PAPERLESS_CORS_ALLOWED_HOSTS: https://paperless.nass.local",
		"PAPERLESS_DBHOST: postgres",
		"PAPERLESS_DBPASS: abcd1234",
		"PAPERLESS_REDIS: redis://redis:6379",
		"PAPERLESS_APPS: allauth.socialaccount.providers.openid_connect",
		`"client_id":"cid"`,
		`"secret":"sec"`,
		`"server_url":"https://auth.nass.local/.well-known/openid-configuration"`,
		"auth.nass.local:host-gateway",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestFireflyComposeRenders(t *testing.T) {
	s, ok := apps.Get("firefly")
	if !ok {
		t.Fatalf("firefly not registered")
	}
	if s.NeedsOIDC {
		t.Fatalf("firefly has no native OIDC; expected NeedsOIDC=false: %+v", s)
	}
	if !s.OIDCGate {
		t.Fatalf("firefly should be portal-gated (remote_user_guard): %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot:      "/srv/nass/data/firefly",
		AdminPassword: "abcd1234",
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: fireflyiii/core:",
		"image: postgres:16-alpine",
		"127.0.0.1:18030:8080",
		"/srv/nass/data/firefly/upload:/var/www/html/storage/upload",
		"/srv/nass/data/firefly/postgres:/var/lib/postgresql/data",
		"/srv/nass/data/firefly/firefly.env",
		"APP_URL: https://firefly.nass.local",
		"DB_HOST: firefly_postgres",
		"DB_PASSWORD: abcd1234",
		"AUTHENTICATION_GUARD: remote_user_guard",
		"AUTHENTICATION_GUARD_HEADER: HTTP_REMOTE_USER",
		"AUTHENTICATION_GUARD_EMAIL: HTTP_REMOTE_EMAIL",
		`TRUSTED_PROXIES: "**"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestQbittorrentComposeRenders(t *testing.T) {
	s, ok := apps.Get("qbittorrent")
	if !ok {
		t.Fatalf("qbittorrent not registered")
	}
	if s.NeedsOIDC {
		t.Fatalf("qbittorrent should not need OIDC: %+v", s)
	}
	if !s.OIDCGate {
		t.Fatalf("qbittorrent should be OIDC-gated: %+v", s)
	}
	ic := &apps.InstallContext{
		Spec: &s, Name: s.Name, Subdomain: s.Subdomain, BaseHost: "nass.local",
		PublicScheme: "https", BackendPort: s.BackendPort,
		DataRoot: "/srv/nass/data/qbittorrent",
	}
	dir := t.TempDir()
	ic.ComposeFile = filepath.Join(dir, "compose.yaml")
	if err := apps.RenderCompose(ic); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, _ := os.ReadFile(ic.ComposeFile)
	for _, want := range []string{
		"image: lscr.io/linuxserver/qbittorrent",
		"127.0.0.1:18100:8080",
		"/srv/nass/data/qbittorrent/config:/config",
		"/srv/nass/data/qbittorrent/downloads:/downloads",
		"6881:6881",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(string(body), "oauth2-proxy") {
		t.Errorf("qbittorrent compose should not include oauth2-proxy (we use the proxy gate now):\n%s", body)
	}
}

func names(specs []apps.Spec) []string {
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = s.Name
	}
	return out
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func occupyLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}
