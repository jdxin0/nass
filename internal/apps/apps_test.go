package apps_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
	_ "github.com/jdxin0/nass/internal/apps/immich"
	_ "github.com/jdxin0/nass/internal/apps/jellyfin"
	_ "github.com/jdxin0/nass/internal/apps/nextcloud"
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
