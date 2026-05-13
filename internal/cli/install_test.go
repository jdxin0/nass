package cli

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
	"github.com/jdxin0/nass/internal/config"
)

func TestResolveUninstallPathsDoesNotGuessForManualRoutes(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Orchestrator: config.Orchestrator{
			ComposeRoot: filepath.Join(root, "apps"),
			DataRoot:    filepath.Join(root, "data"),
		},
	}

	composeFile, dataRoot := resolveUninstallPaths(cfg, "manual", "", "")
	if composeFile != "" || dataRoot != "" {
		t.Fatalf("got compose=%q data=%q, want both empty", composeFile, dataRoot)
	}
}

func TestResolveUninstallPathsFallsBackForLegacyInstall(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Orchestrator: config.Orchestrator{
			ComposeRoot: filepath.Join(root, "apps"),
			DataRoot:    filepath.Join(root, "data"),
		},
	}
	wantCompose := filepath.Join(cfg.Orchestrator.ComposeRoot, "nextcloud", "docker-compose.yaml")
	if err := os.MkdirAll(filepath.Dir(wantCompose), 0o755); err != nil {
		t.Fatalf("mkdir compose dir: %v", err)
	}
	if err := os.WriteFile(wantCompose, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatalf("write compose: %v", err)
	}

	composeFile, dataRoot := resolveUninstallPaths(cfg, "nextcloud", "", "")
	if composeFile != wantCompose {
		t.Fatalf("compose: got %q want %q", composeFile, wantCompose)
	}
	wantData := filepath.Join(cfg.Orchestrator.DataRoot, "nextcloud")
	if dataRoot != wantData {
		t.Fatalf("data: got %q want %q", dataRoot, wantData)
	}
}

func TestBuildInstallContextUsesConfiguredBackendPortRange(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Server: config.Server{BaseHost: "nass.local"},
		OIDC:   config.OIDC{Issuer: "https://auth.nass.local"},
		Orchestrator: config.Orchestrator{
			ComposeRoot:      filepath.Join(root, "apps"),
			DataRoot:         filepath.Join(root, "data"),
			DockerCompose:    "true",
			BackendPortRange: "24000-24999",
		},
	}
	spec := &apps.Spec{Name: "demo", Subdomain: "demo", BackendPort: 18080}

	ic, err := buildInstallContext((*sql.DB)(nil), cfg, spec, "", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("build context: %v", err)
	}
	if ic.BackendPortRange != "24000-24999" {
		t.Fatalf("BackendPortRange: got %q", ic.BackendPortRange)
	}
	if ic.BackendPortExplicit {
		t.Fatalf("BackendPortExplicit should be false without --backend-port")
	}
}

func TestBuildInstallContextMarksExplicitBackendPort(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		Server: config.Server{BaseHost: "nass.local"},
		OIDC:   config.OIDC{Issuer: "https://auth.nass.local"},
		Orchestrator: config.Orchestrator{
			ComposeRoot:      filepath.Join(root, "apps"),
			DataRoot:         filepath.Join(root, "data"),
			DockerCompose:    "true",
			BackendPortRange: apps.DefaultBackendPortRange,
		},
	}
	spec := &apps.Spec{Name: "demo", Subdomain: "demo", BackendPort: 18080}

	ic, err := buildInstallContext((*sql.DB)(nil), cfg, spec, "", "", "", "", "", 25001)
	if err != nil {
		t.Fatalf("build context: %v", err)
	}
	if ic.BackendPort != 25001 {
		t.Fatalf("BackendPort: got %d want 25001", ic.BackendPort)
	}
	if !ic.BackendPortExplicit {
		t.Fatalf("BackendPortExplicit should be true with --backend-port")
	}
}
