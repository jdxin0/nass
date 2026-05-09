package cli

import (
	"os"
	"path/filepath"
	"testing"

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
