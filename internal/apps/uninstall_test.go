package apps

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/jdxin0/nass/internal/db"
)

func TestUninstallRemovesAppFilesAndData(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	if _, err := d.ExecContext(ctx,
		`INSERT INTO apps(name, enabled, settings_json) VALUES ('demo', 1, '{}')`); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	root := t.TempDir()
	composeFile := filepath.Join(root, "apps", "demo", "docker-compose.yaml")
	dataRoot := filepath.Join(root, "data", "demo")
	if err := os.MkdirAll(filepath.Dir(composeFile), 0o755); err != nil {
		t.Fatalf("mkdir compose dir: %v", err)
	}
	if err := os.WriteFile(composeFile, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatalf("write compose: %v", err)
	}
	if err := os.MkdirAll(dataRoot, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}

	if err := Uninstall(ctx, &UninstallContext{
		Name:        "demo",
		ComposeFile: composeFile,
		DataRoot:    dataRoot,
		DB:          d,
	}); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(composeFile); !os.IsNotExist(err) {
		t.Fatalf("compose file still exists or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(dataRoot); !os.IsNotExist(err) {
		t.Fatalf("data root still exists or unexpected stat error: %v", err)
	}
	if got := countApps(t, d); got != 0 {
		t.Fatalf("apps rows: got %d want 0", got)
	}
}

func TestUninstallKeepData(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	if _, err := d.ExecContext(ctx,
		`INSERT INTO apps(name, enabled, settings_json) VALUES ('demo', 1, '{}')`); err != nil {
		t.Fatalf("insert app: %v", err)
	}
	dataRoot := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dataRoot, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}

	if err := Uninstall(ctx, &UninstallContext{
		Name:     "demo",
		DataRoot: dataRoot,
		KeepData: true,
		DB:       d,
	}); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(dataRoot); err != nil {
		t.Fatalf("data root should be preserved: %v", err)
	}
}

func countApps(t *testing.T, d *sql.DB) int {
	t.Helper()
	var n int
	if err := d.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM apps`).Scan(&n); err != nil {
		t.Fatalf("count apps: %v", err)
	}
	return n
}
