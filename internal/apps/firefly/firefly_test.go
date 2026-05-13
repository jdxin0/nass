package firefly

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestPreUpWritesStableEnvFile(t *testing.T) {
	root := t.TempDir()
	ic := &apps.InstallContext{DataRoot: root}

	if err := preUp(context.Background(), ic); err != nil {
		t.Fatalf("preUp: %v", err)
	}
	envPath := filepath.Join(root, envFileName)
	first, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	body := string(first)
	if !strings.Contains(body, "APP_KEY=") {
		t.Errorf("missing APP_KEY: %s", body)
	}
	if !strings.Contains(body, "STATIC_CRON_TOKEN=") {
		t.Errorf("missing STATIC_CRON_TOKEN: %s", body)
	}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed line %q", line)
		}
		if len(v) != 32 {
			t.Errorf("%s value is %d chars, want 32: %q", k, len(v), v)
		}
	}

	// Second run must be a no-op: file content stays identical so that
	// Laravel's APP_KEY (and therefore encrypted DB data) stays valid.
	if err := preUp(context.Background(), ic); err != nil {
		t.Fatalf("preUp 2: %v", err)
	}
	second, _ := os.ReadFile(envPath)
	if string(first) != string(second) {
		t.Fatalf("env file changed on re-run:\nfirst:\n%s\nsecond:\n%s", first, second)
	}

	info, _ := os.Stat(envPath)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("env file perm: got %o want 600", perm)
	}
}
