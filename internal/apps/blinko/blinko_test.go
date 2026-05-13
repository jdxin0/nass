package blinko

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

func TestSeedOAuthProviderRetriesUntilBlinkoConfigTableExists(t *testing.T) {
	ic := &apps.InstallContext{
		ComposeFile:      "/srv/nass/apps/blinko/docker-compose.yaml",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	attempts := 0
	exec := func(ctx context.Context, composeFile, service string, args ...string) (string, error) {
		attempts++
		if attempts < 3 {
			return "", errors.New(`ERROR: relation "config" does not exist`)
		}
		return "", nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := seedOAuthProvider(ctx, ic, exec, time.Millisecond); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts: got %d want 3", attempts)
	}
}
