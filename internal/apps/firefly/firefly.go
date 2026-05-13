// Package firefly is the nass app module for Firefly III.
//
// Firefly III has no native OIDC support. We gate the route through the
// portal (Spec.OIDCGate) and configure Firefly's `remote_user_guard` to
// read the Remote-User / Remote-Email headers that portal.Gate injects on
// authenticated requests. APP_KEY and STATIC_CRON_TOKEN are generated
// once in PreUp and persisted next to the compose file so they survive
// container recreation.
package firefly

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const envFileName = "firefly.env"

func init() {
	apps.Register(apps.Spec{
		Name:            "firefly",
		DisplayName:     "Firefly III",
		Description:     "Personal finance manager",
		Icon:            "💰",
		Subdomain:       "firefly",
		BackendPort:     18030,
		PreserveHost:    true,
		NeedsOIDC:       false,
		OIDCGate:        true,
		ComposeTemplate: composeTemplate,
		PreUp:           preUp,
		PostUp:          postUp,
	})
}

// preUp writes APP_KEY and STATIC_CRON_TOKEN to {DataRoot}/firefly.env on
// first install. Both are 32-char hex strings as Firefly III requires.
// The file is kept stable across re-installs so encrypted data in the DB
// remains decryptable.
func preUp(ctx context.Context, ic *apps.InstallContext) error {
	envPath := filepath.Join(ic.DataRoot, envFileName)
	if _, err := os.Stat(envPath); err == nil {
		return nil
	}
	appKey, err := randomHex(16)
	if err != nil {
		return fmt.Errorf("APP_KEY: %w", err)
	}
	cronToken, err := randomHex(16)
	if err != nil {
		return fmt.Errorf("STATIC_CRON_TOKEN: %w", err)
	}
	body := fmt.Sprintf("APP_KEY=%s\nSTATIC_CRON_TOKEN=%s\n", appKey, cronToken)
	return os.WriteFile(envPath, []byte(body), 0o600)
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for firefly: %w", err)
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
