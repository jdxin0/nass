// Package qbittorrent is the nass app module for qBittorrent.
//
// qBittorrent has no native OIDC, so we don't provision an OIDC client.
// Instead the proxy gates the route with a portal session (Spec.OIDCGate).
// PostUp patches qBittorrent.conf to disable the WebUI's own auth and host
// header validation so reverse-proxied access from a portal-authenticated
// user works without a second login.
package qbittorrent

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

// Path of the conf file inside the container's /config volume. The host
// path is filepath.Join(ic.DataRoot, "config", confSubpath).
const confSubpath = "qBittorrent/qBittorrent.conf"

// Keys we force in the [Preferences] section. Backslash is part of the key
// name in Qt's INI format (e.g. "WebUI\HostHeaderValidation"), not a regex
// escape — we pass these to plain string ops, never to sed/regex.
var webUISettings = map[string]string{
	`WebUI\HostHeaderValidation`:      "false",
	`WebUI\AuthSubnetWhitelistEnabled`: "true",
	`WebUI\AuthSubnetWhitelist`:        "0.0.0.0/0",
	`WebUI\CSRFProtection`:             "false",
}

func init() {
	apps.Register(apps.Spec{
		Name:            "qbittorrent",
		DisplayName:     "qBittorrent",
		Description:     "Torrent client",
		Icon:            "🧲",
		Subdomain:       "qbittorrent",
		BackendPort:     18100,
		PreserveHost:    true,
		NeedsOIDC:       false,
		OIDCGate:        true,
		ComposeTemplate: composeTemplate,
		PostUp:          postUp,
	})
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	// 1. Wait for qBittorrent's WebUI to come up — qBittorrent only writes the
	// conf file once it has fully started.
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for qbittorrent: %w", err)
	}

	confPath := filepath.Join(ic.DataRoot, "config", confSubpath)
	if err := waitForFile(ctx, confPath, 30*time.Second); err != nil {
		return fmt.Errorf("wait for conf file: %w", err)
	}

	body, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", confPath, err)
	}
	patched, changed := patchConf(string(body), webUISettings)
	if !changed {
		return nil
	}

	// 2. SIGKILL qbittorrent before writing — on SIGTERM it flushes its
	// in-memory preferences and would clobber our edits.
	if _, err := ic.Orchestrator.Kill(ctx, ic.ComposeFile, "qbittorrent"); err != nil {
		return fmt.Errorf("kill qbittorrent: %w", err)
	}
	if err := os.WriteFile(confPath, []byte(patched), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", confPath, err)
	}
	if _, err := ic.Orchestrator.Up(ctx, ic.ComposeFile); err != nil {
		return fmt.Errorf("restart qbittorrent: %w", err)
	}

	upCtx, cancel2 := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel2()
	return apps.WaitFor(upCtx, target, 2*time.Second)
}

func waitForFile(ctx context.Context, path string, timeout time.Duration) error {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-deadline.Done():
			return deadline.Err()
		case <-time.After(time.Second):
		}
	}
}

// patchConf applies kv to a Qt-style INI body. For each key it replaces an
// existing `key=...` line in place; missing keys are inserted into
// [Preferences] (the section is created if absent). Returns the new body and
// whether anything changed.
func patchConf(body string, kv map[string]string) (string, bool) {
	lines := strings.Split(body, "\n")
	seen := map[string]bool{}
	changed := false
	for i, line := range lines {
		for k, v := range kv {
			if strings.HasPrefix(line, k+"=") {
				want := k + "=" + v
				if line != want {
					lines[i] = want
					changed = true
				}
				seen[k] = true
			}
		}
	}

	var missing []string
	for k, v := range kv {
		if !seen[k] {
			missing = append(missing, k+"="+v)
		}
	}
	if len(missing) == 0 {
		if !changed {
			return body, false
		}
		return strings.Join(lines, "\n"), true
	}
	sort.Strings(missing)

	// Insert missing keys after the last existing line in [Preferences],
	// or create the section at the end if it doesn't exist.
	insertAt := -1
	inPrefs := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "[Preferences]" {
			inPrefs = true
			insertAt = i + 1
			continue
		}
		if inPrefs {
			if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
				break
			}
			if t != "" {
				insertAt = i + 1
			}
		}
	}
	if insertAt < 0 {
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "[Preferences]")
		lines = append(lines, missing...)
	} else {
		out := make([]string, 0, len(lines)+len(missing))
		out = append(out, lines[:insertAt]...)
		out = append(out, missing...)
		out = append(out, lines[insertAt:]...)
		lines = out
	}
	return strings.Join(lines, "\n"), true
}
