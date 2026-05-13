// Package jitsi is the nass app module for Jitsi Meet.
//
// Jitsi has no native OIDC. We portal-gate the web entry (Spec.OIDCGate)
// and run Jitsi with ENABLE_AUTH=0; anyone who reaches the page is already
// authenticated by the portal. The signalling (WebSocket/BOSH) goes through
// the nass reverse proxy, but the video bridge (JVB) is direct UDP between
// clients and the host on port 10000 — nass does not proxy that.
//
// PreUp detects the host's primary outbound IP and writes it to a .env
// file next to the compose file so JVB can advertise it to clients.
// On a multi-NIC host or behind NAT, edit that .env after install.
package jitsi

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const envFileName = ".env"

func init() {
	apps.Register(apps.Spec{
		Name:            "jitsi",
		DisplayName:     "Jitsi Meet",
		Description:     "Video conferencing in the browser",
		Icon:            "🎥",
		Subdomain:       "meet",
		BackendPort:     18060,
		PreserveHost:    true,
		NeedsOIDC:       false,
		OIDCGate:        true,
		ComposeTemplate: composeTemplate,
		PreUp:           preUp,
		PostUp:          postUp,
	})
}

// preUp writes JITSI_DOCKER_HOST_ADDRESS into a .env file next to the
// compose file so the JVB media bridge advertises a routable IP to
// clients. docker compose reads .env from the compose project directory
// automatically. Re-written on every install so it tracks IP changes.
func preUp(ctx context.Context, ic *apps.InstallContext) error {
	ip, err := detectHostIP()
	if err != nil {
		return fmt.Errorf("detect host IP: %w", err)
	}
	envPath := filepath.Join(filepath.Dir(ic.ComposeFile), envFileName)
	body := fmt.Sprintf("JITSI_DOCKER_HOST_ADDRESS=%s\n", ip)
	return os.WriteFile(envPath, []byte(body), 0o600)
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	target := fmt.Sprintf("http://127.0.0.1:%d/", ic.BackendPort)
	if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
		return fmt.Errorf("wait for jitsi: %w", err)
	}
	return nil
}

// detectHostIP returns the IP of the interface used to reach the public
// internet. We dial a UDP socket — UDP doesn't actually send anything
// until Write — so this resolves the route without touching the network.
func detectHostIP() (string, error) {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}
