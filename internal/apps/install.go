package apps

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/jdxin0/nass/internal/auth/oidc"
	"github.com/jdxin0/nass/internal/proxy"
)

// Result is what Install returns: the installed app's settings + the
// plaintext OIDC client_secret (shown once if NeedsOIDC).
type Result struct {
	AppName          string
	ComposeFile      string
	AdminPassword    string
	BackendPort      int
	OIDCClientID     string
	OIDCClientSecret string
}

// Install runs the full install pipeline:
//  1. resolve InstallContext defaults
//  2. provision OIDC client (if NeedsOIDC)
//  3. render compose file to disk
//  4. save AppSettings to DB
//  5. PreUp -> docker compose up -d -> PostUp
func Install(ctx context.Context, ic *InstallContext) (*Result, error) {
	if ic == nil || ic.Spec == nil {
		return nil, fmt.Errorf("install: nil context or spec")
	}
	spec := ic.Spec
	if ic.Name == "" {
		ic.Name = spec.Name
	}
	if ic.Subdomain == "" {
		ic.Subdomain = spec.Subdomain
	}
	if ic.BackendPort == 0 {
		ic.BackendPort = spec.BackendPort
	}
	selectedPort, err := SelectBackendPort(ctx, ic.BackendPort, ic.BackendPortRange, ic.BackendPortExplicit)
	if err != nil {
		return nil, err
	}
	ic.BackendPort = selectedPort
	if ic.PublicScheme == "" {
		ic.PublicScheme = "https"
	}
	if ic.AdminPassword == "" {
		pw, err := randomPassword()
		if err != nil {
			return nil, err
		}
		ic.AdminPassword = pw
	}

	if err := ic.validate(); err != nil {
		return nil, err
	}

	// 1. OIDC client.
	if spec.NeedsOIDC {
		if spec.OIDCRedirectURIs == nil {
			return nil, fmt.Errorf("app %q: NeedsOIDC=true but OIDCRedirectURIs is nil", ic.Name)
		}
		redirects := spec.OIDCRedirectURIs(ic)
		if len(redirects) == 0 {
			return nil, fmt.Errorf("app %q: OIDCRedirectURIs returned no entries", ic.Name)
		}
		prov, err := oidc.Provision(ctx, ic.DB, ic.Name, redirects)
		if err != nil {
			return nil, fmt.Errorf("provision OIDC client: %w", err)
		}
		ic.OIDCClientID = prov.ClientID
		ic.OIDCClientSecret = prov.ClientSecret
	}

	// 2. Render the compose template.
	if err := os.MkdirAll(filepath.Dir(ic.ComposeFile), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir compose dir: %w", err)
	}
	if err := renderCompose(ic); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ic.DataRoot, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir data root: %w", err)
	}

	// 3. Persist settings (also enables the app and publishes the route).
	settings := proxy.AppSettings{
		Subdomain:    ic.Subdomain,
		Backend:      fmt.Sprintf("http://127.0.0.1:%d", ic.BackendPort),
		PreserveHost: spec.PreserveHost,
		OIDCGate:     spec.OIDCGate,
		DisplayName:  spec.DisplayName,
		Description:  spec.Description,
		Icon:         spec.Icon,
		ComposeFile:  ic.ComposeFile,
		DataRoot:     ic.DataRoot,
	}
	if err := proxy.SaveSettings(ctx, ic.DB, ic.Name, settings); err != nil {
		return nil, fmt.Errorf("save app settings: %w", err)
	}

	// 4. PreUp -> compose up -> PostUp.
	if spec.PreUp != nil {
		if err := spec.PreUp(ctx, ic); err != nil {
			return nil, fmt.Errorf("pre-up: %w", err)
		}
	}
	if _, err := ic.Orchestrator.Up(ctx, ic.ComposeFile); err != nil {
		return nil, fmt.Errorf("compose up: %w", err)
	}
	if spec.PostUp != nil {
		if err := spec.PostUp(ctx, ic); err != nil {
			return nil, fmt.Errorf("post-up: %w", err)
		}
	}

	return &Result{
		AppName:          ic.Name,
		ComposeFile:      ic.ComposeFile,
		AdminPassword:    ic.AdminPassword,
		BackendPort:      ic.BackendPort,
		OIDCClientID:     ic.OIDCClientID,
		OIDCClientSecret: ic.OIDCClientSecret,
	}, nil
}

func (ic *InstallContext) validate() error {
	if ic.Name == "" {
		return fmt.Errorf("name required")
	}
	if ic.Subdomain == "" {
		return fmt.Errorf("subdomain required")
	}
	if ic.BackendPort == 0 {
		return fmt.Errorf("backend_port required")
	}
	if ic.BaseHost == "" {
		return fmt.Errorf("base_host required")
	}
	if ic.ComposeFile == "" {
		return fmt.Errorf("compose_file required")
	}
	if ic.DataRoot == "" {
		return fmt.Errorf("data_root required")
	}
	if ic.DB == nil {
		return fmt.Errorf("db required")
	}
	if ic.Orchestrator == nil {
		return fmt.Errorf("orchestrator required")
	}
	return nil
}

// RenderCompose renders the spec's compose template against the install
// context and writes it to ic.ComposeFile. Exported so tests can exercise it
// without spinning up Docker.
func RenderCompose(ic *InstallContext) error { return renderCompose(ic) }

func renderCompose(ic *InstallContext) error {
	tmpl, err := template.New("compose").Parse(string(ic.Spec.ComposeTemplate))
	if err != nil {
		return fmt.Errorf("parse compose template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ic); err != nil {
		return fmt.Errorf("render compose template: %w", err)
	}
	if err := os.WriteFile(ic.ComposeFile, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write compose file: %w", err)
	}
	return nil
}

// WaitFor polls url every interval until it returns *any* HTTP response, or
// ctx times out. Use it from PostUp to wait for a container to start serving.
func WaitFor(ctx context.Context, target string, interval time.Duration) error {
	if _, err := url.Parse(target); err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if interval == 0 {
		interval = time.Second
	}
	client := &http.Client{Timeout: interval}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %s: %w", target, ctx.Err())
		default:
		}
		resp, err := client.Get(target)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %s: %w", target, ctx.Err())
		case <-time.After(interval):
		}
	}
}

// randomPassword returns a 24-char URL-safe random password (18 raw bytes).
func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
