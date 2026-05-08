// Package jellyfin is the nass app module for Jellyfin.
//
// Jellyfin gets OIDC via the third-party jellyfin-plugin-sso plugin, which
// PostUp installs by downloading the latest release and extracting it into
// the volume-mounted /config/plugins directory. Mirrors the bash post-up in
// nass-simple/jellyfin/.
package jellyfin

import (
	"archive/zip"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

//go:embed branding.xml
var brandingXML []byte

//go:embed network.xml
var networkXML []byte

//go:embed sso-auth.xml.tmpl
var ssoAuthTmpl string

// pluginManifestURL points at the jellyfin-plugin-sso release manifest. The
// first entry's first sourceUrl is the latest plugin zip — same selection the
// bash post-up made.
const pluginManifestURL = "https://raw.githubusercontent.com/9p4/jellyfin-plugin-sso/manifest-release/manifest.json"

// ssoProviderName is the key that ties branding.xml's SSO button (action
// "/sso/OID/start/nass") to the plugin config's <key> entry.
const ssoProviderName = "nass"

func init() {
	apps.Register(apps.Spec{
		Name:            "jellyfin",
		DisplayName:     "Jellyfin",
		Description:     "Media server",
		Icon:            "🎬",
		Subdomain:    "jellyfin",
		BackendPort:  18096,
		PreserveHost: true,
		NeedsOIDC:    true,
		OIDCGate:     false,
		// jellyfin-plugin-sso v4.x posts the OIDC code to
		// /sso/OID/redirect/<provider>. Register both http and https: the
		// plugin builds the URI from the request scheme it sees, and
		// Jellyfin doesn't honor X-Forwarded-Proto without KnownProxies.
		OIDCRedirectURIs: redirectURIs,
		ComposeTemplate:  composeTemplate,
		PostUp:           postUp,
	})
}

func redirectURIs(ic *apps.InstallContext) []string {
	path := "/sso/OID/redirect/" + ssoProviderName
	host := ic.PublicHost()
	return []string{
		"https://" + host + path,
		"http://" + host + path,
	}
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	base := fmt.Sprintf("http://127.0.0.1:%d", ic.BackendPort)

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	completed, err := waitForJellyfin(waitCtx, base)
	if err != nil {
		return fmt.Errorf("wait for jellyfin: %w", err)
	}

	if !completed {
		if err := runStartupWizard(ctx, base, ic.AdminPassword); err != nil {
			return fmt.Errorf("startup wizard: %w", err)
		}
	}

	pluginDir := filepath.Join(ic.DataRoot, "config", "plugins", "SSO_Authentication")
	if _, err := os.Stat(pluginDir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat plugin dir: %w", err)
		}
		if err := installSSOPlugin(ctx, pluginDir); err != nil {
			return fmt.Errorf("install SSO plugin: %w", err)
		}
	}

	if err := writeBrandingAndSSOConfig(ic); err != nil {
		return err
	}

	if _, err := ic.Orchestrator.Restart(ctx, ic.ComposeFile); err != nil {
		return fmt.Errorf("restart jellyfin: %w", err)
	}
	upCtx, cancel2 := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel2()
	if _, err := waitForJellyfin(upCtx, base); err != nil {
		return fmt.Errorf("wait for jellyfin restart: %w", err)
	}
	return nil
}

func writeBrandingAndSSOConfig(ic *apps.InstallContext) error {
	brandingDir := filepath.Join(ic.DataRoot, "config", "config")
	if err := os.MkdirAll(brandingDir, 0o755); err != nil {
		return fmt.Errorf("mkdir branding dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(brandingDir, "branding.xml"), brandingXML, 0o644); err != nil {
		return fmt.Errorf("write branding.xml: %w", err)
	}

	// network.xml registers the docker bridge subnets as KnownProxies so
	// Jellyfin honors X-Forwarded-Proto from nass's reverse proxy. Without
	// this, the SSO plugin builds redirect URIs / post-login navigation as
	// http:// and modern browsers mixed-content-block them.
	configRootDir := filepath.Join(ic.DataRoot, "config")
	if err := os.WriteFile(filepath.Join(configRootDir, "network.xml"), networkXML, 0o644); err != nil {
		return fmt.Errorf("write network.xml: %w", err)
	}

	configsDir := filepath.Join(ic.DataRoot, "config", "plugins", "configurations")
	if err := os.MkdirAll(configsDir, 0o755); err != nil {
		return fmt.Errorf("mkdir plugin configs dir: %w", err)
	}
	xml, err := renderSSOConfig(ic)
	if err != nil {
		return fmt.Errorf("render SSO-Auth.xml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(configsDir, "SSO-Auth.xml"), xml, 0o644); err != nil {
		return fmt.Errorf("write SSO-Auth.xml: %w", err)
	}
	return nil
}

// renderSSOConfig fills the SSO-Auth.xml template with the OIDC issuer + client
// credentials from the install context.
func renderSSOConfig(ic *apps.InstallContext) ([]byte, error) {
	tmpl, err := template.New("sso").Parse(ssoAuthTmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	data := struct {
		ProviderName     string
		OIDCDiscoveryURL string
		OIDCClientID     string
		OIDCClientSecret string
	}{
		ProviderName:     ssoProviderName,
		OIDCDiscoveryURL: ic.OIDCDiscoveryURL(),
		OIDCClientID:     ic.OIDCClientID,
		OIDCClientSecret: ic.OIDCClientSecret,
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// waitForJellyfin polls /System/Info/Public until Jellyfin is actually ready
// to serve API requests, returning the wizard's completion state.
//
// Two boot phases need to be distinguished:
//   - 10.8: a plain HTML "Jellyfin Server is loading" 503 for ~5s, after which
//     all endpoints come up together.
//   - 10.11+: /System/Info/Public answers JSON early, but /Startup/* still
//     returns a 503 migration-progress HTML page until migrations finish.
//
// We therefore require BOTH a JSON /System/Info/Public AND, when the wizard
// isn't yet complete, a JSON /Startup/User before returning.
func waitForJellyfin(ctx context.Context, base string) (bool, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		completed, ok := pollPublicInfo(ctx, client, base)
		if ok && (completed || startupReady(ctx, client, base)) {
			return completed, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// startupReady returns true once /Startup/User serves JSON. During the 10.11
// migration phase it returns 503 with an HTML progress page.
func startupReady(ctx context.Context, client *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/Startup/User", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == 200 &&
		strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json")
}

func pollPublicInfo(ctx context.Context, client *http.Client, base string) (bool, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/System/Info/Public", nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return false, false
	}
	var info struct {
		StartupWizardCompleted bool
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return false, false
	}
	return info.StartupWizardCompleted, true
}

// runStartupWizard drives the four-step first-run setup the way the web
// installer does. The caller is responsible for skipping it when the wizard
// is already complete.
func runStartupWizard(ctx context.Context, base, adminPassword string) error {
	// Jellyfin's first-run wizard insists on these calls in order. Empty
	// /Startup/User read appears to be a precondition for the POST below.
	if err := getJSON(ctx, base+"/Startup/User"); err != nil {
		return fmt.Errorf("GET /Startup/User: %w", err)
	}
	userBody, err := json.Marshal(map[string]string{"Name": "admin", "Password": adminPassword})
	if err != nil {
		return err
	}
	if err := postJSON(ctx, base+"/Startup/User", userBody); err != nil {
		return fmt.Errorf("POST /Startup/User: %w", err)
	}
	if err := postJSON(ctx, base+"/Startup/Configuration",
		[]byte(`{"UICulture":"en-US","MetadataCountryCode":"US","PreferredMetadataLanguage":"en"}`)); err != nil {
		return fmt.Errorf("POST /Startup/Configuration: %w", err)
	}
	if err := postJSON(ctx, base+"/Startup/RemoteAccess",
		[]byte(`{"EnableRemoteAccess":true,"EnableAutomaticPortMapping":false}`)); err != nil {
		return fmt.Errorf("POST /Startup/RemoteAccess: %w", err)
	}
	if err := postJSON(ctx, base+"/Startup/Complete", nil); err != nil {
		return fmt.Errorf("POST /Startup/Complete: %w", err)
	}
	return nil
}

func getJSON(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func postJSON(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

// installSSOPlugin fetches the latest jellyfin-plugin-sso release and
// extracts its zip into pluginDir. The directory is created fresh — caller
// must guarantee it doesn't already exist (or accept overwrites).
func installSSOPlugin(ctx context.Context, pluginDir string) error {
	zipURL, err := latestPluginURL(ctx)
	if err != nil {
		return fmt.Errorf("resolve plugin url: %w", err)
	}
	zipBytes, err := fetch(ctx, zipURL)
	if err != nil {
		return fmt.Errorf("download plugin: %w", err)
	}
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return fmt.Errorf("mkdir plugin dir: %w", err)
	}
	if err := unzipInto(zipBytes, pluginDir); err != nil {
		return fmt.Errorf("unzip plugin: %w", err)
	}
	return nil
}

func latestPluginURL(ctx context.Context) (string, error) {
	body, err := fetch(ctx, pluginManifestURL)
	if err != nil {
		return "", err
	}
	var manifest []struct {
		Versions []struct {
			SourceURL string `json:"sourceUrl"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}
	if len(manifest) == 0 || len(manifest[0].Versions) == 0 {
		return "", fmt.Errorf("manifest has no versions")
	}
	return manifest[0].Versions[0].SourceURL, nil
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// unzipInto writes every file from zipBytes into dest, refusing entries that
// would escape the destination via "../" (zip-slip).
func unzipInto(zipBytes []byte, dest string) error {
	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return err
	}
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for _, f := range r.File {
		out := filepath.Join(destAbs, f.Name)
		if !strings.HasPrefix(out, destAbs+string(os.PathSeparator)) && out != destAbs {
			return fmt.Errorf("zip entry escapes dest: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(w, rc); err != nil {
			rc.Close()
			w.Close()
			return err
		}
		rc.Close()
		w.Close()
	}
	return nil
}
