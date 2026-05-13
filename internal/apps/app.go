// Package apps is the registry + installer for nass-managed services.
//
// Each app is a Go subpackage that implements its own [Spec] and registers
// itself in init(). The main binary blank-imports the children to trigger
// registration, so the parent package never has to know about its children.
package apps

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/jdxin0/nass/internal/orchestrator"
)

// Spec is the per-app contract: defaults plus the two lifecycle hooks.
// PreUp runs *before* `docker compose up`; PostUp runs after the container
// is up (and the hook is responsible for waiting for the service to be
// reachable before doing config work).
type Spec struct {
	// Identity.
	Name        string
	DisplayName string
	Description string
	Icon        string // single emoji or short string

	// Routing defaults; the user can override via CLI flags.
	Subdomain   string // default subdomain
	BackendPort int    // host port the proxy targets

	// PreserveHost forwards original Host header to the container. Most apps want true.
	PreserveHost bool

	// NeedsOIDC, when true, causes the installer to provision an OIDC client
	// and pass client_id/client_secret/issuer into InstallContext.
	NeedsOIDC bool

	// OIDCGate, when true, makes the proxy enforce a portal session for this
	// app. Used for apps without native OIDC (e.g. qBittorrent).
	OIDCGate bool

	// OIDCRedirectURIs returns the full redirect URIs to register on the
	// OIDC client. Apps usually return [ic.PublicURL()+"/path"], but may
	// add multiple variants (e.g. http+https) when an upstream client
	// derives the URI from the request scheme rather than the public URL.
	// Must return a non-empty slice when NeedsOIDC is true.
	OIDCRedirectURIs func(ic *InstallContext) []string

	// ComposeTemplate is the embedded docker-compose.yaml template, parsed
	// with [text/template] against InstallContext.
	ComposeTemplate []byte

	// Hooks. Either may be nil.
	PreUp  func(ctx context.Context, ic *InstallContext) error
	PostUp func(ctx context.Context, ic *InstallContext) error
}

// InstallContext is what the installer hands to the template + hooks. It is
// fully resolved before PreUp runs.
type InstallContext struct {
	Spec *Spec

	// Identity / routing.
	Name      string // the app's name (== Spec.Name)
	Subdomain string // user-chosen, defaults to Spec.Subdomain

	// Public-facing URL pieces (used to compute OVERWRITEHOST etc.).
	BaseHost     string // e.g. "nass.local"
	PublicScheme string // "https" or "http"
	PublicPort   string // ":8443" or "" for default scheme port

	// Backend port the proxy targets.
	BackendPort         int
	BackendPortRange    string
	BackendPortExplicit bool

	// On-disk paths.
	DataRoot    string // where the app's volumes live (per app)
	ComposeFile string // resolved absolute path to the rendered compose file

	// Per-app admin password (generated and shown once).
	AdminPassword string

	// OIDC credentials (empty when Spec.NeedsOIDC is false).
	OIDCClientID     string
	OIDCClientSecret string
	OIDCIssuer       string // e.g. "https://auth.nass.local"

	// Wired services.
	DB           *sql.DB
	Orchestrator *orchestrator.Orchestrator
}

// PublicHost returns the user-visible host (subdomain + base + port).
func (ic *InstallContext) PublicHost() string {
	return ic.Subdomain + "." + ic.BaseHost + ic.PublicPort
}

// PublicURL returns the user-visible base URL.
func (ic *InstallContext) PublicURL() string {
	return ic.PublicScheme + "://" + ic.PublicHost()
}

// OIDCDiscoveryURL is the OIDC well-known URL for the issuer.
func (ic *InstallContext) OIDCDiscoveryURL() string {
	return ic.OIDCIssuer + "/.well-known/openid-configuration"
}

// --- registry ---

var (
	regMu sync.RWMutex
	reg   = map[string]Spec{}
)

// Register adds a Spec to the registry. Apps call this from init().
func Register(spec Spec) {
	regMu.Lock()
	defer regMu.Unlock()
	if spec.Name == "" {
		panic("apps.Register: empty Name")
	}
	if _, dup := reg[spec.Name]; dup {
		panic(fmt.Sprintf("apps.Register: duplicate name %q", spec.Name))
	}
	reg[spec.Name] = spec
}

// Get returns the registered Spec for name.
func Get(name string) (Spec, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	s, ok := reg[name]
	return s, ok
}

// All returns all registered specs (sorted alphabetically).
func All() []Spec {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Spec, 0, len(reg))
	for _, s := range reg {
		out = append(out, s)
	}
	// sort by name
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Name > out[j].Name; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
