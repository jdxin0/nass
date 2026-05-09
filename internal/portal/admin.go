package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"

	"github.com/jdxin0/nass/internal/apps"
	"github.com/jdxin0/nass/internal/orchestrator"
	"github.com/jdxin0/nass/internal/proxy"
)

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type adminAppRow struct {
	Name        string
	DisplayName string
	Settings    proxy.AppSettings
	State       orchestrator.State
}

type availableAppRow struct {
	Name        string
	DisplayName string
	Description string
	Subdomain   string
	Installed   bool
}

func (p *Portal) getAdmin(w http.ResponseWriter, r *http.Request) {
	sess, ok := p.requireAdmin(w, r)
	if !ok {
		return
	}
	installedApps, err := loadAllApps(r.Context(), p.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]adminAppRow, 0, len(installedApps))
	for _, a := range installedApps {
		rows = append(rows, adminAppRow{
			Name:        a.Name,
			DisplayName: a.displayName(),
			Settings:    a.Settings,
			State:       p.stateOf(r.Context(), a),
		})
	}
	installed := make(map[string]bool, len(installedApps))
	for _, a := range installedApps {
		installed[a.Name] = true
	}
	available := make([]availableAppRow, 0)
	for _, spec := range apps.All() {
		available = append(available, availableAppRow{
			Name:        spec.Name,
			DisplayName: spec.DisplayName,
			Description: spec.Description,
			Subdomain:   spec.Subdomain,
			Installed:   installed[spec.Name],
		})
	}
	p.render(w, "admin.html", sess, map[string]any{
		"Apps":      rows,
		"Available": available,
		"Flash":     r.URL.Query().Get("flash"),
		"Error":     r.URL.Query().Get("error"),
	})
}

func (p *Portal) postAddApp(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAdmin(w, r); !ok {
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	if !nameRE.MatchString(name) {
		redirectAdmin(w, r, "", "invalid name (alnum + _ -)")
		return
	}
	spec, ok := apps.Get(name)
	if !ok {
		redirectAdmin(w, r, "", fmt.Sprintf("unknown app %q", name))
		return
	}
	ic, err := p.installContext(&spec)
	if err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	}
	res, err := p.InstallApp(r.Context(), ic)
	if err != nil {
		redirectAdmin(w, r, "", "install failed: "+err.Error())
		return
	}
	if err := p.reload(r.Context()); err != nil {
		redirectAdmin(w, r, "", "installed but route reload failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, fmt.Sprintf("installed %s", res.AppName), "")
}

func (p *Portal) installContext(spec *apps.Spec) (*apps.InstallContext, error) {
	if p.Orchestrator == nil {
		return nil, fmt.Errorf("orchestrator not configured")
	}
	if p.Orchestrator.ComposeRoot == "" {
		return nil, fmt.Errorf("orchestrator compose root is not configured")
	}
	if p.AppDataRoot == "" {
		return nil, fmt.Errorf("app data root is not configured")
	}
	if p.OIDCIssuer == "" {
		return nil, fmt.Errorf("oidc issuer is not configured")
	}
	scheme := "https"
	if !p.HTTPS {
		scheme = "http"
	}
	return &apps.InstallContext{
		Spec:         spec,
		Name:         spec.Name,
		Subdomain:    spec.Subdomain,
		BaseHost:     p.BaseHost,
		PublicScheme: scheme,
		PublicPort:   p.PublicPort,
		BackendPort:  spec.BackendPort,
		DataRoot:     filepath.Join(p.AppDataRoot, spec.Name),
		ComposeFile:  filepath.Join(p.Orchestrator.ComposeRoot, spec.Name, "docker-compose.yaml"),
		OIDCIssuer:   p.OIDCIssuer,
		DB:           p.DB,
		Orchestrator: p.Orchestrator,
	}, nil
}

func (p *Portal) postStartApp(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAdmin(w, r); !ok {
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	composeFile, err := p.composeFile(r, name)
	if err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	}
	if p.Orchestrator == nil {
		redirectAdmin(w, r, "", "orchestrator not configured")
		return
	}
	if _, err := p.Orchestrator.Up(r.Context(), composeFile); err != nil {
		redirectAdmin(w, r, "", "start failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, "started "+name, "")
}

func (p *Portal) postStopApp(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAdmin(w, r); !ok {
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	composeFile, err := p.composeFile(r, name)
	if err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	}
	if p.Orchestrator == nil {
		redirectAdmin(w, r, "", "orchestrator not configured")
		return
	}
	if _, err := p.Orchestrator.Down(r.Context(), composeFile); err != nil {
		redirectAdmin(w, r, "", "stop failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, "stopped "+name, "")
}

func (p *Portal) postDisableApp(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAdmin(w, r); !ok {
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	if _, err := p.DB.ExecContext(r.Context(),
		`UPDATE apps SET enabled = 0 WHERE name = ?`, name); err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	}
	if err := p.reload(r.Context()); err != nil {
		redirectAdmin(w, r, "", "disabled but route reload failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, "disabled "+name+" and dropped route", "")
}

// reload triggers a live route sync if the manager is wired (no-op otherwise).
func (p *Portal) reload(ctx context.Context) error {
	if p.Reload == nil {
		return nil
	}
	return p.Reload(ctx)
}

// composeFile loads the compose_file path for the named app from settings_json.
func (p *Portal) composeFile(r *http.Request, name string) (string, error) {
	apps, err := loadAllApps(r.Context(), p.DB)
	if err != nil {
		return "", err
	}
	for _, a := range apps {
		if a.Name == name {
			if a.Settings.ComposeFile == "" {
				return "", fmt.Errorf("app %q has no compose_file", name)
			}
			return a.Settings.ComposeFile, nil
		}
	}
	return "", fmt.Errorf("app %q not found", name)
}

func redirectAdmin(w http.ResponseWriter, r *http.Request, flash, errMsg string) {
	v := url.Values{}
	if flash != "" {
		v.Set("flash", flash)
	}
	if errMsg != "" {
		v.Set("error", errMsg)
	}
	target := "/portal/admin"
	if len(v) > 0 {
		target += "?" + v.Encode()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// sameOrigin verifies the Origin (or Referer fallback) matches the request Host.
// Combined with SameSite=Lax cookies this gives sufficient CSRF protection.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		// Some browsers omit Origin on same-origin POSTs. Allow it iff the
		// session cookie is SameSite=Lax (which we set).
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}
