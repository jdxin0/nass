package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

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

func (p *Portal) getAdmin(w http.ResponseWriter, r *http.Request) {
	sess, ok := p.requireAdmin(w, r)
	if !ok {
		return
	}
	apps, err := loadAllApps(r.Context(), p.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]adminAppRow, 0, len(apps))
	for _, a := range apps {
		rows = append(rows, adminAppRow{
			Name:        a.Name,
			DisplayName: a.displayName(),
			Settings:    a.Settings,
			State:       p.stateOf(r.Context(), a),
		})
	}
	p.render(w, "admin.html", sess, map[string]any{
		"Apps":  rows,
		"Flash": r.URL.Query().Get("flash"),
		"Error": r.URL.Query().Get("error"),
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
	settings := proxy.AppSettings{
		Subdomain:    r.FormValue("subdomain"),
		Backend:      r.FormValue("backend"),
		PreserveHost: r.FormValue("preserve_host") == "1",
		OIDCGate:     r.FormValue("oidc_gate") == "1",
		DisplayName:  r.FormValue("display_name"),
		Description:  r.FormValue("description"),
		Icon:         r.FormValue("icon"),
		ComposeFile:  r.FormValue("compose_file"),
	}
	if settings.Subdomain == "" || settings.Backend == "" {
		redirectAdmin(w, r, "", "subdomain and backend are required")
		return
	}
	if err := proxy.SaveSettings(r.Context(), p.DB, name, settings); err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	}
	if err := p.reload(r.Context()); err != nil {
		redirectAdmin(w, r, "", "saved but route reload failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, fmt.Sprintf("added %s and published route", name), "")
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
