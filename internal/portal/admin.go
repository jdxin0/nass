package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/jdxin0/nass/internal/apps"
	"github.com/jdxin0/nass/internal/orchestrator"
	"github.com/jdxin0/nass/internal/proxy"
)

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type adminAppRow struct {
	Name        string
	DisplayName string
	Description string
	Subdomain   string
	Settings    proxy.AppSettings
	State       orchestrator.State
	Installed   bool
	Installing  bool
}

type adminUserRow struct {
	ID       int64
	Username string
	Email    string
	IsAdmin  bool
	IsSelf   bool
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
	// Build a single merged list: every installed app first (so manually
	// `nass app enable`d routes not in the registry still show up), then any
	// remaining registry apps that aren't installed yet.
	seen := make(map[string]bool, len(installedApps))
	rows := make([]adminAppRow, 0, len(installedApps)+len(apps.All()))
	for _, a := range installedApps {
		seen[a.Name] = true
		row := adminAppRow{
			Name:        a.Name,
			DisplayName: a.displayName(),
			Settings:    a.Settings,
			State:       p.stateOf(r.Context(), a),
			Installed:   true,
			Installing:  p.hasRunningJob("install", a.Name),
		}
		if spec, ok := apps.Get(a.Name); ok {
			row.Description = spec.Description
			row.Subdomain = spec.Subdomain
		}
		rows = append(rows, row)
	}
	for _, spec := range apps.All() {
		if seen[spec.Name] {
			continue
		}
		rows = append(rows, adminAppRow{
			Name:        spec.Name,
			DisplayName: spec.DisplayName,
			Description: spec.Description,
			Subdomain:   spec.Subdomain,
			Installing:  p.hasRunningJob("install", spec.Name),
		})
	}
	users, err := p.Users.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userRows := make([]adminUserRow, 0, len(users))
	for _, u := range users {
		userRows = append(userRows, adminUserRow{
			ID:       u.ID,
			Username: u.Username,
			Email:    u.Email,
			IsAdmin:  u.IsAdmin,
			IsSelf:   u.ID == sess.User.ID,
		})
	}
	p.render(w, "admin.html", sess, map[string]any{
		"Apps":  rows,
		"Users": userRows,
		"Jobs":  p.recentJobs(),
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
	p.startAppJob("install", name, func(ctx context.Context) error {
		if _, err := p.InstallApp(ctx, ic); err != nil {
			return err
		}
		if err := p.reload(ctx); err != nil {
			return fmt.Errorf("installed but route reload failed: %w", err)
		}
		return nil
	})
	redirectAdmin(w, r, fmt.Sprintf("started installing %s", name), "")
}

func (p *Portal) postCreateUser(w http.ResponseWriter, r *http.Request) {
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
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	isAdmin := r.FormValue("is_admin") == "1"
	u, err := p.Users.Create(r.Context(), username, email, password, isAdmin)
	if err != nil {
		redirectAdmin(w, r, "", "create user failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, fmt.Sprintf("created user %s", u.Username), "")
}

func (p *Portal) postUpdateUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := p.requireAdmin(w, r)
	if !ok {
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
	id, ok := userIDFromPath(w, r)
	if !ok {
		return
	}
	isAdmin := r.FormValue("is_admin") == "1"
	if id == sess.User.ID && !isAdmin {
		redirectAdmin(w, r, "", "cannot remove admin from your own account")
		return
	}
	if !isAdmin {
		if ok, err := p.canRemoveAdmin(r.Context(), id); err != nil {
			redirectAdmin(w, r, "", err.Error())
			return
		} else if !ok {
			redirectAdmin(w, r, "", "cannot remove the last admin")
			return
		}
	}
	if err := p.Users.SetEmail(r.Context(), id, r.FormValue("email")); err != nil {
		redirectAdmin(w, r, "", "update email failed: "+err.Error())
		return
	}
	if err := p.Users.SetAdmin(r.Context(), id, isAdmin); err != nil {
		redirectAdmin(w, r, "", "update role failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, "updated user", "")
}

func (p *Portal) postSetUserPassword(w http.ResponseWriter, r *http.Request) {
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
	id, ok := userIDFromPath(w, r)
	if !ok {
		return
	}
	if err := p.Users.SetPassword(r.Context(), id, r.FormValue("password")); err != nil {
		redirectAdmin(w, r, "", "set password failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, "updated password", "")
}

func (p *Portal) postDeleteUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := p.requireAdmin(w, r)
	if !ok {
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	id, ok := userIDFromPath(w, r)
	if !ok {
		return
	}
	if id == sess.User.ID {
		redirectAdmin(w, r, "", "cannot delete your own account")
		return
	}
	if ok, err := p.canRemoveAdmin(r.Context(), id); err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	} else if !ok {
		redirectAdmin(w, r, "", "cannot delete the last admin")
		return
	}
	if err := p.Users.Delete(r.Context(), id); err != nil {
		redirectAdmin(w, r, "", "delete user failed: "+err.Error())
		return
	}
	redirectAdmin(w, r, "deleted user", "")
}

func userIDFromPath(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func (p *Portal) canRemoveAdmin(ctx context.Context, id int64) (bool, error) {
	users, err := p.Users.List(ctx)
	if err != nil {
		return false, err
	}
	admins := 0
	targetAdmin := false
	for _, u := range users {
		if u.IsAdmin {
			admins++
		}
		if u.ID == id {
			targetAdmin = u.IsAdmin
		}
	}
	return !targetAdmin || admins > 1, nil
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
		Spec:             spec,
		Name:             spec.Name,
		Subdomain:        spec.Subdomain,
		BaseHost:         p.BaseHost,
		PublicScheme:     scheme,
		PublicPort:       p.PublicPort,
		BackendPort:      spec.BackendPort,
		BackendPortRange: p.BackendPortRange,
		DataRoot:         filepath.Join(p.AppDataRoot, spec.Name),
		ComposeFile:      filepath.Join(p.Orchestrator.ComposeRoot, spec.Name, "docker-compose.yaml"),
		OIDCIssuer:       p.OIDCIssuer,
		DB:               p.DB,
		Orchestrator:     p.Orchestrator,
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

func (p *Portal) postUninstallApp(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.requireAdmin(w, r); !ok {
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	composeFile, dataRoot, found, err := apps.LoadAppPaths(r.Context(), p.DB, name)
	if err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	}
	if !found {
		redirectAdmin(w, r, "", fmt.Sprintf("app %q is not installed", name))
		return
	}
	uc := &apps.UninstallContext{
		Name:         name,
		ComposeFile:  composeFile,
		DataRoot:     dataRoot,
		Force:        true,
		DB:           p.DB,
		Orchestrator: p.Orchestrator,
	}
	p.startAppJob("uninstall", name, func(ctx context.Context) error {
		if err := p.UninstallApp(ctx, uc); err != nil {
			return err
		}
		if err := p.reload(ctx); err != nil {
			return fmt.Errorf("uninstalled but route reload failed: %w", err)
		}
		return nil
	})
	redirectAdmin(w, r, fmt.Sprintf("started uninstalling %s", name), "")
}

func (p *Portal) startAppJob(action, name string, fn func(context.Context) error) {
	now := time.Now()
	job := &appJob{
		ID:        now.UnixNano(),
		Action:    action,
		AppName:   name,
		Status:    "running",
		Message:   "running",
		StartedAt: now,
	}
	p.jobsMu.Lock()
	p.jobs = append([]*appJob{job}, p.jobs...)
	if len(p.jobs) > 20 {
		p.jobs = p.jobs[:20]
	}
	p.jobsMu.Unlock()
	p.logAppJob("started", job, nil)

	go func() {
		err := fn(context.Background())
		p.jobsMu.Lock()
		job.FinishedAt = time.Now()
		if err != nil {
			job.Status = "error"
			job.Message = err.Error()
			p.jobsMu.Unlock()
			p.logAppJob("failed", job, err)
			return
		}
		job.Status = "done"
		job.Message = "completed"
		p.jobsMu.Unlock()
		p.logAppJob("completed", job, nil)
	}()
}

func (p *Portal) logAppJob(event string, job *appJob, err error) {
	if p.JobLog == nil {
		return
	}
	duration := time.Since(job.StartedAt).Round(time.Millisecond)
	if err != nil {
		fmt.Fprintf(p.JobLog, "app job %s action=%s app=%s duration=%s error=%v\n",
			event, job.Action, job.AppName, duration, err)
		return
	}
	fmt.Fprintf(p.JobLog, "app job %s action=%s app=%s duration=%s\n",
		event, job.Action, job.AppName, duration)
}

func (p *Portal) recentJobs() []appJob {
	p.jobsMu.Lock()
	defer p.jobsMu.Unlock()
	out := make([]appJob, 0, len(p.jobs))
	for _, job := range p.jobs {
		out = append(out, *job)
	}
	return out
}

func (p *Portal) hasRunningJob(action, name string) bool {
	p.jobsMu.Lock()
	defer p.jobsMu.Unlock()
	for _, job := range p.jobs {
		if job.Action == action && job.AppName == name && job.Status == "running" {
			return true
		}
	}
	return false
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
