// Package portal serves the dashboard, login page, and admin UI.
package portal

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jdxin0/nass/internal/apps"
	"github.com/jdxin0/nass/internal/auth"
	"github.com/jdxin0/nass/internal/orchestrator"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Portal is the HTTP-facing portal server. It owns sessions and renders the
// dashboard / login / admin pages.
type Portal struct {
	DB           *sql.DB
	Users        *auth.Store
	Sessions     *SessionStore
	Orchestrator *orchestrator.Orchestrator

	BaseHost  string
	SiteTitle string
	HTTPS     bool // false in dev: portal links use http://

	AppDataRoot      string
	OIDCIssuer       string
	PublicPort       string
	BackendPortRange string

	InstallApp   func(ctx context.Context, ic *apps.InstallContext) (*apps.Result, error)
	UninstallApp func(ctx context.Context, uc *apps.UninstallContext) error

	// Reload, when set, is called after admin mutations to re-sync the live
	// proxy with the apps table.
	Reload func(ctx context.Context) error

	// JobLog receives one-line app operation diagnostics. nass serve wires this
	// to stderr so failed background installs can be traced from service logs.
	JobLog io.Writer

	jobsMu sync.Mutex
	jobs   []*appJob
	pages  map[string]*template.Template
}

type appJob struct {
	ID         int64
	Action     string
	AppName    string
	Status     string
	Message    string
	StartedAt  time.Time
	FinishedAt time.Time
}

func New(db *sql.DB, users *auth.Store, ss *SessionStore, orch *orchestrator.Orchestrator, baseHost, siteTitle string, https bool) (*Portal, error) {
	pages, err := parsePages("login.html", "dashboard.html", "admin.html")
	if err != nil {
		return nil, err
	}
	return &Portal{
		DB:           db,
		Users:        users,
		Sessions:     ss,
		Orchestrator: orch,
		BaseHost:     baseHost,
		SiteTitle:    siteTitle,
		HTTPS:        https,
		InstallApp:   apps.Install,
		UninstallApp: apps.Uninstall,
		pages:        pages,
	}, nil
}

// parsePages compiles each page as its own tree (sharing base.html) so that
// "content" definitions don't clobber each other in a single template set.
func parsePages(names ...string) (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, n := range names {
		t, err := template.New("base").ParseFS(templatesFS, "templates/base.html", "templates/"+n)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", n, err)
		}
		out[n] = t
	}
	return out, nil
}

// Mount registers the portal routes on mux. The dashboard is at /, login at /portal/login,
// admin at /portal/admin.
func (p *Portal) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /portal/login", p.getLogin)
	mux.HandleFunc("POST /portal/login", p.postLogin)
	mux.HandleFunc("POST /portal/logout", p.postLogout)
	mux.HandleFunc("GET /portal/admin", p.getAdmin)
	mux.HandleFunc("POST /portal/admin/apps", p.postAddApp)
	mux.HandleFunc("POST /portal/admin/apps/{name}/start", p.postStartApp)
	mux.HandleFunc("POST /portal/admin/apps/{name}/stop", p.postStopApp)
	mux.HandleFunc("POST /portal/admin/apps/{name}/uninstall", p.postUninstallApp)
	mux.HandleFunc("POST /portal/admin/users", p.postCreateUser)
	mux.HandleFunc("POST /portal/admin/users/{id}", p.postUpdateUser)
	mux.HandleFunc("POST /portal/admin/users/{id}/password", p.postSetUserPassword)
	mux.HandleFunc("POST /portal/admin/users/{id}/delete", p.postDeleteUser)
	mux.HandleFunc("GET /", p.getDashboard)
}

// requireSession loads the session, redirecting to /portal/login if absent.
func (p *Portal) requireSession(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	sess, err := p.Sessions.Lookup(r.Context(), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, false
	}
	if sess == nil {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/portal/login?next="+url.QueryEscape(next), http.StatusFound)
		return nil, false
	}
	return sess, true
}

func (p *Portal) requireAdmin(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	sess, ok := p.requireSession(w, r)
	if !ok {
		return nil, false
	}
	if !sess.User.IsAdmin {
		http.Error(w, "admin required", http.StatusForbidden)
		return nil, false
	}
	return sess, true
}

// render executes a template by page-file name with the standard data wrapper.
func (p *Portal) render(w http.ResponseWriter, name string, sess *Session, data map[string]any) {
	t, ok := p.pages[name]
	if !ok {
		http.Error(w, "unknown template "+name, http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["SiteTitle"] = p.SiteTitle
	data["Title"] = p.SiteTitle
	if sess != nil {
		data["User"] = sess.User
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, fmt.Sprintf("template: %v", err), http.StatusInternalServerError)
	}
}

// portalURL returns the absolute URL of the portal root with the configured scheme.
func (p *Portal) portalURL() string {
	scheme := "https"
	if !p.HTTPS {
		scheme = "http"
	}
	return scheme + "://" + p.BaseHost
}

// AppHostURL returns the full URL of an app's subdomain.
func (p *Portal) appHostURL(subdomain string) string {
	scheme := "https"
	if !p.HTTPS {
		scheme = "http"
	}
	return scheme + "://" + subdomain + "." + p.BaseHost
}

// VerifyAndIssue is exported for the OIDC server to call into the portal's
// auth flow when SSO-completing an /authorize request from a logged-in user.
func (p *Portal) VerifyAndIssue(ctx context.Context, w http.ResponseWriter, username, password string) (*Session, error) {
	user, err := p.Users.Verify(ctx, username, password)
	if err != nil {
		return nil, err
	}
	return p.Sessions.Issue(ctx, w, user.ID)
}

// CurrentUserID implements oidc.PortalSession: returns the authenticated
// user's ID for the request, or 0 if no portal session.
func (p *Portal) CurrentUserID(r *http.Request) (int64, error) {
	sess, err := p.Sessions.Lookup(r.Context(), r)
	if err != nil {
		return 0, err
	}
	if sess == nil {
		return 0, nil
	}
	return sess.User.ID, nil
}

// LoginURL implements oidc.PortalSession: builds an absolute portal-login URL
// that returns to next on success.
func (p *Portal) LoginURL(next string) string {
	return p.portalURL() + "/portal/login?next=" + url.QueryEscape(next)
}

// safeNext returns next iff it parses as a relative URL on the same origin.
func safeNext(raw string) string {
	if raw == "" {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.Scheme != "" || u.Host != "" {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	return raw
}
