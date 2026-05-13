package oidc

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/jdxin0/nass/internal/auth"
)

//go:embed templates/login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// PortalSession is the contract this package needs from the portal package
// to do SSO: look up the current user from the request, and if absent,
// give us the URL to send the user to for sign-in.
type PortalSession interface {
	// CurrentUserID returns the authenticated user's ID, or 0 if none.
	CurrentUserID(r *http.Request) (int64, error)
	// LoginURL returns the URL of the portal's login form, with `next`
	// embedded so the user is bounced back here once signed in.
	LoginURL(next string) string
}

// Login wires the GET/POST login routes that complete the OIDC auth code flow.
// When a PortalSession is supplied, GET /login becomes SSO: existing portal
// sessions skip the form entirely.
type Login struct {
	storage           *Storage
	users             *auth.Store
	callback          func(ctx context.Context, authReqID string) string
	issuerInterceptor *op.IssuerInterceptor
	portal            PortalSession
	throttle          *auth.LoginThrottle
}

func NewLogin(storage *Storage, users *auth.Store, callback func(context.Context, string) string, ii *op.IssuerInterceptor) *Login {
	return &Login{storage: storage, users: users, callback: callback, issuerInterceptor: ii}
}

// SetPortal enables SSO via the portal's session cookie. Without this,
// every /authorize bounce shows the embedded login form.
func (l *Login) SetPortal(p PortalSession) { l.portal = p }

// SetThrottle wires a brute-force throttle shared with the portal. May be
// nil (no throttling).
func (l *Login) SetThrottle(t *auth.LoginThrottle) { l.throttle = t }

// Mount adds /login routes to mux.
func (l *Login) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", l.get)
	mux.Handle("POST /login", l.issuerInterceptor.HandlerFunc(l.post))
}

type loginPage struct {
	AuthRequestID string
	Error         string
}

func (l *Login) get(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("authRequestID")
	if id == "" {
		http.Error(w, "missing authRequestID", http.StatusBadRequest)
		return
	}
	if l.portal != nil {
		uid, err := l.portal.CurrentUserID(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if uid != 0 {
			// SSO: complete the auth request immediately and redirect to the OP callback.
			if err := markAuthRequestComplete(r.Context(), l.storage.db, id, uid); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, l.callback(r.Context(), id), http.StatusFound)
			return
		}
		// Not logged in: bounce to portal login with `next` pointing back here.
		next := "/login?authRequestID=" + url.QueryEscape(id)
		http.Redirect(w, r, l.portal.LoginURL(next), http.StatusFound)
		return
	}
	// No portal wired: fall back to the embedded form.
	render(w, loginPage{AuthRequestID: id})
}

func (l *Login) post(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	username := r.FormValue("username")
	password := r.FormValue("password")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	key := throttleKey(r, username)
	if !l.throttle.Allow(key) {
		wait := l.throttle.RetryAfter(key)
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", wait.Round(time.Second).Seconds()))
		render(w, loginPage{AuthRequestID: id, Error: "too many attempts; try again later"})
		return
	}

	user, err := l.users.Verify(r.Context(), username, password)
	if err != nil {
		l.throttle.Failed(key)
		render(w, loginPage{AuthRequestID: id, Error: "invalid username or password"})
		return
	}
	l.throttle.Success(key)
	if err := markAuthRequestComplete(r.Context(), l.storage.db, id, user.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, l.callback(r.Context(), id), http.StatusFound)
}

// sameOrigin permits requests whose Origin/Referer matches r.Host, and also
// permits requests that send neither header (curl). Combined with the auth
// request id being a fresh, unguessable UUID this gives meaningful CSRF
// protection without breaking automation.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

func throttleKey(r *http.Request, username string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host + "|" + username
}

func render(w http.ResponseWriter, page loginPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginTmpl.Execute(w, page); err != nil {
		http.Error(w, fmt.Sprintf("template: %v", err), http.StatusInternalServerError)
	}
}
