package portal

import (
	"net/http"
	"net/url"
)

// Gate is the proxy.Gate implementation: it wraps a backend handler with a
// session check, redirecting unauthenticated requests to the portal login.
type Gate struct {
	Sessions *SessionStore
	// PortalURL is the absolute URL of the portal (https://<base_host>).
	// Used to build the login redirect when the gated app lives on a
	// different subdomain.
	PortalURL string
}

func NewGate(ss *SessionStore, portalURL string) *Gate {
	return &Gate{Sessions: ss, PortalURL: portalURL}
}

func (g *Gate) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always drop any caller-supplied identity headers so a client can't
		// smuggle them past us — we (and only we) set them from the session.
		r.Header.Del("Remote-User")
		r.Header.Del("Remote-Email")
		r.Header.Del("Remote-Name")
		r.Header.Del("Remote-Groups")

		sess, err := g.Sessions.Lookup(r.Context(), r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if sess == nil {
			// Build absolute "next" so the portal can bounce the user back to
			// the original protected URL after login.
			next := requestURL(r)
			loginURL := g.PortalURL + "/portal/login?next=" + url.QueryEscape(next)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		// Header-based auth for gated apps that read REMOTE_USER (e.g.
		// Firefly III's remote_user_guard). Harmless for apps that ignore it.
		r.Header.Set("Remote-User", sess.User.Username)
		if sess.User.Email != "" {
			r.Header.Set("Remote-Email", sess.User.Email)
		}
		r.Header.Set("Remote-Name", sess.User.Username)
		if sess.User.IsAdmin {
			r.Header.Set("Remote-Groups", "admin")
		}
		h.ServeHTTP(w, r)
	})
}

func requestURL(r *http.Request) string {
	// nass terminates TLS itself; trust the connection, not a client header.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}
