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
		h.ServeHTTP(w, r)
	})
}

func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			scheme = v
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}
