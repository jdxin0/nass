package proxy

import "net/http"

// HSTS returns a middleware that adds Strict-Transport-Security to every
// response. Safe to apply at the front-door level because the header is
// host-scoped and additive — proxied apps don't need to opt out.
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// FirstPartyHeaders adds the security headers we can safely set on responses
// nass renders itself (portal pages, OIDC discovery + login). It is not
// applied to proxied apps because CSP / X-Frame-Options would break apps
// with their own front-end conventions.
func FirstPartyHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-Frame-Options", "DENY")
		// Only set CSP if the handler didn't already pick one (the OIDC
		// library may want a different policy for its own pages).
		if h.Get("Content-Security-Policy") == "" {
			h.Set("Content-Security-Policy", csp)
		}
		next.ServeHTTP(w, r)
	})
}
