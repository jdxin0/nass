package portal

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jdxin0/nass/internal/auth"
)

func (p *Portal) getLogin(w http.ResponseWriter, r *http.Request) {
	// If already signed in, just bounce to next.
	if sess, _ := p.Sessions.Lookup(r.Context(), r); sess != nil {
		http.Redirect(w, r, p.safeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	p.render(w, "login.html", nil, map[string]any{
		"Next":      r.URL.Query().Get("next"),
		"BodyClass": "login-page",
	})
}

func (p *Portal) postLogin(w http.ResponseWriter, r *http.Request) {
	// Defense in depth against login CSRF. sameOrigin permits requests with
	// no Origin/Referer (curl) but blocks browser cross-site POSTs.
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	next := p.safeNext(r.FormValue("next"))

	ip := auth.ClientIP(r)
	if !p.LoginThrottle.Allow(ip, username) {
		wait := p.LoginThrottle.RetryAfter(ip, username)
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", wait.Round(time.Second).Seconds()))
		p.render(w, "login.html", nil, map[string]any{
			"Next":      r.FormValue("next"),
			"Error":     "too many attempts; try again later",
			"BodyClass": "login-page",
		})
		return
	}

	user, err := p.Users.Verify(r.Context(), username, password)
	if err != nil {
		p.LoginThrottle.Failed(ip, username)
		// Generic message: don't leak which field was wrong.
		p.render(w, "login.html", nil, map[string]any{
			"Next":      r.FormValue("next"),
			"Error":     "invalid username or password",
			"BodyClass": "login-page",
		})
		return
	}
	p.LoginThrottle.Success(ip, username)
	if _, err := p.Sessions.Issue(r.Context(), w, user.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (p *Portal) postLogout(w http.ResponseWriter, r *http.Request) {
	_ = p.Sessions.Revoke(r.Context(), w, r)
	http.Redirect(w, r, "/portal/login", http.StatusFound)
}
