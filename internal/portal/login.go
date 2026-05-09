package portal

import (
	"net/http"

	"github.com/jdxin0/nass/internal/auth"
)

func (p *Portal) getLogin(w http.ResponseWriter, r *http.Request) {
	// If already signed in, just bounce to next.
	if sess, _ := p.Sessions.Lookup(r.Context(), r); sess != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	p.render(w, "login.html", nil, map[string]any{
		"Next":      r.URL.Query().Get("next"),
		"BodyClass": "login-page",
	})
}

func (p *Portal) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	next := safeNext(r.FormValue("next"))

	user, err := p.Users.Verify(r.Context(), username, password)
	if err != nil {
		errMsg := "invalid username or password"
		if err == auth.ErrUserNotFound {
			// keep generic message — don't leak which field was wrong
		}
		p.render(w, "login.html", nil, map[string]any{
			"Next":      r.FormValue("next"),
			"Error":     errMsg,
			"BodyClass": "login-page",
		})
		return
	}
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
