package portal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/jdxin0/nass/internal/auth"
)

const (
	cookieName     = "nass_session"
	sessionTTL     = 7 * 24 * time.Hour
	sessionTokenSz = 32
)

// Session is the resolved session record loaded from the DB on each request
// that needs auth.
type Session struct {
	ID      string
	User    *auth.User
	Expires time.Time
}

// SessionStore manages portal_sessions rows + cookie issuance.
type SessionStore struct {
	db    *sql.DB
	users *auth.Store
	// CookieDomain scopes the session cookie. Set to base_host so that
	// subdomain apps (gated routes, OIDC) share the same session.
	CookieDomain string
	// Insecure disables the Secure cookie flag (dev only).
	Insecure bool
}

func NewSessionStore(db *sql.DB, users *auth.Store, cookieDomain string) *SessionStore {
	return &SessionStore{db: db, users: users, CookieDomain: cookieDomain}
}

// Issue creates a new session for userID and writes the cookie.
func (s *SessionStore) Issue(ctx context.Context, w http.ResponseWriter, userID int64) (*Session, error) {
	id, err := randomToken(sessionTokenSz)
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(sessionTTL)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO portal_sessions(id, user_id, expires_at) VALUES (?, ?, ?)`,
		id, userID, expires); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		Domain:   s.CookieDomain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   !s.Insecure,
		SameSite: http.SameSiteLaxMode,
	})
	user, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &Session{ID: id, User: user, Expires: expires}, nil
}

// Lookup returns the session bound to the request's cookie, or nil if absent /
// expired / unknown. Errors are returned only for DB failures.
func (s *SessionStore) Lookup(ctx context.Context, r *http.Request) (*Session, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, nil
	}
	var (
		uid     int64
		expires time.Time
	)
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM portal_sessions WHERE id = ?`, c.Value)
	if err := row.Scan(&uid, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if time.Now().After(expires) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE id = ?`, c.Value)
		return nil, nil
	}
	user, err := s.users.Get(ctx, uid)
	if err != nil {
		return nil, err
	}
	return &Session{ID: c.Value, User: user, Expires: expires}, nil
}

// Revoke deletes the session and clears the cookie.
func (s *SessionStore) Revoke(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE id = ?`, c.Value); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:    cookieName,
		Value:   "",
		Path:    "/",
		Domain:  s.CookieDomain,
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
	return nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
