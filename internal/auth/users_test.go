package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jdxin0/nass/internal/db"
)

// seedCredentials gives the user a portal session plus OIDC access and
// refresh tokens, the three things a credential change must revoke.
func seedCredentials(t *testing.T, d *sql.DB, userID int64) {
	t.Helper()
	exp := time.Now().UTC().Add(time.Hour)
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO apps(name, enabled, settings_json) VALUES ('app', 1, '{}')`, nil},
		{`INSERT INTO oidc_clients(client_id, app_name, client_secret_hash, redirect_uris) VALUES ('c1', 'app', 'x', '[]')`, nil},
		{`INSERT INTO portal_sessions(id, user_id, expires_at) VALUES ('s1', ?, ?)`, []any{userID, exp}},
		{`INSERT INTO oidc_refresh_tokens(id, user_id, client_id, scopes, audience, auth_time, expires_at) VALUES ('r1', ?, 'c1', '[]', '[]', ?, ?)`, []any{userID, exp, exp}},
		{`INSERT INTO oidc_access_tokens(id, client_id, user_id, refresh_token_id, audience, scopes, expires_at) VALUES ('a1', 'c1', ?, 'r1', '[]', '[]', ?)`, []any{userID, exp}},
	}
	for _, s := range stmts {
		if _, err := d.Exec(s.q, s.args...); err != nil {
			t.Fatalf("%s: %v", s.q, err)
		}
	}
}

func credentialCount(t *testing.T, d *sql.DB, userID int64) int {
	t.Helper()
	total := 0
	for _, table := range []string{"portal_sessions", "oidc_access_tokens", "oidc_refresh_tokens"} {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE user_id = ?`, userID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return NewStore(d), d
}

func TestSetPasswordRevokesSessionsAndTokens(t *testing.T) {
	s, d := newTestStore(t)
	ctx := context.Background()
	u, err := s.Create(ctx, "alice", "", "oldpassword", false)
	if err != nil {
		t.Fatal(err)
	}
	seedCredentials(t, d, u.ID)
	if err := s.SetPassword(ctx, u.ID, "newpassword"); err != nil {
		t.Fatal(err)
	}
	if n := credentialCount(t, d, u.ID); n != 0 {
		t.Fatalf("%d sessions/tokens survived a password change", n)
	}
	if _, err := s.Verify(ctx, "alice", "newpassword"); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
	if err := s.SetPassword(ctx, 9999, "whatever1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: got %v", err)
	}
}

func TestSetAdminRevokesOnlyOnDemotion(t *testing.T) {
	s, d := newTestStore(t)
	ctx := context.Background()
	u, err := s.Create(ctx, "bob", "", "bobpassword", false)
	if err != nil {
		t.Fatal(err)
	}
	seedCredentials(t, d, u.ID)

	if err := s.SetAdmin(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if n := credentialCount(t, d, u.ID); n != 3 {
		t.Fatalf("promotion should not sign the user out, %d of 3 credentials left", n)
	}
	if err := s.SetAdmin(ctx, u.ID, true); err != nil { // no-op re-save, e.g. email edit
		t.Fatal(err)
	}
	if n := credentialCount(t, d, u.ID); n != 3 {
		t.Fatalf("re-saving the same role should not sign the user out, %d of 3 left", n)
	}
	if err := s.SetAdmin(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if n := credentialCount(t, d, u.ID); n != 0 {
		t.Fatalf("demotion should revoke everything, %d left", n)
	}
	if err := s.SetAdmin(ctx, 9999, false); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: got %v", err)
	}
}

func TestVerifyUnknownUserTakesBcryptTime(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	dummyHash() // pay the one-off hash generation outside the measurement

	start := time.Now()
	if _, err := s.Verify(ctx, "nobody", "password"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}
	// bcrypt at DefaultCost takes tens of milliseconds; a bare DB miss takes
	// well under one. A loose floor keeps this stable on slow machines.
	if d := time.Since(start); d < 5*time.Millisecond {
		t.Fatalf("unknown-user Verify returned in %v; it must run a bcrypt comparison", d)
	}
}
