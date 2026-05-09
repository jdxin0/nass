package oidc

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jdxin0/nass/internal/db"
)

func TestRevokeClientDeletesIssuedTokens(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	prov, err := Provision(ctx, d, "demo", []string{"https://demo.example.com/callback"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO users(username, password_hash) VALUES ('alice', 'hash')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := d.ExecContext(ctx, `
		INSERT INTO oidc_refresh_tokens(id, user_id, client_id, scopes, audience, auth_time, expires_at)
		VALUES ('refresh-1', 1, ?, '["openid"]', '[]', ?, ?)`,
		prov.ClientID, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}
	if _, err := d.ExecContext(ctx, `
		INSERT INTO oidc_access_tokens(id, client_id, user_id, refresh_token_id, audience, scopes, expires_at)
		VALUES ('access-1', ?, 1, 'refresh-1', '[]', '["openid"]', ?)`,
		prov.ClientID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert access token: %v", err)
	}

	if err := RevokeClient(ctx, d, "demo"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	for table, want := range map[string]int{
		"oidc_clients":        0,
		"oidc_refresh_tokens": 0,
		"oidc_access_tokens":  0,
		"apps":                1,
	} {
		if got := countRows(t, d, table); got != want {
			t.Fatalf("%s rows: got %d want %d", table, got, want)
		}
	}
}

func countRows(t *testing.T, d *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
