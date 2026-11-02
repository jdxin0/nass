package oidc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/jdxin0/nass/internal/db"
)

// withLocalZone runs the test with time.Local set to zone. Expiry checks
// compare stored text with CURRENT_TIMESTAMP (UTC), so a host whose local
// zone isn't UTC is exactly where they used to break: behind UTC every auth
// request read as already expired, ahead of UTC they outlived their TTL.
func withLocalZone(t *testing.T, zone *time.Location) {
	t.Helper()
	old := time.Local
	time.Local = zone
	t.Cleanup(func() { time.Local = old })
}

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return NewStorage(d, nil, nil)
}

func TestAuthRequestAndCodeValidOutsideUTC(t *testing.T) {
	for _, zone := range []*time.Location{
		time.FixedZone("UTC-5", -5*3600),
		time.FixedZone("UTC+8", 8*3600),
	} {
		t.Run(zone.String(), func(t *testing.T) {
			withLocalZone(t, zone)
			s := newTestStorage(t)
			ctx := context.Background()
			req, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
				ClientID: "c", RedirectURI: "https://app.example.com/cb", ResponseType: oidc.ResponseTypeCode,
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.AuthRequestByID(ctx, req.GetID()); err != nil {
				t.Fatalf("fresh auth request must be found: %v", err)
			}
			if err := s.SaveAuthCode(ctx, req.GetID(), "code-1"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.AuthRequestByCode(ctx, "code-1"); err != nil {
				t.Fatalf("fresh code must be valid: %v", err)
			}

			// An auth request that expired a minute ago must be rejected,
			// not kept alive by the zone offset.
			if _, err := s.db.Exec(`UPDATE oidc_auth_requests SET expires_at = ? WHERE id = ?`,
				time.Now().UTC().Add(-time.Minute), req.GetID()); err != nil {
				t.Fatal(err)
			}
			if _, err := s.AuthRequestByID(ctx, req.GetID()); err == nil {
				t.Fatal("expired auth request must not be found")
			}
		})
	}
}

func TestPurgeExpired(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old, live := now.Add(-48*time.Hour), now.Add(time.Hour)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO users(username, password_hash) VALUES ('u', 'x')`)
	exec(`INSERT INTO apps(name, enabled, settings_json) VALUES ('app', 1, '{}')`)
	exec(`INSERT INTO oidc_clients(client_id, app_name, client_secret_hash, redirect_uris) VALUES ('c', 'app', 'x', '[]')`)
	for _, row := range []struct {
		id  string
		exp time.Time
	}{{"old", old}, {"live", live}} {
		exec(`INSERT INTO oidc_auth_requests(id, client_id, redirect_uri, scopes, response_type, expires_at) VALUES (?, 'c', 'r', '[]', 'code', ?)`, row.id, row.exp)
		exec(`INSERT INTO oidc_auth_codes(code, request_id, expires_at) VALUES (?, ?, ?)`, "code-"+row.id, row.id, row.exp)
		exec(`INSERT INTO oidc_refresh_tokens(id, user_id, client_id, scopes, audience, auth_time, expires_at) VALUES (?, 1, 'c', '[]', '[]', ?, ?)`, "rt-"+row.id, now, row.exp)
		exec(`INSERT INTO oidc_access_tokens(id, client_id, user_id, audience, scopes, expires_at) VALUES (?, 'c', 1, '[]', '[]', ?)`, "at-"+row.id, row.exp)
	}

	if err := s.PurgeExpired(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for table, col := range map[string]string{
		"oidc_auth_requests": "id", "oidc_auth_codes": "code",
		"oidc_refresh_tokens": "id", "oidc_access_tokens": "id",
	} {
		var n int
		var survivor string
		if err := s.db.QueryRow(`SELECT COUNT(*), MAX(`+col+`) FROM `+table).Scan(&n, &survivor); err != nil {
			t.Fatal(err)
		}
		if n != 1 || survivor[len(survivor)-4:] != "live" {
			t.Errorf("%s after purge: %d rows (last %q), want only the live one", table, n, survivor)
		}
	}
}
