package portal_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func login(t *testing.T, f *fixture, username, password string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar}
	resp, err := hc.PostForm(f.server.URL+"/portal/login",
		url.Values{"username": {username}, "password": {password}, "next": {"/"}})
	if err != nil {
		t.Fatalf("login %s: %v", username, err)
	}
	resp.Body.Close()
	return hc
}

func dashboardStatus(t *testing.T, f *fixture, hc *http.Client) int {
	t.Helper()
	noFollow := *hc
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Get(f.server.URL + "/")
	if err != nil {
		t.Fatalf("get dashboard: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestPasswordResetSignsUserOut(t *testing.T) {
	f := newFixture(t)
	alice := login(t, f, "alice", "alicepassword")
	if got := dashboardStatus(t, f, alice); got != http.StatusOK {
		t.Fatalf("alice dashboard before reset: %d", got)
	}
	admin := login(t, f, "admin", "supersecretpw")

	u, err := f.users.GetByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := admin.PostForm(f.server.URL+"/portal/admin/users/"+strconv.FormatInt(u.ID, 10)+"/password",
		url.Values{"password": {"brand-new-password"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := dashboardStatus(t, f, alice); got != http.StatusFound {
		t.Fatalf("alice's old session must be revoked after a reset, got %d", got)
	}
	if got := dashboardStatus(t, f, admin); got != http.StatusOK {
		t.Fatalf("admin resetting someone else's password must stay signed in, got %d", got)
	}
}

func TestOwnPasswordChangeKeepsThisBrowserSignedIn(t *testing.T) {
	f := newFixture(t)
	admin := login(t, f, "admin", "supersecretpw")
	other := login(t, f, "admin", "supersecretpw") // e.g. a stolen session

	u, err := f.users.GetByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := admin.PostForm(f.server.URL+"/portal/admin/users/"+strconv.FormatInt(u.ID, 10)+"/password",
		url.Values{"password": {"brand-new-password"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if got := dashboardStatus(t, f, admin); got != http.StatusOK {
		t.Fatalf("browser that changed the password should get a fresh session, got %d", got)
	}
	if got := dashboardStatus(t, f, other); got != http.StatusFound {
		t.Fatalf("other sessions must be revoked, got %d", got)
	}
}

func TestPurgeExpiredSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	u, err := f.users.GetByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for id, exp := range map[string]time.Time{"old": now.Add(-48 * time.Hour), "live": now.Add(time.Hour)} {
		if _, err := f.db.Exec(`INSERT INTO portal_sessions(id, user_id, expires_at) VALUES (?, ?, ?)`, id, u.ID, exp); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.sessions.PurgeExpired(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var ids []string
	rows, err := f.db.Query(`SELECT id FROM portal_sessions ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	if len(ids) != 1 || ids[0] != "live" {
		t.Fatalf("sessions after purge = %v, want [live]", ids)
	}
}
