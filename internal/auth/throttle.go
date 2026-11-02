package auth

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// LoginThrottle is an in-memory sliding-window failure counter used to slow
// down credential-stuffing and brute-force attempts against the login forms.
//
// It keeps two budgets per window:
//   - per IP+username (max): a user on a shared NAT isn't locked out because
//     somebody else fat-fingered their own password;
//   - per IP across all usernames (ipMax): an attacker can't spray one
//     password across many usernames by switching names.
//
// The zero value is not usable; construct with NewLoginThrottle.
type LoginThrottle struct {
	max    int
	ipMax  int
	window time.Duration

	mu        sync.Mutex
	entries   map[string][]time.Time
	lastSweep time.Time
}

// NewLoginThrottle allows max failures per IP+username and ipMax failures per
// IP (across usernames) inside each window.
func NewLoginThrottle(max, ipMax int, window time.Duration) *LoginThrottle {
	if max <= 0 {
		max = 10
	}
	if ipMax <= 0 {
		ipMax = 3 * max
	}
	if window <= 0 {
		window = time.Minute
	}
	return &LoginThrottle{
		max:     max,
		ipMax:   ipMax,
		window:  window,
		entries: map[string][]time.Time{},
	}
}

// ClientIP returns the peer IP of r. nass terminates connections itself, so
// RemoteAddr is the real client; forwarded headers are not trusted.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func userKey(ip, username string) string { return "u|" + ip + "|" + username }
func ipKey(ip string) string             { return "ip|" + ip }

// Allow returns false when either the IP+username or the IP budget is used up
// inside the active window. A nil receiver always allows (callers can pass nil
// to disable throttling in tests).
func (t *LoginThrottle) Allow(ip, username string) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	uk, ik := userKey(ip, username), ipKey(ip)
	t.trim(uk)
	t.trim(ik)
	return len(t.entries[uk]) < t.max && len(t.entries[ik]) < t.ipMax
}

// Failed records a failed attempt against both budgets.
func (t *LoginThrottle) Failed(ip, username string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for _, k := range []string{userKey(ip, username), ipKey(ip)} {
		t.entries[k] = append(t.entries[k], now)
		t.trim(k)
	}
	t.sweep(now)
}

// Success clears the IP+username counter. The IP counter is left alone so a
// successful login on one account doesn't reset the budget for spraying
// others.
func (t *LoginThrottle) Success(ip, username string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, userKey(ip, username))
}

// RetryAfter returns how long until the caller is allowed again, or zero if
// it is currently allowed.
func (t *LoginThrottle) RetryAfter(ip, username string) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return max(t.wait(userKey(ip, username), t.max), t.wait(ipKey(ip), t.ipMax))
}

func (t *LoginThrottle) wait(key string, limit int) time.Duration {
	t.trim(key)
	failures := t.entries[key]
	if len(failures) < limit {
		return 0
	}
	// The key is allowed again once enough of the oldest failures age out.
	wait := t.window - time.Since(failures[len(failures)-limit])
	if wait < 0 {
		return 0
	}
	return wait
}

// sweep drops expired failures for every key at most once per window, so
// keys that are never touched again (e.g. random usernames) don't accumulate.
func (t *LoginThrottle) sweep(now time.Time) {
	if now.Sub(t.lastSweep) < t.window {
		return
	}
	t.lastSweep = now
	for k := range t.entries {
		t.trim(k)
	}
}

func (t *LoginThrottle) trim(key string) {
	failures, ok := t.entries[key]
	if !ok {
		return
	}
	cutoff := time.Now().Add(-t.window)
	keep := failures[:0]
	for _, ts := range failures {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	if len(keep) == 0 {
		delete(t.entries, key)
		return
	}
	t.entries[key] = keep
}
