package auth

import (
	"sync"
	"time"
)

// LoginThrottle is an in-memory sliding-window failure counter used to slow
// down credential-stuffing and brute-force attempts against the login forms.
// Keys are caller-supplied strings (typically "<ip>|<username>"). The zero
// value is not usable; construct with NewLoginThrottle.
type LoginThrottle struct {
	max    int
	window time.Duration

	mu      sync.Mutex
	entries map[string][]time.Time
}

func NewLoginThrottle(max int, window time.Duration) *LoginThrottle {
	if max <= 0 {
		max = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	return &LoginThrottle{
		max:     max,
		window:  window,
		entries: map[string][]time.Time{},
	}
}

// Allow returns false when key has hit the failure threshold inside the
// active window. A nil receiver always allows (callers can pass nil to
// disable throttling in tests).
func (t *LoginThrottle) Allow(key string) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.trim(key)
	return len(t.entries[key]) < t.max
}

// Failed records a failed attempt against key.
func (t *LoginThrottle) Failed(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = append(t.entries[key], time.Now())
	t.trim(key)
}

// Success clears the failure counter for key.
func (t *LoginThrottle) Success(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// RetryAfter returns the duration until the earliest failure in the window
// drops off, or zero if the key is currently allowed.
func (t *LoginThrottle) RetryAfter(key string) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.trim(key)
	failures := t.entries[key]
	if len(failures) < t.max {
		return 0
	}
	wait := t.window - time.Since(failures[0])
	if wait < 0 {
		return 0
	}
	return wait
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
