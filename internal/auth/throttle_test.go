package auth

import (
	"testing"
	"time"
)

func TestLoginThrottleBlocksAfterMax(t *testing.T) {
	th := NewLoginThrottle(3, 50*time.Millisecond)
	if !th.Allow("k") {
		t.Fatal("fresh key must be allowed")
	}
	for i := 0; i < 3; i++ {
		th.Failed("k")
	}
	if th.Allow("k") {
		t.Fatal("4th attempt must be blocked")
	}
	if ra := th.RetryAfter("k"); ra <= 0 || ra > 50*time.Millisecond {
		t.Fatalf("RetryAfter %v out of range", ra)
	}
}

func TestLoginThrottleWindowExpiresOldFailures(t *testing.T) {
	th := NewLoginThrottle(2, 30*time.Millisecond)
	th.Failed("k")
	th.Failed("k")
	if th.Allow("k") {
		t.Fatal("expected block")
	}
	time.Sleep(40 * time.Millisecond)
	if !th.Allow("k") {
		t.Fatal("window should have expired")
	}
}

func TestLoginThrottleSuccessResets(t *testing.T) {
	th := NewLoginThrottle(2, time.Hour)
	th.Failed("k")
	th.Failed("k")
	if th.Allow("k") {
		t.Fatal("expected block")
	}
	th.Success("k")
	if !th.Allow("k") {
		t.Fatal("Success should clear counter")
	}
}

func TestLoginThrottleNilSafe(t *testing.T) {
	var th *LoginThrottle
	if !th.Allow("k") {
		t.Fatal("nil throttle must allow")
	}
	th.Failed("k")    // must not panic
	th.Success("k")   // must not panic
	th.RetryAfter("k") // must not panic
}
