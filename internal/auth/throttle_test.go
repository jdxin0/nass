package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestLoginThrottleBlocksAfterMax(t *testing.T) {
	th := NewLoginThrottle(3, 100, 50*time.Millisecond)
	if !th.Allow("1.2.3.4", "alice") {
		t.Fatal("fresh key must be allowed")
	}
	for i := 0; i < 3; i++ {
		th.Failed("1.2.3.4", "alice")
	}
	if th.Allow("1.2.3.4", "alice") {
		t.Fatal("4th attempt must be blocked")
	}
	if ra := th.RetryAfter("1.2.3.4", "alice"); ra <= 0 || ra > 50*time.Millisecond {
		t.Fatalf("RetryAfter %v out of range", ra)
	}
	if !th.Allow("5.6.7.8", "alice") {
		t.Fatal("a different IP must not be blocked")
	}
	if !th.Allow("1.2.3.4", "bob") {
		t.Fatal("another username under the IP budget must not be blocked")
	}
}

func TestLoginThrottleBlocksUsernameSpraying(t *testing.T) {
	th := NewLoginThrottle(3, 5, time.Hour)
	for i := 0; i < 5; i++ {
		user := fmt.Sprintf("user%d", i)
		if !th.Allow("1.2.3.4", user) {
			t.Fatalf("attempt %d should be under the IP budget", i)
		}
		th.Failed("1.2.3.4", user)
	}
	if th.Allow("1.2.3.4", "fresh-username") {
		t.Fatal("IP budget must apply across usernames")
	}
	if ra := th.RetryAfter("1.2.3.4", "fresh-username"); ra <= 0 {
		t.Fatalf("RetryAfter = %v, want > 0 once the IP budget is spent", ra)
	}
	th.Success("1.2.3.4", "user0")
	if th.Allow("1.2.3.4", "fresh-username") {
		t.Fatal("a success on one account must not reset the IP budget")
	}
}

func TestLoginThrottleWindowExpiresOldFailures(t *testing.T) {
	th := NewLoginThrottle(2, 100, 30*time.Millisecond)
	th.Failed("ip", "k")
	th.Failed("ip", "k")
	if th.Allow("ip", "k") {
		t.Fatal("expected block")
	}
	time.Sleep(40 * time.Millisecond)
	if !th.Allow("ip", "k") {
		t.Fatal("window should have expired")
	}
}

func TestLoginThrottleSuccessResets(t *testing.T) {
	th := NewLoginThrottle(2, 100, time.Hour)
	th.Failed("ip", "k")
	th.Failed("ip", "k")
	if th.Allow("ip", "k") {
		t.Fatal("expected block")
	}
	th.Success("ip", "k")
	if !th.Allow("ip", "k") {
		t.Fatal("Success should clear counter")
	}
}

func TestLoginThrottleSweepsAbandonedKeys(t *testing.T) {
	th := NewLoginThrottle(10, 1000, 20*time.Millisecond)
	for i := 0; i < 50; i++ {
		th.Failed(fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("random%d", i))
	}
	time.Sleep(30 * time.Millisecond)
	th.Failed("10.9.9.9", "last") // triggers a sweep
	th.mu.Lock()
	n := len(th.entries)
	th.mu.Unlock()
	if n != 2 { // only the last IP+username and IP keys remain
		t.Fatalf("entries after sweep = %d, want 2", n)
	}
}

func TestLoginThrottleNilSafe(t *testing.T) {
	var th *LoginThrottle
	if !th.Allow("ip", "k") {
		t.Fatal("nil throttle must allow")
	}
	th.Failed("ip", "k")     // must not panic
	th.Success("ip", "k")    // must not panic
	th.RetryAfter("ip", "k") // must not panic
}
