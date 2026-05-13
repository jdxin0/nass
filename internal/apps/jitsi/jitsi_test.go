package jitsi

import (
	"net"
	"testing"
)

func TestDetectHostIPReturnsNonEmpty(t *testing.T) {
	ip, err := detectHostIP()
	if err != nil {
		t.Skipf("no route to outside: %v", err)
	}
	if net.ParseIP(ip) == nil {
		t.Fatalf("detectHostIP returned %q, not a valid IP", ip)
	}
}
