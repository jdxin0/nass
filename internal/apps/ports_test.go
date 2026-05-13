package apps

import (
	"context"
	"fmt"
	"net"
	"testing"
)

func TestSelectBackendPortUsesPreferredWhenFree(t *testing.T) {
	free := freePort(t)

	got, err := SelectBackendPort(context.Background(), free, "23000-23010", false)
	if err != nil {
		t.Fatalf("select port: %v", err)
	}
	if got != free {
		t.Fatalf("got %d want preferred %d", got, free)
	}
}

func TestSelectBackendPortFallsBackWhenPreferredBusy(t *testing.T) {
	busy := occupyPort(t)
	fallback := freePort(t)
	portRange := fmt.Sprintf("%d-%d", fallback, fallback)

	got, err := SelectBackendPort(context.Background(), busy, portRange, false)
	if err != nil {
		t.Fatalf("select port: %v", err)
	}
	if got != fallback {
		t.Fatalf("got %d want fallback %d", got, fallback)
	}
}

func TestSelectBackendPortRejectsBusyExplicitPort(t *testing.T) {
	busy := occupyPort(t)

	_, err := SelectBackendPort(context.Background(), busy, "23000-23010", true)
	if err == nil {
		t.Fatalf("expected busy explicit port to fail")
	}
}

func TestSelectBackendPortRejectsInvalidRange(t *testing.T) {
	_, err := SelectBackendPort(context.Background(), 18080, "29999-20000", false)
	if err == nil {
		t.Fatalf("expected invalid range to fail")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func occupyPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}
