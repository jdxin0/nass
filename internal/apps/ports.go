package apps

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const DefaultBackendPortRange = "20000-29999"

// SelectBackendPort returns preferred when it is available. If preferred is
// busy and explicit is false, it scans portRange and returns the first free
// localhost port. The check is necessarily best-effort because docker compose
// binds the port later.
func SelectBackendPort(ctx context.Context, preferred int, portRange string, explicit bool) (int, error) {
	if preferred <= 0 || preferred > 65535 {
		return 0, fmt.Errorf("backend port %d is out of range", preferred)
	}
	if portRange == "" {
		portRange = DefaultBackendPortRange
	}
	start, end, err := parsePortRange(portRange)
	if err != nil {
		return 0, err
	}
	if portAvailable(preferred) {
		return preferred, nil
	}
	if explicit {
		return 0, fmt.Errorf("backend port %d is already in use on 127.0.0.1", preferred)
	}

	for port := start; port <= end; port++ {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("select backend port: %w", ctx.Err())
		default:
		}
		if port == preferred {
			continue
		}
		if portAvailable(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free backend port found in range %s", portRange)
}

func parsePortRange(raw string) (int, int, error) {
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid backend port range %q (want start-end)", raw)
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid backend port range %q: %w", raw, err)
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid backend port range %q: %w", raw, err)
	}
	if start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
		return 0, 0, fmt.Errorf("invalid backend port range %q (ports must be 1-65535 and start <= end)", raw)
	}
	return start, end, nil
}

func portAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
