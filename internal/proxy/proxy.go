// Package proxy is the front door: TLS terminator + host-based dispatcher.
// Each Host is mapped to an http.Handler, which may be a reverse proxy
// (NewReverseProxy) or any other handler (e.g. the OIDC server).
package proxy

import (
	"net/http"
	"strings"
	"sync"
)

// Server dispatches incoming requests by Host header (case-insensitive,
// exact match after stripping any port).
type Server struct {
	mu       sync.RWMutex
	routes   map[string]http.Handler
	fallback http.Handler
}

// New returns an empty Server with a 404 fallback.
func New() *Server {
	return &Server{
		routes:   map[string]http.Handler{},
		fallback: http.HandlerFunc(notFound),
	}
}

// SetFallback installs a handler used when no route matches the Host.
func (s *Server) SetFallback(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fallback = h
}

// AddRoute registers handler for host. Replaces any existing route.
func (s *Server) AddRoute(host string, handler http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[strings.ToLower(host)] = handler
}

// RemoveRoute unregisters host. Returns true if a route existed.
func (s *Server) RemoveRoute(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.routes[strings.ToLower(host)]
	delete(s.routes, strings.ToLower(host))
	return ok
}

// Hosts returns the registered hosts. Order is unspecified.
func (s *Server) Hosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.routes))
	for h := range s.routes {
		out = append(out, h)
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Defense in depth: never let a remote client smuggle the identity
	// headers the OIDC gate uses to authenticate to backends like Firefly.
	// The gate re-sets them from the session for OIDC-gated routes; for
	// every other route, the backend sees them absent.
	r.Header.Del("Remote-User")
	r.Header.Del("Remote-Email")
	r.Header.Del("Remote-Name")
	r.Header.Del("Remote-Groups")

	host := strings.ToLower(stripPort(r.Host))
	s.mu.RLock()
	h, ok := s.routes[host]
	if !ok {
		h = s.fallback
	}
	s.mu.RUnlock()
	h.ServeHTTP(w, r)
}

func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i != -1 {
		// Skip IPv6 bracketed addresses.
		if !strings.HasPrefix(host, "[") {
			return host[:i]
		}
		if j := strings.LastIndexByte(host, ']'); j != -1 && i > j {
			return host[:i]
		}
	}
	return host
}

func notFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "no route for host "+r.Host, http.StatusNotFound)
}
