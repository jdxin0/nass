package proxy

import (
	"context"
	"database/sql"
	"sync"
)

// RouteManager keeps the live host router in sync with the apps table.
// It owns the set of "managed" routes (one per app) so that fixed routes
// — OIDC, portal — registered directly on the Server are never touched.
type RouteManager struct {
	DB       *sql.DB
	BaseHost string
	Server   *Server
	Gate     Gate

	mu       sync.Mutex
	appHosts map[string]string // app name → host currently registered
}

// NewRouteManager returns an empty manager. Call Sync after construction to
// populate routes from the DB.
func NewRouteManager(db *sql.DB, server *Server, baseHost string, gate Gate) *RouteManager {
	return &RouteManager{
		DB:       db,
		BaseHost: baseHost,
		Server:   server,
		Gate:     gate,
		appHosts: map[string]string{},
	}
}

// Sync reconciles the live router with what's in the apps table. It is safe
// to call on every admin mutation; routes not present in this manager's
// registry (e.g. OIDC, portal) are left untouched.
func (m *RouteManager) Sync(ctx context.Context) error {
	desired, err := LoadEnabled(ctx, m.DB, m.BaseHost)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	desiredHosts := make(map[string]string, len(desired))
	for _, r := range desired {
		h, err := HandlerFor(r, m.Gate)
		if err != nil {
			return err
		}
		m.Server.AddRoute(r.Host, h)
		desiredHosts[r.Name] = r.Host
	}

	// Drop routes whose app is no longer enabled, or whose host changed.
	for name, oldHost := range m.appHosts {
		newHost, ok := desiredHosts[name]
		if !ok || newHost != oldHost {
			m.Server.RemoveRoute(oldHost)
		}
	}
	m.appHosts = desiredHosts
	return nil
}

// ManagedHosts returns the set of hosts currently owned by this manager.
// (Mostly useful in tests.)
func (m *RouteManager) ManagedHosts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.appHosts))
	for _, h := range m.appHosts {
		out = append(out, h)
	}
	return out
}
