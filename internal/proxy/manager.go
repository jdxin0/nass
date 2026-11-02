package proxy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	reserved map[string]bool   // hosts no app may claim (OIDC, portal)
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
		reserved: map[string]bool{},
	}
}

// Reserve marks hosts (the fixed OIDC and portal routes) that no app may
// claim. Without this an app on e.g. the "auth" subdomain would replace the
// sign-in server's route, and removing that app would delete it.
func (m *RouteManager) Reserve(hosts ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range hosts {
		m.reserved[strings.ToLower(h)] = true
	}
}

// Sync reconciles the live router with what's in the apps table. It is safe
// to call on every admin mutation; routes not present in this manager's
// registry (e.g. OIDC, portal) are left untouched.
//
// A misconfigured app is skipped (and reported in the returned error) rather
// than aborting the sync, so one bad row can't freeze every other route.
// Only a failed DB query leaves the live routes as they were.
func (m *RouteManager) Sync(ctx context.Context) error {
	routes, problems, err := loadEnabled(ctx, m.DB, m.BaseHost)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	type entry struct {
		host    string
		handler http.Handler
	}
	desired := make(map[string]entry, len(routes))
	claimed := make(map[string]string, len(routes)) // host → app name
	for _, r := range routes {
		if m.reserved[r.Host] {
			problems = append(problems, fmt.Errorf("app %s: host %s is reserved for nass itself; choose another subdomain", r.Name, r.Host))
			continue
		}
		if other, ok := claimed[r.Host]; ok {
			problems = append(problems, fmt.Errorf("app %s: host %s is already used by app %s", r.Name, r.Host, other))
			continue
		}
		h, err := HandlerFor(r, m.Gate)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		claimed[r.Host] = r.Name
		desired[r.Name] = entry{host: r.Host, handler: h}
	}

	// Drop routes whose host no app claims any more. Done before adding so a
	// host that moved from one app to another in this sync isn't removed
	// right after being re-registered.
	for _, oldHost := range m.appHosts {
		if _, ok := claimed[oldHost]; !ok {
			m.Server.RemoveRoute(oldHost)
		}
	}
	hosts := make(map[string]string, len(desired))
	for name, e := range desired {
		m.Server.AddRoute(e.host, e.handler)
		hosts[name] = e.host
	}
	m.appHosts = hosts
	return errors.Join(problems...)
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
