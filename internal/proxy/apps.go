package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AppSettings is the JSON shape stored in apps.settings_json. It captures
// everything the proxy + portal + orchestrator need for an app.
type AppSettings struct {
	// Subdomain to expose under base_host (e.g. "nextcloud" → nextcloud.example.com).
	Subdomain string `json:"subdomain"`

	// Backend URL the request is forwarded to.
	Backend string `json:"backend"`

	// PreserveHost forwards the original Host header to the backend.
	PreserveHost bool `json:"preserve_host"`

	// OIDCGate enforces a portal session on this route (for apps without
	// native OIDC support — qBittorrent, etc).
	OIDCGate bool `json:"oidc_gate"`

	// ResponseHeaderTimeoutSec, optional override for slow backends.
	ResponseHeaderTimeoutSec int `json:"response_header_timeout_sec,omitempty"`

	// Portal display fields.
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Icon        string `json:"icon,omitempty"`

	// ComposeFile is the path to the docker-compose.yml managed by the
	// orchestrator (relative to orchestrator.compose_root if not absolute).
	ComposeFile string `json:"compose_file,omitempty"`

	// DataRoot is the on-disk directory holding the app's persistent data.
	// Recorded so `nass app uninstall` can find and remove it even when the
	// install used a non-default path.
	DataRoot string `json:"data_root,omitempty"`
}

// AppRoute is a fully-resolved route ready to be registered with the Server.
type AppRoute struct {
	Name     string
	Host     string // full host: <subdomain>.<base_host>
	Settings AppSettings
}

// LoadEnabled reads enabled apps from the DB and resolves their proxy routes.
// Apps with empty subdomain or backend are reported as errors so misconfig
// is loud rather than silently dropped.
func LoadEnabled(ctx context.Context, db *sql.DB, baseHost string) ([]AppRoute, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT name, settings_json FROM apps WHERE enabled = 1 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AppRoute
	for rows.Next() {
		var name, settingsJSON string
		if err := rows.Scan(&name, &settingsJSON); err != nil {
			return nil, err
		}
		var s AppSettings
		if settingsJSON != "" {
			if err := json.Unmarshal([]byte(settingsJSON), &s); err != nil {
				return nil, fmt.Errorf("app %s: decode settings: %w", name, err)
			}
		}
		if s.Subdomain == "" {
			return nil, fmt.Errorf("app %s: subdomain empty (run `nass app enable %s --subdomain X --backend Y`)", name, name)
		}
		if s.Backend == "" {
			return nil, fmt.Errorf("app %s: backend empty", name)
		}
		out = append(out, AppRoute{
			Name:     name,
			Host:     s.Subdomain + "." + baseHost,
			Settings: s,
		})
	}
	return out, rows.Err()
}

// SaveSettings replaces the settings_json for an app and marks it enabled.
func SaveSettings(ctx context.Context, db *sql.DB, name string, s AppSettings) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO apps(name, enabled, settings_json, enabled_at)
		VALUES (?, 1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET enabled = 1, settings_json = excluded.settings_json, enabled_at = CURRENT_TIMESTAMP`,
		name, string(body))
	return err
}

// HandlerFor builds the http.Handler for a route, wrapping in the OIDC gate
// when requested.
func HandlerFor(r AppRoute, gate Gate) (http.Handler, error) {
	u, err := parseBackend(r.Settings.Backend)
	if err != nil {
		return nil, fmt.Errorf("app %s: %w", r.Name, err)
	}
	opts := BackendOptions{
		Backend:      u,
		PreserveHost: r.Settings.PreserveHost,
	}
	if r.Settings.ResponseHeaderTimeoutSec > 0 {
		opts.ResponseHeaderTimeout = time.Duration(r.Settings.ResponseHeaderTimeoutSec) * time.Second
	}
	h := NewReverseProxy(opts)
	if r.Settings.OIDCGate {
		if gate == nil {
			return nil, fmt.Errorf("app %s: oidc_gate=true but no Gate is wired (phase 4)", r.Name)
		}
		h = gate.Wrap(h)
	}
	return h, nil
}

// Gate is the interface portal sessions implement to gate routes. Wired in phase 4.
type Gate interface {
	Wrap(http.Handler) http.Handler
}

func parseBackend(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("backend empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("backend %q: missing scheme or host", raw)
	}
	return u, nil
}
