package portal

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/jdxin0/nass/internal/orchestrator"
	"github.com/jdxin0/nass/internal/proxy"
)

type dashboardTile struct {
	Name        string
	DisplayName string
	Description string
	Icon        string
	URL         string
	State       orchestrator.State
}

func (p *Portal) getDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// "/" is the only thing this handler claims; reject other paths cleanly.
		http.NotFound(w, r)
		return
	}
	sess, ok := p.requireSession(w, r)
	if !ok {
		return
	}

	apps, err := loadAppsForDashboard(r.Context(), p.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tiles := make([]dashboardTile, 0, len(apps))
	for _, a := range apps {
		tiles = append(tiles, dashboardTile{
			Name:        a.Name,
			DisplayName: a.displayName(),
			Description: a.Settings.Description,
			Icon:        a.Settings.Icon,
			URL:         p.appHostURL(a.Settings.Subdomain),
			State:       p.stateOf(r.Context(), a),
		})
	}
	p.render(w, "dashboard.html", sess, map[string]any{
		"Apps": tiles,
	})
}

// dbApp is a portal-internal view of an app row.
type dbApp struct {
	Name     string
	Enabled  bool
	Settings proxy.AppSettings
}

func (a dbApp) displayName() string {
	if a.Settings.DisplayName != "" {
		return a.Settings.DisplayName
	}
	return a.Name
}

// loadAppsForDashboard returns enabled apps that have at least a subdomain set.
// (Disabled apps are hidden from the user dashboard but still appear in admin.)
func loadAppsForDashboard(ctx context.Context, db *sql.DB) ([]dbApp, error) {
	return loadApps(ctx, db, true)
}

func loadAllApps(ctx context.Context, db *sql.DB) ([]dbApp, error) {
	return loadApps(ctx, db, false)
}

func loadApps(ctx context.Context, db *sql.DB, enabledOnly bool) ([]dbApp, error) {
	q := `SELECT name, enabled, settings_json FROM apps`
	if enabledOnly {
		q += ` WHERE enabled = 1`
	}
	q += ` ORDER BY name`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dbApp
	for rows.Next() {
		var (
			name, settingsJSON string
			enabled            int
		)
		if err := rows.Scan(&name, &enabled, &settingsJSON); err != nil {
			return nil, err
		}
		a := dbApp{Name: name, Enabled: enabled != 0}
		if settingsJSON != "" {
			if err := json.Unmarshal([]byte(settingsJSON), &a.Settings); err != nil {
				return nil, err
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// stateOf reports the docker compose state, or "unknown" if no compose file
// is configured for the app or the orchestrator is unavailable.
func (p *Portal) stateOf(ctx context.Context, a dbApp) orchestrator.State {
	if p.Orchestrator == nil || a.Settings.ComposeFile == "" {
		return orchestrator.StateUnknown
	}
	state, err := p.Orchestrator.Status(ctx, a.Settings.ComposeFile)
	if err != nil {
		return orchestrator.StateUnknown
	}
	return state
}
