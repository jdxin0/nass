package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jdxin0/nass/internal/orchestrator"
	"github.com/jdxin0/nass/internal/proxy"
)

// UninstallContext is the resolved input to Uninstall. The caller is expected
// to populate Name + DB + Orchestrator; ComposeFile and DataRoot can be empty
// (Uninstall will look them up from saved AppSettings, or fall back to
// defaults).
type UninstallContext struct {
	Name         string
	ComposeFile  string
	DataRoot     string
	KeepData     bool
	Force        bool
	DB           *sql.DB
	Orchestrator *orchestrator.Orchestrator
}

// Uninstall tears an app down and removes its on-disk state:
//  1. `docker compose down -v --remove-orphans` (skipped when ComposeFile empty)
//  2. delete the apps row (cascades to oidc_clients via FK)
//  3. remove the data folder (unless KeepData)
//  4. remove the compose file and its parent dir if empty
//
// docker-compose failures abort the operation unless Force is set.
func Uninstall(ctx context.Context, uc *UninstallContext) error {
	if uc == nil {
		return fmt.Errorf("uninstall: nil context")
	}
	if uc.Name == "" {
		return fmt.Errorf("uninstall: name required")
	}
	if uc.DB == nil {
		return fmt.Errorf("uninstall: db required")
	}

	if uc.ComposeFile != "" && uc.Orchestrator != nil {
		if _, err := uc.Orchestrator.DownWithVolumes(ctx, uc.ComposeFile); err != nil {
			if !uc.Force && !isMissingComposeFile(err) {
				return fmt.Errorf("compose down: %w", err)
			}
		}
	}

	if _, err := uc.DB.ExecContext(ctx, `DELETE FROM apps WHERE name = ?`, uc.Name); err != nil {
		return fmt.Errorf("delete app row: %w", err)
	}

	if !uc.KeepData && uc.DataRoot != "" {
		if err := os.RemoveAll(uc.DataRoot); err != nil {
			return fmt.Errorf("remove data root %s: %w", uc.DataRoot, err)
		}
	}

	if uc.ComposeFile != "" {
		if err := os.Remove(uc.ComposeFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove compose file %s: %w", uc.ComposeFile, err)
		}
		// Best-effort: remove the parent dir if empty (created by Install).
		_ = os.Remove(filepath.Dir(uc.ComposeFile))
	}
	return nil
}

// LoadAppPaths returns the saved compose file and data root for an app,
// pulled from apps.settings_json. Returns (false, nil) when the app row is
// missing, so callers can decide whether that is an error.
func LoadAppPaths(ctx context.Context, db *sql.DB, name string) (composeFile, dataRoot string, found bool, err error) {
	var settingsJSON string
	row := db.QueryRowContext(ctx, `SELECT settings_json FROM apps WHERE name = ?`, name)
	if err := row.Scan(&settingsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	if settingsJSON == "" {
		return "", "", true, nil
	}
	var s proxy.AppSettings
	if err := json.Unmarshal([]byte(settingsJSON), &s); err != nil {
		return "", "", true, fmt.Errorf("decode settings: %w", err)
	}
	return s.ComposeFile, s.DataRoot, true, nil
}

// isMissingComposeFile reports whether the docker compose error is just
// "compose file gone" — survivable during uninstall, since there's nothing
// left to bring down.
func isMissingComposeFile(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "Cannot find file")
}
