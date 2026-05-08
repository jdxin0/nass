package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/jdxin0/nass/internal/auth"
	"github.com/jdxin0/nass/internal/config"
	"github.com/jdxin0/nass/internal/db"
	"github.com/spf13/cobra"
)

type cliCtx struct {
	configPath string
}

var ctx = &cliCtx{}

func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "nass",
		Short:         "Self-host orchestrator with built-in proxy, portal, and OIDC",
		Version:       buildVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// Pre-register the version flag so cobra's default version flag (without
	// a shorthand) does not get added in InitDefaultVersionFlag.
	root.Flags().BoolP("version", "v", false, "print version and exit")
	root.SetVersionTemplate("nass {{.Version}}\n")
	root.PersistentFlags().StringVarP(&ctx.configPath, "config", "c", "nass.toml", "path to nass.toml")
	root.AddCommand(initCmd(), serveCmd(), userCmd(), appCmd(), oidcClientCmd())
	return root
}

// buildVersion returns the short git commit hash embedded by the Go toolchain
// (vcs.revision in BuildInfo). Appends "-dirty" when the working tree had
// uncommitted changes at build time. Returns "unknown" outside a VCS build.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// loadConfig loads the config file pointed to by --config.
func loadConfig() (*config.Config, error) {
	if _, err := os.Stat(ctx.configPath); err != nil {
		return nil, fmt.Errorf("config %s: %w", ctx.configPath, err)
	}
	return config.Load(ctx.configPath)
}

// withDB opens the SQLite DB based on config and runs fn.
func withDB(fn func(context.Context, *sql.DB, *config.Config) error) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	d, err := db.Open(cfg.DB.Path)
	if err != nil {
		return err
	}
	defer d.Close()
	return fn(context.Background(), d, cfg)
}

// withStore is a shortcut for commands that only need the user store.
func withStore(fn func(context.Context, *auth.Store) error) error {
	return withDB(func(c context.Context, d *sql.DB, _ *config.Config) error {
		return fn(c, auth.NewStore(d))
	})
}
