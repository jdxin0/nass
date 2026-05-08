package cli

import (
	"context"
	"database/sql"
	"fmt"
	"text/tabwriter"

	"github.com/jdxin0/nass/internal/config"
	"github.com/jdxin0/nass/internal/proxy"
	"github.com/spf13/cobra"
)

func appCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Manage apps registered with the portal & proxy",
	}
	cmd.AddCommand(appListCmd(), appEnableCmd(), appDisableCmd(), appInstallCmd(), appUninstallCmd(), appAvailableCmd())
	return cmd
}

func appListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDB(func(c context.Context, d *sql.DB, _ *config.Config) error {
				rows, err := d.QueryContext(c,
					`SELECT name, enabled, settings_json FROM apps ORDER BY name`)
				if err != nil {
					return err
				}
				defer rows.Close()
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "NAME\tENABLED\tSETTINGS")
				any := false
				for rows.Next() {
					var name, settings string
					var enabled int
					if err := rows.Scan(&name, &enabled, &settings); err != nil {
						return err
					}
					fmt.Fprintf(w, "%s\t%t\t%s\n", name, enabled != 0, settings)
					any = true
				}
				if !any {
					fmt.Fprintln(cmd.OutOrStdout(), "(no apps registered yet)")
					return nil
				}
				return w.Flush()
			})
		},
	}
}

func appEnableCmd() *cobra.Command {
	var (
		subdomain    string
		backend      string
		preserveHost bool
		oidcGate     bool
		respTimeout  int
	)
	cmd := &cobra.Command{
		Use:   "enable <name>",
		Short: "Enable an app and configure its proxy route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if subdomain == "" || backend == "" {
				return fmt.Errorf("--subdomain and --backend are required")
			}
			settings := proxy.AppSettings{
				Subdomain:                subdomain,
				Backend:                  backend,
				PreserveHost:             preserveHost,
				OIDCGate:                 oidcGate,
				ResponseHeaderTimeoutSec: respTimeout,
			}
			return withDB(func(c context.Context, d *sql.DB, _ *config.Config) error {
				if err := proxy.SaveSettings(c, d, args[0], settings); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "enabled %q at %s.<base_host> → %s\n",
					args[0], subdomain, backend)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&subdomain, "subdomain", "", "subdomain to expose (e.g. nextcloud)")
	cmd.Flags().StringVar(&backend, "backend", "", "backend URL (e.g. http://127.0.0.1:18080)")
	cmd.Flags().BoolVar(&preserveHost, "preserve-host", true, "forward original Host header to backend")
	cmd.Flags().BoolVar(&oidcGate, "oidc-gate", false, "require portal session for this route")
	cmd.Flags().IntVar(&respTimeout, "response-header-timeout-sec", 0, "upstream header timeout in seconds (0 = none)")
	return cmd
}

func appDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDB(func(c context.Context, d *sql.DB, _ *config.Config) error {
				res, err := d.ExecContext(c, `UPDATE apps SET enabled = 0 WHERE name = ?`, args[0])
				if err != nil {
					return err
				}
				n, _ := res.RowsAffected()
				if n == 0 {
					return fmt.Errorf("app %q not found", args[0])
				}
				fmt.Fprintf(cmd.OutOrStdout(), "disabled %q\n", args[0])
				return nil
			})
		},
	}
}
