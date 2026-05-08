package cli

import (
	"context"
	"database/sql"
	"fmt"
	"text/tabwriter"

	"github.com/jdxin0/nass/internal/auth/oidc"
	"github.com/jdxin0/nass/internal/config"
	"github.com/spf13/cobra"
)

func oidcClientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oidc-client",
		Short: "Manage OIDC clients (one per app)",
	}
	cmd.AddCommand(oidcClientAddCmd(), oidcClientListCmd(), oidcClientRmCmd())
	return cmd
}

func oidcClientAddCmd() *cobra.Command {
	var redirects []string
	cmd := &cobra.Command{
		Use:   "add <app-name>",
		Short: "Provision a new OIDC client for an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(redirects) == 0 {
				return fmt.Errorf("at least one --redirect-uri is required")
			}
			return withDB(func(c context.Context, d *sql.DB, _ *config.Config) error {
				res, err := oidc.Provision(c, d, args[0], redirects)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "client_id:     %s\n", res.ClientID)
				fmt.Fprintf(cmd.OutOrStdout(), "client_secret: %s\n", res.ClientSecret)
				fmt.Fprintln(cmd.OutOrStderr(), "(secret is shown once; only its bcrypt hash is stored)")
				return nil
			})
		},
	}
	cmd.Flags().StringSliceVar(&redirects, "redirect-uri", nil, "redirect URI (repeatable)")
	return cmd
}

func oidcClientListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List OIDC clients",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDB(func(c context.Context, d *sql.DB, _ *config.Config) error {
				rows, err := d.QueryContext(c,
					`SELECT client_id, app_name, redirect_uris, created_at FROM oidc_clients ORDER BY app_name`)
				if err != nil {
					return err
				}
				defer rows.Close()
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "APP\tCLIENT_ID\tREDIRECT_URIS\tCREATED")
				any := false
				for rows.Next() {
					var clientID, app, uris, created string
					if err := rows.Scan(&clientID, &app, &uris, &created); err != nil {
						return err
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", app, clientID, uris, created)
					any = true
				}
				if !any {
					fmt.Fprintln(cmd.OutOrStdout(), "(no clients)")
					return nil
				}
				return w.Flush()
			})
		},
	}
}

func oidcClientRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <app-name>",
		Short: "Revoke and delete the OIDC client for an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDB(func(c context.Context, d *sql.DB, _ *config.Config) error {
				if err := oidc.RevokeClient(c, d, args[0]); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "revoked client for %q\n", args[0])
				return nil
			})
		},
	}
}
