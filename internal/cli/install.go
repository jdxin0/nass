package cli

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"text/tabwriter"

	"github.com/jdxin0/nass/internal/apps"
	"github.com/jdxin0/nass/internal/config"
	"github.com/jdxin0/nass/internal/orchestrator"

	// Side-effect imports register each app's Spec in apps.reg.
	_ "github.com/jdxin0/nass/internal/apps/immich"
	_ "github.com/jdxin0/nass/internal/apps/jellyfin"
	_ "github.com/jdxin0/nass/internal/apps/nextcloud"
	_ "github.com/jdxin0/nass/internal/apps/qbittorrent"
	"github.com/spf13/cobra"
)

func appInstallCmd() *cobra.Command {
	var (
		subdomain   string
		dataRoot    string
		composeFile string
		adminPW     string
		publicPort  string
		dryRun      bool
	)
	cmd := &cobra.Command{
		Use:   "install <name>",
		Short: "Install an app from the registry (provisions OIDC, renders compose, runs docker compose up)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			spec, ok := apps.Get(name)
			if !ok {
				return fmt.Errorf("unknown app %q (try `nass app available`)", name)
			}
			return withDB(func(c context.Context, d *sql.DB, cfg *config.Config) error {
				ic, err := buildInstallContext(d, cfg, &spec, subdomain, dataRoot, composeFile, adminPW, publicPort)
				if err != nil {
					return err
				}
				if dryRun {
					fmt.Fprintf(cmd.OutOrStdout(), "would install %s\n", spec.Name)
					fmt.Fprintf(cmd.OutOrStdout(), "  subdomain:    %s\n", ic.Subdomain)
					fmt.Fprintf(cmd.OutOrStdout(), "  public URL:   %s\n", ic.PublicURL())
					fmt.Fprintf(cmd.OutOrStdout(), "  backend port: %d\n", ic.BackendPort)
					fmt.Fprintf(cmd.OutOrStdout(), "  data root:    %s\n", ic.DataRoot)
					fmt.Fprintf(cmd.OutOrStdout(), "  compose file: %s\n", ic.ComposeFile)
					fmt.Fprintf(cmd.OutOrStdout(), "  needs OIDC:   %t\n", spec.NeedsOIDC)
					return nil
				}
				res, err := apps.Install(c, ic)
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "FIELD\tVALUE")
				fmt.Fprintf(w, "app\t%s\n", res.AppName)
				fmt.Fprintf(w, "compose_file\t%s\n", res.ComposeFile)
				fmt.Fprintf(w, "admin_password\t%s\n", res.AdminPassword)
				if res.OIDCClientID != "" {
					fmt.Fprintf(w, "oidc_client_id\t%s\n", res.OIDCClientID)
					fmt.Fprintf(w, "oidc_client_secret\t%s\n", res.OIDCClientSecret)
				}
				w.Flush()
				fmt.Fprintln(cmd.OutOrStderr(), "(secrets shown once; only their hashes are stored)")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&subdomain, "subdomain", "", "override the default subdomain")
	cmd.Flags().StringVar(&dataRoot, "data-root", "", "override the data directory (default: <orchestrator.data_root>/<name>)")
	cmd.Flags().StringVar(&composeFile, "compose-file", "", "override the compose file path (default: <orchestrator.compose_root>/<name>/docker-compose.yaml)")
	cmd.Flags().StringVar(&adminPW, "admin-password", "", "set the per-app admin password (default: random)")
	cmd.Flags().StringVar(&publicPort, "public-port", "", "public port suffix in URLs (e.g. \":8443\"); empty = scheme default")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "resolve everything but don't write files or run docker")
	return cmd
}

func appUninstallCmd() *cobra.Command {
	var (
		yes      bool
		keepData bool
		force    bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall <name>",
		Short: "Stop an app, remove its containers/volumes, delete its data folder and DB row",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			return withDB(func(c context.Context, d *sql.DB, cfg *config.Config) error {
				composeFile, dataRoot, found, err := apps.LoadAppPaths(c, d, name)
				if err != nil {
					return err
				}
				if !found {
					return fmt.Errorf("app %q is not installed", name)
				}
				// Fall back to the install-time conventions when the saved
				// settings predate the DataRoot field.
				if dataRoot == "" && cfg.Orchestrator.DataRoot != "" {
					dataRoot = filepath.Join(cfg.Orchestrator.DataRoot, name)
				}
				if composeFile == "" && cfg.Orchestrator.ComposeRoot != "" {
					composeFile = filepath.Join(cfg.Orchestrator.ComposeRoot, name, "docker-compose.yaml")
				}

				if !yes {
					fmt.Fprintf(cmd.OutOrStderr(),
						"refusing to uninstall %q without --yes\n  compose: %s\n  data:    %s\n",
						name, composeFile, dataRoot)
					return fmt.Errorf("aborted: pass --yes to confirm")
				}

				uc := &apps.UninstallContext{
					Name:         name,
					ComposeFile:  composeFile,
					DataRoot:     dataRoot,
					KeepData:     keepData,
					Force:        force,
					DB:           d,
					Orchestrator: orchestrator.New(cfg.Orchestrator.ComposeRoot, cfg.Orchestrator.DockerCompose),
				}
				if err := apps.Uninstall(c, uc); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "uninstalled %q\n", name)
				if keepData {
					fmt.Fprintf(cmd.OutOrStdout(), "(data folder preserved at %s)\n", dataRoot)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm destructive uninstall (required)")
	cmd.Flags().BoolVar(&keepData, "keep-data", false, "leave the data folder on disk")
	cmd.Flags().BoolVar(&force, "force", false, "ignore docker compose errors during teardown")
	return cmd
}

func appAvailableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "available",
		Short: "List apps registered in the binary that can be installed",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSUBDOMAIN\tPORT\tOIDC\tDESCRIPTION")
			for _, s := range apps.All() {
				fmt.Fprintf(w, "%s\t%s\t%d\t%t\t%s\n",
					s.Name, s.Subdomain, s.BackendPort, s.NeedsOIDC, s.Description)
			}
			return w.Flush()
		},
	}
}

func buildInstallContext(d *sql.DB, cfg *config.Config, spec *apps.Spec,
	subdomainOverride, dataRootOverride, composeFileOverride, adminPW, publicPort string) (*apps.InstallContext, error) {

	subdomain := subdomainOverride
	if subdomain == "" {
		subdomain = spec.Subdomain
	}
	if cfg.Server.BaseHost == "" {
		return nil, fmt.Errorf("server.base_host is empty in nass.toml")
	}
	if cfg.Orchestrator.ComposeRoot == "" {
		return nil, fmt.Errorf("orchestrator.compose_root is empty in nass.toml")
	}
	if cfg.Orchestrator.DataRoot == "" {
		return nil, fmt.Errorf("orchestrator.data_root is empty in nass.toml")
	}
	dataRoot := dataRootOverride
	if dataRoot == "" {
		dataRoot = filepath.Join(cfg.Orchestrator.DataRoot, spec.Name)
	}
	composeFile := composeFileOverride
	if composeFile == "" {
		composeFile = filepath.Join(cfg.Orchestrator.ComposeRoot, spec.Name, "docker-compose.yaml")
	}
	if cfg.OIDC.Issuer == "" {
		return nil, fmt.Errorf("oidc.issuer is unset (set base_host so the issuer can be derived)")
	}

	return &apps.InstallContext{
		Spec:          spec,
		Name:          spec.Name,
		Subdomain:     subdomain,
		BaseHost:      cfg.Server.BaseHost,
		PublicScheme:  "https",
		PublicPort:    publicPort,
		BackendPort:   spec.BackendPort,
		DataRoot:      dataRoot,
		ComposeFile:   composeFile,
		AdminPassword: adminPW,
		OIDCIssuer:    cfg.OIDC.Issuer,
		DB:            d,
		Orchestrator:  orchestrator.New(cfg.Orchestrator.ComposeRoot, cfg.Orchestrator.DockerCompose),
	}, nil
}
