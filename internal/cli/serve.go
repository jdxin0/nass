package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/jdxin0/nass/internal/auth"
	"github.com/jdxin0/nass/internal/auth/oidc"
	"github.com/jdxin0/nass/internal/config"
	"github.com/jdxin0/nass/internal/db"
	"github.com/jdxin0/nass/internal/orchestrator"
	"github.com/jdxin0/nass/internal/portal"
	"github.com/jdxin0/nass/internal/proxy"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	var (
		listen          string
		listenHTTP      string
		insecure        bool
		insecureNoHTTPS bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the long-lived process: TLS proxy + OIDC server + portal",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			d, err := db.Open(cfg.DB.Path)
			if err != nil {
				return err
			}
			defer d.Close()

			devMode := insecure || insecureNoHTTPS

			signingKey, err := oidc.LoadSigningKey(cfg.OIDC.KeyFile)
			if err != nil {
				return err
			}
			cryptoKey, err := oidc.LoadCryptoKey(cfg.OIDC.CryptoKeyFile)
			if err != nil {
				return err
			}

			users := auth.NewStore(d)

			// Portal: sessions cookie scoped to base_host so all subdomains see it.
			sessions := portal.NewSessionStore(d, users, cfg.Server.BaseHost)
			sessions.Insecure = devMode

			orch := orchestrator.New(cfg.Orchestrator.ComposeRoot, cfg.Orchestrator.DockerCompose)

			portalSrv, err := portal.New(d, users, sessions, orch,
				cfg.Server.BaseHost, cfg.Portal.Title, !devMode)
			if err != nil {
				return err
			}
			portalSrv.AppDataRoot = cfg.Orchestrator.DataRoot
			portalSrv.OIDCIssuer = cfg.OIDC.Issuer

			authSrv, err := oidc.New(d, users, oidc.Options{
				Issuer:        cfg.OIDC.Issuer,
				SigningKey:    signingKey,
				SigningKeyID:  "nass-1",
				CryptoKey:     cryptoKey,
				AllowInsecure: devMode,
			})
			if err != nil {
				return err
			}
			// Hook portal SSO into the OIDC /login.
			authSrv.Login.SetPortal(portalSrv)

			gate := portal.NewGate(sessions, portalHostURL(cfg, devMode))

			// Build the host router and register the fixed (non-app) routes.
			router := proxy.New()
			router.AddRoute(authHost(cfg), authSrv.Handler())
			portalMux := http.NewServeMux()
			portalSrv.Mount(portalMux)
			router.AddRoute(portalHost(cfg), portalMux)

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// App routes are managed dynamically: portal admin can add/remove
			// without restarting.
			manager := proxy.NewRouteManager(d, router, cfg.Server.BaseHost, gate)
			if err := manager.Sync(ctx); err != nil {
				return err
			}
			portalSrv.Reload = manager.Sync

			fmt.Fprintf(cmd.OutOrStdout(), "route: %s → OIDC\n", authHost(cfg))
			fmt.Fprintf(cmd.OutOrStdout(), "route: %s → portal\n", portalHost(cfg))
			for _, h := range manager.ManagedHosts() {
				fmt.Fprintf(cmd.OutOrStdout(), "route: %s → app\n", h)
			}

			// Background sync so apps installed via `nass app install` from
			// another process appear without restart. Cheap: one indexed query
			// every 30s.
			go func() {
				t := time.NewTicker(30 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						if err := manager.Sync(ctx); err != nil {
							fmt.Fprintf(cmd.OutOrStderr(), "route sync: %v\n", err)
						}
					}
				}
			}()

			httpsSrv, err := buildHTTPSServer(cfg, listen, router, insecureNoHTTPS)
			if err != nil {
				return err
			}

			errCh := make(chan error, 2)
			go func() {
				if insecureNoHTTPS {
					fmt.Fprintf(cmd.OutOrStdout(), "serving HTTP on %s (insecure)\n", listen)
					errCh <- httpsSrv.ListenAndServe()
					return
				}
				fmt.Fprintf(cmd.OutOrStdout(), "serving HTTPS on %s\n", listen)
				errCh <- httpsSrv.ListenAndServeTLS("", "")
			}()

			var redirectSrv *http.Server
			if listenHTTP != "" && !insecureNoHTTPS {
				redirectSrv = proxy.HTTPRedirectServer(listenHTTP)
				go func() {
					fmt.Fprintf(cmd.OutOrStdout(), "serving HTTP redirector on %s\n", listenHTTP)
					errCh <- redirectSrv.ListenAndServe()
				}()
			}

			select {
			case <-ctx.Done():
				fmt.Fprintln(cmd.OutOrStdout(), "shutting down...")
				shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = httpsSrv.Shutdown(shutCtx)
				if redirectSrv != nil {
					_ = redirectSrv.Shutdown(shutCtx)
				}
				return nil
			case err := <-errCh:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			}
		},
	}
	cmd.Flags().StringVar(&listen, "listen", ":443", "primary listener address")
	cmd.Flags().StringVar(&listenHTTP, "listen-http", ":80", "HTTP-to-HTTPS redirector address (empty disables)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "allow OIDC over plain HTTP (development)")
	cmd.Flags().BoolVar(&insecureNoHTTPS, "no-https", false, "serve plain HTTP on --listen (development)")
	return cmd
}

func authHost(cfg *config.Config) string {
	if cfg.OIDC.Subdomain == "" {
		return cfg.Server.BaseHost
	}
	return cfg.OIDC.Subdomain + "." + cfg.Server.BaseHost
}

func portalHost(cfg *config.Config) string {
	if cfg.Portal.Subdomain == "" {
		return cfg.Server.BaseHost
	}
	return cfg.Portal.Subdomain + "." + cfg.Server.BaseHost
}

func portalHostURL(cfg *config.Config, devMode bool) string {
	scheme := "https"
	if devMode {
		scheme = "http"
	}
	return scheme + "://" + portalHost(cfg)
}

func buildHTTPSServer(cfg *config.Config, addr string, h http.Handler, insecureNoHTTPS bool) (*http.Server, error) {
	if insecureNoHTTPS {
		return &http.Server{
			Addr:              addr,
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
		}, nil
	}
	if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
		return nil, fmt.Errorf("tls.cert_file and tls.key_file must be set in nass.toml (or pass --no-https for dev)")
	}
	tlsConf, err := proxy.TLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, err
	}
	return proxy.HTTPSServer(addr, h, tlsConf), nil
}
