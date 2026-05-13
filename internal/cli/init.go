package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/jdxin0/nass/internal/auth"
	"github.com/jdxin0/nass/internal/config"
	"github.com/jdxin0/nass/internal/db"
	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	var (
		baseHost      string
		adminUser     string
		adminEmail    string
		adminPassword string
		certFile      string
		keyFile       string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate nass.toml, signing key, SQLite DB, and the initial admin user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if baseHost == "" {
				return fmt.Errorf("--base-host is required")
			}
			if adminUser == "" || adminPassword == "" {
				return fmt.Errorf("--admin-user and --admin-password are required")
			}
			if _, err := os.Stat(ctx.configPath); err == nil {
				return fmt.Errorf("%s already exists; refusing to overwrite", ctx.configPath)
			}

			cfg := config.Default()
			cfg.Server.BaseHost = baseHost
			cfg.TLS.CertFile = certFile
			cfg.TLS.KeyFile = keyFile

			if err := config.Write(ctx.configPath, cfg); err != nil {
				return err
			}

			cfg, err := config.Load(ctx.configPath)
			if err != nil {
				return err
			}

			if err := generateSigningKey(cfg.OIDC.KeyFile); err != nil {
				return fmt.Errorf("generate signing key: %w", err)
			}
			if err := generateCryptoKey(cfg.OIDC.CryptoKeyFile); err != nil {
				return fmt.Errorf("generate crypto key: %w", err)
			}

			d, err := db.Open(cfg.DB.Path)
			if err != nil {
				return err
			}
			defer d.Close()

			store := auth.NewStore(d)
			u, err := store.Create(context.Background(), adminUser, adminEmail, adminPassword, true)
			if err != nil {
				return fmt.Errorf("create admin: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", ctx.configPath)
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", cfg.OIDC.KeyFile)
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", cfg.OIDC.CryptoKeyFile)
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", cfg.DB.Path)
			fmt.Fprintf(cmd.OutOrStdout(), "created admin user %q (id=%d)\n", u.Username, u.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&baseHost, "base-host", "", "base host (required)")
	cmd.Flags().StringVar(&adminUser, "admin-user", "admin", "admin username")
	cmd.Flags().StringVar(&adminEmail, "admin-email", "", "admin email (required by some apps' OIDC clients, e.g. immich)")
	cmd.Flags().StringVar(&adminPassword, "admin-password", "", "admin password (required)")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "path to TLS fullchain.pem")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "path to TLS privkey.pem")
	return cmd
}

func generateCryptoKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

// generateSigningKey writes a new RSA 2048 PKCS#8 PEM private key. The OIDC
// server signs ID tokens as RS256, which is what NextAuth-based apps like
// Linkwarden hard-code as the expected id_token_signed_response_alg.
func generateSigningKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
