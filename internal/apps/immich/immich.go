// Package immich is the nass app module for Immich.
//
// Immich loads its system config from a JSON file mounted into the
// immich-server container (IMMICH_CONFIG_FILE). PreUp renders that file with
// the OIDC client provisioned by the installer; PostUp drives the one-shot
// admin signup the way nass-simple/immich/post-compose-up.sh did.
package immich

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

const (
	adminEmail  = "admin@admin"
	adminName   = "admin"
	configBasename = "immich-config.json"
)

func init() {
	apps.Register(apps.Spec{
		Name:            "immich",
		DisplayName:     "Immich",
		Description:     "Photos and videos",
		Icon:            "📷",
		Subdomain:       "immich",
		BackendPort:     18283,
		PreserveHost:    true,
		NeedsOIDC:       true,
		OIDCGate:        false,
		ComposeTemplate: composeTemplate,
		PreUp:           preUp,
		PostUp:          postUp,
	})
}

func preUp(ctx context.Context, ic *apps.InstallContext) error {
	body, err := renderConfig(ic)
	if err != nil {
		return fmt.Errorf("render immich config: %w", err)
	}
	path := filepath.Join(filepath.Dir(ic.ComposeFile), configBasename)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func postUp(ctx context.Context, ic *apps.InstallContext) error {
	base := fmt.Sprintf("http://127.0.0.1:%d", ic.BackendPort)

	// First boot needs the DB schema to come up before the API answers; the
	// 5-minute budget mirrors the bash post-up's open-ended polling loop.
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := waitForReady(waitCtx, base); err != nil {
		return fmt.Errorf("wait for immich: %w", err)
	}

	initialized, err := isInitialized(ctx, base)
	if err != nil {
		return fmt.Errorf("check init state: %w", err)
	}
	if initialized {
		return nil
	}

	body, err := json.Marshal(map[string]string{
		"email":    adminEmail,
		"password": ic.AdminPassword,
		"name":     adminName,
	})
	if err != nil {
		return err
	}
	if err := postJSON(ctx, base+"/api/auth/admin-sign-up", body); err != nil {
		return fmt.Errorf("admin signup: %w", err)
	}
	return nil
}

// waitForReady polls /api/server/config until the response includes the
// "isInitialized" field — its presence (regardless of true/false) is the
// signal that immich's server + DB are wired up.
func waitForReady(ctx context.Context, base string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		resp, err := client.Get(base + "/api/server/config")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(b), "isInitialized") {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func isInitialized(ctx context.Context, base string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/server/config", nil)
	if err != nil {
		return false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var info struct {
		IsInitialized bool `json:"isInitialized"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return false, err
	}
	return info.IsInitialized, nil
}

func postJSON(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

// renderConfig builds the immich system-config JSON from the install context.
// We encode via structs so the OIDC client_secret can't break JSON quoting if
// it ever contains a backslash or double quote.
func renderConfig(ic *apps.InstallContext) ([]byte, error) {
	cfg := immichConfig{
		OAuth: oauthCfg{
			AutoLaunch:              true,
			AutoRegister:            true,
			ButtonText:              "Sign in with SSO",
			ClientID:                ic.OIDCClientID,
			ClientSecret:            ic.OIDCClientSecret,
			DefaultStorageQuota:     0,
			Enabled:                 true,
			IssuerURL:               ic.OIDCDiscoveryURL(),
			MobileOverrideEnabled:   false,
			MobileRedirectURI:       "",
			ProfileSigningAlgorithm: "none",
			Scope:                   "openid email profile",
			SigningAlgorithm:        "RS256",
			StorageLabelClaim:       "preferred_username",
			StorageQuotaClaim:       "immich_quota",
		},
		PasswordLogin: passwordLoginCfg{Enabled: true},
		Server: serverCfg{
			ExternalDomain:   ic.PublicURL(),
			LoginPageMessage: "",
			PublicUsers:      true,
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

type immichConfig struct {
	OAuth         oauthCfg         `json:"oauth"`
	PasswordLogin passwordLoginCfg `json:"passwordLogin"`
	Server        serverCfg        `json:"server"`
}

type oauthCfg struct {
	AutoLaunch              bool   `json:"autoLaunch"`
	AutoRegister            bool   `json:"autoRegister"`
	ButtonText              string `json:"buttonText"`
	ClientID                string `json:"clientId"`
	ClientSecret            string `json:"clientSecret"`
	DefaultStorageQuota     int    `json:"defaultStorageQuota"`
	Enabled                 bool   `json:"enabled"`
	IssuerURL               string `json:"issuerUrl"`
	MobileOverrideEnabled   bool   `json:"mobileOverrideEnabled"`
	MobileRedirectURI       string `json:"mobileRedirectUri"`
	ProfileSigningAlgorithm string `json:"profileSigningAlgorithm"`
	Scope                   string `json:"scope"`
	SigningAlgorithm        string `json:"signingAlgorithm"`
	StorageLabelClaim       string `json:"storageLabelClaim"`
	StorageQuotaClaim       string `json:"storageQuotaClaim"`
}

type passwordLoginCfg struct {
	Enabled bool `json:"enabled"`
}

type serverCfg struct {
	ExternalDomain   string `json:"externalDomain"`
	LoginPageMessage string `json:"loginPageMessage"`
	PublicUsers      bool   `json:"publicUsers"`
}
