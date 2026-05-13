package calibreweb

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
	_ "modernc.org/sqlite"
)

func TestRedirectURIsUsesGenericOIDCCallback(t *testing.T) {
	ic := &apps.InstallContext{
		Subdomain:    "library",
		BaseHost:     "nass.local",
		PublicScheme: "https",
		PublicPort:   ":8443",
	}

	got := redirectURIs(ic)
	want := "https://library.nass.local:8443/login/generic/authorized"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("redirect URIs: got %v want [%s]", got, want)
	}
}

func TestSeedOIDCConfigEnablesGenericProvider(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "app.db")
	d, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer d.Close()

	if _, err := d.Exec(`
		CREATE TABLE settings (
			id INTEGER PRIMARY KEY,
			config_login_type INTEGER DEFAULT 0,
			config_oauth_redirect_host STRING DEFAULT ''
		);
		INSERT INTO settings (id, config_login_type, config_oauth_redirect_host) VALUES (1, 0, '');
		CREATE TABLE oauthProvider (
			id INTEGER PRIMARY KEY,
			provider_name STRING,
			oauth_client_id STRING,
			oauth_client_secret STRING,
			oauth_base_url STRING,
			oauth_authorize_url STRING,
			oauth_token_url STRING,
			oauth_userinfo_url STRING,
			oauth_admin_group STRING,
			metadata_url STRING,
			scope STRING,
			username_mapper STRING,
			email_mapper STRING,
			login_button STRING,
			active BOOLEAN
		);
		INSERT INTO oauthProvider (id, provider_name, active) VALUES (3, 'generic', 0);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	ic := &apps.InstallContext{
		Subdomain:        "calibre",
		BaseHost:         "nass.local",
		PublicScheme:     "https",
		OIDCClientID:     "cid",
		OIDCClientSecret: "sec",
		OIDCIssuer:       "https://auth.nass.local",
	}
	if err := seedOIDCConfig(dbPath, ic); err != nil {
		t.Fatalf("seed OIDC config: %v", err)
	}

	var loginType int
	var redirectHost string
	if err := d.QueryRow(`SELECT config_login_type, config_oauth_redirect_host FROM settings WHERE id = 1`).
		Scan(&loginType, &redirectHost); err != nil {
		t.Fatalf("query settings: %v", err)
	}
	if loginType != cwaLoginOAuth {
		t.Fatalf("config_login_type: got %d want %d", loginType, cwaLoginOAuth)
	}
	if redirectHost != "https://calibre.nass.local" {
		t.Fatalf("config_oauth_redirect_host: got %q", redirectHost)
	}

	var active bool
	var clientID, clientSecret, metadataURL, scope, username, email, button, adminGroup string
	if err := d.QueryRow(`
		SELECT active, oauth_client_id, oauth_client_secret, metadata_url, scope,
		       username_mapper, email_mapper, login_button, oauth_admin_group
		FROM oauthProvider WHERE provider_name = 'generic'
	`).Scan(&active, &clientID, &clientSecret, &metadataURL, &scope, &username, &email, &button, &adminGroup); err != nil {
		t.Fatalf("query provider: %v", err)
	}
	if !active {
		t.Fatalf("generic provider should be active")
	}
	if clientID != "cid" || clientSecret != "sec" {
		t.Fatalf("client credentials: got %q/%q", clientID, clientSecret)
	}
	if metadataURL != "https://auth.nass.local/.well-known/openid-configuration" {
		t.Fatalf("metadata_url: got %q", metadataURL)
	}
	if scope != "openid profile email groups" {
		t.Fatalf("scope: got %q", scope)
	}
	if username != "preferred_username" || email != "email" {
		t.Fatalf("mappers: got %q/%q", username, email)
	}
	if button != "nass" || adminGroup != "admin" {
		t.Fatalf("button/admin group: got %q/%q", button, adminGroup)
	}
}
