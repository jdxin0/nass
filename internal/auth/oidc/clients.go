package oidc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"
)

// clientImpl is the op.Client implementation built from a row in oidc_clients.
type clientImpl struct {
	id              string
	redirectURIs    []string
	applicationType op.ApplicationType
	authMethod      oidc.AuthMethod
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	devMode         bool
}

func (c *clientImpl) GetID() string                        { return c.id }
func (c *clientImpl) RedirectURIs() []string               { return c.redirectURIs }
func (c *clientImpl) PostLogoutRedirectURIs() []string     { return nil }
func (c *clientImpl) ApplicationType() op.ApplicationType  { return c.applicationType }
func (c *clientImpl) AuthMethod() oidc.AuthMethod          { return c.authMethod }
func (c *clientImpl) ResponseTypes() []oidc.ResponseType   { return c.responseTypes }
func (c *clientImpl) GrantTypes() []oidc.GrantType         { return c.grantTypes }
func (c *clientImpl) LoginURL(id string) string            { return "/login?authRequestID=" + id }
func (c *clientImpl) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeBearer }
func (c *clientImpl) IDTokenLifetime() time.Duration       { return time.Hour }
func (c *clientImpl) DevMode() bool                        { return c.devMode }
func (c *clientImpl) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *clientImpl) ClockSkew() time.Duration             { return 0 }
func (c *clientImpl) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *clientImpl) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *clientImpl) IsScopeAllowed(string) bool { return false }

var _ op.Client = (*clientImpl)(nil)

// ProvisionResult is returned by Provision. The plaintext secret is shown once
// (only the bcrypt hash is persisted).
type ProvisionResult struct {
	ClientID     string
	ClientSecret string
	AppName      string
}

// Provision creates a new OIDC client tied to an app and returns the plaintext secret.
func Provision(ctx context.Context, db *sql.DB, appName string, redirectURIs []string) (*ProvisionResult, error) {
	if appName == "" {
		return nil, errors.New("app name required")
	}
	if len(redirectURIs) == 0 {
		return nil, errors.New("at least one redirect_uri required")
	}
	clientID, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	clientSecret, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	uris, _ := json.Marshal(redirectURIs)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO apps(name, enabled, enabled_at) VALUES (?, 1, CURRENT_TIMESTAMP)
		 ON CONFLICT(name) DO UPDATE SET enabled = 1, enabled_at = CURRENT_TIMESTAMP`, appName); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO oidc_clients(client_id, app_name, client_secret_hash, redirect_uris)
		 VALUES (?, ?, ?, ?)`, clientID, appName, string(hash), string(uris)); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("app %q already has a client; revoke and re-provision", appName)
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ProvisionResult{ClientID: clientID, ClientSecret: clientSecret, AppName: appName}, nil
}

// RevokeClient removes the OIDC client (and any tokens) for an app.
func RevokeClient(ctx context.Context, db *sql.DB, appName string) error {
	found, err := deleteClient(ctx, db, appName)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no client for app %q", appName)
	}
	return nil
}

// CleanupClient removes an app's OIDC client and issued tokens, if present.
func CleanupClient(ctx context.Context, db *sql.DB, appName string) error {
	_, err := deleteClient(ctx, db, appName)
	return err
}

func deleteClient(ctx context.Context, db *sql.DB, appName string) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var clientID string
	row := tx.QueryRowContext(ctx, `SELECT client_id FROM oidc_clients WHERE app_name = ?`, appName)
	if err := row.Scan(&clientID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_access_tokens WHERE client_id = ?`, clientID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_refresh_tokens WHERE client_id = ?`, clientID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_clients WHERE client_id = ?`, clientID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// LookupClient fetches a client row and returns an op.Client implementation.
func LookupClient(ctx context.Context, db *sql.DB, clientID string) (op.Client, error) {
	var (
		urisJSON, scopesJSON, grantsJSON, respJSON string
		appType, authMethod                        string
		dev                                        int
	)
	row := db.QueryRowContext(ctx, `
		SELECT redirect_uris, scopes, application_type, auth_method, grant_types, response_types, dev_mode
		FROM oidc_clients WHERE client_id = ?`, clientID)
	if err := row.Scan(&urisJSON, &scopesJSON, &appType, &authMethod, &grantsJSON, &respJSON, &dev); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("client %q not found", clientID)
		}
		return nil, err
	}
	_ = scopesJSON // scopes are used during issuance, not in op.Client interface
	var uris, grants, resp []string
	if err := json.Unmarshal([]byte(urisJSON), &uris); err != nil {
		return nil, fmt.Errorf("decode redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(grantsJSON), &grants); err != nil {
		return nil, fmt.Errorf("decode grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(respJSON), &resp); err != nil {
		return nil, fmt.Errorf("decode response_types: %w", err)
	}
	c := &clientImpl{
		id:              clientID,
		redirectURIs:    uris,
		applicationType: parseAppType(appType),
		authMethod:      oidc.AuthMethod(authMethod),
		devMode:         dev != 0,
	}
	for _, g := range grants {
		c.grantTypes = append(c.grantTypes, oidc.GrantType(g))
	}
	for _, r := range resp {
		c.responseTypes = append(c.responseTypes, oidc.ResponseType(r))
	}
	return c, nil
}

// VerifyClientSecret bcrypt-checks a client_secret.
func VerifyClientSecret(ctx context.Context, db *sql.DB, clientID, secret string) error {
	var hash string
	row := db.QueryRowContext(ctx, `SELECT client_secret_hash FROM oidc_clients WHERE client_id = ?`, clientID)
	if err := row.Scan(&hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("client not found")
		}
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)); err != nil {
		return fmt.Errorf("invalid client secret")
	}
	return nil
}

func parseAppType(s string) op.ApplicationType {
	switch s {
	case "native":
		return op.ApplicationTypeNative
	case "user_agent":
		return op.ApplicationTypeUserAgent
	default:
		return op.ApplicationTypeWeb
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
