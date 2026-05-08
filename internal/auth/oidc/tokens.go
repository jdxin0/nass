package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type accessToken struct {
	ID             string
	ClientID       string
	UserID         string
	RefreshTokenID string
	Audience       []string
	Scopes         []string
	ExpiresAt      time.Time
}

func (s *Storage) insertAccessToken(ctx context.Context, clientID, refreshID, subject string, audience, scopes []string) (*accessToken, error) {
	uid, err := strconv.ParseInt(subject, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid subject %q", subject)
	}
	id := uuid.NewString()
	expires := time.Now().Add(accessTokenTTL)
	audJSON, _ := json.Marshal(audience)
	scopesJSON, _ := json.Marshal(scopes)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_access_tokens(id, client_id, user_id, refresh_token_id, audience, scopes, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, clientID, uid, nullableString(refreshID), string(audJSON), string(scopesJSON), expires); err != nil {
		return nil, err
	}
	return &accessToken{
		ID: id, ClientID: clientID, UserID: subject, RefreshTokenID: refreshID,
		Audience: audience, Scopes: scopes, ExpiresAt: expires,
	}, nil
}

func loadAccessToken(ctx context.Context, db *sql.DB, id string) (*accessToken, error) {
	var (
		uid                       int64
		audJSON, scopesJSON       string
		refreshID                 sql.NullString
		expires                   time.Time
		clientID                  string
	)
	row := db.QueryRowContext(ctx, `
		SELECT client_id, user_id, refresh_token_id, audience, scopes, expires_at
		FROM oidc_access_tokens WHERE id = ?`, id)
	if err := row.Scan(&clientID, &uid, &refreshID, &audJSON, &scopesJSON, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("token is invalid or has expired")
		}
		return nil, err
	}
	tok := &accessToken{
		ID:        id,
		ClientID:  clientID,
		UserID:    strconv.FormatInt(uid, 10),
		ExpiresAt: expires,
	}
	if refreshID.Valid {
		tok.RefreshTokenID = refreshID.String
	}
	if err := json.Unmarshal([]byte(audJSON), &tok.Audience); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopesJSON), &tok.Scopes); err != nil {
		return nil, err
	}
	return tok, nil
}

// refreshTokenRequest implements op.RefreshTokenRequest.
type refreshTokenRequest struct {
	id       string
	clientID string
	userID   string
	scopes   []string
	audience []string
	authTime time.Time
	amr      []string
}

func (r *refreshTokenRequest) GetAMR() []string                   { return r.amr }
func (r *refreshTokenRequest) GetAudience() []string              { return r.audience }
func (r *refreshTokenRequest) GetAuthTime() time.Time             { return r.authTime }
func (r *refreshTokenRequest) GetClientID() string                { return r.clientID }
func (r *refreshTokenRequest) GetScopes() []string                { return r.scopes }
func (r *refreshTokenRequest) GetSubject() string                 { return r.userID }
func (r *refreshTokenRequest) SetCurrentScopes(scopes []string)   { r.scopes = scopes }

var _ op.RefreshTokenRequest = (*refreshTokenRequest)(nil)

func (s *Storage) insertRefreshToken(ctx context.Context, id, subject, clientID string, scopes, audience []string, authTime time.Time, amr []string) error {
	uid, err := strconv.ParseInt(subject, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid subject %q", subject)
	}
	if authTime.IsZero() {
		authTime = time.Now()
	}
	scopesJSON, _ := json.Marshal(scopes)
	audJSON, _ := json.Marshal(audience)
	expires := time.Now().Add(refreshTokenTTL)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oidc_refresh_tokens(id, user_id, client_id, scopes, audience, auth_time, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, uid, clientID, string(scopesJSON), string(audJSON), authTime, expires)
	_ = amr // amr is not persisted in phase 2; OP will recompute on subsequent requests
	return err
}

func loadRefreshToken(ctx context.Context, db *sql.DB, id string) (*refreshTokenRequest, error) {
	var (
		uid                  int64
		scopesJSON, audJSON  string
		authTime             time.Time
		expires              time.Time
		clientID             string
	)
	row := db.QueryRowContext(ctx, `
		SELECT user_id, client_id, scopes, audience, auth_time, expires_at
		FROM oidc_refresh_tokens WHERE id = ?`, id)
	if err := row.Scan(&uid, &clientID, &scopesJSON, &audJSON, &authTime, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, op.ErrInvalidRefreshToken
		}
		return nil, err
	}
	if expires.Before(time.Now()) {
		return nil, op.ErrInvalidRefreshToken
	}
	r := &refreshTokenRequest{
		id:       id,
		clientID: clientID,
		userID:   strconv.FormatInt(uid, 10),
		authTime: authTime,
		amr:      []string{"pwd"},
	}
	if err := json.Unmarshal([]byte(scopesJSON), &r.scopes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(audJSON), &r.audience); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Storage) rotateRefreshToken(ctx context.Context, currentID, newID, accessTokenID string, scopes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var (
		uid       int64
		clientID  string
		audJSON   string
		authTime  time.Time
		expires   time.Time
	)
	row := tx.QueryRowContext(ctx, `
		SELECT user_id, client_id, audience, auth_time, expires_at
		FROM oidc_refresh_tokens WHERE id = ?`, currentID)
	if err := row.Scan(&uid, &clientID, &audJSON, &authTime, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return op.ErrInvalidRefreshToken
		}
		return err
	}
	if expires.Before(time.Now()) {
		return fmt.Errorf("refresh token expired")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_refresh_tokens WHERE id = ?`, currentID); err != nil {
		return err
	}
	scopesJSON, _ := json.Marshal(scopes)
	newExpires := time.Now().Add(refreshTokenTTL)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO oidc_refresh_tokens(id, user_id, client_id, scopes, audience, auth_time, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		newID, uid, clientID, string(scopesJSON), audJSON, authTime, newExpires); err != nil {
		return err
	}
	// Drop the old access token associated with the rotated refresh.
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_access_tokens WHERE refresh_token_id = ? AND id != ?`, currentID, accessTokenID); err != nil {
		return err
	}
	return tx.Commit()
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
