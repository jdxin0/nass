package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/jdxin0/nass/internal/auth"
)

const (
	accessTokenTTL  = 5 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
)

// Storage implements op.Storage backed by SQLite.
type Storage struct {
	db      *sql.DB
	users   *auth.Store
	signing *signingKey
}

func NewStorage(db *sql.DB, users *auth.Store, sk *signingKey) *Storage {
	return &Storage{db: db, users: users, signing: sk}
}

var _ op.Storage = (*Storage)(nil)

// --- AuthStorage ---

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if len(req.Prompt) == 1 && req.Prompt[0] == "none" {
		return nil, oidc.ErrLoginRequired()
	}
	return insertAuthRequest(ctx, s.db, req, userID)
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return loadAuthRequest(ctx, s.db, id)
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	var requestID string
	row := s.db.QueryRowContext(ctx, `
		SELECT request_id FROM oidc_auth_codes
		WHERE code = ? AND expires_at > CURRENT_TIMESTAMP`, code)
	if err := row.Scan(&requestID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("code invalid or expired")
		}
		return nil, err
	}
	return loadAuthRequest(ctx, s.db, requestID)
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_auth_codes(code, request_id, expires_at)
		VALUES (?, ?, ?)`, code, id, time.Now().Add(5*time.Minute))
	return err
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return deleteAuthRequest(ctx, s.db, id)
}

func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	clientID := clientIDFromRequest(req)
	tok, err := s.insertAccessToken(ctx, clientID, "", req.GetSubject(), req.GetAudience(), req.GetScopes())
	if err != nil {
		return "", time.Time{}, err
	}
	return tok.ID, tok.ExpiresAt, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	clientID, authTime, amr := infoFromRequest(req)

	if currentRefreshToken == "" {
		// Code flow with offline_access: issue a fresh pair.
		refreshID := uuid.NewString()
		access, err := s.insertAccessToken(ctx, clientID, refreshID, req.GetSubject(), req.GetAudience(), req.GetScopes())
		if err != nil {
			return "", "", time.Time{}, err
		}
		if err := s.insertRefreshToken(ctx, refreshID, req.GetSubject(), clientID, req.GetScopes(), req.GetAudience(), authTime, amr); err != nil {
			return "", "", time.Time{}, err
		}
		return access.ID, refreshID, access.ExpiresAt, nil
	}

	// Refresh-token grant: rotate.
	newRefreshID := uuid.NewString()
	access, err := s.insertAccessToken(ctx, clientID, newRefreshID, req.GetSubject(), req.GetAudience(), req.GetScopes())
	if err != nil {
		return "", "", time.Time{}, err
	}
	if err := s.rotateRefreshToken(ctx, currentRefreshToken, newRefreshID, access.ID, req.GetScopes()); err != nil {
		return "", "", time.Time{}, err
	}
	return access.ID, newRefreshID, access.ExpiresAt, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	return loadRefreshToken(ctx, s.db, refreshToken)
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	uid, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM oidc_access_tokens WHERE user_id = ? AND client_id = ?`, uid, clientID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM oidc_refresh_tokens WHERE user_id = ? AND client_id = ?`, uid, clientID); err != nil {
		return err
	}
	return nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrID, userID, clientID string) *oidc.Error {
	// First try treating as access token id.
	var accessClient string
	err := s.db.QueryRowContext(ctx, `SELECT client_id FROM oidc_access_tokens WHERE id = ?`, tokenOrID).Scan(&accessClient)
	if err == nil {
		if accessClient != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
		}
		_, _ = s.db.ExecContext(ctx, `DELETE FROM oidc_access_tokens WHERE id = ?`, tokenOrID)
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return oidc.ErrServerError().WithDescription("%s", err.Error())
	}

	// Try as refresh token.
	var refreshClient string
	err = s.db.QueryRowContext(ctx, `SELECT client_id FROM oidc_refresh_tokens WHERE id = ?`, tokenOrID).Scan(&refreshClient)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // unknown token: silently succeed per RFC 7009
	}
	if err != nil {
		return oidc.ErrServerError().WithDescription("%s", err.Error())
	}
	if refreshClient != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oidc_refresh_tokens WHERE id = ?`, tokenOrID); err != nil {
		return oidc.ErrServerError().WithDescription("%s", err.Error())
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oidc_access_tokens WHERE refresh_token_id = ?`, tokenOrID); err != nil {
		return oidc.ErrServerError().WithDescription("%s", err.Error())
	}
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	var (
		uid          int64
		storedClient string
	)
	row := s.db.QueryRowContext(ctx, `SELECT user_id, client_id FROM oidc_refresh_tokens WHERE id = ?`, token)
	if err := row.Scan(&uid, &storedClient); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", op.ErrInvalidRefreshToken
		}
		return "", "", err
	}
	if storedClient != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return strconv.FormatInt(uid, 10), token, nil
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return s.signing, nil
}

func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.ES256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return []op.Key{&publicKey{s: s.signing}}, nil
}

// --- OPStorage ---

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	return LookupClient(ctx, s.db, clientID)
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return VerifyClientSecret(ctx, s.db, clientID, clientSecret)
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil
}

func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	return s.fillUserinfo(ctx, userinfo, request.GetSubject(), scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	tok, err := loadAccessToken(ctx, s.db, tokenID)
	if err != nil {
		return err
	}
	if tok.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("token is expired")
	}
	return s.fillUserinfo(ctx, userinfo, tok.UserID, tok.Scopes)
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, intro *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	tok, err := loadAccessToken(ctx, s.db, tokenID)
	if err != nil {
		return err
	}
	intro.Expiration = oidc.FromTime(tok.ExpiresAt)
	if tok.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("token is expired")
	}
	for _, aud := range tok.Audience {
		if aud == clientID {
			ui := new(oidc.UserInfo)
			if err := s.fillUserinfo(ctx, ui, tok.UserID, tok.Scopes); err != nil {
				return err
			}
			intro.SetUserInfo(ui)
			intro.Scope = tok.Scopes
			intro.ClientID = tok.ClientID
			return nil
		}
	}
	return fmt.Errorf("token is not valid for this client")
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("private_key_jwt not supported")
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if sc == oidc.ScopeOpenID {
			out = append(out, sc)
		}
	}
	return out, nil
}

func (s *Storage) Health(ctx context.Context) error { return s.db.PingContext(ctx) }

// --- helpers ---

func (s *Storage) fillUserinfo(ctx context.Context, info *oidc.UserInfo, subject string, scopes []string) error {
	uid, err := strconv.ParseInt(subject, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid subject %q", subject)
	}
	u, err := s.users.Get(ctx, uid)
	if err != nil {
		return err
	}
	for _, sc := range scopes {
		switch sc {
		case oidc.ScopeOpenID:
			info.Subject = subject
		case oidc.ScopeEmail:
			info.Email = u.Email
		case oidc.ScopeProfile:
			info.PreferredUsername = u.Username
			info.Name = u.Username
		}
	}
	if info.Subject == "" {
		info.Subject = subject
	}
	return nil
}

func clientIDFromRequest(req op.TokenRequest) string {
	if a, ok := req.(*authRequest); ok {
		return a.clientID
	}
	if r, ok := req.(*refreshTokenRequest); ok {
		return r.clientID
	}
	return ""
}

func infoFromRequest(req op.TokenRequest) (clientID string, authTime time.Time, amr []string) {
	if a, ok := req.(*authRequest); ok {
		return a.clientID, a.authTime, a.GetAMR()
	}
	if r, ok := req.(*refreshTokenRequest); ok {
		return r.clientID, r.authTime, r.amr
	}
	return "", time.Time{}, nil
}

