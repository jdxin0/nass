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
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// authRequest implements op.AuthRequest. It mirrors a row in oidc_auth_requests.
type authRequest struct {
	id            string
	clientID      string
	userID        string // empty until login completes
	redirectURI   string
	state         string
	nonce         string
	scopes        []string
	responseType  oidc.ResponseType
	responseMode  oidc.ResponseMode
	codeChallenge *oidc.CodeChallenge
	authTime      time.Time
	done          bool
}

func (a *authRequest) GetID() string                        { return a.id }
func (a *authRequest) GetACR() string                       { return "" }
func (a *authRequest) GetAMR() []string {
	if a.done {
		return []string{"pwd"}
	}
	return nil
}
func (a *authRequest) GetAudience() []string             { return []string{a.clientID} }
func (a *authRequest) GetAuthTime() time.Time            { return a.authTime }
func (a *authRequest) GetClientID() string               { return a.clientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge { return a.codeChallenge }
func (a *authRequest) GetNonce() string                  { return a.nonce }
func (a *authRequest) GetRedirectURI() string            { return a.redirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return a.responseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.responseMode }
func (a *authRequest) GetScopes() []string               { return a.scopes }
func (a *authRequest) GetState() string                  { return a.state }
func (a *authRequest) GetSubject() string                { return a.userID }
func (a *authRequest) Done() bool                        { return a.done }

var _ op.AuthRequest = (*authRequest)(nil)

const authRequestTTL = 30 * time.Minute

func insertAuthRequest(ctx context.Context, db *sql.DB, src *oidc.AuthRequest, userID string) (*authRequest, error) {
	scopes, _ := json.Marshal([]string(src.Scopes))
	id := uuid.NewString()
	codeChallenge := ""
	codeMethod := ""
	if src.CodeChallenge != "" {
		codeChallenge = src.CodeChallenge
		codeMethod = string(src.CodeChallengeMethod)
	}
	expires := time.Now().Add(authRequestTTL)

	if _, err := db.ExecContext(ctx, `
		INSERT INTO oidc_auth_requests
		    (id, client_id, user_id, redirect_uri, state, nonce, scopes,
		     response_type, response_mode, code_challenge, code_challenge_method, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, src.ClientID, nullableUserID(userID), src.RedirectURI, src.State, src.Nonce, string(scopes),
		string(src.ResponseType), string(src.ResponseMode), codeChallenge, codeMethod, expires,
	); err != nil {
		return nil, err
	}
	a := &authRequest{
		id:           id,
		clientID:     src.ClientID,
		userID:       userID,
		redirectURI:  src.RedirectURI,
		state:        src.State,
		nonce:        src.Nonce,
		scopes:       src.Scopes,
		responseType: src.ResponseType,
		responseMode: src.ResponseMode,
	}
	if codeChallenge != "" {
		method := oidc.CodeChallengeMethodPlain
		if codeMethod == "S256" {
			method = oidc.CodeChallengeMethodS256
		}
		a.codeChallenge = &oidc.CodeChallenge{Challenge: codeChallenge, Method: method}
	}
	return a, nil
}

func loadAuthRequest(ctx context.Context, db *sql.DB, id string) (*authRequest, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, client_id, COALESCE(user_id,0), redirect_uri, COALESCE(state,''),
		       COALESCE(nonce,''), scopes, response_type, response_mode,
		       COALESCE(code_challenge,''), COALESCE(code_challenge_method,''),
		       auth_time, completed
		FROM oidc_auth_requests
		WHERE id = ? AND expires_at > CURRENT_TIMESTAMP`, id)

	var (
		uid                              int64
		scopesJSON                       string
		respType, respMode               string
		codeChallenge, codeChallengeAlg  string
		authTime                         sql.NullTime
		completed                        int
	)
	a := &authRequest{}
	if err := row.Scan(&a.id, &a.clientID, &uid, &a.redirectURI, &a.state,
		&a.nonce, &scopesJSON, &respType, &respMode,
		&codeChallenge, &codeChallengeAlg, &authTime, &completed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("auth request %q not found", id)
		}
		return nil, err
	}
	if uid != 0 {
		a.userID = strconv.FormatInt(uid, 10)
	}
	if err := json.Unmarshal([]byte(scopesJSON), &a.scopes); err != nil {
		return nil, fmt.Errorf("decode scopes: %w", err)
	}
	a.responseType = oidc.ResponseType(respType)
	a.responseMode = oidc.ResponseMode(respMode)
	if codeChallenge != "" {
		method := oidc.CodeChallengeMethodPlain
		if codeChallengeAlg == "S256" {
			method = oidc.CodeChallengeMethodS256
		}
		a.codeChallenge = &oidc.CodeChallenge{Challenge: codeChallenge, Method: method}
	}
	if authTime.Valid {
		a.authTime = authTime.Time
	}
	a.done = completed != 0
	return a, nil
}

func markAuthRequestComplete(ctx context.Context, db *sql.DB, id string, userID int64) error {
	res, err := db.ExecContext(ctx, `
		UPDATE oidc_auth_requests
		SET user_id = ?, auth_time = CURRENT_TIMESTAMP, completed = 1
		WHERE id = ?`, userID, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("auth request %q not found", id)
	}
	return nil
}

func deleteAuthRequest(ctx context.Context, db *sql.DB, id string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM oidc_auth_requests WHERE id = ?`, id)
	return err
}

func nullableUserID(s string) any {
	if s == "" {
		return nil
	}
	return s
}
