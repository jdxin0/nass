package oidc

import (
	"crypto"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/jdxin0/nass/internal/auth"
)

// Options configures the OIDC server bootstrapping.
type Options struct {
	Issuer        string
	SigningKey    crypto.Signer
	SigningKeyID  string
	CryptoKey     [32]byte
	AllowInsecure bool // set true for HTTP testing
}

// Server is the assembled OIDC provider plus login handler.
type Server struct {
	Storage  *Storage
	Provider op.OpenIDProvider
	Login    *Login
}

// New builds the OP, storage, and login handler. Caller mounts the resulting
// http.Handler at the issuer host.
func New(db *sql.DB, users *auth.Store, opts Options) (*Server, error) {
	if opts.Issuer == "" {
		return nil, fmt.Errorf("issuer required")
	}
	if opts.SigningKey == nil {
		return nil, fmt.Errorf("signing key required")
	}
	keyID := opts.SigningKeyID
	if keyID == "" {
		keyID = uuid.NewString()
	}
	sk, err := newSigningKey(keyID, opts.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	storage := NewStorage(db, users, sk)

	cfg := &op.Config{
		CryptoKey:               opts.CryptoKey,
		CryptoKeyId:             "nass-1",
		DefaultLogoutRedirectURI: "/logged-out",
		CodeMethodS256:          true,
		AuthMethodPost:          true,
		GrantTypeRefreshToken:   true,
	}
	var providerOpts []op.Option
	if opts.AllowInsecure {
		providerOpts = append(providerOpts, op.WithAllowInsecure())
	}
	provider, err := op.NewOpenIDProvider(opts.Issuer, cfg, storage, providerOpts...)
	if err != nil {
		return nil, fmt.Errorf("create OP: %w", err)
	}
	login := NewLogin(storage, users,
		op.AuthCallbackURL(provider),
		op.NewIssuerInterceptor(provider.IssuerFromRequest),
	)
	return &Server{Storage: storage, Provider: provider, Login: login}, nil
}

// Handler returns the combined HTTP handler that serves both the OP routes
// (/.well-known/openid-configuration, /authorize, /token, /userinfo, /keys, ...)
// and /login.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Login.Mount(mux)
	mux.HandleFunc("GET /logged-out", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("signed out"))
	})
	mux.Handle("/", s.Provider)
	return mux
}
