package oidc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// LoadSigningKey reads a PEM-encoded ECDSA P-256 private key (PKCS#8).
// `nass init` writes the key in this format.
func LoadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("signing key: no PEM block found")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key: expected ECDSA, got %T", priv)
	}
	return ec, nil
}

// LoadCryptoKey reads a 32-byte symmetric key used by the OP for state encryption.
func LoadCryptoKey(path string) ([32]byte, error) {
	var k [32]byte
	b, err := os.ReadFile(path)
	if err != nil {
		return k, fmt.Errorf("read crypto key: %w", err)
	}
	if len(b) != 32 {
		return k, fmt.Errorf("crypto key: expected 32 bytes, got %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// signingKey wraps an ECDSA key so it satisfies op.SigningKey.
type signingKey struct {
	id  string
	key *ecdsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.ES256 }
func (s *signingKey) Key() any                                    { return s.key }
func (s *signingKey) ID() string                                  { return s.id }

// publicKey wraps the public half so it satisfies op.Key.
type publicKey struct{ s *signingKey }

func (p *publicKey) ID() string                          { return p.s.id }
func (p *publicKey) Algorithm() jose.SignatureAlgorithm  { return jose.ES256 }
func (p *publicKey) Use() string                         { return "sig" }
func (p *publicKey) Key() any                            { return &p.s.key.PublicKey }

var (
	_ op.SigningKey = (*signingKey)(nil)
	_ op.Key        = (*publicKey)(nil)
)
