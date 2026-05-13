package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// LoadSigningKey reads a PEM-encoded PKCS#8 private key. RSA produces RS256
// signatures; ECDSA P-256 produces ES256. RSA is the default for new
// deployments because NextAuth-based apps (e.g. Linkwarden) hard-code RS256
// as the expected id_token_signed_response_alg.
func LoadSigningKey(path string) (crypto.Signer, error) {
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
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("signing key: ECDSA curve %s not supported (use P-256)", k.Curve.Params().Name)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("signing key: unsupported type %T", priv)
	}
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

// signingKey wraps a crypto.Signer so it satisfies op.SigningKey. The
// algorithm is derived from the key type so RSA keys sign as RS256 and
// ECDSA P-256 keys sign as ES256.
type signingKey struct {
	id  string
	key crypto.Signer
	alg jose.SignatureAlgorithm
}

func newSigningKey(id string, key crypto.Signer) (*signingKey, error) {
	alg, err := signatureAlg(key)
	if err != nil {
		return nil, err
	}
	return &signingKey{id: id, key: key, alg: alg}, nil
}

func signatureAlg(key crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
		return jose.ES256, nil
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return s.alg }
func (s *signingKey) Key() any                                    { return s.key }
func (s *signingKey) ID() string                                  { return s.id }

// publicKey wraps the public half so it satisfies op.Key.
type publicKey struct{ s *signingKey }

func (p *publicKey) ID() string                         { return p.s.id }
func (p *publicKey) Algorithm() jose.SignatureAlgorithm { return p.s.alg }
func (p *publicKey) Use() string                        { return "sig" }
func (p *publicKey) Key() any                           { return p.s.key.Public() }

var (
	_ op.SigningKey = (*signingKey)(nil)
	_ op.Key        = (*publicKey)(nil)
)
