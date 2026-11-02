package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/auth"
	authoidc "github.com/jdxin0/nass/internal/auth/oidc"
	"github.com/jdxin0/nass/internal/db"
)

// signedOutPortal is a PortalSession with nobody signed in.
type signedOutPortal struct{}

func (signedOutPortal) CurrentUserID(*http.Request) (int64, error) { return 0, nil }
func (signedOutPortal) LoginURL(next string) string {
	return "https://portal.test/portal/login?next=" + url.QueryEscape(next)
}

// The portal lives on a different host from the IdP, so the `next` it gets
// must be absolute; a relative /login would resolve against the portal host.
func TestLoginSendsAbsoluteNextToPortal(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	users := auth.NewStore(d)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var cryptoKey [32]byte
	rand.Read(cryptoKey[:])

	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()
	srv, err := authoidc.New(d, users, authoidc.Options{
		Issuer: ts.URL, SigningKey: priv, CryptoKey: cryptoKey, AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Login.SetPortal(signedOutPortal{})
	mux.Handle("/", srv.Handler())

	const redirectURI = "http://example.test/callback"
	prov, err := authoidc.Provision(context.Background(), d, "test-app", []string{redirectURI})
	if err != nil {
		t.Fatal(err)
	}

	var portalLogin *url.URL
	hc := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == "portal.test" {
			portalLogin = req.URL
			return http.ErrUseLastResponse
		}
		return nil
	}}
	resp, err := hc.Get(ts.URL + "/authorize?" + url.Values{
		"client_id": {prov.ClientID}, "redirect_uri": {redirectURI},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"s"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if portalLogin == nil {
		t.Fatalf("expected a redirect to the portal login, ended at %s", resp.Request.URL)
	}
	next := portalLogin.Query().Get("next")
	if !strings.HasPrefix(next, ts.URL+"/login?authRequestID=") {
		t.Fatalf("next = %q, want an absolute %s/login?authRequestID=... URL", next, ts.URL)
	}
}
