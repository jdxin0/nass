package oidc_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/auth"
	authoidc "github.com/jdxin0/nass/internal/auth/oidc"
	"github.com/jdxin0/nass/internal/db"
)

func TestAuthCodeFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	users := auth.NewStore(d)
	ctx := context.Background()
	if _, err := users.Create(ctx, "alice", "alice@example.com", "wonderlandpw", true); err != nil {
		t.Fatalf("create user: %v", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	var cryptoKey [32]byte
	if _, err := rand.Read(cryptoKey[:]); err != nil {
		t.Fatalf("gen crypto key: %v", err)
	}

	// Use a placeholder issuer for now; we'll patch after the test server starts.
	// The OP needs to know its issuer at construction time, so we build it with
	// a dummy issuer, then point the relying client at the test server.
	// Easier: spin up the server, learn its URL, then build the OP.
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, err := authoidc.New(d, users, authoidc.Options{
		Issuer:        ts.URL,
		SigningKey:    priv,
		SigningKeyID:  "test-1",
		CryptoKey:     cryptoKey,
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("build OIDC server: %v", err)
	}
	mux.Handle("/", srv.Handler())

	const redirectURI = "http://example.test/callback"
	prov, err := authoidc.Provision(ctx, d, "test-app", []string{redirectURI})
	if err != nil {
		t.Fatalf("provision client: %v", err)
	}

	// 1. Discovery sanity check.
	disc := getJSON(t, ts.URL+"/.well-known/openid-configuration")
	if disc["issuer"] != ts.URL {
		t.Fatalf("issuer mismatch: got %v want %s", disc["issuer"], ts.URL)
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		if disc[key] == "" {
			t.Fatalf("discovery missing %s", key)
		}
	}

	// HTTP client that does NOT auto-follow redirects to external hosts (we want to capture
	// the redirect to redirectURI). It does follow same-origin redirects.
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), "http://example.test") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// 2. Hit /authorize -> redirected to /login?authRequestID=X.
	state := "test-state"
	authURL := ts.URL + "/authorize?" + url.Values{
		"client_id":     {prov.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile email groups offline_access"},
		"state":         {state},
		"nonce":         {"n-0S6_WzA2Mj"},
	}.Encode()

	resp, err := hc.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.Request.URL.Path != "/login" {
		t.Fatalf("expected to land on /login, got %s", resp.Request.URL)
	}
	authReqID := resp.Request.URL.Query().Get("authRequestID")
	if authReqID == "" {
		t.Fatalf("login URL missing authRequestID")
	}

	// 3. POST /login with credentials -> 302 to /authorize/callback -> 302 to redirect_uri?code=...
	form := url.Values{
		"id":       {authReqID},
		"username": {"alice"},
		"password": {"wonderlandpw"},
	}
	resp, err = hc.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(resp.Request.URL.String(), redirectURI) && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected final hop to redirect_uri, got status=%d url=%s", resp.StatusCode, resp.Request.URL)
	}
	finalURL := resp.Request.URL
	if resp.StatusCode == http.StatusFound {
		// Our client paused at the external redirect; pull Location header.
		loc := resp.Header.Get("Location")
		if loc == "" {
			t.Fatalf("no Location header on final redirect")
		}
		if u, err := url.Parse(loc); err == nil {
			finalURL = u
		} else {
			t.Fatalf("parse final Location: %v", err)
		}
	}
	if !strings.HasPrefix(finalURL.String(), redirectURI) {
		t.Fatalf("final URL is not redirect_uri: %s", finalURL)
	}
	if got := finalURL.Query().Get("state"); got != state {
		t.Fatalf("state mismatch: got %q want %q", got, state)
	}
	code := finalURL.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in final URL: %s", finalURL)
	}

	// 4. Exchange code for tokens.
	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	tokenReq, _ := http.NewRequest("POST", ts.URL+"/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Authorization", "Basic "+basicAuth(prov.ClientID, prov.ClientSecret))
	tokenResp, err := hc.Do(tokenReq)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token exchange returned %d: %s", tokenResp.StatusCode, body)
	}
	var toks struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&toks); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if toks.AccessToken == "" || toks.IDToken == "" || toks.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", toks)
	}
	// NextAuth-based apps (e.g. Linkwarden) hard-code RS256 as the expected
	// id_token_signed_response_alg and reject anything else, so make sure RSA
	// keys do produce RS256 signatures.
	if alg := jwtHeaderAlg(t, toks.IDToken); alg != "RS256" {
		t.Fatalf("id token alg: got %s, want RS256", alg)
	}
	idClaims := decodeJWTClaims(t, toks.IDToken)
	if idClaims["preferred_username"] != "alice" {
		t.Fatalf("id token preferred_username: got %v want alice; claims=%+v", idClaims["preferred_username"], idClaims)
	}
	if idClaims["email"] != "alice@example.com" {
		t.Fatalf("id token email: got %v want alice@example.com; claims=%+v", idClaims["email"], idClaims)
	}

	// 5. Userinfo with the access token.
	uiReq, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	uiResp, err := hc.Do(uiReq)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	defer uiResp.Body.Close()
	if uiResp.StatusCode != 200 {
		body, _ := io.ReadAll(uiResp.Body)
		t.Fatalf("userinfo returned %d: %s", uiResp.StatusCode, body)
	}
	var ui map[string]any
	if err := json.NewDecoder(uiResp.Body).Decode(&ui); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if ui["sub"] == "" || ui["sub"] == nil {
		t.Fatalf("userinfo missing sub: %+v", ui)
	}
	if ui["preferred_username"] != "alice" {
		t.Fatalf("preferred_username: got %v want alice", ui["preferred_username"])
	}
	if ui["email"] != "alice@example.com" {
		t.Fatalf("email: got %v want alice@example.com", ui["email"])
	}
	groups, ok := ui["groups"].([]any)
	if !ok {
		t.Fatalf("groups: got %T %v, want array", ui["groups"], ui["groups"])
	}
	if !containsAll(groups, "user", "admin") {
		t.Fatalf("groups: got %v, want user and admin", groups)
	}

	// 6. Refresh-token grant.
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {toks.RefreshToken},
	}
	rReq, _ := http.NewRequest("POST", ts.URL+"/oauth/token", strings.NewReader(refreshForm.Encode()))
	rReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rReq.Header.Set("Authorization", "Basic "+basicAuth(prov.ClientID, prov.ClientSecret))
	rResp, err := hc.Do(rReq)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer rResp.Body.Close()
	if rResp.StatusCode != 200 {
		body, _ := io.ReadAll(rResp.Body)
		t.Fatalf("refresh returned %d: %s", rResp.StatusCode, body)
	}
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(rResp.Body).Decode(&refreshed); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	if refreshed.AccessToken == "" {
		t.Fatalf("refresh: empty access_token")
	}
	if refreshed.RefreshToken == toks.RefreshToken {
		t.Fatalf("refresh: token was not rotated")
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	users := auth.NewStore(d)
	ctx := context.Background()
	if _, err := users.Create(ctx, "bob", "", "correctpassword", false); err != nil {
		t.Fatalf("create user: %v", err)
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	var cryptoKey [32]byte
	rand.Read(cryptoKey[:])

	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()

	srv, err := authoidc.New(d, users, authoidc.Options{
		Issuer: ts.URL, SigningKey: priv, SigningKeyID: "k", CryptoKey: cryptoKey, AllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("build OIDC server: %v", err)
	}
	mux.Handle("/", srv.Handler())

	prov, err := authoidc.Provision(ctx, d, "test-app", []string{"http://example.test/cb"})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	hc := &http.Client{}
	authURL := ts.URL + "/authorize?" + url.Values{
		"client_id":     {prov.ClientID},
		"redirect_uri":  {"http://example.test/cb"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"x"},
	}.Encode()
	resp, err := hc.Get(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	authReqID := resp.Request.URL.Query().Get("authRequestID")
	if authReqID == "" {
		t.Fatalf("no authRequestID")
	}

	resp2, err := hc.PostForm(ts.URL+"/login", url.Values{
		"id": {authReqID}, "username": {"bob"}, "password": {"wrong"},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body), "invalid username or password") {
		t.Fatalf("expected error message, got: %s", body)
	}
}

// TestLoadSigningKeyAlg checks that LoadSigningKey accepts both RSA and
// ECDSA P-256 PKCS#8 PEM keys and that the OIDC server signs ID tokens with
// the algorithm matching the loaded key. Legacy nass deployments installed
// before the RS256 switch keep their ECDSA keys and continue to issue ES256
// tokens.
func TestLoadSigningKeyAlg(t *testing.T) {
	cases := []struct {
		name    string
		writeFn func(t *testing.T, path string)
		wantAlg string
	}{
		{
			name: "rsa",
			writeFn: func(t *testing.T, path string) {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("rsa key: %v", err)
				}
				writePKCS8(t, path, k)
			},
			wantAlg: "RS256",
		},
		{
			name: "ecdsa-p256",
			writeFn: func(t *testing.T, path string) {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("ecdsa key: %v", err)
				}
				writePKCS8(t, path, k)
			},
			wantAlg: "ES256",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signing.pem")
			tc.writeFn(t, path)

			signer, err := authoidc.LoadSigningKey(path)
			if err != nil {
				t.Fatalf("LoadSigningKey: %v", err)
			}
			alg := runEndToEndAndGetAlg(t, signer)
			if alg != tc.wantAlg {
				t.Fatalf("alg: got %s want %s", alg, tc.wantAlg)
			}
		})
	}
}

// runEndToEndAndGetAlg spins up an OIDC server with the given signing key,
// drives an auth-code flow as alice, and returns the alg of the issued ID
// token's JWT header.
func runEndToEndAndGetAlg(t *testing.T, signer crypto.Signer) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	users := auth.NewStore(d)
	ctx := context.Background()
	if _, err := users.Create(ctx, "alice", "alice@example.com", "wonderlandpw", true); err != nil {
		t.Fatalf("create user: %v", err)
	}

	var cryptoKey [32]byte
	if _, err := rand.Read(cryptoKey[:]); err != nil {
		t.Fatalf("crypto key: %v", err)
	}

	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	srv, err := authoidc.New(d, users, authoidc.Options{
		Issuer: ts.URL, SigningKey: signer, SigningKeyID: "k", CryptoKey: cryptoKey, AllowInsecure: true,
	})
	if err != nil {
		t.Fatalf("build OIDC server: %v", err)
	}
	mux.Handle("/", srv.Handler())

	const redirectURI = "http://example.test/callback"
	prov, err := authoidc.Provision(ctx, d, "test-app", []string{redirectURI})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), redirectURI) {
			return http.ErrUseLastResponse
		}
		return nil
	}}

	authResp, err := hc.Get(ts.URL + "/authorize?" + url.Values{
		"client_id":     {prov.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"x"},
	}.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	authResp.Body.Close()
	authReqID := authResp.Request.URL.Query().Get("authRequestID")
	if authReqID == "" {
		t.Fatalf("no authRequestID; final URL %s", authResp.Request.URL)
	}

	loginResp, err := hc.PostForm(ts.URL+"/login", url.Values{
		"id": {authReqID}, "username": {"alice"}, "password": {"wonderlandpw"},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()
	loc, err := loginResp.Location()
	if err != nil {
		t.Fatalf("login redirect missing Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}

	tokenReq, _ := http.NewRequest("POST", ts.URL+"/oauth/token", strings.NewReader(url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Authorization", "Basic "+basicAuth(prov.ClientID, prov.ClientSecret))
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token returned %d: %s", tokenResp.StatusCode, body)
	}
	var toks struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&toks); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if toks.IDToken == "" {
		t.Fatalf("empty id_token")
	}
	return jwtHeaderAlg(t, toks.IDToken)
}

func writePKCS8(t *testing.T, path string, key any) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("open key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s returned %d", url, resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func containsAll(got []any, wants ...string) bool {
	seen := make(map[string]bool, len(got))
	for _, v := range got {
		if s, ok := v.(string); ok {
			seen[s] = true
		}
	}
	for _, want := range wants {
		if !seen[want] {
			return false
		}
	}
	return true
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func jwtHeaderAlg(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatalf("unmarshal jwt header: %v", err)
	}
	return h.Alg
}

func decodeJWTClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("unmarshal jwt claims: %v", err)
	}
	return claims
}
