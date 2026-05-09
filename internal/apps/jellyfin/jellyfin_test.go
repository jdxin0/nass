package jellyfin

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestRenderSSOConfig_SubstitutesAllFields(t *testing.T) {
	ic := &apps.InstallContext{
		OIDCClientID:     "client-abc",
		OIDCClientSecret: "secret-xyz",
		OIDCIssuer:       "https://auth.nass.local",
	}
	out, err := renderSSOConfig(ic)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		"<string>nass</string>",
		"<OidEndpoint>https://auth.nass.local/.well-known/openid-configuration</OidEndpoint>",
		"<OidClientId>client-abc</OidClientId>",
		"<OidSecret>secret-xyz</OidSecret>",
		"<Enabled>true</Enabled>",
		"<EnableAuthorization>true</EnableAuthorization>",
		"<string>admin</string>",
		"<string>user</string>",
		"<RoleClaim>groups</RoleClaim>",
		"<string>profile</string>",
		"<string>groups</string>",
		"<DefaultUsernameClaim>preferred_username</DefaultUsernameClaim>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// REPLACE_ tokens from the bash version must not leak through.
	if strings.Contains(got, "REPLACE_") {
		t.Errorf("unsubstituted REPLACE_ token in output:\n%s", got)
	}
}

func TestUnzipInto_ExtractsFiles(t *testing.T) {
	zipBytes := makeZip(t, map[string]string{
		"meta.json":           `{"name":"SSO"}`,
		"SSO-Auth.dll":        "binary-content",
		"sub/nested/file.txt": "hello",
	})
	dest := t.TempDir()
	if err := unzipInto(zipBytes, dest); err != nil {
		t.Fatalf("unzip: %v", err)
	}
	for path, want := range map[string]string{
		"meta.json":           `{"name":"SSO"}`,
		"SSO-Auth.dll":        "binary-content",
		"sub/nested/file.txt": "hello",
	} {
		got, err := os.ReadFile(filepath.Join(dest, path))
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
	}
}

func TestUnzipInto_RejectsZipSlip(t *testing.T) {
	zipBytes := makeZip(t, map[string]string{
		"../escaped.txt": "evil",
	})
	dest := t.TempDir()
	err := unzipInto(zipBytes, dest)
	if err == nil {
		t.Fatal("expected zip-slip rejection, got nil")
	}
	if !strings.Contains(err.Error(), "escapes dest") {
		t.Errorf("error should mention escape, got: %v", err)
	}
}

func TestLatestPluginURL_PicksFirstVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifest := []map[string]any{{
			"name": "SSO Authentication",
			"versions": []map[string]any{
				{"sourceUrl": "https://example.test/v2.0.0.zip"},
				{"sourceUrl": "https://example.test/v1.0.0.zip"},
			},
		}}
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer srv.Close()

	body, err := fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	var manifest []struct {
		Versions []struct {
			SourceURL string `json:"sourceUrl"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := manifest[0].Versions[0].SourceURL; got != "https://example.test/v2.0.0.zip" {
		t.Errorf("expected first version to win, got %q", got)
	}
}

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}
