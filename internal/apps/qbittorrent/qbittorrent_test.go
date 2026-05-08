package qbittorrent

import (
	"strings"
	"testing"
)

func TestPatchConf_AddsMissingKeysIntoPreferences(t *testing.T) {
	in := strings.Join([]string{
		"[BitTorrent]",
		"Session\\Port=6881",
		"",
		"[Preferences]",
		"WebUI\\Address=*",
		"WebUI\\Username=admin",
		"",
	}, "\n")
	want := map[string]string{
		`WebUI\HostHeaderValidation`:       "false",
		`WebUI\AuthSubnetWhitelistEnabled`: "true",
	}
	got, changed := patchConf(in, want)
	if !changed {
		t.Fatal("expected changed=true")
	}
	for k, v := range want {
		if !strings.Contains(got, k+"="+v) {
			t.Errorf("missing %q=%q in:\n%s", k, v, got)
		}
	}
	// Must remain inside [Preferences]: the new keys appear before any
	// subsequent section header. Here there's no later section, so just
	// confirm [BitTorrent] is still untouched and ordered first.
	if i := strings.Index(got, "[BitTorrent]"); i < 0 {
		t.Fatalf("[BitTorrent] header lost:\n%s", got)
	}
	if strings.Index(got, "[BitTorrent]") > strings.Index(got, "[Preferences]") {
		t.Fatalf("section order changed:\n%s", got)
	}
}

func TestPatchConf_ReplacesExistingValues(t *testing.T) {
	in := strings.Join([]string{
		"[Preferences]",
		"WebUI\\Address=*",
		"WebUI\\HostHeaderValidation=true",
		"WebUI\\CSRFProtection=true",
	}, "\n")
	got, changed := patchConf(in, map[string]string{
		`WebUI\HostHeaderValidation`: "false",
		`WebUI\CSRFProtection`:       "false",
	})
	if !changed {
		t.Fatal("expected changed=true")
	}
	if !strings.Contains(got, "WebUI\\HostHeaderValidation=false") {
		t.Errorf("HostHeaderValidation not replaced:\n%s", got)
	}
	if strings.Contains(got, "WebUI\\HostHeaderValidation=true") {
		t.Errorf("old HostHeaderValidation still present:\n%s", got)
	}
	if !strings.Contains(got, "WebUI\\CSRFProtection=false") {
		t.Errorf("CSRFProtection not replaced:\n%s", got)
	}
}

func TestPatchConf_NoOpWhenAlreadyDesired(t *testing.T) {
	in := strings.Join([]string{
		"[Preferences]",
		"WebUI\\HostHeaderValidation=false",
	}, "\n")
	got, changed := patchConf(in, map[string]string{
		`WebUI\HostHeaderValidation`: "false",
	})
	if changed {
		t.Fatal("expected changed=false for already-desired conf")
	}
	if got != in {
		t.Fatalf("body should be unchanged when no edits are needed")
	}
}

func TestPatchConf_CreatesPreferencesSectionIfMissing(t *testing.T) {
	in := "[BitTorrent]\nSession\\Port=6881\n"
	got, changed := patchConf(in, map[string]string{
		`WebUI\HostHeaderValidation`: "false",
	})
	if !changed {
		t.Fatal("expected changed=true")
	}
	if !strings.Contains(got, "[Preferences]") {
		t.Errorf("[Preferences] section not created:\n%s", got)
	}
	if !strings.Contains(got, "WebUI\\HostHeaderValidation=false") {
		t.Errorf("missing key in:\n%s", got)
	}
}

func TestPatchConf_DoesNotInsertIntoLaterSection(t *testing.T) {
	in := strings.Join([]string{
		"[Preferences]",
		"WebUI\\Address=*",
		"",
		"[Network]",
		"PortForwarding=true",
		"",
	}, "\n")
	got, changed := patchConf(in, map[string]string{
		`WebUI\HostHeaderValidation`: "false",
	})
	if !changed {
		t.Fatal("expected changed=true")
	}
	prefIdx := strings.Index(got, "WebUI\\HostHeaderValidation=false")
	netIdx := strings.Index(got, "[Network]")
	if prefIdx < 0 || netIdx < 0 || prefIdx > netIdx {
		t.Fatalf("inserted key must precede [Network]:\n%s", got)
	}
}
