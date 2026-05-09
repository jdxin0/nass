package nextcloud

import (
	"slices"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/apps"
)

func TestProviderArgsProvisionGroups(t *testing.T) {
	ic := &apps.InstallContext{
		OIDCClientID:     "cid",
		OIDCClientSecret: "secret",
		OIDCIssuer:       "https://auth.nass.local",
	}
	args := providerArgs(ic)
	joined := strings.Join(args, " ")

	if !slices.Contains(args, "--group-provisioning=1") {
		t.Fatalf("provider args should enable group provisioning: %v", args)
	}
	if !slices.Contains(args, "--group-whitelist-regex=/^(admin|user)$/") {
		t.Fatalf("provider args should limit provisioned groups: %v", args)
	}
	if !strings.Contains(joined, "openid profile email groups") {
		t.Fatalf("provider args should request groups scope: %v", args)
	}
}
