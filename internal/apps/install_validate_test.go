package apps

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/orchestrator"
)

func TestValidateRejectsIssuerSubdomain(t *testing.T) {
	ic := &InstallContext{
		Name: "gitea", Subdomain: "auth", BackendPort: 13000, BaseHost: "example.com",
		ComposeFile: "/x/docker-compose.yaml", DataRoot: "/x/data",
		OIDCIssuer: "https://auth.example.com", DB: &sql.DB{}, Orchestrator: &orchestrator.Orchestrator{},
	}
	if err := ic.validate(); err == nil || !strings.Contains(err.Error(), "sign-in server") {
		t.Fatalf("installing on the issuer's subdomain must fail, got %v", err)
	}
	ic.Subdomain = "AUTH"
	if err := ic.validate(); err == nil {
		t.Fatal("the check must be case-insensitive")
	}
	ic.Subdomain = "git"
	if err := ic.validate(); err != nil {
		t.Fatalf("a normal subdomain must pass: %v", err)
	}
}
