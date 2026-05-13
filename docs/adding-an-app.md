# Adding a new app

This guide walks through everything needed to add a new app to nass so users can
install it with `nass app install <name>`. The Miniflux package (commit
`a5310b7`) is the smallest reference implementation — start there if you want a
working example.

## What you need before you start

- The app must run under `docker compose` and expose a single HTTP backend port
  on `127.0.0.1`. nass proxies one host (`<subdomain>.<base_host>`) to that
  port. Multi-port apps (e.g. gRPC sidecar) are supported only if the proxy
  doesn't need to touch the extra ports.
- Decide which auth mode the app speaks:
  - **Native OIDC** — the app talks OIDC itself (Miniflux, Nextcloud, Gitea,
    Vaultwarden, …). Set `NeedsOIDC: true`, `OIDCGate: false`. nass provisions
    the client and hands you `OIDCClientID` / `OIDCClientSecret`.
  - **Portal-gated** — the app has no OIDC. nass authenticates the user at the
    proxy and forwards `Remote-User` / `Remote-Email` headers (Firefly III,
    qBittorrent). Set `NeedsOIDC: false`, `OIDCGate: true`. The app must
    either consume the headers (Firefly's `remote_user_guard`) or have its own
    auth disabled (qBittorrent has `AuthSubnetWhitelist`).
- Pick a preferred backend port that isn't already used. Run
  `grep -h BackendPort: internal/apps/*/*.go` to see what's taken. Ports in
  `orchestrator.backend_port_range` (default `20000-29999`) are the runtime
  fallback when the preferred one is busy, so anything outside that range is
  fine.
- Disable public signup wherever possible. nass treats the IdP as the gate;
  any signup form on the app side is a way to bypass it. See the *Signup*
  section below for app-specific patterns.

## File layout

Each app is a Go subpackage under `internal/apps/`. Three files is the norm:

```
internal/apps/<name>/
  <name>.go              # registers the Spec, defines hooks
  <name>_test.go         # at minimum, a redirect-URI test
  docker-compose.yaml    # text/template rendered against InstallContext
```

Larger apps add helpers (config-file generation, conf-file patching) or assets
(e.g. Paperless's `nass_sso/` Django app shipped as data). Keep them inside the
package directory.

## 1. Write the compose template

The compose file is a Go `text/template` rendered against `*apps.InstallContext`
([app.go:60](../internal/apps/app.go)). Fields you'll reach for:

| Field | What it is |
| --- | --- |
| `{{.Name}}` | The app's name. Use as `container_name` and as a prefix for sidecar containers (`{{.Name}}_postgres`). Service names inside the compose file are local to the project and can stay short (`postgres`, `redis`). |
| `{{.BackendPort}}` | Resolved at install time — may differ from `Spec.BackendPort` if the preferred port was busy. **Always** bind to `127.0.0.1:` so the port isn't reachable from outside. |
| `{{.DataRoot}}` | Absolute host path for all persistent volumes for this app. Subdivide with subfolders (`{{.DataRoot}}/postgres`, `{{.DataRoot}}/config`). |
| `{{.BaseHost}}` | The nass base domain. Use in `extra_hosts` so the container can resolve the IdP back through the host. |
| `{{.PublicURL}}` | `https://<sub>.<base_host>[:port]`. Use for `BASE_URL`, `NEXTAUTH_URL`, redirect URLs, etc. |
| `{{.AdminPassword}}` | Per-install random password. Re-use it for Postgres, app admin, anything that needs a secret you don't want to invent more of. |
| `{{.OIDCClientID}}` / `{{.OIDCClientSecret}}` | Populated when `NeedsOIDC: true`. Empty otherwise. |
| `{{.OIDCIssuer}}` | E.g. `https://auth.<base_host>`. The app appends `/.well-known/openid-configuration` itself in most cases. |

Boilerplate every OIDC-speaking app needs:

```yaml
extra_hosts:
  - "auth.{{.BaseHost}}:host-gateway"
  - "{{.BaseHost}}:host-gateway"
```

Without this, the container's resolver doesn't know the IdP exists. nass runs
inside the same host network namespace, so `host-gateway` routes the lookup
back to it.

## 2. Define the Spec

```go
package miniflux

import (
    "context"
    _ "embed"
    "fmt"
    "time"

    "github.com/jdxin0/nass/internal/apps"
)

//go:embed docker-compose.yaml
var composeTemplate []byte

func init() {
    apps.Register(apps.Spec{
        Name:             "miniflux",
        DisplayName:      "Miniflux",
        Description:      "Minimalist RSS reader",
        Icon:             "📰",
        Subdomain:        "miniflux",
        BackendPort:      18070,
        PreserveHost:     true,
        NeedsOIDC:        true,
        OIDCGate:         false,
        OIDCRedirectURIs: redirectURIs,
        ComposeTemplate:  composeTemplate,
        PostUp:           postUp,
    })
}

func redirectURIs(ic *apps.InstallContext) []string {
    return []string{ic.PublicURL() + "/oauth2/oidc/callback"}
}
```

Spec field cheatsheet ([app.go:21](../internal/apps/app.go)):

| Field | Notes |
| --- | --- |
| `Name` | DNS-safe identity. Must be unique across the registry — `Register` panics on duplicates. Used as the compose project, the apps row key, the OIDC client name, etc. |
| `Subdomain` | Default subdomain; user can override with `--subdomain`. Empty defaults aren't allowed at install time. |
| `BackendPort` | Preferred host port. If busy, the installer picks from `backend_port_range`. |
| `PreserveHost` | Set to `true` if the app rejects requests when `Host` is the backend's `127.0.0.1:N`. Almost everyone says yes. |
| `NeedsOIDC` | If `true`, you must also set `OIDCRedirectURIs`. The installer fails fast otherwise. |
| `OIDCGate` | Mutually exclusive in practice with `NeedsOIDC=true`. Setting both is allowed but the app has to handle two auth layers. |
| `OIDCRedirectURIs` | Function so the URIs can include the resolved `PublicURL`. Return every variant the upstream actually uses — some clients send scheme-derived URIs that differ from `BASE_URL`. |
| `PreUp` / `PostUp` | Both may be nil. See *Lifecycle hooks* below. |

## 3. Register the package

There are exactly two places to add a blank import:

```diff
 // internal/cli/install.go
     _ "github.com/jdxin0/nass/internal/apps/linkwarden"
+    _ "github.com/jdxin0/nass/internal/apps/miniflux"
     _ "github.com/jdxin0/nass/internal/apps/nextcloud"

 // internal/apps/apps_test.go
     _ "github.com/jdxin0/nass/internal/apps/linkwarden"
+    _ "github.com/jdxin0/nass/internal/apps/miniflux"
     _ "github.com/jdxin0/nass/internal/apps/nextcloud"
```

The first import is what makes the app available at runtime. The second is what
makes the cross-package render test pick it up. If you forget the second, the
package's own tests still run but the registry-level `TestAllSorted` and the
new render test can't see the spec.

## 4. Lifecycle hooks

Both hooks receive the fully-resolved `InstallContext`. Order is `PreUp` →
`docker compose up -d` → `PostUp`.

**`PreUp`** — runs *after* the compose file is on disk, *before* containers
start. Use it when the app needs a file mounted from the host that depends on
runtime values (Immich's `immich-config.json` with the OIDC client secret;
Firefly's persisted `APP_KEY`; Paperless's `nass_sso/` directory). Generate the
file under `ic.DataRoot` or next to `ic.ComposeFile` and let the compose
template mount it.

**`PostUp`** — runs *after* `docker compose up -d`. The container is up but
not necessarily ready. Always start with:

```go
waitCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
defer cancel()
target := fmt.Sprintf("http://127.0.0.1:%d/healthcheck", ic.BackendPort)
if err := apps.WaitFor(waitCtx, target, 2*time.Second); err != nil {
    return fmt.Errorf("wait for myapp: %w", err)
}
```

`apps.WaitFor` returns as soon as the URL responds with *any* HTTP status,
including 4xx — good enough to know the server is accepting connections. Pick
a path the app actually serves before login (`/`, `/healthcheck`, `/api/ping`).

What goes in `PostUp` depends on the app:

- **Env-driven apps (Miniflux, Linkwarden, Vaultwarden)** — usually just the
  wait. Everything else is in compose env vars.
- **CLI-configured apps (Gitea)** — `ic.Orchestrator.Exec` / `ExecAsUser` to
  run commands inside the container.
- **API-configured apps (Immich)** — HTTP POSTs to the local backend port.
- **DB-seeded apps (Blinko)** — `psql` against the sidecar Postgres via
  `ic.Orchestrator.Exec`.
- **File-patched apps (qBittorrent)** — read/modify a file under
  `ic.DataRoot`; restart or `kill` the container so it picks the change up.

PostUp errors fail the install, so make sure hooks are idempotent (or skip
work that's already done). Most existing apps wrap `ExecAsUser` errors with an
`already exists` check.

## 5. Tests

Two tests are the minimum:

**Package-local redirect URI test** (`<name>_test.go`):

```go
func TestRedirectURIs(t *testing.T) {
    ic := &apps.InstallContext{
        Subdomain: "rss", BaseHost: "nass.local",
        PublicScheme: "https", PublicPort: ":8443",
    }
    got := redirectURIs(ic)
    want := "https://rss.nass.local:8443/oauth2/oidc/callback"
    if len(got) != 1 || got[0] != want {
        t.Fatalf("redirect URIs: got %v want [%s]", got, want)
    }
}
```

**Cross-package compose render test** in
[`internal/apps/apps_test.go`](../internal/apps/apps_test.go) — follow the
existing `Test<App>ComposeRenders` pattern. Assert on every env var, port
binding, image, and volume that the app actually needs to function; this is
the only thing that catches a template typo before someone tries to install.
Don't paste in the entire rendered output — list the substrings.

If you wrote a `PreUp` or `PostUp` with non-trivial logic (parsing,
side-effects), unit-test them in the package. Use the orchestrator's
exec-func hook (see `blinko_test.go` for the `composeExecFunc` injection
pattern) to avoid Docker.

## 6. Disable public signup

nass's threat model is: only IdP-authenticated users get accounts. Anything on
the app side that lets a stranger register breaks that. By app pattern:

- **Env var on the app**: `NEXT_PUBLIC_DISABLE_REGISTRATION=true` (Linkwarden),
  `PAPERLESS_ACCOUNT_ALLOW_SIGNUPS=False` (Paperless), `DISABLE_LOCAL_AUTH=1`
  (Miniflux), `SSO_ONLY=true` + `INVITATIONS_ALLOWED=false` (Vaultwarden).
- **Admin CLI in PostUp**: Gitea disables manual registration by setting
  `service.DISABLE_REGISTRATION` via the rendered `app.ini`; Nextcloud blocks
  it with `occ config:system:set`.
- **Auto-provision on OIDC**: if the app has no "registration disabled" flag,
  set the OIDC client to auto-create users (Miniflux `OAUTH2_USER_CREATION=1`,
  Paperless `PAPERLESS_SOCIAL_AUTO_SIGNUP=True`, Gitea
  `oauth2_client.ENABLE_AUTO_REGISTRATION=true`) so the only way a user
  account exists is *because* a successful OIDC login created it.

Some apps (Vaultwarden) require the public-signup flag *to be on* for SSO
auto-provisioning to work. Leave a comment in the compose template explaining
why — `SIGNUPS_ALLOWED: "true"` looks like a vulnerability at a glance.

## 7. Update the docs

When you add an app, also touch:

- [`README.md`](../README.md) — the supported-apps table, the install example
  block, and the `internal/apps/` layout tree.
- [`docs/usage.md`](usage.md) — the install example block and the "stop
  everything but keep data" loop.
- [`docs/design.md`](design.md) — the blank-import list and a `### <App>
  (apps/<name>/)` subsection in *Per-app notes* covering port, redirect URI,
  what's in compose, and what the hooks do.

## 8. Verify

```sh
go build ./...
go test ./...
```

The render test is the one that catches the most. After that, install against
a real `nass init`'d host:

```sh
sudo nass app install <name>
sudo docker compose -f /srv/nass/apps/<name>/docker-compose.yaml ps
curl -fsSL "https://<sub>.<base_host>/" -o /dev/null  # then sign in
```

If the app is OIDC-native, the first login should bounce through `auth.<host>`
and land on a logged-in dashboard. If it bounces back to the OIDC login page,
the redirect URI registered on the client doesn't match what the app sends —
diff `OIDCRedirectURIs` against the error in the IdP logs.

To uninstall and try again:

```sh
sudo nass app uninstall <name> --yes
```

That tears down the stack, deletes the data folder, removes the OIDC client,
and clears the apps row, so re-running `install` starts from scratch.
