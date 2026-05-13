# Design

This document covers nass's architecture: what each component does, how they
fit together, and why the boundaries are where they are.

## Goals

- **One binary, one config file, one DB.** No fleet of services to wire up.
  `nass init` then `nass serve` and you're done.
- **Apps are first-class.** Installing an app is a single command that handles
  reverse-proxy config, OIDC client provisioning, compose rendering, container
  startup, and any first-boot ritual the app needs. No partial states the
  operator has to clean up by hand.
- **Stay out of the apps' way.** Each app runs in its own compose stack with
  its own volumes. nass terminates TLS, optionally federates auth, and exits
  the request path as fast as possible.
- **No required external services.** SQLite for state. The bundled OIDC
  provider means even apps that demand SSO work on a fresh install with no
  Keycloak/Casdoor sidecar.

## Components

```
                   ┌──────────────────────────────────────┐
   :443 / :80 ───► │  proxy.Server (host-based router)    │
                   │     │                                │
                   │     ├── auth.<host>  ─► oidc.Server  │
                   │     ├── <host>       ─► portal.Mux   │
                   │     └── <app>.<host> ─► reverse proxy│
                   │                       (optional gate) │
                   │                                      │
                   │  proxy.RouteManager (30s sync)       │
                   │       reads `apps` table, rebuilds   │
                   │       app routes without restart     │
                   └──────────────────────────────────────┘
                                       │
                                       ▼
                   ┌──────────────────────────────────────┐
                   │  SQLite (modernc.org/sqlite, WAL)    │
                   │   users, portal_sessions,            │
                   │   apps, oidc_clients,                │
                   │   oidc_auth_requests/codes/tokens    │
                   └──────────────────────────────────────┘
```

### `proxy/` — host-based reverse proxy

`proxy.Server` is a `http.Handler` that dispatches by stripped, lower-cased
`Host` header. Three flavours of route get registered:

1. **Fixed routes** wired up at startup — the OIDC issuer host and the portal
   host. These don't change at runtime.
2. **App routes** — `<subdomain>.<base_host>` for each enabled app, set up by
   `proxy.RouteManager` from the `apps` table on startup and re-synced every
   30 seconds. Re-syncing means a `nass app install` from another shell
   shows up without restarting `serve`.
3. **HTTP redirector** on `:80` — issues 301s to the HTTPS equivalent.

The actual reverse-proxy is `httputil.ReverseProxy` with a custom `Rewrite`
hook that sets `X-Forwarded-*`, optionally preserves the original `Host`, and
sets a per-app `ResponseHeaderTimeout` (Nextcloud needs a long one for big
uploads). WebSocket upgrades work transparently since Go 1.12.

TLS certs are loaded from disk via `tls.LoadX509KeyPair`. There is **no**
autocert / mkcert / ACME integration. You bring your own cert. This keeps the
trust path explicit and works with Let's Encrypt DNS-01, internal CAs, mkcert
for dev, etc.

### `portal/` — login UI, sessions, dashboard, admin

The portal serves three things:

- `/portal/login` — username/password form. On submit, verifies against the
  user store, creates a `portal_sessions` row, sets the `nass_session` cookie
  (HttpOnly, Secure, SameSite=Lax, **Domain scoped to `base_host`** so all
  subdomains see it).
- `/` — the dashboard. For each enabled app, queries `docker compose ps` to
  show running/stopped/unknown, renders a tile linking to its public URL.
  Authenticated users only.
- `/portal/admin` — start/stop/restart apps, enable/disable proxy routes.
  Admin users only.

The `OIDCGate` is a small middleware (`portal/gate.go`) that wraps a proxy
route. If there's no valid portal session, it 302s to
`/portal/login?next=<original>`. We use it for apps that don't speak OIDC
themselves (currently qBittorrent). It's not strong auth — apps behind it are
trusting the proxy to enforce identity — but for a single-tenant home server
it's the right ergonomic.

Session state lives in SQLite, not memory, so restarts don't log everyone out.

### `auth/oidc/` — built-in OpenID Connect provider

Wraps `github.com/zitadel/oidc/v3`. Issuer URL is derived from
`oidc.subdomain + base_host` unless overridden. Standard endpoints:
`/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`,
`/keys`, plus a `/login` page for when a client redirects to us mid-flow.

`/login` has two branches:

- **Portal-wired (the real flow).** If the user already has a `nass_session`
  cookie, we mark the auth request complete and 302 back to the OP callback.
  No second login.
- **Embedded form (fallback).** If portal isn't wired in (or no session),
  render a username/password form. Useful for testing the IdP standalone.

Tokens, codes, and auth requests live in SQLite. Access tokens are 5-minute
UUIDs; refresh tokens are 30-day UUIDs (rotated on each refresh). Signing key
is ECDSA P-256 (key ID `nass-1`), generated by `nass init`. A second 32-byte
symmetric key encrypts state passed through redirect URIs.

Client provisioning (`clients.go`) generates a 16-byte ID and 32-byte secret,
bcrypt-hashes the secret, stores redirect URIs as a JSON array. The plaintext
secret is shown to the operator **once** at install time and never persisted.

### `apps/` — registry and install pipeline

The registry pattern is Go's classic init-side-effect imports:

```go
// internal/cli/install.go
import (
    _ "github.com/jdxin0/nass/internal/apps/gitea"
    _ "github.com/jdxin0/nass/internal/apps/immich"
    _ "github.com/jdxin0/nass/internal/apps/jellyfin"
    _ "github.com/jdxin0/nass/internal/apps/linkwarden"
    _ "github.com/jdxin0/nass/internal/apps/nextcloud"
    _ "github.com/jdxin0/nass/internal/apps/qbittorrent"
    _ "github.com/jdxin0/nass/internal/apps/blinko"
    _ "github.com/jdxin0/nass/internal/apps/firefly"
    _ "github.com/jdxin0/nass/internal/apps/paperless"
    _ "github.com/jdxin0/nass/internal/apps/vaultwarden"
)
```

Each app's package has an `init()` that calls `apps.Register(spec)` with its
`Spec`. `apps.Get(name)` and `apps.All()` are how the CLI looks them up.
Adding an app is "drop a package, add the import" — there's no central list
to keep in sync.

A `Spec` is the static description of the app:

```go
type Spec struct {
    Name            string  // identity
    DisplayName     string  // for the dashboard
    Description     string
    Icon            string  // emoji
    Subdomain       string  // default subdomain
    BackendPort     int     // preferred host port for the proxy
    PreserveHost    bool    // forward original Host header?
    NeedsOIDC       bool    // provision an OIDC client?
    OIDCGate        bool    // gate the proxy route on a portal session?
    ComposeTemplate []byte  // embedded docker-compose.yaml (Go template)
    PreUp           func(ctx, *InstallContext) error
    PostUp          func(ctx, *InstallContext) error
}
```

The install pipeline (`internal/apps/install.go`) is fixed:

1. **Resolve context** — fill in defaults: subdomain from spec, data root from
   `<orchestrator.data_root>/<name>`, compose path from
   `<orchestrator.compose_root>/<name>/docker-compose.yaml`, random admin
   password if none given, and selected backend port. Each app has a preferred
   localhost port; if that port is busy, nass scans
   `orchestrator.backend_port_range` and stores the first free port in the app
   route. An explicit `--backend-port` must be free or the install fails.
2. **Provision OIDC client** if `NeedsOIDC`. Now `ic.OIDCClientID/Secret` are
   populated and the issuer URL is known.
3. **Render compose** — `text/template` over `Spec.ComposeTemplate` with the
   install context as data. Write to disk, `mkdir -p` the data root.
4. **Save app row** — insert into `apps` table with `enabled=1` and the
   serialised proxy settings (subdomain, backend, preserve_host, oidc_gate).
5. **`Spec.PreUp(ctx, ic)`** — runs *after* the compose file is on disk but
   *before* containers start. Used by Immich to write its system-config JSON
   into the directory the compose file mounts.
6. **`docker compose up -d`** via the orchestrator.
7. **`Spec.PostUp(ctx, ic)`** — runs *after* containers are up. This is
   where apps drive their first-boot setup: Nextcloud installs the `user_oidc`
   plugin, Jellyfin runs the startup wizard and sideloads the SSO plugin,
   Immich does admin signup, Gitea adds the nass OIDC source, Blinko seeds its
   OAuth provider config, Linkwarden is configured through environment
   variables, and qBittorrent patches `qBittorrent.conf` for proxy
   compatibility.

The pipeline is straight-line and not idempotent yet. Re-running
`nass app install` on an already-installed app fails (the OIDC client already
exists). Fixing that is on the backlog.

`nass app uninstall <name>` is the destructive cleanup path: it runs
`docker compose down -v --remove-orphans`, removes any OIDC client and issued
tokens for the app, deletes the `apps` row, removes the data folder unless
`--keep-data` is set, and removes the generated compose file. Legacy path
fallbacks are only used when the default generated compose file exists, so
manual `app enable` routes do not cause guessed data paths to be deleted.

### `orchestrator/` — docker compose shell-out

Thin wrapper around `exec.Command`. Each method maps to one compose
subcommand: `Up`, `Down`, `Restart`, `Kill`, `Exec`, `ExecAsUser`, `Status`.
`Status` parses `docker compose ps --format json` and reduces to running /
stopped / unknown — that's what drives the dashboard tile state.

The compose binary is configured by `orchestrator.docker_compose`. Default
`"docker compose"` covers the v2 plugin; on systems with the legacy
standalone binary, set `"docker-compose"`.

### `db/` — SQLite + embedded migrations

`modernc.org/sqlite` (pure Go, no cgo). Migrations are SQL files embedded via
`//go:embed`, applied in version order on `db.Open`. Tables:

| Table | Purpose |
| --- | --- |
| `users` | Username, email, bcrypt password hash, admin flag. |
| `portal_sessions` | Cookie token → user, 7-day TTL. |
| `apps` | One row per app: name, enabled flag, settings JSON. |
| `oidc_clients` | Per-app OIDC client (client_id PK, hashed secret, redirect URIs). |
| `oidc_auth_requests` | In-flight OIDC auth requests (incl. PKCE). |
| `oidc_auth_codes` | Authorisation codes (request_id FK). |
| `oidc_access_tokens` | Issued access tokens (5-min). |
| `oidc_refresh_tokens` | Refresh tokens (30-day, rotated). |
| `schema_migrations` | Applied-version tracker. |

WAL is on for concurrent reads with the writer; `busy_timeout=5000ms` so
short contention doesn't blow up.

## Per-app notes

### Nextcloud (`apps/nextcloud/`)

- BackendPort `18080`, native OIDC via the `user_oidc` app.
- PostUp installs `user_oidc` (`occ app:install user_oidc`), registers nass as
  an OIDC provider (`occ user_oidc:provider nass …`), and enables
  `allow_local_remote_servers` so Nextcloud can reach the IdP through its
  own host.
- Container needs `auth.<base_host>:host-gateway` in `extra_hosts` so the
  discovery URL resolves from inside the container.

### Jellyfin (`apps/jellyfin/`)

- BackendPort `18096`, native OIDC via the third-party
  [`jellyfin-plugin-sso`](https://github.com/9p4/jellyfin-plugin-sso).
- PostUp drives Jellyfin's web-API startup wizard, then downloads the SSO
  plugin's latest release zip from GitHub, unzips it into the volume-mounted
  plugin directory, writes a custom `branding.xml` (SSO sign-in button) and a
  rendered `SSO-Auth.xml` with the OIDC settings. Restarts to pick up the
  plugin.
- The unzip has a zip-slip guard.

### Immich (`apps/immich/`)

- BackendPort `18283`. Compose stack is four services: server, ML worker,
  Postgres, Redis.
- Native OIDC via `IMMICH_CONFIG_FILE`. **PreUp** writes
  `immich-config.json` next to the compose file (mounted in as
  `/immich-config.json`). The config is built from a Go struct and JSON-
  marshalled — not template-substituted — so a client secret containing
  `"` or `\` can't break the file.
- PostUp polls `/api/server-info/config` until `isInitialized` appears, then
  POSTs `/api/auth/admin-sign-up` if not already initialised.

### Gitea (`apps/gitea/`)

- BackendPort `13000`, native OIDC via Gitea's built-in OAuth2/OpenID
  Connect auth source support.
- Compose uses SQLite under `/data`, locks the installer, disables SSH clone
  URLs for now, and enables OAuth2 auto-registration with
  `preferred_username`.
- PostUp creates a local `admin` user, then runs
  `gitea admin auth add-oauth` to register nass with `groups` as the role
  claim and `admin` as the administrator group.

### qBittorrent (`apps/qbittorrent/`)

- BackendPort `18100`. **No** native OIDC: gated by `OIDCGate=true`, so the
  proxy enforces a portal session.
- PostUp waits for the WebUI, waits for `qBittorrent.conf` to appear in the
  volume, patches it to disable host-header validation and CSRF (the proxy
  is doing both), then **`SIGKILL`s** the container before writing the
  patched file. Graceful shutdown would have qBittorrent flush its in-memory
  state and overwrite our edits.

### Blinko (`apps/blinko/`)

- BackendPort `11111`, native OIDC via Blinko's custom OAuth2 provider support.
- Redirect URI: `https://blinko.<base_host>/api/auth/callback/nass`.
- Compose runs Blinko plus Postgres. `NEXTAUTH_URL` and
  `NEXT_PUBLIC_BASE_URL` are set to the public app URL.
- PostUp waits for Blinko's first boot, writes the `oauth2Providers` config row
  in Blinko's Postgres database with nass as a custom provider, then restarts
  the stack so Blinko reloads its OAuth strategies.

### Linkwarden (`apps/linkwarden/`)

- BackendPort `13001`, native OIDC via Linkwarden's Authelia-compatible
  well-known provider.
- Redirect URI:
  `https://linkwarden.<base_host>/api/v1/auth/callback/authelia`.
- Compose runs Linkwarden, Postgres, and Meilisearch. `NEXTAUTH_URL` includes
  Linkwarden's required `/api/v1/auth` suffix; `BASE_URL` points at the public
  app root.
- OIDC is wired with `NEXT_PUBLIC_AUTHELIA_ENABLED`,
  `AUTHELIA_WELLKNOWN_URL`, `AUTHELIA_CLIENT_ID`, and
  `AUTHELIA_CLIENT_SECRET`. Local credential login and self-registration are
  disabled by default.
- PostUp only waits for the web service because all first-boot configuration is
  supplied through environment variables.

### Paperless-ngx (`apps/paperless/`)

- BackendPort `18040`, native OIDC via django-allauth's `openid_connect`
  provider.
- Redirect URI:
  `https://paperless.<base_host>/accounts/oidc/nass/login/callback/`.
- Compose runs Paperless plus Postgres and Redis. `PAPERLESS_APPS` toggles
  the allauth provider on, and `PAPERLESS_SOCIALACCOUNT_PROVIDERS` carries
  the full provider config (client id/secret + discovery URL) as a JSON
  blob.
- `PAPERLESS_SOCIAL_AUTO_SIGNUP=True` creates a Paperless user on the first
  SSO login; the seeded `PAPERLESS_ADMIN_USER` stays as a break-glass
  password account on `/admin/`.
- A tiny embedded Django app, `nass_sso` (in `apps/paperless/nass_sso/`), is
  written to `{DataRoot}/nass_sso/` in PreUp and bind-mounted read-only at
  `/usr/src/paperless/src/nass_sso`. It registers an allauth
  `user_signed_up` receiver that promotes new SSO sign-ups to superuser.
  Paperless's default RBAC otherwise leaves them with no document
  permissions, so they can't upload — nass treats every IdP-authenticated
  user as trusted (the operator curates the IdP), so granting superuser
  matches the trust model.

### Vaultwarden (`apps/vaultwarden/`)

- BackendPort `18050`, native OIDC via Vaultwarden's built-in SSO support.
- Redirect URI:
  `https://vault.<base_host>/identity/connect/oidc-signin` (hardcoded by
  Vaultwarden; derived from `DOMAIN`).
- Compose runs the single Vaultwarden container with embedded SQLite — no
  external database. SSO is wired through `SSO_ENABLED=true`,
  `SSO_AUTHORITY` (the nass issuer; Vaultwarden appends
  `/.well-known/openid-configuration` itself), `SSO_CLIENT_ID`, and
  `SSO_CLIENT_SECRET`, with `SSO_PKCE=true` for PKCE-protected code exchange.
- `SSO_ONLY=true` disables the master-password login form; users still set a
  master password on first sign-in for client-side vault encryption.
  `ADMIN_TOKEN` (the generated admin password) gates the `/admin` panel.

### Firefly III (`apps/firefly/`)

- BackendPort `18030`. **No** native OIDC: gated by `OIDCGate=true`, and the
  portal `Gate` injects `Remote-User` / `Remote-Email` headers on every
  authenticated request.
- Firefly is configured with `AUTHENTICATION_GUARD=remote_user_guard`,
  `AUTHENTICATION_GUARD_HEADER=HTTP_REMOTE_USER`,
  `AUTHENTICATION_GUARD_EMAIL=HTTP_REMOTE_EMAIL`, so it trusts those headers
  and auto-provisions a user on first request.
- Compose runs Firefly plus Postgres. `APP_KEY` and `STATIC_CRON_TOKEN` are
  generated once in PreUp and written to `{DataRoot}/firefly.env` (loaded via
  `env_file`), so they stay stable across container recreation and the
  Laravel-encrypted DB rows remain decryptable.

## Request flow examples

### A user visits `https://nextcloud.example.com`

1. TLS terminates at `proxy.Server`. The host matches the Nextcloud route.
2. Nextcloud has no `OIDCGate`, so the request goes straight through the
   reverse proxy to `127.0.0.1:18080`.
3. Nextcloud sees an unauthenticated request, redirects to its login page,
   user clicks "Log in with nass" → OIDC dance against `auth.example.com` →
   if the user already has a `nass_session`, the IdP completes the request
   without showing a form.

### A user visits `https://qbittorrent.example.com` with no session

1. Proxy matches the qBittorrent route.
2. `OIDCGate` middleware checks for a valid `nass_session` cookie. None.
3. 302 to `https://example.com/portal/login?next=https://qbittorrent.example.com/`.
4. User logs in; cookie is set on `Domain=example.com`.
5. `next` redirect lands them back at qBittorrent, this time the gate lets
   the request through.

## Things that aren't here (yet)

- **Idempotent re-install.** `nass app install <name>` currently fails on the
  second run because the OIDC client already exists. The fix is to detect
  "already installed" early and either no-op, update, or surface a clear
  error.
- **CSRF tokens** on portal admin forms. Today we rely on `SameSite=Lax`
  cookies plus origin/referer checks, which is fine for the threat model
  (single-operator home server) but not great hygiene.
- **A user-management UI.** Today users are managed via `nass user`.
- **Multi-host orchestration.** Apps run on the same machine as `nass serve`.
  No plan to change this.
- **Auto cert renewal / ACME.** Bring your own.
