# nass

A single Go binary that turns a Linux box into a self-hosted multi-app server.
It replaces the usual stack of **nginx + Casdoor + Flame + a pile of bash
scripts** with one process that:

- Terminates TLS and reverse-proxies requests to per-app docker-compose stacks.
- Issues OpenID Connect tokens (built-in IdP) for apps that speak OIDC.
- Gates apps that don't speak OIDC behind a session cookie issued by its portal.
- Manages app installs end-to-end: provision an OIDC client, render the compose
  file, run `docker compose up -d`, drive any first-boot setup the app needs.
- Shows a portal dashboard with each app's tile, status, and link.

## Supported Apps

These apps are bundled in the binary and can be installed with
`nass app install <name>`:

| App | Install name | Purpose | Auth mode |
| --- | --- | --- | --- |
| Nextcloud | `nextcloud` | Files, calendar, contacts | Native OIDC |
| Jellyfin | `jellyfin` | Media server | Native OIDC |
| Immich | `immich` | Photos and videos | Native OIDC |
| Gitea | `gitea` | Lightweight Git hosting | Native OIDC |
| qBittorrent | `qbittorrent` | Torrent client | Portal gate |
| Blinko | `blinko` | AI note-taking | Native OIDC |
| Linkwarden | `linkwarden` | Bookmark and web archive manager | Native OIDC |
| Firefly III | `firefly` | Personal finance manager | Portal gate (remote user) |
| Paperless-ngx | `paperless` | Document management for scanned paper | Native OIDC |
| Vaultwarden | `vaultwarden` | Bitwarden-compatible password manager | Native OIDC |
| Miniflux | `miniflux` | Minimalist RSS reader | Native OIDC |
| Jitsi Meet | `jitsi` | Video conferencing | Portal gate (requires UDP 10000) |

```
                         ┌──────────── nass ────────────┐
   :443 / :80  ─────────►│  TLS proxy (host-based)      │
                         │   ├─ auth.<host>  → OIDC IdP │
                         │   ├─ <host>       → portal   │
                         │   └─ <app>.<host> → app      │──► docker compose
                         │                              │     stack(s)
                         │  SQLite: users, sessions,    │
                         │  apps, OIDC clients/tokens   │
                         └──────────────────────────────┘
```

## Status

Early. The binary works end-to-end on a single host with the bundled apps above,
but there are sharp edges (no idempotent re-install, no CSRF token — relying on
SameSite + Origin checks, no portal user-management UI yet). See
[docs/design.md](docs/design.md) for the architecture and
[docs/usage.md](docs/usage.md) for operational details.

## Requirements

- Linux host with Docker + the `docker compose` plugin.
- A wildcard DNS record (`*.example.com`) pointing at the host.
- A TLS cert/key pair that covers the base host and `*.<base host>` (Let's
  Encrypt DNS-01, mkcert, whatever you like). Dev modes exist (`--no-https`,
  `--insecure`) if you want to try it on localhost first.
- Go 1.26+ to build (or grab a release binary once they exist).

## Install

```sh
git clone https://github.com/jdxin0/nass
cd nass
go build -o nass ./cmd/nass
sudo install -m 0755 nass /usr/local/bin/
```

## Quickstart

```sh
# 1. One-shot init: writes nass.toml, generates signing keys, creates the
#    SQLite DB, creates the admin user.
sudo nass init \
  --base-host example.com \
  --admin-user admin \
  --admin-password 'choose-something-good' \
  --cert-file /etc/letsencrypt/live/example.com/fullchain.pem \
  --key-file  /etc/letsencrypt/live/example.com/privkey.pem

# 2. Edit nass.toml if you want to move data_root / compose_root off the
#    defaults (/srv/nass/data, /srv/nass/apps).

# 3. Start the server (binds :80 + :443; needs CAP_NET_BIND_SERVICE or root).
sudo nass serve

# 4. From another shell: install an app. This provisions an OIDC client,
#    writes the compose file, runs `docker compose up -d`, drives first-boot
#    setup.
sudo nass app install nextcloud
sudo nass app install jellyfin
sudo nass app install immich
sudo nass app install gitea
sudo nass app install qbittorrent
sudo nass app install blinko
sudo nass app install linkwarden
sudo nass app install firefly
sudo nass app install paperless
sudo nass app install vaultwarden
sudo nass app install miniflux
sudo nass app install jitsi
```

Now `https://nextcloud.example.com`, `https://jellyfin.example.com`, etc.
should be reachable, and the dashboard at `https://example.com` shows the tiles.

## Commands

| Command | What it does |
| --- | --- |
| `nass init` | Generate config, signing keys, DB, admin user. One-shot. |
| `nass serve` | Run the long-lived process: TLS proxy + OIDC IdP + portal. |
| `nass app available` | List apps registered in the binary. |
| `nass app install <name>` | Full install: provision OIDC, render compose, `docker compose up -d`, run app's PostUp setup. |
| `nass app uninstall <name>` | Stop and remove an installed app, its OIDC client, and its managed files. |
| `nass app list` | List apps the proxy is currently serving. |
| `nass app enable <name>` | Manually configure a proxy route (for an app you set up by hand). |
| `nass app disable <name>` | Stop serving an app at the proxy (does not touch its containers). |
| `nass user add\|list\|rm\|passwd` | Manage portal/IdP users. |
| `nass oidc-client add\|list\|rm` | Manage OIDC clients (mostly used internally by `app install`). |

Every subcommand has `--help`. Most accept `-c /path/to/nass.toml` to point
at a non-default config.

## Configuration

Defaults are in [`nass.toml.sample`](nass.toml.sample). Relative paths are
resolved against the directory of `nass.toml`.

| Section | Key | Default | What it controls |
| --- | --- | --- | --- |
| `server` | `https_addr` | `:443` | HTTPS listener. |
| `server` | `http_addr` | `:80` | HTTP→HTTPS redirector (empty disables). |
| `server` | `base_host` | (required) | Hostname suffix; subdomains routed under this. |
| `tls` | `cert_file` / `key_file` | — | TLS cert + key, must cover `*.<base_host>`. |
| `db` | `path` | `nass.db` | SQLite DB. |
| `oidc` | `issuer` | `https://<oidc.subdomain>.<base_host>` | OIDC issuer URL. |
| `oidc` | `subdomain` | `auth` | Subdomain the IdP listens on. |
| `oidc` | `key_file` | `oidc.key` | ECDSA P-256 signing key (PEM PKCS#8). |
| `oidc` | `crypto_key_file` | `oidc-crypto.key` | 32-byte symmetric key for state encryption. |
| `portal` | `title` | `nass` | Page title. |
| `portal` | `subdomain` | `""` | Empty = portal at root of `base_host`. |
| `orchestrator` | `data_root` | `/srv/nass/data` | App data volumes live under here. |
| `orchestrator` | `compose_root` | `/srv/nass/apps` | Per-app `docker-compose.yaml` lives here. |
| `orchestrator` | `docker_compose` | `docker compose` | Argv tokens for the compose CLI. |
| `orchestrator` | `backend_port_range` | `20000-29999` | Fallback localhost port range when an app's preferred port is busy. |

## Documentation

- [Design](docs/design.md) — component breakdown, request flow, install
  pipeline, DB schema, why-it's-shaped-this-way notes.
- [Usage](docs/usage.md) — day-to-day operations: adding apps, managing
  users, recovering from common problems.
- [Adding an app](docs/adding-an-app.md) — step-by-step guide for bundling a
  new app into the binary.

## Layout

```
cmd/nass/             # binary entry point
internal/
  apps/               # app registry + install pipeline
    blinko/
    firefly/
    nextcloud/        # one package per app
    gitea/
    jellyfin/
    jitsi/
    linkwarden/
    immich/
    miniflux/
    paperless/
    qbittorrent/
    vaultwarden/
  auth/
    oidc/             # built-in OpenID Connect provider
    users.go          # password-auth user store (bcrypt)
  cli/                # cobra subcommands
  config/             # nass.toml loader
  db/                 # SQLite open + embedded migrations
  orchestrator/       # docker-compose shell-out
  portal/             # session cookies, login page, dashboard, admin
  proxy/              # HTTPS server, host router, dynamic route manager
```

## License

Not yet chosen — open an issue if you want to use this and need clarity.
