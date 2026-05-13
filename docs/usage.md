# Usage

A practical guide for operating a nass deployment. For the architecture, read
[design.md](design.md) first.

## Initial setup

```sh
sudo nass init \
  --base-host example.com \
  --admin-user admin \
  --admin-password 'something-good' \
  --cert-file /etc/letsencrypt/live/example.com/fullchain.pem \
  --key-file  /etc/letsencrypt/live/example.com/privkey.pem
```

This creates, in the current directory:

- `nass.toml` — config file. Edit it before `nass serve` if defaults don't
  fit (esp. `orchestrator.data_root` and `orchestrator.compose_root`).
- `oidc.key` — ECDSA P-256 signing key. Treat as a secret. **Back this up.**
  Rotating it invalidates all live tokens.
- `oidc-crypto.key` — 32-byte symmetric key used to encrypt OIDC state
  through redirects. Also a secret.
- `nass.db` — SQLite database. Contains users, sessions, app settings,
  hashed OIDC client secrets, and tokens. Back this up too — this is the
  source of truth for everything except the apps' own data volumes.

`init` refuses to overwrite an existing `nass.toml`.

The TLS cert/key paths from `--cert-file`/`--key-file` are written into
`nass.toml`, not copied. nass reads them from those paths every restart, so
renewing them in place "just works".

## Running the server

```sh
sudo nass serve
```

Logs each route it set up:

```
route: auth.example.com → OIDC
route: example.com → portal
route: nextcloud.example.com → app
serving HTTPS on :443
serving HTTP redirector on :80
```

`SIGINT`/`SIGTERM` triggers a 5-second graceful shutdown.

For development on a machine with no real cert:

```sh
nass serve --no-https --listen :8080 --listen-http "" --insecure
```

That serves plain HTTP on `:8080`, disables the redirector, and lets the
embedded OIDC provider work over HTTP.

### Run under systemd

Minimal unit:

```ini
# /etc/systemd/system/nass.service
[Unit]
Description=nass
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/nass -c /etc/nass/nass.toml serve
Restart=on-failure
RestartSec=5
# Allow binding 80/443 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`nass serve` itself only needs to be able to bind low ports and reach the
docker socket. Driving `docker compose` through the user that owns the
socket is up to you (group membership, rootless docker, etc.).

## Installing apps

```sh
sudo nass app install nextcloud
sudo nass app install jellyfin
sudo nass app install immich
sudo nass app install gitea
sudo nass app install qbittorrent
sudo nass app install blinko
sudo nass app install calibreweb
sudo nass app install linkwarden
sudo nass app install firefly
sudo nass app install paperless
sudo nass app install vaultwarden
sudo nass app install miniflux
sudo nass app install jitsi
```

Each install:

1. Provisions an OIDC client (if the app speaks OIDC).
2. Renders the compose template into
   `/srv/nass/apps/<name>/docker-compose.yaml`.
3. Creates `/srv/nass/data/<name>/` for volumes.
4. Runs `docker compose up -d`.
5. Drives the app's first-boot setup (different per app — see
   [design.md](design.md)).

Each app has a preferred localhost backend port, but nass checks whether it is
free before rendering compose. If the preferred port is busy, nass picks the
first free port from `orchestrator.backend_port_range` and stores that selected
port in the proxy route.

Output looks like:

```
FIELD              VALUE
app                jellyfin
compose_file       /srv/nass/apps/jellyfin/docker-compose.yaml
backend_port       18096
admin_password     a3F2k9m...
oidc_client_id     8c4a91a3d2f7b6e1
oidc_client_secret R8tZ7x...
(secrets shown once; only their hashes are stored)
```

Save those secrets somewhere — the OIDC secret in particular cannot be
recovered later.

### Useful flags

| Flag | When you'd use it |
| --- | --- |
| `--dry-run` | Print what would happen without writing files or running docker. |
| `--subdomain foo` | Override the default subdomain. |
| `--data-root /tank/jellyfin` | Override per-app data path (e.g. media on a different disk). |
| `--admin-password '…'` | Set the per-app admin password instead of letting nass generate one. |
| `--public-port :8443` | If you're not on `:443` (dev). |
| `--backend-port 25001` | Force a specific localhost backend port; install fails if it is busy. |

### Inspect what's installed

```sh
nass app available   # everything compiled into the binary
nass app list        # what's actually configured in this DB
```

### Disable / re-enable a route

`disable` stops the proxy from routing to the app but leaves the containers
running:

```sh
nass app disable nextcloud
nass app enable nextcloud --subdomain nextcloud --backend http://127.0.0.1:18080
```

To stop containers and remove an installed app from nass entirely, use
`uninstall` instead.

### Uninstalling

```sh
sudo nass app uninstall nextcloud --yes
```

This runs `docker compose down -v --remove-orphans`, removes the app row,
removes its OIDC client and issued tokens, deletes the managed data folder,
and removes the generated compose file.

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--keep-data` | Leave the app data folder on disk. |
| `--force` | Continue DB/file cleanup even if `docker compose down` fails. |
| `--yes` | Required confirmation for destructive uninstall. |

To only stop containers without removing nass state:

```sh
sudo docker compose -f /srv/nass/apps/nextcloud/docker-compose.yaml down
```

### Re-installing

Re-running `nass app install` on an already-installed app fails because the
OIDC client row already exists. Uninstall first, then install again:

```sh
sudo nass app uninstall <name> --yes
sudo nass app install <name>
```

Use `--keep-data` when you want to preserve the data folder and only rebuild
the compose file / OIDC client.

## Managing users

```sh
nass user list
nass user add alice --email alice@example.com           # prompts for password
echo 'pw' | NASS_PASSWORD=... nass user passwd alice    # also accepts stdin
nass user rm alice
nass user add bob --admin                               # admin = portal admin tab
```

User entries back portal logins, admin access, and OIDC `sub` claims.
There's no email-verification or password-reset flow yet; for self-service,
you're on `nass user passwd` over SSH.

## Managing OIDC clients directly

`nass app install` provisions a client automatically — you only need these
commands for clients that aren't backed by a registry app, or for repairs.

```sh
nass oidc-client list
nass oidc-client add my-thing \
  --redirect-uri https://my-thing.example.com/oauth/callback
nass oidc-client rm my-thing
```

`add` prints the plaintext `client_id` and `client_secret` once. They cannot
be retrieved again — only the bcrypt hash is stored.

## Backups

The minimum to back up:

- `nass.toml`
- `oidc.key`
- `oidc-crypto.key`
- `nass.db` (use `sqlite3 nass.db ".backup target.db"` for a consistent
  copy while `nass serve` is running)
- `/srv/nass/data/` — actual app data (Nextcloud files, Jellyfin library,
  etc.)

`/srv/nass/apps/` is regenerated by `nass app install` from templates in
the binary, so it's fine to lose.

## Troubleshooting

### A new app's tile is "stopped" or "unknown" on the dashboard

The dashboard runs `docker compose ps --format json` against the app's
compose file. If the file's missing or the user running `nass serve` can't
talk to the docker socket, you get `unknown`. Check:

```sh
sudo -u <nass-user> docker compose -f /srv/nass/apps/<name>/docker-compose.yaml ps
```

### `nass app install` hangs on PostUp

PostUp waits for the app's HTTP API to come up (5-minute budget for most
apps). If the container's still starting (cold image pull, slow disk),
that's fine. If it's stuck:

```sh
sudo docker compose -f /srv/nass/apps/<name>/docker-compose.yaml logs --tail=200
```

Common causes: out-of-disk on `/srv/nass/data`, wrong port already bound on
the host, or the container can't resolve `auth.<base_host>` (check
`extra_hosts` is set in the compose file).

### "OIDC discovery URL not reachable from container"

Apps fetch `https://auth.<base_host>/.well-known/openid-configuration` from
*inside* the container. The compose templates add
`auth.<base_host>:host-gateway` to `extra_hosts` so the hostname resolves to
the docker host, but TLS still has to validate. If you used a private CA,
mount the CA cert into the container or use Let's Encrypt.

### Lost the admin password

```sh
sudo nass user passwd admin
```

Reads new password from stdin or `NASS_PASSWORD`.

### The proxy isn't picking up an app I installed

`nass serve` syncs from the DB every 30 seconds. If you don't want to wait,
restart `serve`. If a re-sync still doesn't pick it up, check `nass app
list` — the row needs `enabled=true`. (`nass app install` sets this; manual
DB edits don't.)

### Re-running `init` says "nass.toml already exists"

That's the safety check. To start over: stop `nass serve`, move the existing
`nass.toml`/`oidc.key`/`oidc-crypto.key`/`nass.db` aside, then re-run
`init`. Keep in mind that a new `oidc.key` invalidates every issued token
and every OIDC-using app will need its client re-provisioned.

## Useful one-liners

```sh
# What ports are the apps listening on?
nass app available

# Stop everything but keep data:
for app in nextcloud jellyfin immich gitea qbittorrent blinko calibreweb linkwarden firefly paperless vaultwarden miniflux jitsi; do
  sudo docker compose -f /srv/nass/apps/$app/docker-compose.yaml stop
done

# Update an app's image (edit the compose file, then):
sudo docker compose -f /srv/nass/apps/<name>/docker-compose.yaml pull
sudo docker compose -f /srv/nass/apps/<name>/docker-compose.yaml up -d

# Inspect the current OIDC discovery doc:
curl https://auth.example.com/.well-known/openid-configuration | jq .
```
