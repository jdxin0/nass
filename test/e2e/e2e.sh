#!/usr/bin/env bash
# End-to-end check of nass's auth, proxy and lifecycle behaviour against a
# real `nass serve`. No Docker or root needed; requires curl and python3.
#
#   go build -o /tmp/nass ./cmd/nass
#   test/e2e/e2e.sh /tmp/nass /tmp/nass-e2e     # work dir is wiped first
#
# Runs nass on 127.0.0.1:18080 in --no-https dev mode, with base host
# nass.test (curl --connect-to maps every host to the local listener), in the
# America/New_York timezone so UTC-vs-local timestamp bugs show up. Docker is
# replaced by `false`, so "docker compose" always fails.
#
# SKIP_BAD=1 leaves out the deliberately broken app rows. Useful against
# older builds, which refuse to start with them and so hide every other check.
# Uses ports 18080 and 19999 on 127.0.0.1.
set -u
BIN=$(realpath "$1"); W=$2
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=18080
export TZ=America/New_York

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; [ -n "${2:-}" ] && echo "        got: $2"; fail=$((fail+1)); }
expect_eq()       { [ "$2" = "$3" ] && ok "$1" || bad "$1 (want: $3)" "$2"; }
expect_contains() { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (want to contain: $3)" "$2";; esac; }
expect_absent()   { case "$2" in *"$3"*) bad "$1 (must not contain: $3)" "$2";; *) ok "$1";; esac; }

sql() { python3 -I -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2], sys.argv[3:]).fetchall(); c.commit(); print("\n".join("|".join(map(str,x)) for x in r))' "$W/nass.db" "$@"; }
# curl printing "status|redirect_url"; $1 = cookie jar, rest = curl args
hit() { local jar=$1; shift; curl -s -o /dev/null -w '%{http_code}|%{redirect_url}' --connect-to "::127.0.0.1:$PORT" -b "$jar" -c "$jar" "$@"; }
login() { hit "$1" -X POST http://nass.test/portal/login --data-urlencode "username=$2" --data-urlencode "password=$3" --data-urlencode "next=$4"; }
qparam() { python3 -I -c 'import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query)[sys.argv[2]][0])' "$1" "$2"; }

rm -rf "$W"; mkdir -p "$W"; cd "$W" || exit 1
cleanup() { [ -f serve.pid ] && kill "$(cat serve.pid)" 2>/dev/null; [ -f backend.pid ] && kill "$(cat backend.pid)" 2>/dev/null; }
trap cleanup EXIT

echo "== setup ($BIN, TZ=$TZ)"
"$BIN" init --base-host nass.test --admin-user admin --admin-password e2e-admin-pass >/dev/null || exit 1
sed -i -e "s#^\s*issuer\s*=.*#issuer = \"http://auth.nass.test:$PORT\"#" \
       -e "s#^\s*data_root\s*=.*#  data_root = \"$W/data\"#" \
       -e "s#^\s*compose_root\s*=.*#  compose_root = \"$W/apps\"#" \
       -e 's#^\s*docker_compose\s*=.*#  docker_compose = "false"#' nass.toml
N="$BIN -c $W/nass.toml"
$N user add alice --password alice-password-1 >/dev/null
$N app enable demo --subdomain demo --backend http://127.0.0.1:19999 --oidc-gate >/dev/null
$N oidc-client add myapp --redirect-uri http://myapp.test/cb > client.txt 2>&1
$N app enable myapp --subdomain myapp --backend http://127.0.0.1:19999 >/dev/null
CLIENT_ID=$(awk '/client_id/{print $2}' client.txt)

# An app whose compose file and data folder exist, for the forced-uninstall check.
mkdir -p "$W/apps/olddata" "$W/data/olddata" && echo 'services: {}' > "$W/apps/olddata/docker-compose.yaml" && echo precious > "$W/data/olddata/db.sqlite"
sql "INSERT INTO apps(name, enabled, settings_json) VALUES ('olddata', 1, ?)" \
    "{\"subdomain\":\"olddata\",\"backend\":\"http://127.0.0.1:19998\",\"compose_file\":\"$W/apps/olddata/docker-compose.yaml\",\"data_root\":\"$W/data/olddata\"}" >/dev/null

# One expired (two days ago) and one live session for the purge check, in UTC.
ALICE_ID=$(sql "SELECT id FROM users WHERE username='alice'")
sql "INSERT INTO portal_sessions(id,user_id,expires_at) VALUES ('stale-session', ?, datetime('now','-2 days')), ('live-session', ?, datetime('now','+1 day'))" "$ALICE_ID" "$ALICE_ID" >/dev/null

if [ -z "${SKIP_BAD:-}" ]; then
  # Bad rows written straight to the DB, bypassing CLI validation.
  sql "INSERT INTO apps(name, enabled, settings_json) VALUES ('broken', 1, '{\"subdomain\":\"broken\",\"backend\":\"127.0.0.1:1\"}')" >/dev/null
  sql "INSERT INTO apps(name, enabled, settings_json) VALUES ('sneaky', 1, '{\"subdomain\":\"auth\",\"backend\":\"http://127.0.0.1:19999\"}')" >/dev/null
fi

python3 -I "$HERE/echo_backend.py" & echo $! > backend.pid
$N serve --no-https --listen "127.0.0.1:$PORT" --listen-http "" > serve.log 2>&1 & echo $! > serve.pid
for _ in $(seq 1 50); do curl -s -o /dev/null --connect-to "::127.0.0.1:$PORT" http://nass.test/ && break; sleep 0.2; done

echo "== startup with misconfigured apps (finding 6) and reserved host (finding 7)"
if kill -0 "$(cat serve.pid)" 2>/dev/null; then ok "nass serve is running"; else bad "nass serve is running" "$(tail -3 serve.log)"; fi
if [ -z "${SKIP_BAD:-}" ]; then
  expect_contains "broken app is reported, not fatal" "$(cat serve.log)" "app broken"
  expect_contains "app on the auth subdomain is refused" "$(cat serve.log)" "reserved"
  expect_contains "auth host still serves the IdP" "$(curl -s --connect-to ::127.0.0.1:$PORT http://auth.nass.test:$PORT/.well-known/openid-configuration)" '"issuer"'
fi
expect_contains "CLI refuses 'app enable --subdomain auth'" "$($N app enable x --subdomain auth --backend http://127.0.0.1:1 2>&1)" "reserved"

echo "== expired-row purge at startup (finding 10)"
expect_eq "stale session deleted, live one kept" "$(sql "SELECT group_concat(id) FROM portal_sessions WHERE id IN ('stale-session','live-session')")" "live-session"

echo "== gated app: return after login (finding 1)"
J=$W/admin.jar
R=$(hit "$J" 'http://demo.nass.test/hello?x=1')
expect_contains "unauthenticated request goes to portal login" "$R" "302|http://nass.test/portal/login?next="
NEXT=$(qparam "${R#*|}" next)
expect_eq "login lands back on the gated app" "$(login "$J" admin e2e-admin-pass "$NEXT")" "302|http://demo.nass.test/hello?x=1"

echo "== session cookie never reaches the app (finding 2)"
SAW=$(curl -s --connect-to "::127.0.0.1:$PORT" -b "$J" -H 'Cookie: other=keep' 'http://demo.nass.test/hello?x=1')
expect_contains "gate let the signed-in user through" "$SAW" "Remote-User=admin"
expect_contains "other cookies still forwarded" "$SAW" "other=keep"
expect_absent  "nass_session stripped" "$SAW" "nass_session"

echo "== open redirect (finding 3)"
expect_eq 'next=/\evil.com is refused' "$(login "$W/x.jar" admin e2e-admin-pass '/\evil.com')" "302|http://nass.test/"
expect_eq "next=https://evil.com is refused" "$(hit "$J" 'http://nass.test/portal/login?next=https://evil.com/')" "302|http://nass.test/"

echo "== native OIDC SSO, signed out first (finding 1 + UTC timestamps)"
J2=$W/sso.jar
R=$(hit "$J2" "http://auth.nass.test:$PORT/authorize?client_id=$CLIENT_ID&redirect_uri=http%3A%2F%2Fmyapp.test%2Fcb&response_type=code&scope=openid&state=st123")
expect_contains "authorize accepted the request" "$R" "302|http://auth.nass.test:$PORT/login?authRequestID="
R=$(hit "$J2" "${R#*|}")
expect_contains "IdP sends signed-out user to portal" "$R" "302|http://nass.test/portal/login?next="
NEXT=$(qparam "${R#*|}" next)
expect_contains "next is an absolute IdP URL" "$NEXT" "http://auth.nass.test:$PORT/login?authRequestID="
R=$(login "$J2" admin e2e-admin-pass "$NEXT")
expect_eq "portal login returns to the IdP" "$R" "302|$NEXT"
R=$(hit "$J2" "${R#*|}")
expect_contains "IdP completes the request (not expired)" "$R" "/authorize/callback?id="
R=$(hit "$J2" "${R#*|}")
expect_contains "app receives an authorization code" "$R" "302|http://myapp.test/cb?code="

echo "== password reset revokes sessions (finding 4)"
JA=$W/alice.jar
login "$JA" alice alice-password-1 / >/dev/null
expect_eq "alice signed in" "$(hit "$JA" http://nass.test/)" "200|"
hit "$J" -X POST "http://nass.test/portal/admin/users/$ALICE_ID/password" --data-urlencode password=alice-password-2 >/dev/null
expect_contains "alice's old session no longer works" "$(hit "$JA" http://nass.test/)" "302|http://nass.test/portal/login"
expect_eq "admin who did the reset stays signed in" "$(hit "$J" http://nass.test/)" "200|"

echo "== forced uninstall keeps data when compose down fails (finding 5)"
OUT=$($N app uninstall olddata --yes --force 2>&1); RC=$?
[ $RC -ne 0 ] && ok "uninstall reports the failure (exit $RC)" || bad "uninstall reports the failure" "exit 0: $OUT"
expect_contains "message says containers may still run" "$OUT" "may still be running"
[ -f "$W/data/olddata/db.sqlite" ] && ok "data folder kept" || bad "data folder kept" "deleted"
[ -f "$W/apps/olddata/docker-compose.yaml" ] && ok "compose file kept" || bad "compose file kept" "deleted"
expect_eq "app row removed from nass" "$(sql "SELECT COUNT(*) FROM apps WHERE name='olddata'")" "0"

echo "== username timing (finding 9)"
t() { local s; s=$(date +%s%N); login "$W/t.jar" "$1" wrong-password / >/dev/null; echo $(( ($(date +%s%N) - s) / 1000000 )); }
known=0; unknown=0
for _ in 1 2 3 4; do known=$((known + $(t alice))); unknown=$((unknown + $(t "nobody-$RANDOM"))); done
echo "        known user: $((known/4)) ms avg, unknown user: $((unknown/4)) ms avg"
[ $((unknown * 2)) -ge "$known" ] && ok "unknown usernames take as long as known ones" || bad "unknown usernames take as long as known ones" "unknown $((unknown/4)) ms vs known $((known/4)) ms"

echo "== login throttle: per-IP budget across usernames (finding 8)"
blocked_at=""
for i in $(seq 1 40); do
  body=$(curl -s --connect-to "::127.0.0.1:$PORT" -X POST http://nass.test/portal/login \
         --data-urlencode "username=spray-$i" --data-urlencode password=Summer2026 --data-urlencode next=/)
  case "$body" in *"too many attempts"*) blocked_at=$i; break;; esac
done
# 8 failures above + 30-per-IP budget: blocked well before 40 fresh usernames.
[ -n "$blocked_at" ] && ok "spraying is blocked after $blocked_at fresh usernames" || bad "spraying is blocked" "40 fresh usernames, never blocked"

echo
echo "RESULT: $pass passed, $fail failed"
[ $fail -eq 0 ]
