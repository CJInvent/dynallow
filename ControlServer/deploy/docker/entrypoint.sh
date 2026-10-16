#!/bin/sh
# DynAllow control server container: first-run setup, cron loop, Apache.
set -eu
APP=/var/www/dynallow
DATA=$APP/data
as_www() { setpriv --reuid=www-data --regid=www-data --init-groups "$@"; }
say() { printf '[dynallow] %s\n' "$*"; }

mkdir -p "$DATA"
chown www-data:www-data "$DATA"
chmod 750 "$DATA"

# The release trust anchor is mounted read-only. Docker turns a missing file into an empty directory.
if [ -d "$APP/release-public.pem" ]; then
    say "ERROR: release-public.pem is missing on the host (Docker made a directory in its place)."
    say "Put the PUBLIC release key next to docker-compose.yml as release-public.pem, delete the empty directory, and start again."
    exit 1
fi
[ -f "$APP/release-public.pem" ] || say "WARNING: no release-public.pem mounted. Docker installers and signed updates are disabled until it is."

if [ ! -f "$DATA/dynallow.sqlite" ] && [ ! -f "$DATA/ipfailover.sqlite" ]; then
    export DYNALLOW_ADMIN="${DYNALLOW_ADMIN:-admin}"
    generated=""
    if [ -z "${DYNALLOW_PASSWORD:-}" ]; then
        generated=$(php -r 'echo rtrim(strtr(base64_encode(random_bytes(18)), "+/", "-_"), "=");')
        export DYNALLOW_PASSWORD="$generated"
    fi
    as_www php "$APP/bin/manage.php" init
    say "First start: created admin user '$DYNALLOW_ADMIN'."
    [ -n "$generated" ] && say "Generated password (shown ONCE, change it after signing in): $generated"
    unset DYNALLOW_PASSWORD generated
fi
unset DYNALLOW_PASSWORD 2>/dev/null || true

# Alerts, DNS retries, drift checks. The dashboard shows a red banner if this ever stops.
( while :; do as_www php "$APP/bin/cron.php" || say "cron run failed (exit $?)"; sleep 60; done ) &

# Exec Apache itself (not apache2ctl) so `docker stop` reaches it directly.
set +u; . /etc/apache2/envvars; set -u
mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR"
exec apache2 -D FOREGROUND
