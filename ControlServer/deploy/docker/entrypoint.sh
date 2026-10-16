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

# Release trust: the PUBLIC key in the read-only ./trust mount (production), or development mode.
KEY="${DYNALLOW_RELEASE_KEY_FILE:-$APP/release-public.pem}"
case "${DYNALLOW_ALLOW_DEV_RELEASES:-0}" in
    1|true|yes|on) say "DEVELOPMENT server: agent releases are checked by SHA-256 only. Never use this for customers." ;;
    *) [ -f "$KEY" ] || say "WARNING: no release key at $KEY. Docker installers and agent updates stay off until it is there (or set DYNALLOW_ALLOW_DEV_RELEASES=1 on a dev server)." ;;
esac

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
