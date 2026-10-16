#!/usr/bin/env bash
# Assembles a dev release from the Windows job's output. Used by .github/workflows/dev-release.yml.
#   TAG=v3.1.0-dev.7 N=7 BASE=3.1.70 BASE_SEQ=70 UPDATE=3.1.71 tools/package-dev-release.sh <built-dir> <out-dir>
# <built-dir> holds DynAllow.Agent.exe(.build.json), release-public.pem, key-info.json and the
# signed dynallow-update-test-*.json bundles.
set -euo pipefail
cd "$(dirname "$0")/.."
in=$(cd "$1" && pwd); mkdir -p "$2"; out=$(cd "$2" && pwd)
: "${TAG:?}" "${N:?}" "${BASE:?}" "${BASE_SEQ:?}" "${UPDATE:?}"
for f in DynAllow.Agent.exe DynAllow.Agent.exe.build.json release-public.pem key-info.json \
         "dynallow-update-test-windows-x64-$UPDATE.json" "dynallow-update-test-docker-$UPDATE.json"; do
  [ -s "$in/$f" ] || { echo "missing build output: $f"; exit 1; }
done
fp=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fingerprint"])' "$in/key-info.json")
mode=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["mode"])' "$in/key-info.json")
commit=$(git rev-parse HEAD)

# ---- control server -----------------------------------------------------------------------
srv="$out/dynallow-server-$TAG"
rm -rf "$srv"; mkdir -p "$srv"
git archive HEAD ControlServer | tar -x -C "$out/" --strip-components=1 --one-top-level="$(basename "$srv")"
rm -rf "$srv/agents/windows-native"
sed -i "s/define('APP_VERSION', '[0-9.]*');/define('APP_VERSION', '$BASE');/" "$srv/src/bootstrap.php"
sed -i -e "s/const AGENT_VERSION = '[0-9.]*';/const AGENT_VERSION = '$BASE';/" \
       -e "s/const RELEASE_SEQUENCE = [0-9]*;/const RELEASE_SEQUENCE = $BASE_SEQ;/" "$srv/agents/docker/agent.php"
grep -q "define('APP_VERSION', '$BASE');" "$srv/src/bootstrap.php"
grep -q "const AGENT_VERSION = '$BASE';" "$srv/agents/docker/agent.php"
grep -q "const RELEASE_SEQUENCE = $BASE_SEQ;" "$srv/agents/docker/agent.php"
cp "$in/release-public.pem" "$srv/release-public.pem"
cat > "$srv/INSTALL.txt" <<EOF
DynAllow control server $BASE (dev build $N, commit ${commit:0:12})

You need: a Linux host with Docker Engine and the Compose plugin.

1. Copy this folder to the host and go into it.
2. cp .env.example .env      then edit .env (port, admin name, reverse proxy, time zone)
3. docker compose up -d --build
4. docker compose logs server    shows the admin password if you left DYNALLOW_PASSWORD empty
5. Open http://<host>:<port>, sign in, then Settings -> General -> Public URL for agents.

release-public.pem is this build's release trust key (SHA256 $fp).
The Releases page must show the same fingerprint. Back up ./data (docker compose exec server
php bin/manage.php backup /var/www/dynallow/data/backup.dynbak).
EOF
tar -C "$out" -czf "$out/dynallow-server-$TAG.tar.gz" "$(basename "$srv")"
rm -rf "$srv"

# ---- Windows agent ------------------------------------------------------------------------
win="$out/DynAllow.Agent-$BASE-win-x64"
rm -rf "$win"; mkdir -p "$win"
cp "$in/DynAllow.Agent.exe" "$in/DynAllow.Agent.exe.build.json" "$win/"
cat > "$win/INSTALL.txt" <<EOF
DynAllow Windows agent $BASE (dev build $N, x64)

DEV BUILD: not Authenticode-signed, so SmartScreen or Defender may warn before it runs.
It accepts updates signed only by this build's release key (SHA256 $fp).

1. On the server: open the site, click "Download Windows profile" (a .json file).
2. Copy DynAllow.Agent.exe and that .json to the PC.
3. In an elevated PowerShell in that folder:
     .\\DynAllow.Agent.exe install --profile .\\dynallow-agt_xxxx.json
4. The site turns green on the server within a minute or two.
   The tray icon appears at the next sign-in, or now with:  .\\DynAllow.Agent.exe tray

Status: .\\DynAllow.Agent.exe status      Check now: .\\DynAllow.Agent.exe check
Remove: .\\DynAllow.Agent.exe uninstall   (add --purge to destroy the identity too)
EOF
(cd "$out" && zip -q -r "$(basename "$win").zip" "$(basename "$win")")
rm -rf "$win"

# ---- update-test bundles, checksums, notes -------------------------------------------------
cp "$in/dynallow-update-test-windows-x64-$UPDATE.json" "$in/dynallow-update-test-docker-$UPDATE.json" "$out/"
(cd "$out" && sha256sum ./*.tar.gz ./*.zip ./*.json | sed 's# \./# #' > SHA256SUMS)
cat > "$out/RELEASE-NOTES.md" <<EOF
Dev build **$N** of commit \`${commit:0:12}\`. For test deployments and the [test ledger](https://github.com/${GITHUB_REPOSITORY:-CJInvent/dynallow}/blob/$commit/TEST-LEDGER.md), not customers.

| File | What it is |
|---|---|
| \`dynallow-server-$TAG.tar.gz\` | Control server for Docker Compose. Agents installed from it are Docker agent $BASE. |
| \`DynAllow.Agent-$BASE-win-x64.zip\` | Windows agent $BASE (Native AOT, x64). Not Authenticode-signed. |
| \`dynallow-update-test-windows-x64-$UPDATE.json\` | Signed Windows release $UPDATE: upload on **Releases** to test a remote update. |
| \`dynallow-update-test-docker-$UPDATE.json\` | Signed Docker agent release $UPDATE, same purpose. |
| \`SHA256SUMS\` | Checksums for all of the above. |

Release trust key: **$mode**, SHA256 \`$fp\`. The server's Releases page must show the same fingerprint.
Install steps: [README](https://github.com/${GITHUB_REPOSITORY:-CJInvent/dynallow}/blob/$commit/README.md#deploy-a-dev-test-environment).
EOF
ls -l "$out"
