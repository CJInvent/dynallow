#!/usr/bin/env bash
# Repository hygiene gate: what must never be committed, and what must stay true.
set -euo pipefail
cd "$(dirname "$0")/.."
bad=0
fail() { printf 'HYGIENE FAIL: %s\n' "$*"; bad=1; }

# 1. Runtime state, credentials and build output are never tracked.
while IFS= read -r f; do fail "tracked file that must not be committed: $f"; done < <(git ls-files | grep -E \
  'agents/windows-native/bin/|(^|/)(obj|__pycache__|artifacts)/|\.sqlite(-|$)|(^|/)secret\.key$|\.dynbak$|(^|/)provisioning\.json$|dynallow-agt_[^/]*\.(json|sh)$|(^|/)\.env$|\.pyc$|(^|/)release-(public|private)[^/]*\.pem$' || true)

# 2. No private key material in any tracked file. (Pattern built from parts so this file never matches itself.)
marker="-----BEGIN"; kinds="(EC |ENCRYPTED |RSA )?PRIVATE KEY-----"
while IFS= read -r f; do fail "private key material in $f"; done < <(git grep -lIE -- "${marker} ${kinds}" || true)

# 3. The old product name survives only where it is load-bearing (migration, frozen identifiers).
allowed='^(README\.md|docs/upgrading\.md|docs/7-troubleshooting\.md|docs/8-native-agents-and-releases\.md|docs/review-2026-10-16\.md|TEST-LEDGER\.md|tests/README\.md|tests/review_v4\.py|ControlServer/agents/docker/agent\.php'
allowed+='|ControlServer/src/db\.php|ControlServer/bin/manage\.php|ControlServer/agents/docker/install\.sh|ControlServer/deploy/docker/entrypoint\.sh'
allowed+='|ControlServer/agents/windows-native/(Program|Crypto|Tray|Install|Native|SelfTest|Profile)\.cs|tests/windows-smoke\.ps1|tests/hygiene\.sh)$'
while IFS= read -r f; do
  [[ "$f" =~ $allowed ]] || fail "old product name in $f (add it to the allowlist in tests/hygiene.sh only if it is a migration path)"
done < <(git grep -lIiE 'ipfailover|ip failover' || true)

# 4. Relative links in Markdown resolve.
while IFS= read -r md; do
  dir=$(dirname "$md")
  while IFS= read -r link; do
    target=${link%%#*}; [ -z "$target" ] && continue
    [ -e "$dir/$target" ] || fail "$md links to missing $target"
  done < <(grep -oE '\]\([^)]+\)' "$md" | sed -E 's/^\]\(//; s/\)$//' | grep -vE '^(https?:|mailto:|#)' || true)
done < <(git ls-files '*.md')

# 5. Shell scripts that run on Linux hosts keep LF line endings.
while IFS= read -r f; do grep -q $'\r' "$f" && fail "CRLF line endings in $f"; done < <(git ls-files '*.sh')

[ $bad -eq 0 ] && echo 'Repository hygiene: OK'
exit $bad
