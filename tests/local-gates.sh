#!/usr/bin/env bash
# The CI gate set in one command, minus the Windows job (that needs a Windows machine).
#   tests/local-gates.sh                 lint, hygiene, portable suite
#   sudo tests/local-gates.sh --docker   ...plus the real-Docker end-to-end test
# Needs PHP 8.3 (pdo_sqlite, sodium), Python 3, .NET 10 SDK. pwsh is used if present
# (or set PWSH=/path/to/pwsh). PHP / DOTNET override those executables.
# Under GitHub Actions a failing gate is also reported as an ::error annotation with its
# last output lines, because annotations stay readable when job logs are not.
set -euo pipefail
cd "$(dirname "$0")/.."
export PHP=${PHP:-php}
ran=(); skipped=()

gate() {
  local name=$1; shift
  local log; log=$(mktemp)
  printf '\n== %s\n' "$name"
  if "$@" 2>&1 | tee "$log"; then
    ran+=("$name"); rm -f "$log"
  else
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      printf '::error title=Gate failed: %s::%s\n' "$name" "$(tail -n 30 "$log" | sed 's/%/%25/g' | sed ':a;N;$!ba;s/\n/%0A/g')"
    fi
    rm -f "$log"
    echo "GATE FAILED: $name"
    exit 1
  fi
}

php_lint() { git ls-files '*.php' | while IFS= read -r f; do "$PHP" -l "$f" >/dev/null || { echo "PHP syntax error: $f"; return 1; }; done; }
shell_lint() {
  git ls-files '*.sh' | while IFS= read -r f; do
    if head -1 "$f" | grep -q bash; then bash -n "$f"; else sh -n "$f"; fi || { echo "shell syntax error: $f"; return 1; }
  done
}
python_lint() { python3 -c 'import ast,sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]' $(git ls-files '*.py'); }
powershell_parse() {
  local list; list=$(git ls-files '*.ps1' | sed "s/.*/'&'/" | paste -sd, -)
  "${PWSH:-pwsh}" -NoProfile -NonInteractive -Command "\$bad=0; foreach (\$f in @($list)) { \$e=\$null; [void][Management.Automation.Language.Parser]::ParseFile((Resolve-Path \$f), [ref]\$null, [ref]\$e); if (\$e) { \$bad=1; \$e | ForEach-Object { \"\$f : \$_\" } } }; if (\$bad) { exit 1 }; 'PowerShell parse OK: ' + @($list).Count + ' files'"
}

gate 'PHP syntax' php_lint
gate 'Shell syntax' shell_lint
gate 'Python syntax' python_lint
if [ -n "${PWSH:-}" ] || command -v pwsh >/dev/null 2>&1; then gate 'PowerShell syntax' powershell_parse
else skipped+=('PowerShell syntax'); echo 'skipped PowerShell syntax: no pwsh (set PWSH=/path/to/pwsh)'; fi
gate 'Repository hygiene' bash tests/hygiene.sh
gate 'Portable suite (C# build + self-tests, protocol/security, Docker agent without a daemon, web UI)' bash tests/run_all.sh
if [ "${1:-}" = "--docker" ]; then gate 'Docker end-to-end' python3 tests/docker_e2e.py
else skipped+=('Docker end-to-end'); echo 'skipped Docker end-to-end: pass --docker (as root, Docker running)'; fi

echo
printf 'Gates run: %s\n' "$(IFS=,; echo "${ran[*]}")"
if [ ${#skipped[@]} -eq 0 ]; then echo 'ALL LOCAL GATES PASSED (the Windows job runs in CI only)'
else printf 'PASSED, but NOT all gates ran. Skipped: %s\n' "$(IFS=,; echo "${skipped[*]}")"; fi
