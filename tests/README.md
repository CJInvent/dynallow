# Tests

One command runs what CI runs, minus the Windows job:

```bash
tests/local-gates.sh                 # lint, hygiene, portable suite
sudo tests/local-gates.sh --docker   # ...plus the real-Docker end-to-end test
```

Needs PHP 8.3 CLI (pdo_sqlite, sodium), Python 3 and the .NET 10 SDK. It also uses `pwsh` if
present (or `PWSH=/path/to/pwsh`). `PHP` and `DOTNET` override those executables.
It prints **ALL LOCAL GATES PASSED** only when every gate ran; otherwise it names what was skipped.
Every test works on disposable copies, temporary ports and throwaway keys, never on a deployed server.

## CI checks (`.github/workflows/ci.yml`, every pull request)

| Check | What it proves |
|---|---|
| **Lint, hygiene, portable suite** | `local-gates.sh`: PHP/shell/Python/PowerShell syntax, `hygiene.sh`, then `run_all.sh` |
| **Docker end-to-end** | `docker_e2e.py` on a real Docker host (details below) |
| **Windows** | Native AOT build with a throwaway key, then `windows-smoke.ps1` on a clean runner |

When a check fails, its reason is also posted as a GitHub annotation on the run, so it can be read
even when the job log can't.

## The pieces

- `hygiene.sh` fails on any of these:
  - committed runtime state, credentials or build output;
  - private key material;
  - the old product name outside its migration allowlist;
  - a broken relative link in the docs;
  - CRLF line endings in shell scripts.
- `run_v3.py`:
  - C# build and self-tests;
  - **contract:** a provisioning profile minted by the real server must pass the Windows agent's own validator;
  - PHP and C# wire interop;
  - identity enrollment, rotation, replay and decommission;
  - rejection of tampered or rolled-back signed releases;
  - roles, CSRF, feed scope and log escaping;
  - the Docker agent's enroll, signed update, restart and tamper path, with no Docker daemon.
- `run_ui.py` (with `ui_test.py`, `web.py`, `mock.py`): login, CSP, settings, SMTP, DNS provider
  forms against mock APIs, and survey validation.
- `docker_e2e.py` builds the server image and runs it the way a customer would. A technician flow in
  the web UI then:
  - generates and runs the real Docker agent installer;
  - checks the container is healthy and hardened;
  - checks the authoritative IP;
  - rejects a release signed with the wrong key;
  - uploads and pushes a signed update, then sees the exit-10 restart onto the new code;
  - checks the launcher refuses tampered bytes after a restart;
  - checks data survives a server restart;
  - runs a decommission.

  Run it as root.
- `windows-smoke.ps1`: **clean, disposable Windows machines only** (it installs and purges the real
  service). It covers:
  - platform tests (DPAPI, v2 identity migration, power request);
  - install, removal of the retired PowerShell agent, and the service consuming the profile;
  - folder ACLs, check-now, restart, and uninstall `--purge`.

What no automated test can cover (TPM hardware, reboots, multiple signed-in users, customer
antivirus, real Starlink IP changes) is in [TEST-LEDGER.md](../TEST-LEDGER.md).
