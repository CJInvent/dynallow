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
Release handling is tested in both channels: **signed** (production) and **dev-sha256** (development, no key).

## CI checks (`.github/workflows/ci.yml`, every pull request)

| Check | What it proves |
|---|---|
| **Lint, hygiene, portable suite** | `local-gates.sh`: PHP/shell/Python/PowerShell syntax, `hygiene.sh`, then `run_all.sh` |
| **Docker end-to-end** (dev, signed) | `docker_e2e.py` on a real Docker host, once per release channel (details below) |
| **Windows** (development, signed) | Native AOT build (dev build, or signed policy with a throwaway public key), then `windows-smoke.ps1` on a clean runner |

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
  - rejection of tampered or rolled-back releases, signed and dev (`run_v3.py` runs twice: default and `--development`);
  - roles, CSRF, feed scope and log escaping;
  - the Docker agent's enroll, update, restart and tamper path, with no Docker daemon.
- `review_v4.py`: legacy `ipfailover.sqlite` read live (WAL) and never renamed, two database names
  refused, the dev packager, server channel rules (no dev release offered to a signed agent), and the
  Docker installer refusing two identities or nested paths before touching anything.
- `run_ui.py` (with `ui_test.py`, `web.py`, `mock.py`): login, CSP, settings, SMTP, DNS provider
  forms against mock APIs, and survey validation.
- `docker_e2e.py` builds the server image and runs it the way a customer would. A technician flow in
  the web UI then:
  - generates and runs the real Docker agent installer;
  - checks the container is healthy and hardened;
  - checks the authoritative IP;
  - rejects the other channel's bundles and tampered ones (`DYNALLOW_E2E_CHANNEL=dev|signed`);
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
