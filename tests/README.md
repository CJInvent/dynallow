# Tests

Run `bash tests/run_all.sh` from the repository root. Requires Python 3, .NET 10 SDK, and PHP 8.3 CLI with OpenSSL, ctype, sodium, PDO SQLite and SQLite3. Set `PHP` and `DOTNET` to executable paths when needed. Tests use temporary server/database copies, ephemeral keys, and loopback HTTP servers; they do not alter your deployed database.

- `run_v3.py`: C# cryptographic self-tests, PHP interoperability and security regressions, authenticated logs, roles/CSRF/feed scope, Docker PHP enrollment, independently signed update, restart and tamper rejection. Runs launcher/agent code without a Docker daemon.
- `run_ui.py`: login/CSP, settings, SMTP mock delivery, provider account forms/API checks, and site-creation validation. Uses `ui_test.py`, `web.py`, and `mock.py`; stops only processes it starts and uses temporary ports.
- `windows-smoke.ps1`: elevated, **clean disposable Windows VM only**. Checks native platform crypto/power and service install/start/restart/uninstall. Build with an ephemeral test public key. See `.github/workflows/native-agent.yml`; never distribute its test-key binaries.

The removed PowerShell end-to-end suite asserted the obsolete script installer and unsigned-update design; it is not a current acceptance gate. Protocol/update security cases are covered by `run_v3.py`; Windows runtime behavior uses the smoke script and the manual acceptance matrix in `CLAUDE-HANDOFF.md`. Broader provider drift/retry, webhook, backup/restore, and real Docker lifecycle checks from that old combined suite have **not** all been ported. Do not mistake the portable runner for full production acceptance.
