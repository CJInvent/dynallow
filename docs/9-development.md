# Key-free development workflow

Development releases use SHA-256 integrity checks, with no offline keypair, release signature, or Authenticode step required. This follows the current NimbusBackupClient approach of publishing SHA256SUMS and allowing unsigned builds when signing is unconfigured. DynAllow keeps target/version/sequence checks and an explicit development channel. A hash detects mismatched bytes; it does not establish publisher identity if someone controls both the bundle and the expected hash. Development therefore trusts the control server, whose authenticated IPF1 update offer includes the bundle's SHA-256 and size.

Use a separate development server/data directory. In its `ControlServer/config.php`, set:

```php
'allow_dev_releases' => true,
```

No `release-public.pem` is needed for development. This setting is file-level, not web-editable. Development release uploads are disabled by default. The Releases page shows the mode and each release's channel; agents report their channel. A production agent cannot be switched to development by a server response or provisioning profile.

## Windows

On the Windows build computer, install .NET 10 SDK, Visual Studio C++ build tools, PowerShell 7.4+, and Python 3 for packaging. Customer/client runtime does not require those tools.

```powershell
pwsh -File .\tools\Build-Windows.ps1 -Development -Version 3.0.0 -Sequence 1 -OutputDirectory .\artifacts\dev
.\artifacts\dev\DynAllow.Agent.exe install --profile C:\SecureTransfer\dynallow-agt_example.json
```

The build uses an isolated temporary source copy, so builds no longer overwrite `BuildInfo.cs` or the source trust anchor. The EXE has development policy compiled in. It logs and reports `dev-sha256`; a production build reports `signed`. Use separate output directories for concurrent builds.

To test an update, increment both version and sequence:

```powershell
pwsh -File .\tools\Build-Windows.ps1 -Development -Version 3.0.1 -Sequence 2 -OutputDirectory .\artifacts\dev-next
python .\tools\New-DevRelease.py --target windows-x64 --version 3.0.1 --sequence 2 --input .\artifacts\dev-next\DynAllow.Agent.exe --output .\artifacts\windows-dev-3.0.1.json
```

Upload that JSON on **Releases**, then push to a dev agent. No signing command is involved. The packager checks the build metadata and writes the payload SHA-256; the server hashes the complete bundle and clients match that offered hash before installation. Tamper, architecture, version, size and replay checks remain enabled. The normal protected staging/rollback mechanism remains in use.

## Docker

Download the generated installer from the development server. It installs `update-policy.json` with `allow_dev_releases: true` inside the root-owned, read-only `/app` directory. A missing policy defaults to signed-only. The environment, writable data volume and online policy cannot enable this option. For manual deployment, download that policy along with the agent/launcher/verifier; production also requires the public key.

Increment `AGENT_VERSION` and `RELEASE_SEQUENCE` in `ControlServer/agents/docker/agent.php`, then package:

```powershell
python .\tools\New-DevRelease.py --target docker --version 3.0.1 --sequence 2 --input .\ControlServer\agents\docker\agent.php --output .\artifacts\docker-dev-3.0.1.json
```

Deploy through Releases as above. The launcher verifies hashes again at every startup. Signed production bundles and hash-only development bundles have distinct format markers. There is no fallback from failed signature verification to hash-only acceptance.

## Continued development

Run `bash tests/run_all.sh` on Linux/macOS or an equivalent shell environment with .NET 10, PHP 8.3 (OpenSSL, sodium, ctype, SQLite/PDO) and Python 3. It runs production and development transport/update suites, the 29-check UI/provider/SMTP suite, and rename/WAL/policy/installer regressions. `PHP` and `DOTNET` can specify executable paths. Windows smoke tests are separate and destructive only in a clean disposable VM.

CI now runs the portable suite and separate development/signed-policy Windows smoke builds. No customer artifacts or signing secrets are published by this validation workflow. GitHub CI and Windows SCM/AOT execution have not been run in the Linux authoring environment.

To move a machine to production, install a production build and root-controlled production Docker policy locally, with the offline public key. Do not reuse a development fleet as an implicit production trust boundary. Keep the existing offline signing path for production; it is not required for this development workflow.
