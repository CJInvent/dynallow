# Native agents, diagnostics, and signed updates (v3)

For development, use [SHA-256-only dev releases](9-development.md); no signing key is needed. The key setup below applies to production.

This change replaces the distributed Windows PowerShell launcher with a C# Windows service. The target is a self-contained Native AOT executable: no Python, PowerShell, or separately installed .NET runtime on client machines. Build on Windows with .NET 10 SDK and Visual Studio C++ build tools. Windows x64 and ARM64 are separate release targets. The supplied source compiles and portable protocol tests pass; Windows platform acceptance is still required before customer rollout. No production EXE or production signing key is included.

Authenticode signing and a stable publisher help customers identify the software. They do not guarantee antivirus acceptance. Use ordinary service installation, sign and timestamp the finished executable, submit false positives through vendors' normal channels, and pilot with customer EDR policies. No packer, obfuscation, exclusions, or AV bypass is used. Measure final executable size, idle RSS, startup, and CPU on that pilot; these were not measured in the Linux build environment.

## Establish the independent release identity

On your offline signing Windows computer, using PowerShell 7.4 or later:

```powershell
pwsh -File .\tools\New-ReleaseKey.ps1 -OutputDirectory E:\DynAllowSigning
```

The script prompts for a passphrase and creates `release-private.encrypted.pem` (encrypted PKCS#8) and `release-public.pem` (SPKI). Retain a protected offline backup of the private key and passphrase. Only the public file goes to the build machine and server. Record the printed SHA256 fingerprint separately. Never upload the private key to the server, repository, chat, or CI.

Install the public file at `ControlServer/release-public.pem` (or the configured `release_public_key_file` path), owned by the server administrator and not writable by the web worker. Windows embeds this same public key at build time; generated Docker installers include it in their immutable `/app` mount. Compare the server Releases page fingerprint with your offline record. The online IPF1 transport identity is separate and cannot authorize replacement release keys. Initial trust distribution is out of band; legacy agents need a local migration.

## Build and install Windows

From the repo root on Windows:

```powershell
pwsh -File .\tools\Build-Windows.ps1 -PublicKey E:\DynAllowSigning\release-public.pem -Runtime win-x64 -Version 3.0.0 -Sequence 1 -OutputDirectory artifacts\windows-x64
```

Use `win-arm64` for ARM64. Authenticode-sign and timestamp the resulting `DynAllow.Agent.exe` with your organization's certificate. Keep its `.build.json` sidecar for the offline release tool. The build injects version and public anchor into an isolated temporary source copy; it never requires the private key or modifies the checkout. Use separate output directories for concurrent builds.

For a new site, download its Windows JSON provisioning profile from the server. In an elevated terminal:

```powershell
.\DynAllow.Agent.exe install --profile C:\SecureTransfer\site.json
```

The consumed profile is deleted after durable persistence. `--no-tray` omits the per-user sign-in tray. The service `DynAllowAgent` starts automatically at boot as LocalSystem, has restart-on-failure recovery, and uses `%ProgramFiles%\DynAllow` and `%ProgramData%\IPFailoverAgent` (the data folder keeps its pre-rename name so existing identities are reused in place). SYSTEM is used for compatibility with machine TPM/DPAPI identity and self-update; customer administrators can inspect service configuration and binaries normally. Standard users can read public status/logs and request a check; they cannot write secrets or update code.

To migrate an existing v2 Windows installation, back up its protected data first, stop the old agent, and run the new EXE's `install` command **without** `--profile`. The installer removes known legacy tasks and reuses the existing state, TPM/DPAPI wrapping, active key, and pending rotation. A legacy plaintext master key is upgraded to DPAPI. Explicit `--reprovision --profile FILE` destroys the old identity and is only for deliberate re-enrollment. Verify no legacy worker remains running on the migration pilot.

Commands: `status`, `check`, `tray`, `run` (elevated diagnostic console), `once`, `uninstall`, and `uninstall --purge`. Uninstall retains identity unless purged; remove the Program Files directory after the executable exits. The tray offers status, check-now, log access, and hide. It is optional; service operation does not require user login.

## Prevent sleep

The agent page has a per-agent automatic-sleep prevention checkbox, default **off**. On Windows the policy takes effect at the next successful check-in, persists across reboot, and reports `on`, `off`, or `failed`. A SystemRequired power request prevents automatic idle sleep while the service runs and the OS honors it. It does not keep the display on, prevent deliberate sleep/shutdown, or override all Modern Standby/power policies. It is released on stop/decommission. Docker reports unsupported and does not manipulate the host power policy.

## Docker migration

Deploy the new generated Docker installer locally once. For an existing installation, use `sudo sh dynallow-agt_….sh --upgrade`; this stops the existing container and preserves its data and identity, ignoring the newly embedded profile. Use `--reprovision` only to deliberately replace identity. The installer puts `agent.php`, `launcher.php`, `release.php`, and the public trust key under a root-owned, read-only `/app` mount. The container runs UID/GID 65534 with all capabilities dropped, a read-only root filesystem, writable data, and temporary `/tmp`. The launcher ignores legacy writable `/data/agent.php` and verifies any installed release before executing it on every boot.

The signed remote update target is **agent PHP code only**. Updating PHP, the container image, immutable launcher/verifier, or trust anchor requires a separate administrator-controlled container deployment. Pin/test your chosen image digest in production. Do not mount the Docker socket into the agent. Real Docker runtime health/restart/signal behavior must be checked in the pilot; the automated test here runs the same launcher and agent against an HTTP server without a Docker daemon.

## Sign and deploy a release

Increase both the semantic version and integer sequence for every target release. Never reuse a sequence. For Windows, build the chosen version/sequence and Authenticode-sign the EXE first. On the offline signing machine:

```powershell
pwsh -File .\tools\Sign-Release.ps1 -Target windows-x64 -Version 3.0.1 -Sequence 2 -InputFile .\DynAllow.Agent.exe -PrivateKey E:\DynAllowSigning\release-private.encrypted.pem -OutputFile .\windows-x64-3.0.1.json
```

For Docker, update `AGENT_VERSION` and `RELEASE_SEQUENCE` in `ControlServer/agents/docker/agent.php`, then use `-Target docker -InputFile .\ControlServer\agents\docker\agent.php` with matching version/sequence. The signer prompts for the encrypted private key passphrase. Bundles contain exact manifest bytes, a DER-encoded ECDSA P-256/SHA256 signature, and one hash/size-bound payload. Target, filename, version and sequence are signed.

As a server **admin**, open **Releases**, upload the bundle, verify its displayed target/version/hash, and push to one canary agent. Agents fetch on their next check-in; this is polling, not an inbound client listener. After a successful pilot, activate automatic rollout and enable the server's automatic-update setting. Explicit per-agent pushes work independently of that setting. Pause stops future offers and clears assignments for that release; it cannot recall bytes already downloaded.

Clients independently reject mismatched keys, altered bytes, invalid paths, wrong architecture, and replay/downgrade versions or sequences. A server-side key change alone cannot make existing clients accept a new signer. Windows trust rotation can be carried by a new EXE signed by the old trusted release key; Docker anchor rotation is out of band. Plan fleet overlap before rotating keys.

Windows stages updates under protected Program Files, uses the already trusted executable as updater, stops the service, swaps the EXE, and requires the new version/sequence to initialize within 45 seconds. Failure restores the previous executable. This is initialization health, not proof that every business function works. The high-water sequence is committed after initialization. A bad signed Docker release fails closed; restore service using a newer signed release supplied locally or explicit administrator recovery. An agent unable to run cannot fetch its own repair. Never delete a watermark merely to work around a rejected network downgrade.

The server exposes content-addressed release bundles as public software downloads; no keys or provisioning secrets belong in these payloads. Configure PHP `upload_max_filesize >= 64M`, `post_max_size >= 70M`, sufficient `memory_limit` (start at 512M for worst-case bundles), and matching reverse-proxy request limits. Maximum payload is 48,000,000 bytes, bundle 64 MiB. Use TLS for the web UI and normal deployments.

## Dev releases (CI)

Every merge to `main` runs the full CI gate set, then `.github/workflows/dev-release.yml` publishes a
prerelease `v3.1.0-dev.N`. Nothing in it is signed ([development workflow](9-development.md)):

- **Server package:** `ControlServer` stamped as version `3.1.N0`, with dev mode on in `.env.example`.
- **Windows agent:** a `-Development` Native AOT x64 EXE (`3.1.N0`, channel `dev-sha256`), smoke-tested on
  the runner before it is published.
- **Update-test bundles:** one-step-newer dev releases (`3.1.N1`) for Windows and Docker, made by
  `tools/New-DevRelease.py`.
- **`SHA256SUMS`.**

Version numbers grow with N, so every dev build is newer than every earlier one, and a dev test bed can
take the next dev build as a remote update. CI never holds a signing key of any kind.

## Before production

1. Create the production release key offline (above). Install only `release-public.pem` on the server,
   and confirm its fingerprint against your separate record.
2. Back up the server (`manage.php backup`), then deploy. Schema migrations run automatically;
   rolling back the code does not roll back the data, so test a restore.
3. Build x64 (and ARM64 if needed) with `Build-Windows.ps1`, then Authenticode-sign and timestamp.
4. Pass the manual cases in [TEST-LEDGER.md](../TEST-LEDGER.md) on a dev build first, then once more
   on the signed production build (at least the W and D install, update and recovery cases). A dev
   fleet is never promoted to production: install production builds locally (docs/9).
5. Canary one Windows and one Docker site before turning on automatic rollout.

## Logs and operational monitoring

**Logs** combines authenticated agent diagnostics and server application diagnostics, with source, agent, severity, text, pagination, and unacknowledged-issue filters. Technicians can read; admins acknowledge. WARN/ERROR entries raise a visible banner until acknowledged or removed by retention. Actor/action audit events retain their existing views, and mutations are mirrored to PHP's configured error log when `audit_syslog` is enabled (despite that configuration name, the sink is PHP `error_log`, not a direct syslog socket).

Agents keep a durable, redacted, bounded queue and upload at most 20 entries per check-in. Server acknowledgments deduplicate retries. Backlogs are capped at 500, with a warning on overflow; ingestion is limited to 240 new entries per agent/hour. Windows also rotates local public logs at about 1 MiB. Redaction is best-effort: do not intentionally log credentials or customer payloads. Standard local users can read public diagnostic messages.

The cron job still performs heartbeat/email/notification checks and now prunes diagnostics using event retention (minimum seven days). Keep cron and an external uptime check running. A disconnected agent cannot upload its current failure until connectivity recovers; the last heartbeat and missed-check-in alert are the immediate signal. A stopped/broken server or unavailable database cannot report through its own web UI. Collect web-server/PHP/container/Windows service logs externally as well. Database-backed audit history is not tamper-evident against a server administrator/compromise; send the audit/error stream to an independently controlled append-only collector.
