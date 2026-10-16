# Claude handoff: DynAllow native Windows agent and signed fleet updates

## Apply

Base repository: https://github.com/CJInvent/dynallow
Base commit: `e9647d89501f5befba2935190f43474c95c09f61`.

**This cleaned archive supersedes the first delivery.** Do not apply both full patches. The full patch starts at the base below and explicitly deletes obsolete tracked files. If the first patch was already applied, use the separate `cleanup-after-first-handoff.patch` instead. Deploy into a fresh application directory (preserving runtime data/config) or honor deletions with your deployment tool; copying new files over an old tree will retain files that Git correctly deleted.

The delivery archive contains `source/` (complete tracked source), `dynallow-v3.patch` (mail-format commit), and portable test/build evidence. Apply the patch on a new branch using `git am /path/to/dynallow-v3.patch`. If main has moved, merge/review conflicts against this base; do not overwrite newer Claude work with the source snapshot. Nothing was pushed remotely.

This is implemented source plus portable validation, **not a production Windows binary**. The actual Windows Native AOT build needs the user's public trust anchor and a Windows build host. Do not advertise a tested EXE, measured memory footprint, complete security audit, or antivirus guarantee. No production keypair has been generated or included.

## Implemented

- C# service and native tray, boot startup/recovery, protected persistent identity compatible with existing TPM/DPAPI formats, key rotation, IPF1 transport, check-now, status, decommission, and diagnostics.
- Per-agent prevent-sleep policy defaulting off, Windows power requests and reported status; Docker reports unsupported.
- Agent/server diagnostic web UI, durable client spool, acknowledgments/deduplication, issue banner, role checks and external audit mirror.
- Offline P-256 release signing tools; separate Windows x64/ARM64 and Docker targets; immutable pinned trust, payload verification, anti-rollback, admin releases UI and staged deployment.
- Windows protected updater with initialization rollback; Docker immutable verifying launcher and signed PHP updates.
- Targeted fixes to feed authorization, untrusted IPv6, enrollment/rotation/replay races, TOTP replay, decommission revocation, transport bounds, SMTP validation, migration concurrency, and Windows installer ACLs.

Read `docs/8-native-agents-and-releases.md` for exact provisioning, signing, rollout, log limits, and recovery behavior. Read `docs/security-review-v3.md` for findings and remaining boundaries. Installation, security, troubleshooting, and test documentation now consistently describe the native/signed flow.

## Required before production

1. Ask the owner to run `pwsh -File .\tools\New-ReleaseKey.ps1 -OutputDirectory E:\DynAllowSigning` locally/offline (PowerShell 7.4+). Receive **only** `release-public.pem` and confirm its separately recorded fingerprint. Keep the encrypted private key and passphrase offline. Install the public anchor on the server and use it for both client builds/installers.
2. Back up SQLite/data and config, then deploy the server changes. Schema v2 migration runs automatically. Keep `data/`, config and the trust anchor outside the web document root. Configure release upload/proxy/memory limits and cron/external log collection as documented. Test recovery from backup; code rollback alone does not reverse schema/data changes.
3. Build x64 and ARM64 on Windows with `tools/Build-Windows.ps1`. Authenticode-sign/timestamp finished EXEs. The supplied GitHub workflow uses ephemeral test keys only and has not been run in this environment; do not distribute its test-key binaries.
4. Run `tests/windows-smoke.ps1 -Executable <absolute exe path>` elevated on a clean disposable VM. Then test real enrollment, v2 TPM and DPAPI migrations, no-TPM fallback, reboot/service failure recovery, standard-user ACL isolation, multiple user sessions/tray, sleep toggle on/off/stop, rotation lost responses, decommission, offline logging/reconnect, successful update, tamper/wrong key/old sequence/architecture rejection, startup rollback and power interruption. Test ARM64 separately. Verify actual footprint and customer EDR compatibility.
5. Test generated Docker installer in a real Docker environment: new install and v2 migration, preserved identity, UID/read-only mounts, healthcheck, restart exit10, SIGTERM, signed update, tamper rejection, lost/corrupt data, and manual newer-release repair. The PHP agent/launcher HTTP integration already passes without Docker.
6. Run `bash tests/run_all.sh` with PHP 8.3 (ctype, sodium, PDO SQLite/OpenSSL), Python 3 and .NET 10 (`PHP`/`DOTNET` environment overrides available). This runs the portable security/update suite and the 29-check UI/provider/SMTP suite. See tests/README.md for broader acceptance coverage not yet ported from the retired PowerShell suite.
7. Canary one Windows and one Docker site before enabling fleet rollout. Require actual Windows health evidence before publishing a customer release. Commit/review/push according to the owner's repo workflow.

## Scope notes

Initial legacy migration is local because old clients do not possess the independent release trust anchor. Server pushes arrive at the next poll. Docker remote updates replace PHP agent code only; runtime/image/launcher/trust-anchor deployment is separate. Windows LocalSystem remains intentional for machine identity compatibility and self-update. Audit history requires an external protected collector to survive server compromise. Sleep prevention concerns automatic idle sleep only. No uploaded private key or runtime trust-key override is provided.

## Cleanup sweep

Deleted all five `ControlServer/agents/windows/*.ps1` files, three obsolete server update helpers, the unused PowerShell embed helper and other unused PHP helpers. Removed the obsolete PowerShell/unsigned-update test runner and its dedicated scripts. Kept current UI/provider mocks and replaced process-wide port killing/fixed-port setup with a disposable runner. Updated UI provisioning text and every affected installation/security/troubleshooting guide. Retained only intentional old identity-format reading/task retirement for migration safety, not a second agent implementation.
