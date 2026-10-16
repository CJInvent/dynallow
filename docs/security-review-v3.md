# v3 security review and residual risks

The [follow-up review](review-2026-10-16.md) covers subsequent rename fixes and explicit SHA-256-only development mode. The offline-signature guarantees below apply to production mode.

Reviewed the repository snapshot `e9647d89501f5befba2935190f43474c95c09f61` and the v3 changes, focusing on identity lifecycle, trust boundaries, API replay handling, feeds, diagnostics, updates, and administrative routes. This is a targeted source review and regression effort, not an independent penetration test or a claim that every provider/integration is secure.

## Findings addressed

| Finding | Change |
|---|---|
| Online control-server identity could authorize executable agent scripts without an offline release signature | Removed unsigned legacy update offers; added independently pinned release verification in both clients and admin upload path |
| Docker executed writable legacy `agent.php` | Immutable launcher ignores that path, verifies signed bundle/hash/sequence at startup |
| Feed query tag could widen a token's scope | Enforced token-bound tag; HTTP regression returns 403 |
| Agent-reported IPv6 could reach feeds without corroboration | Require server observation unless the site explicitly uses agent-trust mode |
| Pending identity promotion preceded freshness validation | Validate timestamp/nonce first; return active key ID for recoverable lost-response promotion |
| Lost enrollment response could strand an otherwise enrolled client | Narrow idempotent retry only for the same registered key/UID; atomic enrollment token claim |
| Client profile could be deleted before state was committed | Persist and verify state first; missing/corrupt enrolled identity fails closed |
| TOTP replay checks could race | Atomic conditional update of accepted time step |
| Decommission left server key authorization available | Authenticated decommission acknowledgment revokes registered/pending identity and enrollment token; stops DNS work |
| Invalid CIDR masks, unbounded HTTP responses, header injection | Bounds checks and HTTP URL/header/body validation |
| SMTP address injection / localhost suffix trust | Address validation and exact local-host matching for plaintext authentication exception |
| Server errors and client failures were insufficiently visible | Durable authenticated diagnostic ingestion, issue banner, server hooks, admin acknowledgment audit, external error-log mirror |
| Existing explicit Windows ACL grants could survive reinstallation | Replace protected directory ACLs; reset descendants; reject existing reparse points before installation |
| Concurrent database initialization could conflict | Serialize schema migration with BEGIN IMMEDIATE and re-read version inside lock |

## Trust boundaries and limitations

- Offline signing protects executable authenticity even if the online server is compromised, provided the pinned public key, installed verifier, endpoint admin account, and offline private key remain trustworthy. It does not stop a compromised server from changing legitimate configuration, withholding updates, changing DNS, or sending decommission policy.
- The server retains DNS/provider and notification credentials by design. Back up/encrypt and protect the host/data directory, use least-privilege provider tokens, restrict administrative access, enforce MFA, and protect the external log collector. A local admin/root compromise is outside the client tamper-resistance boundary.
- The existing IPF1 application crypto is retained for compatibility. Its interoperability is tested, but custom protocol review is not equivalent to formal cryptographic verification. Use HTTPS in production; HTTP remains supported for existing/private deployments and tests.
- Administrative configuration includes outbound URLs and DNS provider endpoints. This remains an SSRF/network-egress trust boundary for authorized operators, not a generic safe URL fetcher. Restrict server egress and proxy trust to the actual infrastructure.
- Docker data holds the identity key in the protected volume; it does not provide Windows TPM/DPAPI protection. Host volume permissions and backup protection matter.
- Logs are bounded and redact common secrets; they are not guaranteed lossless, complete, or tamper-proof. Retention can delete unacknowledged entries. External monitoring is required for the application itself being down.
- Offline-signed bad code is still bad code. Canary testing, independent review, protected release workstations, and staged rollout are required. Automatic Windows rollback only checks service initialization; interrupted power-loss installation recovery and full runtime behavior require Windows pilot tests.
- Obsolete PowerShell agent files and unsigned-update helpers are deleted by the patch. Identity-format compatibility remains in the native client; it does not execute old scripts. PHP release verification has one shared source for server and Docker packaging.

## Validation evidence

`tests/run_v3.py` exercises disposable server/database copies, C# cryptographic fixtures, PHP wire interoperability, identity enrollment/rotation/replay/decommission, offline signature failures, target/downgrade rules, feed scope, log redaction/escaping/deduplication, real HTTP sessions/CSRF/roles, and Docker enrollment/signed-update/restart/tamper rejection. All portable tests pass. The C# project compiles on .NET 10. PHP lint, shell/Python/PowerShell syntax, repository hygiene, a real-Docker end-to-end run and a Windows service smoke test are CI gates (`tests/README.md`).

Not executed here: Windows Native AOT publish, SCM boot/recovery/ACL tests, real TPM/DPAPI migration and failure modes, multi-session tray, power-policy behavior, Windows signed update rollback under faults, Authenticode verification, customer AV/EDR, ARM64 hardware, actual Docker namespaces/restart behavior, production DNS provider/SMTP integrations. The obsolete combined PowerShell suite was removed; see tests/README.md for coverage not yet ported. Supplied Windows smoke script and CI workflow provide initial gates, but do not cover the entire acceptance matrix. No production release is certified by this package.

The cleanup sweep additionally ran the current web UI suite: 29 checks cover login/CSP, settings, SMTP mock delivery, provider account API checks and site creation. The replacement runner uses disposable copies, loopback-only mocks and temporary ports.
