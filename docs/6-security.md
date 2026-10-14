# 6. Security design

Goal: zero trust. No network path, no stored file, and no single stolen
credential should be enough to point a customer's DNS — or a firewall
allowlist — somewhere else.

## The layers

**1. DNS credentials never leave the control server.**
Agents hold no provider tokens and never talk to a DNS provider. All pushes
happen server-side. Credentials are encrypted at rest (libsodium secretbox,
key in `data/secret.key`) and are write-only in the UI: once saved, they are
never shown again.

**2. Every agent message is end-to-end encrypted and signed ("IPF1").**
This makes plain HTTP safe for agents; HTTPS becomes defense in depth.

| Piece | How |
|---|---|
| Server identity | The server's P-256 key is **pinned inside the provisioning profile**, so even the very first contact can't be intercepted. |
| Request confidentiality | Fresh ephemeral ECDH (P-256) per request → AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC). |
| Agent identity | ECDSA P-256 signature over every request. The server stores **only the public key**: a stolen database can't impersonate an agent. There are no bearer tokens. |
| Replay | Timestamp window + every nonce remembered. A captured request can't be sent twice. |
| Response authenticity | Keyed to the request's ephemeral secret and bound to its nonce. A man-in-the-middle can't forge "decommission", "change interval", or a software update. |

Primitives were chosen because Windows PowerShell 5.1 (.NET Framework 4.7+),
PHP's openssl, and .NET 8 all have them built in — no libraries on any agent.
The full wire format is documented at the top of `ControlServer/src/wire.php`.

**3. The IP must be corroborated, not just claimed.**
By default (**Agree** mode) DNS changes only when the IP the agent *signs* matches
the address the server *sees* the request come from (or, over IPv6, the same /64).
Someone relaying an agent's traffic from elsewhere produces a mismatch: DNS is
**held** and you're emailed. **Manual** mode adds a human approval for every change.

**4. Agent keys are protected like NimbusBackupClient's.**

- Random 256-bit key (DEK) seals the private key on disk.
- The DEK is wrapped by the strongest thing the machine has:
  **TPM** (Microsoft Platform Crypto Provider, RSA-2048 machine key, OAEP-SHA256,
  proven with a full round trip before it's trusted) → **DPAPI** (machine) →
  **plaintext**, which is logged loudly and reported to the server.
- It upgrades itself automatically (DPAPI → TPM) when a TPM shows up.
- Every key is **written, flushed, read back and verified** before use.
- **Two slots** during rotation: the old key keeps working until the server has
  seen the new one in use, so a rotation can never strand an agent.
- Keys rotate automatically (90 days by default) and on demand.
- The server shows each site's key storage (TPM / DPAPI / container file /
  PLAINTEXT) and can refuse enrollment below a minimum (Settings → Security).

**5. Provisioning profiles follow the Nimbus rules.**
Minted at download (only a SHA-256 is stored), **single use**, **expiring**,
each download voids the previous one, POST + CSRF only, `no-store`,
rate limited, audited, and **destroyed by the installer and the agent** after
use — even when enrollment fails. An enrolled agent is **never** silently
re-pointed by a stray profile.

**6. The Windows install is locked down.**
Scripts that run as SYSTEM live in `Program Files\IPFailoverAgent` with
users read-only. Secrets live in `ProgramData\IPFailoverAgent`, readable by
SYSTEM and Administrators only. Only `public\` (status + log, no secrets) is
readable by users, for the tray. (Version 1.x kept a DNS token in plain text
in `C:\IPUpdater`, where any local user could also edit the script SYSTEM
ran — the 2.0 installer removes it.)

**7. The Docker agent runs with nothing.**
Stock image, read-only root filesystem, user `nobody`, all Linux capabilities
dropped, `no-new-privileges`.

**8. Detection, not just prevention.**
Alerts for: forged requests, an agent key appearing on different hardware,
IP mismatches, DNS records changed outside the system (checked against the
provider's API and repaired), weak key storage, and a dead cron job (plus an
optional dead-man's-switch URL).

**9. The web UI.**
Strict Content-Security-Policy (no inline script, style or handlers),
CSRF on every form, `HttpOnly` + `SameSite=Strict` session cookies, login rate
limiting, timing-safe login, optional/required TOTP 2FA (replay-protected),
role separation where controls a technician can't use are **absent**, not
greyed out, and a full audit log.

**10. Updates are authenticated.**
Self-updates travel inside the authenticated response, are hash-checked and
parse-checked before anything is replaced. The launcher that restarts the
agent never updates itself.

**11. Allowlist feeds** refuse plain HTTP, can be pinned to the consumer's
address, drop silent sites automatically, and are signed.

## What it can't protect

- **A compromised control server** controls DNS. Protect it like a domain controller:
  HTTPS, 2FA for everyone, backups, patching, and limit who can reach `/` (agents
  only need `/api/v1.php`).
- **SYSTEM/root on a site machine** can use that site's key. TPM storage stops
  the key being *copied off* the machine; it can't stop the machine itself being misused.
- **A machine with no TPM and no DPAPI** (or a Docker volume) only obfuscates its key.
  You'll see it on the dashboard.
- **CGNAT addresses are shared.** Allowlisting a Starlink/cellular IPv4 trusts
  other customers behind it too. Prefer the IPv6 prefix, and keep passwords on.
- **Your DNS provider account.** Use scoped tokens (Cloudflare: one zone, DNS edit only).
- **The IP lookup services** (ipify etc.) could lie — but in Agree mode a lie only
  causes a hold and an email, never a wrong DNS record.
- The **admin UI over plain HTTP** exposes your login. Use HTTPS.
