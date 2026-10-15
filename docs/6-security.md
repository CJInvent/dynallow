# 6. Security design

The server holds DNS credentials; agents report their IP and receive policy. This separation limits what an agent credential can do, but the server remains a trusted, high-value system. Read the [targeted security review](security-review-v3.md) for fixes, validation coverage, and residual risks.

## Identity and transport

IPF1 pins the online server P-256 key in the provisioning profile. Requests use ephemeral ECDH, AES-256-CBC plus HMAC-SHA256, and an ECDSA agent signature. Responses are authenticated and bound to the request nonce. The server checks timestamp and nonce before applying identity changes. Use HTTPS in production, including the administrative UI; application encryption does not replace transport/host hardening.

Enrollment credentials are one-time, expiring, hashed in the database, issued via authenticated CSRF-protected POST, and excluded from caching. A lost enrollment response can be retried only by the same registered identity. Clients persist enrollment state before deleting the profile. Enrolled clients ignore stray new profiles. Missing/corrupt identity fails closed instead of silently creating a replacement.

Windows seals private identity material with a random DEK wrapped by a verified TPM key or machine DPAPI. New installations do not fall back to plaintext; existing plaintext protectors can be upgraded. Pending and active keys support recoverable two-phase rotation. Program Files code and ProgramData secrets are protected for SYSTEM/administrators; only public status and diagnostic logs are readable by ordinary users. A compromised local administrator can still misuse the running agent.

Docker uses a protected volume for its identity key, not TPM/DPAPI protection. It runs as UID 65534 with read-only root and application mounts, dropped capabilities, and no-new-privileges. Protect the host and volume backups.

## Release trust

An independent offline ECDSA P-256 key signs exact release manifests binding target, version, sequence, filename, size and SHA256. The server and clients verify independently. Windows embeds the public key; Docker loads it from the immutable application mount. Old versions, replayed sequences, mismatched targets and altered payloads are rejected. An online server key or administrator login alone cannot authorize new executable bytes without the offline signer. See [signing and recovery](8-native-agents-and-releases.md).

## IP, web UI, and audit

Default Agree mode corroborates the agent observation with the server-seen IP; Manual mode requires approval. Choosing agent-trust mode explicitly relaxes corroboration. Feeds enforce token scope, expiry/heartbeat policy and their configured transport/address restrictions. DNS tokens remain encrypted at rest on the server; compromise of both server data and its encryption key defeats that protection.

The UI uses CSRF protection, CSP, session protections, login throttling and optional/required replay-protected TOTP. Release administration and diagnostic acknowledgment require admin rights; technicians can inspect logs. Client spools are bounded, authenticated and deduplicated. Server application failures appear in Logs when database/logging services are available. External uptime and protected audit-log collection remain necessary: the server cannot reliably report its own complete outage or make its database tamper-proof against compromise.

Use scoped DNS tokens, protected backups, restricted operator access and egress, and pilot signed releases. CGNAT IPs can be shared by unrelated subscribers; allowlisting an IP is not a replacement for authentication.
