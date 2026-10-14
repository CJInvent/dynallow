# 5. Allowlist feeds

A live list of your sites' verified IPs, for firewalls and PBXes.

## Make one

1. **Allowlist feeds → New feed token.**
2. Name it after who uses it. Optionally only include sites with a **tag** (e.g. `pbx`).
3. **Only allow fetching from:** the firewall's IP. Strongly recommended.
4. **Create** — copy the token now. It is never shown again.

## Use it

```
https://ipctl.yourdomain.com/feed.php?token=TOKEN              one IP per line
https://ipctl.yourdomain.com/feed.php?token=TOKEN&format=json  with names and hostnames
https://ipctl.yourdomain.com/feed.php?token=TOKEN&format=csv
```

- **pfSense / OPNsense:** Firewall → Aliases → type **URL Table (IPs)**.
- **FortiGate:** Security Fabric → External Connectors → **Threat Feed → IP Address**.
- **Scripts:** fetch it and load it into ipset / a MikroTik address list.

## Good to know

- **HTTPS only.** Plain HTTP is refused, because anyone in the path could add an IP to your allowlist.
- A site that stops checking in drops out after the feed's age limit (24 h default),
  so an old, re-assigned address doesn't stay trusted.
- **CGNAT warning:** a Starlink/cellular public IPv4 is **shared** with strangers.
  Allowlisting it trusts them too. Keep passwords on the service anyway. Tick
  "Include IPv6" to also list each site's own IPv6 network, which is not shared.
- Every response is signed (`X-IPF-Signature`, ECDSA P-256). The public key is at
  `/feed.php?pubkey=1` if your consumer can check it.
