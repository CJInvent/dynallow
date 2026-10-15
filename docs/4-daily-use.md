# 4. Daily use

## The dashboard

| Color | Meaning |
|---|---|
| 🟢 **OK** | Checking in, IP verified, DNS up to date |
| 🔵 **Waiting / Syncing / No IP yet** | Normal for a new site. Not a problem. |
| 🟠 **Late / IP held / Needs approval** | Look at it soon |
| 🔴 **Offline / DNS failing / Key on new machine** | Needs a person now |
| ⚪ **Disabled / Maintenance / Decommissioned** | Paused on purpose |

Click a site to see everything about it.

## Emails you can get

| Email | What it means |
|---|---|
| **OFFLINE** | Missed 2 check-ins in a row (change per site). DNS stays on the last good IP. |
| **RECOVERED** | It's back. |
| **IP changed** | New verified IP; DNS is being updated. (Can be turned off in Settings.) |
| **DNS UPDATE FAILING / RECOVERED** | The provider refused or was down. It retries automatically. |
| **DNS DRIFT** | Someone changed the record by hand. It was put back. |
| **IP HELD** | The agent and the server see different IPs. DNS was **not** changed. |
| **APPROVAL NEEDED** | A site in Manual mode wants to change IP. Approve it on the site page. |
| **Forged request** | Someone tried to pretend to be this site. It was refused. |
| **Agent key moved to another machine** | The site's key files were copied to other hardware. |
| **Weak key storage** | The reported protector is below policy; inspect the agent details. |

## Common jobs

- **Mute alerts during work:** site page → **Mute alerts 1h / 4h / 24h**.
- **Check right now:** at the site, right-click the dot → **Check now**. In the web page: DNS → **Push now**.
- **Change how often it checks in:** site page → Settings → **Check in**. Takes effect at its next check-in.
- **Switch DNS provider:** site page → DNS → **Add a DNS name** with the new account → update whatever uses the old name → **Remove** the old one.
- **Pause a site:** **Disable**. No DNS changes, no alerts, removed from allowlist feeds.
- **Remove a site properly:** **Decommission** (the agent deletes its identity and stops operation at its next check-in; uninstall the service/container locally), then **Delete site**.
- **Clean up old sites:** dashboard → **Stale** tile → **Delete all stale**. Tick "also delete their DNS records" to remove Cloudflare/PowerDNS names too.
- **Move a site to new hardware:** site page → **Re-provision…** → download a new installer → run it on the new machine.

## Users

- **Admin:** everything.
- **Technician:** create sites, download installers, edit and push sites. Can't delete, decommission, or see settings/DNS accounts/users.
- Turn on **Settings → Security → Require two-factor sign-in for everyone**.

## Diagnostics and releases

Use **Logs** for agent/server diagnostics and unacknowledged warnings/errors. Admins acknowledge issues after review. Use **Releases** for offline-signed bundle upload and canary/fleet rollout. The per-site automatic-sleep prevention policy defaults off. See the [deployment guide](8-native-agents-and-releases.md) for retention, external monitoring, and update recovery.
