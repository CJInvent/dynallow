# DynAllow

Public-IP tracking and DDNS updates at scale, for dynamic firewall allowlisting of client sites.

Keeps a DNS name (and firewall allowlists) pointed at sites whose internet
address keeps changing — Starlink, CGNAT, cellular, cable.

## How it works (the short version)

1. A small **agent** runs at each site (a Windows PC, or Docker on a Linux box / LXC).
2. Every few minutes it **checks in** with your **control server**.
3. The control server sees the site's real public IP, double-checks it, and
   **updates the DNS record itself** (Cloudflare, PowerDNS, No-IP, DuckDNS, …).
4. If a site stops checking in, you get an **email** (and an optional chat message).

The site never holds a DNS password. Everything is managed from one web page.

## What's in this folder

| Folder | What it is | Where it goes |
|---|---|---|
| `ControlServer/` | The website + brains. Agents' files are inside it too (`agents/`). | Your Linux web server |
| `docs/` | Plain-language guides | Read them |
| `tests/` | Automatic tests (for developers) | Nowhere |

## Native agents and signed updates (v3)

See [the v3 deployment guide](docs/8-native-agents-and-releases.md) for the Windows service, offline release keys, Docker migration, sleep policy, and web diagnostics. Read the [security review](docs/security-review-v3.md) and [Claude handoff](CLAUDE-HANDOFF.md) before rollout. Windows platform acceptance and production signing remain required. All installation guides use the native Windows service and signed Docker release flow.

## Setup in 3 steps

1. **Set up the control server once.** Follow [docs/1-install-control-server.md](docs/1-install-control-server.md).
2. **Add a DNS account once.** In the web page: **DNS accounts → Add**. See [docs/2-dns-accounts.md](docs/2-dns-accounts.md).
3. **For each site:** click **New site**, answer the questions, download the
   Windows profile or Docker installer, and install the agent at the site. See [docs/3-add-a-site.md](docs/3-add-a-site.md).

## How do I know it's working?

- **Web page:** the site shows a green **OK**.
- **Windows PC:** the dot by the clock is **green**.
- **Docker:** `docker ps` says **(healthy)**.
- **Email:** you only hear from it when something is wrong — and again when it's fixed.

## More

- [docs/4-daily-use.md](docs/4-daily-use.md) — dashboard, alerts, deleting old sites, changing DNS provider
- [docs/5-allowlist-feeds.md](docs/5-allowlist-feeds.md) — give firewalls a live list of site IPs
- [docs/6-security.md](docs/6-security.md) — how it's protected, and what it can't protect
- [docs/7-troubleshooting.md](docs/7-troubleshooting.md) — what each problem means and how to fix it
- [docs/upgrading.md](docs/upgrading.md) — upgrading from builds named "IP Failover", or off the old IPUpdater version
