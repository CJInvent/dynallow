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

## Deploy a dev test environment

Use the newest **dev release**: on GitHub, **Releases → `v3.1.0-dev.N`** (or
`gh release download v3.1.0-dev.N -R CJInvent/dynallow`). Each one has passed every CI check.
Dev builds are for testing, never for customers.

You need a Linux host with Docker (a VM, or an LXC with nesting on), and a Windows PC or VM.

### 1. Start the server

```bash
tar xzf dynallow-server-v3.1.0-dev.N.tar.gz
cd dynallow-server-v3.1.0-dev.N
cp .env.example .env
nano .env                                  # port, admin name, time zone
docker compose up -d --build
docker compose logs server | grep password # the admin password, shown once
```

1. Open `http://<host>:8080` and sign in. Change the password (**Account**).
2. **Settings → General → Public URL for agents:** the address sites will use, e.g. `http://<host>:8080`. **Save**.
3. **Releases:** the fingerprint shown must match the one in the release notes.

Behind HAProxy or another HTTPS proxy? In `.env` set `DYNALLOW_TRUSTED_PROXIES` to the proxy's IP and
`DYNALLOW_SECURE_COOKIES=1`, then run `docker compose up -d` again.

### 2. Install a Windows test agent

1. On the server: **New site**, choose **Windows**, finish the questions, then **Download Windows profile**.
2. Copy `DynAllow.Agent-…-win-x64.zip` and the profile `.json` to the PC. Unzip it.
3. In an **elevated** PowerShell in that folder:

   ```powershell
   .\DynAllow.Agent.exe install --profile .\dynallow-agt_xxxx.json
   ```

4. The site turns green on the server within a minute or two.

### 3. (Optional) Install a Docker test agent

**New site → Docker → Download Docker installer**, copy it to a Linux host with Docker, run
`sudo sh dynallow-agt_xxxx.sh`. It is healthy when `docker ps` says **(healthy)**.

### 4. Test and record

Work through [TEST-LEDGER.md](TEST-LEDGER.md) and add your run to its log. The two
`dynallow-update-test-*.json` files on the release are for the remote-update tests.

## Production install

1. **Server:** [docs/1-install-control-server.md](docs/1-install-control-server.md) (Docker or Apache, with HTTPS).
2. **Release key and signed Windows builds:** [docs/8-native-agents-and-releases.md](docs/8-native-agents-and-releases.md).
   Production uses your own offline key and Authenticode-signed EXEs, not a dev release.
3. **DNS account:** [docs/2-dns-accounts.md](docs/2-dns-accounts.md). **Sites:** [docs/3-add-a-site.md](docs/3-add-a-site.md).

## How do I know it's working?

- **Web page:** the site shows a green **OK**.
- **Windows PC:** the dot by the clock is **green**.
- **Docker:** `docker ps` says **(healthy)**.
- **Email:** you only hear from it when something is wrong — and again when it's fixed.

## For developers

| Folder | What it is |
|---|---|
| `ControlServer/` | The server (PHP 8.3, SQLite) and its Docker build. Agent sources are in `agents/`. |
| `tools/` | Windows build, release signing, dev-release packaging |
| `tests/` | Automated checks ([tests/README.md](tests/README.md)) |
| `docs/` | Guides |

- `tests/local-gates.sh` runs the CI checks locally (add `--docker`, as root, for the real-Docker test).
- Every pull request runs three checks: **gates**, **Docker end-to-end**, **Windows**.
- Every merge to `main` runs them again, then publishes a dev release.

## More

- [docs/4-daily-use.md](docs/4-daily-use.md): dashboard, alerts, deleting old sites, changing DNS provider
- [docs/5-allowlist-feeds.md](docs/5-allowlist-feeds.md): give firewalls a live list of site IPs
- [docs/6-security.md](docs/6-security.md) and [docs/security-review-v3.md](docs/security-review-v3.md): how it's protected, and what it can't protect
- [docs/7-troubleshooting.md](docs/7-troubleshooting.md): what each problem means and how to fix it
- [docs/upgrading.md](docs/upgrading.md): upgrading from builds named "IP Failover", or off the old IPUpdater version
