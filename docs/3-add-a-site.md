# 3. Add a site

## In the web page (2 minutes)

1. Click **New site**.
2. Answer the six short steps:
   - **Site** — customer and a short unique name (e.g. `SmithDental-PBX`).
   - **Machine** — a Windows PC, or Docker (Linux / Proxmox LXC).
   - **Internet** — type of connection. Say **Yes** if the site has two internet links.
   - **DNS name** — pick a DNS account. **Random name** is recommended.
   - **Alerts** — how often it checks in, and who gets emailed.
   - **Review** — check it, click **Create site**.
3. Click **Download … installer**.

The installer holds a **one-time** key for this site: it works once, expires
(14 days by default), and deletes itself after use. Downloading again cancels the old one.

## At the site: Windows PC

1. Copy `Install-ipfailover-agt_xxxx.ps1` to the PC (USB, RMM, file share).
2. Right-click it → **Run with PowerShell**. Click **Yes** when Windows asks for admin.
3. Wait for **INSTALLED** (under a minute).
4. A dot appears by the clock for everyone who signs in:
   🟢 green = all good · 🔴 red = problem (right-click it) · ⚪ grey = waiting / paused.

Nothing to install first. It runs from power-on, even when nobody is signed in.

> Domain with "AllSigned" script policy? Run it from an admin PowerShell instead:
> `powershell -ExecutionPolicy Bypass -File .\Install-ipfailover-agt_xxxx.ps1`

## At the site: Docker / Proxmox LXC

**Only once per LXC — get Docker working:**

1. In Proxmox: click the LXC → **Options → Features** → tick **nesting** and **keyctl** → restart the LXC.
2. In the LXC (Debian 12/13 — paste the whole block):

   ```bash
   apt update && apt install -y ca-certificates curl
   install -m 0755 -d /etc/apt/keyrings
   curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
   echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
   apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
   ```

   (If `docker run hello-world` fails, make the LXC **privileged** in Proxmox and try again.)

**Install the agent:**

1. Copy `ipfailover-agt_xxxx.sh` into the LXC (WinSCP / scp).
2. Run:

   ```bash
   sudo sh ipfailover-agt_xxxx.sh
   ```

3. Wait for **INSTALLED**. Check any time with `docker ps` — look for **(healthy)**.

## Then

The site's page turns green within a minute or two. If a DNS name was chosen,
it's already pointing at the site.

**For the FreePBX/Sangoma firewall:** add the site's DNS name (not its IP) to
the trusted Networks list. Or use an [allowlist feed](5-allowlist-feeds.md).
