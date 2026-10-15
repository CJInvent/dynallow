# 7. Troubleshooting

Start on the **site's page** in the web page: the status line and the
**Logs** and **Activity** views show application diagnostics and audit events.

| You see | It means | Do this |
|---|---|---|
| Red banner: **cron job is not running** | No alerts, no retries | Step 6 of the server install: `cp deploy/ipfailover.cron /etc/cron.d/ipfailover` |
| **IP held** | Agent and server see different IPs | Two internet links at the site? Set the site's **Trust mode** to *Server-seen only*. A proxy (HAProxy) in front of the server? Add it to `trusted_proxies` in `config.php`. Otherwise someone may be relaying the traffic — investigate. |
| **Server saw a private address** | The server only sees a LAN/proxy IP | Same as above: `trusted_proxies`. |
| **Agent could not determine its IPv4** | The site can't reach ipify etc. | Check the site's internet / firewall. Settings → General → IP lookup services. |
| **DNS failing** | The provider refused the update | Read the detail: wrong token, name not in that account, zone not found… Fix the DNS account, then **Push now**. |
| **Offline** | No check-ins | Is the PC on? Windows: is the **DynAllowAgent** service running? Docker: `docker ps`. Then read the agent log. |
| **Waiting for install** / **Profile expired** | Installer not run yet / too late | Download a new installer on the site page. |
| **Key on new machine** | The key files were copied to other hardware | Planned swap? **Accept the new machine**. If not, **Disable** the site and re-provision. |
| **Forged request** email | Someone used the site's ID with the wrong key | Usually a rebuilt PC running an old copy — re-provision it. If not, investigate. |
| Windows installer: **already set up** | That PC already has an identity | Use `DynAllow.Agent.exe install` to retain identity, or `install --reprovision --profile FILE` to replace it deliberately. |
| Windows install: **No offline release public key embedded** | Incorrect build | Rebuild using `tools/Build-Windows.ps1` with the trusted public key. |
| Docker installer: **Docker is not running / nesting** | LXC can't run Docker | Proxmox → LXC → Options → Features → nesting + keyctl, restart. |
| Tray dot grey with **Agent: NOT RUNNING** | The Windows service stopped | `Start-Service DynAllowAgent` (admin), then check the log. |
| No alert emails | SMTP | Settings → Email → **Send a test email** and read the error. |

## Logs

- **Windows:** `C:\ProgramData\IPFailoverAgent\public\agent.log` (or tray → **Open log**)
- **Docker:** `cd /opt/ipfailover-agent && docker compose logs --tail 50`
- **Docker health:** `docker exec ipfailover-agent php /app/launcher.php health`
- **Server:** the **Logs** and **Activity** pages, and `/var/log/apache2/ipfailover-error.log`

## Useful commands (server)

```bash
sudo -u www-data php bin/manage.php status          # quick health
sudo -u www-data php bin/cron.php -v                # run the cron job by hand, verbosely
sudo -u www-data php bin/manage.php reset-password NAME
sudo -u www-data php bin/manage.php reset-2fa NAME
sudo -u www-data php bin/manage.php rotate-server-key
```

## Remove the agent from a Windows PC by hand

Admin PowerShell: `& "$env:ProgramFiles\DynAllow\DynAllow.Agent.exe" uninstall`

## Remove the agent from Docker by hand

```bash
cd /opt/ipfailover-agent && docker compose down && cd / && rm -rf /opt/ipfailover-agent
```
