# 3. Add a site

Where `DynAllow.Agent.exe` comes from:

- **Testing:** the `DynAllow.Agent-…-win-x64.zip` on the newest dev release (see the [README](../README.md#deploy-a-dev-test-environment)).
- **Customers:** your own Authenticode-signed build, made with your offline release key ([release setup](8-native-agents-and-releases.md)).

The EXE is self-contained: customer PCs need no PowerShell modules or .NET install.

## In the web UI

1. Click **New site** and fill in customer/site, Windows or Docker, connection details, DNS account/name, and alert settings.
2. Create the site and download **Windows profile (.json)** or **Docker installer (.sh)**.
3. Transfer the file securely to its intended machine. The embedded enrollment credential expires (14 days by default). Downloading again invalidates an earlier unused credential.

## Windows

Transfer the common signed `DynAllow.Agent.exe` and the site's profile. In an elevated terminal:

```powershell
.\DynAllow.Agent.exe install --profile C:\SecureTransfer\dynallow-agt_xxxx.json
```

The installer persists the profile and deletes the transferred copy. The `DynAllowAgent` service starts at boot without a user login. The tray starts at user sign-in; run `DynAllow.Agent.exe tray` to show it immediately. Green means healthy, red indicates a problem, and grey means waiting/paused. Use `--no-tray` for headless installations. Runtime service and identity details are in the [deployment guide](8-native-agents-and-releases.md).

## Docker

Use a supported Docker Engine and Compose installation on the host. For Proxmox LXC, ensure the host/container configuration supports Docker; do not enable privileged mode merely to suppress an unexplained error.

```bash
sudo sh dynallow-agt_xxxx.sh
```

The installer lays out a read-only application and trust anchor, preserves a writable identity volume, starts the container, and deletes itself. Check `docker ps` and the site's web page. For an existing installation, use `--upgrade` to preserve enrollment or `--reprovision` only to replace it deliberately.

## Verify

Confirm a successful check-in, expected IP, DNS targets, and log entries in the web UI. If needed, use the site DNS name or an [allowlist feed](5-allowlist-feeds.md) in your firewall. Enable automatic-sleep prevention only on Windows sites that need it; it defaults off.
