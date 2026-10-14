# Upgrading from 1.x (IPUpdater)

Version 2.0 is a new design: the server does the DNS updates, so the old
`config.json` with a DNS token on each PC goes away. There's nothing to convert.

1. Install the 2.0 control server ([guide](1-install-control-server.md)). It can
   run on the same Linux box as the 1.x status page, in a new folder.
2. Add your DNS account(s) once ([guide](2-dns-accounts.md)).
3. For each site, run **New site** and use the **same hostname** the old agent
   updated (choose *I'll type the name*).
4. Run the new installer on the PC. It **removes the old version automatically**:
   the `IPUpdater` and `IPUpdaterTray` tasks, the old tray, and the `C:\IPUpdater`
   folder (which held the DNS token in plain text).
5. Docker sites: `docker compose down` in the old `DockerClient` folder, delete it,
   then run the new Docker installer.
6. When every site shows green, retire the old status page and **revoke the old
   DNS tokens** at your provider — they were stored on site PCs.
