# Replacing pre-service installations

New installations should follow [Add a site](3-add-a-site.md). This page is only for retiring older deployed clients; old executable scripts are not shipped in this source tree.

For the previous IPF1 agent, preserve identity using the native EXE's `install` command without a profile, or the Docker installer's `--upgrade`. Back up protected data and verify the former processes have stopped. See the [deployment guide](8-native-agents-and-releases.md).

For pre-IPF1 IPUpdater deployments, create a new server site using the existing hostname. Stop and disable the old updater before installing the new client. The native installer removes known old scheduled tasks, but does not promise to remove arbitrary old processes, scripts, or DNS-token files. Identify and remove those files locally after confirming the replacement works, and revoke the old per-machine DNS tokens. Retire the old status server after all sites have migrated.

## From a build named "IP Failover"

Same product, new name. Nothing is re-provisioned and the wire protocol is unchanged,
so agents keep checking in while you move things over.

- **Control server:** deploy into a fresh folder and carry `data/` and `config.php` across:

  ```bash
  sudo mv /var/www/ipfailover /var/www/ipfailover-old
  sudo cp -r ControlServer /var/www/dynallow
  sudo cp -a /var/www/ipfailover-old/data /var/www/dynallow/
  sudo cp -a /var/www/ipfailover-old/config.php /var/www/dynallow/config.php
  sudo chown -R www-data:www-data /var/www/dynallow
  ```

  `ipfailover.sqlite` is adopted as `dynallow.sqlite` on first load. Replace the Apache
  site with `deploy/apache-dynallow.conf` and the cron file with `deploy/dynallow.cron`
  (delete `/etc/cron.d/ipfailover`), and keep the **same Public URL**. Old `.ipfbak`
  backups still restore. Everyone signs in again once (the session cookie was renamed).
  Delete `/var/www/ipfailover-old` once the dashboard looks right.
- **Windows PCs:** run `DynAllow.Agent.exe install` **without** a profile. It removes the
  old `IPFailoverAgent`/`IPFailoverTray` tasks and the old scripts in
  `C:\Program Files\IPFailoverAgent`, and keeps using the PC's identity in
  `C:\ProgramData\IPFailoverAgent` (that folder name is kept on purpose).
- **Docker hosts:** run the new installer for the same site with `--upgrade`. It stops the
  old `ipfailover-agent` container, moves the identity out of `/opt/ipfailover-agent`
  into `/opt/dynallow-agent`, deletes the old folder, and starts `dynallow-agent`.
