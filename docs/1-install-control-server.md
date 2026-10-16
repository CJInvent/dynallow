# 1. Install the control server (once)

You need: a Linux server (a VM or LXC is fine) that the sites can reach on the internet,
and a name for it with HTTPS in front (e.g. `ipctl.yourdomain.com`). About 10 minutes.

Pick one:

- **Option A: Docker.** Easiest to run and to upgrade.
- **Option B: Apache on the host.** No Docker needed.

Both need the **release public key** (`release-public.pem`) from your offline signing
machine ([docs/8](8-native-agents-and-releases.md)). Without it, Docker installers and signed updates stay off.

## Option A: Docker

1. **Get the files.** Copy the `ControlServer` folder (or a release's `dynallow-server-…tar.gz`,
   unpacked) to the server, and put `release-public.pem` inside it.
2. **Settings:**

   ```bash
   cp .env.example .env
   nano .env
   ```

   Set the port, admin name and time zone. If HAProxy/nginx/Caddy sits in front, set
   `DYNALLOW_TRUSTED_PROXIES` to its IP, and `DYNALLOW_SECURE_COOKIES=1`.
3. **Start it:**

   ```bash
   docker compose up -d --build
   docker compose logs server | grep password   # the admin password, shown once
   ```

4. **HTTPS:** point your reverse proxy at `http://<server>:<port>`.
5. Go to step 7 below (**Sign in**). The alert/retry job already runs inside the container,
   and its log is `docker compose logs server`.
   Backups: `docker compose exec -u www-data server php bin/manage.php backup /var/www/dynallow/data/backup-$(date +%F).dynbak`,
   then copy the file off the server.

## Option B: Apache on the host

1. **Install Apache and PHP.**

   ```bash
   sudo apt update
   sudo apt install -y apache2 php libapache2-mod-php php-sqlite3
   ```

   (`openssl` and `sodium` come built into PHP. Nothing else is needed.)

2. **Copy the files.** Put the `ControlServer` folder at `/var/www/dynallow`, with `release-public.pem` inside it:

   ```bash
   sudo cp -r ControlServer /var/www/dynallow
   sudo install -d -o www-data -g www-data -m 750 /var/www/dynallow/data
   ```

   The code stays owned by root: the web server can write only to `data/`.

3. **Create the database and your admin login.** It asks for a username and a password (12+ characters):

   ```bash
   cd /var/www/dynallow
   sudo -u www-data php bin/manage.php init
   ```

4. **Turn on the website.** Edit the `ServerName` line first, then:

   ```bash
   sudo cp deploy/apache-dynallow.conf /etc/apache2/sites-available/dynallow.conf
   sudo nano /etc/apache2/sites-available/dynallow.conf      # set ServerName
   sudo a2enmod headers
   sudo a2ensite dynallow
   sudo systemctl reload apache2
   ```

5. **Add HTTPS** (strongly recommended — it protects your login):

   ```bash
   sudo apt install -y certbot python3-certbot-apache
   sudo certbot --apache -d ipctl.yourdomain.com
   ```

   Then open `config.php` and set `'secure_cookies' => true,`.

6. **Turn on the cron job.** This sends the alerts and retries DNS. Without it, no emails!

   ```bash
   sudo cp deploy/dynallow.cron /etc/cron.d/dynallow
   ```

7. **Sign in** at `https://ipctl.yourdomain.com` and go to **Settings**:
   - **General → Public URL for agents:** the address sites will use, e.g. `https://ipctl.yourdomain.com`
   - **Alerts → Always email:** who gets alerts
   - **Email:** your SMTP server, then click **Send a test email**

8. **Make a backup now, and on a schedule:**

   ```bash
   sudo -u www-data php bin/manage.php backup /root/dynallow-$(date +%F).dynbak
   ```

   It asks for a passphrase. **Keep the passphrase somewhere safe.** The backup holds
   the database *and* `data/secret.key` — without that key, saved DNS passwords can't be read.

## Is a reverse proxy (HAProxy, nginx) in front of Apache?

Docker: set `DYNALLOW_TRUSTED_PROXIES` in `.env` and run `docker compose up -d`.
Apache: open `config.php` and put the proxy's IP in `trusted_proxies`, for example:

```php
'trusted_proxies' => ['10.0.0.5'],
```

If you skip this, every site looks like it's coming from the proxy, and the
dashboard will show **"IP held"** with a hint pointing here.

## Done?

The dashboard has no red banner at the top. (A red "cron job is not running"
banner means step 6 didn't take. In Docker, read `docker compose logs server`.)

Next: [2. DNS accounts](2-dns-accounts.md)
