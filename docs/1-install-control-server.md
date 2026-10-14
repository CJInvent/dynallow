# 1. Install the control server (once)

You need: a Debian/Ubuntu Linux server (a VM or LXC is fine) that the sites
can reach on the internet. About 10 minutes.

## Steps

1. **Install Apache and PHP.**

   ```bash
   sudo apt update
   sudo apt install -y apache2 php libapache2-mod-php php-sqlite3
   ```

   (`openssl` and `sodium` come built into PHP. Nothing else is needed.)

2. **Copy the files.** Put the `ControlServer` folder at `/var/www/ipfailover`:

   ```bash
   sudo cp -r ControlServer /var/www/ipfailover
   sudo chown -R www-data:www-data /var/www/ipfailover
   ```

3. **Create the database and your admin login.** It asks for a username and a password (12+ characters):

   ```bash
   cd /var/www/ipfailover
   sudo -u www-data php bin/manage.php init
   ```

4. **Turn on the website.** Edit the `ServerName` line first, then:

   ```bash
   sudo cp deploy/apache-ipfailover.conf /etc/apache2/sites-available/ipfailover.conf
   sudo nano /etc/apache2/sites-available/ipfailover.conf      # set ServerName
   sudo a2enmod headers
   sudo a2ensite ipfailover
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
   sudo cp deploy/ipfailover.cron /etc/cron.d/ipfailover
   ```

7. **Sign in** at `https://ipctl.yourdomain.com` and go to **Settings**:
   - **General → Public URL for agents:** the address sites will use, e.g. `https://ipctl.yourdomain.com`
   - **Alerts → Always email:** who gets alerts
   - **Email:** your SMTP server, then click **Send a test email**

8. **Make a backup now, and on a schedule:**

   ```bash
   sudo -u www-data php bin/manage.php backup /root/ipfailover-$(date +%F).ipfbak
   ```

   It asks for a passphrase. **Keep the passphrase somewhere safe.** The backup holds
   the database *and* `data/secret.key` — without that key, saved DNS passwords can't be read.

## Is a reverse proxy (HAProxy, nginx) in front of Apache?

Open `config.php` and put the proxy's IP in `trusted_proxies`, for example:

```php
'trusted_proxies' => ['10.0.0.5'],
```

If you skip this, every site looks like it's coming from the proxy, and the
dashboard will show **"IP held"** with a hint pointing here.

## Done?

The dashboard has no red banner at the top. (A red "cron job is not running"
banner means step 6 didn't take.)

Next: [2. DNS accounts](2-dns-accounts.md)
