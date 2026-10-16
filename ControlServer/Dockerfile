# DynAllow control server: Apache + PHP 8.3 (Ubuntu packages), cron loop, nothing else.
# Build context is this ControlServer folder:   docker compose up -d --build
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 libapache2-mod-php8.3 php8.3-cli php8.3-sqlite3 php8.3-mbstring ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && a2dissite 000-default >/dev/null \
 && a2disconf other-vhosts-access-log >/dev/null \
 && rm -f /var/www/html/index.html
COPY deploy/docker/apache-vhost.conf /etc/apache2/sites-available/dynallow.conf
COPY deploy/docker/php.ini /etc/php/8.3/apache2/conf.d/90-dynallow.ini
COPY deploy/docker/php.ini /etc/php/8.3/cli/conf.d/90-dynallow.ini
COPY deploy/docker/entrypoint.sh /usr/local/bin/dynallow-entrypoint
# Code is root-owned and read-only to the web worker; only data/ is writable.
COPY . /var/www/dynallow
RUN a2ensite dynallow >/dev/null \
 && chmod 755 /usr/local/bin/dynallow-entrypoint \
 && rm -rf /var/www/dynallow/data /var/www/dynallow/deploy/docker \
 && chown -R root:root /var/www/dynallow && chmod -R go-w /var/www/dynallow \
 && php -l /var/www/dynallow/src/bootstrap.php >/dev/null
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD php -r 'exit(@file_get_contents("http://127.0.0.1/login.php") === false ? 1 : 0);'
ENTRYPOINT ["/usr/local/bin/dynallow-entrypoint"]
