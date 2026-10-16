<?php
// DynAllow control server — file-level settings.
//
// Almost everything (email, alert rules, DNS accounts, users) is managed in
// the web UI. Only things that must be known before the database opens, or
// that should never be editable from the web, live here.

return [
    // SQLite database and the encryption key for stored DNS/SMTP credentials.
    // Both live in data/, which must NOT be inside the Apache DocumentRoot.
    'data_dir' => __DIR__ . '/data',

    // Reverse proxies allowed to tell us the real client IP via
    // X-Forwarded-For (e.g. your HAProxy). Agents' public IPs are the whole
    // point of this system, so if a proxy sits in front of Apache and is NOT
    // listed here, every agent will look like it comes from the proxy.
    // IPs or CIDRs, IPv4 or IPv6.
    // In Docker, set DYNALLOW_TRUSTED_PROXIES instead (comma-separated).
    'trusted_proxies' => array_merge([
        // '10.0.0.5',
        // '192.168.10.0/24',
    ], array_values(array_filter(array_map('trim', explode(',', (string)getenv('DYNALLOW_TRUSTED_PROXIES')))))),

    // Session cookie: set true once the site is served over HTTPS (it should be).
    // In Docker, set DYNALLOW_SECURE_COOKIES=1 instead.
    'secure_cookies' => filter_var(getenv('DYNALLOW_SECURE_COOKIES') ?: '0', FILTER_VALIDATE_BOOLEAN),

    // Development only: accept SHA-256-only release bundles (docs/9-development.md). The integrity
    // check stays; authenticity rests on this server. Never on a production server.
    // In Docker, set DYNALLOW_ALLOW_DEV_RELEASES=1 instead.
    'allow_dev_releases' => filter_var(getenv('DYNALLOW_ALLOW_DEV_RELEASES') ?: '0', FILTER_VALIDATE_BOOLEAN),
    // Production release trust: the PUBLIC half only, pinned out of band. Never the private key.
    // In Docker it lives in the read-only ./trust folder (see docker-compose.yml).
    'release_public_key_file' => getenv('DYNALLOW_RELEASE_KEY_FILE') ?: __DIR__ . '/release-public.pem',
    // Mirror audit events to PHP's error log; forward that log to an external collector.
    'audit_syslog' => true,

    // API base overrides — only for testing against mock servers. Leave null.
    'cloudflare_api_base' => null,   // default https://api.cloudflare.com/client/v4
    'duckdns_api_base'    => null,   // default https://www.duckdns.org
];
