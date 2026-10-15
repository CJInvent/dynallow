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
    'trusted_proxies' => [
        // '10.0.0.5',
        // '192.168.10.0/24',
    ],

    // Session cookie: set true once the site is served over HTTPS (it should be).
    'secure_cookies' => false,

    // Public half ONLY, pinned out-of-band. Never store the offline private key here.
    'release_public_key_file' => __DIR__ . '/release-public.pem',
    // Mirror audit events to PHP's error log; forward that log to an external collector.
    'audit_syslog' => true,

    // API base overrides — only for testing against mock servers. Leave null.
    'cloudflare_api_base' => null,   // default https://api.cloudflare.com/client/v4
    'duckdns_api_base'    => null,   // default https://www.duckdns.org
];
