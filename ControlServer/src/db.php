<?php
declare(strict_types=1);

/**
 * SQLite access + schema migrations. Schema version is tracked with
 * PRAGMA user_version so upgrades apply automatically on first request.
 */

function db_path(): string
{
    $dir = app_config('data_dir');
    $old = "$dir/ipfailover.sqlite"; $current = "$dir/dynallow.sqlite";
    if (is_file($old) && is_file($current)) throw new RuntimeException('Both database names exist; stop services and resolve the conflicting databases before startup');
    // Existing databases keep their on-disk name. SQLite owns its WAL/SHM lifecycle.
    return is_file($old) ? $old : $current;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $dir = app_config('data_dir');
    if (!is_dir($dir)) {
        throw new RuntimeException("Data directory $dir does not exist. Run: php bin/manage.php init");
    }
    $pdo = new PDO('sqlite:' . db_path());
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA busy_timeout = 5000');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    db_migrate($pdo);
    return $pdo;
}

function db_migrate(PDO $pdo): void
{
    $version = (int)$pdo->query('PRAGMA user_version')->fetchColumn();
    $migrations = db_migrations();
    $target = count($migrations);
    if ($version >= $target) {
        return;
    }
    $pdo->exec('BEGIN IMMEDIATE');
    try {
        // Another first request may have migrated while this connection waited.
        $version = (int)$pdo->query('PRAGMA user_version')->fetchColumn();
        for ($i = $version; $i < $target; $i++) {
            foreach ($migrations[$i] as $sql) {
                $pdo->exec($sql);
            }
        }
        $pdo->exec('PRAGMA user_version = ' . $target);
        $pdo->exec('COMMIT');
    } catch (Throwable $e) {
        $pdo->exec('ROLLBACK');
        throw $e;
    }
}

/** Append-only list. Never edit a shipped entry; add a new one. */
function db_migrations(): array
{
    return [
        // v1
        [
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                pass_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin','tech')),
                totp_secret_enc TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0,
                totp_last_step INTEGER NOT NULL DEFAULT 0,
                disabled INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                last_login_at INTEGER
            )",
            "CREATE TABLE login_attempts (ip TEXT NOT NULL, at INTEGER NOT NULL)",
            "CREATE INDEX idx_login_attempts ON login_attempts(ip, at)",
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE TABLE dns_accounts (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                provider TEXT NOT NULL,
                config_enc TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            "CREATE TABLE agents (
                id INTEGER PRIMARY KEY,
                uid TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                customer TEXT NOT NULL DEFAULT '',
                site_address TEXT NOT NULL DEFAULT '',
                site_contact TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL DEFAULT 'windows',
                purpose TEXT NOT NULL DEFAULT '',
                isp TEXT NOT NULL DEFAULT '',
                cgnat TEXT NOT NULL DEFAULT 'unknown',
                notes TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                interval_sec INTEGER NOT NULL DEFAULT 300,
                missed_threshold INTEGER NOT NULL DEFAULT 2,
                alert_emails TEXT NOT NULL DEFAULT '',
                maintenance_until INTEGER,
                trust_mode TEXT NOT NULL DEFAULT 'agree' CHECK (trust_mode IN ('agree','server','agent','manual')),
                -- provisioning profile token (single use, sha256 only)
                enroll_token_hash TEXT UNIQUE,
                enroll_issued_at INTEGER,
                enroll_issued_by TEXT,
                enroll_expires_at INTEGER,
                enrolled_at INTEGER,
                -- agent identity (P-256, public half only) and its custody report
                pubkey TEXT,
                pubkey_id TEXT,
                pubkey_at INTEGER,
                pending_pubkey TEXT,
                pending_pubkey_id TEXT,
                rotate_requested INTEGER NOT NULL DEFAULT 0,
                key_protector TEXT,
                machine_id TEXT,
                machine_id_changed_at INTEGER,
                decommission INTEGER NOT NULL DEFAULT 0,
                decommissioned_at INTEGER,
                created_at INTEGER NOT NULL,
                created_by TEXT NOT NULL DEFAULT '',
                first_checkin_at INTEGER,
                last_checkin_at INTEGER,
                last_bad_auth_at INTEGER,
                checkin_count INTEGER NOT NULL DEFAULT 0,
                last_remote_addr TEXT,
                current_ipv4 TEXT,
                current_ipv6 TEXT,
                ip_source TEXT,
                ip_changed_at INTEGER,
                pending_ipv4 TEXT,
                pending_count INTEGER NOT NULL DEFAULT 0,
                agent_reported_ipv4 TEXT,
                agent_reported_ipv6 TEXT,
                server_seen_ipv4 TEXT,
                ip_mismatch INTEGER NOT NULL DEFAULT 0,
                ip_mismatch_since INTEGER,
                mismatch_alerted INTEGER NOT NULL DEFAULT 0,
                agent_version TEXT,
                agent_os TEXT,
                agent_hostname TEXT,
                alert_state TEXT NOT NULL DEFAULT 'ok',
                alert_changed_at INTEGER
            )",
            "CREATE TABLE dns_targets (
                id INTEGER PRIMARY KEY,
                agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                account_id INTEGER NOT NULL REFERENCES dns_accounts(id) ON DELETE RESTRICT,
                hostname TEXT NOT NULL COLLATE NOCASE,
                generated_name INTEGER NOT NULL DEFAULT 0,
                target_config_enc TEXT NOT NULL DEFAULT '',
                ttl INTEGER NOT NULL DEFAULT 120,
                proxied INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                state TEXT NOT NULL DEFAULT 'pending',
                detail TEXT NOT NULL DEFAULT '',
                last_pushed_ip TEXT,
                last_pushed_at INTEGER,
                last_attempt_at INTEGER,
                fail_count INTEGER NOT NULL DEFAULT 0,
                last_verified_at INTEGER,
                alerted INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                UNIQUE (hostname)
            )",
            "CREATE INDEX idx_targets_agent ON dns_targets(agent_id)",
            "CREATE TABLE ip_history (
                id INTEGER PRIMARY KEY,
                agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                previous_ip TEXT,
                source TEXT NOT NULL,
                at INTEGER NOT NULL
            )",
            "CREATE INDEX idx_ip_history_agent ON ip_history(agent_id, at)",
            "CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                at INTEGER NOT NULL,
                agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
                agent_name TEXT,
                actor TEXT NOT NULL DEFAULT 'system',
                level TEXT NOT NULL DEFAULT 'info',
                message TEXT NOT NULL
            )",
            "CREATE INDEX idx_events_at ON events(at)",
            "CREATE INDEX idx_events_agent ON events(agent_id, at)",
            // Server key pairs (P-256). 'kex' = agents encrypt requests to it
            // (pinned in their config); 'sign' = signs allowlist feeds.
            // Retired keys are kept so agents pinned to them can still be
            // answered and handed the new key during a rotation.
            "CREATE TABLE server_keys (
                id INTEGER PRIMARY KEY,
                kid TEXT NOT NULL UNIQUE,
                purpose TEXT NOT NULL CHECK (purpose IN ('kex','sign')),
                public_key TEXT NOT NULL,
                private_enc TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                retired_at INTEGER
            )",
            // Replay protection: every request nonce is remembered for longer
            // than the accepted clock window.
            "CREATE TABLE seen_nonces (nonce TEXT PRIMARY KEY, at INTEGER NOT NULL)",
            "CREATE INDEX idx_seen_nonces_at ON seen_nonces(at)",
            "CREATE TABLE feed_tokens (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                tag_filter TEXT NOT NULL DEFAULT '',
                max_age_hours INTEGER NOT NULL DEFAULT 24,
                allowed_sources TEXT NOT NULL DEFAULT '',
                include_ipv6 INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER,
                last_used_from TEXT
            )",
        ],
        // v2: native agents, independently signed releases, diagnostic logs.
        [
            "ALTER TABLE agents ADD COLUMN prevent_sleep INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE agents ADD COLUMN sleep_status TEXT NOT NULL DEFAULT 'unknown'",
            "ALTER TABLE agents ADD COLUMN release_target TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE agents ADD COLUMN release_sequence INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE agents ADD COLUMN update_release_id INTEGER",
            "ALTER TABLE agents ADD COLUMN update_status TEXT NOT NULL DEFAULT ''",
            "CREATE TABLE releases (id INTEGER PRIMARY KEY, target TEXT NOT NULL, version TEXT NOT NULL,
                sequence INTEGER NOT NULL, sha256 TEXT NOT NULL UNIQUE, size INTEGER NOT NULL,
                created_at INTEGER NOT NULL, uploaded_by TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0,
                UNIQUE(target, sequence))",
            "CREATE TABLE diagnostics (id INTEGER PRIMARY KEY, source TEXT NOT NULL, agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
                agent_name TEXT, entry_id TEXT NOT NULL, at INTEGER NOT NULL, client_at INTEGER,
                level TEXT NOT NULL, message TEXT NOT NULL, acknowledged_at INTEGER, acknowledged_by TEXT,
                UNIQUE(source, agent_id, entry_id))",
            "CREATE INDEX idx_diag_agent ON diagnostics(agent_id, id)",
            "CREATE INDEX idx_diag_time ON diagnostics(at)",
            "CREATE INDEX idx_diag_attention ON diagnostics(level, acknowledged_at, at)",
        ],
        // v3: product renamed. Only touches a sender name nobody customised.
        [
            "UPDATE settings SET value = 'DynAllow' WHERE key = 'smtp_from_name' AND value = 'IP Failover'",
        ],
        // v4: separate hash-only development updates from production releases.
        [
            "ALTER TABLE agents ADD COLUMN update_channel TEXT NOT NULL DEFAULT 'signed'",
            "ALTER TABLE releases ADD COLUMN channel TEXT NOT NULL DEFAULT 'signed'",
        ],
    ];
}

function db_one(string $sql, array $params = []): ?array
{
    $st = db()->prepare($sql);
    $st->execute($params);
    $row = $st->fetch();
    return $row === false ? null : $row;
}

function db_all(string $sql, array $params = []): array
{
    $st = db()->prepare($sql);
    $st->execute($params);
    return $st->fetchAll();
}

function db_val(string $sql, array $params = [])
{
    $st = db()->prepare($sql);
    $st->execute($params);
    return $st->fetchColumn();
}

function db_exec(string $sql, array $params = []): int
{
    $st = db()->prepare($sql);
    $st->execute($params);
    return $st->rowCount();
}

function db_update(string $table, int $id, array $fields): void
{
    if (!$fields) {
        return;
    }
    $sets = [];
    foreach (array_keys($fields) as $k) {
        if (!preg_match('/^[a-z_0-9]+$/', $k)) {
            throw new InvalidArgumentException("bad column $k");
        }
        $sets[] = "$k = :$k";
    }
    $fields['__id'] = $id;
    db_exec("UPDATE $table SET " . implode(', ', $sets) . " WHERE id = :__id", $fields);
}

// ---------------------------------------------------------------------------
// Settings (key/value, editable in the UI)
// ---------------------------------------------------------------------------

function setting_defaults(): array
{
    return [
        'public_url'           => '',          // what agents use to reach us, e.g. https://ipctl.example.com
        'timezone'             => 'America/Chicago',
        'default_interval_sec' => '300',
        'default_missed'       => '2',
        'alert_emails'         => '',          // always notified, comma separated
        'notify_ip_change'     => '1',         // email when an authoritative IP changes
        'ip_confirm_checkins'  => '1',         // consecutive check-ins needed before accepting a new IP
        'ip_check_urls'        => "https://api.ipify.org\nhttps://ipv4.icanhazip.com\nhttps://v4.ident.me",
        'verify_minutes'       => '15',        // DNS drift verification cadence
        'dns_fail_alert_after' => '3',         // consecutive DNS push failures before emailing
        'auto_update'          => '1',         // offer agent self-updates
        'event_retention_days' => '180',
        'stale_days'           => '30',        // "stale" filter for bulk delete
        'clock_skew_sec'       => '300',       // accepted agent clock drift; agents self-correct from server time
        'key_max_age_days'     => '90',        // server asks agents to rotate their keypair after this
        'enroll_valid_days'    => '14',        // how long a survey-issued enrollment code works
        'mismatch_alert_minutes' => '15',      // email if server-seen and agent-signed IPs disagree this long
        'allow_http_feed'      => '0',         // allowlist feeds refuse plain HTTP unless this is 1
        'require_totp'         => '0',         // every user must enroll 2FA before doing anything
        'min_key_protector'    => 'none',      // none | dpapi | tpm  — refuse enrollment below this
        'webhook_url'          => '',          // optional: POST JSON for every alert (Teams/Slack/ntfy/n8n)
        'cron_ping_url'        => '',          // optional dead-man's switch pinged every cron run
        'smtp_host'            => '',
        'smtp_port'            => '587',
        'smtp_security'        => 'starttls',  // starttls | ssl | none
        'smtp_user'            => '',
        'smtp_pass_enc'        => '',
        'smtp_from'            => '',
        'smtp_from_name'       => 'DynAllow',
        'cron_last_run'        => '0',
    ];
}

function setting(string $key): string
{
    static $cache = null;
    if ($cache === null || $key === '__reload') {
        $cache = setting_defaults();
        foreach (db_all('SELECT key, value FROM settings') as $r) {
            $cache[$r['key']] = $r['value'];
        }
        if ($key === '__reload') {
            return '';
        }
    }
    return (string)($cache[$key] ?? '');
}

function setting_set(string $key, string $value): void
{
    db_exec('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', [$key, $value]);
    setting('__reload');
}
