<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_admin();

/**
 * One registry drives rendering, the save whitelist, and bounds. Bounds
 * mirror the clamps in the consuming code so the UI can't store a value the
 * consumer would silently ignore.
 */
$registry = [
    'General' => [
        'public_url' => ['Public URL for agents', 'url', 'The address agents use to reach this server, e.g. <code>https://ipctl.example.com</code>. Pinned into every provisioning profile. Plain HTTP is safe for agents (their traffic is end-to-end encrypted); HTTPS is still better.'],
        'timezone' => ['Time zone', 'tz', ''],
        'default_interval_sec' => ['Default check-in interval (seconds)', ['int', 60, 3600], ''],
        'default_missed' => ['Default missed check-ins before an alert', ['int', 1, 20], ''],
        'ip_check_urls' => ['IP lookup services (one per line)', 'lines', 'Agents ask these "what is my IP?" services, in order. IPv4-only services work best.'],
        'ip_confirm_checkins' => ['Check-ins needed to confirm a new IP', ['int', 1, 5], '1 = act on the first verified change. 2+ rides out brief flaps at the cost of slower failover.'],
    ],
    'Alerts' => [
        'alert_emails' => ['Always email', 'emails', 'Comma-separated; these get every alert for every site.'],
        'notify_ip_change' => ['Email when a site\'s IP changes', 'bool', ''],
        'dns_fail_alert_after' => ['Email after this many failed DNS pushes in a row', ['int', 1, 20], ''],
        'mismatch_alert_minutes' => ['Email when an IP has been held for (minutes)', ['int', 1, 1440], ''],
        'webhook_url' => ['Webhook URL (optional)', 'url', 'Every alert is also POSTed here as JSON with a <code>text</code> field: Slack, Teams workflows, Mattermost, ntfy, n8n…'],
        'cron_ping_url' => ['Cron heartbeat URL (optional)', 'url', 'Pinged every minute by the cron job (e.g. a healthchecks.io check), so you hear about it if the cron itself dies.'],
    ],
    'Security' => [
        'require_totp' => ['Require two-factor sign-in for everyone', 'bool', 'Users without 2FA are sent to set it up before they can do anything else.'],
        'min_key_protector' => ['Minimum agent key protection', ['enum', ['none' => 'Accept anything (report it)', 'dpapi' => 'DPAPI or TPM (refuses Docker and weak Windows)', 'tpm' => 'TPM only']], 'Agents below this are refused at enrollment.'],
        'enroll_valid_days' => ['Provisioning profiles expire after (days)', ['int', 1, 90], ''],
        'key_max_age_days' => ['Agents rotate their key every (days, 0 = never)', ['int', 0, 3650], ''],
        'clock_skew_sec' => ['Accepted agent clock drift (seconds)', ['int', 60, 3600], 'Agents correct their clock from the server automatically; this only covers the first contact.'],
        'auto_update' => ['Update agents automatically', 'bool', 'Offer the active offline-signed release for each platform. Clients verify their pinned offline public key and reject downgrades. Use Releases to upload and deploy.'],
        'allow_http_feed' => ['Allow allowlist feeds over plain HTTP', 'bool', 'Not recommended: anyone in the path could add an address to your firewall allowlist.'],
    ],
    'Housekeeping' => [
        'stale_days' => ['A site is "stale" after this many days without a check-in', ['int', 1, 3650], 'Used by the dashboard\'s Stale filter and "Delete all stale".'],
        'event_retention_days' => ['Keep activity history for (days)', ['int', 7, 3650], ''],
        'verify_minutes' => ['Re-check DNS records every (minutes)', ['int', 5, 1440], 'Detects records changed outside this system and puts them back.'],
    ],
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? 'save');
    if ($action === 'save') {
        $section = (string)($_POST['section'] ?? '');
        $errors = [];
        foreach ($registry[$section] ?? [] as $key => [$label, $type]) {
            $raw = $_POST[$key] ?? '';
            if (is_array($type) && $type[0] === 'int') {
                $val = (string)max($type[1], min($type[2], (int)$raw));
            } elseif (is_array($type) && $type[0] === 'enum') {
                $val = array_key_exists((string)$raw, $type[1]) ? (string)$raw : setting($key);
            } elseif ($type === 'bool') {
                $val = empty($raw) ? '0' : '1';
            } elseif ($type === 'url') {
                $val = rtrim(trim((string)$raw), '/');
                if ($val !== '' && !preg_match('#^https?://[^\s/]+#i', $val)) { $errors[] = "$label must start with http:// or https://"; continue; }
            } elseif ($type === 'emails') {
                $bad = array_diff(preg_split('/[\s,;]+/', trim((string)$raw), -1, PREG_SPLIT_NO_EMPTY), parse_emails((string)$raw));
                if ($bad) { $errors[] = 'Not a valid email: ' . implode(', ', $bad); continue; }
                $val = implode(', ', parse_emails((string)$raw));
            } elseif ($type === 'tz') {
                $val = in_array($raw, DateTimeZone::listIdentifiers(), true) ? (string)$raw : setting($key);
            } elseif ($type === 'lines') {
                $lines = array_filter(array_map('trim', preg_split('/\R/', (string)$raw)), fn($l) => preg_match('#^https?://\S+$#', $l));
                if (!$lines) { $errors[] = "$label needs at least one http(s) URL"; continue; }
                $val = implode("\n", $lines);
            } else {
                $val = trim((string)$raw);
            }
            if ($val !== setting($key)) {
                setting_set($key, $val);
                log_event("Setting changed: $key", 'info');
            }
        }
        foreach ($errors as $e) flash('error', $e);
        if (!$errors) flash('ok', "$section settings saved.");
        redirect('settings.php#' . rawurlencode($section));
    }
    if ($action === 'smtp') {
        foreach (['smtp_host', 'smtp_user', 'smtp_from', 'smtp_from_name'] as $k) setting_set($k, trim((string)($_POST[$k] ?? '')));
        setting_set('smtp_port', (string)max(1, min(65535, (int)($_POST['smtp_port'] ?? 587))));
        setting_set('smtp_security', in_array($_POST['smtp_security'] ?? '', ['starttls', 'ssl', 'none'], true) ? $_POST['smtp_security'] : 'starttls');
        if (($_POST['smtp_pass'] ?? '') !== '') setting_set('smtp_pass_enc', encrypt_str((string)$_POST['smtp_pass']));
        if (!empty($_POST['smtp_pass_clear'])) setting_set('smtp_pass_enc', '');
        log_event('Email (SMTP) settings changed: host ' . setting('smtp_host'), 'info');
        flash('ok', 'Email settings saved.');
        redirect('settings.php#Email');
    }
    if ($action === 'test_mail') {
        $to = alert_recipients() ?: parse_emails((string)$me['email']);
        $r = send_mail($to, '[DynAllow] Test email', "This is a test from the DynAllow control server.\nIf you can read this, alerts will reach you.\n\nSent by {$me['username']}.");
        flash($r['ok'] ? 'ok' : 'error', $r['ok'] ? 'Test email sent to ' . implode(', ', $to) . '.' : 'Test failed: ' . $r['error']);
        redirect('settings.php#Email');
    }
    if ($action === 'test_webhook') {
        notify_webhook('Test webhook', 'This is a test from the DynAllow control server.', null);
        flash('ok', 'Test webhook sent (failures appear in Activity).');
        redirect('settings.php#Alerts');
    }
    if ($action === 'rotate_server_key') {
        $old = server_key_active('kex');
        $new = server_key_create('kex');
        log_event("Server agent key rotated {$old['kid']} → {$new['kid']}", 'warn');
        flash('ok', "New server key {$new['kid']}. Agents pinned to {$old['kid']} keep working and are handed the new key at their next check-in.");
        redirect('settings.php#Keys');
    }
}

page_header('Settings', 'settings');
echo '<h1>Settings</h1><div class="row small">';
foreach (array_merge(array_keys($registry), ['Email', 'Keys']) as $s) echo '<a href="#' . h($s) . '">' . h($s) . '</a> ';
echo '</div>';

foreach ($registry as $section => $fields) {
    echo '<div class="card" id="' . h($section) . '"><h2>' . h($section) . '</h2><form method="post">' . csrf_field()
        . '<input type="hidden" name="action" value="save"><input type="hidden" name="section" value="' . h($section) . '">';
    foreach ($fields as $key => [$label, $type, $help]) {
        $val = setting($key);
        if ($type === 'bool') {
            echo '<div class="field">' . checkbox($key, $val === '1', $label) . ($help ? '<small class="dim">' . $help . '</small>' : '') . '</div>';
            continue;
        }
        if (is_array($type) && $type[0] === 'int') $in = input($key, $val, 'number', ['min' => (string)$type[1], 'max' => (string)$type[2]]);
        elseif (is_array($type) && $type[0] === 'enum') $in = select($key, $type[1], $val);
        elseif ($type === 'tz') $in = select($key, array_combine(DateTimeZone::listIdentifiers(), DateTimeZone::listIdentifiers()), $val);
        elseif ($type === 'lines') $in = '<textarea name="' . h($key) . '">' . h($val) . '</textarea>';
        else $in = input($key, $val, $type === 'url' ? 'url' : 'text');
        echo field($label, $in, $help);
    }
    echo '<button class="primary">Save ' . h(strtolower($section)) . '</button></form>';
    if ($section === 'Alerts' && setting('webhook_url') !== '') {
        echo ' ' . action_button('test_webhook', 'Send test webhook');
    }
    echo '</div>';
}

echo '<div class="card" id="Email"><h2>Email</h2><p class="small dim">Built-in SMTP client: works with Microsoft 365, Gmail, SMTP2GO, or your own relay. No local mail server needed.</p>'
    . '<form method="post" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="smtp"><div class="cols2">'
    . field('SMTP server', input('smtp_host', setting('smtp_host'), 'text', ['placeholder' => 'smtp.office365.com']))
    . field('Port', input('smtp_port', setting('smtp_port'), 'number'))
    . field('Encryption', select('smtp_security', ['starttls' => 'STARTTLS (587)', 'ssl' => 'SSL/TLS (465)', 'none' => 'None (local relay only)'], setting('smtp_security')))
    . field('Username', input('smtp_user', setting('smtp_user'), 'text', ['autocomplete' => 'off']))
    . field('Password', input('smtp_pass', '', 'password', ['autocomplete' => 'new-password', 'placeholder' => setting('smtp_pass_enc') !== '' ? '•••••••• (saved — leave blank to keep)' : '']))
    . field('From address', input('smtp_from', setting('smtp_from'), 'email'))
    . field('From name', input('smtp_from_name', setting('smtp_from_name')))
    . '</div>' . (setting('smtp_pass_enc') !== '' ? checkbox('smtp_pass_clear', false, 'Remove the saved password') : '')
    . '<button class="primary">Save email settings</button></form><div class="mt">' . action_button('test_mail', 'Send a test email') . '</div></div>';

$kex = server_key_active('kex');
$sign = server_key_active('sign');
echo '<div class="card" id="Keys"><h2>Server keys</h2><table class="kv">'
    . '<tr><th>Agent key (pinned in profiles)</th><td class="mono">' . h($kex['kid']) . ' <span class="dim">since ' . h(fmt_time((int)$kex['created_at'])) . '</span></td></tr>'
    . '<tr><th>Feed signing key</th><td class="mono">' . h($sign['kid']) . ' <span class="dim">public key at <a href="feed.php?pubkey=1">feed.php?pubkey=1</a></span></td></tr>'
    . '<tr><th>Retired agent keys still honored</th><td>' . (int)db_val("SELECT COUNT(*) FROM server_keys WHERE purpose = 'kex' AND active = 0") . '</td></tr></table>'
    . '<p class="small dim">Rotating creates a new agent key. Agents keep working with the old one and are moved to the new one, authenticated, at their next check-in.</p>'
    . action_button('rotate_server_key', 'Rotate the server agent key', [], '', 'Create a new server key? Existing agents move over automatically.')
    . '<p class="small dim">Back up <code>data/</code> regularly: <code>php bin/manage.php backup /path/backup.dynbak</code> — the database alone is useless without <code>data/secret.key</code>.</p></div>';
page_footer();
