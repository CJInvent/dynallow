<?php
declare(strict_types=1);

/**
 * Page chrome + small render helpers. No inline <script> or event handlers
 * anywhere (CSP script-src 'self'): behaviour lives in assets/app.js and is
 * attached through data-* attributes.
 */

function send_security_headers(): void
{
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000');
    }
}

function page_header(string $title, string $active = ''): void
{
    send_security_headers();
    $u = current_user();
    $nav = [
        'index'  => ['Dashboard', 'index.php', false],
        'survey' => ['New site', 'survey.php', false],
        'events' => ['Activity', 'events.php', false],
        'accounts' => ['DNS accounts', 'accounts.php', true],
        'feeds'  => ['Allowlist feeds', 'feeds.php', true],
        'users'  => ['Users', 'users.php', true],
        'settings' => ['Settings', 'settings.php', true],
    ];
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . h($title) . ' · IP Failover</title><link rel="stylesheet" href="assets/app.css?v=' . APP_VERSION . '">';
    echo '<script src="assets/app.js?v=' . APP_VERSION . '" defer></script></head><body>';
    if ($u) {
        echo '<header class="top"><a class="brand" href="index.php"><span class="dot"></span>IP Failover</a><nav>';
        foreach ($nav as $key => [$label, $href, $adminOnly]) {
            if ($adminOnly && $u['role'] !== 'admin') {
                continue; // absent, not disabled
            }
            echo '<a href="' . $href . '"' . ($active === $key ? ' class="on"' : '') . '>' . h($label) . '</a>';
        }
        echo '</nav><div class="who"><a href="account.php"' . ($active === 'account' ? ' class="on"' : '') . '>' . h($u['username'])
            . ' <span class="role">' . h($u['role']) . '</span></a>'
            . '<form method="post" action="logout.php">' . csrf_field() . '<button class="linkish">Sign out</button></form></div></header>';
        foreach (system_banners($u) as [$tone, $msg]) {
            echo '<div class="banner ' . $tone . '">' . $msg . '</div>';
        }
    }
    echo '<main>';
    if (session_status() === PHP_SESSION_ACTIVE) {
        foreach (take_flashes() as [$type, $msg]) {
            echo '<div class="flash ' . h($type) . '">' . h($msg) . '</div>';
        }
    }
}

function page_footer(): void
{
    echo '</main><footer>IP Failover control server ' . APP_VERSION . '</footer></body></html>';
}

/** Server-wide conditions an operator must not miss. */
function system_banners(array $u): array
{
    $b = [];
    $cron = (int)setting('cron_last_run');
    if ($cron === 0 || time() - $cron > 300) {
        $b[] = ['bad', '<strong>The cron job is not running</strong> (' . ($cron ? 'last ran ' . h(fmt_ago($cron)) : 'never ran')
            . '). Missed-check-in emails, DNS retries and drift checks are stopped. See deploy/ipfailover.cron.'];
    }
    if (!is_https()) {
        $b[] = ['warn', 'This admin page is being served over <strong>plain HTTP</strong>. Agents are protected either way, but your login and session are not. Put the site behind HTTPS.'];
    }
    if (setting('public_url') === '' && $u['role'] === 'admin') {
        $b[] = ['warn', 'Set <a href="settings.php">Settings → General → Public URL for agents</a> before creating sites.'];
    }
    return $b;
}

function badge(string $tone, string $label, string $title = ''): string
{
    return '<span class="badge ' . h($tone) . '"' . ($title !== '' ? ' title="' . h($title) . '"' : '') . '>' . h($label) . '</span>';
}

function status_badge(array $st): string
{
    return badge($st['tone'], $st['label'], $st['detail']);
}

function ip_source_badge(?string $src): string
{
    $map = [
        'verified'     => ['good', 'verified'],
        'verified-v6'  => ['good', 'verified (v6)'],
        'server-seen'  => ['neutral', 'server-seen'],
        'agent-signed' => ['neutral', 'agent-signed'],
        'manual'       => ['neutral', 'set by admin'],
        'approved'     => ['good', 'approved'],
    ];
    [$tone, $label] = $map[$src ?? ''] ?? ['muted', $src ?: 'none'];
    return badge($tone, $label);
}

function target_dot(array $t): string
{
    $tone = !$t['enabled'] ? 'muted' : ['ok' => 'good', 'fault' => 'bad', 'pending' => 'neutral'][$t['state']] ?? 'muted';
    return '<span class="tdot ' . $tone . '" title="' . h($t['state'] . ': ' . $t['detail']) . '"></span>';
}

function protector_badge(?string $p): string
{
    switch ($p) {
        case 'tpm': return badge('good', 'TPM', 'Private key wrapped by this machine\'s TPM');
        case 'dpapi': return badge('neutral', 'DPAPI', 'Private key wrapped with Windows DPAPI (machine scope); no TPM available');
        case 'container-file': return badge('warn', 'container file', 'Private key in the container volume (no TPM/DPAPI in Docker)');
        case 'plaintext': return badge('bad', 'PLAINTEXT', 'No TPM or DPAPI: key is only obfuscated on disk');
        default: return badge('muted', '—');
    }
}

function field(string $label, string $input, string $help = ''): string
{
    return '<label class="field"><span>' . h($label) . '</span>' . $input . ($help !== '' ? '<small>' . $help . '</small>' : '') . '</label>';
}

function input(string $name, $value = '', string $type = 'text', array $attrs = []): string
{
    $a = '';
    foreach ($attrs as $k => $v) {
        $a .= $v === true ? ' ' . h($k) : ' ' . h($k) . '="' . h($v) . '"';
    }
    return '<input type="' . h($type) . '" name="' . h($name) . '" value="' . h($value) . '"' . $a . '>';
}

function select(string $name, array $options, $selected, array $attrs = []): string
{
    $a = '';
    foreach ($attrs as $k => $v) {
        $a .= $v === true ? ' ' . h($k) : ' ' . h($k) . '="' . h($v) . '"';
    }
    $o = '';
    foreach ($options as $val => $label) {
        $o .= '<option value="' . h($val) . '"' . ((string)$val === (string)$selected ? ' selected' : '') . '>' . h($label) . '</option>';
    }
    return '<select name="' . h($name) . '"' . $a . '>' . $o . '</select>';
}

function checkbox(string $name, bool $checked, string $label): string
{
    return '<label class="check"><input type="checkbox" name="' . h($name) . '" value="1"' . ($checked ? ' checked' : '') . '> ' . h($label) . '</label>';
}

/** A POST button for one action (CSRF included). $confirm text → app.js asks first. */
function action_button(string $action, string $label, array $hidden = [], string $class = '', string $confirm = '', string $url = ''): string
{
    $h = csrf_field() . '<input type="hidden" name="action" value="' . h($action) . '">';
    foreach ($hidden as $k => $v) {
        $h .= '<input type="hidden" name="' . h($k) . '" value="' . h($v) . '">';
    }
    return '<form method="post" class="inline"' . ($url !== '' ? ' action="' . h($url) . '"' : '') . '>' . $h
        . '<button class="' . h($class) . '"' . ($confirm !== '' ? ' data-confirm="' . h($confirm) . '"' : '') . '>' . h($label) . '</button></form>';
}

function trust_modes(): array
{
    return [
        'agree'  => 'Agree (recommended): agent and server must see the same IP',
        'manual' => 'Manual: like Agree, and a person approves every change',
        'server' => 'Server-seen only (sites with multiple WAN links)',
        'agent'  => 'Agent-signed only (control server reached through a proxy you can\'t trust-list)',
    ];
}

function interval_options(): array
{
    return ['60' => 'every minute', '120' => 'every 2 minutes', '300' => 'every 5 minutes', '600' => 'every 10 minutes', '900' => 'every 15 minutes', '1800' => 'every 30 minutes'];
}

/** One DNS-target editor row; used by the survey and the agent page. */
function target_row_html(array $accounts, string $prefix, array $v = [], bool $removable = true): string
{
    $opts = '';
    foreach ($accounts as $a) {
        $meta = providers()[$a['provider']] ?? ['creates' => false, 'label' => $a['provider']];
        $domain = dns_account_domain($a);
        $opts .= '<option value="' . (int)$a['id'] . '" data-provider="' . h($a['provider']) . '" data-creates="' . ($meta['creates'] ? '1' : '0')
            . '" data-domain="' . h($domain) . '"' . ((string)($v['account_id'] ?? '') === (string)$a['id'] ? ' selected' : '') . '>'
            . h($a['name'] . ' — ' . $meta['label']) . '</option>';
    }
    $mode = $v['name_mode'] ?? 'random';
    $h = '<div class="target-row"><div class="cols2">';
    $h .= field('DNS account', '<select name="' . $prefix . '[account_id]" data-account required>' . $opts . '</select>',
        'Accounts are set up once by an admin under DNS accounts.');
    $h .= field('Name', select($prefix . '[name_mode]', ['random' => 'Random name (recommended)', 'custom' => 'I\'ll type the name'], $mode, ['data-name-mode' => '1']),
        'A random name is hard to guess, so it isn\'t a target for scanners.');
    $h .= '</div>';
    $h .= '<div data-when-random class="small dim">Will be created as <code>xxxxxxxxxxxx<span data-domain-label></span></code> when you save.</div>';
    $h .= '<div data-when-custom>' . field('Hostname', input($prefix . '[hostname]', $v['hostname'] ?? '', 'text', ['data-hostname' => '1', 'placeholder' => 'pbx.customer.com  or just  pbx']),
        'For DynDNS-style accounts the name must already exist at the provider.') . '</div>';
    foreach (providers() as $pkey => $meta) {
        foreach ($meta['target_fields'] as $f) {
            $h .= '<div data-target-provider="' . h($pkey) . '" class="hidden">' . field($f['label'],
                input($prefix . '[tf_' . $f['key'] . ']', '', $f['type'] === 'secret' ? 'password' : 'text', ['autocomplete' => 'off']), h($f['help'] ?? '')) . '</div>';
        }
    }
    $h .= '<div class="row">' . '<label class="field w-ttl"><span>TTL (seconds)</span>' . input($prefix . '[ttl]', $v['ttl'] ?? '120', 'number', ['min' => '30', 'max' => '86400']) . '</label>';
    $h .= '<span data-cf-only>' . checkbox($prefix . '[proxied]', !empty($v['proxied']), 'Cloudflare proxy (orange cloud) — leave OFF for SIP/VPN') . '</span>';
    if ($removable) {
        $h .= '<button type="button" class="small" data-remove-row>Remove</button>';
    }
    return $h . '</div></div>';
}
