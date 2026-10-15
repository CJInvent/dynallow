<?php
declare(strict_types=1);

/**
 * Loaded by every entry point. Pulls in config, DB, and shared helpers.
 * Plain PHP 8.1+ with pdo_sqlite + sodium (both bundled with PHP on
 * Debian/Ubuntu). No Composer, no framework, no curl extension required.
 */

if (PHP_VERSION_ID < 80100) {
    http_response_code(500);
    exit('PHP 8.1 or newer is required.');
}

define('APP_ROOT', dirname(__DIR__));
define('APP_VERSION', '3.0.0');

function app_config(string $key)
{
    static $cfg = null;
    if ($cfg === null) {
        $cfg = require APP_ROOT . '/config.php';
    }
    return $cfg[$key] ?? null;
}

require __DIR__ . '/db.php';
require __DIR__ . '/crypto.php';
require __DIR__ . '/wire.php';
require __DIR__ . '/http.php';
require __DIR__ . '/mailer.php';
require __DIR__ . '/providers.php';
require __DIR__ . '/agents.php';
require __DIR__ . '/auth.php';
require __DIR__ . '/views.php';
require __DIR__ . '/diagnostics.php';
require __DIR__ . '/releases.php';
install_diagnostic_handlers();

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

function h($v): string
{
    return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function app_tz(): DateTimeZone
{
    static $tz = null;
    if ($tz === null) {
        try {
            $tz = new DateTimeZone(setting('timezone') ?: 'UTC');
        } catch (Throwable $e) {
            $tz = new DateTimeZone('UTC');
        }
    }
    return $tz;
}

function fmt_time(?int $ts): string
{
    if (!$ts) {
        return '—';
    }
    return (new DateTimeImmutable('@' . $ts))->setTimezone(app_tz())->format('Y-m-d H:i T');
}

function fmt_ago(?int $ts): string
{
    if (!$ts) {
        return 'never';
    }
    $d = time() - $ts;
    if ($d < 0) {
        return 'in ' . fmt_duration(-$d);
    }
    return fmt_duration($d) . ' ago';
}

function fmt_duration(int $s): string
{
    if ($s < 60) return $s . 's';
    if ($s < 3600) return intdiv($s, 60) . 'm';
    if ($s < 86400) return intdiv($s, 3600) . 'h ' . intdiv($s % 3600, 60) . 'm';
    return intdiv($s, 86400) . 'd ' . intdiv($s % 86400, 3600) . 'h';
}

function log_event(string $message, string $level = 'info', ?array $agent = null, ?string $actor = null): void
{
    if ($actor === null) {
        $actor = function_exists('current_user') && current_user() ? current_user()['username'] : 'system';
    }
    $message = diagnostic_redact($message);
    if (in_array($level, ['warn', 'error'], true)) server_diagnostic($level, ($agent ? $agent['name'] . ': ' : '') . $message);
    if (app_config('audit_syslog')) error_log('[dynallow-audit] ' . json_encode(['at' => time(), 'actor' => $actor, 'agent' => $agent['uid'] ?? null, 'level' => $level, 'message' => $message]));
    db_exec(
        'INSERT INTO events(at, agent_id, agent_name, actor, level, message) VALUES(?,?,?,?,?,?)',
        [time(), $agent['id'] ?? null, $agent['name'] ?? null, $actor, $level, $message]
    );
}

function random_token(int $bytes = 32): string
{
    return bin2hex(random_bytes($bytes));
}

function parse_emails(string $list): array
{
    $out = [];
    foreach (preg_split('/[\s,;]+/', $list) as $e) {
        $e = trim($e);
        if ($e !== '' && filter_var($e, FILTER_VALIDATE_EMAIL)) {
            $out[strtolower($e)] = $e;
        }
    }
    return array_values($out);
}

function parse_tags(string $list): array
{
    $out = [];
    foreach (preg_split('/[,]+/', $list) as $t) {
        $t = strtolower(trim($t));
        $t = preg_replace('/[^a-z0-9._-]+/', '-', $t);
        if ($t !== '' && $t !== '-') {
            $out[$t] = $t;
        }
    }
    return array_values($out);
}

function valid_hostname(string $host): bool
{
    $host = rtrim($host, '.');
    if (strlen($host) > 253 || strpos($host, '.') === false) {
        return false;
    }
    foreach (explode('.', $host) as $label) {
        if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i', $label)) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// IP helpers
// ---------------------------------------------------------------------------

function ip_in_cidr(string $ip, string $cidr): bool
{
    if (strpos($cidr, '/') === false) {
        return inet_pton($ip) !== false && inet_pton($cidr) !== false && inet_pton($ip) === inet_pton($cidr);
    }
    [$net, $bits] = explode('/', $cidr, 2);
    $ipBin = @inet_pton($ip);
    $netBin = @inet_pton($net);
    if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin)) {
        return false;
    }
    if (!preg_match('/^[0-9]+$/D', $bits) || (int)$bits > strlen($ipBin) * 8) return false;
    $bits = (int)$bits;
    $bytes = intdiv($bits, 8);
    if (substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = chr((0xFF << (8 - $rem)) & 0xFF);
    return (($ipBin[$bytes] & $mask) === ($netBin[$bytes] & $mask));
}

function ip_is_trusted_proxy(string $ip): bool
{
    foreach ((array)app_config('trusted_proxies') as $cidr) {
        if (ip_in_cidr($ip, (string)$cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * Real client address. Walks X-Forwarded-For right-to-left, skipping hops
 * that are trusted proxies, so a client can't spoof its IP by sending its
 * own X-Forwarded-For header.
 */
function client_ip(): string
{
    $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!ip_is_trusted_proxy($remote)) {
        return $remote;
    }
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    $hops = array_reverse(array_filter(array_map('trim', explode(',', $xff))));
    foreach ($hops as $hop) {
        if (filter_var($hop, FILTER_VALIDATE_IP) === false) {
            break;
        }
        if (!ip_is_trusted_proxy($hop)) {
            return $hop;
        }
    }
    return $remote;
}

/** True when the browser/consumer reached us over TLS (directly or via a trusted proxy). */
function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    return ip_is_trusted_proxy($_SERVER['REMOTE_ADDR'] ?? '')
        && strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

/** Normalizes IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain IPv4. */
function normalize_ip(string $ip): string
{
    if (stripos($ip, '::ffff:') === 0 && filter_var(substr($ip, 7), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return substr($ip, 7);
    }
    return $ip;
}

function is_public_ipv4(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
        // 100.64.0.0/10 is carrier-grade NAT space: never a usable public address.
        && !ip_in_cidr($ip, '100.64.0.0/10');
}

function is_ipv6(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}
