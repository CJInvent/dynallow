<?php
declare(strict_types=1);

/**
 * Allowlist feed: the authoritative IPs, for firewalls, PBXes and scripts.
 *
 *   GET /feed.php?token=XXXX[&format=txt|json|csv][&tag=pbx]
 *   GET /feed.php?pubkey=1        the key that signs feeds (no token needed)
 *
 * txt  = one address per line: pfSense/OPNsense URL table alias, FortiGate
 *        external threat feed, MikroTik fetch scripts, iptables/ipset scripts.
 *
 * Zero-trust defaults: HTTPS only (an IP slipped into a firewall allowlist is
 * the worst thing a man-in-the-middle could do here), tokens can be pinned to
 * the consumer's source address, and every response carries an ECDSA P-256
 * signature (X-IPF-Signature, base64 r||s over the exact body) for consumers
 * that can check one.
 */
require dirname(__DIR__) . '/src/bootstrap.php';

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function feed_fail(int $code, string $msg): void
{
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg, "\n";
    exit;
}

$sign = server_key_active('sign');
if (isset($_GET['pubkey'])) {
    header('Content-Type: application/json');
    echo json_encode(['kid' => $sign['kid'], 'curve' => 'P-256', 'public_key_raw_b64' => $sign['public_key'],
                      'public_key_pem' => "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(hex2bin(IPF_SPKI_P256_PREFIX) . base64_decode($sign['public_key'])), 64, "\n") . "-----END PUBLIC KEY-----"]);
    exit;
}

if (!is_https() && setting('allow_http_feed') !== '1') {
    feed_fail(403, 'Refused: allowlist feeds are only served over HTTPS (Settings → Security to override, not recommended).');
}
$token = (string)($_GET['token'] ?? '');
if ($token === '' && preg_match('/^Bearer\s+(\S+)$/', (string)($_SERVER['HTTP_AUTHORIZATION'] ?? ''), $m)) {
    $token = $m[1];
}
$bucket = 'feed:' . client_ip();
if (rate_limited($bucket, 20, 600)) {
    feed_fail(429, 'Too many failed attempts.');
}
$ft = $token !== '' ? db_one('SELECT * FROM feed_tokens WHERE token_hash = ?', [token_hash($token)]) : null;
if (!$ft) {
    rate_hit($bucket);
    feed_fail(401, 'Unknown feed token.');
}
$src = client_ip();
$allowed = array_filter(array_map('trim', preg_split('/[\s,]+/', (string)$ft['allowed_sources'])));
if ($allowed) {
    $ok = false;
    foreach ($allowed as $cidr) {
        if (ip_in_cidr($src, $cidr)) { $ok = true; break; }
    }
    if (!$ok) {
        log_event("Feed token '{$ft['name']}' refused for $src (not in its allowed sources)", 'warn', null, 'feed');
        feed_fail(403, 'This feed token is not allowed from your address.');
    }
}
db_exec('UPDATE feed_tokens SET last_used_at = ?, last_used_from = ? WHERE id = ?', [time(), $src, $ft['id']]);

// A request may narrow a token's scope, never widen it.
$tokenTag = strtolower(trim((string)$ft['tag_filter']));
$tag = strtolower(trim((string)($_GET['tag'] ?? $tokenTag)));
if ($tokenTag !== '' && $tag !== $tokenTag) feed_fail(403, 'This token is restricted to its configured tag.');
$maxAge = max(1, (int)$ft['max_age_hours']) * 3600;
$rows = [];
foreach (db_all("SELECT * FROM agents WHERE enabled = 1 AND decommission = 0 AND current_ipv4 IS NOT NULL ORDER BY name") as $a) {
    // A site that has gone quiet drops OUT of the allowlist: its last address
    // may already belong to someone else (CGNAT pools recycle).
    if (time() - (int)$a['last_checkin_at'] > $maxAge) continue;
    if ($tag !== '' && !in_array($tag, parse_tags($a['tags']), true)) continue;
    $rows[] = $a;
}

$format = (string)($_GET['format'] ?? 'txt');
$lines = [];
switch ($format) {
    case 'json':
        header('Content-Type: application/json');
        $out = ['generated_at' => gmdate('c'), 'tag' => $tag ?: null, 'max_age_hours' => (int)$ft['max_age_hours'], 'entries' => []];
        foreach ($rows as $a) {
            $e = ['name' => $a['name'], 'customer' => $a['customer'], 'ipv4' => $a['current_ipv4'], 'verified_by' => $a['ip_source'],
                  'ip_since' => $a['ip_changed_at'] ? gmdate('c', (int)$a['ip_changed_at']) : null,
                  'last_checkin' => gmdate('c', (int)$a['last_checkin_at']), 'tags' => parse_tags($a['tags']),
                  'hostnames' => array_column(db_all('SELECT hostname FROM dns_targets WHERE agent_id = ? AND enabled = 1', [$a['id']]), 'hostname')];
            if ($ft['include_ipv6'] && $a['current_ipv6']) {
                $e['ipv6_prefix'] = ipv6_prefix64_cidr($a['current_ipv6']);
            }
            $out['entries'][] = $e;
        }
        $body = json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        break;
    case 'csv':
        header('Content-Type: text/csv; charset=utf-8');
        $lines[] = 'name,customer,ipv4,ipv6_prefix,verified_by,last_checkin_utc';
        foreach ($rows as $a) {
            $v6 = ($ft['include_ipv6'] && $a['current_ipv6']) ? ipv6_prefix64_cidr($a['current_ipv6']) : '';
            $lines[] = implode(',', array_map(fn($v) => '"' . str_replace('"', '""', (string)$v) . '"',
                [$a['name'], $a['customer'], $a['current_ipv4'], $v6, $a['ip_source'], gmdate('Y-m-d H:i:s', (int)$a['last_checkin_at'])]));
        }
        $body = implode("\n", $lines) . "\n";
        break;
    default:
        header('Content-Type: text/plain; charset=utf-8');
        $seen = [];
        foreach ($rows as $a) {
            $seen[$a['current_ipv4']] = true;
            if ($ft['include_ipv6'] && $a['current_ipv6']) $seen[ipv6_prefix64_cidr($a['current_ipv6'])] = true;
        }
        $body = $seen ? implode("\n", array_keys($seen)) . "\n" : '';
}
$sig = ecdsa_sign_p1363(decrypt_str($sign['private_enc']), $body);
header('X-IPF-Key-Id: ' . $sign['kid']);
header('X-IPF-Signature: ' . base64_encode($sig));
echo $body;
