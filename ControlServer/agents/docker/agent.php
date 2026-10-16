<?php
declare(strict_types=1);

/**
 * DynAllow agent — Docker edition.
 *
 * Deliberately small. It holds NO DNS credentials and talks to NO DNS
 * provider: it proves who it is, reports the address it sees, and does what
 * the authenticated server response says. The control server does the rest.
 *
 * Runs on the stock php:8.3-cli-alpine image (openssl + json are built in).
 *
 *   php launcher.php           run the agent loop
 *   php launcher.php health    container HEALTHCHECK (exit 0 healthy, 1 not)
 *   php launcher.php status    print the last status
 *
 * Files in DATA_DIR (default /data, a volume):
 *   provisioning.json   the profile from the survey; consumed and DESTROYED on start
 *   state.json          server URL, pinned server key, agent uid, interval
 *   agent-key.json      identity keypair, two slots (active / pending rotation)
 *   status.json         what `health` reads
 *   current-release.json   signed update bundle verified by the immutable launcher
 *   update-state.json      accepted release sequence and manifest hash
 */

const AGENT_VERSION = '3.0.0';
const RELEASE_SEQUENCE = 1;
const SPKI_P256_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

$DATA = rtrim(getenv('DATA_DIR') ?: '/data', '/');

// Executed only by the immutable, signature-checking launcher.
require_once (getenv('DYNALLOW_APP_DIR') ?: '/app') . '/release.php';

function logline(string $level, string $msg): void
{
    global $DATA;
    $msg = preg_replace('~https?://[^\s]+~', '[URL]', $msg);
    $msg = preg_replace('/\b(password|token|secret|authorization|enroll_token|private_pem)\s*[:=]\s*\S+/i', '$1=[REDACTED]', $msg);
    $msg = substr($msg, 0, 1200);
    fwrite(STDOUT, gmdate('Y-m-d\TH:i:s\Z') . " [$level] $msg\n");
    $q = jread("$DATA/log-spool.json") ?? [];
    $q[] = ['id' => bin2hex(random_bytes(16)), 'at' => time(), 'level' => strtolower($level), 'message' => $msg];
    if (count($q) > 500) {
        $q = array_slice($q, -499);
        array_unshift($q, ['id' => bin2hex(random_bytes(16)), 'at' => time(), 'level' => 'warn', 'message' => 'Log spool overflow: oldest undelivered records dropped (500 entry limit)']);
    }
    jwrite("$DATA/log-spool.json", $q);
}

function jread(string $path): ?array
{
    if (!is_file($path)) return null;
    $d = json_decode((string)file_get_contents($path), true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($d)) throw new RuntimeException('Invalid persisted JSON: ' . basename($path));
    return $d;
}

/** Write, flush, read back. A key held only in memory dies at the next restart. */
function jwrite(string $path, array $data): void
{
    $tmp = "$path.tmp";
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $fh = fopen($tmp, 'wb');
    if (!$fh) throw new RuntimeException("cannot write $tmp");
    fwrite($fh, $json);
    fflush($fh);
    if (function_exists('fsync')) fsync($fh);
    fclose($fh);
    chmod($tmp, 0600);
    rename($tmp, $path);
    if ((string)file_get_contents($path) !== $json) {
        throw new RuntimeException("$path did not read back what was written");
    }
}

function destroy_file(string $path): void
{
    if (!is_file($path)) return;
    $size = filesize($path);
    if ($size > 0 && ($fh = @fopen($path, 'r+b'))) {
        fwrite($fh, str_repeat("\0", $size));
        fflush($fh);
        fclose($fh);
    }
    if (!@unlink($path)) {
        logline('WARN', "could not delete $path — it still holds an enrollment token; delete it by hand");
    }
}

// ---------------------------------------------------------------------------
// Crypto (IPF1 — must match the control server's src/wire.php byte for byte)
// ---------------------------------------------------------------------------

function p256_new(): array
{
    $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($k, $pem);
    return [$pem, p256_raw($k)];
}

function p256_raw($key): string
{
    $d = openssl_pkey_get_details($key);
    return "\x04" . str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT);
}

function p256_pub($raw)
{
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(hex2bin(SPKI_P256_PREFIX) . $raw), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $k = openssl_pkey_get_public($pem);
    if (!$k) throw new RuntimeException('invalid P-256 public key');
    return $k;
}

function sig_p1363(string $pem, string $data): string
{
    openssl_sign($data, $der, openssl_pkey_get_private($pem), OPENSSL_ALGO_SHA256);
    $pos = 2 + ((ord($der[1]) & 0x80) ? (ord($der[1]) & 0x7f) : 0);
    $out = '';
    for ($i = 0; $i < 2; $i++) {
        $len = ord($der[$pos + 1]);
        $out .= str_pad(ltrim(substr($der, $pos + 2, $len), "\0"), 32, "\0", STR_PAD_LEFT);
        $pos += 2 + $len;
    }
    return $out;
}

function verify_p1363(string $raw, string $data, string $sig): bool
{
    $enc = function (string $i): string {
        $i = ltrim($i, "\0");
        if ($i === '') $i = "\0";
        if (ord($i[0]) & 0x80) $i = "\0" . $i;
        return "\x02" . chr(strlen($i)) . $i;
    };
    $body = $enc(substr($sig, 0, 32)) . $enc(substr($sig, 32));
    return openssl_verify($data, "\x30" . chr(strlen($body)) . $body, p256_pub($raw), OPENSSL_ALGO_SHA256) === 1;
}

/** Seals a request to the pinned server key; returns [body, ctx]. */
function seal_request(array $state, array $plain, ?string $signPem): array
{
    $serverRaw = base64_decode($state['server_key']);
    [$ephPem, $epk] = p256_new();
    $z = openssl_pkey_derive(p256_pub($serverRaw), openssl_pkey_get_private($ephPem), 32);
    $k = hash('sha256', 'IPF1' . $z . $epk, true);
    $keys = [];
    foreach (['req-enc', 'req-mac', 'resp-enc', 'resp-mac'] as $l) {
        $keys[$l] = hash_hmac('sha256', $l, $k, true);
    }
    $iv = random_bytes(16);
    $ct = openssl_encrypt(json_encode($plain, JSON_UNESCAPED_SLASHES), 'aes-256-cbc', $keys['req-enc'], OPENSSL_RAW_DATA, $iv);
    $kid = $state['server_key_id'];
    $mac = hash_hmac('sha256', 'IPF1|req|' . $kid . $epk . $iv . $ct, $keys['req-mac'], true);
    $env = ['v' => 1, 'kid' => $kid, 'epk' => base64_encode($epk), 'iv' => base64_encode($iv), 'ct' => base64_encode($ct), 'mac' => base64_encode($mac)];
    if ($signPem !== null) {
        $env['sig'] = base64_encode(sig_p1363($signPem, 'IPF1|sig|' . $kid . $epk . $iv . $ct . $mac));
    }
    return [json_encode($env), ['keys' => $keys, 'epk' => $epk, 'nonce' => $plain['nonce']]];
}

/** Authenticates and decrypts a response. Anything that fails here is ignored, never obeyed. */
function open_response(array $ctx, string $body): array
{
    $env = json_decode($body, true);
    if (!is_array($env) || ($env['v'] ?? 0) !== 1 || !isset($env['iv'], $env['ct'], $env['mac'])) {
        $msg = is_array($env) ? ($env['error'] ?? 'unknown') . ': ' . ($env['message'] ?? '') : substr($body, 0, 120);
        throw new RuntimeException("unauthenticated response from server ($msg)");
    }
    $iv = base64_decode($env['iv']);
    $ct = base64_decode($env['ct']);
    $mac = base64_decode($env['mac']);
    $expect = hash_hmac('sha256', 'IPF1|resp|' . $ctx['epk'] . $iv . $ct, $ctx['keys']['resp-mac'], true);
    if (!hash_equals($expect, (string)$mac)) {
        throw new RuntimeException('response failed authentication — ignored (possible tampering in transit)');
    }
    $plain = json_decode((string)openssl_decrypt($ct, 'aes-256-cbc', $ctx['keys']['resp-enc'], OPENSSL_RAW_DATA, $iv), true);
    if (!is_array($plain) || ($plain['req_nonce'] ?? '') !== $ctx['nonce']) {
        throw new RuntimeException('response is not bound to this request — ignored (possible replay)');
    }
    return $plain;
}

function http_post(string $url, string $body): string
{
    $ctx = stream_context_create(['http' => [
        'method' => 'POST', 'header' => "Content-Type: application/json\r\nConnection: close\r\nUser-Agent: dynallow-agent/" . AGENT_VERSION,
        'content' => $body, 'timeout' => 30, 'ignore_errors' => true, 'follow_location' => 0,
    ]]);
    $r = @file_get_contents($url, false, $ctx, 0, 1048577);
    if ($r !== false && strlen($r) > 1048576) throw new RuntimeException('Server response too large');
    if ($r === false) {
        throw new RuntimeException('cannot reach control server: ' . (error_get_last()['message'] ?? 'unknown'));
    }
    return $r;
}

function http_get_ip(string $url, int $flag): ?string
{
    $r = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 8, 'follow_location' => 0, 'header' => 'User-Agent: dynallow-agent']]), 0, 129);
    $ip = trim((string)$r);
    return filter_var($ip, FILTER_VALIDATE_IP, $flag) ? $ip : null;
}

// ---------------------------------------------------------------------------
// Identity key custody — two slots, written/flushed/read back, pair verified
// ---------------------------------------------------------------------------

function key_file(): string { global $DATA; return "$DATA/agent-key.json"; }

function key_record(): array
{
    [$pem, $raw] = p256_new();
    return ['key_id' => substr(hash('sha256', $raw), 0, 16), 'public' => base64_encode($raw),
            'protector' => 'container-file', 'private_pem' => $pem, 'created_at' => gmdate('c')];
}

function key_verify_pair(array $rec): void
{
    $probe = random_bytes(32);
    if (!verify_p1363(base64_decode($rec['public']), $probe, sig_p1363($rec['private_pem'], $probe))) {
        throw new RuntimeException('stored key pair does not verify');
    }
}

function keys_load(): array
{
    return jread(key_file()) ?? [];
}

function keys_save(array $k): void
{
    jwrite(key_file(), $k);
    $back = keys_load();
    foreach (['active', 'pending'] as $slot) {
        if (isset($k[$slot])) {
            if (($back[$slot]['public'] ?? '') !== $k[$slot]['public']) throw new RuntimeException("$slot key did not read back");
            key_verify_pair($back[$slot]);
        }
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

function machine_id(): string
{
    global $DATA;
    // Mount the host's /etc/machine-id at /host-machine-id (the shipped
    // compose file does) so a copied volume shows up as a different machine.
    foreach (['/host-machine-id', '/etc/machine-id'] as $f) {
        if (is_readable($f) && trim((string)file_get_contents($f)) !== '') {
            return 'linux:' . hash('sha256', trim((string)file_get_contents($f)));
        }
    }
    if (!is_file("$DATA/machine-id")) {
        file_put_contents("$DATA/machine-id", bin2hex(random_bytes(16)));
    }
    return 'volume:' . trim((string)file_get_contents("$DATA/machine-id"));
}

function write_status(array $s): void
{
    global $DATA;
    $s['updated_at'] = time();
    $s['version'] = AGENT_VERSION;
    jwrite("$DATA/status.json", $s);
}

function consume_profile(?array $state): ?array
{
    global $DATA;
    $path = "$DATA/provisioning.json";
    if (!is_file($path)) {
        return $state;
    }
    $p = jread($path);
    if (!$p || !in_array($p['format'] ?? '', ['dynallow-provisioning', 'ipfailover-provisioning'], true) || empty($p['enroll_token'])) {
        logline('ERROR', 'provisioning.json is not a valid DynAllow profile; ignored and deleted');
        return $state;
    }
    if ($state && !empty($state['enrolled'])) {
        // Never re-point an enrolled agent because a stray profile appeared.
        logline('WARN', 'already enrolled as ' . $state['agent_uid'] . ' — new profile discarded. To re-provision, delete state.json and agent-key.json first.');
        return $state;
    }
    if (!preg_match('#^https?://#', (string)$p['control_url']) || strlen(base64_decode((string)$p['server_key'])) !== 65) {
        logline('ERROR', 'profile has an invalid URL or server key; ignored');
        return $state;
    }
    logline('INFO', 'provisioning profile for ' . $p['site_name'] . ' (' . $p['agent_uid'] . ') applied and destroyed');
    $newState = ['control_url' => $p['control_url'], 'server_key_id' => $p['server_key_id'], 'server_key' => $p['server_key'],
            'agent_uid' => $p['agent_uid'], 'site_name' => $p['site_name'], 'enroll_token' => $p['enroll_token'],
            'enrolled' => false, 'interval' => 300, 'clock_offset' => 0, 'ip_check_urls' => []];
    jwrite("$DATA/state.json", $newState); // persist credential before destroying its source
    destroy_file($path);
    return $newState;
}

function do_request(array &$state, array $plain, ?string $signPem): array
{
    $plain['ts'] = time() + (int)($state['clock_offset'] ?? 0);
    $plain['nonce'] = $plain['nonce'] ?? bin2hex(random_bytes(16));
    [$body, $ctx] = seal_request($state, $plain, $signPem);
    $url = rtrim($state['control_url'], '/') . '/api/v1.php';
    $resp = open_response($ctx, http_post($url, $body));
    if (isset($resp['server_ts'])) {
        $state['clock_offset'] = (int)$resp['server_ts'] - time();   // authenticated, so safe to trust
    }
    if (!empty($resp['server_key']['public_key']) && strlen(base64_decode($resp['server_key']['public_key'])) === 65) {
        // The server rotated its key; this answer was authenticated by the old one.
        $state['server_key_id'] = $resp['server_key']['kid'];
        $state['server_key'] = $resp['server_key']['public_key'];
        logline('INFO', 'server key rotated; now pinned to ' . $state['server_key_id']);
    }
    if (($resp['error'] ?? '') === 'clock_skew' && empty($plain['_clock_retry'])) {
        $plain['_clock_retry'] = true;
        unset($plain['nonce']);
        return do_request($state, $plain, $signPem);
    }
    return $resp;
}

function run_cycle(array &$state): array
{
    global $DATA;
    $keys = keys_load();
    if (empty($keys['active'])) {
        if (!empty($state['enrolled'])) throw new RuntimeException('Enrolled identity is missing; local administrator recovery required');
        $keys['active'] = key_record();
        keys_save($keys);
        logline('INFO', 'generated identity key ' . $keys['active']['key_id'] . ' (written, flushed, read back, pair verified)');
    }
    $urls = $state['ip_check_urls'] ?: ['https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://v4.ident.me'];
    $v4 = null;
    foreach ($urls as $u) {
        if ($v4 = http_get_ip($u, FILTER_FLAG_IPV4)) break;
    }
    $v6 = http_get_ip('https://api6.ipify.org', FILTER_FLAG_IPV6);
    $base = [
        'agent' => $state['agent_uid'], 'observed_ipv4' => $v4, 'observed_ipv6' => $v6,
        'version' => AGENT_VERSION, 'platform' => 'docker', 'os' => php_uname('s') . ' ' . php_uname('r'),
        'release_target' => 'docker', 'release_sequence' => RELEASE_SEQUENCE, 'update_channel' => docker_development_updates(getenv('DYNALLOW_APP_DIR') ?: '/app') ? 'dev-sha256' : 'signed', 'sleep_status' => 'unsupported',
        'update_status' => $state['update_status'] ?? '', 'logs' => array_slice(jread("$DATA/log-spool.json") ?? [], 0, 20),
        'hostname' => gethostname(), 'key_protector' => 'container-file', 'machine_id' => machine_id(),
    ];

    if (empty($state['enrolled'])) {
        $req = $base + ['type' => 'enroll', 'enroll_token' => $state['enroll_token'], 'public_key' => $keys['active']['public']];
        $resp = do_request($state, $req, $keys['active']['private_pem']);
        if (!empty($resp['ok'])) {
            $state['enrolled'] = true;
            unset($state['enroll_token']);   // single use; gone now
            logline('INFO', 'enrolled as ' . $state['agent_uid']);
        }
    } else {
        // Mid-rotation and the server has our pending key: sign with it, and
        // the server promotes it on sight.
        $useSlot = (!empty($keys['pending']) && !empty($state['rotation_sent'])) ? 'pending' : 'active';
        $resp = do_request($state, $base + ['type' => 'checkin'], $keys[$useSlot]['private_pem']);
        if (($resp['error'] ?? '') === 'bad_signature' && $useSlot === 'pending') {
            logline('WARN', 'server did not accept the rotated key; falling back to the current key');
            $state['rotation_sent'] = false;
            $useSlot = 'active';
            $resp = do_request($state, $base + ['type' => 'checkin'], $keys['active']['private_pem']);
        }
        if (($resp['error'] ?? '') === 'clock_skew') {
            logline('WARN', 'clock corrected from authenticated server time; retrying');
            $resp = do_request($state, $base + ['type' => 'checkin'], $keys[$useSlot]['private_pem']);
        }
        if (!empty($keys['pending']) && ($resp['active_key_id'] ?? '') === $keys['pending']['key_id']) {
            $keys['active'] = $keys['pending'];
            unset($keys['pending']);
            keys_save($keys);
            $state['rotation_sent'] = false;
            logline('INFO', 'key rotation complete: now ' . $keys['active']['key_id']);
        }
    }
    if (empty($resp['ok'])) {
        return $resp;
    }

    $acks = array_intersect(array_column($base['logs'], 'id'), (array)($resp['log_ack'] ?? []));
    $q = jread("$DATA/log-spool.json") ?? [];
    jwrite("$DATA/log-spool.json", array_values(array_filter($q, fn($e) => !in_array($e['id'], $acks, true))));
    $state['interval'] = max(60, min(86400, (int)($resp['interval'] ?? 300)));
    $state['ip_check_urls'] = array_values(array_filter((array)($resp['ip_check_urls'] ?? []), fn($u) => is_string($u) && preg_match('#^https?://#', $u)));

    if (!empty($resp['rotate_key']) || (!empty($keys['pending']) && empty($state['rotation_sent']))) {
        if (empty($keys['pending'])) { $keys['pending'] = key_record(); keys_save($keys); }
        $nonce = bin2hex(random_bytes(16));
        $proof = sig_p1363($keys['pending']['private_pem'], 'IPF1|rotate|' . $state['agent_uid'] . '|' . $nonce . '|' . $keys['pending']['public']);
        $r = do_request_with_nonce($state, ['type' => 'rotate', 'agent' => $state['agent_uid'], 'new_public_key' => $keys['pending']['public'],
            'new_key_proof' => base64_encode($proof), 'key_protector' => 'container-file'], $keys['active']['private_pem'], $nonce);
        $state['rotation_sent'] = !empty($r['ok']);
        $okRot = !empty($r['ok']);
        logline($okRot ? 'INFO' : 'WARN', 'key rotation requested by server: ' . ($okRot ? 'pending key registered' : ($r['message'] ?? 'failed')));
    }
    // Persist enrollment / rotation before update can terminate the process.
    jwrite("$DATA/state.json", $state);
    if (empty($resp['decommission']) && !empty($resp['update'])) {
        try { apply_update($resp['update'], $state); }
        catch (Throwable $e) { $state['update_status'] = 'Rejected update: ' . $e->getMessage(); logline('ERROR', $state['update_status']); }
    }
    return $resp;
}

function do_request_with_nonce(array &$state, array $plain, string $pem, string $nonce): array
{
    $plain['ts'] = time() + (int)($state['clock_offset'] ?? 0);
    $plain['nonce'] = $nonce;
    [$body, $ctx] = seal_request($state, $plain, $pem);
    return open_response($ctx, http_post(rtrim($state['control_url'], '/') . '/api/v1.php', $body));
}

function apply_update(array $offer, array &$state): void
{
    global $DATA;
    $hash = (string)($offer['sha256'] ?? '');
    if (!preg_match('/^[a-f0-9]{64}$/D', $hash) || (int)($offer['size'] ?? 0) > RELEASE_MAX_BYTES) throw new RuntimeException('Invalid update offer');
    if (($state['update_attempt_hash'] ?? '') === $hash && time() - (int)($state['update_attempt_at'] ?? 0) < 3600) return;
    $state['update_attempt_hash'] = $hash; $state['update_attempt_at'] = time();
    $bytes = @file_get_contents(rtrim($state['control_url'], '/') . '/release.php?sha256=' . $hash, false,
        stream_context_create(['http' => ['timeout' => 120, 'follow_location' => 0]]), 0, RELEASE_MAX_BYTES + 1);
    if ($bytes === false || strlen($bytes) !== (int)$offer['size'] || !hash_equals($hash, hash('sha256', $bytes))) throw new RuntimeException('Release download hash/size mismatch');
    $m = verify_docker_release($bytes, getenv('DYNALLOW_APP_DIR') ?: '/app');
    $watermark = jread("$DATA/update-state.json") ?? [];
    if ($m['target'] !== 'docker' || $m['sequence'] <= max(RELEASE_SEQUENCE, (int)($watermark['sequence'] ?? 0))
        || version_compare($m['version'], AGENT_VERSION, '<=')) throw new RuntimeException('Release target/version/sequence rejected');
    $code = base64_decode(json_decode($bytes, true)['files']['agent.php']);
    if (!preg_match("/const AGENT_VERSION = '([0-9.]+)'/", $code, $v) || $v[1] !== $m['version']
        || !preg_match('/const RELEASE_SEQUENCE = ([0-9]+);/', $code, $seq) || (int)$seq[1] !== $m['sequence']) throw new RuntimeException('Signed code metadata does not match manifest');
    $tmp = tempnam(sys_get_temp_dir(), 'ipf-lint-');
    try {
        file_put_contents($tmp, $code);
        exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($tmp) . ' 2>&1', $lines, $rc);
        if ($rc !== 0) throw new RuntimeException('Signed PHP release does not parse');
    } finally { @unlink($tmp); }
    // Atomic bundle publish; immutable launcher verifies it again before every execution.
    jwrite("$DATA/current-release.json", json_decode($bytes, true, 16, JSON_THROW_ON_ERROR));
    $state['update_status'] = 'Staged verified release ' . $m['version'] . ' sequence ' . $m['sequence'];
    logline('INFO', $state['update_status']);
    jwrite("$DATA/state.json", $state);
    exit(10);
}

function status_from(array $state, array $resp, ?string $error): array
{
    $ok = $error === null && !empty($resp['ok']);
    $s = [
        'agent_uid' => $state['agent_uid'] ?? null, 'site' => $state['site_name'] ?? null,
        'server_ok' => $ok, 'server_error' => $error ?? ($ok ? null : (($resp['error'] ?? 'error') . ': ' . ($resp['message'] ?? ''))),
        'interval' => (int)($state['interval'] ?? 300),
    ];
    if ($ok) {
        $s['last_success_at'] = time();
        $s['ip'] = $resp['ip'] ?? null;
        $s['targets'] = $resp['targets'] ?? [];
        $s['enabled'] = $resp['agent']['enabled'] ?? true;
        $s['decommission'] = !empty($resp['decommission']);
    }
    return $s;
}

function main(bool $once = false): void
{
    global $DATA;
    if (!is_dir($DATA)) mkdir($DATA, 0700, true);
    $statePath = "$DATA/state.json";
    if (is_file("$DATA/DECOMMISSIONED") && !is_file("$DATA/provisioning.json")) {
        logline('WARN', 'this agent was decommissioned on ' . trim((string)file_get_contents("$DATA/DECOMMISSIONED")) . '. Remove the container (docker compose down).');
        write_status(['server_ok' => false, 'decommissioned' => true, 'server_error' => 'decommissioned — remove this container']);
        while (true) sleep(3600);
    }
    if (is_file("$DATA/provisioning.json")) {
        @unlink("$DATA/DECOMMISSIONED");   // a new profile deliberately brings it back
    }
    $state = consume_profile(jread($statePath));
    if (!$state) {
        logline('ERROR', "not provisioned: put the provisioning profile from the survey at $DATA/provisioning.json and restart");
        write_status(['server_ok' => false, 'server_error' => 'not provisioned (no provisioning.json)']);
        sleep(300);
        exit(1);
    }
    jwrite($statePath, $state);
    $prev = jread("$DATA/status.json") ?? [];
    if (docker_development_updates(getenv('DYNALLOW_APP_DIR') ?: '/app')) logline('WARN', 'DEVELOPMENT mode: SHA-256 updates trust the online server');
    logline('INFO', 'DynAllow agent ' . AGENT_VERSION . ' for ' . ($state['site_name'] ?? '?') . ' -> ' . $state['control_url']);

    while (true) {
        $error = null;
        $resp = [];
        try {
            $resp = run_cycle($state);
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }
        jwrite($statePath, $state);
        $st = status_from($state, $resp, $error);
        if (!$st['server_ok']) {
            // Keep the last known server view so health can explain itself.
            $st += array_intersect_key($prev, array_flip(['last_success_at', 'ip', 'targets', 'enabled']));
            logline('ERROR', (string)$st['server_error']);
        } else {
            $ip = $resp['ip']['authoritative'] ?? 'none';
            logline('INFO', "checked in; authoritative IP $ip (" . ($resp['ip']['source'] ?? '') . ')' . (!empty($resp['ip']['mismatch']) ? ' — HELD: ' . $resp['ip']['detail'] : ''));
        }
        write_status($st);
        $prev = $st;

        if (!empty($resp['decommission'])) {
            logline('WARN', 'DECOMMISSIONED by the control server: identity destroyed. Remove this container.');
            try { $k = keys_load(); do_request($state, ['type' => 'decommission_ack', 'agent' => $state['agent_uid'], 'logs' => array_slice(jread("$DATA/log-spool.json") ?? [], 0, 20)], $k['active']['private_pem']); }
            catch (Throwable $e) { logline('WARN', 'Decommission acknowledgement not delivered'); }
            // Survives restarts (restart: unless-stopped), so the container keeps
            // saying "decommissioned" instead of "not provisioned" and crash-looping.
            file_put_contents("$DATA/DECOMMISSIONED", gmdate('c') . "\n");
            destroy_file(key_file());
            destroy_file($statePath);
            write_status(['server_ok' => false, 'decommissioned' => true, 'server_error' => 'decommissioned — remove this container']);
            while (true) sleep(3600);
        }
        if ($once) return;
        $fatal = in_array($resp['error'] ?? '', ['unknown_agent', 'enroll_invalid', 'enroll_expired', 'protector_too_weak'], true);
        $wait = $st['server_ok'] ? (int)$state['interval'] : ($fatal ? 900 : min(60, (int)$state['interval']));
        sleep($wait);
    }
}

function health(): int
{
    global $DATA;
    $s = jread("$DATA/status.json");
    if (!$s) { echo "UNHEALTHY: no status yet\n"; return 1; }
    $problems = [];
    if (!empty($s['decommissioned'])) $problems[] = 'decommissioned — remove this container';
    $interval = max(60, (int)($s['interval'] ?? 300));
    $last = (int)($s['last_success_at'] ?? 0);
    if (!$last) $problems[] = 'never reached the control server: ' . ($s['server_error'] ?? '');
    elseif (time() - $last > 2 * $interval + 60) $problems[] = 'control server unreachable for ' . (time() - $last) . 's: ' . ($s['server_error'] ?? '');
    if (time() - (int)($s['updated_at'] ?? 0) > 2 * $interval + 120) $problems[] = 'agent loop is not running (status is stale)';
    if (!empty($s['ip']['mismatch'])) $problems[] = 'IP held: ' . ($s['ip']['detail'] ?? 'mismatch');
    foreach ((array)($s['targets'] ?? []) as $t) {
        if (($t['state'] ?? '') === 'fault') $problems[] = 'DNS ' . $t['hostname'] . ': ' . $t['detail'];
    }
    if ($problems) { echo 'UNHEALTHY: ' . implode('; ', $problems) . "\n"; return 1; }
    echo 'HEALTHY: ' . ($s['ip']['authoritative'] ?? 'no IP yet') . ' (' . ($s['ip']['source'] ?? '') . ")\n";
    return 0;
}

if (defined('DYNALLOW_AGENT_TEST')) return;
$mode = $argv[1] ?? 'run';
if ($mode === 'health') exit(health());
if ($mode === 'status') { echo json_encode(jread("$DATA/status.json"), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n"; exit(0); }
main($mode === 'once');
