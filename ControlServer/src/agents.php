<?php
declare(strict_types=1);

/**
 * Agent lifecycle: provisioning profiles, enrollment, check-in, the
 * authoritative-IP decision, key rotation, and server-side DNS sync.
 *
 * INVARIANT (carried over from Nimbus V4-FIRST-ENROLLMENT): a state reachable
 * by doing nothing wrong — provisioned, waiting to install, just enrolled,
 * waiting for the first push — is never shown as an error.
 */

const AGENT_KEY_PROTECTOR_RANK = ['plaintext' => 0, 'container-file' => 0, 'dpapi' => 1, 'tpm' => 2];

function agent_get(int $id): ?array
{
    return db_one('SELECT * FROM agents WHERE id = ?', [$id]);
}

function agent_targets(int $agentId): array
{
    return db_all('SELECT t.*, a.name AS account_name, a.provider FROM dns_targets t
                   JOIN dns_accounts a ON a.id = t.account_id WHERE t.agent_id = ? ORDER BY t.id', [$agentId]);
}

function new_agent_uid(): string
{
    return 'agt_' . random_dns_label(10);
}

// ---------------------------------------------------------------------------
// Provisioning profile (the file the survey hands the technician)
// ---------------------------------------------------------------------------

/**
 * Mints a fresh single-use enrollment token and returns the profile. Any
 * earlier unconsumed profile for this agent stops working. Only the SHA-256
 * of the token is stored; the plaintext exists in this response alone.
 */
function agent_issue_profile(array $agent, string $issuedBy, int $validDays): array
{
    $url = rtrim(setting('public_url'), '/');
    if ($url === '') {
        throw new RuntimeException('Settings → General → "Public URL for agents" must be set before a profile can be issued.');
    }
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $exp = time() + max(1, $validDays) * 86400;
    db_update('agents', (int)$agent['id'], [
        'enroll_token_hash' => token_hash($token),
        'enroll_issued_at'  => time(),
        'enroll_issued_by'  => $issuedBy,
        'enroll_expires_at' => $exp,
    ]);
    $kex = server_key_active('kex');
    log_event('Provisioning profile issued (valid ' . $validDays . ' days); any earlier unused profile is now void', 'info', $agent);
    return [
        'format'          => 'ipfailover-provisioning',
        'version'         => 1,
        'control_url'     => $url,
        'server_key_id'   => $kex['kid'],
        'server_key'      => $kex['public_key'],
        'enroll_token'    => $token,
        'agent_uid'       => $agent['uid'],
        'site_name'       => $agent['name'],
        'issued_at'       => gmdate('c'),
        'expires_at'      => gmdate('c', $exp),
    ];
}

function agent_profile_filename(array $agent): string
{
    // Named by the opaque uid, not the customer: the file is a credential and
    // its name lands in Downloads folders, email attachments and USB sticks.
    return 'ipfailover-' . $agent['uid'] . '.json';
}

// ---------------------------------------------------------------------------
// Request dispatch (called by public/api/v1.php after the envelope opened)
// ---------------------------------------------------------------------------

function api_dispatch(array $plain, array $ctx): array
{
    $type = (string)($plain['type'] ?? '');
    switch ($type) {
        case 'enroll':  $resp = api_enroll($plain, $ctx); break;
        case 'checkin': $resp = api_checkin($plain, $ctx); break;
        case 'rotate':  $resp = api_rotate($plain, $ctx); break;
        default: throw new WireError('bad_request', 'unknown request type');
    }
    // Pinned to a retired server key? Hand over the current one. The answer
    // is authenticated by the key the agent already trusts.
    $active = server_key_active('kex');
    if ($ctx['kid'] !== $active['kid']) {
        $resp['server_key'] = ['kid' => $active['kid'], 'public_key' => $active['public_key']];
    }
    return $resp;
}

function rate_limited(string $bucket, int $max, int $windowSec): bool
{
    db_exec('DELETE FROM login_attempts WHERE at < ?', [time() - 86400]);
    $n = (int)db_val('SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND at > ?', [$bucket, time() - $windowSec]);
    return $n >= $max;
}

function rate_hit(string $bucket): void
{
    db_exec('INSERT INTO login_attempts(ip, at) VALUES(?, ?)', [$bucket, time()]);
}

function api_enroll(array $p, array $ctx): array
{
    $bucket = 'enroll:' . client_ip();
    if (rate_limited($bucket, 10, 900)) {
        throw new WireError('rate_limited', 'too many enrollment attempts from this address; wait 15 minutes');
    }
    $pubB64 = (string)($p['public_key'] ?? '');
    $pub = base64_decode($pubB64, true);
    if ($pub === false) {
        throw new WireError('bad_key', 'public_key is not base64');
    }
    p256_public_from_raw($pub); // throws on an invalid point
    // Proof of possession: the request must be signed by the key it registers.
    if (!ipf_verify_agent_sig($ctx, $pubB64)) {
        rate_hit($bucket);
        throw new WireError('bad_signature', 'enrollment must be signed by the key being registered');
    }
    $token = (string)($p['enroll_token'] ?? '');
    $agent = $token !== '' ? db_one('SELECT * FROM agents WHERE enroll_token_hash = ?', [token_hash($token)]) : null;
    if (!$agent) {
        rate_hit($bucket);
        log_event('Enrollment refused: unknown or already-used provisioning token from ' . client_ip(), 'warn', null, 'api');
        throw new WireError('enroll_invalid', 'provisioning token is not valid (already used, revoked, or never issued)');
    }
    if ((int)$agent['enroll_expires_at'] < time()) {
        rate_hit($bucket);
        log_event('Enrollment refused: provisioning profile expired ' . fmt_ago((int)$agent['enroll_expires_at']), 'warn', $agent, 'api');
        throw new WireError('enroll_expired', 'provisioning profile has expired; ask for a new one');
    }
    ipf_check_fresh($p);

    $protector = agent_clean_protector((string)($p['key_protector'] ?? ''));
    $min = setting('min_key_protector');
    if ($min !== 'none' && (AGENT_KEY_PROTECTOR_RANK[$protector] ?? 0) < (AGENT_KEY_PROTECTOR_RANK[$min] ?? 0)) {
        log_event("Enrollment refused: key protector '$protector' is below the required '$min'", 'warn', $agent, 'api');
        throw new WireError('protector_too_weak', "this server requires the agent key to be protected by at least '$min'; this machine offered '$protector'");
    }

    $wasEnrolled = !empty($agent['pubkey']);
    db_update('agents', (int)$agent['id'], [
        'enroll_token_hash' => null,          // single use
        'enrolled_at'       => time(),
        'pubkey'            => $pubB64,
        'pubkey_id'         => p256_fingerprint($pub),
        'pubkey_at'         => time(),
        'pending_pubkey'    => null,
        'pending_pubkey_id' => null,
        'rotate_requested'  => 0,
        'key_protector'     => $protector,
        'machine_id'        => substr((string)($p['machine_id'] ?? ''), 0, 128) ?: null,
        'machine_id_changed_at' => null,
        'decommission'      => 0,
        'decommissioned_at' => null,
    ]);
    $agent = agent_get((int)$agent['id']);
    log_event(($wasEnrolled ? 'RE-ENROLLED with a new key (previous key revoked)' : 'Enrolled')
        . " from " . client_ip() . " — key " . $agent['pubkey_id'] . ", protected by $protector", 'info', $agent, 'api');
    if ($protector === 'plaintext') {
        notify("Weak key storage on {$agent['name']}",
            "Agent {$agent['name']} enrolled, but its private key is stored with the PLAINTEXT protector (no TPM, DPAPI unavailable).\n"
            . "Anyone who copies its data folder can impersonate it. Consider Settings → Security → minimum key protector.", $agent);
    }
    $resp = agent_process_checkin($agent, $p, $ctx);
    $resp['enrolled'] = true;
    return $resp;
}

function agent_clean_protector(string $p): string
{
    return array_key_exists($p, AGENT_KEY_PROTECTOR_RANK) ? $p : 'plaintext';
}

/** Finds and authenticates the agent behind a signed request. Promotes a pending key on first use. */
function api_authenticate(array $p, array $ctx): array
{
    $uid = (string)($p['agent'] ?? '');
    $agent = preg_match('/^agt_[a-z0-9]{6,20}$/', $uid) ? db_one('SELECT * FROM agents WHERE uid = ?', [$uid]) : null;
    if (!$agent || empty($agent['pubkey'])) {
        throw new WireError('unknown_agent', 'this agent is not registered on the server (deleted, or never enrolled)');
    }
    if (ipf_verify_agent_sig($ctx, (string)$agent['pubkey'])) {
        return $agent;
    }
    if (!empty($agent['pending_pubkey']) && ipf_verify_agent_sig($ctx, (string)$agent['pending_pubkey'])) {
        // First request signed by the rotated-in key: the agent has written,
        // read back and is USING it, so the old key can go.
        $raw = base64_decode($agent['pending_pubkey']);
        db_update('agents', (int)$agent['id'], [
            'pubkey' => $agent['pending_pubkey'], 'pubkey_id' => p256_fingerprint($raw), 'pubkey_at' => time(),
            'pending_pubkey' => null, 'pending_pubkey_id' => null, 'rotate_requested' => 0,
        ]);
        log_event('Key rotation complete: now ' . p256_fingerprint($raw) . ' (retired ' . $agent['pubkey_id'] . ')', 'info', $agent, 'api');
        $agent = agent_get((int)$agent['id']);
        $agent['_key_promoted'] = true;
        return $agent;
    }
    $last = (int)($agent['last_bad_auth_at'] ?? 0);
    db_update('agents', (int)$agent['id'], ['last_bad_auth_at' => time()]);
    if (time() - $last > 3600) {
        log_event('Rejected a request with a BAD SIGNATURE from ' . client_ip() . ' — someone is using this agent\'s ID without its key', 'error', $agent, 'api');
        notify("Forged request for {$agent['name']}",
            "A request claiming to be agent {$agent['name']} ({$agent['uid']}) arrived from " . client_ip()
            . " with a signature that does not match its registered key. It was rejected.\n\n"
            . "If this machine was rebuilt, issue a new provisioning profile. Otherwise treat this as an attempted impersonation.", $agent);
    }
    throw new WireError('bad_signature', 'signature does not match this agent\'s registered key');
}

function api_checkin(array $p, array $ctx): array
{
    $agent = api_authenticate($p, $ctx);
    ipf_check_fresh($p);
    return agent_process_checkin($agent, $p, $ctx);
}

function api_rotate(array $p, array $ctx): array
{
    $agent = api_authenticate($p, $ctx);
    ipf_check_fresh($p);
    $newB64 = (string)($p['new_public_key'] ?? '');
    $new = base64_decode($newB64, true);
    if ($new === false) {
        throw new WireError('bad_key', 'new_public_key is not base64');
    }
    p256_public_from_raw($new);
    $proof = base64_decode((string)($p['new_key_proof'] ?? ''), true);
    $msg = 'IPF1|rotate|' . $agent['uid'] . '|' . $p['nonce'] . '|' . $newB64;
    if ($proof === false || !ecdsa_verify_p1363($new, $msg, $proof)) {
        throw new WireError('bad_signature', 'new key proof failed');
    }
    if ($newB64 === $agent['pubkey']) {
        throw new WireError('bad_key', 'new key is the current key');
    }
    $protector = agent_clean_protector((string)($p['key_protector'] ?? ''));
    db_update('agents', (int)$agent['id'], [
        'pending_pubkey' => $newB64, 'pending_pubkey_id' => p256_fingerprint($new), 'key_protector' => $protector,
    ]);
    log_event('Key rotation started: pending key ' . p256_fingerprint($new) . " ($protector)", 'info', $agent, 'api');
    return ['ok' => true, 'pending_key_id' => p256_fingerprint($new)];
}

// ---------------------------------------------------------------------------
// The check-in itself
// ---------------------------------------------------------------------------

function v6_prefix64(string $ip): ?string
{
    $bin = @inet_pton($ip);
    return ($bin !== false && strlen($bin) === 16) ? bin2hex(substr($bin, 0, 8)) : null;
}

function ipv6_prefix64_cidr(string $ip): string
{
    $bin = inet_pton($ip);
    return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
}

function is_global_ipv6(string $ip): bool
{
    return is_ipv6($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
        && !ip_in_cidr($ip, 'fe80::/10') && !ip_in_cidr($ip, 'fc00::/7');
}

/**
 * Decides what this check-in says about the site's address.
 * @return array{candidate: ?string, source: string, mismatch: bool, detail: string, v6: ?string}
 */
function agent_decide_ip(array $agent, string $remote, ?string $agentV4, ?string $agentV6): array
{
    $serverV4 = is_public_ipv4($remote) ? $remote : null;
    $serverV6 = is_global_ipv6($remote) ? $remote : null;
    $v6 = $serverV6 ?: $agentV6;
    $mode = $agent['trust_mode'];

    if ($mode === 'server') {
        return $serverV4
            ? ['candidate' => $serverV4, 'source' => 'server-seen', 'mismatch' => false, 'detail' => 'Trust mode: server-seen address', 'v6' => $v6]
            : ['candidate' => null, 'source' => 'none', 'mismatch' => false,
               'detail' => 'Trust mode "server" but the server saw ' . ($serverV6 ? 'IPv6' : 'a non-public address') . '; holding', 'v6' => $v6];
    }
    if ($mode === 'agent') {
        return $agentV4
            ? ['candidate' => $agentV4, 'source' => 'agent-signed', 'mismatch' => false, 'detail' => 'Trust mode: agent-signed address', 'v6' => $v6]
            : ['candidate' => null, 'source' => 'none', 'mismatch' => false, 'detail' => 'Agent could not determine its IPv4; holding', 'v6' => $v6];
    }

    // agree / manual: the agent's signed claim must be corroborated by what
    // the server actually saw this request come from.
    if (!$agentV4) {
        return ['candidate' => null, 'source' => 'none', 'mismatch' => false,
                'detail' => 'Agent could not determine its IPv4 (lookup services unreachable); holding current IP', 'v6' => $v6];
    }
    if ($serverV4) {
        if ($serverV4 === $agentV4) {
            return ['candidate' => $agentV4, 'source' => 'verified', 'mismatch' => false, 'detail' => 'Verified: agent-signed IP matches the connection', 'v6' => $v6];
        }
        return ['candidate' => null, 'source' => 'none', 'mismatch' => true,
                'detail' => "MISMATCH: agent signed $agentV4 but connected from $serverV4; holding", 'v6' => $v6];
    }
    if ($serverV6) {
        if ($agentV6 && v6_prefix64($agentV6) === v6_prefix64($serverV6)) {
            return ['candidate' => $agentV4, 'source' => 'verified-v6', 'mismatch' => false,
                    'detail' => 'Verified: connection came from the agent\'s own IPv6 network', 'v6' => $v6];
        }
        return ['candidate' => null, 'source' => 'none', 'mismatch' => true,
                'detail' => "Cannot corroborate: agent reached the server over IPv6 ($serverV6) that doesn't match its own"
                    . ($agentV6 ? " ($agentV6)" : ' (it reported none)') . '; holding', 'v6' => $v6];
    }
    return ['candidate' => null, 'source' => 'none', 'mismatch' => true,
            'detail' => "Server saw a private address ($remote) — check trusted_proxies in config.php; holding", 'v6' => $v6];
}

function agent_process_checkin(array $agent, array $p, array $ctx): array
{
    $now = time();
    $promoted = !empty($agent['_key_promoted']);   // set by api_authenticate; lost on re-read
    $remote = normalize_ip(client_ip());
    $agentV4 = is_string($p['observed_ipv4'] ?? null) && is_public_ipv4($p['observed_ipv4']) ? $p['observed_ipv4'] : null;
    $agentV6 = is_string($p['observed_ipv6'] ?? null) && is_global_ipv6($p['observed_ipv6']) ? $p['observed_ipv6'] : null;
    $d = agent_decide_ip($agent, $remote, $agentV4, $agentV6);

    $upd = [
        'last_checkin_at'     => $now,
        'checkin_count'       => (int)$agent['checkin_count'] + 1,
        'last_remote_addr'    => $remote,
        'agent_reported_ipv4' => $agentV4,
        'agent_reported_ipv6' => $agentV6,
        'server_seen_ipv4'    => is_public_ipv4($remote) ? $remote : null,
        'agent_version'       => substr((string)($p['version'] ?? ''), 0, 32),
        'agent_os'            => substr((string)($p['os'] ?? ''), 0, 120),
        'agent_hostname'      => substr((string)($p['hostname'] ?? ''), 0, 120),
        'ip_mismatch'         => $d['mismatch'] ? 1 : 0,
        'ip_mismatch_since'   => $d['mismatch'] ? ($agent['ip_mismatch_since'] ?: $now) : null,
    ];
    if (!empty($p['key_protector'])) {
        $upd['key_protector'] = agent_clean_protector((string)$p['key_protector']);
    }
    if ($d['v6']) {
        $upd['current_ipv6'] = $d['v6'];
    }
    if (!$agent['first_checkin_at']) {
        $upd['first_checkin_at'] = $now;
        log_event('First check-in from ' . $remote, 'info', $agent, 'api');
    }
    if ($agent['ip_mismatch'] && !$d['mismatch']) {
        log_event('IP corroboration restored (' . $d['detail'] . ')', 'info', $agent, 'api');
        if ((int)$agent['mismatch_alerted'] === 1) {
            notify("RESOLVED: IP corroboration restored for {$agent['name']}", $d['detail'], $agent);
        }
        $upd['mismatch_alerted'] = 0;
    } elseif (!$agent['ip_mismatch'] && $d['mismatch']) {
        log_event($d['detail'], 'warn', $agent, 'api');
    }

    // Same identity key showing up on different hardware = a copied key.
    $mid = substr((string)($p['machine_id'] ?? ''), 0, 128);
    if ($mid !== '' && $agent['machine_id'] && $mid !== $agent['machine_id']) {
        if (!$agent['machine_id_changed_at']) {
            $upd['machine_id_changed_at'] = $now;
            log_event('This agent\'s key is now being used from a DIFFERENT machine', 'error', $agent, 'api');
            notify("Agent key moved to another machine: {$agent['name']}",
                "Agent {$agent['name']} ({$agent['uid']}) checked in with its valid key from a different machine than it enrolled on "
                . "(machine id changed). That usually means its key files were copied. If this was a planned hardware swap, "
                . "issue a new provisioning profile; otherwise disable the agent.", $agent);
        }
    }

    // Recovery from a missed-check-in alert.
    if ($agent['alert_state'] === 'missed') {
        $upd['alert_state'] = 'ok';
        $upd['alert_changed_at'] = $now;
        $down = fmt_duration($now - (int)$agent['last_checkin_at']);
        log_event("Back online after $down", 'info', $agent, 'api');
        notify("RECOVERED: {$agent['name']} is checking in again",
            "Agent {$agent['name']} checked in after being silent for $down.\nCurrent IP: " . ($agent['current_ipv4'] ?: 'unknown'), $agent);
    }

    // ---- IP change ---------------------------------------------------------
    $cand = $d['candidate'];
    $confirm = max(1, (int)setting('ip_confirm_checkins'));
    if ($cand !== null && $cand !== $agent['current_ipv4']) {
        $count = ($agent['pending_ipv4'] === $cand) ? (int)$agent['pending_count'] + 1 : 1;
        if ($agent['trust_mode'] === 'manual' && $agent['current_ipv4']) {
            if ($agent['pending_ipv4'] !== $cand) {
                log_event("IP change to $cand awaiting approval (was {$agent['current_ipv4']})", 'warn', $agent, 'api');
                notify("APPROVAL NEEDED: {$agent['name']} wants to change IP",
                    "Agent {$agent['name']} reports a new verified address.\n\n  Current: {$agent['current_ipv4']}\n  New:     $cand\n\n"
                    . "This agent is in manual-approval mode, so DNS and allowlist feeds keep the current address until someone approves the change on the agent page.", $agent);
            }
            $upd['pending_ipv4'] = $cand;
            $upd['pending_count'] = $count;
        } elseif ($count >= $confirm || !$agent['current_ipv4']) {
            agent_accept_ip($agent, $cand, $d['source'], 'api');
            $upd['pending_ipv4'] = null;
            $upd['pending_count'] = 0;
        } else {
            $upd['pending_ipv4'] = $cand;
            $upd['pending_count'] = $count;
        }
    } elseif ($cand !== null && $cand === $agent['current_ipv4'] && $agent['pending_ipv4'] && $agent['trust_mode'] !== 'manual') {
        $upd['pending_ipv4'] = null;   // flapped back before confirmation
        $upd['pending_count'] = 0;
    }
    if ($cand !== null && $cand === ($agent['current_ipv4'] ?? null)) {
        $upd['ip_source'] = $d['source'];
    }
    if ($agent['current_ipv4'] === null && $cand === null && !$agent['ip_source']) {
        $upd['ip_source'] = 'none';
    }

    db_update('agents', (int)$agent['id'], $upd);
    $agent = agent_get((int)$agent['id']);

    if ($agent['enabled'] && $agent['current_ipv4']) {
        dns_sync_agent($agent, false);
    }
    return agent_checkin_response($agent, $d, $promoted);
}

/** Makes $ip the site's authoritative address. Callers decide when that's allowed. */
function agent_accept_ip(array $agent, string $ip, string $source, string $actor): void
{
    $prev = $agent['current_ipv4'];
    db_update('agents', (int)$agent['id'], [
        'current_ipv4' => $ip, 'ip_source' => $source, 'ip_changed_at' => time(),
        'pending_ipv4' => null, 'pending_count' => 0,
    ]);
    db_exec('INSERT INTO ip_history(agent_id, ip, previous_ip, source, at) VALUES(?,?,?,?,?)',
        [$agent['id'], $ip, $prev, $source, time()]);
    // Every enabled target now needs a push; a fresh change also skips backoff.
    db_exec("UPDATE dns_targets SET state = CASE WHEN enabled = 1 THEN 'pending' ELSE state END, fail_count = 0 WHERE agent_id = ?", [$agent['id']]);
    log_event($prev ? "IP changed $prev → $ip ($source)" : "Initial IP $ip ($source)", 'info', $agent, $actor);
    if ($prev && setting('notify_ip_change') === '1') {
        notify("IP changed: {$agent['name']} is now $ip",
            "Agent {$agent['name']} changed public IP.\n\n  Old: $prev\n  New: $ip\n  Evidence: $source\n\nDNS targets are being updated automatically.", $agent);
    }
}

function agent_checkin_response(array $agent, array $d, bool $promoted): array
{
    $targets = [];
    foreach (agent_targets((int)$agent['id']) as $t) {
        $targets[] = [
            'hostname' => $t['hostname'], 'provider' => providers()[$t['provider']]['label'] ?? $t['provider'],
            'account'  => $t['account_name'], 'state' => $t['enabled'] ? $t['state'] : 'disabled', 'detail' => $t['detail'],
        ];
    }
    $rotateAge = (int)setting('key_max_age_days') * 86400;
    $wantRotate = empty($agent['pending_pubkey'])
        && ((int)$agent['rotate_requested'] === 1 || ($rotateAge > 0 && $agent['pubkey_at'] && time() - (int)$agent['pubkey_at'] > $rotateAge));

    $update = null;
    if (setting('auto_update') === '1') {
        $update = agent_update_offer((string)$agent['platform'], (string)$agent['agent_version']);
    }
    return [
        'ok'          => true,
        'agent'       => ['uid' => $agent['uid'], 'name' => $agent['name'], 'enabled' => (bool)$agent['enabled']],
        'interval'    => max(60, (int)$agent['interval_sec']),
        'ip_check_urls' => array_values(array_filter(array_map('trim', preg_split('/\R/', setting('ip_check_urls'))))),
        'ip'          => [
            'authoritative' => $agent['current_ipv4'], 'ipv6' => $agent['current_ipv6'],
            'source' => $agent['ip_source'], 'mismatch' => (bool)$agent['ip_mismatch'],
            'pending' => $agent['pending_ipv4'], 'trust_mode' => $agent['trust_mode'], 'detail' => $d['detail'],
        ],
        'targets'     => $targets,
        'rotate_key'  => $wantRotate,
        'key_promoted'=> $promoted,
        'update'      => $update,
        'decommission'=> (bool)$agent['decommission'],
    ];
}

// ---------------------------------------------------------------------------
// Agent self-update (hash-pinned inside the authenticated response)
// ---------------------------------------------------------------------------

function agent_files(string $platform): array
{
    $dir = APP_ROOT . '/agents/' . ($platform === 'docker' ? 'docker' : 'windows');
    return $platform === 'docker'
        ? ['agent.php' => "$dir/agent.php"]
        : ['ip-agent.ps1' => "$dir/ip-agent.ps1", 'ip-agent-tray.ps1' => "$dir/ip-agent-tray.ps1"];
}

function agent_shipped_version(string $platform): ?string
{
    $main = array_values(agent_files($platform))[0];
    if (!is_file($main)) return null;
    return preg_match('/AGENT_VERSION\s*=\s*[\'"]([0-9.]+)[\'"]/', (string)file_get_contents($main), $m) ? $m[1] : null;
}

function agent_update_offer(string $platform, string $running): ?array
{
    $ver = agent_shipped_version($platform);
    if (!$ver || $running === '' || version_compare($ver, $running, '<=')) {
        return null;
    }
    $files = [];
    foreach (agent_files($platform) as $name => $path) {
        $content = (string)file_get_contents($path);
        // The whole file travels inside the authenticated, encrypted response,
        // and the hash is checked again on the agent before anything runs.
        $files[] = ['name' => $name, 'sha256' => hash('sha256', $content), 'content' => base64_encode($content)];
    }
    return ['version' => $ver, 'files' => $files];
}

// ---------------------------------------------------------------------------
// DNS sync (server-side pushes)
// ---------------------------------------------------------------------------

function dns_sync_agent(array $agent, bool $force): void
{
    foreach (db_all('SELECT * FROM dns_targets WHERE agent_id = ? AND enabled = 1', [$agent['id']]) as $t) {
        dns_sync_target($t, $agent, $force);
    }
}

function dns_backoff_seconds(int $fails): int
{
    return $fails <= 0 ? 0 : min(3600, 60 * (2 ** min(6, $fails - 1)));
}

/** Pushes one target if it's out of date (or $force). @return ?array the push result, null if nothing done */
function dns_sync_target(array $t, array $agent, bool $force): ?array
{
    $ip = $agent['current_ipv4'];
    if (!$ip || !$agent['enabled'] || !$t['enabled']) {
        return null;
    }
    if (!$force && $t['last_pushed_ip'] === $ip && $t['state'] === 'ok') {
        return null;
    }
    if (!$force && (int)$t['fail_count'] > 0
        && time() < (int)$t['last_attempt_at'] + dns_backoff_seconds((int)$t['fail_count'])) {
        return null;
    }
    $account = db_one('SELECT * FROM dns_accounts WHERE id = ?', [$t['account_id']]);
    if (!$account) {
        return null;
    }
    $r = provider_push($account, $t, $ip);
    $fields = ['last_attempt_at' => time(), 'detail' => mb_substr_safe($r['detail'], 300)];
    if ($r['ok']) {
        $fields += ['state' => 'ok', 'last_pushed_ip' => $ip, 'last_pushed_at' => time(), 'fail_count' => 0,
                    'last_verified_at' => time(), 'alerted' => 0];
        log_event("DNS {$t['hostname']} via {$account['name']}: {$r['detail']}", 'info', $agent, 'system');
        if ((int)$t['alerted'] === 1) {
            notify("DNS RECOVERED: {$t['hostname']}", "The DNS record {$t['hostname']} for agent {$agent['name']} is updating again.\n\n{$r['detail']}", $agent);
        }
    } else {
        $fails = (int)$t['fail_count'] + 1;
        $fields += ['state' => 'fault', 'fail_count' => $fails];
        log_event("DNS {$t['hostname']} via {$account['name']} FAILED (attempt $fails): {$r['detail']}", 'error', $agent, 'system');
        if ($fails >= (int)setting('dns_fail_alert_after') && (int)$t['alerted'] === 0) {
            $fields['alerted'] = 1;
            notify("DNS UPDATE FAILING: {$t['hostname']}",
                "The DNS record {$t['hostname']} for agent {$agent['name']} could not be set to $ip after $fails attempts.\n\n"
                . "Last error: {$r['detail']}\n\nThe server keeps retrying with backoff (max once an hour).", $agent);
        }
    }
    db_update('dns_targets', (int)$t['id'], $fields);
    return $r;
}

function mb_substr_safe(string $s, int $len): string
{
    // UTF-8-safe truncation without the mbstring extension.
    if (strlen($s) <= $len) return $s;
    return preg_match('/^.{0,' . $len . '}/su', $s, $m) ? $m[0] . '…' : substr($s, 0, $len);
}

// ---------------------------------------------------------------------------
// Status for the UI (neutral states are never red)
// ---------------------------------------------------------------------------

/** @return array{key: string, label: string, tone: string, detail: string} */
function agent_status(array $a, ?array $targets = null): array
{
    $now = time();
    if ($a['decommission']) {
        return ['key' => 'decommissioned', 'label' => $a['decommissioned_at'] ? 'Decommissioned' : 'Decommissioning', 'tone' => 'muted',
                'detail' => $a['decommissioned_at'] ? 'Agent removed itself ' . fmt_ago((int)$a['decommissioned_at']) : 'Will uninstall itself at its next check-in'];
    }
    if (empty($a['pubkey'])) {
        if ($a['enroll_token_hash'] && (int)$a['enroll_expires_at'] < $now) {
            return ['key' => 'profile_expired', 'label' => 'Profile expired', 'tone' => 'muted', 'detail' => 'Issue a new provisioning profile to install this agent'];
        }
        if (!$a['enroll_token_hash']) {
            return ['key' => 'no_profile', 'label' => 'No profile issued', 'tone' => 'muted', 'detail' => 'Download a provisioning profile to install this agent'];
        }
        return ['key' => 'awaiting', 'label' => 'Waiting for install', 'tone' => 'neutral', 'detail' => 'Profile issued; expires ' . fmt_ago((int)$a['enroll_expires_at'])];
    }
    if (!$a['enabled']) {
        return ['key' => 'disabled', 'label' => 'Disabled', 'tone' => 'muted', 'detail' => 'Paused: no DNS pushes, no alerts'];
    }
    if ($a['maintenance_until'] && (int)$a['maintenance_until'] > $now) {
        return ['key' => 'maintenance', 'label' => 'Maintenance', 'tone' => 'muted', 'detail' => 'Alerts muted until ' . fmt_time((int)$a['maintenance_until'])];
    }
    if ($a['alert_state'] === 'missed') {
        return ['key' => 'offline', 'label' => 'Offline', 'tone' => 'bad', 'detail' => 'Missed check-ins; last seen ' . fmt_ago((int)$a['last_checkin_at'])];
    }
    if ($a['last_checkin_at'] && $now - (int)$a['last_checkin_at'] > (int)$a['interval_sec'] + 90) {
        return ['key' => 'late', 'label' => 'Late', 'tone' => 'warn', 'detail' => 'Last check-in ' . fmt_ago((int)$a['last_checkin_at'])];
    }
    if ($a['machine_id_changed_at']) {
        return ['key' => 'cloned', 'label' => 'Key on new machine', 'tone' => 'bad', 'detail' => 'Its key is in use on different hardware'];
    }
    if ($a['pending_ipv4'] && $a['trust_mode'] === 'manual') {
        return ['key' => 'approval', 'label' => 'Needs approval', 'tone' => 'warn', 'detail' => "New IP {$a['pending_ipv4']} waiting for approval"];
    }
    if ($a['ip_mismatch']) {
        return ['key' => 'held', 'label' => 'IP held', 'tone' => 'warn', 'detail' => 'Agent-signed and server-seen IPs disagree'];
    }
    $targets = $targets ?? agent_targets((int)$a['id']);
    foreach ($targets as $t) {
        if ($t['enabled'] && $t['state'] === 'fault') {
            return ['key' => 'dns_fault', 'label' => 'DNS failing', 'tone' => 'bad', 'detail' => $t['hostname'] . ': ' . $t['detail']];
        }
    }
    foreach ($targets as $t) {
        if ($t['enabled'] && $t['state'] === 'pending') {
            return ['key' => 'syncing', 'label' => 'Syncing', 'tone' => 'neutral', 'detail' => $t['hostname'] . ' waiting for its first push'];
        }
    }
    if (!$a['current_ipv4']) {
        return ['key' => 'no_ip', 'label' => 'No IP yet', 'tone' => 'neutral', 'detail' => 'Enrolled; waiting for a verified address'];
    }
    return ['key' => 'ok', 'label' => 'OK', 'tone' => 'good', 'detail' => 'Checked in ' . fmt_ago((int)$a['last_checkin_at'])];
}

// ---------------------------------------------------------------------------
// DNS targets: one code path for the survey and the agent page
// ---------------------------------------------------------------------------

function dns_accounts_all(): array
{
    return db_all('SELECT * FROM dns_accounts ORDER BY name');
}

function dns_account_domain(array $account): string
{
    return (string)(decrypt_json($account['config_enc'])['domain'] ?? '');
}

/**
 * Validates one submitted target row. Does not write anything.
 * Row keys: account_id, name_mode (random|custom), hostname, ttl, proxied, tf_* (provider target fields)
 * @return array{0: ?array, 1: string[]}  [fields ready to insert, errors]
 */
function target_from_input(array $row, ?int $ignoreTargetId = null): array
{
    $errors = [];
    $acc = db_one('SELECT * FROM dns_accounts WHERE id = ?', [(int)($row['account_id'] ?? 0)]);
    if (!$acc) {
        return [null, ['Choose a DNS account.']];
    }
    $meta = provider_meta($acc['provider']);
    $domain = dns_account_domain($acc);
    $mode = ($row['name_mode'] ?? 'custom') === 'random' ? 'random' : 'custom';
    $generated = 0;

    if ($acc['provider'] === 'none') {
        // Tracking-only targets still need a unique label for the UI.
        $host = 'track-' . random_dns_label(8) . '.invalid';
        $generated = 1;
    } elseif ($mode === 'random') {
        if (!$meta['creates'] || $domain === '') {
            return [null, ["{$acc['name']} can't create new names (or has no domain set), so pick a name instead."]];
        }
        do {
            $host = random_dns_label() . '.' . $domain;
        } while (db_one('SELECT id FROM dns_targets WHERE hostname = ?', [$host]));
        $generated = 1;
    } else {
        $host = strtolower(trim((string)($row['hostname'] ?? ''), " ."));
        if ($host !== '' && strpos($host, '.') === false && $domain !== '') {
            $host .= '.' . $domain;   // a bare label goes under the account's domain
        }
        if (!valid_hostname($host)) {
            $errors[] = 'Hostname "' . ($row['hostname'] ?? '') . '" is not a valid DNS name.';
        } elseif ($domain !== '' && $meta['creates'] && substr($host, -strlen('.' . $domain)) !== '.' . $domain && $host !== $domain) {
            $errors[] = "$host is outside {$acc['name']}'s domain ($domain).";
        }
        $clash = db_one('SELECT t.id, a.name FROM dns_targets t JOIN agents a ON a.id = t.agent_id WHERE t.hostname = ?', [$host]);
        if ($clash && (int)$clash['id'] !== (int)$ignoreTargetId) {
            // Two agents writing one name would fight forever.
            $errors[] = "$host is already kept updated by agent \"{$clash['name']}\".";
        }
    }
    [$tcfg, $terr] = provider_target_from_input($acc['provider'], $row);
    $errors = array_merge($errors, $terr);
    $ttl = (int)($row['ttl'] ?? 120);
    if ($ttl < 30 || $ttl > 86400) {
        $errors[] = 'TTL must be between 30 and 86400 seconds.';
    }
    if ($errors) {
        return [null, $errors];
    }
    return [[
        'account_id' => (int)$acc['id'], 'hostname' => $host, 'generated_name' => $generated,
        'target_config_enc' => $tcfg ? encrypt_json($tcfg) : '', 'ttl' => $ttl,
        'proxied' => ($acc['provider'] === 'cloudflare' && !empty($row['proxied'])) ? 1 : 0,
    ], []];
}

function target_insert(array $agent, array $f): int
{
    db_exec('INSERT INTO dns_targets(agent_id, account_id, hostname, generated_name, target_config_enc, ttl, proxied, created_at)
             VALUES(?,?,?,?,?,?,?,?)', [$agent['id'], $f['account_id'], $f['hostname'], $f['generated_name'], $f['target_config_enc'], $f['ttl'], $f['proxied'], time()]);
    $id = (int)db()->lastInsertId();
    log_event("DNS target added: {$f['hostname']}" . ($f['generated_name'] ? ' (random name)' : ''), 'info', $agent);
    return $id;
}

/** Removes the record at the provider where the API allows it. @return array{ok: bool, detail: string} */
function provider_delete(array $account, array $target): array
{
    $cfg = decrypt_json($account['config_enc']);
    $host = rtrim(strtolower($target['hostname']), '.');
    switch ($account['provider']) {
        case 'cloudflare':
            $zone = cf_zone_id($cfg, $host);
            if (!$zone) return ['ok' => false, 'detail' => 'zone not found'];
            foreach (cf_records($cfg, $zone, $host) as $rec) {
                $r = http_json('DELETE', cf_base() . "/zones/$zone/dns_records/" . $rec['id'], cf_headers($cfg));
                if (!($r['json']['success'] ?? false)) return ['ok' => false, 'detail' => cf_error($r)];
            }
            return ['ok' => true, 'detail' => "deleted A $host"];
        case 'powerdns':
            [$zone, $why] = pdns_zone($cfg, $host);
            if (!$zone) return ['ok' => false, 'detail' => $why];
            $sid = rawurlencode($cfg['server_id'] ?: 'localhost');
            $r = http_json('PATCH', pdns_base($cfg) . "/servers/$sid/zones/" . rawurlencode($zone), pdns_headers($cfg),
                ['rrsets' => [['name' => $host . '.', 'type' => 'A', 'changetype' => 'DELETE']]]);
            return ($r['status'] === 204 || $r['status'] === 200) ? ['ok' => true, 'detail' => "deleted A $host"] : ['ok' => false, 'detail' => pdns_error($r)];
        default:
            return ['ok' => false, 'detail' => 'this provider has no delete API; remove the name in its control panel'];
    }
}

/** Deletes an agent and (optionally) its records at providers that support it. */
function agent_delete(array $agent, bool $removeRecords, string $actor): array
{
    $notes = [];
    if ($removeRecords) {
        foreach (agent_targets((int)$agent['id']) as $t) {
            $acc = db_one('SELECT * FROM dns_accounts WHERE id = ?', [$t['account_id']]);
            if ($acc && $acc['provider'] !== 'none') {
                $r = provider_delete($acc, $t);
                $notes[] = $t['hostname'] . ': ' . $r['detail'];
            }
        }
    }
    log_event("Agent deleted ({$agent['uid']})" . ($notes ? '; ' . implode('; ', $notes) : ''), 'warn', $agent, $actor);
    db_exec('DELETE FROM agents WHERE id = ?', [$agent['id']]);
    return $notes;
}
