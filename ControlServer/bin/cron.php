<?php
declare(strict_types=1);

/**
 * Runs every minute (deploy/dynallow.cron). Alerts, retries and checks
 * depend on it — the dashboard shows a red banner if it stops.
 *
 *   1. Missed check-ins  -> OFFLINE email after the agent's threshold (default 2)
 *   2. Held IPs          -> email if agent and server disagree for too long
 *   3. DNS retries       -> failed/pending pushes, with exponential backoff
 *   4. DNS drift         -> re-read each record; re-push if someone changed it
 *   5. Housekeeping      -> prune old events, nonces, rate-limit rows
 *   6. Dead-man's switch -> ping an external URL so a dead cron is noticed
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require dirname(__DIR__) . '/src/bootstrap.php';

$lock = fopen(app_config('data_dir') . '/cron.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0); // previous run still going (slow provider); never overlap
}

$now = time();
$verbose = in_array('-v', $argv, true);
$say = function (string $s) use ($verbose) { if ($verbose) echo $s, "\n"; };

// ---- 1. missed check-ins ----------------------------------------------------
$agents = db_all("SELECT * FROM agents WHERE enabled = 1 AND decommission = 0 AND pubkey IS NOT NULL
                  AND first_checkin_at IS NOT NULL AND alert_state = 'ok'");
foreach ($agents as $a) {
    if ($a['maintenance_until'] && (int)$a['maintenance_until'] > $now) {
        continue;
    }
    $interval = max(60, (int)$a['interval_sec']);
    $missed = max(1, (int)$a['missed_threshold']);
    $deadline = (int)$a['last_checkin_at'] + $interval * $missed + 30;
    if ($now > $deadline) {
        db_update('agents', (int)$a['id'], ['alert_state' => 'missed', 'alert_changed_at' => $now]);
        log_event("OFFLINE: missed $missed check-ins (last seen " . fmt_ago((int)$a['last_checkin_at']) . ')', 'error', $a, 'cron');
        notify("OFFLINE: {$a['name']} missed $missed check-ins",
            "Agent {$a['name']}" . ($a['customer'] ? " ({$a['customer']})" : '') . " has not checked in since " . fmt_time((int)$a['last_checkin_at'])
            . " (expected every " . fmt_duration($interval) . ").\n\nLast known IP: " . ($a['current_ipv4'] ?: 'none')
            . "\nLast connection from: " . ($a['last_remote_addr'] ?: 'unknown')
            . "\n\nDNS keeps pointing at the last verified address. You'll get a RECOVERED email when it checks in again.", $a);
        $say("offline: {$a['name']}");
    }
}

// ---- 2. held IPs that stay held -----------------------------------------------
$mm = max(1, (int)setting('mismatch_alert_minutes')) * 60;
foreach (db_all('SELECT * FROM agents WHERE ip_mismatch = 1 AND mismatch_alerted = 0 AND ip_mismatch_since < ? AND enabled = 1', [$now - $mm]) as $a) {
    db_update('agents', (int)$a['id'], ['mismatch_alerted' => 1]);
    notify("IP HELD for {$a['name']}: agent and server disagree",
        "For " . fmt_duration($now - (int)$a['ip_mismatch_since']) . ", agent {$a['name']} has signed one address while its requests arrive from another.\n\n"
        . "  Agent says:     " . ($a['agent_reported_ipv4'] ?: 'unknown') . "\n"
        . "  Server sees:    " . ($a['last_remote_addr'] ?: 'unknown') . "\n"
        . "  DNS stays on:   " . ($a['current_ipv4'] ?: 'none') . "\n\n"
        . "Usual causes: a second WAN / load balancer at the site, a proxy in front of the control server that isn't in trusted_proxies, "
        . "or someone relaying the agent's traffic. If the site really has two exits, set this agent's trust mode to \"server\" or \"agent\".", $a);
    $say("mismatch alert: {$a['name']}");
}

// ---- 3. DNS retries -------------------------------------------------------------
$rows = db_all("SELECT t.*, a.current_ipv4 FROM dns_targets t JOIN agents a ON a.id = t.agent_id
                WHERE t.enabled = 1 AND a.enabled = 1 AND a.decommission = 0 AND a.current_ipv4 IS NOT NULL
                  AND (t.state IN ('pending','fault') OR t.last_pushed_ip IS NULL OR t.last_pushed_ip <> a.current_ipv4)");
foreach ($rows as $t) {
    $agent = agent_get((int)$t['agent_id']);
    $r = dns_sync_target($t, $agent, false);
    if ($r) $say("push {$t['hostname']}: " . ($r['ok'] ? 'ok' : 'FAIL ') . $r['detail']);
}

// ---- 4. DNS drift ---------------------------------------------------------------
$every = max(5, (int)setting('verify_minutes')) * 60;
$rows = db_all("SELECT t.* FROM dns_targets t JOIN agents a ON a.id = t.agent_id
                WHERE t.enabled = 1 AND t.state = 'ok' AND a.enabled = 1 AND a.decommission = 0 AND a.current_ipv4 IS NOT NULL
                  AND COALESCE(t.last_verified_at, 0) < ? ORDER BY t.last_verified_at LIMIT 50", [$now - $every]);
foreach ($rows as $t) {
    $agent = agent_get((int)$t['agent_id']);
    $account = db_one('SELECT * FROM dns_accounts WHERE id = ?', [$t['account_id']]);
    $look = $account ? provider_lookup($account, $t) : null;
    db_update('dns_targets', (int)$t['id'], ['last_verified_at' => $now]);
    if ($look === null || ($look['ip'] === null && $look['method'] !== 'api')) {
        continue; // provider can't be read back, or a resolver hiccup — not evidence of drift
    }
    // Resolver answers can lag a fresh push by the record's TTL.
    if ($look['method'] === 'resolver' && $now - (int)$t['last_pushed_at'] < max(300, (int)$t['ttl'] * 2)) {
        continue;
    }
    if ($look['ip'] !== $agent['current_ipv4']) {
        log_event("DNS DRIFT on {$t['hostname']}: provider shows " . ($look['ip'] ?: 'nothing') . ", should be {$agent['current_ipv4']} — re-pushing", 'warn', $agent, 'cron');
        notify("DNS DRIFT: {$t['hostname']} was changed outside DynAllow",
            "The record {$t['hostname']} ({$account['name']}) shows " . ($look['ip'] ?: 'no address') . " but agent {$agent['name']}'s verified IP is {$agent['current_ipv4']}.\n\n"
            . "Someone or something changed it at the provider. DynAllow is putting it back. If that change was intentional, disable this DNS target first.", $agent);
        db_update('dns_targets', (int)$t['id'], ['state' => 'pending']);
        $t = db_one('SELECT * FROM dns_targets WHERE id = ?', [$t['id']]);
        dns_sync_target($t, $agent, true);
        $say("drift fixed: {$t['hostname']}");
    }
}

// ---- 5. housekeeping ------------------------------------------------------------
db_exec('DELETE FROM diagnostics WHERE at < ?', [$now - max(7, (int)setting('event_retention_days')) * 86400]);
db_exec('DELETE FROM events WHERE at < ?', [$now - max(7, (int)setting('event_retention_days')) * 86400]);
db_exec('DELETE FROM seen_nonces WHERE at < ?', [$now - 2 * max(60, (int)setting('clock_skew_sec')) - 60]);
db_exec('DELETE FROM login_attempts WHERE at < ?', [$now - 86400]);

setting_set('cron_last_run', (string)$now);

// ---- 6. dead-man's switch ---------------------------------------------------------
$ping = setting('cron_ping_url');
if ($ping !== '' && preg_match('#^https?://#i', $ping)) {
    http_request('GET', $ping, [], null, 10);
}
flock($lock, LOCK_UN);
