<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_login();
$isAdmin = $me['role'] === 'admin';

$agent = agent_get((int)($_GET['id'] ?? $_POST['id'] ?? 0));
if (!$agent) {
    http_response_code(404);
    page_header('Not found');
    echo '<div class="card"><h2>No such site</h2><p><a href="index.php">Back to the dashboard</a></p></div>';
    page_footer();
    exit;
}
$id = (int)$agent['id'];
$self = 'agent.php?id=' . $id;

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');
    $adminOnly = ['approve_ip', 'reject_ip', 'set_ip', 'target_delete', 'rotate_key', 'clear_clone', 'decommission', 'cancel_decommission', 'delete'];
    if (in_array($action, $adminOnly, true) && !$isAdmin) {
        http_response_code(403);
        exit('Admins only.');
    }
    $target = isset($_POST['target_id']) ? db_one('SELECT * FROM dns_targets WHERE id = ? AND agent_id = ?', [(int)$_POST['target_id'], $id]) : null;

    switch ($action) {
        case 'save':
            $name = trim((string)$_POST['name']);
            $errors = [];
            if ($name === '' || strlen($name) > 80) $errors[] = 'Site name is required (80 characters max).';
            elseif (db_one('SELECT id FROM agents WHERE name = ? AND id <> ?', [$name, $id])) $errors[] = "Another site is already called \"$name\".";
            $trust = (string)$_POST['trust_mode'];
            if (!isset(trust_modes()[$trust])) $errors[] = 'Unknown trust mode.';
            $bad = array_diff(preg_split('/[\s,;]+/', trim((string)$_POST['alert_emails']), -1, PREG_SPLIT_NO_EMPTY), parse_emails((string)$_POST['alert_emails']));
            if ($bad) $errors[] = 'Not valid email: ' . implode(', ', $bad);
            if ($errors) {
                foreach ($errors as $e) flash('error', $e);
                redirect($self);
            }
            $fields = [
                'name' => $name, 'customer' => trim((string)$_POST['customer']), 'site_address' => trim((string)$_POST['site_address']),
                'site_contact' => trim((string)$_POST['site_contact']), 'tags' => implode(', ', parse_tags((string)$_POST['tags'])),
                'notes' => trim((string)$_POST['notes']), 'interval_sec' => max(60, min(86400, (int)$_POST['interval_sec'])),
                'missed_threshold' => max(1, min(20, (int)$_POST['missed_threshold'])), 'alert_emails' => implode(', ', parse_emails((string)$_POST['alert_emails'])),
                'trust_mode' => $trust,
                'prevent_sleep' => $agent['platform'] === 'windows' && !empty($_POST['prevent_sleep']) ? 1 : 0,
            ];
            $changed = [];
            foreach ($fields as $k => $v) {
                if ((string)$agent[$k] !== (string)$v) $changed[] = $k;
            }
            db_update('agents', $id, $fields);
            if ($changed) log_event('Settings changed: ' . implode(', ', $changed), 'info', $agent);
            flash('ok', $changed ? 'Saved. The agent picks up interval changes at its next check-in.' : 'No changes.');
            break;

        case 'enable':
        case 'disable':
            db_update('agents', $id, ['enabled' => $action === 'enable' ? 1 : 0, 'alert_state' => 'ok']);
            log_event($action === 'enable' ? 'Enabled' : 'Disabled (no DNS pushes, no alerts, dropped from allowlist feeds)', 'warn', $agent);
            flash('ok', $action === 'enable' ? 'Enabled.' : 'Disabled.');
            break;

        case 'maintenance':
            $hours = (int)$_POST['hours'];
            db_update('agents', $id, ['maintenance_until' => $hours > 0 ? time() + $hours * 3600 : null]);
            log_event($hours > 0 ? "Alerts muted for $hours h (maintenance)" : 'Maintenance ended', 'info', $agent);
            flash('ok', $hours > 0 ? "Alerts muted for $hours hours." : 'Maintenance ended.');
            break;

        case 'approve_ip':
            if ($agent['pending_ipv4']) {
                agent_accept_ip($agent, $agent['pending_ipv4'], 'approved', $me['username']);
                dns_sync_agent(agent_get($id), true);
                flash('ok', "Approved {$agent['pending_ipv4']}; DNS updated.");
            }
            break;

        case 'reject_ip':
            db_update('agents', $id, ['pending_ipv4' => null, 'pending_count' => 0]);
            log_event("Rejected pending IP {$agent['pending_ipv4']}", 'warn', $agent);
            flash('ok', 'Rejected. The current IP stays.');
            break;

        case 'set_ip':
            // Resolving a held mismatch by hand: the admin picks which observed address is right.
            $ip = (string)$_POST['ip'];
            if (in_array($ip, [$agent['agent_reported_ipv4'], $agent['server_seen_ipv4']], true) && is_public_ipv4($ip)) {
                agent_accept_ip($agent, $ip, 'manual', $me['username']);
                db_update('agents', $id, ['ip_mismatch' => 0, 'ip_mismatch_since' => null, 'mismatch_alerted' => 0]);
                dns_sync_agent(agent_get($id), true);
                flash('ok', "Authoritative IP set to $ip. It will be held again if the next check-in still disagrees — fix the cause or change the trust mode.");
            }
            break;

        case 'target_add':
            $added = 0;
            foreach ((array)($_POST['targets'] ?? []) as $row) {
                [$f, $errs] = target_from_input((array)$row);
                foreach ($errs as $e) flash('error', $e);
                if ($f) {
                    target_insert($agent, $f);
                    $added++;
                }
            }
            if ($added) {
                dns_sync_agent(agent_get($id), true);
                flash('ok', "$added DNS target(s) added" . (agent_get($id)['current_ipv4'] ? ' and pushed.' : '; they will be pushed once the site has a verified IP.'));
            }
            break;

        case 'target_push':
            if ($target) {
                $r = dns_sync_target($target, agent_get($id), true);
                flash($r && $r['ok'] ? 'ok' : 'error', $r ? $r['detail'] : 'Nothing to push yet (no verified IP, or the site/target is disabled).');
            }
            break;

        case 'target_toggle':
            if ($target) {
                db_update('dns_targets', (int)$target['id'], ['enabled' => $target['enabled'] ? 0 : 1, 'state' => 'pending']);
                log_event('DNS target ' . $target['hostname'] . ($target['enabled'] ? ' paused' : ' resumed'), 'info', $agent);
                if (!$target['enabled']) dns_sync_agent(agent_get($id), true);
            }
            break;

        case 'target_delete':
            if ($target) {
                if (!empty($_POST['remove_record'])) {
                    $acc = db_one('SELECT * FROM dns_accounts WHERE id = ?', [$target['account_id']]);
                    $r = provider_delete($acc, $target);
                    flash($r['ok'] ? 'ok' : 'warn', 'Provider: ' . $r['detail']);
                }
                db_exec('DELETE FROM dns_targets WHERE id = ?', [$target['id']]);
                log_event("DNS target removed: {$target['hostname']}", 'warn', $agent);
            }
            break;

        case 'revoke_profile':
            db_update('agents', $id, ['enroll_token_hash' => null, 'enroll_expires_at' => null]);
            log_event('Unused provisioning profile revoked', 'warn', $agent);
            flash('ok', 'The outstanding provisioning profile no longer works.');
            break;

        case 'rotate_key':
            db_update('agents', $id, ['rotate_requested' => 1]);
            log_event('Key rotation requested', 'info', $agent);
            flash('ok', 'The agent will rotate its key over its next two check-ins.');
            break;

        case 'clear_clone':
            db_update('agents', $id, ['machine_id_changed_at' => null, 'machine_id' => null]);
            log_event('Machine-change warning acknowledged; the next check-in becomes the new reference', 'warn', $agent);
            break;

        case 'decommission':
            db_update('agents', $id, ['decommission' => 1]);
            log_event('Decommission ordered: the agent removes its key and disable its service at its next check-in', 'warn', $agent);
            flash('ok', 'At its next check-in the agent will remove itself. Delete the site afterwards.');
            break;

        case 'cancel_decommission':
            db_update('agents', $id, ['decommission' => 0]);
            log_event('Decommission cancelled', 'info', $agent);
            break;

        case 'delete':
            $notes = agent_delete($agent, !empty($_POST['remove_records']), $me['username']);
            flash('ok', "Deleted {$agent['name']}." . ($notes ? ' ' . implode('; ', $notes) : ''));
            redirect('index.php');
    }
    redirect($self);
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
$agent = agent_get($id);
$targets = agent_targets($id);
$st = agent_status($agent, $targets);
$accounts = dns_accounts_all();

page_header($agent['name'], 'index');
echo '<div data-autorefresh="60"></div>';
echo '<div class="spread"><h1>' . h($agent['name']) . ' ' . status_badge($st) . '</h1><div class="small dim mono">' . h($agent['uid']) . '</div></div>';
echo '<p class="dim">' . h($st['detail']) . ($agent['customer'] ? ' · ' . h($agent['customer']) : '') . '</p>';

// ---- install / provisioning ----
if (!$agent['pubkey'] || isset($_GET['new'])) {
    echo '<div class="card"><h2>' . ($agent['pubkey'] ? 'Re-provision this site' : 'Install the agent') . '</h2>';
    if (setting('public_url') === '') {
        echo '<div class="callout">An admin must set Settings → General → Public URL first.</div>';
    } else {
        echo '<p>Download the provisioning file for the site\'s ' . ($agent['platform'] === 'docker' ? 'Docker host (LXC)' : 'Windows PC')
            . '. It contains a <b>one-time</b> provisioning profile: it works once, expires in ' . (int)setting('enroll_valid_days')
            . ' days. Windows uses a separate common signed executable. Each download issues a new profile and cancels the previous one.</p>';
        echo '<form method="post" action="profile.php" class="row">' . csrf_field() . '<input type="hidden" name="id" value="' . $id . '">';
        if ($agent['platform'] === 'docker') {
            echo '<button class="primary" name="format" value="docker">Download Docker installer (.sh)</button>';
        } else {
            echo '<button class="primary" name="format" value="windows">Download Windows profile (.json)</button>';
        }
        echo '<button name="format" value="json">Profile only (.json)</button></form>'
            . '<p class="small dim">Installing from the bare profile? Get the program files from <a href="download.php">Agent files</a>.</p>';
        if ($agent['platform'] === 'docker') {
            echo '<h3>Then, in the LXC</h3><ol class="howto"><li>Copy the file to the LXC (WinSCP/scp).</li><li>Run <code>sudo bash dynallow-' . h($agent['uid']) . '.sh</code></li><li>This page turns green within a minute or two.</li></ol>';
        } else {
            echo '<h3>Then, on the PC</h3><ol class="howto"><li>Copy the file to the PC.</li><li>Install the common signed native agent, then run <code>DynAllow.Agent.exe install --profile &quot;path-to-profile.json&quot;</code> from an elevated terminal.</li>'
                . '<li>A colored dot appears by the clock. This page turns green within a minute or two.</li></ol>';
        }
        if ($agent['enroll_token_hash'] && (int)$agent['enroll_expires_at'] > time()) {
            echo '<p class="small dim">A profile issued ' . h(fmt_ago((int)$agent['enroll_issued_at'])) . ' by ' . h($agent['enroll_issued_by']) . ' is still unused. '
                . action_button('revoke_profile', 'Revoke it', ['id' => $id], 'small', 'Revoke the unused profile? Anyone holding it can no longer install this site.') . '</p>';
        }
        if ($agent['pubkey']) {
            echo '<div class="callout">This site is already installed. Installing a new profile replaces its identity: the current machine stops working until it runs the new installer.</div>';
        }
    }
    echo '</div>';
}

echo '<div class="grid">';

// ---- address ----
echo '<div class="card"><h2>Address</h2><table class="kv">';
echo '<tr><th>Authoritative IPv4</th><td><b class="mono">' . h($agent['current_ipv4'] ?: '—') . '</b> ' . ($agent['current_ipv4'] ? ip_source_badge($agent['ip_source']) : '') . '</td></tr>';
echo '<tr><th>Since</th><td>' . h(fmt_time($agent['ip_changed_at'] ? (int)$agent['ip_changed_at'] : null)) . '</td></tr>';
echo '<tr><th>Agent signed</th><td class="mono">' . h($agent['agent_reported_ipv4'] ?: '—') . '</td></tr>';
echo '<tr><th>Server saw</th><td class="mono">' . h($agent['last_remote_addr'] ?: '—') . '</td></tr>';
echo '<tr><th>IPv6 network</th><td class="mono">' . h($agent['current_ipv6'] ? ipv6_prefix64_cidr($agent['current_ipv6']) : '—') . '</td></tr>';
echo '<tr><th>Trust mode</th><td>' . h(explode(':', trust_modes()[$agent['trust_mode']])[0]) . '</td></tr>';
echo '</table>';
if ($agent['pending_ipv4'] && $agent['trust_mode'] === 'manual') {
    echo '<div class="callout">New verified IP <b class="mono">' . h($agent['pending_ipv4']) . '</b> is waiting for approval.</div>';
    if ($isAdmin) {
        echo '<div class="row">' . action_button('approve_ip', 'Approve ' . $agent['pending_ipv4'], ['id' => $id], 'primary', 'Make ' . $agent['pending_ipv4'] . ' authoritative and update DNS?')
            . action_button('reject_ip', 'Reject', ['id' => $id]) . '</div>';
    }
}
if ($agent['ip_mismatch']) {
    echo '<div class="callout">Held: the agent signed <b class="mono">' . h($agent['agent_reported_ipv4'] ?: 'nothing') . '</b> but its request came from <b class="mono">'
        . h($agent['last_remote_addr']) . '</b>. DNS stays on the last verified IP. Common causes: two internet links at the site, or a proxy in front of this server missing from <code>trusted_proxies</code>.</div>';
    if ($isAdmin) {
        echo '<div class="row">';
        foreach (array_unique(array_filter([$agent['agent_reported_ipv4'], $agent['server_seen_ipv4']])) as $ip) {
            echo action_button('set_ip', "Use $ip", ['id' => $id, 'ip' => $ip], 'small', "Set $ip as the authoritative IP by hand?");
        }
        echo '</div>';
    }
}
echo '</div>';

// ---- DNS targets ----
echo '<div class="card"><h2>DNS</h2>';
if (!$targets) {
    echo '<p class="dim">No DNS names yet — the IP is still tracked for alerts and allowlist feeds.</p>';
}
foreach ($targets as $t) {
    $label = $t['provider'] === 'none' ? 'Tracking only' : $t['hostname'];
    echo '<div class="target-row"><div class="spread"><div>' . target_dot($t) . '<b class="mono">' . h($label) . '</b>'
        . ($t['generated_name'] && $t['provider'] !== 'none' ? ' ' . badge('muted', 'random') : '') . '<div class="small dim">' . h($t['account_name'])
        . ' · ' . h($t['enabled'] ? $t['state'] : 'paused') . ' · TTL ' . (int)$t['ttl'] . ($t['proxied'] ? ' · proxied' : '') . '</div></div><div class="row">'
        . action_button('target_push', 'Push now', ['id' => $id, 'target_id' => $t['id']], 'small')
        . action_button('target_toggle', $t['enabled'] ? 'Pause' : 'Resume', ['id' => $id, 'target_id' => $t['id']], 'small');
    if ($isAdmin) {
        echo '<form method="post" class="inline">' . csrf_field() . '<input type="hidden" name="action" value="target_delete"><input type="hidden" name="id" value="' . $id
            . '"><input type="hidden" name="target_id" value="' . (int)$t['id'] . '"><input type="hidden" name="remove_record" value="1">'
            . '<button class="small danger" data-confirm="Remove ' . h($t['hostname']) . ' from this site AND delete the record at the provider (where its API allows)?">Remove</button></form>';
    }
    echo '</div></div><div class="small">' . h($t['detail']) . '</div><div class="small dim">Last pushed: '
        . h($t['last_pushed_ip'] ?: '—') . ' · ' . h(fmt_ago($t['last_pushed_at'] ? (int)$t['last_pushed_at'] : null))
        . ' · verified ' . h(fmt_ago($t['last_verified_at'] ? (int)$t['last_verified_at'] : null)) . '</div></div>';
}
if ($accounts) {
    echo '<details><summary>Add a DNS name / switch provider</summary><form method="post">' . csrf_field()
        . '<input type="hidden" name="action" value="target_add"><input type="hidden" name="id" value="' . $id . '"><div data-targets>'
        . target_row_html($accounts, 'targets[0]', [], false) . '</div><button class="primary">Add</button>'
        . '<p class="small dim">To move a site to a different DNS provider: add the new name here, update whatever points at the old name, then remove the old one.</p></form></details>';
} elseif ($isAdmin) {
    echo '<p class="small"><a href="accounts.php">Add a DNS account</a> to keep a hostname updated.</p>';
}
echo '</div>';

// ---- settings ----
echo '<div class="card"><h2>Settings</h2><form method="post">' . csrf_field() . '<input type="hidden" name="action" value="save"><input type="hidden" name="id" value="' . $id . '">';
echo '<div class="cols2">' . field('Site name', input('name', $agent['name'], 'text', ['required' => true, 'maxlength' => '80']))
    . field('Customer', input('customer', $agent['customer'])) . '</div>';
echo '<div class="cols2">' . field('Site address', input('site_address', $agent['site_address'])) . field('Site contact', input('site_contact', $agent['site_contact'])) . '</div>';
echo '<div class="cols2">' . field('Check in', select('interval_sec', interval_options() + [(string)$agent['interval_sec'] => fmt_duration((int)$agent['interval_sec'])], $agent['interval_sec']))
    . field('Email after this many missed check-ins', input('missed_threshold', $agent['missed_threshold'], 'number', ['min' => '1', 'max' => '20'])) . '</div>';
echo field('Trust mode', select('trust_mode', trust_modes(), $agent['trust_mode']));
if ($agent['platform'] === 'windows') echo checkbox('prevent_sleep', (bool)$agent['prevent_sleep'], 'Prevent automatic system sleep (display may turn off; default off)');
echo '<p class="small dim">Reported sleep state: ' . h($agent['sleep_status']) . '</p>';
echo field('Extra alert emails for this site', input('alert_emails', $agent['alert_emails']), 'Comma-separated. Global recipients (Settings) always get alerts too.');
echo field('Tags', input('tags', $agent['tags']), 'Comma-separated, e.g. <code>pbx, starlink</code>. Allowlist feeds can filter by tag.');
echo field('Notes', '<textarea name="notes">' . h($agent['notes']) . '</textarea>');
echo '<button class="primary">Save</button></form></div>';

// ---- operations & security ----
echo '<div class="card"><h2>Operations</h2><div class="row">';
echo action_button($agent['enabled'] ? 'disable' : 'enable', $agent['enabled'] ? 'Disable' : 'Enable', ['id' => $id], '', $agent['enabled'] ? 'Disable this site? DNS stops updating, alerts stop, and it drops out of allowlist feeds.' : '');
if ($agent['maintenance_until'] && (int)$agent['maintenance_until'] > time()) {
    echo action_button('maintenance', 'End maintenance', ['id' => $id, 'hours' => 0]);
} else {
    foreach ([1, 4, 24] as $hrs) echo action_button('maintenance', "Mute alerts {$hrs}h", ['id' => $id, 'hours' => $hrs], 'small');
}
echo '</div><table class="kv mt">';
echo '<tr><th>Agent</th><td>' . h($agent['platform']) . ' ' . h($agent['agent_version'] ?: '') . ' on ' . h($agent['agent_hostname'] ?: '—') . '<div class="small dim">' . h($agent['agent_os'] ?: '') . '</div></td></tr>';
echo '<tr><th>Key storage</th><td>' . protector_badge($agent['key_protector']) . '</td></tr>';
echo '<tr><th>Identity key</th><td class="mono">' . h($agent['pubkey_id'] ?: '—') . ($agent['pending_pubkey_id'] ? ' → ' . h($agent['pending_pubkey_id']) . ' (rotating)' : '')
    . '<div class="small dim">created ' . h(fmt_ago($agent['pubkey_at'] ? (int)$agent['pubkey_at'] : null)) . '</div></td></tr>';
echo '<tr><th>Enrolled</th><td>' . h(fmt_time($agent['enrolled_at'] ? (int)$agent['enrolled_at'] : null)) . '</td></tr>';
echo '<tr><th>Check-ins</th><td>' . (int)$agent['checkin_count'] . ' · first ' . h(fmt_ago($agent['first_checkin_at'] ? (int)$agent['first_checkin_at'] : null)) . '</td></tr>';
if ($agent['last_bad_auth_at']) {
    echo '<tr><th>Last forged request</th><td>' . badge('bad', fmt_ago((int)$agent['last_bad_auth_at'])) . '</td></tr>';
}
echo '</table>';
if ($agent['machine_id_changed_at']) {
    echo '<div class="callout">This site\'s key checked in from a <b>different machine</b> ' . h(fmt_ago((int)$agent['machine_id_changed_at'])) . '. Its key files were probably copied.</div>';
}
if ($isAdmin && $agent['pubkey']) {
    echo '<div class="row">' . action_button('rotate_key', 'Rotate key now', ['id' => $id], 'small');
    if ($agent['machine_id_changed_at']) echo action_button('clear_clone', 'This was planned — accept the new machine', ['id' => $id], 'small', 'Accept the new hardware as this site\'s machine?');
    echo '<a class="btn small" href="agent.php?id=' . $id . '&new=1">Re-provision…</a></div>';
}
echo '</div>';
echo '</div>'; // grid

echo '<div class="card"><h2>Agent diagnostics and updates</h2><p><a href="logs.php?source=agent&amp;agent=' . $id . '">View agent logs</a></p>';
echo '<p>Update: ' . h($agent['update_status'] ?: 'No update reported') . ' · release sequence ' . (int)$agent['release_sequence'] . '</p>';
if ($agent['pubkey'] && !$agent['release_target']) echo '<p class="callout">Legacy agent: install the signed 3.x build locally to enable protected updates and log upload.</p>';
if ($isAdmin) echo '<a href="releases.php?agent=' . $id . '">Deploy a signed release to this agent</a>';
echo '</div>';
// ---- history + events ----
echo '<div class="grid"><div class="card"><h2>IP history</h2><div class="tablewrap"><table><thead><tr><th>When</th><th>IP</th><th>Was</th><th>Evidence</th></tr></thead><tbody>';
foreach (db_all('SELECT * FROM ip_history WHERE agent_id = ? ORDER BY at DESC LIMIT 25', [$id]) as $r) {
    echo '<tr><td class="small nowrap">' . h(fmt_time((int)$r['at'])) . '</td><td class="mono">' . h($r['ip']) . '</td><td class="mono dim">' . h($r['previous_ip'] ?: '—') . '</td><td>' . ip_source_badge($r['source']) . '</td></tr>';
}
echo '</tbody></table></div></div><div class="card"><h2>Activity</h2><div class="tablewrap"><table><tbody>';
foreach (db_all('SELECT * FROM events WHERE agent_id = ? ORDER BY id DESC LIMIT 30', [$id]) as $e) {
    echo '<tr><td class="small nowrap">' . h(fmt_time((int)$e['at'])) . '</td><td>' . badge(['error' => 'bad', 'warn' => 'warn'][$e['level']] ?? 'muted', $e['level'])
        . '</td><td class="small">' . h($e['message']) . ' <span class="dim">— ' . h($e['actor']) . '</span></td></tr>';
}
echo '</tbody></table></div><p class="small"><a href="events.php?agent=' . $id . '">All activity for this site</a></p></div></div>';

// ---- danger zone ----
if ($isAdmin) {
    echo '<div class="card danger"><h2>Danger zone</h2><div class="row">';
    if ($agent['decommission']) {
        echo action_button('cancel_decommission', 'Cancel decommission', ['id' => $id]);
    } elseif ($agent['pubkey']) {
        echo action_button('decommission', 'Decommission (agent removes itself)', ['id' => $id], 'danger',
            'At its next check-in the agent will destroy its key and disable its service. Continue?');
    }
    echo '<form method="post" class="inline">' . csrf_field() . '<input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="' . $id . '">'
        . checkbox('remove_records', false, 'also delete its DNS records') . ' <button class="danger" data-confirm="Delete ' . h($agent['name'])
        . ' permanently? The agent stops working immediately and its history is removed.">Delete site</button></form>';
    echo '</div></div>';
}
page_footer();
