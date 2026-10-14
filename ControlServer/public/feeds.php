<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_admin();
$newToken = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    if (($_POST['action'] ?? '') === 'add') {
        $sources = array_filter(array_map('trim', preg_split('/[\s,]+/', (string)$_POST['allowed_sources'])));
        $bad = array_filter($sources, function ($c) {
            [$ip, $bits] = array_pad(explode('/', $c, 2), 2, null);
            return filter_var($ip, FILTER_VALIDATE_IP) === false || ($bits !== null && !ctype_digit($bits));
        });
        $name = trim((string)$_POST['name']);
        if ($name === '') flash('error', 'Give the feed a name (who uses it).');
        elseif ($bad) flash('error', 'Not an IP or CIDR: ' . implode(', ', $bad));
        else {
            $newToken = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
            db_exec('INSERT INTO feed_tokens(name, token_hash, tag_filter, max_age_hours, allowed_sources, include_ipv6, created_at) VALUES(?,?,?,?,?,?,?)', [
                $name, token_hash($newToken), implode(',', array_slice(parse_tags((string)$_POST['tag_filter']), 0, 1)),
                max(1, min(8760, (int)$_POST['max_age_hours'])), implode(', ', $sources), empty($_POST['include_ipv6']) ? 0 : 1, time()]);
            log_event("Allowlist feed token \"$name\" created", 'info');
        }
    }
    if (($_POST['action'] ?? '') === 'delete') {
        $f = db_one('SELECT * FROM feed_tokens WHERE id = ?', [(int)$_POST['id']]);
        if ($f) {
            db_exec('DELETE FROM feed_tokens WHERE id = ?', [$f['id']]);
            log_event("Allowlist feed token \"{$f['name']}\" revoked", 'warn');
            flash('ok', 'Revoked.');
        }
    }
    if ($newToken === null) redirect('feeds.php');
}

page_header('Allowlist feeds', 'feeds');
$base = rtrim(setting('public_url'), '/') ?: '(public URL)';
echo '<h1>Allowlist feeds</h1><p class="dim">Give firewalls, PBXes and scripts a live list of your sites\' verified IPs. A site that stops checking in drops out of the list after the feed\'s age limit, '
    . 'so a recycled address doesn\'t stay trusted.</p>';
if ($newToken) {
    echo '<div class="card"><h2>Token created — copy it now, it won\'t be shown again</h2><div class="secret" id="tok">' . h($newToken) . '</div>'
        . '<button type="button" class="small mt" data-copy="tok">Copy</button><h3>Use it</h3><pre class="cmd">' . h("$base/feed.php?token=$newToken") . "\n"
        . h("$base/feed.php?token=$newToken&format=json") . "\n" . h("$base/feed.php?token=$newToken&format=csv") . '</pre>'
        . '<p class="small">pfSense/OPNsense: Firewall → Aliases → URL Table (IPs). FortiGate: External Threat Feed (IP address). Feeds are refused over plain HTTP. '
        . 'Signature: verify the <code>X-IPF-Signature</code> header (ECDSA P-256, raw r‖s, over the body) with the key at <code>' . h($base) . '/feed.php?pubkey=1</code>.</p></div>';
}
$rows = db_all('SELECT * FROM feed_tokens ORDER BY name');
if ($rows) {
    echo '<div class="card tablewrap"><table><thead><tr><th>Name</th><th>Filter</th><th>Max age</th><th>Allowed from</th><th>Last used</th><th></th></tr></thead><tbody>';
    foreach ($rows as $f) {
        echo '<tr><td><b>' . h($f['name']) . '</b></td><td>' . h($f['tag_filter'] ? "tag: {$f['tag_filter']}" : 'all sites') . ($f['include_ipv6'] ? ' + IPv6 /64' : '') . '</td><td>' . (int)$f['max_age_hours'] . ' h</td><td class="small mono">'
            . h($f['allowed_sources'] ?: 'anywhere') . '</td><td class="small">' . h(fmt_ago($f['last_used_at'] ? (int)$f['last_used_at'] : null)) . ($f['last_used_from'] ? '<div class="dim">' . h($f['last_used_from']) . '</div>' : '')
            . '</td><td>' . action_button('delete', 'Revoke', ['id' => $f['id']], 'small danger', "Revoke {$f['name']}? Anything using it stops getting updates.") . '</td></tr>';
    }
    echo '</tbody></table></div>';
}
echo '<div class="card"><h2>New feed token</h2><form method="post">' . csrf_field() . '<input type="hidden" name="action" value="add"><div class="cols2">'
    . field('Name', input('name', '', 'text', ['required' => true, 'placeholder' => 'e.g. FreePBX cluster firewall']))
    . field('Only sites with tag (optional)', input('tag_filter', '', 'text', ['placeholder' => 'pbx']))
    . field('Drop sites silent for more than (hours)', input('max_age_hours', '24', 'number', ['min' => '1', 'max' => '8760']))
    . field('Only allow fetching from (optional)', input('allowed_sources', '', 'text', ['placeholder' => '203.0.113.5, 10.0.0.0/8']), 'IPs or CIDRs of the consumer. Strongly recommended.')
    . '</div>' . checkbox('include_ipv6', false, 'Include each site\'s IPv6 /64 (not shared like CGNAT IPv4)') . '<button class="primary mt">Create token</button></form></div>';
page_footer();
