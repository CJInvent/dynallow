<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_login();

$staleDays = max(1, (int)setting('stale_days'));
$staleCut = time() - $staleDays * 86400;

function agent_is_stale(array $a, int $cut): bool
{
    if ($a['decommission'] && $a['decommissioned_at']) return true;
    if (!$a['pubkey']) return (int)$a['created_at'] < $cut;           // provisioned, never installed
    return (int)($a['last_checkin_at'] ?: $a['enrolled_at']) < $cut;  // went silent
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    if ($me['role'] !== 'admin') {
        http_response_code(403);
        exit('Admins only.');
    }
    $remove = !empty($_POST['remove_records']);
    $targets = [];
    if (($_POST['action'] ?? '') === 'bulk_delete') {
        foreach ((array)($_POST['ids'] ?? []) as $id) {
            if ($a = agent_get((int)$id)) $targets[] = $a;
        }
    } elseif (($_POST['action'] ?? '') === 'delete_stale') {
        foreach (db_all('SELECT * FROM agents') as $a) {
            if (agent_is_stale($a, $staleCut)) $targets[] = $a;
        }
    }
    foreach ($targets as $a) {
        agent_delete($a, $remove, $me['username']);
    }
    flash('ok', count($targets) . ' agent(s) deleted.' . ($remove ? ' DNS records were removed where the provider allows it.' : ''));
    redirect('index.php');
}

$all = db_all('SELECT * FROM agents ORDER BY name COLLATE NOCASE');
$targetsBy = [];
foreach (db_all('SELECT t.*, a.provider, a.name AS account_name FROM dns_targets t JOIN dns_accounts a ON a.id = t.account_id ORDER BY t.id') as $t) {
    $targetsBy[$t['agent_id']][] = $t;
}
$counts = ['all' => 0, 'good' => 0, 'warn' => 0, 'bad' => 0, 'neutral' => 0, 'muted' => 0, 'stale' => 0];
$rows = [];
$show = (string)($_GET['show'] ?? 'all');
$q = strtolower(trim((string)($_GET['q'] ?? '')));
$tag = strtolower(trim((string)($_GET['tag'] ?? '')));
foreach ($all as $a) {
    $st = agent_status($a, $targetsBy[$a['id']] ?? []);
    $stale = agent_is_stale($a, $staleCut);
    $counts['all']++;
    $counts[$st['tone']]++;
    if ($stale) $counts['stale']++;
    if ($show === 'problems' && $st['tone'] !== 'bad') continue;
    if ($show === 'attention' && $st['tone'] !== 'warn') continue;
    if ($show === 'waiting' && $st['tone'] !== 'neutral') continue;
    if ($show === 'off' && $st['tone'] !== 'muted') continue;
    if ($show === 'stale' && !$stale) continue;
    if ($tag !== '' && !in_array($tag, parse_tags($a['tags']), true)) continue;
    if ($q !== '') {
        $hay = strtolower($a['name'] . ' ' . $a['customer'] . ' ' . $a['current_ipv4'] . ' ' . $a['uid'] . ' ' . $a['tags'] . ' '
            . implode(' ', array_column($targetsBy[$a['id']] ?? [], 'hostname')));
        if (strpos($hay, $q) === false) continue;
    }
    $rows[] = [$a, $st, $stale];
}

if (($_GET['export'] ?? '') === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="dynallow-sites-' . date('Ymd') . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['name', 'customer', 'status', 'ipv4', 'ip_source', 'ipv6', 'last_checkin', 'hostnames', 'tags', 'platform', 'version', 'key_protector', 'uid']);
    foreach ($rows as [$a, $st]) {
        fputcsv($out, [$a['name'], $a['customer'], $st['label'], $a['current_ipv4'], $a['ip_source'], $a['current_ipv6'],
            $a['last_checkin_at'] ? gmdate('c', (int)$a['last_checkin_at']) : '', implode(' ', array_column($targetsBy[$a['id']] ?? [], 'hostname')),
            $a['tags'], $a['platform'], $a['agent_version'], $a['key_protector'], $a['uid']]);
    }
    exit;
}

page_header('Dashboard', 'index');
echo '<div data-autorefresh="60"></div>';
echo '<div class="spread"><h1>Sites</h1><div class="row"><a class="btn primary" href="survey.php">+ New site</a>'
    . '<a class="btn" href="?' . h(http_build_query(['show' => $show, 'q' => $q, 'tag' => $tag, 'export' => 'csv'])) . '">Export CSV</a></div></div>';

$tile = function (string $key, string $label, int $n, string $tone) use ($show) {
    return '<a class="tile ' . $tone . '" href="?show=' . $key . '"' . ($show === $key ? ' aria-current="true"' : '') . '><b>' . $n . '</b><span>' . h($label) . '</span></a>';
};
echo '<div class="tiles">' . $tile('all', 'All sites', $counts['all'], '') . $tile('problems', 'Problems', $counts['bad'], 'bad')
    . $tile('attention', 'Needs attention', $counts['warn'], 'warn') . $tile('waiting', 'Waiting / syncing', $counts['neutral'], 'neutral')
    . $tile('off', 'Disabled / paused', $counts['muted'], '') . $tile('stale', "Stale ({$staleDays}d+)", $counts['stale'], '') . '</div>';

echo '<form method="get" class="row card"><input type="hidden" name="show" value="' . h($show) . '">'
    . input('q', $q, 'text', ['placeholder' => 'Search name, customer, IP, hostname, tag…']) . input('tag', $tag, 'text', ['placeholder' => 'tag'])
    . '<button>Filter</button>' . ($q !== '' || $tag !== '' || $show !== 'all' ? ' <a href="index.php">Clear</a>' : '') . '</form>';

if (!$all) {
    echo '<div class="card"><h2>No sites yet</h2><p>Start with <a href="survey.php">New site</a>. ';
    if (!dns_accounts_all() && $me['role'] === 'admin') {
        echo 'You may want to add a <a href="accounts.php">DNS account</a> first so sites can keep a hostname updated.';
    }
    echo '</p></div>';
    page_footer();
    exit;
}

$isAdmin = $me['role'] === 'admin';
echo '<form method="post" class="card tablewrap">' . csrf_field() . '<table><thead><tr>';
if ($isAdmin) echo '<th><input type="checkbox" data-check-all="ids[]" aria-label="select all"></th>';
echo '<th>Site</th><th>Status</th><th>Authoritative IP</th><th>DNS</th><th>Last check-in</th><th>Agent</th></tr></thead><tbody>';
foreach ($rows as [$a, $st, $stale]) {
    echo '<tr>';
    if ($isAdmin) echo '<td><input type="checkbox" name="ids[]" value="' . (int)$a['id'] . '"></td>';
    echo '<td><a href="agent.php?id=' . (int)$a['id'] . '"><b>' . h($a['name']) . '</b></a><div class="small dim">' . h($a['customer'])
        . ($a['tags'] ? ' · ' . h($a['tags']) : '') . '</div></td>';
    echo '<td>' . status_badge($st) . ($stale ? ' ' . badge('muted', 'stale') : '') . '<div class="small dim">' . h($st['detail']) . '</div></td>';
    echo '<td class="nowrap"><span class="mono">' . h($a['current_ipv4'] ?: '—') . '</span> ' . ($a['current_ipv4'] ? ip_source_badge($a['ip_source']) : '')
        . ($a['current_ipv6'] ? '<div class="small dim mono">' . h(ipv6_prefix64_cidr($a['current_ipv6'])) . '</div>' : '') . '</td><td>';
    foreach ($targetsBy[$a['id']] ?? [] as $t) {
        echo '<div class="nowrap small">' . target_dot($t) . h($t['provider'] === 'none' ? 'tracking only' : $t['hostname']) . '</div>';
    }
    echo '</td><td class="nowrap small">' . h(fmt_ago($a['last_checkin_at'] ? (int)$a['last_checkin_at'] : null)) . '</td>';
    echo '<td class="small nowrap">' . h($a['platform']) . ($a['agent_version'] ? ' ' . h($a['agent_version']) : '') . '<br>' . protector_badge($a['key_protector']) . '</td></tr>';
}
echo '</tbody></table>';
if ($isAdmin) {
    echo '<div class="row mt">' . checkbox('remove_records', false, 'Also delete their DNS records')
        . '<button name="action" value="bulk_delete" class="danger" data-confirm="Delete the selected sites? Their agents stop working immediately.">Delete selected</button></div>';
}
echo '</form>';
if ($isAdmin) {
    echo '<div class="card"><h2>Clean up</h2><form method="post" class="row">' . csrf_field()
        . checkbox('remove_records', false, 'Also delete their DNS records (Cloudflare/PowerDNS)')
        . '<button name="action" value="delete_stale" class="danger" data-confirm="Delete all ' . $counts['stale'] . ' stale sites (no check-in for ' . $staleDays . '+ days, or never installed)? This cannot be undone.">Delete all stale (' . $counts['stale'] . ')</button>'
        . '</form><p class="small dim">To delete specific sites, tick them in the table and use "Delete selected". "Stale" = no check-in for ' . $staleDays . ' days, or provisioned and never installed (change in Settings).</p></div>';
}
page_footer();
