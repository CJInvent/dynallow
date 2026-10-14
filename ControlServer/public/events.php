<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_login();

$where = [];
$args = [];
if (!empty($_GET['agent'])) { $where[] = 'agent_id = ?'; $args[] = (int)$_GET['agent']; }
if (in_array($_GET['level'] ?? '', ['info', 'warn', 'error'], true)) { $where[] = 'level = ?'; $args[] = $_GET['level']; }
if (($q = trim((string)($_GET['q'] ?? ''))) !== '') { $where[] = '(message LIKE ? OR agent_name LIKE ? OR actor LIKE ?)'; array_push($args, "%$q%", "%$q%", "%$q%"); }
$page = max(1, (int)($_GET['page'] ?? 1));
$sql = 'SELECT * FROM events' . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY id DESC LIMIT 101 OFFSET ' . (($page - 1) * 100);
$rows = db_all($sql, $args);

page_header('Activity', 'events');
echo '<h1>Activity</h1><form method="get" class="row card">' . (isset($_GET['agent']) ? '<input type="hidden" name="agent" value="' . (int)$_GET['agent'] . '">' : '')
    . input('q', $q, 'text', ['placeholder' => 'Search']) . select('level', ['' => 'All levels', 'info' => 'Info', 'warn' => 'Warnings', 'error' => 'Errors'], $_GET['level'] ?? '')
    . '<button>Filter</button> <a href="events.php">Clear</a></form>';
echo '<div class="card tablewrap"><table><thead><tr><th>When</th><th>Level</th><th>Site</th><th>What happened</th><th>By</th></tr></thead><tbody>';
foreach (array_slice($rows, 0, 100) as $e) {
    echo '<tr><td class="small nowrap">' . h(fmt_time((int)$e['at'])) . '</td><td>' . badge(['error' => 'bad', 'warn' => 'warn'][$e['level']] ?? 'muted', $e['level']) . '</td><td class="small">'
        . ($e['agent_id'] ? '<a href="agent.php?id=' . (int)$e['agent_id'] . '">' . h($e['agent_name']) . '</a>' : h($e['agent_name'] ?: '—'))
        . '</td><td class="small">' . h($e['message']) . '</td><td class="small dim">' . h($e['actor']) . '</td></tr>';
}
echo '</tbody></table></div><div class="spread">';
$qs = $_GET;
if ($page > 1) { $qs['page'] = $page - 1; echo '<a href="?' . h(http_build_query($qs)) . '">← Newer</a>'; } else echo '<span></span>';
if (count($rows) > 100) { $qs['page'] = $page + 1; echo '<a href="?' . h(http_build_query($qs)) . '">Older →</a>'; }
echo '</div>';
page_footer();
