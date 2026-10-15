<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_login();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    if ($me['role'] !== 'admin') { http_response_code(403); exit('Admins only'); }
    $id = (int)($_POST['ack'] ?? 0);
    if (db_exec('UPDATE diagnostics SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL', [time(), $me['username'], $id])) {
        log_event('Diagnostic acknowledged: #' . $id, 'info', null, $me['username']);
    }
    redirect('logs.php?attention=1');
}
$where = []; $args = [];
$source = (string)($_GET['source'] ?? '');
if (in_array($source, ['server', 'agent'], true)) { $where[] = 'source = ?'; $args[] = $source; }
if (!empty($_GET['agent'])) { $where[] = 'agent_id = ?'; $args[] = (int)$_GET['agent']; }
if (!empty($_GET['attention'])) $where[] = "level IN ('warn','error') AND acknowledged_at IS NULL";
$level = (string)($_GET['level'] ?? '');
if (in_array($level, ['info', 'warn', 'error'], true)) { $where[] = 'level = ?'; $args[] = $level; }
$q = substr(trim((string)($_GET['q'] ?? '')), 0, 200);
if ($q !== '') { $where[] = 'message LIKE ?'; $args[] = '%' . $q . '%'; }
$before = max(0, (int)($_GET['before'] ?? 0));
if ($before) { $where[] = 'id < ?'; $args[] = $before; }
$rows = db_all('SELECT * FROM diagnostics' . ($where ? ' WHERE ' . implode(' AND ', $where) : '') . ' ORDER BY id DESC LIMIT 101', $args);
page_header('Logs', 'logs');
echo '<h1>Logs</h1><p>Server receipt time is authoritative. Agent time is reported by the endpoint. Offline logs arrive after connectivity returns. <a href="events.php">Administrative audit trail</a></p>';
echo '<form method="get" class="card row">' . select('source', ['' => 'All sources', 'server' => 'Server', 'agent' => 'Agents'], $source)
    . select('level', ['' => 'All levels', 'info' => 'Info', 'warn' => 'Warnings', 'error' => 'Errors'], $level) . input('q', $q)
    . (!empty($_GET['agent']) ? '<input type="hidden" name="agent" value="' . (int)$_GET['agent'] . '">' : '')
    . checkbox('attention', !empty($_GET['attention']), 'Unacknowledged warnings/errors') . '<button>Filter</button> <a href="logs.php">Clear</a></form>';
echo '<div class="card tablewrap"><table><tr><th>Received / agent time</th><th>Source</th><th>Level</th><th>Message</th><th>Review</th></tr>';
foreach (array_slice($rows, 0, 100) as $r) {
    echo '<tr><td>' . h(fmt_time((int)$r['at'])) . ($r['client_at'] ? '<br><small>' . h(fmt_time((int)$r['client_at'])) . '</small>' : '') . '</td><td>' . h($r['source']) . ' ' . h($r['agent_name'])
        . '</td><td>' . badge(['warn' => 'warn', 'error' => 'bad'][$r['level']] ?? 'muted', $r['level']) . '</td><td><pre>' . h($r['message']) . '</pre></td><td>';
    if ($r['acknowledged_at']) echo h($r['acknowledged_by']) . '<br>' . h(fmt_time((int)$r['acknowledged_at']));
    elseif ($me['role'] === 'admin' && $r['level'] !== 'info') echo '<form method="post">' . csrf_field() . '<button name="ack" value="' . (int)$r['id'] . '">Acknowledge</button></form>';
    echo '</td></tr>';
}
echo '</table></div>';
if (count($rows) > 100) { $qs = $_GET; $qs['before'] = $rows[99]['id']; echo '<a href="?' . h(http_build_query($qs)) . '">Older logs →</a>'; }
page_footer();
