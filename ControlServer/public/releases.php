<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_admin();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    try {
        $action = (string)($_POST['action'] ?? '');
        if ($action === 'upload') {
            $f = $_FILES['bundle'] ?? [];
            if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || ($f['size'] ?? 0) > RELEASE_MAX_BYTES || !is_uploaded_file($f['tmp_name'])) throw new RuntimeException('Upload failed; check PHP upload_max_filesize/post_max_size (at least 64M/70M)');
            release_store((string)file_get_contents($f['tmp_name']), $me['username']);
            flash('ok', 'Signature verified. Release stored; select a deployment action below.');
        } elseif (in_array($action, ['activate', 'push', 'pause'], true)) {
            $r = db_one('SELECT * FROM releases WHERE id = ?', [(int)($_POST['release'] ?? 0)]);
            if (!$r) throw new RuntimeException('Release not found');
            if ($action === 'activate') {
                db()->beginTransaction();
                db_exec('UPDATE releases SET active = 0 WHERE target = ?', [$r['target']]);
                db_update('releases', (int)$r['id'], ['active' => 1]);
                db()->commit();
            } elseif ($action === 'pause') {
                db_update('releases', (int)$r['id'], ['active' => 0]);
                db_exec('UPDATE agents SET update_release_id = NULL WHERE update_release_id = ?', [$r['id']]);
            } else {
                $a = agent_get((int)($_POST['agent'] ?? 0));
                if (!$a || $a['release_target'] !== $r['target']) throw new RuntimeException('Agent target does not match release (3.x agent must have checked in)');
                if ((int)$r['sequence'] <= (int)$a['release_sequence']) throw new RuntimeException('Agent already has this sequence or newer');
                db_update('agents', (int)$a['id'], ['update_release_id' => $r['id']]);
            }
            log_event("Release {$r['target']} {$r['version']} #{$r['sequence']}: $action" . ($action === 'push' ? ' to agent #' . (int)$_POST['agent'] : ''), 'warn', null, $me['username']);
            flash('ok', 'Deployment updated. Agents fetch on their next check-in; pause cannot recall an already downloaded release.');
        }
    } catch (Throwable $e) {
        if (db()->inTransaction()) db()->rollBack();
        server_diagnostic('warn', 'Release operation rejected: ' . $e->getMessage());
        flash('error', $e->getMessage());
    }
    redirect('releases.php');
}
page_header('Releases', 'releases');
echo '<h1>Offline-signed client releases</h1><p>Upload bundles made by tools/Sign-Release.ps1. The private signing key stays offline. Clients also verify their independently pinned public key, target, version and increasing sequence.</p>';
try { $pem = release_public_pem(); $d = openssl_pkey_get_details(openssl_pkey_get_public($pem)); echo '<p>Trusted public-key SHA256 (SPKI DER): <code>' . h(hash('sha256', base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $d['key'])))) . '</code></p>'; }
catch (Throwable $e) { echo '<div class="callout">' . h($e->getMessage()) . '</div>'; }
echo '<form method="post" enctype="multipart/form-data" class="card">' . csrf_field() . '<input type="hidden" name="action" value="upload"><input type="file" name="bundle" accept=".json" required><button>Verify and upload</button></form>';
$agents = ['0' => 'Select one agent'];
foreach (db_all("SELECT id, name, release_target FROM agents WHERE release_target <> '' ORDER BY name") as $a) $agents[$a['id']] = $a['name'] . ' (' . $a['release_target'] . ')';
foreach (db_all('SELECT * FROM releases ORDER BY id DESC LIMIT 100') as $r) {
    echo '<div class="card"><h2>' . h($r['target'] . ' ' . $r['version']) . ' · #' . (int)$r['sequence'] . ($r['active'] ? ' (automatic rollout)' : '') . '</h2><p>Uploaded ' . h(fmt_time((int)$r['created_at'])) . ' by ' . h($r['uploaded_by']) . '</p><code>' . h($r['sha256']) . '</code><div class="row">'
        . action_button('activate', 'Activate automatic rollout', ['release' => $r['id']], '', 'Offer this release to all matching agents with automatic updates enabled?')
        . action_button('pause', 'Pause rollout', ['release' => $r['id']])
        . '<form method="post">' . csrf_field() . '<input type="hidden" name="action" value="push"><input type="hidden" name="release" value="' . (int)$r['id'] . '">'
        . select('agent', $agents, $_GET['agent'] ?? 0) . '<button>Push to agent</button></form></div></div>';
}
page_footer();
