<?php
declare(strict_types=1);

/**
 * Agent program files, for installing from a bare profile (.json) instead of
 * the one-file installers. These contain no secrets.
 */
require dirname(__DIR__) . '/src/bootstrap.php';
require_login();
$files = [
    'install.ps1' => 'windows/install.ps1', 'uninstall.ps1' => 'windows/uninstall.ps1', 'run-agent.ps1' => 'windows/run-agent.ps1',
    'ip-agent.ps1' => 'windows/ip-agent.ps1', 'ip-agent-tray.ps1' => 'windows/ip-agent-tray.ps1',
    'agent.php' => 'docker/agent.php', 'docker-compose.yml' => 'docker/docker-compose.yml',
];
$f = (string)($_GET['f'] ?? '');
if (!isset($files[$f])) {
    page_header('Agent files');
    echo '<h1>Agent files</h1><div class="card"><p>Normally you don\'t need these: the site page gives a one-file installer with everything inside. '
        . 'Use them to install from a bare <code>.json</code> profile.</p><h3>Windows</h3><ul>';
    foreach (['install.ps1', 'uninstall.ps1', 'run-agent.ps1', 'ip-agent.ps1', 'ip-agent-tray.ps1'] as $n) echo '<li><a href="?f=' . $n . '">' . $n . '</a></li>';
    echo '</ul><p class="small">Put all five and the profile (renamed <code>provisioning.json</code>) in one folder and run <code>install.ps1</code> as administrator.</p>'
        . '<h3>Docker</h3><ul><li><a href="?f=agent.php">agent.php</a></li><li><a href="?f=docker-compose.yml">docker-compose.yml</a></li></ul>'
        . '<p class="small">Put both in a folder, create <code>data/</code>, put the profile at <code>data/provisioning.json</code>, run <code>docker compose up -d</code>.</p></div>';
    page_footer();
    exit;
}
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $f . '"');
header('X-Content-Type-Options: nosniff');
readfile(APP_ROOT . '/agents/' . $files[$f]);
