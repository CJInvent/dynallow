<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
require_login();
$files = ['agent.php'=>'docker/agent.php', 'launcher.php'=>'docker/launcher.php', 'release.php'=>'docker/release.php', 'docker-compose.yml'=>'docker/docker-compose.yml'];
$f=(string)($_GET['f']??'');
if ($f==='update-policy.json') {
    header('Content-Type: application/json'); header('Content-Disposition: attachment; filename="update-policy.json"'); header('Cache-Control: no-store');
    echo json_encode(['allow_dev_releases' => app_config('allow_dev_releases') === true]); exit;
}
if ($f==='release-public.pem') {
    header('Content-Type: application/octet-stream'); header('Content-Disposition: attachment; filename="release-public.pem"'); header('Cache-Control: no-store');
    echo release_public_pem(); exit;
}
if (isset($files[$f])) {
    header('Content-Type: application/octet-stream'); header('Content-Disposition: attachment; filename="'.$f.'"'); header('X-Content-Type-Options: nosniff');
    readfile(APP_ROOT.'/agents/'.$files[$f]);exit;
}
page_header('Agent files');
if (app_config('allow_dev_releases') === true) echo '<div class="callout">Development updates use SHA-256 without release signing. Use a Development Windows build. Docker installers include this local development policy.</div>';
echo '<h1>Agent installation</h1><div class="card"><h2>Windows native service</h2><p>Obtain the common signed <code>DynAllow.Agent.exe</code> from your administrator. Download a one-time JSON profile from the site page, then run in an elevated terminal:</p>'
    . '<pre>DynAllow.Agent.exe install --profile "C:\\Downloads\\dynallow-agt_....json"</pre><p>To migrate an existing PowerShell installation without changing its identity, run <code>DynAllow.Agent.exe install</code>. The installer retains the existing protected ProgramData identity. Legacy PowerShell executables are no longer distributed here.</p></div>';
echo '<div class="card"><h2>Docker</h2><p>Use the site page’s generated installer, or create <code>app/</code> and <code>data/</code> beside the Compose file. Place these PHP files and the local update policy and (for production) verified offline public key in <code>app/</code>; place the profile at <code>data/provisioning.json</code>.</p><ul>';
foreach (array_merge(array_keys($files),['release-public.pem','update-policy.json']) as $n) echo '<li><a href="?f='.rawurlencode($n).'">'.h($n).'</a></li>';
echo '</ul><p>Verify the public-key fingerprint against the offline signing workstation before installation. Keep <code>app/</code> owned by the administrator and mounted read-only. Set <code>data/</code> owner to UID/GID 65534 and mode 700. Run <code>docker compose up -d</code>.</p></div>';
page_footer();
