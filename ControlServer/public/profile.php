<?php
declare(strict_types=1);

/**
 * Issues a provisioning profile — a credential — as a download.
 *
 * Same rules as NimbusControl's install profiles: POST + CSRF only, minted at
 * the moment of download (only its SHA-256 is stored, so it can't be shown
 * twice), single use, expiring, rate limited per user, audited, and served as
 * a no-store attachment. Every download voids the previous unused profile.
 *
 *   format=json     the bare profile
 *   format=windows  one-file Windows installer with the profile + agent embedded
 *   format=docker   one-file shell installer for a Docker host / LXC
 */
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_login();
csrf_check();

$agent = agent_get((int)($_POST['id'] ?? 0));
if (!$agent) {
    http_response_code(404);
    exit('No such site.');
}
$bucket = 'profile:' . $me['id'];
if (rate_limited($bucket, 30, 3600)) {
    http_response_code(429);
    exit('Too many profiles issued in the last hour.');
}
rate_hit($bucket);

try {
    $profile = agent_issue_profile($agent, $me['username'], (int)setting('enroll_valid_days'));
} catch (RuntimeException $e) {
    flash('error', $e->getMessage());
    redirect('agent.php?id=' . (int)$agent['id']);
}
$profileJson = json_encode($profile, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
$format = (string)($_POST['format'] ?? 'json');
$base = 'ipfailover-' . $agent['uid'];

header('Cache-Control: no-store, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');

function embed_block(array $files): string
{
    $lines = [];
    foreach ($files as $name => $content) {
        $lines[] = "    '" . $name . "' = '" . base64_encode($content) . "'";
    }
    return implode("\n", $lines);
}

switch ($format) {
    case 'windows':
        $dir = APP_ROOT . '/agents/windows';
        $tpl = (string)file_get_contents("$dir/install.ps1");
        $files = ['provisioning.json' => $profileJson];
        foreach (['run-agent.ps1', 'ip-agent.ps1', 'ip-agent-tray.ps1', 'uninstall.ps1'] as $f) {
            $files[$f] = (string)file_get_contents("$dir/$f");
        }
        $out = preg_replace('/# IPF-EMBED-BEGIN.*# IPF-EMBED-END/s',
            "# IPF-EMBED-BEGIN (generated " . gmdate('c') . " for {$agent['uid']})\n\$Embedded = @{\n" . embed_block($files) . "\n}\n# IPF-EMBED-END", $tpl, 1);
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="Install-' . $base . '.ps1"');
        log_event('Windows installer downloaded (contains a one-time profile)', 'info', $agent);
        echo $out;
        break;

    case 'docker':
        $dir = APP_ROOT . '/agents/docker';
        $tpl = (string)file_get_contents("$dir/install.sh");
        $out = strtr($tpl, [
            '__AGENT_PHP_B64__'    => base64_encode((string)file_get_contents("$dir/agent.php")),
            '__COMPOSE_B64__'      => base64_encode((string)file_get_contents("$dir/docker-compose.yml")),
            '__PROFILE_B64__'      => base64_encode($profileJson),
            '__AGENT_UID__'        => $agent['uid'],
        ]);
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $base . '.sh"');
        log_event('Docker installer downloaded (contains a one-time profile)', 'info', $agent);
        echo $out;
        break;

    default:
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $base . '.json"');
        echo $profileJson, "\n";
}
