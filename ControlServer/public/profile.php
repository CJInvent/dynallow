<?php
declare(strict_types=1);

/**
 * Issues a provisioning profile — a credential — as a download.
 *
 * POST + CSRF only, minted at
 * the moment of download (only its SHA-256 is stored, so it can't be shown
 * twice), single use, expiring, rate limited per user, audited, and served as
 * a no-store attachment. Every download voids the previous unused profile.
 *
 *   format=json     the bare profile
 *   format=windows  JSON profile for the separately distributed signed native EXE
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
    if (($_POST['format'] ?? '') === 'docker') release_public_pem();
    $profile = agent_issue_profile($agent, $me['username'], (int)setting('enroll_valid_days'));
} catch (RuntimeException $e) {
    flash('error', $e->getMessage());
    redirect('agent.php?id=' . (int)$agent['id']);
}
$profileJson = json_encode($profile, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
$format = (string)($_POST['format'] ?? 'json');
$base = 'dynallow-' . $agent['uid'];

header('Cache-Control: no-store, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');

switch ($format) {
    case 'windows':
        // Common signed executable + separate one-time credential, never a per-customer binary.
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $base . '.json"');
        log_event('Windows native provisioning profile downloaded', 'info', $agent);
        echo $profileJson, "\n";
        break;

    case 'docker':
        $dir = APP_ROOT . '/agents/docker';
        $tpl = (string)file_get_contents("$dir/install.sh");
        $out = strtr($tpl, [
            '__UPDATE_POLICY_B64__' => base64_encode(json_encode(['allow_dev_releases' => app_config('allow_dev_releases') === true])),
            '__LAUNCHER_B64__' => base64_encode((string)file_get_contents("$dir/launcher.php")),
            '__VERIFIER_B64__' => base64_encode((string)file_get_contents("$dir/release.php")),
            '__RELEASE_PUBLIC_B64__' => base64_encode(release_public_pem()),
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
