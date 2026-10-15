<?php
declare(strict_types=1);
// Immutable /app mount. Never execute writable agent.php left by legacy 2.x.
require __DIR__ . '/release.php';
$data = rtrim(getenv('DATA_DIR') ?: '/data', '/');
$mode = $argv[1] ?? 'run';
$base = __DIR__ . '/agent.php';
putenv('IPF_APP_DIR=' . __DIR__);
$child = null;
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    foreach ([SIGTERM, SIGINT] as $signal) pcntl_signal($signal, function ($s) use (&$child) {
        if (is_resource($child)) proc_terminate($child, $s);
        exit(0);
    });
}
try {
    $file = $base;
    $bundle = "$data/current-release.json";
    $statePath = "$data/update-state.json";
    $water = is_file($statePath) ? json_decode((string)file_get_contents($statePath), true, 8, JSON_THROW_ON_ERROR) : [];
    preg_match('/const RELEASE_SEQUENCE = ([0-9]+);/', (string)file_get_contents($base), $bs);
    $baseSequence = (int)($bs[1] ?? 1);
    if (is_file($bundle)) {
        if (filesize($bundle) > RELEASE_MAX_BYTES) throw new RuntimeException('Oversized staged release');
        $json = (string)file_get_contents($bundle);
        $pem = (string)file_get_contents(__DIR__ . '/release-public.pem');
        $m = verify_release_bundle($json, $pem);
        if ($m['target'] !== 'docker' || $m['sequence'] < max($baseSequence, (int)($water['sequence'] ?? 0))) throw new RuntimeException('Staged release rollback/target rejected');
        $fingerprint = hash('sha256', base64_decode(json_decode($json, true)['manifest']));
        if ($m['sequence'] === (int)($water['sequence'] ?? 0) && !hash_equals($water['manifest_hash'] ?? '', $fingerprint)) throw new RuntimeException('Conflicting release at accepted sequence');
        // Persist watermark before executing. A valid but broken signed release fails closed;
        // recover with a newer signed release or an explicit local administrator repair.
        if (in_array($mode, ['run', 'once'], true)) {
            $tmp = "$statePath.tmp";
            if (file_put_contents($tmp, json_encode(['sequence' => $m['sequence'], 'manifest_hash' => $fingerprint]), LOCK_EX) === false
                || !rename($tmp, $statePath)) throw new RuntimeException('Cannot persist update watermark');
            chmod($statePath, 0600);
        }
        $file = tempnam(sys_get_temp_dir(), 'dynallow-');
        file_put_contents($file, base64_decode(json_decode($json, true)['files']['agent.php']));
        chmod($file, 0600);
    } elseif ((int)($water['sequence'] ?? 0) > $baseSequence) {
        throw new RuntimeException('Accepted release is missing; refusing silent downgrade');
    }
    $child = proc_open([PHP_BINARY, $file, $mode], [0 => STDIN, 1 => STDOUT, 2 => STDERR], $pipes);
    if (!is_resource($child)) throw new RuntimeException('Cannot start agent');
    $rc = proc_close($child);
    if ($file !== $base) @unlink($file);
    exit($rc);
} catch (Throwable $e) {
    // Fail closed; container becomes unhealthy and server missed-check-in alerts fire.
    fwrite(STDERR, 'RELEASE VERIFICATION FAILED: ' . $e->getMessage() . "\n");
    exit(1);
}
