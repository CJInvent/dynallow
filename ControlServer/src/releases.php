<?php
declare(strict_types=1);

// One verifier implementation is used by the server and packaged Docker launcher.
require_once dirname(__DIR__) . '/agents/docker/release.php';

function release_public_pem(): string
{
    $path = app_config('release_public_key_file');
    if (!$path || !is_file($path)) throw new RuntimeException('Offline release public key is not configured. Install release-public.pem out of band.');
    $pem = (string)file_get_contents($path);
    if (str_contains($pem, 'PRIVATE KEY')) throw new RuntimeException('Release trust file must contain PUBLIC key only');
    $key = openssl_pkey_get_public($pem);
    $d = $key ? openssl_pkey_get_details($key) : false;
    if (!$d || ($d['ec']['curve_name'] ?? '') !== 'prime256v1') throw new RuntimeException('Release public key must be ECDSA P-256 SPKI PEM');
    return $pem;
}

function release_store(string $bundle, string $actor): array
{
    $m = verify_release_bundle($bundle, release_public_pem());
    $hash = hash('sha256', $bundle);
    $dir = app_config('data_dir') . '/releases';
    if (!is_dir($dir) && !mkdir($dir, 0700, true)) throw new RuntimeException('Cannot create releases directory');
    $path = "$dir/$hash.json";
    if (!is_file($path)) {
        $tmp = tempnam($dir, '.upload-');
        try {
            if (file_put_contents($tmp, $bundle, LOCK_EX) !== strlen($bundle)) throw new RuntimeException('Release write failed');
            chmod($tmp, 0600);
            if (!rename($tmp, $path)) throw new RuntimeException('Release publish failed');
        } finally { if (is_file($tmp)) unlink($tmp); }
    }
    $existing = db_one('SELECT * FROM releases WHERE target = ? AND sequence = ?', [$m['target'], $m['sequence']]);
    if ($existing) {
        if ($existing['sha256'] !== $hash) throw new RuntimeException('This target/sequence already has different bytes; use a new sequence');
        return $existing;
    }
    db_exec('INSERT INTO releases(target, version, sequence, sha256, size, created_at, uploaded_by) VALUES(?,?,?,?,?,?,?)',
        [$m['target'], $m['version'], $m['sequence'], $hash, strlen($bundle), time(), $actor]);
    $r = db_one('SELECT * FROM releases WHERE sha256 = ?', [$hash]);
    log_event("Offline-signed release uploaded: {$m['target']} {$m['version']} sequence {$m['sequence']} SHA256 $hash", 'info', null, $actor);
    return $r;
}

function release_offer(array $agent): ?array
{
    if (!$agent['release_target'] || $agent['decommission']) return null;
    $r = $agent['update_release_id'] ? db_one('SELECT * FROM releases WHERE id = ?', [$agent['update_release_id']]) :
        (setting('auto_update') === '1' ? db_one('SELECT * FROM releases WHERE target = ? AND active = 1 ORDER BY sequence DESC LIMIT 1', [$agent['release_target']]) : null);
    if (!$r || $r['target'] !== $agent['release_target'] || (int)$r['sequence'] <= (int)$agent['release_sequence']
        || version_compare($r['version'], (string)$agent['agent_version'], '<=')) return null;
    return ['sha256' => $r['sha256'], 'size' => (int)$r['size'], 'version' => $r['version'], 'sequence' => (int)$r['sequence']];
}
