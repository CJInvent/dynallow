<?php
declare(strict_types=1);
const RELEASE_MAX_BYTES = 67108864;
/** Signature covers EXACT manifest bytes; filenames, target, version, sequence, hashes and sizes are bound. */
function verify_release_bundle(string $json, string $pem): array
{
    if (strlen($json) > RELEASE_MAX_BYTES) throw new RuntimeException('Release bundle exceeds 64 MiB');
    $b = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($b) || !is_string($b['manifest'] ?? null) || strlen($b['manifest']) > 12000
        || !is_string($b['signature'] ?? null) || !is_array($b['files'] ?? null)) throw new RuntimeException('Malformed release bundle');
    $raw = base64_decode($b['manifest'], true);
    $sig = base64_decode($b['signature'], true);
    if ($raw === false || $sig === false || strlen($sig) > 80
        || openssl_verify($raw, $sig, $pem, OPENSSL_ALGO_SHA256) !== 1) throw new RuntimeException('Offline release signature is invalid');
    $m = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
    if (($m['format'] ?? '') !== 'dynallow-release-v1' || !in_array($m['target'] ?? '', ['windows-x64', 'windows-arm64', 'docker'], true)
        || !preg_match('/^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$/D', (string)($m['version'] ?? ''))
        || !is_int($m['sequence'] ?? null) || $m['sequence'] < 1 || $m['sequence'] > 2147483647
        || !is_array($m['files'] ?? null)) throw new RuntimeException('Invalid signed manifest');
    $expected = $m['target'] === 'docker' ? ['agent.php'] : ['DynAllow.Agent.exe'];
    if (array_column($m['files'], 'name') !== $expected || array_keys($b['files']) !== $expected) throw new RuntimeException('Unexpected release filenames');
    foreach ($m['files'] as $f) {
        $data = base64_decode((string)$b['files'][$f['name']], true);
        if (!is_int($f['size'] ?? null) || $f['size'] < 1 || $f['size'] > 48000000 || $data === false || strlen($data) !== $f['size']
            || !preg_match('/^[a-f0-9]{64}$/D', (string)($f['sha256'] ?? '')) || !hash_equals($f['sha256'], hash('sha256', $data))) throw new RuntimeException('Release content hash/size mismatch');
    }
    return $m;
}
