<?php
declare(strict_types=1);

/**
 * IPF1 — the agent <-> control-server envelope. Safe over plain HTTP;
 * TLS, when present, is defense in depth.
 *
 * Primitives were chosen because all three runtimes have them natively:
 * .NET Framework 4.7+ (Windows PowerShell 5.1), PHP openssl, .NET 8 (pwsh).
 * No libsodium on the agent side.
 *
 *   Curve        NIST P-256 for both ECDH and ECDSA
 *   Cipher       AES-256-CBC + HMAC-SHA256, encrypt-then-MAC
 *   Signatures   ECDSA P-256 / SHA-256, IEEE P1363 (r||s, 64 bytes) on the wire
 *
 * REQUEST (agent -> server), HTTP body is JSON:
 *   { "v":1, "kid":<server kex key id>, "epk":b64(65-byte uncompressed P-256),
 *     "iv":b64(16), "ct":b64, "mac":b64(32), "sig":b64(64) | absent for enroll }
 *
 *   Z        = ECDH(agent ephemeral private, server kex public)    (32-byte x-coord)
 *   K        = SHA256("IPF1" || Z || epk)                        (.NET DeriveKeyFromHash with prepend/append)
 *   k_*      = HMAC-SHA256(K, label) for labels req-enc, req-mac, resp-enc, resp-mac
 *   mac      = HMAC(k_req_mac, "IPF1|req|" || kid || epk || iv || ct)
 *   sig      = ECDSA(agent static key, "IPF1|sig|" || kid || epk || iv || ct || mac)
 *
 *   The plaintext carries type, agent uid, ts and a random nonce. The server
 *   rejects stale ts (clock window) and any nonce it has seen (replay).
 *
 * RESPONSE (server -> agent):
 *   { "v":1, "iv":b64, "ct":b64, "mac":b64 }
 *   mac = HMAC(k_resp_mac, "IPF1|resp|" || epk || iv || ct)
 *
 *   Only the holder of the server's kex private key can derive K for the
 *   agent's fresh ephemeral key, so a valid MAC authenticates the server; the
 *   plaintext echoes the request nonce, binding the response to this request.
 *
 * Fixed DER prefix of a P-256 SubjectPublicKeyInfo, used to turn raw points
 * into keys openssl accepts (avoids needing EC-from-params support).
 */

const IPF_SPKI_P256_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';
const IPF_MAX_BODY = 65536;

final class WireError extends RuntimeException
{
    /** Machine-readable code returned to agents, e.g. 'bad_mac', 'replay'. */
    public string $codeStr;
    public function __construct(string $code, string $message)
    {
        parent::__construct($message);
        $this->codeStr = $code;
    }
}

// ---------------------------------------------------------------------------
// P-256 key handling
// ---------------------------------------------------------------------------

/** @return array{private_pem: string, public_raw: string} */
function p256_generate(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    if ($key === false) {
        throw new RuntimeException('openssl could not generate a P-256 key: ' . openssl_error_string());
    }
    openssl_pkey_export($key, $pem);
    return ['private_pem' => $pem, 'public_raw' => p256_public_raw($key)];
}

/** 65-byte uncompressed point (0x04 || X || Y) from an openssl key. */
function p256_public_raw($key): string
{
    $d = openssl_pkey_get_details($key);
    if (!$d || !isset($d['ec']['x'], $d['ec']['y'])) {
        throw new RuntimeException('not an EC key');
    }
    return "\x04" . str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT);
}

/** Validates a raw point is a real P-256 point and returns an openssl public key. */
function p256_public_from_raw(string $raw)
{
    if (strlen($raw) !== 65 || $raw[0] !== "\x04") {
        throw new WireError('bad_key', 'public key must be a 65-byte uncompressed P-256 point');
    }
    $der = hex2bin(IPF_SPKI_P256_PREFIX) . $raw;
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $k = openssl_pkey_get_public($pem);
    if ($k === false) {
        // openssl rejects points that are not on the curve (invalid-curve attacks).
        throw new WireError('bad_key', 'public key is not a valid P-256 point');
    }
    return $k;
}

function p256_fingerprint(string $raw): string
{
    return substr(hash('sha256', $raw), 0, 16);
}

// ---------------------------------------------------------------------------
// ECDSA P1363 <-> DER
// ---------------------------------------------------------------------------

function ecdsa_der_to_p1363(string $der): string
{
    $pos = 0;
    $readLen = function () use ($der, &$pos): int {
        $len = ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x7f;
            $len = 0;
            for ($i = 0; $i < $n; $i++) {
                $len = ($len << 8) | ord($der[$pos++]);
            }
        }
        return $len;
    };
    if (ord($der[$pos++]) !== 0x30) throw new RuntimeException('bad DER');
    $readLen();
    $out = '';
    for ($i = 0; $i < 2; $i++) {
        if (ord($der[$pos++]) !== 0x02) throw new RuntimeException('bad DER int');
        $len = $readLen();
        $int = ltrim(substr($der, $pos, $len), "\0");
        $pos += $len;
        if (strlen($int) > 32) throw new RuntimeException('bad DER int length');
        $out .= str_pad($int, 32, "\0", STR_PAD_LEFT);
    }
    return $out;
}

function ecdsa_p1363_to_der(string $sig): string
{
    if (strlen($sig) !== 64) {
        throw new WireError('bad_signature', 'signature must be 64 bytes');
    }
    $enc = function (string $i): string {
        $i = ltrim($i, "\0");
        if ($i === '' ) $i = "\0";
        if (ord($i[0]) & 0x80) $i = "\0" . $i;
        return "\x02" . chr(strlen($i)) . $i;
    };
    $body = $enc(substr($sig, 0, 32)) . $enc(substr($sig, 32));
    return "\x30" . chr(strlen($body)) . $body;
}

function ecdsa_sign_p1363(string $privatePem, string $data): string
{
    $key = openssl_pkey_get_private($privatePem);
    if (!$key || !openssl_sign($data, $der, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('ECDSA sign failed');
    }
    return ecdsa_der_to_p1363($der);
}

function ecdsa_verify_p1363(string $publicRaw, string $data, string $sig): bool
{
    try {
        $pub = p256_public_from_raw($publicRaw);
        return openssl_verify($data, ecdsa_p1363_to_der($sig), $pub, OPENSSL_ALGO_SHA256) === 1;
    } catch (Throwable $e) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Symmetric layer
// ---------------------------------------------------------------------------

/** @return array{req_enc:string, req_mac:string, resp_enc:string, resp_mac:string} */
function ipf_derive_keys(string $z, string $epk): array
{
    $k = hash('sha256', 'IPF1' . $z . $epk, true);
    return [
        'req_enc'  => hash_hmac('sha256', 'req-enc', $k, true),
        'req_mac'  => hash_hmac('sha256', 'req-mac', $k, true),
        'resp_enc' => hash_hmac('sha256', 'resp-enc', $k, true),
        'resp_mac' => hash_hmac('sha256', 'resp-mac', $k, true),
    ];
}

function aes_cbc_encrypt(string $key, string $plain): array
{
    $iv = random_bytes(16);
    $ct = openssl_encrypt($plain, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($ct === false) throw new RuntimeException('AES encrypt failed');
    return [$iv, $ct];
}

function aes_cbc_decrypt(string $key, string $iv, string $ct): string
{
    $p = openssl_decrypt($ct, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($p === false) throw new WireError('bad_ciphertext', 'decryption failed');
    return $p;
}

function b64d(?string $s, int $len = 0, string $field = 'field'): string
{
    $b = base64_decode((string)$s, true);
    if ($b === false || ($len && strlen($b) !== $len)) {
        throw new WireError('bad_envelope', "malformed $field");
    }
    return $b;
}

// ---------------------------------------------------------------------------
// Server keys
// ---------------------------------------------------------------------------

function server_key_create(string $purpose): array
{
    $k = p256_generate();
    $kid = p256_fingerprint($k['public_raw']);
    db_exec('UPDATE server_keys SET active = 0, retired_at = ? WHERE purpose = ? AND active = 1', [time(), $purpose]);
    db_exec('INSERT INTO server_keys(kid, purpose, public_key, private_enc, active, created_at) VALUES(?,?,?,?,1,?)',
        [$kid, $purpose, base64_encode($k['public_raw']), encrypt_str($k['private_pem']), time()]);
    return db_one('SELECT * FROM server_keys WHERE kid = ?', [$kid]);
}

function server_key_active(string $purpose): array
{
    $row = db_one('SELECT * FROM server_keys WHERE purpose = ? AND active = 1', [$purpose]);
    return $row ?: server_key_create($purpose);
}

// ---------------------------------------------------------------------------
// Envelope: open a request, seal a response
// ---------------------------------------------------------------------------

/**
 * Decrypts and integrity-checks a request. Does NOT verify the agent
 * signature (the caller must look up the agent named inside the plaintext
 * first) — see ipf_verify_agent_sig(). Returns [payload, ctx].
 */
function ipf_open_request(string $body): array
{
    if (strlen($body) > IPF_MAX_BODY) {
        throw new WireError('too_large', 'request too large');
    }
    $env = json_decode($body, true);
    if (!is_array($env) || ($env['v'] ?? null) !== 1) {
        throw new WireError('bad_envelope', 'not an IPF1 envelope');
    }
    $kid = (string)($env['kid'] ?? '');
    $keyRow = $kid !== '' ? db_one("SELECT * FROM server_keys WHERE kid = ? AND purpose = 'kex'", [$kid]) : null;
    if (!$keyRow) {
        throw new WireError('unknown_server_key', 'request is encrypted to a server key this server does not have');
    }
    $epk = b64d($env['epk'] ?? null, 65, 'epk');
    $iv  = b64d($env['iv'] ?? null, 16, 'iv');
    $ct  = b64d($env['ct'] ?? null, 0, 'ct');
    $mac = b64d($env['mac'] ?? null, 32, 'mac');
    $sig = isset($env['sig']) ? b64d($env['sig'], 64, 'sig') : null;

    $peer = p256_public_from_raw($epk);
    $priv = openssl_pkey_get_private(decrypt_str($keyRow['private_enc']));
    $z = openssl_pkey_derive($peer, $priv, 32);
    if ($z === false || strlen($z) !== 32) {
        throw new WireError('bad_key', 'key agreement failed');
    }
    $keys = ipf_derive_keys($z, $epk);
    $ctx = ['keys' => $keys, 'epk' => $epk, 'kid' => $kid, 'key_row' => $keyRow];

    $expect = hash_hmac('sha256', 'IPF1|req|' . $kid . $epk . $iv . $ct, $keys['req_mac'], true);
    if (!hash_equals($expect, $mac)) {
        throw new WireError('bad_mac', 'request integrity check failed');
    }
    $plain = json_decode(aes_cbc_decrypt($keys['req_enc'], $iv, $ct), true);
    if (!is_array($plain)) {
        throw new WireError('bad_envelope', 'payload is not JSON');
    }
    $ctx['signed_data'] = 'IPF1|sig|' . $kid . $epk . $iv . $ct . $mac;
    $ctx['sig'] = $sig;
    $ctx['nonce'] = (string)($plain['nonce'] ?? '');
    return [$plain, $ctx];
}

function ipf_verify_agent_sig(array $ctx, string $publicRawB64): bool
{
    if ($ctx['sig'] === null || $publicRawB64 === '') {
        return false;
    }
    $raw = base64_decode($publicRawB64, true);
    return $raw !== false && ecdsa_verify_p1363($raw, $ctx['signed_data'], $ctx['sig']);
}

/** Freshness + replay. Must run AFTER authentication so strangers can't fill the nonce table. */
function ipf_check_fresh(array $plain): void
{
    $skew = (int)setting('clock_skew_sec');
    $ts = (int)($plain['ts'] ?? 0);
    if (abs(time() - $ts) > $skew) {
        throw new WireError('clock_skew', 'request timestamp outside the accepted window');
    }
    $nonce = (string)($plain['nonce'] ?? '');
    if (!preg_match('/^[a-f0-9]{32,64}$/', $nonce)) {
        throw new WireError('bad_envelope', 'missing nonce');
    }
    try {
        db_exec('INSERT INTO seen_nonces(nonce, at) VALUES(?, ?)', [$nonce, time()]);
    } catch (PDOException $e) {
        throw new WireError('replay', 'this request was already processed');
    }
}

function ipf_seal_response(array $ctx, array $payload): string
{
    $payload['req_nonce'] = $ctx['nonce'];
    $payload['server_ts'] = time();
    [$iv, $ct] = aes_cbc_encrypt($ctx['keys']['resp_enc'], json_encode($payload, JSON_UNESCAPED_SLASHES));
    $mac = hash_hmac('sha256', 'IPF1|resp|' . $ctx['epk'] . $iv . $ct, $ctx['keys']['resp_mac'], true);
    return json_encode(['v' => 1, 'iv' => base64_encode($iv), 'ct' => base64_encode($ct), 'mac' => base64_encode($mac)]);
}
