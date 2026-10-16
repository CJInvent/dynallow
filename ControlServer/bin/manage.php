<?php
declare(strict_types=1);

/**
 * Command-line administration. Run as the web server user, e.g.:
 *   sudo -u www-data php bin/manage.php init
 *
 * Commands:
 *   init                       create data/, encryption key, database, server keys, first admin
 *   create-user <name> [admin|tech]
 *   reset-password <name>
 *   reset-2fa <name>
 *   rotate-server-key          new agent-facing key; agents re-pin automatically
 *   backup <file>              passphrase-encrypted backup of database + encryption key
 *   restore <file> [--force]
 *   status
 *
 * Passwords/passphrases are prompted (hidden). For automation, set
 * DYNALLOW_PASSWORD / DYNALLOW_PASSPHRASE in the environment instead.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require dirname(__DIR__) . '/src/bootstrap.php';

function out(string $s): void { fwrite(STDOUT, $s . PHP_EOL); }
function fail(string $s): void { fwrite(STDERR, 'ERROR: ' . $s . PHP_EOL); exit(1); }

function prompt(string $label, bool $hidden = false): string
{
    fwrite(STDOUT, $label);
    if ($hidden && DIRECTORY_SEPARATOR === '/' && stream_isatty(STDIN)) {
        shell_exec('stty -echo');
        $v = fgets(STDIN);
        shell_exec('stty echo');
        fwrite(STDOUT, PHP_EOL);
    } else {
        $v = fgets(STDIN);
    }
    return trim((string)$v);
}

function secret_input(string $env, string $label, int $min): string
{
    $v = getenv($env);
    if ($v === false || $v === '') {
        $v = prompt($label, true);
        $again = prompt('Repeat: ', true);
        if ($v !== $again) fail('the two entries do not match');
    }
    if (strlen($v) < $min) fail("must be at least $min characters");
    return $v;
}

function create_user(string $username, string $role): void
{
    if (!preg_match('/^[A-Za-z0-9._@-]{2,64}$/', $username)) fail('username: 2-64 of letters, digits, . _ @ -');
    if (!in_array($role, ['admin', 'tech'], true)) fail('role must be admin or tech');
    if (db_one('SELECT id FROM users WHERE username = ?', [$username])) fail("user $username already exists");
    $pass = secret_input('DYNALLOW_PASSWORD', "Password for $username (12+ chars): ", 12);
    db_exec('INSERT INTO users(username, name, pass_hash, role, created_at) VALUES(?,?,?,?,?)',
        [$username, $username, password_hash($pass, PASSWORD_DEFAULT), $role, time()]);
    log_event("User $username created ($role) from the command line", 'info', null, 'cli');
    out("Created $role user $username.");
}

$cmd = $argv[1] ?? 'help';
$dataDir = app_config('data_dir');

switch ($cmd) {
    case 'init':
        if (!is_dir($dataDir) && !mkdir($dataDir, 0750, true)) fail("cannot create $dataDir");
        @chmod($dataDir, 0750);
        $keyFile = "$dataDir/secret.key";
        if (!is_file($keyFile)) {
            file_put_contents($keyFile, sodium_bin2hex(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)) . "\n");
            chmod($keyFile, 0600);
            out("Generated encryption key: $keyFile  (BACK THIS UP with the database — see 'backup')");
        } else {
            out("Encryption key already exists: $keyFile");
        }
        db(); // creates + migrates
        $kex = server_key_active('kex');
        server_key_active('sign');
        out('Server agent key: ' . $kex['kid'] . ' (pinned into every provisioning profile)');
        if ((int)db_val('SELECT COUNT(*) FROM users') === 0) {
            $u = getenv('DYNALLOW_ADMIN') ?: prompt('First admin username: ');
            create_user($u, 'admin');
        }
        out('Database ready: ' . $dataDir . '/dynallow.sqlite');
        out('Next: point Apache at public/, add the cron line (deploy/dynallow.cron), log in, set Settings → General → Public URL.');
        break;

    case 'create-user':
        if (empty($argv[2])) fail('usage: create-user <name> [admin|tech]');
        create_user($argv[2], $argv[3] ?? 'tech');
        break;

    case 'reset-password':
        $u = db_one('SELECT * FROM users WHERE username = ?', [$argv[2] ?? '']) ?? fail('no such user');
        $pass = secret_input('DYNALLOW_PASSWORD', 'New password (12+ chars): ', 12);
        db_update('users', (int)$u['id'], ['pass_hash' => password_hash($pass, PASSWORD_DEFAULT)]);
        log_event("Password reset for {$u['username']} from the command line", 'warn', null, 'cli');
        out('Password updated.');
        break;

    case 'reset-2fa':
        $u = db_one('SELECT * FROM users WHERE username = ?', [$argv[2] ?? '']) ?? fail('no such user');
        db_update('users', (int)$u['id'], ['totp_secret_enc' => null, 'totp_enabled' => 0, 'totp_last_step' => 0]);
        log_event("2FA reset for {$u['username']} from the command line", 'warn', null, 'cli');
        out('2FA removed; the user will be asked to set it up again if it is required.');
        break;

    case 'rotate-server-key':
        $old = server_key_active('kex');
        $new = server_key_create('kex');
        log_event("Server agent key rotated {$old['kid']} → {$new['kid']}", 'warn', null, 'cli');
        out("New server key {$new['kid']}. The old key {$old['kid']} keeps working; each agent is handed the new key at its next check-in.");
        out('New provisioning profiles pin the new key automatically.');
        break;

    case 'backup':
        $file = $argv[2] ?? fail('usage: backup <file>');
        $pass = secret_input('DYNALLOW_PASSPHRASE', 'Backup passphrase (16+ chars, store it somewhere safe): ', 16);
        $tmp = tempnam(sys_get_temp_dir(), 'dyndb');
        unlink($tmp);
        db()->exec('VACUUM INTO ' . db()->quote($tmp));
        $payload = json_encode(['secret_key' => trim((string)file_get_contents("$dataDir/secret.key")), 'db' => base64_encode((string)file_get_contents($tmp))]);
        unlink($tmp);
        // Cleartext header so the file is identifiable years later, bound in as
        // AEAD additional data so relabelling it breaks decryption.
        $header = json_encode(['kind' => 'dynallow-server-backup', 'app_version' => APP_VERSION, 'created_at' => gmdate('c'), 'host' => gethostname()]);
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $key = sodium_crypto_pwhash(32, $pass, $salt, SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($payload, $header, $nonce, $key);
        file_put_contents($file, 'DYNBAK01' . pack('N', strlen($header)) . $header . $salt . $nonce . $ct);
        chmod($file, 0600);
        log_event('Encrypted server backup written by CLI', 'info', null, 'cli');
        out("Backup written: $file (" . round(filesize($file) / 1024) . ' KB). Keep the passphrase separately.');
        break;

    case 'restore':
        $file = $argv[2] ?? fail('usage: restore <file> [--force]');
        $raw = (string)@file_get_contents($file);
        // IPFBAK01 = the same format, written before the rename.
        if (!in_array(substr($raw, 0, 8), ['DYNBAK01', 'IPFBAK01'], true)) fail('not a DynAllow backup file');
        $hlen = unpack('N', substr($raw, 8, 4))[1];
        $header = substr($raw, 12, $hlen);
        $off = 12 + $hlen;
        $salt = substr($raw, $off, SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $off += SODIUM_CRYPTO_PWHASH_SALTBYTES;
        $nonce = substr($raw, $off, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ct = substr($raw, $off + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        out('Backup: ' . $header);
        if ((is_file("$dataDir/dynallow.sqlite") || is_file("$dataDir/secret.key")) && !in_array('--force', $argv, true)) {
            fail('data/ already has a database or key; re-run with --force to overwrite');
        }
        $pass = getenv('DYNALLOW_PASSPHRASE') ?: prompt('Backup passphrase: ', true);
        $key = sodium_crypto_pwhash(32, $pass, $salt, SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $header, $nonce, $key);
        if ($plain === false) fail('wrong passphrase, or the file was altered');
        $p = json_decode($plain, true);
        if (!is_dir($dataDir)) mkdir($dataDir, 0750, true);
        foreach (['-wal', '-shm', ''] as $sfx) @unlink("$dataDir/dynallow.sqlite$sfx");
        file_put_contents("$dataDir/secret.key", $p['secret_key'] . "\n");
        chmod("$dataDir/secret.key", 0600);
        file_put_contents("$dataDir/dynallow.sqlite", base64_decode($p['db']));
        out('Restored. Fix ownership if needed: chown -R www-data:www-data ' . $dataDir);
        break;

    case 'status':
        out('Agents: ' . db_val('SELECT COUNT(*) FROM agents') . ', users: ' . db_val('SELECT COUNT(*) FROM users')
            . ', DNS accounts: ' . db_val('SELECT COUNT(*) FROM dns_accounts'));
        $last = (int)setting('cron_last_run');
        out('Cron last ran: ' . ($last ? fmt_ago($last) : 'NEVER — alerts and DNS retries will not happen'));
        out('Server agent key: ' . server_key_active('kex')['kid']);
        break;

    default:
        out(trim(substr((string)file_get_contents(__FILE__), strpos((string)file_get_contents(__FILE__), 'Commands:'), 700), " \n*/"));
}
