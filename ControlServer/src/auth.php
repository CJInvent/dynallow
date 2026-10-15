<?php
declare(strict_types=1);

/**
 * Sessions, login (with optional TOTP 2FA), roles, CSRF.
 *
 * Roles:  admin — everything.
 *         tech  — dashboard, survey, agent pages, issue profiles, push/edit
 *                 agents. Cannot delete/decommission, see settings, manage
 *                 users, DNS accounts or feeds. Denied controls are not
 *                 rendered at all, and every handler re-checks the role.
 */

function session_boot(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    session_name('ipfsid');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => is_https() || (bool)app_config('secure_cookies'),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.save_path', app_config('data_dir') . '/sessions');
    if (!is_dir(app_config('data_dir') . '/sessions')) {
        @mkdir(app_config('data_dir') . '/sessions', 0700);
    }
    session_start();
    // Idle timeout: 8 hours.
    if (isset($_SESSION['seen']) && time() - $_SESSION['seen'] > 8 * 3600) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    $_SESSION['seen'] = time();
}

function current_user(): ?array
{
    static $user = false;
    if ($user !== false) {
        return $user;
    }
    $user = null;
    if (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['uid']) && empty($_SESSION['need_2fa'])) {
        $u = db_one('SELECT * FROM users WHERE id = ? AND disabled = 0', [$_SESSION['uid']]);
        if ($u && hash_equals((string)($_SESSION['pw_fp'] ?? ''), substr($u['pass_hash'], -16))) {
            $user = $u; // a password change elsewhere ends this session
        }
    }
    return $user;
}

function require_login(): array
{
    session_boot();
    $u = current_user();
    if (!$u) {
        $next = $_SERVER['REQUEST_METHOD'] === 'GET' ? ($_SERVER['REQUEST_URI'] ?? '/') : '/';
        header('Location: login.php?next=' . rawurlencode($next));
        exit;
    }
    // Forced 2FA enrollment confines the user to their account page.
    if (setting('require_totp') === '1' && !$u['totp_enabled'] && basename($_SERVER['SCRIPT_NAME']) !== 'account.php') {
        flash('warn', 'Two-factor authentication is required on this server. Set it up to continue.');
        header('Location: account.php');
        exit;
    }
    return $u;
}

function require_admin(): array
{
    $u = require_login();
    if ($u['role'] !== 'admin') {
        http_response_code(403);
        page_header('Not allowed');
        echo '<div class="card"><h2>Admins only</h2><p>Your account (' . h($u['role']) . ') can\'t open this page.</p></div>';
        page_footer();
        exit;
    }
    return $u;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = random_token(16);
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">';
}

/** Every POST handler calls this first. */
function csrf_check(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('Form expired or invalid (CSRF). Go back, reload the page and try again.');
    }
}

function safe_next(string $next): string
{
    // Same-site relative paths only: no scheme, no //host, no backslashes, no control chars.
    if ($next === '' || $next[0] !== '/' || preg_match('#^//|\\\\|[\x00-\x1f]#', $next)) {
        return 'index.php';
    }
    return ltrim($next, '/') ?: 'index.php';
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/** @return string|null error message, or null on success (2FA may still be pending) */
function login_attempt(string $username, string $password): ?string
{
    $bucket = 'login:' . client_ip();
    if (rate_limited($bucket, 8, 900)) {
        return 'Too many failed attempts from your address. Wait 15 minutes.';
    }
    $u = db_one('SELECT * FROM users WHERE username = ?', [$username]);
    // Unknown user: still pay for a real hash so timing doesn't reveal which usernames exist.
    $hash = $u['pass_hash'] ?? password_hash(random_token(8), PASSWORD_DEFAULT);
    if (!password_verify($password, $hash) || !$u || $u['disabled']) {
        rate_hit($bucket);
        log_event('Failed login for "' . substr($username, 0, 64) . '" from ' . client_ip(), 'warn', null, 'web');
        return 'Wrong username or password.';
    }
    if (password_needs_rehash($u['pass_hash'], PASSWORD_DEFAULT)) {
        db_update('users', (int)$u['id'], ['pass_hash' => password_hash($password, PASSWORD_DEFAULT)]);
        $u = db_one('SELECT * FROM users WHERE id = ?', [$u['id']]);
    }
    session_regenerate_id(true);
    $_SESSION['uid'] = (int)$u['id'];
    $_SESSION['pw_fp'] = substr($u['pass_hash'], -16);
    $_SESSION['need_2fa'] = (bool)$u['totp_enabled'];
    if (!$u['totp_enabled']) {
        login_complete($u);
    }
    return null;
}

function login_complete(array $u): void
{
    unset($_SESSION['need_2fa']);
    session_regenerate_id(true);
    db_update('users', (int)$u['id'], ['last_login_at' => time()]);
    log_event("User {$u['username']} signed in from " . client_ip(), 'info', null, $u['username']);
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238, SHA-1, 6 digits, 30 s) — no library needed
// ---------------------------------------------------------------------------

function base32_encode(string $bin): string
{
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($bin) as $c) {
        $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $out .= $alpha[bindec(str_pad($chunk, 5, '0'))];
    }
    return $out;
}

function base32_decode(string $s): string
{
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $s = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $s));
    $bits = '';
    foreach (str_split($s) as $c) {
        $bits .= str_pad(decbin(strpos($alpha, $c)), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $out .= chr(bindec($byte));
        }
    }
    return $out;
}

function totp_code(string $secret, int $step): string
{
    $h = hash_hmac('sha1', pack('J', $step), $secret, true);
    $o = ord($h[19]) & 0x0f;
    $n = ((ord($h[$o]) & 0x7f) << 24) | (ord($h[$o + 1]) << 16) | (ord($h[$o + 2]) << 8) | ord($h[$o + 3]);
    return str_pad((string)($n % 1000000), 6, '0', STR_PAD_LEFT);
}

/** Accepts ±1 step of drift; each code works once (replay-proof via totp_last_step). */
function totp_verify(array $user, string $code, ?string $secretOverride = null): bool
{
    $code = preg_replace('/\D/', '', $code);
    if (strlen($code) !== 6) {
        return false;
    }
    $secret = $secretOverride ?? decrypt_str((string)$user['totp_secret_enc']);
    $now = intdiv(time(), 30);
    foreach ([0, -1, 1] as $d) {
        $step = $now + $d;
        if ($step > (int)$user['totp_last_step'] && hash_equals(totp_code($secret, $step), $code)) {
            // Atomic consume: parallel requests cannot reuse the same TOTP.
            return db_exec('UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?',
                [$step, $user['id'], $step]) === 1;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Flash messages
// ---------------------------------------------------------------------------

function flash(string $type, string $msg): void
{
    $_SESSION['flash'][] = [$type, $msg];
}

function take_flashes(): array
{
    $f = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $f;
}

function redirect(string $to): void
{
    header('Location: ' . $to);
    exit;
}
