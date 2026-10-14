<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
session_boot();

$next = safe_next((string)($_GET['next'] ?? $_POST['next'] ?? '/'));
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    if (!empty($_SESSION['need_2fa']) && isset($_POST['code'])) {
        $u = db_one('SELECT * FROM users WHERE id = ? AND disabled = 0', [$_SESSION['uid'] ?? 0]);
        $bucket = 'totp:' . client_ip();
        if ($u && !rate_limited($bucket, 8, 900) && totp_verify($u, (string)$_POST['code'])) {
            login_complete($u);
            redirect($next);
        }
        rate_hit($bucket);
        $error = 'That code didn\'t work. Use the current 6-digit code from your authenticator app.';
    } else {
        $error = login_attempt(trim((string)($_POST['username'] ?? '')), (string)($_POST['password'] ?? ''));
        if ($error === null && empty($_SESSION['need_2fa'])) {
            redirect($next);
        }
    }
}
if (isset($_GET['cancel'])) {
    $_SESSION = [];
    session_regenerate_id(true);
}
if (current_user()) {
    redirect($next);
}

page_header('Sign in');
echo '<div class="login card"><h1>IP Failover</h1>';
if ($error) {
    echo '<div class="flash error">' . h($error) . '</div>';
}
if (!is_https()) {
    echo '<div class="callout">This sign-in page is on plain HTTP. Your password crosses the network unencrypted.</div>';
}
echo '<form method="post">' . csrf_field() . '<input type="hidden" name="next" value="' . h($next) . '">';
if (!empty($_SESSION['need_2fa'])) {
    echo field('Authenticator code', input('code', '', 'text', ['inputmode' => 'numeric', 'autocomplete' => 'one-time-code', 'pattern' => '[0-9 ]{6,7}', 'required' => true, 'autofocus' => true]));
    echo '<div class="spread"><button class="primary">Verify</button><a href="login.php?cancel=1">Start over</a></div>';
} else {
    echo field('Username', input('username', '', 'text', ['autocomplete' => 'username', 'required' => true, 'autofocus' => true]));
    echo field('Password', input('password', '', 'password', ['autocomplete' => 'current-password', 'required' => true]));
    echo '<button class="primary">Sign in</button>';
}
echo '</form></div>';
page_footer();
