<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_login();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');
    if ($action === 'password') {
        if (!password_verify((string)$_POST['current'], $me['pass_hash'])) flash('error', 'Current password is wrong.');
        elseif (strlen((string)$_POST['new']) < 12) flash('error', 'New password must be at least 12 characters.');
        elseif ($_POST['new'] !== $_POST['again']) flash('error', 'The two new passwords don\'t match.');
        else {
            db_update('users', (int)$me['id'], ['pass_hash' => password_hash((string)$_POST['new'], PASSWORD_DEFAULT)]);
            $_SESSION['pw_fp'] = substr(db_val('SELECT pass_hash FROM users WHERE id = ?', [$me['id']]), -16);
            log_event('Changed own password', 'info');
            flash('ok', 'Password changed. Other sessions are signed out.');
        }
    }
    if ($action === 'email') {
        db_update('users', (int)$me['id'], ['email' => implode('', array_slice(parse_emails((string)$_POST['email']), 0, 1)), 'name' => trim((string)$_POST['name'])]);
        flash('ok', 'Saved.');
    }
    if ($action === 'totp_start') {
        $_SESSION['totp_pending'] = base32_encode(random_bytes(20));
    }
    if ($action === 'totp_confirm' && !empty($_SESSION['totp_pending'])) {
        $secret = base32_decode($_SESSION['totp_pending']);
        if (totp_verify($me, (string)$_POST['code'], $secret)) {
            db_update('users', (int)$me['id'], ['totp_secret_enc' => encrypt_str($secret), 'totp_enabled' => 1]);
            unset($_SESSION['totp_pending']);
            log_event('Enabled two-factor sign-in', 'info');
            flash('ok', 'Two-factor sign-in is on.');
        } else flash('error', 'That code didn\'t match. Check the time on your phone and try the current code.');
    }
    if ($action === 'totp_off') {
        if (setting('require_totp') === '1') flash('error', 'This server requires 2FA; it can\'t be turned off.');
        elseif (totp_verify($me, (string)$_POST['code'])) {
            db_update('users', (int)$me['id'], ['totp_secret_enc' => null, 'totp_enabled' => 0]);
            log_event('Turned off two-factor sign-in', 'warn');
            flash('ok', 'Two-factor sign-in is off.');
        } else flash('error', 'Enter a current code to turn 2FA off.');
    }
    redirect('account.php');
}

page_header('My account', 'account');
echo '<h1>My account</h1><div class="grid">';
echo '<div class="card"><h2>Profile</h2><form method="post">' . csrf_field() . '<input type="hidden" name="action" value="email">'
    . field('Name', input('name', $me['name'])) . field('Email', input('email', $me['email'], 'email'), 'Pre-filled as an alert recipient on sites you create.')
    . '<button class="primary">Save</button></form></div>';
echo '<div class="card"><h2>Password</h2><form method="post">' . csrf_field() . '<input type="hidden" name="action" value="password">'
    . field('Current password', input('current', '', 'password', ['autocomplete' => 'current-password', 'required' => true]))
    . field('New password', input('new', '', 'password', ['autocomplete' => 'new-password', 'minlength' => '12', 'required' => true]))
    . field('New password again', input('again', '', 'password', ['autocomplete' => 'new-password', 'required' => true]))
    . '<button class="primary">Change password</button></form></div>';
echo '<div class="card"><h2>Two-factor sign-in</h2>';
if ($me['totp_enabled']) {
    echo '<p>' . badge('good', 'On') . ' Sign-in asks for a code from your authenticator app.</p>';
    if (setting('require_totp') !== '1') {
        echo '<form method="post" class="row">' . csrf_field() . '<input type="hidden" name="action" value="totp_off">'
            . input('code', '', 'text', ['inputmode' => 'numeric', 'placeholder' => 'current code', 'autocomplete' => 'one-time-code']) . '<button>Turn off</button></form>';
    }
} elseif (!empty($_SESSION['totp_pending'])) {
    $issuer = rawurlencode('IP Failover');
    $uri = 'otpauth://totp/' . $issuer . ':' . rawurlencode($me['username']) . '?secret=' . $_SESSION['totp_pending'] . '&issuer=' . $issuer;
    echo '<ol class="howto"><li>In Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden etc., add an account and choose <b>enter a setup key</b>.</li>'
        . '<li>Account: <b>IP Failover (' . h($me['username']) . ')</b> · Key:</li></ol><div class="secret" id="totpkey">' . h(trim(chunk_split($_SESSION['totp_pending'], 4, ' '))) . '</div>'
        . '<button type="button" class="small mt" data-copy="totpkey">Copy key</button><details class="mt"><summary class="small">Setup link</summary><div class="secret small">' . h($uri) . '</div></details>'
        . '<form method="post" class="row mt">' . csrf_field() . '<input type="hidden" name="action" value="totp_confirm">'
        . input('code', '', 'text', ['inputmode' => 'numeric', 'placeholder' => '6-digit code', 'autocomplete' => 'one-time-code', 'required' => true]) . '<button class="primary">Confirm</button></form>';
} else {
    echo '<p>' . badge('muted', 'Off') . ' Add a code from your phone to every sign-in.</p>' . action_button('totp_start', 'Set up two-factor', [], 'primary');
}
echo '</div></div>';
page_footer();
