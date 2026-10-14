<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_admin();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');
    $u = isset($_POST['id']) ? db_one('SELECT * FROM users WHERE id = ?', [(int)$_POST['id']]) : null;
    $admins = (int)db_val("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0");
    $lastAdmin = $u && $u['role'] === 'admin' && !$u['disabled'] && $admins <= 1;

    switch ($action) {
        case 'add':
            $name = trim((string)$_POST['username']);
            $pass = (string)$_POST['password'];
            $role = $_POST['role'] === 'admin' ? 'admin' : 'tech';
            if (!preg_match('/^[A-Za-z0-9._@-]{2,64}$/', $name)) flash('error', 'Username: 2-64 of letters, digits, . _ @ -');
            elseif (db_one('SELECT id FROM users WHERE username = ?', [$name])) flash('error', "$name already exists.");
            elseif (strlen($pass) < 12) flash('error', 'Password must be at least 12 characters.');
            else {
                db_exec('INSERT INTO users(username, name, email, pass_hash, role, created_at) VALUES(?,?,?,?,?,?)',
                    [$name, trim((string)$_POST['name']), implode('', array_slice(parse_emails((string)$_POST['email']), 0, 1)), password_hash($pass, PASSWORD_DEFAULT), $role, time()]);
                log_event("User $name created ($role)", 'info');
                flash('ok', "Created $name. Share the password with them over a separate channel.");
            }
            break;
        case 'role':
            if ($u && !$lastAdmin) {
                $role = $u['role'] === 'admin' ? 'tech' : 'admin';
                db_update('users', (int)$u['id'], ['role' => $role]);
                log_event("User {$u['username']} is now $role", 'warn');
            } elseif ($lastAdmin) flash('error', 'That is the last admin.');
            break;
        case 'toggle':
            if ($u && $u['id'] != $me['id'] && !$lastAdmin) {
                db_update('users', (int)$u['id'], ['disabled' => $u['disabled'] ? 0 : 1]);
                log_event("User {$u['username']} " . ($u['disabled'] ? 'enabled' : 'disabled'), 'warn');
            } else flash('error', 'You can\'t disable yourself or the last admin.');
            break;
        case 'reset_password':
            if ($u && strlen((string)$_POST['password']) >= 12) {
                db_update('users', (int)$u['id'], ['pass_hash' => password_hash((string)$_POST['password'], PASSWORD_DEFAULT)]);
                log_event("Password reset for {$u['username']}", 'warn');
                flash('ok', "Password changed; {$u['username']}'s sessions are signed out.");
            } else flash('error', 'New password must be at least 12 characters.');
            break;
        case 'reset_2fa':
            if ($u) {
                db_update('users', (int)$u['id'], ['totp_secret_enc' => null, 'totp_enabled' => 0, 'totp_last_step' => 0]);
                log_event("2FA reset for {$u['username']}", 'warn');
                flash('ok', "2FA removed for {$u['username']}.");
            }
            break;
        case 'delete':
            if ($u && $u['id'] != $me['id'] && !$lastAdmin) {
                db_exec('DELETE FROM users WHERE id = ?', [$u['id']]);
                log_event("User {$u['username']} deleted", 'warn');
            } else flash('error', 'You can\'t delete yourself or the last admin.');
            break;
    }
    redirect('users.php');
}

page_header('Users', 'users');
echo '<h1>Users</h1><div class="card tablewrap"><table><thead><tr><th>User</th><th>Role</th><th>2FA</th><th>Last sign-in</th><th></th></tr></thead><tbody>';
foreach (db_all('SELECT * FROM users ORDER BY username') as $u) {
    echo '<tr><td><b>' . h($u['username']) . '</b>' . ($u['disabled'] ? ' ' . badge('muted', 'disabled') : '') . '<div class="small dim">' . h($u['name']) . ' ' . h($u['email']) . '</div></td>'
        . '<td>' . h($u['role']) . '</td><td>' . ($u['totp_enabled'] ? badge('good', 'on') : badge('muted', 'off')) . '</td>'
        . '<td class="small">' . h(fmt_ago($u['last_login_at'] ? (int)$u['last_login_at'] : null)) . '</td><td class="nowrap">'
        . action_button('role', $u['role'] === 'admin' ? 'Make tech' : 'Make admin', ['id' => $u['id']], 'small') . ' ';
    if ($u['id'] != $me['id']) {
        echo action_button('toggle', $u['disabled'] ? 'Enable' : 'Disable', ['id' => $u['id']], 'small') . ' ';
        if ($u['totp_enabled']) echo action_button('reset_2fa', 'Reset 2FA', ['id' => $u['id']], 'small', "Remove {$u['username']}'s 2FA? They'll sign in with just a password until they set it up again.") . ' ';
        echo action_button('delete', 'Delete', ['id' => $u['id']], 'small danger', "Delete {$u['username']}?");
        echo '<form method="post" class="inline row mt">' . csrf_field() . '<input type="hidden" name="action" value="reset_password"><input type="hidden" name="id" value="' . (int)$u['id'] . '">'
            . input('password', '', 'password', ['placeholder' => 'new password (12+)', 'autocomplete' => 'new-password', 'minlength' => '12']) . '<button class="small">Set password</button></form>';
    }
    echo '</td></tr>';
}
echo '</tbody></table></div>';
echo '<div class="card"><h2>Add a user</h2><form method="post" autocomplete="off">' . csrf_field() . '<input type="hidden" name="action" value="add"><div class="cols2">'
    . field('Username', input('username', '', 'text', ['required' => true]))
    . field('Role', select('role', ['tech' => 'Technician — create and manage sites', 'admin' => 'Admin — everything'], 'tech'))
    . field('Full name', input('name')) . field('Email', input('email', '', 'email'), 'Pre-filled as an alert recipient when they create sites.')
    . field('Password', input('password', '', 'password', ['required' => true, 'minlength' => '12', 'autocomplete' => 'new-password']), '12 characters or more.')
    . '</div><button class="primary">Add user</button></form></div>';
page_footer();
