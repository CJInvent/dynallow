<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
session_boot();
csrf_check();
if ($u = current_user()) {
    log_event("User {$u['username']} signed out", 'info', null, $u['username']);
}
$_SESSION = [];
session_regenerate_id(true);
redirect('login.php');
