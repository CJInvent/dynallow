<?php
// Release bytes are public software, contain no provisioning or identity secrets.
// Content-addressed URL; clients independently verify pinned offline signature.
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$hash = (string)($_GET['sha256'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/D', $hash) || !db_one('SELECT id FROM releases WHERE sha256 = ?', [$hash])) { http_response_code(404); exit; }
$path = app_config('data_dir') . '/releases/' . $hash . '.json';
if (!is_file($path)) { server_diagnostic('error', 'Published release artifact missing: ' . $hash); http_response_code(503); exit; }
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Content-Length: ' . filesize($path));
header('Cache-Control: public, max-age=31536000, immutable');
readfile($path);
