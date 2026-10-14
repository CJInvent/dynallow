#!/bin/bash
# Fresh copy of the control server wired to the mocks. Usage: setup_srv.sh <dir>
set -e
D=$1
rm -rf $D; cp -r "$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd)/ControlServer" $D 2>/dev/null || cp -r "${IPF_PKG:?set IPF_PKG to the package folder}/ControlServer" $D
python3 - "$D" <<'PY'
import sys,re
d=sys.argv[1]; p=d+'/config.php'; s=open(p).read()
s=s.replace("'trusted_proxies' => [","'trusted_proxies' => ['127.0.0.1', '172.16.0.0/12', '192.0.2.2',")
s=s.replace("'cloudflare_api_base' => null","'cloudflare_api_base' => 'http://127.0.0.1:8099/cf'")
s=s.replace("'duckdns_api_base'    => null","'duckdns_api_base'    => 'http://127.0.0.1:8099'")
open(p,'w').write(s)
PY
cat > $D/public/_router.php <<'PHP'
<?php
// TEST ONLY: stands in for a reverse proxy that reports the client address.
$f = dirname(__DIR__) . '/fake_remote';
if (is_file($f)) { $_SERVER['HTTP_X_FORWARDED_FOR'] = trim(file_get_contents($f)); }
$root = dirname(__DIR__);
if (is_file("$root/capture")) { file_put_contents("$root/captured.bin", file_get_contents('php://input')); }
if (is_file("$root/tamper")) { ob_start(function ($out) { $j = json_decode($out, true); if (isset($j['ct'])) { $b = base64_decode($j['ct']); $b[5] = chr(ord($b[5]) ^ 1); $j['ct'] = base64_encode($b); return json_encode($j); } return $out; }); }
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path !== '/' && is_file(__DIR__ . $path) && substr($path, -4) !== '.php') return false;
$file = __DIR__ . ($path === '/' ? '/index.php' : $path);
if (is_file($file)) { $_SERVER['SCRIPT_NAME'] = $path; $_SERVER['SCRIPT_FILENAME'] = $file; chdir(dirname($file)); require $file; return true; }
http_response_code(404); echo "404 $path";
PHP
cd $D && IPF_ADMIN=admin IPF_PASSWORD='correct-horse-battery' php bin/manage.php init
