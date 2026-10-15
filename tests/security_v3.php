<?php
declare(strict_types=1);
// Run only against the disposable copy created by run_v3.py.
require $argv[1] . '/src/bootstrap.php';
function ok(bool $value, string $label): void { if (!$value) throw new RuntimeException('FAIL: ' . $label); echo "PASS: $label\n"; }
function rejects(callable $fn, string $label): void { try { $fn(); } catch (Throwable $e) { echo "PASS: $label\n"; return; } throw new RuntimeException('FAIL accepted: ' . $label); }
function request_for(array $plain, array $identity): array {
    $server = server_key_active('kex'); $e = p256_generate();
    $z = openssl_pkey_derive(p256_public_from_raw(base64_decode($server['public_key'])), openssl_pkey_get_private($e['private_pem']), 32);
    $keys = ipf_derive_keys($z, $e['public_raw']);
    $plain += ['ts' => time(), 'nonce' => bin2hex(random_bytes(16))];
    [$iv, $ct] = aes_cbc_encrypt($keys['req_enc'], json_encode($plain));
    $mac = hash_hmac('sha256', 'IPF1|req|' . $server['kid'] . $e['public_raw'] . $iv . $ct, $keys['req_mac'], true);
    $sig = ecdsa_sign_p1363($identity['private_pem'], 'IPF1|sig|' . $server['kid'] . $e['public_raw'] . $iv . $ct . $mac);
    $body = json_encode(['v' => 1, 'kid' => $server['kid'], 'epk' => base64_encode($e['public_raw']), 'iv' => base64_encode($iv), 'ct' => base64_encode($ct), 'mac' => base64_encode($mac), 'sig' => base64_encode($sig)]);
    [$p, $ctx] = ipf_open_request($body); return [$p, $ctx];
}
function dispatch(array $plain, array $key): array { [$p, $ctx] = request_for($plain, $key); return api_dispatch($p, $ctx); }
$_SERVER['REMOTE_ADDR'] = '8.8.8.8';
setting_set('public_url', 'http://127.0.0.1:8088'); setting_set('notify_ip_change', '0');
db_exec('INSERT INTO agents(uid,name,platform,created_at) VALUES(?,?,?,?)', ['agt_testsite01', 'Test site', 'windows', time()]);
$a = agent_get((int)db()->lastInsertId());
ok((int)$a['prevent_sleep'] === 0, 'sleep prevention defaults off');
$profile = agent_issue_profile($a, 'test', 1); $key = p256_generate();
$base = ['agent' => $a['uid'], 'observed_ipv4' => '8.8.8.8', 'platform' => 'windows', 'version' => '3.0.0', 'release_target' => 'windows-x64', 'release_sequence' => 1, 'key_protector' => 'dpapi', 'machine_id' => 'test-device'];
$enroll = $base + ['type' => 'enroll', 'enroll_token' => $profile['enroll_token'], 'public_key' => base64_encode($key['public_raw'])];
ok(dispatch($enroll, $key)['ok'], 'signed enrollment');
ok(dispatch($enroll, $key)['ok'], 'lost enrollment response can be retried with same identity');
$other = p256_generate(); $bad = $enroll; $bad['public_key'] = base64_encode($other['public_raw']);
rejects(fn() => dispatch($bad, $other), 'consumed token cannot enroll a different identity');
[$p, $ctx] = request_for($base + ['type' => 'checkin'], $key);
ok(api_dispatch($p, $ctx)['ok'], 'signed checkin');
rejects(fn() => api_dispatch($p, $ctx), 'replayed request rejected');
rejects(fn() => dispatch($base + ['type' => 'checkin'], $other), 'forged identity rejected');
$log = ['id' => bin2hex(random_bytes(16)), 'at' => time()-500, 'level' => 'error', 'message' => '<script>alert(1)</script> token=credential https://example.com/?secret=foo'];
$r = dispatch($base + ['type' => 'checkin', 'logs' => [$log]], $key);
ok($r['log_ack'] === [$log['id']], 'authenticated logs acknowledged');
$r = dispatch($base + ['type' => 'checkin', 'logs' => [$log]], $key);
ok((int)db_val('SELECT COUNT(*) FROM diagnostics WHERE entry_id = ?', [$log['id']]) === 1, 'log retry deduplicated');
$text = db_val('SELECT message FROM diagnostics WHERE entry_id = ?', [$log['id']]);
ok(!str_contains($text, 'credential') && !str_contains($text, 'secret=foo'), 'diagnostic credential redaction');
rejects(fn() => dispatch($base + ['type' => 'checkin', 'logs' => array_fill(0,21,$log)], $key), 'log batch bounded');
db_update('agents', (int)$a['id'], ['prevent_sleep' => 1]);
ok(dispatch($base + ['type' => 'checkin'], $key)['prevent_sleep'] === true, 'sleep policy delivered in authenticated response');
$pending = p256_generate(); $raw = base64_encode($pending['public_raw']);
$nonce = bin2hex(random_bytes(16));
$rotate = ['type' => 'rotate', 'agent' => $a['uid'], 'new_public_key' => $raw, 'new_key_proof' => base64_encode(ecdsa_sign_p1363($pending['private_pem'], 'IPF1|rotate|' . $a['uid'] . '|' . $nonce . '|' . $raw)), 'nonce' => $nonce, 'key_protector' => 'dpapi'];
ok(dispatch($rotate, $key)['ok'], 'rotation registered');
rejects(fn() => dispatch($base + ['type' => 'checkin', 'ts' => time()-10000], $pending), 'stale pending-key request rejected before promotion');
ok(agent_get((int)$a['id'])['pubkey'] === base64_encode($key['public_raw']), 'stale request did not change identity');
$r = dispatch($base + ['type' => 'checkin'], $pending);
ok($r['key_promoted'] && $r['active_key_id'] === p256_fingerprint($pending['public_raw']), 'pending key promoted');
$r = dispatch($base + ['type' => 'checkin'], $pending);
ok($r['active_key_id'] === p256_fingerprint($pending['public_raw']), 'lost promotion response recoverable using active key id');
rejects(fn() => dispatch($base + ['type' => 'checkin'], $key), 'retired identity rejected');
$key = $pending;
ok(!ip_in_cidr('8.8.8.8', '0.0.0.0/999') && !ip_in_cidr('8.8.8.8','0.0.0.0/-1'), 'invalid CIDR masks rejected');
$d = agent_decide_ip(agent_get((int)$a['id']), '8.8.8.8', '8.8.8.8', '2606:4700:4700::1111');
ok($d['v6'] === null, 'uncorroborated IPv6 excluded from feeds');
$signing = p256_generate(); $pem = openssl_pkey_get_details(openssl_pkey_get_private($signing['private_pem']))['key'];
file_put_contents($argv[1] . '/release-public.pem', $pem);
$code = 'MZ test executable';
$m = ['format'=>'dynallow-release-v1', 'target'=>'windows-x64','version'=>'3.0.1','sequence'=>2, 'files'=>[['name'=>'DynAllow.Agent.exe','size'=>strlen($code),'sha256'=>hash('sha256',$code)]]];
function bundle(array $m,string $code,array $key): string { $raw=json_encode($m); openssl_sign($raw,$sig,$key['private_pem'],OPENSSL_ALGO_SHA256); return json_encode(['manifest'=>base64_encode($raw),'signature'=>base64_encode($sig),'files'=>[$m['files'][0]['name']=>base64_encode($code)]]); }
$bundle = bundle($m,$code,$signing);
ok(verify_release_bundle($bundle,$pem)['sequence']===2,'server verifies offline release signature');
rejects(fn()=>verify_release_bundle($bundle,openssl_pkey_get_details(openssl_pkey_get_private($other['private_pem']))['key']),'wrong release public key rejected');
$t = json_decode($bundle,true); $t['files']['DynAllow.Agent.exe']=base64_encode('tamper');
rejects(fn()=>verify_release_bundle(json_encode($t),$pem),'release payload tampering rejected');
$t=$m; $t['files'][0]['name']='../agent.exe';
rejects(fn()=>verify_release_bundle(bundle($t,$code,$signing),$pem),'signed path traversal rejected');
$r=release_store($bundle,'test'); db_update('releases',(int)$r['id'],['active'=>1]);
ok(release_offer(agent_get((int)$a['id']))['sequence']===2,'matching agent offered activated release');
db_update('agents',(int)$a['id'],['release_sequence'=>2]);
ok(release_offer(agent_get((int)$a['id']))===null,'server suppresses downgrade/replay');
db_update('agents',(int)$a['id'],['release_sequence'=>1,'release_target'=>'windows-arm64']);
ok(release_offer(agent_get((int)$a['id']))===null,'server target isolation');
ok(release_offer(array_replace($a, ['release_target'=>'', 'update_release_id'=>null]))===null, 'agents without release capability receive no executable update');
server_diagnostic('error','Test server diagnostic');
ok((int)db_val("SELECT COUNT(*) FROM diagnostics WHERE source='server' AND message='Test server diagnostic'")===1,'server diagnostics persist for web UI');
// Fixture for web authorization / XSS / feed-scope tests.
setting_set('allow_http_feed','1');
db_exec('INSERT INTO feed_tokens(name,token_hash,tag_filter,created_at) VALUES(?,?,?,?)',['restricted',token_hash('test-restricted-token'),'customer-a',time()]);
file_put_contents($argv[1].'/test-agent-id',(string)$a['id']);
db_update('agents',(int)$a['id'],['decommission'=>1]);
ok(dispatch($base+['type'=>'checkin'],$key)['decommission'],'decommission command delivered');
ok(dispatch(['type'=>'decommission_ack','agent'=>$a['uid']],$key)['ok'],'decommission acknowledgement accepted');
ok(agent_get((int)$a['id'])['pubkey']===null,'decommission revokes registered identity');
if (!empty($argv[2])) {
    $dir=$argv[2]; $e=json_decode(file_get_contents("$dir/csharp-request.json"),true);
    $epk=base64_decode($e['epk']); $z=openssl_pkey_derive(p256_public_from_raw($epk),openssl_pkey_get_private(file_get_contents("$dir/server-private.pem")),32);
    $keys=ipf_derive_keys($z,$epk); $iv=base64_decode($e['iv']); $ct=base64_decode($e['ct']); $mac=base64_decode($e['mac']);
    ok(hash_equals($mac,hash_hmac('sha256','IPF1|req|'.$e['kid'].$epk.$iv.$ct,$keys['req_mac'],true)),'C# -> PHP wire MAC interoperability');
    $data='IPF1|sig|'.$e['kid'].$epk.$iv.$ct.$mac;
    ok(openssl_verify($data,ecdsa_p1363_to_der(base64_decode($e['sig'])),file_get_contents("$dir/agent-public.pem"),OPENSSL_ALGO_SHA256)===1,'C# -> PHP identity signature interoperability');
    ok(json_decode(aes_cbc_decrypt($keys['req_enc'],$iv,$ct),true)['type']==='checkin','C# -> PHP payload interoperability');
    ok(verify_release_bundle(file_get_contents("$dir/csharp-release.json"),file_get_contents("$dir/release-public.pem"))['sequence']===2,'C# -> PHP release signature interoperability');
}
echo "Server security tests complete\n";
