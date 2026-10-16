<?php
declare(strict_types=1);
require $argv[1].'/src/bootstrap.php';
$base=$argv[2];$data=$argv[3];$app=$argv[4];
setting_set('public_url',$base);setting_set('ip_check_urls',$base.'/test-ip.php');
file_put_contents($argv[1].'/public/test-ip.php','<?php echo "8.8.8.8";');
db_exec('INSERT INTO agents(uid,name,platform,trust_mode,created_at) VALUES(?,?,?,?,?)',['agt_dockerhttp1','Docker HTTP test','docker','agent',time()]);
$a=agent_get((int)db()->lastInsertId());
$p=agent_issue_profile($a,'test',1);file_put_contents($data.'/provisioning.json',json_encode($p));
file_put_contents($data.'/test-agent-id',(string)$a['id']);
$dev = ($argv[5] ?? '') === 'development';
if ($dev) {
    @unlink($argv[1].'/release-public.pem'); @unlink($app.'/release-public.pem');
    file_put_contents($app.'/update-policy.json', json_encode(['allow_dev_releases'=>true]));
} else {
    $key=p256_generate();$pem=openssl_pkey_get_details(openssl_pkey_get_private($key['private_pem']))['key'];
    file_put_contents($argv[1].'/release-public.pem',$pem);file_put_contents($app.'/release-public.pem',$pem);
}
$code=file_get_contents($app.'/agent.php');
$code=str_replace("const AGENT_VERSION = '3.0.0';","const AGENT_VERSION = '3.0.1';",$code);
$code=str_replace('const RELEASE_SEQUENCE = 1;','const RELEASE_SEQUENCE = 2;',$code);
$m=['format'=>$dev ? 'dynallow-dev-release-v1' : 'dynallow-release-v1','target'=>'docker','version'=>'3.0.1','sequence'=>2,'files'=>[['name'=>'agent.php','size'=>strlen($code),'sha256'=>hash('sha256',$code)]]];
$raw=json_encode($m);$sig='';if (!$dev) openssl_sign($raw,$sig,$key['private_pem'],OPENSSL_ALGO_SHA256);
$bundle=json_encode(['manifest'=>base64_encode($raw),'signature'=>base64_encode($sig),'files'=>['agent.php'=>base64_encode($code)]]);
$r=release_store($bundle,'test');db_update('agents',(int)$a['id'],['update_release_id'=>$r['id']]);
