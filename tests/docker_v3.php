<?php
declare(strict_types=1);
putenv('DATA_DIR=' . $argv[2]); putenv('DYNALLOW_APP_DIR=' . $argv[1]);
define('DYNALLOW_AGENT_TEST', true);
require $argv[1] . '/agent.php';
function ok(bool $v,string $label):void { if (!$v) throw new RuntimeException('FAIL: '.$label); echo "PASS: $label\n"; }
function rejects(callable $f,string $label):void { try {$f();}catch(Throwable $e){echo "PASS: $label\n";return;}throw new RuntimeException('FAIL accepted: '.$label); }
@mkdir($DATA,0700,true);
$k=key_record(); key_verify_pair($k); keys_save(['active'=>$k]);
ok(keys_load()['active']['public']===$k['public'],'Docker persisted identity pair');
logline('ERROR','offline issue token=secret https://example.test/credential');
$q=jread("$DATA/log-spool.json");ok(count($q)===1 && !str_contains($q[0]['message'],'token=secret'),'Docker durable redacted log spool');
file_put_contents("$DATA/broken.json",'{broken'); rejects(fn()=>jread("$DATA/broken.json"),'Docker corrupt state fails closed');
for($i=0;$i<505;$i++){ob_start();logline('INFO','spool test');ob_end_clean();}
$q=jread("$DATA/log-spool.json");ok(count($q)<=500 && $q[0]['level']==='warn','Docker spool bounded with loss indication');
$profile=['format'=>'dynallow-provisioning','control_url'=>'http://localhost','server_key_id'=>'key','server_key'=>$k['public'],'enroll_token'=>'one-time','agent_uid'=>'agt_testsite01','site_name'=>'test'];
jwrite("$DATA/provisioning.json",$profile);$state=consume_profile(null);
ok(!file_exists("$DATA/provisioning.json") && jread("$DATA/state.json")['enroll_token']==='one-time','Docker profile committed before credential deletion');
unlink("$DATA/agent-key.json"); $state['enrolled']=true;
rejects(function() use (&$state) { run_cycle($state); }, 'Docker missing enrolled identity fails closed');
echo "Docker helper tests complete\n";
