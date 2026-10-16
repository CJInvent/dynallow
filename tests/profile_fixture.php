<?php
// Mints a real provisioning profile with the server's own code, for the Windows
// agent's contract test (run_v3.py passes it to `DynAllow.Agent self-test`).
declare(strict_types=1);
require $argv[1] . '/src/bootstrap.php';
setting_set('public_url', 'https://dynallow.example.test');
db_exec('INSERT INTO agents(uid,name,platform,trust_mode,created_at) VALUES(?,?,?,?,?)', ['agt_contract01', 'Contract test', 'windows', 'agree', time()]);
$p = agent_issue_profile(agent_get((int)db()->lastInsertId()), 'test', 1);
file_put_contents($argv[2], json_encode($p, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
