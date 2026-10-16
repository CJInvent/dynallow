#!/usr/bin/env python3
"""Regression tests for rename migration, dev trust policy, packaging, and installer preflight."""
import base64, concurrent.futures, importlib.util, json, os, pathlib, shutil, sqlite3, subprocess, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
PHP = os.environ.get('PHP', 'php')
def run(*args, **kw): return subprocess.run(args, check=True, text=True, **kw)
def check(value, label):
    if not value: raise AssertionError(label)
    print('PASS:', label, flush=True)
with tempfile.TemporaryDirectory(prefix='dynallow-review-') as tmp:
    work = pathlib.Path(tmp); server = work/'server'
    shutil.copytree(ROOT/'ControlServer', server, ignore=shutil.ignore_patterns('bin','obj','data'))
    shutil.copytree(ROOT/'ControlServer/bin', server/'bin')
    env = os.environ | {'DYNALLOW_ADMIN':'admin','DYNALLOW_PASSWORD':'test-password-long-enough'}
    run(PHP,str(server/'bin/manage.php'),'init',env=env,stdout=subprocess.DEVNULL)
    data=server/'data'; (data/'dynallow.sqlite').rename(data/'ipfailover.sqlite')
    conn=sqlite3.connect(data/'ipfailover.sqlite');conn.execute('PRAGMA journal_mode=WAL');conn.execute('PRAGMA wal_autocheckpoint=0')
    conn.execute("INSERT INTO settings(key,value) VALUES('wal_probe','durable')");conn.commit()
    probe=work/'probe.php';probe.write_text('<?php require $argv[1]."/src/bootstrap.php"; echo setting("wal_probe");')
    def read(_): return run(PHP,str(probe),str(server),capture_output=True).stdout
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        check(all(v=='durable' for v in pool.map(read,range(8))), 'concurrent startup reads committed legacy WAL data')
    check(not (data/'dynallow.sqlite').exists() and (data/'ipfailover.sqlite-wal').exists(), 'startup never renames SQLite/WAL files')
    conn.close()
    # Ambiguity must never silently select the wrong database.
    (data/'dynallow.sqlite').touch()
    rejected=subprocess.run([PHP,str(probe),str(server)],capture_output=True,text=True)
    check(rejected.returncode!=0 and 'Both database names' in rejected.stderr, 'two database names fail closed with original diagnostic')
    (data/'dynallow.sqlite').unlink()

    spec=importlib.util.spec_from_file_location('devpack',ROOT/'tools/New-DevRelease.py');pack=importlib.util.module_from_spec(spec);spec.loader.exec_module(pack)
    payload=work/'agent.php';payload.write_text("<?php const AGENT_VERSION = '3.0.1'; const RELEASE_SEQUENCE = 2;")
    bundle=pack.make_bundle('docker','3.0.1',2,payload);bundle_path=work/'dev.json';bundle_path.write_bytes(bundle)
    check(json.loads(bundle)['signature']=='', 'development packager generates no signature')
    verifier=work/'verify.php';verifier.write_text('''<?php require $argv[1];
try { $m=verify_release_bundle(file_get_contents($argv[2]), '', ($argv[3]??'')==='dev'); echo $m['version']; }
catch(Throwable $e) {fwrite(STDERR,$e->getMessage());exit(1);}''')
    def verify(path, dev): return subprocess.run([PHP,str(verifier),str(server/'agents/docker/release.php'),str(path),'dev' if dev else 'prod'],capture_output=True,text=True)
    check(verify(bundle_path,True).stdout=='3.0.1', 'PHP accepts SHA-256 development payload without a key')
    check(verify(bundle_path,False).returncode!=0, 'production PHP rejects development bundle')
    bad=json.loads(bundle);bad['files']['agent.php']=base64.b64encode(b'tampered').decode();bad_path=work/'bad.json';bad_path.write_text(json.dumps(bad))
    check(verify(bad_path,True).returncode!=0, 'development PHP rejects payload hash mismatch')
    bad=json.loads(bundle);m=json.loads(base64.b64decode(bad['manifest']));m['files'][0]['name']='../agent.php';bad['manifest']=base64.b64encode(json.dumps(m).encode()).decode();bad_path.write_text(json.dumps(bad))
    check(verify(bad_path,True).returncode!=0, 'development PHP rejects path traversal')
    try:pack.make_bundle('docker','3.0.2',2,payload);raise AssertionError('mismatched metadata accepted')
    except ValueError:check(True, 'development packager rejects mismatched source metadata')
    store_probe=work/'store.php';store_probe.write_text('''<?php require $argv[1].'/src/bootstrap.php';
try {
 if (($argv[3]??'')==='offer') {
  $r=db_one("SELECT * FROM releases WHERE channel='dev-sha256'");
  $a=['release_target'=>'docker','decommission'=>0,'update_release_id'=>$r['id'],'release_sequence'=>1,'agent_version'=>'3.0.0','update_channel'=>$argv[4]];
  echo release_offer($a)===null ? 'none' : 'offer';
 } else {release_store(file_get_contents($argv[2]),'test');echo 'stored';}
} catch(Throwable $e) {fwrite(STDERR,$e->getMessage());exit(1);}''')
    def store(*extra):return subprocess.run([PHP,str(store_probe),str(server),str(bundle_path),*extra],capture_output=True,text=True)
    check(store().returncode!=0, 'production server refuses development upload')
    config=server/'config.php';original=config.read_text();config.write_text(original.replace("'allow_dev_releases' => false", "'allow_dev_releases' => true"))
    check(store().stdout=='stored', 'development server accepts hash-only upload without signing key')
    check(store('offer','signed').stdout=='none', 'server never offers dev payload to production channel')
    check(store('offer','dev-sha256').stdout=='offer', 'server offers matching dev payload to dev channel')
    config.write_text(original)
    check(store('offer','dev-sha256').stdout=='none', 'disabling development mode suppresses queued dev offers')
    # Fake only external Docker calls; installer executes its real preflight and must not mutate identities.
    fake=work/'fakebin';fake.mkdir();docker=fake/'docker';docker.write_text('#!/bin/sh\necho "$*" >> "$DOCKER_TRACE"\nexit 0\n');docker.chmod(0o755)
    # Installer needs root; do not elevate on developer workstations.
    if hasattr(os,'geteuid') and os.geteuid()==0:
        current=work/'current';legacy=work/'legacy'
        for d in (current,legacy):(d/'data').mkdir(parents=True);(d/'data/state.json').write_text('{"identity":"'+d.name+'"}')
        trace=work/'docker.trace';installer=work/'install.sh';shutil.copy(ROOT/'ControlServer/agents/docker/install.sh',installer)
        e=env|{'PATH':str(fake)+os.pathsep+env['PATH'],'DYNALLOW_DIR':str(current),'DYNALLOW_LEGACY_DIR':str(legacy),'DOCKER_TRACE':str(trace)}
        before={d.name:(d/'data/state.json').read_bytes() for d in (current,legacy)}
        result=subprocess.run(['sh',str(installer),'--upgrade'],env=e,capture_output=True,text=True)
        check(result.returncode!=0 and 'two identities' in result.stdout, 'Docker migration refuses conflicting installations')
        check(all((d/'data/state.json').read_bytes()==before[d.name] for d in (current,legacy)) and 'down' not in trace.read_text(), 'conflict refusal preserves identities and running containers')
        e['DYNALLOW_DIR']=str(legacy/'nested')
        result=subprocess.run(['sh',str(installer),'--upgrade'],env=e,capture_output=True,text=True)
        check(result.returncode!=0 and 'nested' in result.stdout, 'Docker migration rejects overlapping installation paths')
    else: print('SKIP: root-only installer preflight regression')
print('ALL REVIEW REGRESSIONS PASSED')
