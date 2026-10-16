#!/usr/bin/env python3
"""Portable v3 regression harness. Uses disposable copies, never the live database.
PHP env: executable path. DOTNET env: SDK host path. Windows SCM/TPM tests are separate.
"""
import os, pathlib, shutil, subprocess, tempfile, json, urllib.request, urllib.parse, http.cookiejar, re, time, socket
ROOT=pathlib.Path(__file__).resolve().parents[1]
PHP=os.environ.get('PHP','php'); DOTNET=os.environ.get('DOTNET','dotnet')
def run(*args,**kw): return subprocess.run(args,check=True,text=True,**kw)
def check(v,label):
    if not v: raise AssertionError(label)
    print('PASS:',label,flush=True)
with tempfile.TemporaryDirectory(prefix='dynallow-v3-') as temp:
    work=pathlib.Path(temp); server=work/'server'
    shutil.copytree(ROOT/'ControlServer',server,ignore=shutil.ignore_patterns('bin','obj','data'))
    # bin/manage.php is real source, not a compiler output.
    shutil.copytree(ROOT/'ControlServer/bin',server/'bin')
    env=os.environ.copy(); env.update(DYNALLOW_ADMIN='admin',DYNALLOW_PASSWORD='test-password-long-enough')
    run(PHP,str(server/'bin/manage.php'),'init',env=env,stdout=subprocess.DEVNULL)
    project=ROOT/'ControlServer/agents/windows-native'
    run(DOTNET,'build',str(project),'-c','Release','-p:IsAotCompatible=false','--nologo',stdout=subprocess.DEVNULL)
    interop=work/'interop'
    minted=work/'server-profile.json'
    run(PHP,str(ROOT/'tests/profile_fixture.php'),str(server),str(minted))
    run(DOTNET,str(project/'bin/Release/net10.0/DynAllow.Agent.dll'),'self-test',str(interop),str(minted))
    run(PHP,str(ROOT/'tests/security_v3.php'),str(server),str(interop))
    with open(work/'docker-tests.log','w') as f: run(PHP,str(ROOT/'tests/docker_v3.php'),str(server/'agents/docker'),str(work/'docker-data'),stdout=f)
    check('Docker helper tests complete' in (work/'docker-tests.log').read_text(),'Docker helper suite')
    # Test boot-time verifier independently of Docker runtime/namespace behavior.
    app=server/'agents/docker'; data=work/'launcher-data';data.mkdir()
    env2=env|{'DATA_DIR':str(data),'DYNALLOW_APP_DIR':str(app)}
    (data/'agent.php').write_text('<?php file_put_contents('+json.dumps(str(work/'UNTRUSTED_EXECUTED'))+', "bad");')
    run(PHP,str(app/'launcher.php'),'status',env=env2,stdout=subprocess.DEVNULL)
    check(not (work/'UNTRUSTED_EXECUTED').exists(),'Docker ignores legacy writable executable')
    (data/'current-release.json').write_text('{"manifest":"bad","signature":"bad","files":{}}')
    r=subprocess.run([PHP,str(app/'launcher.php'),'status'],env=env2,capture_output=True,text=True)
    check(r.returncode!=0 and 'VERIFICATION FAILED' in r.stderr,'Docker launcher fails closed on untrusted staged update')
    # Real HTTP sessions: admin vs tech, CSRF, log escaping, token scope.
    s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
    log=open(work/'http.log','w');proc=subprocess.Popen([PHP,'-S',f'127.0.0.1:{port}','-t',str(server/'public')],stdout=log,stderr=log)
    base=f'http://127.0.0.1:{port}'
    try:
        for i in range(50):
            try: urllib.request.urlopen(base+'/login.php');break
            except OSError: time.sleep(.1)
        op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def get(path): return op.open(base+path).read().decode()
        def post(path,fields): return op.open(base+path,urllib.parse.urlencode(fields).encode()).read().decode()
        def csrf(html): return re.search(r'name="csrf" value="([a-f0-9]+)"',html)[1]
        page=get('/login.php'); page=post('/login.php',{'csrf':csrf(page),'username':'admin','password':'test-password-long-enough'})
        check('Dashboard' in page,'admin login')
        # Full PHP agent/server transport + signed update + restart, without Docker daemon.
        docker_data=work/'docker-http';docker_data.mkdir()
        run(PHP,str(ROOT/'tests/docker_http_fixture.php'),str(server),base,str(docker_data),str(app))
        docker_env=env|{'DATA_DIR':str(docker_data),'DYNALLOW_APP_DIR':str(app)}
        agent_log=open(work/'docker-http.log','w')
        try:
            first=subprocess.run([PHP,str(app/'launcher.php'),'once'],env=docker_env,stdout=agent_log,stderr=agent_log,timeout=100)
            check(first.returncode==10,'Docker enrolls over HTTP and stages independently signed update')
            run(PHP,str(app/'launcher.php'),'once',env=docker_env,stdout=agent_log,stderr=agent_log,timeout=100)
            status=json.loads((docker_data/'status.json').read_text())
            check(status['version']=='3.0.1' and status['server_ok'],'Docker restart executes verified release and checks in')
            # Startup verifier rejects mutation even after a successful prior install.
            staged=json.loads((docker_data/'current-release.json').read_text());staged['files']['agent.php']='dGFtcGVy'
            (docker_data/'current-release.json').write_text(json.dumps(staged))
            failed=subprocess.run([PHP,str(app/'launcher.php'),'status'],env=docker_env,stdout=agent_log,stderr=agent_log)
            check(failed.returncode!=0,'Docker revalidates installed update bytes on every startup')
        finally: agent_log.close()

        page=get('/logs.php');check('&lt;script&gt;' in page and '<script>alert(1)</script>' not in page,'agent log HTML safely escaped')
        check('Test server diagnostic' in page,'server logs visible in web UI')
        page=get('/releases.php');check('3.0.1' in page,'verified release visible in web UI')
        try: post('/releases.php',{'action':'activate','release':1,'csrf':'bad'});raise AssertionError('CSRF accepted')
        except urllib.error.HTTPError as e: check(e.code==400,'release CSRF enforced')
        try: get('/feed.php?token=test-restricted-token&tag=');raise AssertionError('Scope widened')
        except urllib.error.HTTPError as e: check(e.code==403,'feed token scope cannot be widened via HTTP')
        run(PHP,str(server/'bin/manage.php'),'create-user','tech','tech',env=env,stdout=subprocess.DEVNULL)
        op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        page=get('/login.php');post('/login.php',{'csrf':csrf(page),'username':'tech','password':'test-password-long-enough'})
        try:get('/releases.php');raise AssertionError('Tech opened release admin')
        except urllib.error.HTTPError as e:check(e.code==403,'release deployment admin-only')
        page=get('/logs.php');check('Test server diagnostic' in page,'technicians can inspect diagnostics')
        try:post('/logs.php',{'csrf':csrf(page),'ack':1});raise AssertionError('Tech acknowledged')
        except urllib.error.HTTPError as e:check(e.code==403,'diagnostic acknowledgement admin-only')
    finally: proc.terminate();proc.wait(timeout=10);log.close()
print('ALL PORTABLE V3 TESTS PASSED')
