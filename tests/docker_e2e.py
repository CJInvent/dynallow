#!/usr/bin/env python3
"""Real-Docker end-to-end: server image + generated agent installer + signed update.

Runs as root on a Docker host (CI: ubuntu runner). Uses the real web UI for
everything a technician does, and only reads the database to assert results.

  sudo python3 tests/docker_e2e.py            build the server image from ControlServer/
  DYNALLOW_E2E_IMAGE=tag ...                  use an already built image instead
  DYNALLOW_E2E_BUILD_NETWORK=host ...         pass --network host to docker build
  DYNALLOW_E2E_KEEP=1 ...                     leave containers/files for inspection

The server runs with host networking (port 80) so the agent container, which
lives on its own Compose network, reaches it through a host address exactly the
way a remote site reaches a real server.
"""
import base64, hashlib, http.server, json, os, pathlib, re, shutil, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request, uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER = 'dynallow-e2e-server'
AGENT = 'dynallow-agent'
PASSWORD = 'e2e-password-not-secret'
KEEP = os.environ.get('DYNALLOW_E2E_KEEP') == '1'
passed = 0


def check(cond, label):
    global passed
    if not cond:
        raise AssertionError(label)
    passed += 1
    print('PASS:', label, flush=True)


def sh(*args, check_rc=True, **kw):
    r = subprocess.run(args, text=True, capture_output=True, **kw)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} -> {r.returncode}\n{r.stdout}\n{r.stderr}")
    return r


def wait(fn, label, timeout=150, every=2):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception:
            pass
        time.sleep(every)
    raise AssertionError('timed out: ' + label)


def db(sql, *params):
    """One row from the server database, read inside the server container."""
    code = ('require "/var/www/dynallow/src/bootstrap.php";'
            '$a=json_decode($argv[2],true); echo json_encode(db_one($argv[1],$a));')
    r = sh('docker', 'exec', '-u', 'www-data', SERVER, 'php', '-r', code, sql, json.dumps(list(params)))
    return json.loads(r.stdout.strip().splitlines()[-1])


def health(name):
    r = sh('docker', 'inspect', '-f', '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', name, check_rc=False)
    return r.stdout.strip()


def sign_bundle(key, target, version, sequence, name, payload):
    manifest = json.dumps({'format': 'dynallow-release-v1', 'target': target, 'version': version, 'sequence': sequence,
                           'files': [{'name': name, 'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}]},
                          separators=(',', ':')).encode()
    sig = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=manifest, capture_output=True, check=True).stdout
    return json.dumps({'manifest': base64.b64encode(manifest).decode(), 'signature': base64.b64encode(sig).decode(),
                       'files': {name: base64.b64encode(payload).decode()}}).encode()


def multipart(fields, file_field, filename, content):
    boundary = uuid.uuid4().hex
    out = b''
    for k, v in fields.items():
        out += f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    out += (f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
            f'Content-Type: application/json\r\n\r\n').encode() + content + b'\r\n' + f'--{boundary}--\r\n'.encode()
    return out, 'multipart/form-data; boundary=' + boundary


class Echo(http.server.BaseHTTPRequestHandler):
    """Stands in for ipify: tells the agent its 'public' IP."""
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type', 'text/plain'); self.end_headers(); self.wfile.write(b'8.8.8.8')
    def log_message(self, *a):
        pass


def main():
    if os.geteuid() != 0:
        sys.exit('run as root (the agent installer requires it): sudo python3 tests/docker_e2e.py')
    work = pathlib.Path(tempfile.mkdtemp(prefix='dynallow-e2e-'))
    agent_dir = work / 'agent'
    echo = http.server.ThreadingHTTPServer(('0.0.0.0', 0), Echo)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    try:
        # ---- server image + container -------------------------------------------------
        image = os.environ.get('DYNALLOW_E2E_IMAGE')
        if not image:
            image = 'dynallow-server:e2e'
            build = ['docker', 'build', '-q', '-t', image]
            if os.environ.get('DYNALLOW_E2E_BUILD_NETWORK'):
                build += ['--network', os.environ['DYNALLOW_E2E_BUILD_NETWORK']]
            sh(*build, str(ROOT / 'ControlServer'))
        sh('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(work / 'release-private.pem'))
        sh('openssl', 'ec', '-in', str(work / 'release-private.pem'), '-pubout', '-out', str(work / 'release-public.pem'))
        (work / 'data').mkdir()
        sh('docker', 'rm', '-f', SERVER, check_rc=False)
        sh('docker', 'run', '-d', '--name', SERVER, '--network', 'host', '--init',
           '-e', 'DYNALLOW_ADMIN=admin', '-e', 'DYNALLOW_PASSWORD=' + PASSWORD,
           '-v', f'{work}/data:/var/www/dynallow/data', '-v', f'{work}/release-public.pem:/var/www/dynallow/release-public.pem:ro', image)
        wait(lambda: health(SERVER) == 'healthy', 'server container healthy', 120)
        check(True, 'server image builds and its container reports healthy')
        logs = sh('docker', 'logs', SERVER).stdout + sh('docker', 'logs', SERVER).stderr
        check(PASSWORD not in logs and "created admin user 'admin'" in logs, 'first start creates the admin without echoing a supplied password')
        check(oct((work / 'data' / 'secret.key').stat().st_mode)[-3:] == '600', 'encryption key is created mode 600 in the data volume')

        # ---- technician flow in the web UI ---------------------------------------------
        os.environ['DYNALLOW_TEST_BASE'] = 'http://127.0.0.1'
        sys.path.insert(0, str(ROOT / 'tests'))
        from web import Browser, flashes
        b = Browser('http://127.0.0.1')
        b.get('login.php')
        c, t, h = b.post('login.php', {'username': 'admin', 'password': PASSWORD})
        check('<h1>Sites' in t, 'admin signs in to the containerized server')
        for p in ['config.php', 'data/secret.key', 'data/dynallow.sqlite', 'src/db.php', 'bin/manage.php', 'release-public.pem']:
            c, _, _ = Browser('http://127.0.0.1').get(p)
            if c != 404:
                raise AssertionError(f'{p} is reachable over HTTP ({c})')
        check(True, 'nothing outside public/ is served by the container')
        gw = sh('docker', 'network', 'inspect', 'bridge', '-f', '{{(index .IPAM.Config 0).Gateway}}').stdout.strip()
        public_url = f'http://{gw}'
        b.get('settings.php')
        c, t, h = b.post('settings.php', {'action': 'save', 'section': 'General', 'public_url': public_url, 'timezone': 'UTC',
                                          'default_interval_sec': '60', 'default_missed': '2', 'ip_confirm_checkins': '1',
                                          'ip_check_urls': f'http://{gw}:{echo.server_address[1]}/'})
        check(('ok', 'General settings saved.') in flashes(t), 'public URL and IP lookup saved in Settings')
        b.get('survey.php')
        c, t, h = b.post('survey.php', {'customer': 'E2E', 'name': 'E2E-Docker', 'platform': 'docker', 'isp': 'cable', 'cgnat': 'no',
                                        'multiwan': 'no', 'interval_sec': '60', 'missed_threshold': '2', 'alert_emails': '', 'tags': 'e2e',
                                        'trust_mode': 'agent'})
        check('Download Docker installer' in t, 'survey creates a Docker site')
        agent_id = int(re.search(r'name="id" value="(\d+)"', t)[1])
        c, installer, h = b.post('profile.php', {'id': str(agent_id), 'format': 'docker'}, follow=False)
        check(c == 200 and installer.startswith('#!/bin/sh') and 'no-store' in h.get('Cache-Control', ''), 'Docker installer downloads as a no-store attachment')

        # ---- install the agent with the generated installer ------------------------------
        inst = work / 'dynallow-agt.sh'
        inst.write_text(installer)
        env = os.environ | {'DYNALLOW_DIR': str(agent_dir)}
        r = subprocess.run(['sh', str(inst)], env=env, text=True, capture_output=True, timeout=240)
        print(r.stdout[-1500:], r.stderr[-1500:], sep='\n')
        check(r.returncode == 0 and 'INSTALLED.' in r.stdout, 'generated installer installs, enrolls and reports healthy')
        check(not inst.exists(), 'installer deleted itself (it carried a one-time credential)')
        check(not (agent_dir / 'data' / 'provisioning.json').exists(), 'provisioning profile consumed and destroyed')
        wait(lambda: health(AGENT) == 'healthy', 'agent container healthcheck', 150)
        check(True, 'agent container healthcheck turns healthy')
        inspect = json.loads(sh('docker', 'inspect', AGENT).stdout)[0]
        hc = inspect['HostConfig']
        check(inspect['Config']['User'] == '65534:65534' and hc['ReadonlyRootfs'] and 'ALL' in (hc['CapDrop'] or [])
              and any('no-new-privileges' in o for o in hc['SecurityOpt'] or []), 'agent runs as nobody, read-only, all capabilities dropped')
        a = db('SELECT * FROM agents WHERE id = ?', agent_id)
        check(a['enrolled_at'] and a['release_target'] == 'docker' and a['key_protector'], 'server shows the agent enrolled with its release target')

        sh('docker', 'restart', AGENT)  # second cycle uses the server-provided IP lookup
        a = wait(lambda: (lambda x: x if x['current_ipv4'] == '8.8.8.8' else None)(db('SELECT * FROM agents WHERE id = ?', agent_id)), 'authoritative IP')
        check(True, 'agent-signed IP becomes the authoritative IP')

        # ---- independently signed update -------------------------------------------------
        code = (ROOT / 'ControlServer/agents/docker/agent.php').read_text()
        ver = re.search(r"const AGENT_VERSION = '([0-9.]+)';", code)[1]
        seq = int(re.search(r'const RELEASE_SEQUENCE = (\d+);', code)[1])
        major, minor, patch = (int(x) for x in ver.split('.'))
        new_ver, new_seq = f'{major}.{minor}.{patch + 1}', seq + 1
        new_code = code.replace(f"const AGENT_VERSION = '{ver}';", f"const AGENT_VERSION = '{new_ver}';").replace(
            f'const RELEASE_SEQUENCE = {seq};', f'const RELEASE_SEQUENCE = {new_seq};').encode()
        bundle = sign_bundle(work / 'release-private.pem', 'docker', new_ver, new_seq, 'agent.php', new_code)
        wrong = work / 'other-private.pem'
        sh('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(wrong))
        def upload(payload):
            b.get('releases.php')
            body, ctype = multipart({'csrf': b.csrf, 'action': 'upload'}, 'bundle', 'release.json', payload)
            try:
                b.op.open(urllib.request.Request('http://127.0.0.1/releases.php', data=body, headers={'Content-Type': ctype}))
            except urllib.error.HTTPError as e:
                if e.code != 302:  # the page redirects after every upload, accepted or not
                    raise
        upload(sign_bundle(wrong, 'docker', new_ver, new_seq, 'agent.php', new_code))
        check(db('SELECT COUNT(*) AS n FROM releases')['n'] == 0, 'server rejects a release signed with the wrong key')
        upload(bundle)
        rel = db('SELECT * FROM releases WHERE target = ? AND sequence = ?', 'docker', new_seq)
        check(rel and rel['version'] == new_ver, 'signed Docker release uploads through the web UI')
        b.get('releases.php')
        c, t, h = b.post('releases.php', {'action': 'push', 'release': str(rel['id']), 'agent': str(agent_id)})
        check(any(k == 'ok' for k, _ in flashes(t)), 'release pushed to the agent')
        sh('docker', 'restart', AGENT)
        wait(lambda: db('SELECT agent_version FROM agents WHERE id = ?', agent_id)['agent_version'] == new_ver, 'agent reports new version', 180)
        check(True, f'agent stages the release, restarts (exit 10) and checks in as {new_ver}')
        wait(lambda: health(AGENT) == 'healthy', 'healthy after update', 150)
        check(True, 'agent is healthy on the updated code')

        # ---- tamper with the installed release ---------------------------------------------
        staged = agent_dir / 'data' / 'current-release.json'
        good = staged.read_bytes()
        doc = json.loads(good); doc['files']['agent.php'] = base64.b64encode(b'<?php echo "tampered";').decode()
        staged.write_text(json.dumps(doc))
        sh('docker', 'restart', AGENT)
        wait(lambda: 'VERIFICATION FAILED' in (lambda r: r.stdout + r.stderr)(sh('docker', 'logs', '--tail', '50', AGENT)), 'launcher refuses tampered code', 60)
        check(True, 'launcher refuses to run tampered release bytes after a restart')
        staged.write_bytes(good)
        sh('docker', 'restart', AGENT)
        wait(lambda: health(AGENT) == 'healthy', 'healthy after restoring the release', 150)
        check(True, 'agent recovers once the verified release is restored')

        # ---- server restart keeps everything -----------------------------------------------
        before = db('SELECT checkin_count FROM agents WHERE id = ?', agent_id)['checkin_count']
        sh('docker', 'restart', SERVER)
        wait(lambda: health(SERVER) == 'healthy', 'server healthy after restart', 120)
        sh('docker', 'restart', AGENT)
        wait(lambda: db('SELECT checkin_count FROM agents WHERE id = ?', agent_id)['checkin_count'] > before, 'check-in after server restart')
        check(True, 'server restart keeps its data and the agent keeps checking in')

        # ---- decommission ----------------------------------------------------------------
        b.get(f'agent.php?id={agent_id}')
        b.post(f'agent.php?id={agent_id}', {'action': 'decommission'})
        sh('docker', 'restart', AGENT)
        wait(lambda: (agent_dir / 'data' / 'DECOMMISSIONED').exists(), 'agent decommissions itself')
        check(not (agent_dir / 'data' / 'agent-key.json').exists(), 'decommission destroys the agent identity')
        wait(lambda: db('SELECT decommissioned_at FROM agents WHERE id = ?', agent_id)['decommissioned_at'], 'server records the acknowledgment', 60)
        check(True, 'server records the decommission acknowledgment')
        print(f'ALL DOCKER E2E TESTS PASSED ({passed})')
    except Exception:
        for name in (SERVER, AGENT):
            r = sh('docker', 'logs', '--tail', '80', name, check_rc=False)
            print(f'----- docker logs {name} -----\n{r.stdout[-6000:]}\n{r.stderr[-6000:]}', file=sys.stderr)
        raise
    finally:
        echo.shutdown()
        if not KEEP:
            if (agent_dir / 'docker-compose.yml').exists():
                subprocess.run(['docker', 'compose', 'down', '-v'], cwd=agent_dir, capture_output=True)
            subprocess.run(['docker', 'rm', '-f', SERVER, AGENT], capture_output=True)
            shutil.rmtree(work, ignore_errors=True)
        else:
            print('kept:', work)


if __name__ == '__main__':
    main()
