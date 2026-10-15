#!/usr/bin/env python3
"""Current web UI/provider-adapter tests in disposable copies and loopback-only mocks."""
import os, pathlib, shutil, socket, subprocess, sys, tempfile, time, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[1]
PHP = os.environ.get('PHP', 'php')
def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]
def ready(url, proc):
    for _ in range(100):
        if proc.poll() is not None: raise RuntimeError('Test server exited; inspect test output')
        try: urllib.request.urlopen(url, timeout=1).close(); return
        except OSError: time.sleep(.1)
    raise RuntimeError('Test server did not start')
with tempfile.TemporaryDirectory(prefix='dynallow-ui-') as tmp:
    tmp = pathlib.Path(tmp); server = tmp/'server'; processes = []
    shutil.copytree(ROOT/'ControlServer', server, ignore=shutil.ignore_patterns('data', 'obj', 'bin'))
    shutil.copytree(ROOT/'ControlServer/bin', server/'bin')
    # Source mutations stay inside this disposable test copy.
    http_port, mock_port, smtp_port = port(), port(), port()
    base = f'http://127.0.0.1:{http_port}'; mock = f'http://127.0.0.1:{mock_port}'
    p = server/'config.php'; s = p.read_text()
    s = s.replace("'cloudflare_api_base' => null", f"'cloudflare_api_base' => '{mock}/cf'")
    s = s.replace("'duckdns_api_base'    => null", f"'duckdns_api_base'    => '{mock}'")
    p.write_text(s)
    env = os.environ | {'IPF_ADMIN':'admin', 'IPF_PASSWORD':'correct-horse-battery',
        'IPF_TEST_BASE':base, 'IPF_TEST_MOCK':mock, 'IPF_TEST_SMTP_PORT':str(smtp_port)}
    subprocess.run([PHP, str(server/'bin/manage.php'), 'init'], env=env, check=True, stdout=subprocess.DEVNULL)
    with open(tmp/'services.log', 'w+') as log:
        try:
            processes.append(subprocess.Popen([sys.executable, str(ROOT/'tests/mock.py'), str(mock_port), str(smtp_port)], stdout=log, stderr=log))
            ready(mock+'/_state', processes[-1])
            processes.append(subprocess.Popen([PHP, '-S', f'127.0.0.1:{http_port}', '-t', str(server/'public')], stdout=log, stderr=log))
            ready(base+'/login.php', processes[-1])
            # ui_test imports helpers from argv[1] and writes only its fixture ids there.
            for name in ['ui_test.py', 'web.py']: shutil.copy(ROOT/'tests'/name, tmp/name)
            subprocess.run([sys.executable, '-I', str(tmp/'ui_test.py'), str(tmp)], env=env, check=True)
        except Exception:
            log.flush(); log.seek(0); print(log.read()[-12000:], file=sys.stderr); raise
        finally:
            for proc in reversed(processes):
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
print('ALL WEB UI TESTS PASSED')
