#!/usr/bin/env python3
"""Package a SHA-256-only development release. No private key, certificates, or signing step."""
import argparse, base64, hashlib, json, pathlib, re

def make_bundle(target, version, sequence, path):
    if target not in ('windows-x64', 'windows-arm64', 'docker'): raise ValueError('Invalid target')
    if not re.fullmatch(r'[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}', version) or not 1 <= sequence <= 2147483647:
        raise ValueError('Invalid version/sequence')
    path = pathlib.Path(path)
    if not 1 <= path.stat().st_size <= 48000000: raise ValueError('Payload must be 1..48,000,000 bytes')
    data = path.read_bytes()
    if target == 'docker':
        code = data.decode('utf-8')
        if not re.search(r"const AGENT_VERSION = '" + re.escape(version) + r"';", code) or not re.search(r'const RELEASE_SEQUENCE = ' + str(sequence) + r';', code):
            raise ValueError('Docker source version/sequence do not match')
        name = 'agent.php'
    else:
        meta = json.loads(pathlib.Path(str(path) + '.build.json').read_text(encoding='utf-8-sig'))
        if any(meta.get(k) != v for k, v in dict(version=version, sequence=sequence, target=target, channel='dev-sha256').items()):
            raise ValueError('Expected matching metadata from Build-Windows.ps1 -Development')
        name = 'DynAllow.Agent.exe'
    manifest = dict(format='dynallow-dev-release-v1', target=target, version=version, sequence=sequence,
                    files=[dict(name=name, size=len(data), sha256=hashlib.sha256(data).hexdigest())])
    raw = json.dumps(manifest, separators=(',', ':')).encode()
    return json.dumps(dict(manifest=base64.b64encode(raw).decode(), signature='', files={name:base64.b64encode(data).decode()}), separators=(',', ':')).encode()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', required=True, choices=['windows-x64','windows-arm64','docker'])
    p.add_argument('--version', required=True); p.add_argument('--sequence', required=True, type=int)
    p.add_argument('--input', required=True); p.add_argument('--output', required=True)
    a = p.parse_args()
    try:
        bundle = make_bundle(a.target, a.version, a.sequence, a.input)
        output = pathlib.Path(a.output)
        with output.open('xb') as f: f.write(bundle)
        print(f'DEV SHA-256 bundle: {output}\nSHA256 {hashlib.sha256(bundle).hexdigest()}')
    except (ValueError, OSError) as e: p.exit(1, str(e)+'\n')
if __name__ == '__main__': main()
