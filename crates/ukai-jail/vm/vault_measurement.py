#!/usr/bin/env python3
"""Live measurement of vault-value consumption (J18 §6).

An agent attempt with a vaulted launch profile: the credential value
crosses over vsock once, lands in the guest's tmpfs, the guest jail's
`--launch` resolves it, and the guest proxy injects it into an admitted
request. The echo server (this Mac, reached through the guest NAT)
records the header, which proves injection end to end. The measurement
also proves the value never reached the guest's on-disk attempt state
(only tmpfs), and that the exported evidence contains no value bytes.
"""
import base64
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

BIN = Path('/Users/monocursive/code/ouroboros/target/release/ukai-jail')
HOME = sys.argv[1]
WS = Path(sys.argv[2])
OUT = Path(sys.argv[3])
SECRET = b'ukai-vault-measurement-token-773f'

received = []


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        received.append({h.lower(): v for h, v in self.headers.items()})
        self.send_response(200)
        self.send_header('content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'echo')

    def log_message(self, *_):
        pass


def mac_address():
    for interface in ('en0', 'en1'):
        result = subprocess.run(['ipconfig', 'getifaddr', interface],
                                capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    raise SystemExit('no Mac interface address for the echo server')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in WS.iterdir():
        shutil.rmtree(stale) if stale.is_dir() else stale.unlink()

    address = mac_address()
    server = http.server.HTTPServer(('0.0.0.0', 0), Echo)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    config = Path(tempfile.mkdtemp(prefix='vault-cfg-'))
    (config / 'launch').mkdir(mode=0o700)
    source = Path(tempfile.mkdtemp(prefix='vault-src-')).resolve() / 'token'
    source.write_bytes(SECRET)
    os.chmod(source, 0o600)
    profile = f'''# measurement-only vault profile
name = "vault-test"
jail = "agent"

[credentials.test]
mode = "vault"
source = "{source}"
hosts = ["http://{address}:{port}"]
allow_plaintext = true
header = {{ name = "x-test-token" }}

[network]
allow = ["{address}:{port}"]
'''
    (config / 'launch' / 'vault-test.toml').write_text(profile)
    os.chmod(config / 'launch' / 'vault-test.toml', 0o600)

    fetch = ("python3 -c \"import os, urllib.request; "
             "print('PROXYENV', {k: v for k, v in os.environ.items() if 'proxy' in k.lower()}); "
             "r=urllib.request.urlopen('http://%s:%d/echo', timeout=20); "
             "print('ECHO', r.status, r.read().decode())\"" % (address, port))

    data = Path(tempfile.mkdtemp(prefix='vault-run-'))
    env = dict(os.environ, UKAI_VM_HOME=str(HOME), UKAI_DATA_DIR=str(data),
               UKAI_CONFIG_DIR=str(config))
    started = time.monotonic()
    run = subprocess.run(
        [str(BIN), 'run', '--vm', '--terminal', 'detach', '--profile', 'agent',
         '--launch', 'vault-test', '--limit', 'wall=40s',
         '--workspace', str(WS), '--', '/bin/sh', '-c', fetch],
        env=env, capture_output=True, text=True, timeout=900)
    server.shutdown()

    # The exported evidence and the attempt's exported workspace must not
    # contain the value bytes.
    def grep_tree(root):
        hits = []
        for path in Path(root).rglob('*'):
            if path.is_file() and path.stat().st_size < 2_000_000:
                if SECRET in path.read_bytes():
                    hits.append(str(path))
        return hits

    leaked = []
    for group in ('workspace', 'evidence'):
        exported = data / 'attempts'
        for attempt in exported.glob('att_*'):
            leaked += grep_tree(attempt / group)

    records = None
    for jail_json in sorted((data / 'attempts').glob('att_*/jail.json'),
                            key=lambda p: p.stat().st_mtime, reverse=True):
        record = json.loads(jail_json.read_text())
        guest_path = jail_json.parent / 'evidence/jail.json'
        guest = (json.loads(guest_path.read_text())
                 if guest_path.exists() else {})
        records = {
            'phase': record.get('phase'),
            'exit': record.get('outcome', {}).get('code'),
            'tree_empty': record.get('lifetime', {}).get('tree_empty'),
            'guest_credentials': guest.get('credentials'),
            'guest_network': (guest.get('applied') or {}).get('network'),
        }
        break

    header = received[0].get('x-test-token') if received else None
    all_headers = received[0] if received else {}
    verdict = {
        'run': {'exit': run.returncode,
                'elapsed': round(time.monotonic() - started, 1),
                'stdout': run.stdout[-200:],
                'stderr': run.stderr[-300:]},
        'echo_requests': len(received),
        'injected_header': header,
        'received_headers': {k: v for k, v in all_headers.items()},
        'value_leaked_to_exports': sorted(set(leaked)),
        'records': records,
    }
    verdict['outcome'] = 'PASS' if (
        header == SECRET.decode()
        and not leaked
        and records
        and records['phase'] == 'settled'
        and records['exit'] == 0
        and records['tree_empty'] is True
        and records['guest_credentials']
    ) else 'FAIL'
    (OUT / 'vault-consumption.json').write_text(json.dumps(verdict, indent=2) + '\n')
    print(json.dumps({k: v for k, v in verdict.items()
                      if k not in ('run', 'records')}))
    return 0 if verdict['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
