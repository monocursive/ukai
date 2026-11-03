#!/usr/bin/env python3
"""Live measurement of vault-value consumption (J18 §6).

An agent attempt with a vaulted launch profile: the credential value
crosses over vsock once, lands in the guest's tmpfs, the guest jail's
`--launch` resolves it, and the guest proxy injects it into an admitted
request. The echo server (this Mac, reached through the guest NAT) records
the header, which proves injection end to end. PASS also needs:

- the child saw a placeholder, not the value (it prints the SHA-256 and
  length of its environment variable; the hash must differ from the
  value's, and the variable must be non-empty);
- the guest receipt records the credential `test` as mode `vault`,
  `never_staged` (the jail never wrote it into the attempt);
- no exported byte holds the value: every regular file under the run's data
  directory (receipts, policy.json, trace.ndjson, transport and binding
  records, console logs), the workspace, and the client's own stdout and
  stderr, with no size cap;
- the value never reached the guest's disk: after a `sync` attempt on the
  same boot, the boot's raw disk image is scanned for the value's bytes
  (the only staging place left is the guest tmpfs, which is not on it).

The Mac's LAN address the echo server needs is redacted in the record.

Usage: vault_measurement.py <home> <workspace> <out> [--ukai-jail PATH]
       (or UKAI_JAIL_BINARY=...)
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

SECRET = b'ukai-vault-measurement-token-773f'
CHUNK = 8 * 1024 * 1024


class Echo(http.server.BaseHTTPRequestHandler):
    received = []

    def do_GET(self):
        Echo.received.append({h.lower(): v for h, v in self.headers.items()})
        self.send_response(200)
        self.send_header('content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'echo')

    def log_message(self, *_):
        pass


def mac_address():
    for interface in ('en0', 'en1'):
        result = subprocess.run(['ipconfig', 'getifaddr', interface], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    raise harness.HarnessError('no Mac interface address for the echo server')


def file_holds(path, needle, chunk=CHUNK):
    """Whether `needle` occurs in the file at `path`, streamed with overlap."""
    overlap = len(needle) - 1
    tail = b''
    with open(path, 'rb') as source:
        while block := source.read(chunk):
            if needle in tail + block:
                return True
            tail = (tail + block)[-overlap:] if overlap else b''
    return False


def leak_scan(roots, needle, skip=()):
    """Every regular file under each root (never following links), no size cap."""
    hits, scanned = [], 0
    skip = {Path(path).resolve() for path in skip}
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for directory, _, names in os.walk(root, followlinks=False):
            for name in names:
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file() or path.resolve() in skip:
                    continue
                scanned += 1
                if file_holds(path, needle):
                    hits.append(str(path))
    return sorted(hits), scanned


def fetch_script(address, port):
    return ("python3 -c \"import hashlib, os, urllib.request; "
            "token = os.environ.get('UKAI_VAULT_TEST', ''); "
            "print('PLACEHOLDER', hashlib.sha256(token.encode()).hexdigest(), len(token)); "
            "req = urllib.request.Request('http://%s:%d/echo', headers={'x-test-token': token}); "
            "r = urllib.request.urlopen(req, timeout=20); "
            "print('ECHO', r.status, r.read().decode())\"" % (address, port))


def placeholder(stdout):
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == 'PLACEHOLDER' and parts[2].isdigit():
            return {'sha256': parts[1], 'length': int(parts[2])}
    return None


def judge(observed):
    seen = observed.get('placeholder') or {}
    credentials = observed.get('guest_credentials') or []
    entry = next((c for c in credentials if isinstance(c, dict) and c.get('id') == 'test'), {})
    facts = {
        'run_exit_zero': observed.get('run_exit') == 0,
        'header_injected': observed.get('header') == SECRET.decode(),
        'child_saw_a_placeholder': bool(seen) and seen.get('length', 0) > 0
        and seen.get('sha256') != hashlib.sha256(SECRET).hexdigest(),
        'guest_credential_vault_never_staged': entry.get('mode') == 'vault' and entry.get('never_staged') is True,
        'guest_network_proxy': observed.get('guest_network_mode') == 'proxy',
        'settled_exit_zero_tree_empty': (observed.get('phase') == 'settled' and observed.get('exit') == 0
                                         and observed.get('tree_empty') is True),
        'no_value_in_any_export': observed.get('leaks') == [] and observed.get('files_scanned', 0) > 0,
        'no_value_in_client_output': observed.get('client_output_leak') is False,
        'guest_disk_scanned_clean': observed.get('disk_scan') == 'clean' and observed.get('sync_exit') == 0,
    }
    return facts, 'PASS' if all(facts.values()) else 'FAIL'


def agent_attempt(data):
    """The vaulted (agent) attempt; the sync attempt on the same boot is `tool`."""
    for attempt in sorted((Path(data) / 'attempts').glob('att_*'), key=lambda p: p.stat().st_mtime):
        try:
            record = json.loads((attempt / 'jail.json').read_text())
        except (OSError, ValueError):
            continue
        if (record.get('policy') or {}).get('name') == 'agent':
            return attempt, record
    return None, None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('home', type=Path)
    parser.add_argument('workspace', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('--ukai-jail', help='the ukai-jail under test (default: $UKAI_JAIL_BINARY)')
    args = parser.parse_args(argv)
    jail = harness.required_binary('UKAI_JAIL_BINARY', args.ukai_jail)
    home = args.home.resolve(strict=True)
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    harness.clean_workspace(workspace)

    address = mac_address()
    server = http.server.HTTPServer(('0.0.0.0', 0), Echo)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    config = Path(tempfile.mkdtemp(prefix='vault-cfg-'))
    os.chmod(config, 0o700)
    (config / 'launch').mkdir(mode=0o700)
    source_dir = Path(tempfile.mkdtemp(prefix='vault-src-')).resolve()
    source = source_dir / 'token'
    source.write_bytes(SECRET)
    os.chmod(source, 0o600)
    (config / 'launch' / 'vault-test.toml').write_text(f'''# measurement-only vault profile
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
''')
    os.chmod(config / 'launch' / 'vault-test.toml', 0o600)

    data = Path(tempfile.mkdtemp(prefix='vault-run-'))
    env = dict(os.environ, UKAI_VM_HOME=str(home), UKAI_DATA_DIR=str(data), UKAI_CONFIG_DIR=str(config))
    env.pop('UKAI_VM_GUEST_NAT', None)
    observed = {}
    disk_paths = []
    started = time.monotonic()
    try:
        try:
            run = subprocess.run([str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'agent',
                                  '--launch', 'vault-test', '--limit', 'wall=40s',
                                  '--workspace', str(workspace), '--', '/bin/sh', '-c',
                                  fetch_script(address, port)],
                                 env=env, capture_output=True, text=True, timeout=900)
            observed.update(run_exit=run.returncode, stdout=run.stdout, stderr=run.stderr)
        except subprocess.TimeoutExpired as error:
            observed.update(run_exit=None, stdout=str(error.stdout or ''), stderr='timeout')
        observed['elapsed_s'] = round(time.monotonic() - started, 1)
        server.shutdown()
        # The same boot: flush the guest's caches, then read its disk image.
        sync = subprocess.run([str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'tool',
                               '--limit', 'wall=20s', '--workspace', str(workspace), '--', '/bin/sync'],
                              env=env, capture_output=True, text=True, timeout=300)
        observed['sync_exit'] = sync.returncode
        disks = sorted((data / 'vm').glob('vm-*/image/base.raw'))
        if len(disks) == 1:
            observed['disk_scan'] = 'value-present' if file_holds(disks[0], SECRET) else 'clean'
        else:
            observed['disk_scan'] = f'not-checked: {len(disks)} boot disks found'
        disk_paths = disks
    finally:
        stop = subprocess.run([str(home / 'bin' / 'ukai-vm'), 'stop'], env=env,
                              capture_output=True, text=True, timeout=60)
        observed['stop_exit'] = stop.returncode
        source.unlink(missing_ok=True)
        source_dir.rmdir()
    vault_attempt, record = agent_attempt(data)
    if vault_attempt is not None:
        guest_path = vault_attempt / 'evidence/jail.json'
        guest = json.loads(guest_path.read_text()) if guest_path.exists() else {}
        observed.update(phase=record.get('phase'), exit=(record.get('outcome') or {}).get('code'),
                        tree_empty=(record.get('lifetime') or {}).get('tree_empty'),
                        guest_credentials=guest.get('credentials'),
                        guest_network_mode=((guest.get('applied') or {}).get('network') or {}).get('mode'))
    observed['leaks'], observed['files_scanned'] = leak_scan([data, workspace], SECRET, skip=disk_paths)
    observed['client_output_leak'] = SECRET.decode() in (observed.get('stdout', '') + observed.get('stderr', ''))
    observed['placeholder'] = placeholder(observed.get('stdout', ''))
    observed['header'] = Echo.received[0].get('x-test-token') if Echo.received else None
    facts, outcome = judge(observed)

    def redact(text):
        return str(text).replace(address, '<mac-address>')

    verdict = {'schema': 'ukai.vm.vault-consumption/2', 'binary': harness.fingerprint(jail),
               'echo_requests': len(Echo.received),
               'received_header_names': sorted(Echo.received[0]) if Echo.received else [],
               'facts': facts, 'outcome': outcome,
               'observed': {key: (redact(value) if key in ('stdout', 'stderr') else value)
                            for key, value in observed.items() if key != 'header'},
               'header_matches_value': facts['header_injected']}
    harness.write_json(out / 'vault-consumption.json', json.loads(redact(json.dumps(verdict))))
    print(json.dumps({'facts': facts, 'outcome': outcome}))
    return 0 if outcome == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
