"""harness.py: the pieces every VM-tier harness judges with.

No VM boots and no packet leaves this host: the egress probe's real source
runs against loopback targets only, and the attempt and control sockets are
in-process fakes (FakeAttemptServer) speaking the §6 protocol.

    python3 -s -E -m unittest test_harness
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import harness

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[2] / 'docs' / 'benchmarks' / 'jail' / 'results'


def probe_line(tag, control='connected', accepted=True, egress='ENETUNREACH', dns=None):
    record = {'nonce': tag, 'control': control, 'control_accepted': accepted, 'egress': egress,
              'target': ['1.1.1.1', 443]}
    if dns is not None:
        record['dns'] = dns
    return 'UKAI_NET_PROBE ' + json.dumps(record)


class ProbeVerdictTests(unittest.TestCase):
    """Each way a probe can fail to prove a denial is never a denial."""

    def test_a_denial_needs_the_positive_control(self):
        self.assertEqual(harness.probe_verdict(probe_line('t1'), 't1')['verdict'], 'egress_denied')
        self.assertTrue(harness.probe_verdict(probe_line('t1'), 't1')['denied'])

    def test_mutations_are_never_a_denial(self):
        cases = {
            'no probe line (python3 missing, /dev/tcp style shell)': ('net_refused\n', 'no_probe'),
            'control failed to connect': (probe_line('t', control='ECONNREFUSED'), 'inconclusive'),
            'control connected but never accepted': (probe_line('t', accepted=False), 'inconclusive'),
            'listener could not bind': (probe_line('t', control='listener-EPERM', accepted=False), 'inconclusive'),
            'egress connected': (probe_line('t', egress='connected'), 'egress_allowed'),
            'another run\'s probe': (probe_line('other'), 'no_probe'),
            'two probes with the tag': (probe_line('t') + '\n' + probe_line('t'), 'ambiguous'),
            'malformed json': ('UKAI_NET_PROBE {not json', 'no_probe'),
        }
        for name, (stdout, verdict) in cases.items():
            with self.subTest(name):
                result = harness.probe_verdict(stdout, 't')
                self.assertEqual(result['verdict'], verdict)
                self.assertFalse(result['denied'])

    def test_shell_text_cannot_forge_a_denial(self):
        # The old harness's `(echo > /dev/tcp/...) && echo NET_ALLOWED || echo net_refused`
        # printed net_refused for every outcome under dash; no such text counts here.
        self.assertFalse(harness.probe_verdict('net_refused\nnet_denied\n', 'x')['denied'])

    def test_only_the_jails_own_errno_is_a_denial(self):
        # Reviewer FX9: a timeout, ECONNREFUSED (a peer answered: the packet
        # left), EHOSTUNREACH and unknown errnos all counted as denials.
        self.assertEqual(harness.DENIAL_ERRNOS, ('ENETUNREACH',))
        for egress in ('timeout', 'ECONNREFUSED', 'EHOSTUNREACH', 'errno-999', 'EPERM', '', None):
            with self.subTest(egress=egress):
                verdict = harness.probe_verdict(probe_line('t', egress=egress), 't')
                self.assertEqual(verdict['verdict'], 'inconclusive')
                self.assertFalse(verdict['denied'])
        self.assertTrue(harness.probe_verdict(probe_line('t', egress='ENETUNREACH'), 't')['denied'])


class ProbeSourceTests(unittest.TestCase):
    """The probe's real source, against loopback targets only (no external network)."""

    def run_probe(self, port):
        tag = harness.nonce()
        argv = harness.probe_argv(tag, target=('127.0.0.1', port), timeout=2.0)
        argv[0] = sys.executable  # the guest's /usr/bin/python3; any python3 runs the source
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return harness.probe_verdict(done.stdout, tag)

    def test_detects_a_connection_and_a_refusal(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        open_port = listener.getsockname()[1]
        try:
            self.assertEqual(self.run_probe(open_port)['verdict'], 'egress_allowed')
        finally:
            listener.close()
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        verdict = self.run_probe(closed_port)
        # A refusal is a peer answering, not the jail: never a denial.
        self.assertEqual(verdict['verdict'], 'inconclusive')
        self.assertEqual(verdict['egress'], 'ECONNREFUSED')
        self.assertFalse(verdict['denied'])

    def test_the_shell_form_quotes_the_source(self):
        tag = harness.nonce()
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        try:
            command = harness.probe_shell(tag, target=('127.0.0.1', listener.getsockname()[1]), timeout=2.0)
            command = command.replace(harness.PYTHON, sys.executable, 1)
            # The verdict ignores the shell's status: `false ||` and `&& false` change nothing.
            done = subprocess.run(['/bin/sh', '-c', f'false || {command} && false; echo after'],
                                  capture_output=True, text=True, timeout=30)
        finally:
            listener.close()
        self.assertEqual(harness.probe_verdict(done.stdout, tag)['verdict'], 'egress_allowed')
        self.assertNotIn('/dev/tcp', command)


class FakeConnectProxy:
    """A loopback stand-in for the guest jail's proxy: answers CONNECT with `status`
    for `allowed` targets, 403 for any other; connects nowhere."""

    def __init__(self, allowed, status='200 Connection established'):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(4)
        self.allowed, self.status, self.requests = set(allowed), status, []
        threading.Thread(target=self.serve, daemon=True).start()

    @property
    def url(self):
        return 'http://127.0.0.1:%d' % self.listener.getsockname()[1]

    def serve(self):
        while True:
            try:
                stream, _ = self.listener.accept()
            except OSError:
                return
            with stream:
                head = b''
                while b'\r\n\r\n' not in head:
                    chunk = stream.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                line = head.split(b'\r\n', 1)[0].decode()
                self.requests.append(line)
                target = line.split()[1] if line.startswith('CONNECT ') else None
                status = self.status if target in self.allowed else '403 Forbidden'
                stream.sendall(f'HTTP/1.1 {status}\r\n\r\n'.encode())

    def close(self):
        self.listener.close()


class RouteControlTests(unittest.TestCase):
    """The same-boot route control (F-2): its real source against a loopback proxy."""

    TARGET = ('127.0.0.1', 9)

    def run_control(self, proxy_url, target=TARGET):
        tag = harness.nonce()
        argv = harness.route_argv(tag, target=target, timeout=3.0)
        argv[0] = sys.executable
        environment = {key: value for key, value in os.environ.items() if 'proxy' not in key.lower()}
        if proxy_url is not None:
            environment['HTTPS_PROXY'] = proxy_url
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30, env=environment)
        return harness.route_verdict(done.stdout, tag, target), done

    def test_reached_only_when_the_proxy_tunnels_to_this_target(self):
        proxy = FakeConnectProxy({'127.0.0.1:9'})
        self.addCleanup(proxy.close)
        verdict, done = self.run_control(proxy.url)
        self.assertEqual(verdict['verdict'], 'reached', done.stderr)
        self.assertEqual(proxy.requests, ['CONNECT 127.0.0.1:9 HTTP/1.1'])
        self.assertEqual(harness.route_rule(self.TARGET), '127.0.0.1:9')

    def test_every_other_answer_is_not_reached(self):
        refusing = FakeConnectProxy({'127.0.0.1:9'}, status='502 Bad Gateway')
        self.addCleanup(refusing.close)
        self.assertFalse(self.run_control(refusing.url)[0]['reached'])
        other = FakeConnectProxy({'127.0.0.1:10'})
        self.addCleanup(other.close)
        self.assertFalse(self.run_control(other.url)[0]['reached'])
        verdict, _ = self.run_control(None)
        self.assertEqual(verdict['verdict'], 'not_reached')
        self.assertIn('HTTPS_PROXY', verdict['error'])

    def test_the_verdict_reads_one_line_for_this_target(self):
        def line(tag, status='HTTP/1.1 200 Connection established', target=('1.1.1.1', 443)):
            return 'UKAI_ROUTE_CONTROL ' + json.dumps({'nonce': tag, 'target': list(target), 'status_line': status})
        with mock.patch.object(harness, 'PROBE_TARGET', ('1.1.1.1', 443)):
            self.assertTrue(harness.route_verdict(line('r'), 'r')['reached'])
            for name, stdout, verdict in [
                    ('no line', 'proxy said yes\n', 'no_control'),
                    ('another run', line('other'), 'no_control'),
                    ('two lines', line('r') + '\n' + line('r'), 'ambiguous'),
                    ('another target', line('r', target=('8.8.8.8', 443)), 'not_reached'),
                    ('a refusal', line('r', status='HTTP/1.1 403 Forbidden'), 'not_reached'),
                    ('a 2000 is not a 200', line('r', status='HTTP/1.1 2000 x'), 'not_reached'),
                    ('no status', line('r', status=None), 'not_reached')]:
                with self.subTest(name):
                    result = harness.route_verdict(stdout, 'r')
                    self.assertEqual(result['verdict'], verdict)
                    self.assertFalse(result['reached'])
            self.assertEqual(harness.route_rule(), '1.1.1.1:443')


class NetworkDenialTests(unittest.TestCase):
    """Reviewer FX4: a denial with no route at all (`unshare -rn`) is not the jail's."""

    def facts(self, **changes):
        values = dict(probe={'denied': True}, route={'reached': True}, guest_nat=True,
                      probe_guest_boot='g-1', route_guest_boot='g-1', route_bound=True)
        values.update(changes)
        return harness.network_denial(**values)

    def test_the_jails_denial_needs_every_fact(self):
        self.assertTrue(all(self.facts().values()))
        for name, changes, fact in [
                ('no NAT: no route for anyone', {'guest_nat': False}, 'guest_nat_attached'),
                ('NAT unknown', {'guest_nat': None}, 'guest_nat_attached'),
                ('the route control never reached the target', {'route': {'reached': False}}, 'route_control_reached_the_target'),
                ('no route control', {'route': None}, 'route_control_reached_the_target'),
                ('the route control ran on another boot', {'route_guest_boot': 'g-2'}, 'route_control_on_the_same_guest_boot'),
                ('no guest boot measured', {'probe_guest_boot': None, 'route_guest_boot': None}, 'route_control_on_the_same_guest_boot'),
                ('the route control receipt is another attempt\'s', {'route_bound': False}, 'route_control_receipt_bound'),
                ('the probe connected', {'probe': {'denied': False}}, 'probe_saw_the_jails_denial')]:
            with self.subTest(name):
                facts = self.facts(**changes)
                self.assertFalse(facts[fact])
                self.assertEqual([key for key, value in facts.items() if value is not True], [fact])


class ReceiptBindingTests(unittest.TestCase):
    """F-5 / reviewer FX10: only a verified receipt bound to this attempt backs a verdict."""

    ARGV = ['/bin/sh', '-c', 'echo x']

    def good(self):
        digest = harness.argv_digest(self.ARGV)
        return {'attempt_id': 'a-1', 'profile': 'tool', 'argv_digest': digest, 'boot_id': 'vm-1',
                'receipt_digest_ok': True, 'receipt': {'argv_digest': digest},
                'binding': {'attempt_id': 'a-1', 'profile': 'tool', 'argv_digest': digest, 'boot_id': 'vm-1',
                            'guest_boot_id': 'g-1', 'guest_attempt_id': 'att_1'}}

    def test_each_mismatch_unbinds(self):
        self.assertTrue(harness.receipt_bound(self.good()))
        other = harness.argv_digest(['/bin/sh', '-c', 'other'])
        for name, change in [
                ('digest mismatch', lambda r: r.update(receipt_digest_ok=False)),
                ('bound to another attempt', lambda r: r['binding'].update(attempt_id='a-2')),
                ('another argv in the binding', lambda r: r['binding'].update(argv_digest=other)),
                ('another argv in the receipt', lambda r: r['receipt'].update(argv_digest=other)),
                ('another profile', lambda r: r['binding'].update(profile='agent')),
                ('another serve boot', lambda r: r['binding'].update(boot_id='vm-2')),
                ('no serve boot', lambda r: r.update(boot_id=None)),
                ('no guest boot', lambda r: r['binding'].pop('guest_boot_id')),
                ('no binding', lambda r: r.pop('binding')),
                ('no receipt', lambda r: r.pop('receipt'))]:
            with self.subTest(name):
                record = self.good()
                change(record)
                self.assertFalse(harness.receipt_bound(record))

    def test_run_attempt_records_the_argv_digest(self):
        server = FakeAttemptServer(completing())
        self.addCleanup(server.close)
        record = harness.run_attempt(server.connect, 'a1', self.ARGV)
        self.assertEqual(record['argv_digest'], harness.argv_digest(self.ARGV))
        bound = FakeAttemptServer(completing(bound=True))
        self.addCleanup(bound.close)
        self.assertTrue(harness.receipt_bound(harness.run_attempt(bound.connect, 'a2', self.ARGV)))
        self.assertFalse(harness.receipt_bound(record), 'the default fake binding names no attempt')

    def attempt_dir(self):
        root = Path(tempfile.mkdtemp(prefix='harness-attdir-'))
        self.addCleanup(shutil.rmtree, root, True)
        attempt = root / 'att_42'
        (attempt / 'evidence').mkdir(parents=True)
        digest = harness.argv_digest(self.ARGV)
        guest = json.dumps({'argv_digest': digest}).encode()
        (attempt / 'evidence' / 'jail.json').write_bytes(guest)
        (attempt / 'vm-transport.json').write_text(json.dumps({'boot_id': 'vm-1',
                                                               'guest_receipt_sha256': hashlib.sha256(guest).hexdigest()}))
        (attempt / 'evidence' / 'vm-binding.json').write_text(json.dumps({
            'attempt_id': 'att_42', 'argv_digest': digest, 'boot_id': 'vm-1', 'guest_boot_id': 'g-1'}))
        return attempt

    def test_an_attempt_directory_binds_the_same_way(self):
        attempt = self.attempt_dir()
        self.assertTrue(harness.attempt_dir_bound(attempt, self.ARGV))
        self.assertFalse(harness.attempt_dir_bound(attempt, ['/bin/sh', '-c', 'other']))
        for name, path, change in [
                ('another attempt', 'evidence/vm-binding.json', {'attempt_id': 'att_41'}),
                ('another serve boot', 'evidence/vm-binding.json', {'boot_id': 'vm-2'}),
                ('no guest boot', 'evidence/vm-binding.json', {'guest_boot_id': None}),
                ('a receipt digest that is not this receipt', 'vm-transport.json', {'guest_receipt_sha256': '0' * 64})]:
            with self.subTest(name):
                attempt = self.attempt_dir()
                value = json.loads((attempt / path).read_text())
                value.update(change)
                (attempt / path).write_text(json.dumps(value))
                self.assertFalse(harness.attempt_dir_bound(attempt, self.ARGV))
        attempt = self.attempt_dir()
        (attempt / 'evidence' / 'jail.json').write_bytes(b'{"argv_digest": "sha256:other"}')
        self.assertFalse(harness.attempt_dir_bound(attempt, self.ARGV))


class PortableRecordTests(unittest.TestCase):
    """F-10 / reviewer FX5: no absolute home, repository or temp path in a record."""

    def test_fingerprints_and_records_carry_relative_paths(self):
        here = harness.REPOSITORY / 'crates' / 'ukai-jail' / 'vm' / 'harness.py'
        self.assertEqual(harness.fingerprint(here)['path'], 'crates/ukai-jail/vm/harness.py')
        home = str(Path.home())
        self.assertEqual(harness.relative_path(Path.home() / 'ukai-ws' / 'w'), '~/ukai-ws/w')
        self.assertEqual(harness.relative_path('/usr/bin/python3'), '/usr/bin/python3')
        root = Path(tempfile.mkdtemp(prefix='harness-portable-'))
        self.addCleanup(shutil.rmtree, root, True)
        record = {'status': {'live_workspace': f'{home}/ukai-ws/w'},
                  'stderr': f'opened {harness.REPOSITORY}/crates/x and {root}/data/vm.sock',
                  'list': [str(harness.REPOSITORY), str(Path.home())], 'n': 3}
        harness.write_json(root / 'r.json', record)
        text = (root / 'r.json').read_text()
        self.assertNotIn(home, text)
        self.assertNotIn(str(Path(tempfile.gettempdir()).resolve()), text)
        written = json.loads(text)
        self.assertEqual(written['status']['live_workspace'], '~/ukai-ws/w')
        self.assertEqual(written['stderr'], f'opened crates/x and $TMPDIR/{root.name}/data/vm.sock')
        self.assertEqual(written['list'], ['.', '~'])
        self.assertEqual(written['n'], 3)


class VmClientRuleTests(unittest.TestCase):
    """S1's carry rule, as every harness `ukai-jail run --vm` must meet it."""

    def test_the_environment_admits_lang_only(self):
        base = {'TERM': 'dumb', 'TZ': 'UTC', 'LC_CTYPE': 'UTF-8', 'LC_ALL': 'C', 'LANG': 'fr_FR.UTF-8',
                'UKAI_VM_GUEST_NAT': '1', 'PATH': '/bin', 'HOME': '/h'}
        environment = harness.vm_client_environment(base, UKAI_DATA_DIR=Path('/d'))
        self.assertEqual(environment, {'LANG': 'C.UTF-8', 'PATH': '/bin', 'HOME': '/h', 'UKAI_DATA_DIR': '/d'})
        self.assertEqual(base['TERM'], 'dumb', 'the caller\'s mapping is not modified')

    def test_the_wall_is_whole_seconds_up_to_300(self):
        self.assertEqual(harness.vm_wall(300), ['--limit', 'wall=300s'])
        for bad in (0, 301, 2.5, '20', None):
            with self.subTest(bad=bad), self.assertRaises(harness.HarnessError):
                harness.vm_wall(bad)

    def test_refusal_codes_are_found_and_named(self):
        text = ('ukai-jail: refused at probing [unsupported]: vm:not-measured:limit:wall, '
                'vm:not-measured:network_none; vm:not-carried:environment.TERM\n')
        self.assertEqual(harness.vm_refusals(text), ['vm:not-carried:environment.TERM',
                                                     'vm:not-measured:limit:wall', 'vm:not-measured:network_none'])
        self.assertEqual(harness.vm_refusals('settled · exited 0'), [])

    def test_the_standard_input_refusal_is_a_recorded_refusal(self):
        # S1's F11d text (platform/macos/vm.rs), one per kind it names.
        for kind in ('a pipe', 'a file', 'a socket', 'a character device other than /dev/null',
                     'a descriptor that cannot be inspected', 'neither a terminal nor /dev/null'):
            with self.subTest(kind):
                text = (f'ukai-jail: refused at preparing [invalid_config]: --vm: standard input is {kind}, '
                        "and the guest jail's standard input is /dev/null: nothing written to it would "
                        'reach the target; run with `</dev/null`, or without --vm\n')
                self.assertEqual(harness.vm_refusals(text), [f'--vm: standard input is {kind}'])
                self.assertTrue(harness.stdin_refused(harness.vm_refusals(text)))
        both = harness.vm_refusals('vm:not-measured:limit:wall\n--vm: standard input is a pipe, and the '
                                   "guest jail's standard input is /dev/null: ...")
        self.assertEqual(both, ['--vm: standard input is a pipe', 'vm:not-measured:limit:wall'])
        self.assertFalse(harness.stdin_refused(['vm:not-measured:limit:wall']))
        self.assertFalse(harness.stdin_refused(None))
        # The guest's own words about its standard input are no refusal.
        self.assertEqual(harness.vm_refusals('the standard input is /dev/null'), [])


class WorkspaceGuardTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='harness-guard-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.workspace = self.root / 'ws'
        self.workspace.mkdir()

    def test_mark_then_guard_then_clean(self):
        harness.mark_workspace(self.workspace)
        (self.workspace / 'stale.txt').write_text('old')
        (self.workspace / 'keep-me').write_text('binary')
        (self.workspace / 'dir').mkdir()
        (self.workspace / 'dir' / 'f').write_text('x')
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'precious').write_text('never removed')
        (self.workspace / 'link').symlink_to(outside)
        removed = harness.clean_workspace(self.workspace, keep=('keep-me',))
        self.assertEqual(sorted(removed), ['dir', 'link', 'stale.txt'])
        self.assertEqual(sorted(p.name for p in self.workspace.iterdir()),
                         sorted([harness.WORKSPACE_MARKER, 'keep-me']))
        self.assertEqual((outside / 'precious').read_text(), 'never removed')

    def test_unmarked_and_wrongly_marked_directories_refuse(self):
        with self.assertRaisesRegex(harness.HarnessError, 'no .ukai-vm-harness-workspace'):
            harness.clean_workspace(self.workspace)
        marker = self.workspace / harness.WORKSPACE_MARKER
        marker.write_text('something else\n')
        with self.assertRaisesRegex(harness.HarnessError, 'does not carry'):
            harness.guarded_workspace(self.workspace)
        marker.unlink()
        real = self.root / 'real-marker'
        real.write_text(harness.WORKSPACE_MARKER_TEXT)
        marker.symlink_to(real)
        with self.assertRaisesRegex(harness.HarnessError, 'regular single-link'):
            harness.guarded_workspace(self.workspace)
        marker.unlink()
        os.link(real, marker)
        with self.assertRaisesRegex(harness.HarnessError, 'regular single-link'):
            harness.guarded_workspace(self.workspace)

    def test_mark_needs_an_empty_directory(self):
        (self.workspace / 'something').write_text('x')
        with self.assertRaisesRegex(harness.HarnessError, 'not empty'):
            harness.mark_workspace(self.workspace)

    def test_a_marked_directory_holding_the_cwd_refuses(self):
        # Reviewer H8 and FX7: the cwd (and home, the repository) or any of
        # their ancestors never qualify, marker or not.
        harness.mark_workspace(self.workspace)
        inside = self.workspace / 'project'
        inside.mkdir()
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        for here in (inside, self.workspace):
            with self.subTest(cwd=here):
                os.chdir(here)
                with self.assertRaisesRegex(harness.HarnessError, 'is or contains'):
                    harness.guarded_workspace(self.workspace)
        os.chdir(cwd)
        self.assertEqual(harness.guarded_workspace(self.workspace), self.workspace)

    def test_a_marked_directory_inside_the_repository_refuses(self):
        # Reviewer H10: with REPOSITORY pointed at a scratch tree.
        repo = self.root / 'repo'
        inside = repo / 'crates' / 'ws'
        inside.mkdir(parents=True)
        harness.mark_workspace(inside)
        with mock.patch.object(harness, 'REPOSITORY', repo):
            with self.assertRaisesRegex(harness.HarnessError, 'inside the repository'):
                harness.guarded_workspace(inside)

    def test_reviewer_fx7_guard_cases(self):
        harness.mark_workspace(self.workspace)
        (self.root / 'link-home').symlink_to(Path.home())
        (self.root / 'link-ws').symlink_to(self.workspace)
        for path in (str(self.root / 'link-home'), str(self.root / 'link-home') + '/', str(self.root / 'link-ws'),
                     'ws', str(harness.REPOSITORY), str(Path.home()), str(harness.REPOSITORY / 'crates/ukai-jail/vm')):
            with self.subTest(path=path), self.assertRaises((harness.HarnessError, OSError)):
                harness.guarded_workspace(path)
        moved = self.root / 'ws.moved'
        self.workspace.rename(moved)
        precious = self.root / 'precious'
        precious.mkdir()
        self.workspace.symlink_to(precious)
        with self.assertRaises(harness.HarnessError):
            harness.guarded_workspace(self.workspace)

    def test_protected_places_refuse_even_when_marked(self):
        for path in ('relative/dir', '/', str(Path.home()), str(harness.REPOSITORY),
                     str(harness.REPOSITORY / 'crates'), str(Path.home().parent)):
            with self.subTest(path=path):
                with self.assertRaises(harness.HarnessError):
                    harness.guarded_workspace(path)
        link = self.root / 'ws-link'
        link.symlink_to(self.workspace)
        harness.mark_workspace(self.workspace)
        with self.assertRaisesRegex(harness.HarnessError, 'symlink'):
            harness.guarded_workspace(link)


class OutputTests(unittest.TestCase):
    def test_an_output_directory_and_record_are_never_reused(self):
        root = Path(tempfile.mkdtemp(prefix='harness-out-'))
        self.addCleanup(shutil.rmtree, root, True)
        out = harness.fresh_out_dir(root / 'run')
        harness.write_json(out / 'record.json', {'a': 1})
        with self.assertRaisesRegex(harness.HarnessError, 'previous run'):
            harness.fresh_out_dir(root / 'run')
        with self.assertRaises(FileExistsError):
            harness.write_json(out / 'record.json', {'a': 2})
        self.assertEqual(json.loads((out / 'record.json').read_text()), {'a': 1})

    def test_no_binary_default(self):
        environment = {key: value for key, value in os.environ.items() if key != 'UKAI_VM_BINARY'}
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(harness.HarnessError, 'no default'):
                harness.required_binary('UKAI_VM_BINARY')
        self.assertEqual(harness.required_binary('X', sys.executable), Path(sys.executable).resolve())

    def test_a_binary_must_be_an_executable_file(self):
        # Reviewer H15.
        root = Path(tempfile.mkdtemp(prefix='harness-bin-'))
        self.addCleanup(shutil.rmtree, root, True)
        plain = root / 'plain'
        plain.write_text('#!/bin/sh\n')
        plain.chmod(0o644)
        for path in (plain, root):
            with self.subTest(path=path), self.assertRaisesRegex(harness.HarnessError, 'not an executable file'):
                harness.required_binary('X', str(path))
        with self.assertRaises(FileNotFoundError):
            harness.required_binary('X', str(root / 'absent'))


class FakeAttemptServer:
    """The §6 attempt socket, scripted: one `script(index, request, send)` per connection."""

    def __init__(self, script, boot_id='vm-fake'):
        self.root = Path(tempfile.mkdtemp(prefix='fake-serve-'))
        self.path = self.root / 'attempt.sock'
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        self.listener.listen(8)
        self.script = script
        self.boot_id = boot_id
        self.closed = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        index = 0
        while True:
            try:
                stream, _ = self.listener.accept()
            except OSError:
                return
            channel = harness.Channel(stream)

            def send(**value):
                channel.send(**value)
            try:
                send(event='ready', boot_id=self.boot_id)
                request = channel.frame()
                self.script(index, request, send, channel)
            except (OSError, harness.StreamEnded):
                pass
            finally:
                self.closed.append(index)
                channel.close()
            index += 1

    def connect(self):
        return harness.connect_unix(self.path, timeout=10)

    def close(self):
        self.listener.close()
        shutil.rmtree(self.root, ignore_errors=True)


def receipt_frame(receipt, binding=None, corrupt=False):
    raw = json.dumps(receipt).encode()
    digest = hashlib.sha256(raw).hexdigest()
    return {'event': 'bound_receipt', 'sha256': ('0' * 64) if corrupt else digest,
            'data': base64.b64encode(raw).decode(),
            'binding': binding or {'guest_boot_id': 'guest-boot-1', 'argv_digest': 'sha256:x'}}


def bound_frame(request, receipt=None, boot_id='vm-fake', guest_boot='guest-boot-1', corrupt=False):
    """A bound_receipt frame as guest.py builds it for this prepare `request`."""
    words = [base64.b64decode(word) for word in request['argv']]
    digest = harness.argv_digest(words)
    receipt = dict(receipt or {}, argv_digest=digest)
    return receipt_frame(receipt, corrupt=corrupt, binding={
        'attempt_id': request['attempt_id'], 'boot_id': boot_id, 'guest_attempt_id': 'att_' + request['attempt_id'],
        'guest_boot_id': guest_boot, 'profile': request['profile'], 'argv_digest': digest})


def completing(stdout=b'hello\n', exit_code=0, corrupt=False, bound=False):
    def script(index, request, send, channel):
        send(event='prepared', kernel='k', staged_secrets=[])
        assert channel.frame()['op'] == 'run'
        send(event='released', supervisor_pid=7)
        send(event='stdout', data=base64.b64encode(stdout).decode())
        receipt = {'outcome': {'code': exit_code}}
        send(**(bound_frame(request, receipt, corrupt=corrupt) if bound
                else receipt_frame(receipt, corrupt=corrupt)))
        send(event='done', exit_code=exit_code)
    return script


class ChannelTests(unittest.TestCase):
    def test_two_streams_never_share_a_buffer(self):
        # fault_matrix.frame(s, buf=[b'']) shared one default buffer between
        # sockets: a frame left over from one stream was read as another's.
        a_local, a_peer = socket.socketpair()
        b_local, b_peer = socket.socketpair()
        a_peer.sendall(b'{"from": "a", "n": 1}\n{"from": "a", "n": 2}\n')
        b_peer.sendall(b'{"from": "b", "n": 1}\n')
        a, b = harness.Channel(a_local), harness.Channel(b_local)
        self.assertEqual(a.frame(), {'from': 'a', 'n': 1})
        self.assertEqual(b.frame(), {'from': 'b', 'n': 1})
        self.assertEqual(a.frame(), {'from': 'a', 'n': 2})
        for sock in (a_local, a_peer, b_local, b_peer):
            sock.close()

    def test_end_of_stream_is_named(self):
        local, peer = socket.socketpair()
        peer.sendall(b'{"partial":')
        peer.close()
        with self.assertRaises(harness.StreamEnded):
            harness.Channel(local).frame()
        local.close()


class RunAttemptTests(unittest.TestCase):
    def test_a_completed_attempt_is_recorded_with_its_receipt(self):
        server = FakeAttemptServer(completing())
        self.addCleanup(server.close)
        record = harness.run_attempt(server.connect, 'a1', ['/bin/sh', '-c', 'echo hello'])
        self.assertEqual(record['exit_code'], 0)
        self.assertEqual(record['stdout'], 'hello\n')
        self.assertTrue(record['receipt_digest_ok'])
        self.assertEqual(harness.guest_boot(record), 'guest-boot-1')
        self.assertEqual(record['boot_id'], 'vm-fake')
        for key in ('connect_to_released', 'run_to_released', 'prepare_to_released', 'released_to_done'):
            self.assertIsNotNone(record['timings_ms'][key], key)

    def test_a_receipt_digest_mismatch_is_seen(self):
        server = FakeAttemptServer(completing(corrupt=True))
        self.addCleanup(server.close)
        self.assertFalse(harness.run_attempt(server.connect, 'a1', ['true'])['receipt_digest_ok'])

    def test_a_dropped_attempt_is_a_record_with_an_error(self):
        def drop(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
        server = FakeAttemptServer(drop)
        self.addCleanup(server.close)
        record = harness.run_attempt(server.connect, 'a1', ['true'])
        self.assertIsNone(record['exit_code'])
        self.assertIn('StreamEnded', record['error'])

    def test_the_argv_crosses_base64_encoded(self):
        seen = {}

        def capture(index, request, send, channel):
            seen.update(request)
        server = FakeAttemptServer(capture)
        self.addCleanup(server.close)
        harness.run_attempt(server.connect, 'a1', ['/bin/sh', '-c', 'x y'], secrets=[('id/one', b'v')])
        self.assertEqual([base64.b64decode(word) for word in seen['argv']], [b'/bin/sh', b'-c', b'x y'])
        self.assertEqual(seen['secrets'], [{'id': 'id/one', 'data': base64.b64encode(b'v').decode()}])


class HeartbeatTests(unittest.TestCase):
    """The K110 workload: a leader with descendants, beating into the workspace."""

    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix='harness-beats-'))
        self.addCleanup(shutil.rmtree, self.workspace, True)
        shim = self.workspace / '.bin'
        shim.mkdir()
        # The guest's GNU date prints nanoseconds; macOS date does not.
        (shim / 'date').write_text(f'#!/bin/sh\nexec {sys.executable} -c "import time; print(time.time_ns())"\n')
        (shim / 'date').chmod(0o755)
        self.environment = dict(os.environ, PATH=f'{shim}:/usr/bin:/bin')

    def start(self, marker, beats):
        return subprocess.Popen(['/bin/sh', '-c', harness.heartbeat_script(marker, beats=beats)],
                                cwd=self.workspace, env=self.environment, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True, text=True)

    def test_a_bounded_workload_beats_from_every_process_then_finishes(self):
        process = self.start('m1', beats=8)
        watch = harness.BeatWatch(self.workspace, 'm1')
        self.assertTrue(watch.wait_beating(10))
        out, _ = process.communicate(timeout=20)
        self.assertEqual(process.returncode, 0)
        self.assertIn('hb-m1-done', out)
        quiet, last = watch.wait_quiet(0.5, 5)
        self.assertTrue(quiet)

    def test_killing_the_group_stops_every_descendant(self):
        process = self.start('m2', beats=None)
        watch = harness.BeatWatch(self.workspace, 'm2')
        self.assertTrue(watch.wait_beating(10))
        # Killing only the leader leaves the children beating: the watch sees it.
        os.kill(process.pid, signal.SIGKILL)
        quiet, _ = watch.wait_quiet(1.0, 2.5)
        self.assertFalse(quiet, 'the descendants kept beating after the leader died')
        killed_at = time.monotonic()
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        quiet, last = watch.wait_quiet(1.0, 10)
        process.stdout.close()
        self.assertTrue(quiet)
        self.assertLess(last - killed_at, 1.0)

    def test_first_sight_is_not_a_beat_and_changes_are_dated(self):
        # Reviewer H28 and H30, on a fake clock: a file seen once has not
        # beaten, and changed_since() counts only changes after its moment.
        now = [100.0]
        watch = harness.BeatWatch(self.workspace, 'm3', children=0, clock=lambda: now[0], sleep=lambda _: None)
        beat = self.workspace / 'hb-m3-0'
        beat.write_text('1')
        watch.poll()
        self.assertFalse(watch.all_beating())
        self.assertEqual(watch.changed_since(0.0), [])
        now[0] = 101.0
        watch.poll()
        self.assertEqual(watch.changed_since(0.0), [], 'unchanged bytes are no beat')
        now[0] = 102.0
        beat.write_text('2')
        watch.poll()
        self.assertTrue(watch.all_beating())
        self.assertEqual(watch.changed_since(101.5), ['hb-m3-0'])
        self.assertEqual(watch.changed_since(102.0), [])
        self.assertEqual(watch.changed_since(103.0), [])


class ClientProcessTests(unittest.TestCase):
    def test_a_killed_client_ends_the_attempt_by_eof(self):
        released = threading.Event()
        ended = threading.Event()

        def hold(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            released.set()
            try:
                channel.frame()
            except harness.StreamEnded:
                ended.set()
        server = FakeAttemptServer(hold)
        self.addCleanup(server.close)
        client = harness.ClientProcess(server.path, 'c1', ['sleep', '60'], 60)
        self.assertIsNotNone(client.wait_event('released', 10))
        self.assertIsNotNone(client.capture_identity())
        harness.signal_checked(client.process.pid, client.identity, signal.SIGKILL)
        self.assertTrue(ended.wait(5), 'the server never saw the lease end')
        self.assertEqual(client.finish(), -signal.SIGKILL)
        self.assertFalse(client.ended_by_itself())

    def test_a_ctrl_z_suspends_without_ending_and_resume_completes(self):
        go = threading.Event()

        def slow(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            go.wait(10)
            send(event='done', exit_code=0)
        server = FakeAttemptServer(slow)
        self.addCleanup(server.close)
        client = harness.ClientProcess(server.path, 'c2', ['true'], 60)
        self.assertIsNotNone(client.wait_event('released', 10))
        os.killpg(os.getpgid(client.process.pid), signal.SIGTSTP)
        time.sleep(0.3)
        state = subprocess.run(['ps', '-p', str(client.process.pid), '-o', 'stat='],
                               capture_output=True, text=True).stdout.strip()
        self.assertTrue(state.startswith('T'), state)
        go.set()
        os.killpg(os.getpgid(client.process.pid), signal.SIGCONT)
        self.assertEqual((client.wait_event('done', 10) or {}).get('exit_code'), 0)
        self.assertEqual(client.finish(), 0)

    def test_a_kill_of_a_recycled_pid_refuses(self):
        with self.assertRaisesRegex(harness.HarnessError, 'not signalled'):
            harness.signal_checked(os.getpid(), 'Mon Jan  1 00:00:00 1990 not-this', signal.SIGTERM)

    def test_wait_gone_sees_a_live_process_and_its_death(self):
        # Reviewer H26: every "gone" fact rests on wait_gone telling alive from gone.
        process = subprocess.Popen(['sleep', '30'])
        self.addCleanup(lambda: (process.poll() is None and process.kill(), process.wait()))
        ident = harness.identity(process.pid)
        self.assertIsNotNone(ident)
        self.assertIsNone(harness.wait_gone([(process.pid, ident)], 0.3))
        process.kill()
        process.wait()
        self.assertIsNotNone(harness.wait_gone([(process.pid, ident)], 5))

    def test_the_client_records_when_its_stream_ended_and_its_receipt(self):
        go = threading.Event()

        def finish(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            go.wait(10)
            send(**bound_frame(request, boot_id='vm-fake'))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(finish)
        self.addCleanup(server.close)
        client = harness.ClientProcess(server.path, 'c3', ['true'], 60)
        self.assertIsNotNone(client.wait_event('released', 10))
        self.assertIsNone(client.wait_exit(0.2), 'wait_exit never kills')
        self.assertIsNone(client.process.poll())
        go.set()
        self.assertEqual(client.wait_exit(10), 0)
        client.finish()
        self.assertTrue(client.receipt_bound())
        self.assertIsNone(client.ended_at())

        def drop(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
        server = FakeAttemptServer(drop)
        self.addCleanup(server.close)
        before = time.monotonic()
        client = harness.ClientProcess(server.path, 'c4', ['true'], 60)
        client.finish()
        self.assertGreaterEqual(client.ended_at(), before)
        self.assertFalse(client.receipt_bound())

    def test_the_client_refuses_a_receipt_bound_elsewhere(self):
        def other(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            send(**bound_frame(dict(request, attempt_id='someone-else')))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(other)
        self.addCleanup(server.close)
        client = harness.ClientProcess(server.path, 'c5', ['true'], 60)
        client.finish()
        self.assertFalse(client.receipt_bound())

        def corrupt(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            send(**bound_frame(request, corrupt=True))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(corrupt)
        self.addCleanup(server.close)
        client = harness.ClientProcess(server.path, 'c6', ['true'], 60)
        client.finish()
        self.assertFalse(client.receipt_bound())


class ProcessTableTests(unittest.TestCase):
    def test_only_this_boots_image_binaries_are_its_controllers(self):
        # Reviewer H27: a command that merely mentions vz or custodian, or
        # runs another boot's copy, is not this boot's.
        boot = Path('/d/vm/vm-1')
        table = [{'pid': 10, 'command': '/d/vm/vm-1/image/custodian --lease 3'},
                 {'pid': 11, 'command': '/d/vm/vm-1/image/vz'},
                 {'pid': 12, 'command': '/d/vm/vm-2/image/vz'},
                 {'pid': 13, 'command': '/usr/bin/vzdump /d/vm/vm-1/image/vz'},
                 {'pid': 14, 'command': '/d/vm/vm-1/image/vz-helper'},
                 {'pid': 15, 'command': 'python3 custodian.py'}]
        self.assertEqual(harness.boot_processes(boot, table), {'custodian': [10], 'vz': [11]})


class ReceiptRecordTests(unittest.TestCase):
    """Checked against the committed 2026-11-03 evidence the review judged."""

    def test_the_argv_digest_is_the_receipts_own_construction(self):
        binding = json.loads((EVIDENCE / 'macos-vm-installed-2026-11-03/k111-attempt/evidence/vm-binding.json').read_text())
        self.assertEqual(harness.argv_digest(['/bin/sh', '-c', 'printf "row-k111\\n" > k111.txt; echo row-k111-done']),
                         binding['argv_digest'])
        self.assertNotEqual(harness.argv_digest(['/bin/sh', '-c', 'something else']), binding['argv_digest'])

    def test_the_k113_host_receipt_contradicts_its_guest_receipt(self):
        attempt = EVIDENCE / 'macos-vm-claude-2026-11-03/k113-attempt'
        host = json.loads((attempt / 'jail.json').read_text())
        guest = json.loads((attempt / 'evidence/jail.json').read_text())
        fields = {entry['field'] for entry in harness.receipt_contradictions(host, guest)}
        self.assertTrue({'applied.network', 'observer', 'coverage', 'platform.kernel'} <= fields, fields)
        mirrored = json.loads(json.dumps(host))
        for key in ('platform', 'exec_observed', 'observer', 'coverage', 'outcome'):
            mirrored[key] = guest.get(key)
        mirrored['applied'] = dict(guest['applied'], terminal='host-own')  # the host keeps its terminal
        self.assertEqual(harness.receipt_contradictions(mirrored, guest), [])
        # A marker never excuses a difference.
        mirrored['observer'] = {'carried_by': 'guest', 'guest_carried': True}
        self.assertEqual([entry['field'] for entry in harness.receipt_contradictions(mirrored, guest)], ['observer'])

    def test_the_k113_run_summary_states_no_guest_fact(self):
        attempt = EVIDENCE / 'macos-vm-claude-2026-11-03/k113-attempt'
        guest = json.loads((attempt / 'evidence/jail.json').read_text())
        transport = json.loads((attempt / 'vm-transport.json').read_text())
        text = json.loads((EVIDENCE / 'macos-vm-claude-2026-11-03/k113-claude.json').read_text())['stdout_tail']
        facts = harness.summary_facts(text, guest, transport)
        self.assertTrue(facts['transport_line_from_record'])
        self.assertFalse(facts['network_line_is_the_guests'])        # "network: not applied"
        self.assertFalse(facts['observer_classes_are_the_guests'])   # "0/6 classes active"
        self.assertFalse(facts['observer_attachment_is_the_guests'])  # "observer not attached"
        fixed = (text.replace('network: not applied', 'network: allowed api.anthropic.com (4)')
                 .replace('observer not attached · 0/6 classes active', '6/6 classes active, no gaps'))
        self.assertTrue(all(harness.summary_facts(fixed, guest, transport).values()))
        self.assertFalse(harness.summary_facts('', guest, transport)['transport_line_present'])
        forged = text.replace(transport['boot_id'], 'vm-forged')
        self.assertFalse(harness.summary_facts(forged, guest, transport)['transport_line_from_record'])


class SummaryNetworkLineTests(unittest.TestCase):
    """The network line states the guest's applied mode (summary.rs's spellings)."""

    def facts(self, line, mode, proxy_active=True):
        guest = {'applied': {'network': {'mode': mode}}, 'observer': {'attached': True},
                 'coverage': {'proxy.net': {'status': 'active' if proxy_active else 'inactive'}}}
        return harness.summary_facts(f'network: {line}\nevidence: 1/6 classes active\n', guest, {})

    def test_none_is_exactly_none(self):
        # Reviewer H20.
        self.assertTrue(self.facts('none', 'none')['network_line_is_the_guests'])
        for line in ('not applied', 'proxy, no connections', 'host, not observed', 'none recorded'):
            with self.subTest(line=line):
                self.assertFalse(self.facts(line, 'none')['network_line_is_the_guests'])

    def test_proxy_lines(self):
        # Reviewer FX6: a disagreement is never the guest's line.
        for line in ('allowed api.anthropic.com (4)', 'denied example.com (1)',
                     'allowed a.test (2) · denied b.test (1)', 'proxy, no connections',
                     'proxy, none recorded (a lower bound)',
                     'allowed a.test (2) · 1 refused for resolver capacity, not policy'):
            with self.subTest(line=line):
                self.assertTrue(self.facts(line, 'proxy')['network_line_is_the_guests'])
        for line in ('proxy, journal and receipt disagree on proxy.net', 'not applied', 'none',
                     'host, not observed', 'proxy, not observed', 'proxy, journal missing',
                     'allowed a.test (2) · journal and receipt disagree on proxy.net'):
            with self.subTest(line=line):
                self.assertFalse(self.facts(line, 'proxy')['network_line_is_the_guests'])
        self.assertTrue(self.facts('proxy, not observed', 'proxy', proxy_active=False)['network_line_is_the_guests'])
        self.assertFalse(self.facts('allowed a.test (2)', 'proxy', proxy_active=False)['network_line_is_the_guests'])


if __name__ == '__main__':
    unittest.main()
