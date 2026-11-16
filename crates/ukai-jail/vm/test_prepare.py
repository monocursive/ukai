import hashlib
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import prepare


class VirtualDiskAttachmentTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                         'requires the macOS Virtualization SDK')
    def test_actual_disk_attachments_use_cached_full_and_preserve_read_only(self):
        # Compile the actual production declarations, excluding only the entry
        # point that starts a VM. Constructing storage attachments boots nothing.
        source = (Path(prepare.__file__).parent / 'vz.swift').read_text()
        declarations, entry = source.rsplit('\ndo {\n', 1)
        self.assertIn('Runner(arguments:', entry)
        self.assertIn('attachment: try diskAttachment(', declarations)
        probe = r'''
let url = URL(fileURLWithPath: CommandLine.arguments[1])
var rows = [[String: Any]]()
for readOnly in [false, true] {
    let previous = try VZDiskImageStorageDeviceAttachment(url: url, readOnly: readOnly)
    let current = try diskAttachment(url: url, readOnly: readOnly)
    rows.append(["read_only_requested": readOnly,
        "old_cache": previous.cachingMode.rawValue,
        "old_sync": previous.synchronizationMode.rawValue,
        "old_read_only": previous.isReadOnly,
        "new_cache": current.cachingMode.rawValue,
        "new_sync": current.synchronizationMode.rawValue,
        "new_read_only": current.isReadOnly])
}
print(String(data: try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys]),
             encoding: .utf8)!)
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            swift, binary, raw = root / 'probe.swift', root / 'probe', root / 'disk.raw'
            swift.write_text(declarations + probe)
            original = bytes(range(256)) * 16
            raw.write_bytes(original)
            compiled = subprocess.run(['swiftc', '-warnings-as-errors', '-O', str(swift),
                                       '-o', str(binary)], capture_output=True, timeout=120)
            self.assertEqual((compiled.returncode, compiled.stderr), (0, b''))
            observed = subprocess.run([str(binary), str(raw)], capture_output=True, timeout=10)
            self.assertEqual((observed.returncode, observed.stderr), (0, b''))
            rows = json.loads(observed.stdout)
            self.assertEqual(len(rows), 2)
            for row, read_only in zip(rows, (False, True)):
                self.assertIs(row['read_only_requested'], read_only)
                self.assertIs(row['old_read_only'], read_only)
                self.assertIs(row['new_read_only'], read_only)
                self.assertEqual(row['new_cache'], 2)  # VZDiskImageCachingModeCached
                self.assertEqual(row['new_sync'], 1)   # VZDiskImageSynchronizationModeFull
            self.assertEqual(raw.read_bytes(), original)
            print('VZ_ATTACHMENT_SDK ' + observed.stdout.decode().strip())


class AptSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = self.root / 'sources.list.d'
        self.sources.mkdir()
        self.own = self.sources / 'ukai-snapshot.sources'
        self.own.write_text(prepare.snapshot_sources())
        self.digest = hashlib.sha256(self.own.read_bytes()).hexdigest()

    def guard(self, expected=None):
        result = subprocess.run([sys.executable, '-I', '-B', '-c', prepare.APT_SOURCE_GUARD,
                                 str(self.root), self.digest], capture_output=True, timeout=10)
        self.assertEqual(result.stdout, b'')
        if expected is None:
            self.assertEqual((result.returncode, result.stderr), (0, b''))
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, f'ukai apt source guard: {expected}\n'.encode())

    def test_authenticated_image_snapshot_and_signed_jail_pins_are_coherent(self):
        self.assertEqual(prepare.IMAGE_URL, 'https://cloud-images.ubuntu.com/minimal/releases/'
                         'stonking/release-20261105/ubuntu-26.10-minimal-cloudimg-arm64.img')
        self.assertEqual(prepare.IMAGE_SHA256, 'bac15af78c37fec8e9474a9a784041c13ddb2603b9095435b7e4269e3faf3064')
        self.assertEqual(prepare.NATIVE_JAIL_SHA256, 'c0c1f0e7cecb1fabe9c4ff42f9ae4534e24b16cb9dc0cf5ab21f4d827db6e38f')
        self.assertEqual(prepare.SNAPSHOT, '20261106T000000Z')
        self.assertEqual(prepare.snapshot_sources(),
                         'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/20261106T000000Z\n'
                         'Suites: stonking stonking-updates stonking-security\n'
                         'Components: main universe\n'
                         'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n')

    def test_exact_snapshot_and_only_blank_or_comment_sources_pass(self):
        self.guard()
        (self.root / 'sources.list').write_bytes(b'\n \t# old source disabled\r\n')
        (self.sources / 'empty.list').write_bytes(b'')
        (self.sources / 'comments.sources').write_bytes(b'# Types: deb\n\t\r\n')
        # APT does not treat this suffix as an active source file.
        (self.sources / 'old.sources.save').write_bytes(b'not an active source\n')
        self.guard()

    def test_unexpected_legacy_and_deb822_sources_refuse_without_mutation(self):
        for name, raw in [('sources.list', b'deb https://example.invalid resolute main\n'),
                          ('old.list', b'deb-src https://example.invalid stonking main\n'),
                          ('old.sources', b'Types: deb\nURIs: https://example.invalid\nSuites: resolute\n'),
                          ('disabled.sources', b'Enabled: no\nTypes: deb\n')]:
            with self.subTest(name=name):
                path = (self.root if name == 'sources.list' else self.sources) / name
                path.write_bytes(raw)
                self.guard('unexpected_source')
                self.assertEqual(path.read_bytes(), raw)
                path.unlink()

    def test_missing_or_modified_own_snapshot_refuses(self):
        self.own.write_text(prepare.snapshot_sources().replace('stonking-updates', 'resolute-updates'))
        self.guard('snapshot_mismatch')
        self.own.unlink()
        self.guard('snapshot_missing')

    def test_source_symlinks_and_special_files_refuse_without_following(self):
        outside = self.root / 'outside'
        raw = b'PUBLIC_TEST_SOURCE_CONTENT_MUST_NOT_BE_PRINTED\n'
        outside.write_bytes(raw)
        for path in (self.root / 'sources.list', self.sources / 'other.sources'):
            with self.subTest(path=path.name):
                path.symlink_to(outside)
                self.guard('source_io')
                self.assertEqual(outside.read_bytes(), raw)
                path.unlink()
        special = self.sources / 'special.list'
        os.mkfifo(special)
        self.guard('file_type')
        special.unlink()
        special.mkdir()
        self.guard('file_type')

    def test_symlink_source_directory_refuses(self):
        moved = self.root / 'moved'
        self.sources.rename(moved)
        self.sources.symlink_to(moved, target_is_directory=True)
        self.guard('source_io')

    def test_unreadable_source_refuses(self):
        if os.geteuid() == 0:
            self.skipTest('root bypasses fixture file read permissions')
        other = self.sources / 'unreadable.list'
        other.write_bytes(b'# comment\n')
        other.chmod(0)
        self.addCleanup(other.chmod, 0o600)
        self.guard('source_io')

    def test_file_and_aggregate_byte_caps_refuse(self):
        other = self.sources / 'large.list'
        other.write_bytes(b'#' + b' ' * 65536)
        self.guard('byte_limit')
        other.unlink()
        for number in range(16):
            (self.sources / f'{number}.list').write_bytes(b'#' + b' ' * 65535)
        self.guard('byte_limit')

    def test_file_count_and_directory_enumeration_are_bounded(self):
        (self.root / 'sources.list').write_bytes(b'')
        for number in range(63):
            (self.sources / f'{number}.list').write_bytes(b'')
        self.guard('file_count')
        for path in self.sources.glob('*.list'):
            path.unlink()
        (self.root / 'sources.list').unlink()
        for number in range(64):
            (self.sources / f'{number}.save').write_bytes(b'')
        self.guard('directory_count')

    def test_generated_update_runs_exact_guard_before_apt_without_other_removals(self):
        script = prepare.apt_update_script()
        self.assertIn(prepare.snapshot_sources() + 'UKAI_APT_SNAPSHOT\n', script)
        marker = f"python3 - /etc/apt {self.digest} <<'UKAI_APT_SOURCE_GUARD'\n"
        self.assertIn(marker + prepare.APT_SOURCE_GUARD + 'UKAI_APT_SOURCE_GUARD\n', script)
        self.assertLess(script.index('rm -f /etc/apt/sources.list.d/ubuntu.sources'), script.index(marker))
        self.assertLess(script.index(marker), script.index('apt-get update'))
        self.assertEqual([line for line in script.splitlines() if line.startswith('rm ')],
                         ['rm -f /etc/apt/sources.list.d/ubuntu.sources'])
        result = subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
        # The actual setup uses this renderer rather than a second source stanza.
        import inspect
        self.assertIn('{apt_update_script()}echo UKAI_STEP apt_install', inspect.getsource(prepare.main))


class SessionBusPreparationTests(unittest.TestCase):
    # Exact files inspected in the authenticated Ubuntu packages; no systemd
    # command or guest process is executed by these fixtures.
    UNITS = {
        'dbus.service': '[Unit]\nDescription=D-Bus User Message Bus\nDocumentation=man:dbus-daemon(1)\n'
            'Requires=dbus.socket\n\n[Service]\nType=notify\nNotifyAccess=main\n'
            'ExecStart=/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile '
            '--systemd-activation --syslog-only\nExecReload=/usr/bin/dbus-send --print-reply --session '
            '--type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig\n'
            'Slice=session.slice\n',
        'dbus.socket': '[Unit]\nDescription=D-Bus User Message Bus Socket\n\n[Socket]\n'
            'ListenStream=%t/bus\nExecStartPost=-/bin/systemctl --user set-environment '
            'DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus\n',
        'dbus-broker.service': '[Unit]\nDescription=D-Bus User Message Bus\n'
            'Documentation=man:dbus-broker-launch(1)\nDefaultDependencies=false\nAfter=dbus.socket\n'
            'Before=basic.target shutdown.target\nRequires=dbus.socket\nConflicts=shutdown.target\n\n'
            '[Service]\nType=notify-reload\nSockets=dbus.socket\n'
            'ExecStart=/usr/bin/dbus-broker-launch --scope user\nSlice=session.slice\n\n'
            '[Install]\nAlias=dbus.service\n',
    }

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.vendor = self.root / 'usr/lib/systemd/user'
        self.vendor.mkdir(parents=True)
        self.etc = self.root / 'etc/systemd/user'
        self.etc.mkdir(parents=True)
        for name, text in self.UNITS.items():
            (self.vendor / name).write_text(text)
        self.guard = {'__name__': 'guard_fixture'}
        exec(compile(prepare.SESSION_BUS_GUARD, '<session-bus-guard>', 'exec'), self.guard)

    def unit_properties(self):
        return {'FragmentPath': '/usr/lib/systemd/user/dbus.service', 'DropInPaths': '',
                'ExecStart': '{ path=/usr/bin/dbus-daemon ; argv[]=' + ' '.join(self.guard['ARGV'])
                    + ' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=123 ; code=(null) ; status=0/0 }',
                'MainPID': '123', 'Type': 'notify', 'NotifyAccess': 'main',
                'ActiveState': 'active', 'SubState': 'running'}

    @staticmethod
    def property_text(values):
        return ''.join(f'{key}={value}\n' for key, value in values.items())

    @staticmethod
    def proc_stat(birth=456):
        return b'123 (dbus-daemon) ' + b' '.join([b'S', *([b'1'] * 18), str(birth).encode()]) + b'\n'

    def process_fixture(self):
        proc = self.root / 'proc'
        process = proc / '123'
        process.mkdir(parents=True)
        (process / 'stat').write_bytes(self.proc_stat())
        (process / 'status').write_bytes(b'Name:\tdbus-daemon\nUid:\t1001\t1001\t1001\t1001\n')
        (process / 'cmdline').write_bytes(b'\0'.join(a.encode() for a in self.guard['ARGV']) + b'\0')
        (process / 'exe').symlink_to('/usr/bin/dbus-daemon')
        return proc, process

    def test_exact_packaged_units_and_known_alias_select_only_global_user_provider(self):
        check = self.guard['check_units']
        check(self.root)
        alias = self.etc / 'dbus.service'
        alias.symlink_to(self.vendor / 'dbus-broker.service')
        self.guard['check_units'] = lambda **kw: check(self.root, **kw)
        calls = []
        def disable(argv):
            calls.append(argv)
            alias.unlink()
        self.guard['command'] = disable
        self.guard['select']()
        self.assertEqual(calls, [['--global', 'disable', 'dbus-broker.service']])
        self.assertTrue((self.vendor / 'dbus-broker.service').exists())
        check(self.root)

    def test_wrong_vendor_alias_override_and_dropin_refuse_before_command(self):
        check = self.guard['check_units']
        self.guard['check_units'] = lambda **kw: check(self.root, **kw)
        self.guard['command'] = mock.Mock()
        for kind in ('vendor', 'alias', 'override', 'dropin'):
            with self.subTest(kind=kind):
                if kind == 'vendor':
                    path = self.vendor / 'dbus.service'; saved = path.read_bytes(); path.write_bytes(b'changed')
                elif kind == 'alias':
                    path = self.etc / 'dbus.service'; path.symlink_to(self.vendor / 'dbus.socket')
                elif kind == 'override':
                    path = self.etc / 'dbus.socket'; path.write_bytes(b'override')
                else:
                    path = self.etc / 'dbus.service.d'; path.mkdir()
                with self.assertRaises(ValueError): self.guard['select']()
                self.guard['command'].assert_not_called()
                if kind == 'vendor': path.write_bytes(saved)
                elif kind == 'dropin': path.rmdir()
                else: path.unlink()

    def test_alias_remaining_after_disable_refuses(self):
        check = self.guard['check_units']
        (self.etc / 'dbus.service').symlink_to(self.vendor / 'dbus-broker.service')
        self.guard['check_units'] = lambda **kw: check(self.root, **kw)
        self.guard['command'] = mock.Mock()
        with self.assertRaisesRegex(ValueError, 'unit_override'): self.guard['select']()
        self.guard['command'].assert_called_once_with(['--global', 'disable', 'dbus-broker.service'])

    def test_effective_daemon_unit_requires_exact_single_exec_and_positive_main_pid(self):
        parse = self.guard['properties']; valid = self.unit_properties()
        self.assertEqual(parse(self.property_text(valid)), 123)
        for key, value in [('FragmentPath', '/usr/lib/systemd/user/dbus-broker.service'),
                           ('DropInPaths', '/etc/systemd/user/dbus.service.d/override.conf'),
                           ('MainPID', '0'), ('MainPID', '1' * 30), ('Type', 'simple'),
                           ('ActiveState', 'inactive'), ('ExecStart', valid['ExecStart'].replace('--nofork', '--fork')),
                           ('ExecStart', valid['ExecStart'] + valid['ExecStart'])]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                parse(self.property_text({**valid, key: value}))
        with self.assertRaises(ValueError): parse(self.property_text(valid) + 'MainPID=123\n')

    def test_live_pid_executable_argv_and_all_four_uids_are_required(self):
        proc, process = self.process_fixture()
        verify = self.guard['verify_process']; verify(123, proc)
        for name, raw, code in [('cmdline', b'dbus-broker-launch\0', 'process_argv'),
                                ('status', b'Uid:\t1001\t1001\t0\t1001\n', 'process_uid'),
                                ('stat', self.proc_stat().replace(b'123 (', b'124 ('), 'process_identity')]:
            path = process / name; saved = path.read_bytes(); path.write_bytes(raw)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, code): verify(123, proc)
            path.write_bytes(saved)
        (process / 'exe').unlink(); (process / 'exe').symlink_to('/usr/bin/dbus-broker-launch')
        with self.assertRaisesRegex(ValueError, 'process_executable'): verify(123, proc)

    def test_zero_sized_proc_metadata_is_read_and_generation_change_refuses(self):
        from types import SimpleNamespace
        proc, _ = self.process_fixture()
        original = os.fstat
        with mock.patch.object(os, 'fstat', side_effect=lambda fd:
                               SimpleNamespace(st_mode=original(fd).st_mode, st_size=0)):
            self.guard['verify_process'](123, proc)
        read = self.guard['read_small']; count = 0
        def changed(name, *args, **kwargs):
            nonlocal count
            if name == 'stat':
                count += 1
                if count == 2: return self.proc_stat(457)
            return read(name, *args, **kwargs)
        self.guard['read_small'] = changed
        with self.assertRaisesRegex(ValueError, 'process_changed'): self.guard['verify_process'](123, proc)

    def test_fixed_direct_user_identity_environment_and_command_bound(self):
        from types import SimpleNamespace
        account = SimpleNamespace(pw_uid=1001, pw_gid=1002)
        with mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ok', b'')) as run:
            self.assertEqual(self.guard['command'](['--user', 'show', 'dbus.service'], account), 'ok')
        self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl', '--user', 'show', 'dbus.service'])
        options = run.call_args.kwargs
        self.assertEqual((options['user'], options['group'], options['extra_groups'], options['cwd'], options['timeout']),
                         (1001, 1002, [], '/', 30))
        self.assertEqual(options['env'], {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                                         'XDG_RUNTIME_DIR': '/run/user/1001'})
        for result in [subprocess.CompletedProcess([], 1, b'', b'failure'),
                       subprocess.CompletedProcess([], 0, b'x' * 16385, b'')]:
            with mock.patch.object(subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'systemctl_failed'):
                self.guard['command'](['--user', 'show', 'dbus.service'], account)

    def test_effective_unit_is_rechecked_while_same_proc_directory_remains_held(self):
        proc, process = self.process_fixture()
        verify_process = self.guard['verify_process']
        self.guard['verify_process'] = lambda pid, confirm: verify_process(pid, proc, confirm)
        self.guard['check_units'] = mock.Mock()
        valid = self.unit_properties()
        account = mock.Mock(pw_uid=1001, pw_gid=1001)
        for changed in (None, 'pid', 'unit', 'birth'):
            with self.subTest(changed=changed):
                (process / 'stat').write_bytes(self.proc_stat())
                calls = []
                def command(argv, actual_account):
                    self.assertIs(actual_account, account)
                    calls.append(argv)
                    if len(calls) == 1: return ''
                    values = dict(valid)
                    if len(calls) == 3:
                        if changed == 'pid': values['MainPID'] = '124'
                        if changed == 'unit': values['DropInPaths'] = '/unexpected.conf'
                        if changed == 'birth': (process / 'stat').write_bytes(self.proc_stat(457))
                    return self.property_text(values)
                self.guard['command'] = command
                with mock.patch.object(self.guard['pwd'], 'getpwnam', return_value=account):
                    if changed is None: self.guard['verify']()
                    else:
                        with self.assertRaises(ValueError): self.guard['verify']()
                self.assertEqual(calls[0], ['--user', 'start', 'dbus.service'])
                self.assertEqual(len(calls), 3)
                self.assertEqual(calls[1], calls[2])

    def test_generated_selection_and_verification_precede_manager_and_controller(self):
        import inspect
        source = inspect.getsource(prepare.main)
        self.assertLess(source.index("{session_bus_script('select')}"), source.index('useradd --create-home'))
        self.assertLess(source.index('systemctl start user@1001.service'), source.index("{session_bus_script('verify')}"))
        self.assertLess(source.index("{session_bus_script('verify')}"), source.index('systemctl enable ukai-vm.service'))
        self.assertEqual(source.count('bubblewrap dbus-user-session dbus-daemon'), 3)
        self.assertEqual(source.count('apt-get install '), 1)
        for phase in ('select', 'verify'):
            script = prepare.session_bus_script(phase)
            self.assertIn(prepare.SESSION_BUS_GUARD, script)
            result = subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True, timeout=10)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))


@unittest.skipUnless(shutil.which('minisign'), 'local-candidate verification requires minisign')
class SignedCandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        for name in ('coordinates.py', 'release.json', 'package.py', 'notices.py',
                     'prepare_release.py', 'publish_release.py', 'bootstrap.py'):
            shutil.copyfile(prepare.SOURCE.parent / 'dist' / name, self.dist / name)
        self.key = self.root / 'test.key'
        subprocess.run(['minisign', '-G', '-W', '-s', str(self.key), '-p', str(self.dist / 'release.pub')],
                       check=True, capture_output=True)
        self.candidate = self.root / 'candidate'
        self.candidate.mkdir()
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.version = '9.9.9-rc.1'
        revision, inputs = 'a' * 40, 'sha256:' + 'b' * 64
        self.records = []
        for target, machine in [('aarch64-unknown-linux-gnu', 183), ('x86_64-unknown-linux-gnu', 62)]:
            binary = b'\x7fELF\x02\x01' + bytes(12) + machine.to_bytes(2, 'little') + target.encode()
            archive = self.candidate / f'ukai-jail-{self.version}-{target}.tar.gz'
            with tarfile.open(archive, 'w:gz') as stream:
                for name, contents, mode in [('ukai-jail', binary, 0o755),
                                             ('ukai-jail.LICENSES.txt', b'test license\n', 0o644)]:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = len(contents), mode
                    stream.addfile(member, io.BytesIO(contents))
            self.records.append({
                'schema': 'ukai.jail.release-artifact/1', 'target': target, 'release': self.version,
                'archive': archive.name, 'archive_sha256': prepare.sha(archive),
                'binary_sha256': hashlib.sha256(binary).hexdigest(),
                'version': {'build': {'target': target, 'revision': revision, 'inputs': inputs,
                                      'dirty': False, 'opt_level': '3', 'debug_assertions': False,
                                      'rustc': 'rustc 1.98.1 (test)'}},
            })
        self.plan = {'schema': 'ukai.jail.release-candidate/1',
                     'repository': prepare.coordinates.REPOSITORY,
                     'publication_scope': prepare.coordinates.PUBLICATION_SCOPE,
                     'unsupported_clauses': prepare.coordinates.UNSUPPORTED_CLAUSES,
                     'target_commit': revision, 'inputs': inputs,
                     'tag': prepare.coordinates.jail_tag(self.version),
                     'signature_verified': True, 'artifacts': self.records}
        (self.candidate / 'install.sh').write_text('# signed test installer\n')
        (self.candidate / 'RELEASE_NOTES.md').write_text('Test candidate\n')
        (self.candidate / 'bootstrap.sh').write_text(
            f'    version={self.version}\n    # BEGIN SHA256 PINS\n'
            + ''.join(f"        {self.version}:{r['target']}) expected='{r['archive_sha256']}' ;;\n"
                      for r in self.records)
            + '    # END SHA256 PINS\n')
        self.sign()

    def sign(self):
        (self.candidate / 'release-plan.json').write_text(json.dumps(self.plan))
        names = ['release-plan.json', 'RELEASE_NOTES.md', 'install.sh', 'bootstrap.sh']
        names.extend(record['archive'] for record in self.records)
        manifest = self.candidate / 'SHA256SUMS'
        manifest.write_text(''.join(f'{prepare.sha(self.candidate / name)}  {name}\n' for name in sorted(set(names))))
        signature = self.candidate / 'SHA256SUMS.minisig'
        signature.unlink(missing_ok=True)
        subprocess.run(['minisign', '-Sm', str(manifest), '-s', str(self.key)],
                       check=True, capture_output=True)

    def stage(self):
        return prepare.stage_candidate(self.candidate, self.cache, self.dist)

    def test_selects_arm_and_retains_verified_source_signature_and_build_identity(self):
        digest, provenance = self.stage()
        arm = self.records[0]
        self.assertEqual(digest, arm['archive_sha256'])
        self.assertEqual((self.cache / 'jail.tar.gz').read_bytes(),
                         (self.candidate / arm['archive']).read_bytes())
        self.assertEqual(provenance['source_revision'], self.plan['target_commit'])
        self.assertEqual(provenance['build_inputs'], self.plan['inputs'])
        self.assertEqual(provenance['binary_sha256'], arm['binary_sha256'])
        self.assertEqual(provenance['target'], prepare.JAIL_TARGET)
        self.assertTrue(provenance['signature_verified'])
        retained = self.cache / 'signed-jail-candidate'
        for name, expected in provenance['verified_assets_sha256'].items():
            self.assertEqual(prepare.sha(retained / name), expected)
        self.assertEqual((retained / 'trusted-release.pub').read_bytes(),
                         (self.dist / 'release.pub').read_bytes())

    def test_refuses_archive_tampering_before_creating_selected_input(self):
        with (self.candidate / self.records[0]['archive']).open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaises(subprocess.CalledProcessError):
            self.stage()
        self.assertFalse((self.cache / 'jail.tar.gz').exists())

    def test_refuses_changed_signature_or_trust_key(self):
        for change in ('signature', 'key'):
            with self.subTest(change=change):
                path = self.candidate / 'SHA256SUMS.minisig' if change == 'signature' else self.dist / 'release.pub'
                saved = path.read_bytes()
                path.write_text('invalid signature or key\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    self.stage()
                self.assertFalse((self.cache / 'jail.tar.gz').exists())
                path.write_bytes(saved)

    def test_refuses_signed_plan_with_inconsistent_source_or_inputs(self):
        for field, changed in [('target_commit', 'c' * 40), ('inputs', 'sha256:' + 'd' * 64)]:
            with self.subTest(field=field):
                saved = self.plan[field]
                self.plan[field] = changed
                self.sign()
                with self.assertRaises(subprocess.CalledProcessError):
                    self.stage()
                self.assertFalse((self.cache / 'jail.tar.gz').exists())
                self.plan[field] = saved

    def test_refuses_candidate_without_both_distinct_native_targets(self):
        self.plan['artifacts'] = [self.records[1]]
        self.sign()
        with self.assertRaises(subprocess.CalledProcessError):
            self.stage()
        self.assertFalse((self.cache / 'jail.tar.gz').exists())

    def test_refuses_a_copy_changed_after_the_original_verification(self):
        copy = shutil.copyfile
        arm_name = self.records[0]['archive']

        def changed(source, destination):
            result = copy(source, destination)
            if Path(destination).name == arm_name:
                with Path(destination).open('ab') as stream:
                    stream.write(b'changed during copy')
            return result

        with mock.patch.object(prepare.shutil, 'copyfile', side_effect=changed):
            with self.assertRaises(subprocess.CalledProcessError):
                self.stage()
        self.assertFalse((self.cache / 'jail.tar.gz').exists())

    def test_preserves_existing_selected_archive(self):
        (self.cache / 'jail.tar.gz').write_bytes(b'existing input')
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual((self.cache / 'jail.tar.gz').read_bytes(), b'existing input')


class NativeProgramPreparationTests(unittest.TestCase):
    """No VM/installer execution; exercise the opt-in retained input path."""
    def setUp(self):
        from test_guest_program import elf_bytes
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / 'vendor-elf'; self.binary.write_bytes(elf_bytes())
        self.out = self.root / 'prepared'; self.out.mkdir()
        self.jail = b'pinned synthetic guest jail'
        patches = {'NATIVE_SHA256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                   'NATIVE_SIZE': self.binary.stat().st_size,
                   'NATIVE_JAIL_SHA256': hashlib.sha256(self.jail).hexdigest()}
        for name, value in patches.items():
            patcher = mock.patch.object(prepare, name, value); patcher.start(); self.addCleanup(patcher.stop)

    def stage(self):
        return prepare.stage_native_program(self.binary, self.out, self.jail)

    def test_pinned_catalog_profile_jail_and_payload_are_retained(self):
        native = self.stage()
        value = prepare.guest_program.parse_catalog(native['catalog']); entry = value['entries'][0]
        self.assertEqual(entry['executable_sha256'], prepare.NATIVE_SHA256)
        self.assertEqual(entry['profile_sha256'], prepare.NATIVE_PROFILE_SHA256)
        self.assertEqual(entry['guest_jail_sha256'], prepare.NATIVE_JAIL_SHA256)
        self.assertEqual(native['payload'].read_bytes(), self.binary.read_bytes())
        self.assertEqual((self.out/prepare.guest_program.CATALOG_FILENAME).read_bytes(), native['catalog'])
        self.assertEqual(native['sha256'], hashlib.sha256(native['catalog']).hexdigest())

    def test_wrong_jail_profile_and_file_hash_refuse(self):
        with self.assertRaisesRegex(ValueError, 'guest jail'):
            prepare.stage_native_program(self.binary, self.out, b'wrong jail')
        with mock.patch.object(prepare, 'NATIVE_PROFILE_SHA256', '0'*64), self.assertRaisesRegex(ValueError, 'profile'):
            self.stage()
        with mock.patch.object(prepare, 'NATIVE_SHA256', '0'*64), self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.stage()

    def test_symlink_and_multiple_links_refuse(self):
        import os
        link = self.root/'link'; link.symlink_to(self.binary)
        with self.assertRaises(OSError): prepare.stage_native_program(link, self.out, self.jail)
        os.link(self.binary, self.root/'hardlink')
        with self.assertRaisesRegex(ValueError, 'type/link/size'): self.stage()

    def test_other_architecture_refuses_even_if_pinned_hash(self):
        raw = bytearray(self.binary.read_bytes()); raw[18:20] = (62).to_bytes(2, 'little'); self.binary.write_bytes(raw)
        with mock.patch.object(prepare, 'NATIVE_SHA256', hashlib.sha256(raw).hexdigest()), self.assertRaisesRegex(ValueError, 'ELF'):
            self.stage()

    def test_seed_payload_is_separate_and_verified_after_copy(self):
        native = self.stage(); seed = self.root/'seed'
        with mock.patch.object(prepare.subprocess, 'run') as run:
            prepare.seed(seed, [('/metadata', b'public metadata', '0644')], [],
                         {'native-programs/claude': native['payload']})
        self.assertEqual((seed/'native-programs/claude').read_bytes(), self.binary.read_bytes())
        self.assertNotIn(base64.b64encode(self.binary.read_bytes()).decode(), (seed/'user-data').read_text())
        self.assertEqual(run.call_args.args[0][0:2], ['hdiutil', 'makehybrid'])
        original = prepare.shutil.copyfile
        def corrupt(source, target):
            result = original(source, target); Path(target).write_bytes(b'tampered'); return result
        with mock.patch.object(prepare.shutil, 'copyfile', side_effect=corrupt), self.assertRaisesRegex(ValueError, 'payload changed'):
            prepare.seed(self.root/'bad-seed', [], [], {'native-programs/claude': native['payload']})

    def test_guest_install_script_checks_both_copies_and_immutable_modes(self):
        native = self.stage(); script = prepare.native_install_script(native)
        self.assertIn('mount -t iso9660 -o ro ', script)
        self.assertIn('install -d -o 0 -g 0 -m 0555', script)
        self.assertIn('install -o 0 -g 0 -m 0555', script)
        self.assertEqual(script.count('sha256sum -c -'), 2)
        self.assertIn('guest_program.verify_catalog()', script)
        self.assertEqual(prepare.native_install_script(None), '')
        self.assertNotIn('/launch/claude.toml', script)




class ExposureControlMetadataTests(unittest.TestCase):
    def report(self):
        from guest_exposure import READ_STATES
        counts={name:{state:int(state=='readable') for state in READ_STATES} for name in ('environment','argv')}
        return dict(schema='ukai.vm.sampled-exposure-control/1',passed=True,
            scope='owned-public-canary-process-detector-control',actual_values_retained=False,jail_execution_claimed=False,
            facts={name:True for name in ('environment_canary_detected','argv_canary_detected',
                'verified_program_environment_read','verified_program_argv_read','only_owned_child_observed',
                'sampler_source_unchanged','owned_child_reaped')},
            sampling={'ticks':1,'verified_program_reads':counts,'scan_errors':{'inventory_vanished':1}},errors=[],
            control_source_sha256='c'*64,sampler_sha256='s'*64,guest_boot_id='guest-boot',guest_kernel='7.0.0-test',
            process={'pid':10,'starttime':100,'executable_dev':1,'executable_ino':2})

    def parse(self,report):
        return prepare.exposure_control_from_console('prefix\nUKAI_EXPOSURE_CONTROL '+json.dumps(report)+'\n',
            {'guest_exposure.py':'s'*64,'guest_exposure_control.py':'c'*64})

    def test_actual_control_source_and_exact_facts_required(self):
        report=self.report(); self.assertEqual(self.parse(report),report)
        # Inventory churn stays visible; this proves detector function only.
        self.assertEqual(self.parse(report)['sampling']['scan_errors'],{'inventory_vanished':1})
        for key,value in [('sampler_sha256','wrong'),('control_source_sha256','wrong'),('passed',1),
                          ('actual_values_retained',True),('errors',['error']),('facts',{})]:
            with self.subTest(key=key),self.assertRaises(ValueError): self.parse({**report,key:value})
        for mutation in ('unknown','false','integer'):
            changed=self.report()
            if mutation=='unknown': changed['facts']['invented']=True
            elif mutation=='false': changed['facts']['owned_child_reaped']=False
            else: changed['facts']['owned_child_reaped']=1
            with self.assertRaises(ValueError): self.parse(changed)

    def test_duplicate_marker_key_and_unreadable_identity_refuse(self):
        hashes={'guest_exposure.py':'s'*64,'guest_exposure_control.py':'c'*64}
        marker='UKAI_EXPOSURE_CONTROL '+json.dumps(self.report())+'\n'
        for text in ('',marker+marker,marker.replace('"passed": true','"passed": true,"passed": true')):
            with self.assertRaises(ValueError): prepare.exposure_control_from_console(text,hashes)
        for key,value in [('pid',True),('starttime',0),('executable_ino',0)]:
            changed=self.report();changed['process'][key]=value
            with self.assertRaises(ValueError):self.parse(changed)
        changed=self.report();changed['sampling']['verified_program_reads']['argv']['readable']=0
        with self.assertRaises(ValueError):self.parse(changed)
        changed=self.report();changed['sampling']['scan_errors']={'arbitrary_error_message':1}
        with self.assertRaises(ValueError):self.parse(changed)


if __name__ == '__main__':
    unittest.main()
