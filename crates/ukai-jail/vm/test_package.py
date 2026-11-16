import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

import package

# A caller's GIT_DIR or GIT_INDEX_FILE would point git at another repository,
# and user or system configuration (signing, hooks) must not change the result.
GIT_ENVIRONMENT = {**{key: value for key, value in os.environ.items() if not key.startswith('GIT_')},
                   'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipUnless(shutil.which('git'), 'git is required to list committed sources')
class CommittedSourceTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, GIT_ENVIRONMENT, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name) / 'repo'
        self.vm = self.repo / 'crates' / 'vm'
        (self.vm / 'sub').mkdir(parents=True)
        for name in ('guest.py', 'run.py', 'sub/notes.txt'):
            (self.vm / name).write_text(name + '\n')
        (self.repo / 'outside.txt').write_text('not preview source\n')
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-q', '-m', 'sources')

    def git(self, *args):
        subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True, timeout=30)

    def test_lists_only_committed_files_under_the_directory(self):
        (self.vm / '__pycache__').mkdir()
        (self.vm / '__pycache__' / 'run.cpython-313.pyc').write_bytes(b'stray')
        (self.vm / 'local-output.json').write_text('{}')
        (self.repo / 'outside.txt').write_text('edited outside the preview sources\n')
        self.assertEqual(package.committed_sources(self.vm), ['guest.py', 'run.py', 'sub/notes.txt'])

    def test_refuses_uncommitted_changes_to_committed_files(self):
        for change in (lambda: (self.vm / 'run.py').write_text('edited\n'),
                       lambda: ((self.vm / 'run.py').write_text('staged\n'), self.git('add', '.')),
                       lambda: (self.vm / 'sub' / 'notes.txt').unlink(),
                       lambda: self.git('rm', '-q', '--cached', 'crates/vm/guest.py')):
            with self.subTest(change=change):
                change()
                with self.assertRaisesRegex(package.SourceError, 'uncommitted changes'):
                    package.committed_sources(self.vm)
                self.git('reset', '-q', '--hard')

    def test_refuses_outside_a_repository_or_without_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(package.SourceError):
                package.committed_sources(Path(temporary))
        with mock.patch.dict(os.environ, {'PATH': str(self.repo / 'no-tools')}):
            with self.assertRaisesRegex(package.SourceError, 'cannot list'):
                package.committed_sources(self.vm)


    def test_require_clean_covers_untracked_and_modified_inputs(self):
        package.require_clean(self.repo, ['crates/vm'])
        (self.repo / 'crates' / 'vm' / 'new.rs').write_text('mod planted;\n')
        with self.assertRaisesRegex(package.SourceError, 'new.rs'):
            package.require_clean(self.repo, ['crates/vm'])
        (self.repo / 'crates' / 'vm' / 'new.rs').unlink()
        (self.repo / 'outside.txt').write_text('changed outside the inputs\n')
        package.require_clean(self.repo, ['crates/vm'])
        with self.assertRaisesRegex(package.SourceError, 'outside.txt'):
            package.require_clean(self.repo, ['crates/vm', 'outside.txt'])

    def test_require_clean_refuses_an_ignored_input_but_not_bytecode(self):
        # Reviewer F-16: an ignored file under the inputs is one a build could read.
        (self.repo / '.gitignore').write_text('*.local\n__pycache__/\n')
        self.git('add', '.gitignore')
        self.git('-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-q', '-m', 'ignore')
        (self.vm / '__pycache__').mkdir()
        (self.vm / '__pycache__' / 'run.cpython-315.pyc').write_bytes(b'bytecode')
        package.require_clean(self.repo, ['crates/vm'])
        (self.vm / 'override.local').write_text('read by the build\n')
        with self.assertRaisesRegex(package.SourceError, 'override.local'):
            package.require_clean(self.repo, ['crates/vm'])

    def test_require_clean_sees_through_assume_unchanged_and_skip_worktree(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag):
                self.git('update-index', flag, 'crates/vm/run.py')
                (self.vm / 'run.py').write_text('edited behind the index\n')
                with self.assertRaisesRegex(package.SourceError, 'run.py'):
                    package.require_clean(self.repo, ['crates/vm'])
                self.git('update-index', flag.replace('--', '--no-'), 'crates/vm/run.py')
                self.git('checkout', '--', 'crates/vm/run.py')
                package.require_clean(self.repo, ['crates/vm'])

    def test_require_clean_refuses_the_marks_themselves(self):
        # Mutation R40: a mark is refused before any edit, and named as a mark,
        # so the operator clears it instead of hunting for a change.
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag):
                self.git('update-index', flag, 'crates/vm/run.py')
                with self.assertRaisesRegex(package.SourceError,
                                            'assume-unchanged or skip-worktree: crates/vm/run.py'):
                    package.require_clean(self.repo, ['crates/vm'])
                self.git('update-index', flag.replace('--', '--no-'), 'crates/vm/run.py')
        package.require_clean(self.repo, ['crates/vm'])

    def test_require_clean_compares_the_bytes_with_heads_blobs(self):
        # Even with every mark cleared and status quiet, the bytes are HEAD's.
        with mock.patch.object(package, 'git_lines', wraps=package.git_lines) as lines:
            package.require_clean(self.repo, ['crates/vm'])
        self.assertIn('ls-tree', [call.args[1] for call in lines.call_args_list])
        real = package.git_lines

        def quiet(repo, *args):
            if args[0] in ('status', 'ls-files'):
                return b'' if args[0] == 'status' else real(repo, *args)
            return real(repo, *args)
        (self.vm / 'run.py').write_text('edited\n')
        with mock.patch.object(package, 'git_lines', quiet):
            with self.assertRaisesRegex(package.SourceError, 'differ from HEAD: crates/vm/run.py'):
                package.require_clean(self.repo, ['crates/vm'])

    def test_tree_sources_and_the_revision(self):
        sources = package.tree_sources(self.repo, ['crates/vm'])
        self.assertEqual(sorted(sources), ['crates/vm/guest.py', 'crates/vm/run.py', 'crates/vm/sub/notes.txt'])
        self.assertEqual(sources['crates/vm/run.py'], sha256(b'run.py\n'))
        self.assertRegex(package.head_revision(self.repo), '^[0-9a-f]{40}$')

    def test_require_clean_large_inventory_finishes_with_exact_blobs(self):
        # Exceed both sides of the observed 89,660-byte path inventory and
        # 49,692-byte hash response. Exercise real Git, not a mocked hash list.
        for number in range(2048):
            name = f'{number:04d}-' + 'long-committed-source-name-' * 5 + '.txt'
            (self.vm / name).write_text(f'committed source {number}\n')
        self.git('add', '.')
        self.git('-c', 'user.name=test', '-c', 'user.email=test@example.invalid',
                 'commit', '-q', '-m', 'large source inventory')
        names = package.listed_sources(self.repo, ['crates/vm'])
        self.assertGreater(len(('\n'.join(names) + '\n').encode()), 89660)
        self.assertGreater(len(names) * 41, 49692)
        script = ('import sys; sys.path.insert(0, sys.argv[1]); import package; '
                  'package.require_clean(package.Path(sys.argv[2]), ["crates/vm"]); '
                  'print("verified")')
        optimized = ['-' + 'O' * sys.flags.optimize] if sys.flags.optimize else []
        child = subprocess.Popen(
            [sys.executable, '-B', *optimized, '-c', script, str(package.SOURCE), str(self.repo)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        try:
            out, err = child.communicate(timeout=45)
            self.assertEqual(child.returncode, 0, err)
            self.assertEqual(out, 'verified\n')
        finally:
            # A regression to the blocked exchange must not leave either the
            # test driver or its exact Git child running after the test fails.
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=10)

    def test_require_clean_hash_timeout_refuses(self):
        real = subprocess.run

        def timed_out(args, **kwargs):
            if 'hash-object' in args:
                raise subprocess.TimeoutExpired(args, kwargs['timeout'])
            return real(args, **kwargs)

        with mock.patch.object(package.subprocess, 'run', side_effect=timed_out):
            with self.assertRaisesRegex(package.SourceError, 'git hash-object timed out'):
                package.require_clean(self.repo, ['crates/vm'])


class ReleaseCoordinateTests(unittest.TestCase):
    def test_the_package_version_is_the_candidate_never_the_published_version(self):
        coordinates = types.SimpleNamespace(VM_VERSION='0.1.0-preview.1', VM_CANDIDATE_VERSION='0.1.0-preview.2')
        self.assertEqual(package.candidate_version(coordinates), '0.1.0-preview.2')

    def test_an_absent_or_malformed_candidate_refuses(self):
        for values in ({'VM_VERSION': '0.1.0-preview.1'}, {'VM_CANDIDATE_VERSION': ''},
                       {'VM_CANDIDATE_VERSION': 'latest'}, {'VM_CANDIDATE_VERSION': 2}):
            with self.subTest(values=values), self.assertRaisesRegex(package.SourceError, 'VM_CANDIDATE_VERSION'):
                package.candidate_version(types.SimpleNamespace(**values))

    def test_the_coordinates_are_the_dist_module(self):
        module = package.release_coordinates()
        self.assertEqual(Path(module.__file__).resolve(),
                         (package.REPO / 'crates/ukai-jail/dist/coordinates.py').resolve())


def pinned_versions(pin):
    return {'rustc_vV': f'rustc {pin} (abc 2026-10-01)\nbinary: rustc\nhost: aarch64-apple-darwin\nrelease: {pin}\n',
            'cargo_V': f'cargo {pin} (def 2026-10-01)'}


class BuildTests(unittest.TestCase):
    OVERRIDES = {'CARGO_TARGET_DIR': '/elsewhere/stale', 'RUSTUP_TOOLCHAIN': 'stable', 'RUSTFLAGS': '-C opt-level=0',
                 'RUSTC_WRAPPER': '/x/sccache', 'CARGO_BUILD_TARGET': 'x86_64-apple-darwin',
                 'CARGO_PROFILE_RELEASE_DEBUG': 'true'}

    def test_ukai_vm_builds_locked_into_the_named_target_with_provenance(self):
        calls, probed = [], []
        pin = package.toolchain_pin()

        def versions(environment, repo):
            probed.append((dict(environment), repo))
            return pinned_versions(pin)
        with mock.patch.dict(os.environ, self.OVERRIDES):
            built, record = package.build_ukai_vm(Path('/tmp/pkg/cargo-target'), 'a' * 40, '9.9.9-x',
                                                  run=lambda *args, env=None, cwd=None: calls.append((args, env, cwd)),
                                                  versions=versions)
        (args, env, cwd), = calls
        words = [str(word) for word in args]
        self.assertIn('--locked', words)
        self.assertEqual([words[i + 1] for i, word in enumerate(words) if word == '--bin'],
                         ['ukai-vm', 'ukai-jail'])
        self.assertEqual(words[words.index('--target-dir') + 1], '/tmp/pkg/cargo-target')
        self.assertEqual(built, Path('/tmp/pkg/cargo-target/release/ukai-vm'))
        self.assertEqual((env['UKAI_BUILD_REVISION'], env['UKAI_BUILD_DIRTY'], env['UKAI_VM_PACKAGE_VERSION']),
                         ('a' * 40, 'false', '9.9.9-x'))
        # Reviewer F-4 / FX8: no override reaches cargo or the version probe,
        # and the build runs where rustup reads rust-toolchain.toml.
        for environment in (env, probed[0][0]):
            self.assertEqual(sorted(set(self.OVERRIDES) & set(environment)), [])
            self.assertLessEqual(set(environment) - {'UKAI_BUILD_REVISION', 'UKAI_BUILD_DIRTY', 'UKAI_VM_PACKAGE_VERSION'},
                                 set(package.BUILD_ENVIRONMENT))
        self.assertEqual(cwd, package.REPO)
        self.assertEqual(probed[0][1], package.REPO)
        self.assertTrue(record['locked'])
        self.assertEqual((record['toolchain_pin'], record['rustc_vV'], record['cargo_V']),
                         (pin, pinned_versions(pin)['rustc_vV'], pinned_versions(pin)['cargo_V']))
        self.assertEqual(record['environment_names'], sorted(env))

    def test_a_toolchain_that_is_not_the_pin_refuses_before_cargo(self):
        pin = package.toolchain_pin()
        for name, found, message in [
                ('another rustc', dict(pinned_versions(pin), rustc_vV='rustc 1.96.0 (x)\nrelease: 1.96.0\n'), 'rustc is 1.96.0'),
                ('no release line', dict(pinned_versions(pin), rustc_vV='rustc ?'), 'rustc is unknown'),
                ('another cargo', dict(pinned_versions(pin), cargo_V='cargo 1.96.0 (x)'), 'cargo is'),
                ('a cargo whose version only starts with the pin', dict(pinned_versions(pin), cargo_V=f'cargo {pin}9 (x)'), 'cargo is')]:
            with self.subTest(name):
                calls = []
                with self.assertRaisesRegex(package.SourceError, message):
                    package.build_ukai_vm(Path('/tmp/t'), 'a' * 40, 'v', run=lambda *a, **k: calls.append(a),
                                          versions=lambda environment, repo: found)
                self.assertEqual(calls, [])

    def test_the_build_environment_keeps_only_its_names(self):
        base = dict(self.OVERRIDES, PATH='/usr/bin', HOME='/Users/x', RUSTUP_HOME='/r', LANG='fr_FR.UTF-8')
        self.assertEqual(package.build_environment(base), {'PATH': '/usr/bin', 'HOME': '/Users/x', 'RUSTUP_HOME': '/r'})

    def test_the_pin_is_an_exact_release(self):
        self.assertRegex(package.toolchain_pin(), r'^\d+\.\d+\.\d+$')
        with tempfile.TemporaryDirectory() as temporary:
            for channel, ok in (('"1.98.1"', True), ('"stable"', False), ('"1.98"', False), ('"nightly-2026-10-01"', False)):
                with self.subTest(channel=channel):
                    (Path(temporary) / 'rust-toolchain.toml').write_text(f'[toolchain]\nchannel = {channel}\n')
                    if ok:
                        self.assertEqual(package.toolchain_pin(temporary), '1.98.1')
                    else:
                        with self.assertRaisesRegex(package.SourceError, 'pins no exact release'):
                            package.toolchain_pin(temporary)

    def test_the_versions_are_probed_in_the_build_environment(self):
        seen = []

        def run(*args, env=None, cwd=None):
            seen.append((args, env, cwd))
            return f'{args[0]} out\n'
        found = package.toolchain_versions({'PATH': '/usr/bin'}, Path('/repo'), run=run)
        self.assertEqual(found, {'rustc_vV': 'rustc out', 'cargo_V': 'cargo out'})
        self.assertEqual([call[0] for call in seen], [('rustc', '-vV'), ('cargo', '-V')])
        self.assertTrue(all(call[1] == {'PATH': '/usr/bin'} and call[2] == Path('/repo') for call in seen))

    @unittest.skipUnless(shutil.which('rustup') and shutil.which('rustc'), 'rustup is not installed')
    def test_this_hosts_scrubbed_build_sees_the_pin(self):
        # FX8 on this host: a shell RUSTUP_TOOLCHAIN (stable) never reaches the build.
        pin = package.toolchain_pin()
        listed = subprocess.run(['rustup', 'toolchain', 'list'], capture_output=True, text=True).stdout
        if not any(line.startswith(pin + '-') for line in listed.splitlines()):
            self.skipTest(f'the pinned {pin} toolchain is not installed (rustup would download it)')
        with mock.patch.dict(os.environ, {'RUSTUP_TOOLCHAIN': 'stable'}):
            found = package.toolchain_versions(package.build_environment())
        package.require_pinned_toolchain(found, pin)

    def test_check_built_needs_the_version_the_revision_and_a_clean_tree(self):
        # Reviewer PK7, PK8: each post-build check on its own.
        with mock.patch.object(package, 'head_revision', return_value='a' * 40), \
                mock.patch.object(package, 'require_clean') as clean:
            self.assertEqual(package.check_built(Path('/b'), 'v1', 'a' * 40, reported=lambda b: 'v1'), 'v1')
            clean.assert_called_once_with(package.REPO, package.build_inputs())
            with self.assertRaisesRegex(package.SourceError, "reports version 'v0', not v1"):
                package.check_built(Path('/b'), 'v1', 'a' * 40, reported=lambda b: 'v0')
            with self.assertRaisesRegex(package.SourceError, 'HEAD moved during the build'):
                package.check_built(Path('/b'), 'v1', 'b' * 40, reported=lambda b: 'v1')
            clean.side_effect = package.SourceError('build inputs differ from HEAD: x')
            with self.assertRaisesRegex(package.SourceError, 'differ from HEAD'):
                package.check_built(Path('/b'), 'v1', 'a' * 40, reported=lambda b: 'v1')

    def test_check_version_needs_the_cli_version(self):
        # Reviewer PK9.
        package.check_version('0.1.0-preview.2', '0.1.0-preview.2')
        with self.assertRaisesRegex(package.SourceError, 'cli.VERSION is 0.1.0-preview.2'):
            package.check_version('0.1.0-preview.3', '0.1.0-preview.2')
        self.assertEqual(package.check_version.__defaults__, (None,))

    def test_client_build_must_match_the_clean_native_revision(self):
        pin = package.toolchain_pin()
        report = {'component': 'ukai-jail', 'version': '0.1.0', 'build': {
            'revision': 'a' * 40, 'dirty': False, 'target': 'aarch64-apple-darwin',
            'opt_level': '3', 'debug_assertions': False, 'rustc': f'rustc {pin} (fixture)',
            'inputs': 'sha256:' + 'b' * 64}}
        self.assertEqual(package.check_built_client(Path('/client'), 'a' * 40, pin, report), report)
        for field, value in [('revision', 'c' * 40), ('dirty', True), ('dirty', None),
                             ('target', 'x86_64-apple-darwin'), ('opt_level', '0'),
                             ('debug_assertions', True), ('rustc', 'rustc 1.80.0 (fixture)'),
                             ('inputs', 'unknown')]:
            with self.subTest(field=field, value=value), self.assertRaises(package.SourceError):
                package.check_built_client(Path('/client'), 'a' * 40, pin,
                                           {**report, 'build': {**report['build'], field: value}})

    def test_both_operator_binaries_are_signed_without_es_entitlements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            built, payload = root / 'release', root / 'payload'
            built.mkdir(); payload.mkdir()
            for name in ('ukai-vm', 'ukai-jail'):
                (built / name).write_bytes(name.encode())
            calls = []
            package.sign_operator_binaries(built / 'ukai-vm', payload, 'test identity',
                                            run=lambda *args: calls.append(args))
            self.assertEqual(len(calls), 4)
            for index, name in enumerate(('ukai-vm', 'ukai-jail')):
                self.assertEqual((payload / name).read_bytes(), name.encode())
                self.assertEqual(calls[index * 2], ('codesign', '--force', '--options', 'runtime',
                                                  '--timestamp', '--sign', 'test identity', payload / name))
                self.assertEqual(calls[index * 2 + 1], ('codesign', '--verify', '--strict', payload / name))

    def test_head_revision_is_a_full_commit(self):
        # Reviewer PK12.
        for output, ok in ((b'a' * 40 + b'\n', True), (b'abc\n', False), (b'HEAD\n', False), (b'b' * 64 + b'\n', False)):
            with self.subTest(output=output), mock.patch.object(package, 'git_lines', return_value=output):
                if ok:
                    self.assertEqual(package.head_revision(), 'a' * 40)
                else:
                    with self.assertRaisesRegex(package.SourceError, 'not a full commit'):
                        package.head_revision()

    def test_the_archived_tree_check_covers_every_build_input(self):
        # main() checks the tree once, under archive_paths(): every build
        # input build.rs checks is one of its pathspecs.
        self.assertLessEqual(set(package.build_inputs()), set(package.archive_paths()))
        self.assertLessEqual(set(package.SOURCE_PATHS), set(package.archive_paths()))

    def test_the_build_inputs_are_build_provenance_rs_list(self):
        inputs = package.build_inputs()
        self.assertEqual(inputs[0], 'crates/ukai-jail/src')
        self.assertEqual(len(inputs), 48)
        for name in ('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'crates/ukai-jail/build.rs',
                     'docs/specs/jail-v1/network-addresses.json'):
            self.assertIn(name, inputs)
        for name in ('guest-native-profile-inputs.json', 'guest-program-catalog.json',
                     'guest-program-catalog-vectors.json', 'sampled-exposure-context.json',
                     'sampled-exposure-receipt.json', 'sampled-exposure-report.json', 'managed-sampled-exposure.json'):
            self.assertIn('crates/ukai-jail/vm/fixtures/' + name, inputs)


@unittest.skipUnless(shutil.which('git'), 'git is required to list committed sources')
class SourceArchiveCoverageTests(unittest.TestCase):
    """preview-source.tar.gz holds what builds every binary the DMG ships."""

    def test_the_archived_paths_build_every_shipped_binary(self):
        listed = set(package.listed_sources(package.REPO, package.archive_paths()))
        members = re.findall(r'"([^"]+)"', re.search(r'members = \[([^\]]*)\]',
                                                     (package.REPO / 'Cargo.toml').read_text()).group(1))
        needed = {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml', 'LICENSE',
                  'crates/ukai-jail/src/bin/ukai-vm.rs', 'crates/ukai-jail/build.rs',
                  'crates/ukai-jail/vm/vz.swift', 'crates/ukai-jail/vm/custodian.c',
                  'crates/ukai-jail/vm/entitlements.plist', 'crates/ukai-jail/vm/cli.py',
                  'crates/ukai-jail/vm/run.py', 'crates/ukai-jail/vm/guest.py',
                  'docs/specs/jail-v1/examples/event-note-learning-read.json',
                  *(member + '/Cargo.toml' for member in members), *package.build_inputs()[1:]}
        self.assertEqual(sorted(needed - listed), [])
        self.assertTrue(any(name.startswith('crates/ukai-jail/src/') for name in listed))

    def test_extracted_source_imports_image_preparation_without_the_checkout(self):
        names = package.listed_sources(package.REPO, package.archive_paths())
        sources = {name: package.digest(package.REPO / name) for name in names}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / 'source.tar.gz'
            package.write_source_archive(archive_path, package.REPO, sources)
            with tarfile.open(archive_path) as archive:
                archive.extractall(root / 'extracted', filter='data')
            exported = root / 'extracted' / 'vm'
            # Isolated Python cannot borrow the checkout or a caller's PYTHONPATH.
            # Importing the exported builder must resolve its public installer pin
            # without starting a build, invoking a process or contacting a service.
            script = '''import sys
def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn')) or event == 'os.system':
        raise RuntimeError('unexpected import side effect: ' + event)
sys.addaudithook(audit)
sys.path.insert(0, sys.argv[1])
import prepare
print(prepare.JAIL_SHA256)
'''
            result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
                                     str(exported / 'crates/ukai-jail/vm')],
                                    cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r'\A[0-9a-f]{64}\n\Z')
            self.assertEqual((exported / 'install.sh').read_bytes(),
                             (package.REPO / 'install.sh').read_bytes())


    def test_only_the_bounded_proof_and_exact_compile_fixture_are_archived(self):
        proof = 'docs/benchmarks/jail/results/macos-vm-admission-2026-11-15'
        self.assertEqual(package.ADMISSION_PROOF, proof)
        docs = {name for name in package.archive_paths() if name.startswith('docs')}
        fixture = 'docs/specs/jail-v1/examples/event-note-learning-read.json'
        self.assertEqual(docs, {proof, 'docs/specs/jail-v1/network-addresses.json', fixture})
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, GIT_ENVIRONMENT, clear=True):
            repo = Path(temporary) / 'repo'; repo.mkdir()
            included = {fixture: b'{"event":"note"}\n',
                        proof + '/handshake-capabilities/capabilities.json': b'{"fixture":true}\n',
                        proof + '/handshake-raw-credential/guest-artifact/evidence/guest-journal/0000.part': b'exact journal bytes\n'}
            excluded = {'docs/specs/jail-v1/examples/unrelated.json': b'not selected',
                        'docs/unrelated.json': b'not selected', 'docs/benchmarks/jail/results/other/binary.dmg': b'not selected',
                        'evidence/private-key.pem': b'not selected', 'vm-disks/base.raw': b'not selected'}
            for name, data in {**included, **excluded}.items():
                path = repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            subprocess.run(['git', '-C', str(repo), 'init', '-q'], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True, capture_output=True)
            names = package.listed_sources(repo, package.archive_paths())
            self.assertEqual(set(names), set(included))
            archive = Path(temporary) / 'source.tar.gz'
            package.write_source_archive(archive, repo, {name: sha256(included[name]) for name in names})
            with tarfile.open(archive) as held:
                self.assertEqual(set(held.getnames()), {'vm/' + name for name in included})
                for name, data in included.items():
                    self.assertEqual(held.extractfile('vm/' + name).read(), data)


class PreparedSourceTests(unittest.TestCase):
    current = {'guest.py': 'g', 'vz.swift': 'v', 'custodian.c': 'c', 'prepare.py': 'p', 'run.py': 'r'}

    def test_accepts_sources_that_reproduce_every_recorded_hash(self):
        package.verify_prepared_sources({'guest.py': 'g', 'vz.swift': 'v', 'custodian.c': 'c', 'prepare.py': 'p'},
                                        self.current)

    def test_refuses_any_recorded_source_that_differs_or_is_not_committed(self):
        for recorded, named in [({'guest.py': 'g', 'vz.swift': 'old'}, 'vz.swift'),
                                ({'guest.py': 'g', 'prepare.py': 'old', 'custodian.c': 'old'}, 'custodian.c, prepare.py'),
                                ({'guest.py': 'old'}, 'guest.py'),
                                ({'guest.py': 'g', 'removed.py': 'x'}, 'removed.py')]:
            with self.subTest(recorded=recorded):
                with self.assertRaisesRegex(package.SourceError, 'other sources: ' + named + '$'):
                    package.verify_prepared_sources(recorded, self.current)

    def test_refuses_an_image_without_a_recorded_guest_source(self):
        for recorded in (None, [], {}, {'vz.swift': 'v'}):
            with self.subTest(recorded=recorded), self.assertRaises(package.SourceError):
                package.verify_prepared_sources(recorded, self.current)


class SourceArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'vm'
        (self.source / 'sub').mkdir(parents=True)
        self.files = {'run.py': b'print(1)\n', 'sub/notes.txt': b'\x00\xff', 'z.txt': b''}
        for name, data in self.files.items():
            (self.source / name).write_bytes(data)
        (self.source / 'stray.pyc').write_bytes(b'not listed')
        self.sources = {name: sha256(data) for name, data in self.files.items()}

    def test_archives_exactly_the_listed_files(self):
        archive_path = self.root / 'preview-source.tar.gz'
        package.write_source_archive(archive_path, self.source, self.sources)
        with tarfile.open(archive_path) as archive:
            members = archive.getmembers()
            self.assertEqual([m.name for m in members], ['vm/' + name for name in sorted(self.files)])
            for member in members:
                self.assertTrue(member.isreg())
                self.assertEqual(archive.extractfile(member).read(), self.files[member.name[len('vm/'):]])

    def test_refuses_a_file_that_changed_after_hashing(self):
        (self.source / 'run.py').write_bytes(b'print(2)\n')
        with self.assertRaisesRegex(package.SourceError, 'changed while packaging: run.py'):
            package.write_source_archive(self.root / 'out.tar.gz', self.source, self.sources)

    def test_archives_under_the_named_prefix(self):
        archive_path = self.root / 'source.tar.gz'
        package.write_source_archive(archive_path, self.source, self.sources, prefix='ukai-vm-1.0-source/')
        with tarfile.open(archive_path) as archive:
            self.assertEqual([m.name for m in archive.getmembers()],
                             ['ukai-vm-1.0-source/' + name for name in sorted(self.files)])

    def test_refuses_a_symlink(self):
        (self.source / 'link').symlink_to('run.py')
        with self.assertRaisesRegex(package.SourceError, 'not a regular file: link'):
            package.write_source_archive(self.root / 'out.tar.gz', self.source,
                                         dict(self.sources, link=self.sources['run.py']))


class DistributionModeTests(unittest.TestCase):
    def test_private_umask_stage_is_readable_without_changing_originals_or_archive_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'; source.mkdir()
            for name, mode in [('client', 0o750), ('data', 0o640)]:
                (source / name).write_bytes(name.encode())
                (source / name).chmod(mode)
            originals = {p.name: (p.read_bytes(), p.stat().st_mode) for p in source.iterdir()}
            previous = os.umask(0o077)
            try:
                stage = root / 'volume'; (stage / 'payload').mkdir(parents=True)
                for name in originals:
                    shutil.copy2(source / name, stage / 'payload' / name)
                (stage / 'install.sh').write_bytes(b'#!/bin/sh\n')
                (stage / 'install.sh').chmod(0o700)
                (stage / 'SHA256SUMS').write_bytes(b'exact manifest\n')
                archive = stage / 'preview-source.tar.gz'
                package.write_source_archive(archive, source,
                                             {name: sha256(data) for name, (data, _) in originals.items()})
                before = {p.relative_to(stage): p.read_bytes() for p in stage.rglob('*') if p.is_file()}
                self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
                package.normalize_distribution_modes(stage)
            finally:
                os.umask(previous)
            self.assertEqual({p.relative_to(stage).as_posix(): stat.S_IMODE(p.stat().st_mode)
                              for p in [stage, *stage.rglob('*')]},
                             {'.': 0o755, 'payload': 0o755, 'payload/client': 0o755,
                              'payload/data': 0o644, 'install.sh': 0o755,
                              'SHA256SUMS': 0o644, 'preview-source.tar.gz': 0o644})
            self.assertEqual({p.relative_to(stage): p.read_bytes() for p in stage.rglob('*') if p.is_file()}, before)
            self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mode) for p in source.iterdir()}, originals)
            with tarfile.open(archive) as held:
                self.assertEqual({m.name: m.mode for m in held}, {'vm/client': 0o750, 'vm/data': 0o640})

    def test_links_and_special_files_refuse_before_chmod_and_do_not_touch_outside(self):
        for kind in ('file-link', 'directory-link', 'fifo', 'hardlink', 'root-link'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                outside = root / 'outside'; outside.mkdir(mode=0o700)
                original = outside / 'original'; original.write_bytes(b'outside'); original.chmod(0o600)
                stage = root / 'volume'; stage.mkdir(mode=0o700)
                normal = stage / 'a-data'; normal.write_bytes(b'owned'); normal.chmod(0o600)
                if kind == 'file-link':
                    (stage / 'z-bad').symlink_to(original)
                elif kind == 'directory-link':
                    (stage / 'z-bad').symlink_to(outside, target_is_directory=True)
                elif kind == 'fifo':
                    os.mkfifo(stage / 'z-bad')
                elif kind == 'hardlink':
                    os.link(original, stage / 'z-bad')
                else:
                    link = root / 'volume-link'; link.symlink_to(stage, target_is_directory=True)
                def metadata(path):
                    info = path.stat()
                    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                            info.st_mtime_ns, info.st_ctime_ns)

                before = (original.read_bytes(), metadata(original), metadata(outside))
                opened = []
                real_open = os.open

                def record_open(*args, **kwargs):
                    fd = real_open(*args, **kwargs); opened.append(fd); return fd

                with mock.patch.object(package.os, 'open', side_effect=record_open):
                    with self.assertRaises(package.SourceError):
                        package.normalize_distribution_modes(link if kind == 'root-link' else stage)
                self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(normal.stat().st_mode), 0o600)
                self.assertEqual((original.read_bytes(), metadata(original), metadata(outside)), before)
                for fd in opened:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_stage_permissions_clear_special_and_write_bits_preserving_executability(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / 'volume'; stage.mkdir(); stage.chmod(0o2777)
            for name, mode in [('data', 0o666), ('executable', 0o4751)]:
                (stage / name).write_bytes(name.encode()); (stage / name).chmod(mode)
            package.normalize_distribution_modes(stage)
            self.assertEqual([stat.S_IMODE(p.stat().st_mode) for p in
                              (stage, stage / 'data', stage / 'executable')], [0o755, 0o644, 0o755])

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS quarantine and ACL preservation')
    def test_normalization_preserves_quarantine_and_acl(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / 'volume'; stage.mkdir(mode=0o700)
            data = stage / 'data'; data.write_bytes(b'public fixture'); data.chmod(0o600)
            quarantine = b'0081;00000000;ukai-stage-test;'
            subprocess.run(['/usr/bin/xattr', '-wx', 'com.apple.quarantine', quarantine.hex(), str(data)],
                           check=True, capture_output=True)
            subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(data)], check=True, capture_output=True)
            acl = subprocess.run(['/bin/ls', '-le', str(data)], check=True, capture_output=True).stdout.splitlines()[1:]
            self.assertTrue(acl)
            package.normalize_distribution_modes(stage)
            found = subprocess.run(['/usr/bin/xattr', '-px', 'com.apple.quarantine', str(data)],
                                   check=True, capture_output=True).stdout.decode()
            self.assertEqual(bytes.fromhex(found), quarantine)
            self.assertEqual(subprocess.run(['/bin/ls', '-le', str(data)], check=True,
                                            capture_output=True).stdout.splitlines()[1:], acl)
            self.assertEqual(stat.S_IMODE(data.stat().st_mode), 0o644)


class PackageMetadataTests(unittest.TestCase):
    def test_host_client_notices_come_from_current_source_not_guest_archive(self):
        notices = package.host_notices()
        self.assertIn((package.REPO / 'crates/ukai-jail/dist/THIRD_PARTY_NOTICES.txt').read_bytes(), notices)
        self.assertIn(b'Copyright 2015-2025 Brian Smith.', notices)
        self.assertIn(b'Copyright notices for The Rust Standard Library', notices)

    def test_stale_host_notices_refuse(self):
        with mock.patch('package.subprocess.check_output', side_effect=subprocess.CalledProcessError(1, ['notice-check'])):
            with self.assertRaises(subprocess.CalledProcessError):
                package.host_notices()

    def test_keeps_prepare_time_source_hashes(self):
        prepared = {'schema': 'ukai.vm.image-build/1', 'status': 'prepared',
                    'source_sha256': {'guest.py': 'g0', 'vz.swift': 'v0'}, 'helper_sha256': 'prepared-vz'}
        packaged = {'guest.py': 'g0', 'vz.swift': 'v0', 'run.py': 'r1', 'README.md': 'm1'}
        metadata = package.package_metadata(prepared, packaged, helper_sha256='signed-vz')
        self.assertEqual(metadata['source_sha256'], {'guest.py': 'g0', 'vz.swift': 'v0'})
        self.assertEqual(metadata['package_source_sha256'], packaged)
        self.assertEqual(metadata['guest_source_sha256'], 'g0')
        self.assertEqual(metadata['helper_sha256'], 'signed-vz')
        self.assertEqual(prepared['helper_sha256'], 'prepared-vz')
        self.assertEqual(list(metadata)[:4], list(prepared))


if __name__ == '__main__':
    unittest.main()
