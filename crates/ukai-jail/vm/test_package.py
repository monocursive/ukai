import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
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
        subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)

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

    def test_tree_sources_and_the_revision(self):
        sources = package.tree_sources(self.repo, ['crates/vm'])
        self.assertEqual(sorted(sources), ['crates/vm/guest.py', 'crates/vm/run.py', 'crates/vm/sub/notes.txt'])
        self.assertEqual(sources['crates/vm/run.py'], sha256(b'run.py\n'))
        self.assertRegex(package.head_revision(self.repo), '^[0-9a-f]{40}$')


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


class BuildTests(unittest.TestCase):
    def test_ukai_vm_builds_locked_into_the_named_target_with_provenance(self):
        calls = []
        with mock.patch.dict(os.environ, {'CARGO_TARGET_DIR': '/elsewhere/stale'}):
            built, record = package.build_ukai_vm(Path('/tmp/pkg/cargo-target'), 'a' * 40, '9.9.9-x',
                                                  run=lambda *args, env=None: calls.append((args, env)))
        (args, env), = calls
        words = [str(word) for word in args]
        self.assertIn('--locked', words)
        self.assertEqual(words[words.index('--target-dir') + 1], '/tmp/pkg/cargo-target')
        self.assertEqual(built, Path('/tmp/pkg/cargo-target/release/ukai-vm'))
        self.assertEqual((env['UKAI_BUILD_REVISION'], env['UKAI_BUILD_DIRTY'], env['UKAI_VM_PACKAGE_VERSION']),
                         ('a' * 40, 'false', '9.9.9-x'))
        self.assertNotIn('CARGO_TARGET_DIR', env)
        self.assertTrue(record['locked'])

    def test_the_build_inputs_are_build_provenance_rs_list(self):
        inputs = package.build_inputs()
        self.assertEqual(inputs[0], 'crates/ukai-jail/src')
        self.assertEqual(len(inputs), 41)
        for name in ('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'crates/ukai-jail/build.rs',
                     'docs/specs/jail-v1/network-addresses.json'):
            self.assertIn(name, inputs)


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
                  *(member + '/Cargo.toml' for member in members), *package.build_inputs()[1:]}
        self.assertEqual(sorted(needed - listed), [])
        self.assertTrue(any(name.startswith('crates/ukai-jail/src/') for name in listed))


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


class PackageMetadataTests(unittest.TestCase):
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
