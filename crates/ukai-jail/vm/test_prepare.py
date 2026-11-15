import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import prepare


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


if __name__ == '__main__':
    unittest.main()
