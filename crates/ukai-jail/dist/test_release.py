import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from package import create_archive
from prepare_release import assemble, stage, verify_build, verify_stage, TARGETS
from bootstrap import archive_pins
import coordinates
from coordinates import (ARM64_TARGET, JAIL_VERSION, REPOSITORY, STABLE_HOST, STABLE_TARGET, VM_TARGET, VM_VERSION,
                         release_scope, release_targets)

# An ARM64 stable release from 0.1.1 on, whatever the repository's coordinates say today:
# the version and its qualified host are named, and the scope takes its two-target name.
ARM64_STABLE = patch.multiple(coordinates, ARM64_STABLE_VERSION='0.1.1',
                              ARM64_STABLE_HOST='Ubuntu ARM64, qualified for the test',
                              PUBLICATION_SCOPE='linux-x86_64-arm64-stable')

REVISION = 'a' * 40
INPUTS = 'sha256:' + 'b' * 64


def version(target):
    return {'build': {'target': target, 'revision': REVISION, 'inputs': INPUTS,
                     'dirty': False, 'opt_level': '3', 'debug_assertions': False,
                     'rustc': 'rustc 1.98.1 (fixture)'}}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, target, release='9.9.9-rc.1', tag='stage'):
        binary = self.root / target
        contents = bytearray(64)
        contents[:6] = b'\x7fELF\x02\x01'
        contents[18:20] = TARGETS[target].to_bytes(2, 'little')
        binary.write_bytes(contents)
        out = self.root / (tag + '-' + target)
        # Unit fixture only; actual native execution is exercised separately.
        with patch('prepare_release.subprocess.check_output', return_value=json.dumps(version(target)).encode()):
            stage(binary, target, REVISION, INPUTS, out, release)
        return out

    def test_cli_valid_assembly_and_argument_validation(self):
        script = Path(__file__).with_name('prepare_release.py')
        stages = [self.fixture(target) for target in TARGETS]
        command = [sys.executable, str(script), 'assemble', '--revision', REVISION,
                   '--inputs', INPUTS, '--version', '9.9.9-rc.1', '--out', str(self.root / 'cli-out')]
        for directory in stages:
            command += ['--stage', str(directory)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['published'])
        for field, invalid in [('--revision', 'short'), ('--inputs', 'sha256:bad')]:
            bad = command.copy(); bad[bad.index(field) + 1] = invalid
            result = subprocess.run(bad, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('provide a full 40-character git revision', result.stderr)
        # The stage entry point reaches its binary checks with valid CLI
        # arguments, and rejects invalid provenance before touching a binary.
        binary = self.root / 'invalid-elf'; binary.write_bytes(b'not an ELF image')
        command = [sys.executable, str(script), 'stage', '--binary', str(binary),
                   '--target', next(iter(TARGETS)), '--revision', REVISION, '--inputs', INPUTS,
                   '--version', '9.9.9-rc.1', '--out', str(self.root / 'cli-stage')]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('binary ELF architecture does not match', result.stderr)
        command[command.index('--revision') + 1] = 'short'
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_packaging_is_independent_of_source_mtime_and_location(self):
        binary = self.root / 'binary'
        binary.write_bytes(b'fixed test payload')
        target = next(iter(TARGETS))
        first_archive = create_archive(binary, target, self.root / 'first', '9.9.9-rc.1')
        first = first_archive.read_bytes()
        with tarfile.open(first_archive, 'r:gz') as archive:
            notices = archive.extractfile('ukai-jail.LICENSES.txt').read()
        from notices import checked, read_source
        self.assertEqual(notices, checked(read_source(Path(__file__).resolve().parents[3])))
        self.assertIn(Path(__file__).with_name('WEBPKI_ROOTS_LICENSE').read_bytes(), notices)
        os.utime(binary, (1234567, 1234567))
        other = self.root / 'other'; shutil.copyfile(binary, other)
        second = create_archive(other, target, self.root / 'second', '9.9.9-rc.1').read_bytes()
        self.assertEqual(first, second)
        self.assertEqual(first, create_archive(
            binary, target, self.root / 'renamed', '9.9.9').read_bytes())

    def test_dirty_mismatched_and_debug_builds_refuse(self):
        target = next(iter(TARGETS))
        for key, value in [('target', 'aarch64-apple-darwin'), ('revision', 'c' * 40),
                           ('inputs', 'sha256:' + 'd' * 64), ('dirty', True),
                           ('dirty', None), ('opt_level', '0'), ('debug_assertions', True),
                           ('rustc', 'rustc 1.80.0 (fixture)')]:
            with self.subTest(key=key, value=value):
                record = version(target); record['build'][key] = value
                with self.assertRaises(ValueError):
                    verify_build(record, REVISION, INPUTS, target)

    def test_assembly_refuses_a_stage_with_stale_notices(self):
        targets = iter(TARGETS)
        current = self.fixture(next(targets))
        with patch('package.checked', return_value=b'Notices from an earlier package'):
            stale = self.fixture(next(targets))
        destination = self.root / 'candidate'
        with self.assertRaisesRegex(ValueError, 'license notices differ'):
            assemble([current, stale], REVISION, INPUTS, '9.9.9-rc.1', destination)
        self.assertFalse(destination.exists())

    def test_the_release_coordinates_name_the_arm64_release_together_or_not_at_all(self):
        # Nothing in the publisher re-measures K17: naming the ARM64 stable release is
        # the maintainers' act, and it is one coordinate change, made in full or not at all.
        self.assertEqual(bool(coordinates.ARM64_STABLE_VERSION), bool(coordinates.ARM64_STABLE_HOST))
        self.assertEqual(coordinates.PUBLICATION_SCOPE == 'linux-x86_64-arm64-stable',
                         bool(coordinates.ARM64_STABLE_VERSION))
        self.assertEqual(release_targets(coordinates.JAIL_VERSION), (STABLE_TARGET,))

    def signed_stable(self, release):
        """Assemble and sign a stable candidate of `release` for every target it ships."""
        key = self.root / f'key-{release}'
        pub = self.root / f'public-{release}'
        subprocess.run(['minisign', '-G', '-W', '-s', key, '-p', pub], check=True, capture_output=True)
        trusted = pub.read_text().splitlines()[1]
        stages = [self.fixture(target, release=release) for target in release_targets(release)]
        out = self.root / f'signed-{release}'
        assemble(stages, REVISION, INPUTS, release, out, key, trusted)
        return out, trusted

    @unittest.skipUnless(shutil.which('minisign'), 'minisign is required')
    def test_a_stable_candidate_without_an_arm64_archive_has_one_qualified_target(self):
        # Stable 0.1.0 was published for x86_64 alone and keeps that scope.
        from publish_release import ROOT, check, stable_title, verify_remote_assets
        out, trusted = self.signed_stable('0.0.9')
        with self.assertRaisesRegex(ValueError, 'outside this release scope'):
            self.fixture(ARM64_TARGET, release='0.0.9')
        plan, names = check(out, trusted, source=ROOT)
        self.assertEqual(plan['publication_scope'], 'linux-x86_64-stable')
        self.assertEqual(plan['support'], {'x86_64': STABLE_HOST})
        self.assertEqual(stable_title('0.0.9'), ' — stable Linux x86_64')
        self.assertEqual(len(names), 7)
        with self.assertRaises(ValueError):
            verify_remote_assets(plan, out, names, {'tag_name': plan['tag'], 'prerelease': True, 'assets': []})

    @unittest.skipUnless(shutil.which('minisign'), 'minisign is required')
    def test_a_stable_candidate_from_the_arm64_release_ships_both_qualified_targets(self):
        from publish_release import ROOT, check, stable_title
        release = '0.1.1'
        # Until the coordinates name the ARM64 release, a stable version ships x86_64 alone.
        self.assertEqual(release_targets(release), (STABLE_TARGET,))
        self.assertEqual(release_scope(release), 'linux-x86_64-stable')
        with ARM64_STABLE:
            self.assertEqual(release_targets(release), (STABLE_TARGET, ARM64_TARGET))
            self.assertEqual(release_scope(release), coordinates.PUBLICATION_SCOPE)
            with self.assertRaisesRegex(ValueError, 'exactly one native artifact per release target'):
                assemble([self.fixture(STABLE_TARGET, release=release, tag='alone')], REVISION, INPUTS, release,
                         self.root / 'x86-only', 'A' * 64, 'A' * 56)
            out, trusted = self.signed_stable(release)
            plan, names = check(out, trusted, source=ROOT)
            self.assertEqual(plan['publication_scope'], coordinates.PUBLICATION_SCOPE)
            self.assertEqual(plan['support'], {'x86_64': STABLE_HOST, 'aarch64': coordinates.ARM64_STABLE_HOST})
            self.assertEqual(stable_title(release), ' — stable Linux x86_64 and ARM64')
            self.assertEqual(len(names), 8)
            notes = (out / 'RELEASE_NOTES.md').read_text()
            self.assertIn(f'# Ukai Jail {release} — stable Linux x86_64 and ARM64', notes)
            self.assertIn(f"- aarch64: {coordinates.ARM64_STABLE_HOST}", notes)
            # A stable plan cannot quietly drop a target's qualified host: an edited plan is
            # no longer the signed one. (A re-signed plan with a broader scope is refused by
            # test_publish, whatever it signs.)
            plan_path = out / 'release-plan.json'
            edited = json.loads(plan_path.read_text())
            edited['support'] = {'x86_64': STABLE_HOST}
            plan_path.write_text(json.dumps(edited) + '\n')
            with self.assertRaisesRegex(ValueError, 'signed release asset changed'):
                check(out, trusted, source=ROOT)

    def test_assembly_requires_both_distinct_native_targets(self):
        single = self.fixture(next(iter(TARGETS)))
        for records in [[single], [single, single]]:
            with self.assertRaises(ValueError):
                assemble(records, REVISION, INPUTS, '9.9.9-rc.1', self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_assembly_cannot_reuse_a_published_version_for_different_archives(self):
        stages = [self.fixture(target, release=JAIL_VERSION) for target in release_targets(JAIL_VERSION)]
        with patch('prepare_release.subprocess.run') as signing:
            with self.assertRaisesRegex(ValueError, 'use a new release version'):
                assemble(stages, REVISION, INPUTS, JAIL_VERSION, self.root / 'out',
                         self.root / 'unused-key', 'A' * 56)
            signing.assert_not_called()
        self.assertFalse((self.root / 'out').exists())

    def test_tampered_archive_and_binary_attestation_refuse(self):
        target = next(iter(TARGETS)); directory = self.fixture(target)
        archive = next(directory.glob('*.tar.gz'))
        original = archive.read_bytes(); archive.write_bytes(original + b'corruption')
        with self.assertRaises(ValueError):
            verify_stage(directory, REVISION, INPUTS)
        archive.write_bytes(original)
        record = json.loads((directory / 'artifact.json').read_text())
        record['binary_sha256'] = '0' * 64
        (directory / 'artifact.json').write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            verify_stage(directory, REVISION, INPUTS)

    def test_architecture_is_checked_independently_of_version_json(self):
        target = next(iter(TARGETS)); directory = self.fixture(target)
        other = next(t for t in TARGETS if t != target)
        binary = self.root / target
        with patch('prepare_release.subprocess.check_output', return_value=json.dumps(version(other)).encode()):
            with self.assertRaises(ValueError):
                stage(binary, other, REVISION, INPUTS, self.root / 'wrong', '9.9.9-rc.1')
        record = json.loads((directory / 'artifact.json').read_text())
        record['archive'] = '../outside.tar.gz'
        (directory / 'artifact.json').write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            verify_stage(directory, REVISION, INPUTS)
        record['archive'] = f"ukai-jail-0.0.1-{target}.tar.gz"
        (directory / 'artifact.json').write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            verify_stage(directory, REVISION, INPUTS)

    def test_assembly_refuses_artifacts_from_another_release_version(self):
        target = next(iter(TARGETS))
        other = next(t for t in TARGETS if t != target)
        first = self.fixture(target)
        second = self.fixture(other, release='9.9.9-rc.2')
        with self.assertRaises(ValueError):
            assemble([first, second], REVISION, INPUTS, '9.9.9-rc.1', self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_bootstrap_help_follows_the_assembled_release(self):
        stages = [self.fixture(target, release='9.9.9-rc.2') for target in TARGETS]
        out = self.root / 'out'
        assemble(stages, REVISION, INPUTS, '9.9.9-rc.2', out)
        result = subprocess.run(['bash', str(out / 'bootstrap.sh'), '--help'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Linux: installs Ukai Jail 9.9.9-rc.2 ', result.stdout)
        pins = archive_pins((out / 'bootstrap.sh').read_text())
        for directory in stages:
            record = json.loads((directory / 'artifact.json').read_text())
            self.assertEqual(pins['9.9.9-rc.2', record['target']], record['archive_sha256'])
        # The current public releases remain installable with their original pins.
        self.assertEqual({target for release, target in pins if release == JAIL_VERSION}, set(release_targets(JAIL_VERSION)))
        self.assertIn((VM_VERSION, VM_TARGET), pins)

    def test_unsigned_preparation_remains_unpublished_and_names_signing_blocker(self):
        stages = [self.fixture(t) for t in TARGETS]
        plan = assemble(stages, REVISION, INPUTS, '9.9.9-rc.1', self.root / 'out')
        self.assertFalse(plan['published']); self.assertFalse(plan['signature_verified'])
        self.assertTrue(plan['draft'])
        self.assertIn('production_signing_identity_not_configured', plan['publication_blockers'])
        self.assertEqual(plan['repository'], REPOSITORY)
        # The signed manifest covers the archives of this release and the
        # installer that ships beside them, nothing else.
        manifest = (self.root / 'out' / 'SHA256SUMS').read_text().splitlines()
        names = sorted(line.split('  ')[1] for line in manifest)
        self.assertEqual(names, sorted(
            [f'ukai-jail-9.9.9-rc.1-{target}.tar.gz' for target in TARGETS]
            + ['install.sh', 'bootstrap.sh', 'release-plan.json', 'RELEASE_NOTES.md']))

    def test_native_artifacts_do_not_inherit_historical_host_qualification(self):
        stages = [self.fixture(t) for t in TARGETS]
        out = self.root / 'out'
        plan = assemble(stages, REVISION, INPUTS, '9.9.9-rc.1', out)
        self.assertEqual(set(plan['support']), {'x86_64', 'aarch64'})
        for claim in plan['support'].values():
            self.assertIn('native installation alone does not establish runtime host qualification', claim)
            self.assertIn('matching candidate revision and build-input digest', claim)
            self.assertNotIn('Raspberry Pi', claim)
        self.assertIn('operator_review_of_host_support_and_validation_required', plan['publication_blockers'])
        notes = (out / 'RELEASE_NOTES.md').read_text()
        self.assertIn('developer preview', notes)
        self.assertIn('Previously documented host limitations remain in force', notes)
        self.assertNotIn('Pi memory ceilings', notes)

    @unittest.skipUnless(shutil.which('minisign'), 'minisign is required for actual signature checks')
    def test_real_signature_and_wrong_key_rejection(self):
        stages = [self.fixture(t) for t in TARGETS]
        for name in ['test', 'wrong']:
            subprocess.run(['minisign', '-G', '-W', '-s', str(self.root / (name + '.key')),
                            '-p', str(self.root / (name + '.pub'))], check=True, capture_output=True)
        key = (self.root / 'test.pub').read_text().splitlines()[1]
        plan = assemble(stages, REVISION, INPUTS, '9.9.9-rc.1', self.root / 'signed',
                        self.root / 'test.key', key)
        self.assertTrue(plan['signature_verified']); self.assertFalse(plan['published'])
        self.assertIn('operator_review_of_host_support_and_validation_required', plan['publication_blockers'])
        wrong = (self.root / 'wrong.pub').read_text().splitlines()[1]
        with self.assertRaises(subprocess.CalledProcessError):
            assemble(stages, REVISION, INPUTS, '9.9.9-rc.1', self.root / 'refused',
                     self.root / 'test.key', wrong)
        self.assertFalse((self.root / 'refused/release-plan.json').exists())


if __name__ == '__main__':
    unittest.main()
