import hashlib
import base64
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
