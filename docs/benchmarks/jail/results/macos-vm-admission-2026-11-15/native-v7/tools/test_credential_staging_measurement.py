import copy
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import credential_staging_measurement as admission


def image():
    revision, guest_revision = 'b' * 40, 'c' * 40
    build = {'revision': revision, 'dirty': False, 'debug_assertions': False,
             'opt_level': '3', 'target': 'aarch64-apple-darwin',
             'inputs': 'sha256:' + 'a' * 64, 'rustc': 'rustc 1.98.1 (fixture)'}
    guest_build = dict(build, revision=guest_revision, target='aarch64-unknown-linux-gnu')
    return {'schema': 'ukai.vm.image-build/1', 'status': 'prepared', 'source_revision': revision,
            'ukai_jail_version': {'component': 'ukai-jail', 'version': '0.1.0', 'build': build},
            **{key: 'a' * 64 for key in (*admission.IMAGE_KEYS, 'ukai_vm_sha256', 'ukai_jail_sha256',
                'source_archive_sha256', 'compressed_disk_sha256', 'guest_source_sha256', 'jail_archive_sha256')},
            'source_sha256': {'guest.py': 'a' * 64},
            'jail_candidate': {'kind': 'signed-local-candidate', 'signature_verified': True,
                'target': 'aarch64-unknown-linux-gnu', 'archive_sha256': 'a' * 64,
                'binary_sha256': 'd' * 64, 'source_revision': guest_revision,
                'build_inputs': guest_build['inputs'], 'version': {'build': guest_build}}}


def proof():
    held = image()
    installed = {'image': held, 'service_sha256': 'a' * 64, 'client_sha256': 'a' * 64,
                 'image_manifest_sha256': 'e' * 64, 'signing': 'verified-developer-id',
                 'dmg_sha256': 'f' * 64}
    replayed = {'outcome': 'PASS', 'facts': {'independent_probe': True}, 'errors': [],
                'record': {'attempt_id': 'k113-raw-fixture', 'started_at': '2026-11-15T13:00:00Z',
                           'ready': {'guest_contracts': dict(admission.GUEST_CONTRACTS)}},
                'guest': {'attempt_id': 'att_fixture'}, 'image': copy.deepcopy(held),
                'identity': {'binary': {'sha256': 'a' * 64}, 'summary_binary': {'sha256': 'a' * 64},
                             'image_manifest_sha256': 'e' * 64}, 'inputs_sha256': '1' * 64}
    return replayed, installed


def native_proof():
    replayed, installed = proof()
    replayed['record']['ready']['guest_contracts'].update(admission.OPTIONAL_NATIVE_CONTRACTS)
    replayed['record']['ready'][admission.CATALOG_KEY] = '2' * 64
    for held in (replayed['image'], installed['image']):
        held[admission.CATALOG_KEY] = '2' * 64
    return replayed, installed


class AdmissionProofTests(unittest.TestCase):
    def test_all_known_sampling_versions_preserve_only_generic_admission_scope(self):
        for native in (admission.OPTIONAL_NATIVE_CONTRACTS, admission.CURRENT_NATIVE_CONTRACTS,
                       admission.MANAGED_NATIVE_CONTRACTS):
            replayed, installed = native_proof()
            replayed['record']['ready']['guest_contracts'] = admission.GUEST_CONTRACTS | native
            result = admission.derive(replayed, installed)
            self.assertEqual(result['outcome'], 'PASS')
            self.assertFalse(result['qualified'])
            self.assertEqual(result['compatibility']['required_guest_contracts'], admission.GUEST_CONTRACTS)
            self.assertEqual(result['guest_contract_observation']['contracts'], admission.GUEST_CONTRACTS | native)
            self.assertFalse(result['guest_contract_observation']['native_launch_or_sampling_qualified'])
        for contracts in (admission.GUEST_CONTRACTS | {'sampled_exposure': 'ukai.vm.sampled-exposure/2'},
                          admission.GUEST_CONTRACTS | admission.CURRENT_NATIVE_CONTRACTS | {'unknown': 'future/1'},
                          admission.GUEST_CONTRACTS | dict(admission.CURRENT_NATIVE_CONTRACTS, native_program='ukai.vm.guest-native-launch/2')):
            replayed, installed = native_proof()
            replayed['record']['ready']['guest_contracts'] = contracts
            with self.assertRaises(admission.AdmissionError): admission.derive(replayed, installed)

    def test_known_paired_native_contracts_do_not_extend_the_measurement_scope(self):
        result = admission.derive(*native_proof())
        self.assertEqual(result['outcome'], 'PASS')
        self.assertFalse(result['qualified'])
        self.assertEqual(result['compatibility']['required_guest_contracts'], admission.GUEST_CONTRACTS)
        self.assertEqual(result['guest_contract_observation'], {
            'contracts': admission.GUEST_CONTRACTS | admission.OPTIONAL_NATIVE_CONTRACTS,
            admission.CATALOG_KEY: '2' * 64, 'native_launch_or_sampling_qualified': False})
        self.assertIn('program-bound credentials',
                      result['measurements']['credential_staging']['not_measured'])

    def test_native_contract_pair_versions_types_and_catalog_are_exact(self):
        changes = [
            lambda r, i: r['record']['ready'].update(guest_contracts=None),
            lambda r, i: r['record']['ready'].update(guest_contracts=[]),
            lambda r, i: r['record']['ready']['guest_contracts'].update(unknown='future/1'),
            lambda r, i: r['record']['ready']['guest_contracts'].pop('native_program'),
            lambda r, i: r['record']['ready']['guest_contracts'].pop('sampled_exposure'),
            lambda r, i: r['record']['ready']['guest_contracts'].update(native_program='ukai.vm.guest-native-launch/2'),
            lambda r, i: r['record']['ready']['guest_contracts'].update(sampled_exposure='ukai.vm.sampled-exposure/4'),
            lambda r, i: r['record']['ready']['guest_contracts'].update(native_program=True),
            lambda r, i: r['record']['ready']['guest_contracts'].update(sampled_exposure=None),
            lambda r, i: r['record']['ready']['guest_contracts'].update(secret_revocation='future/2'),
            lambda r, i: r['record']['ready']['guest_contracts'].pop('journal_export'),
            lambda r, i: r['record']['ready'].pop(admission.CATALOG_KEY),
            lambda r, i: r['record']['ready'].update({admission.CATALOG_KEY: None}),
            lambda r, i: r['record']['ready'].update({admission.CATALOG_KEY: True}),
            lambda r, i: r['record']['ready'].update({admission.CATALOG_KEY: 'X' * 64}),
            lambda r, i: r['record']['ready'].update({admission.CATALOG_KEY: '3' * 64}),
            lambda r, i: (r['image'].pop(admission.CATALOG_KEY), i['image'].pop(admission.CATALOG_KEY)),
            lambda r, i: (r['image'].update({admission.CATALOG_KEY: None}),
                          i['image'].update({admission.CATALOG_KEY: None})),
        ]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                raw, installed = native_proof(); change(raw, installed)
                with self.assertRaises(admission.AdmissionError):
                    admission.derive(raw, installed)

    def test_legacy_contracts_reject_advertised_or_image_bound_native_catalog(self):
        for location in ('ready', 'image'):
            with self.subTest(location=location):
                raw, installed = proof()
                if location == 'ready':
                    raw['record']['ready'][admission.CATALOG_KEY] = '2' * 64
                else:
                    raw['image'][admission.CATALOG_KEY] = '2' * 64
                    installed['image'][admission.CATALOG_KEY] = '2' * 64
                with self.assertRaises(admission.AdmissionError):
                    admission.derive(raw, installed)

    def test_complete_component_evidence_preserves_its_limited_scope(self):
        result = admission.derive(*proof())
        self.assertEqual(result['outcome'], 'PASS')
        self.assertFalse(result['qualified'])
        row = result['measurements']['credential_staging']
        self.assertEqual(row['measured_at'], '2026-11-15T13:00:00Z')
        self.assertIn('normal installed-client host-source watch', row['not_measured'])
        self.assertFalse(result['compatibility']['older_images_inherit_measurement'])

    def test_v2_separates_measured_artifacts_from_guest_admission_identity(self):
        raw, installed = proof()
        result = admission.derive(raw, installed)
        self.assertEqual(result['schema'], 'ukai.vm.credential-staging-measurement/2')
        compatible = result['compatibility']
        self.assertNotIn('required_image', compatible)
        self.assertEqual(compatible['measured_image'],
                         {key: raw['image'][key] for key in admission.IMAGE_KEYS})
        self.assertEqual(compatible['required_guest_image'],
                         {key: raw['image'][key] for key in ('disk_sha256', 'seed_sha256')})
        self.assertEqual(compatible['required_guest_contracts'], admission.GUEST_CONTRACTS)
        self.assertEqual(result['installation'], installed)
        changed = compatible['changed_host_runtime']
        self.assertFalse(changed['inherits_runtime_qualification'])
        self.assertEqual(changed['requires'], ['clean-source rebuild',
            'Developer ID signature and exact installed-byte verification',
            'fresh installed-client live requalification'])

    def test_guest_only_compatibility_does_not_relax_exact_measured_artifact_binding(self):
        for key in admission.IMAGE_KEYS:
            for side in ('raw', 'installed'):
                with self.subTest(key=key, side=side):
                    raw, installed = proof()
                    (raw if side == 'raw' else installed)['image'][key] = '2' * 64
                    with self.assertRaises(admission.AdmissionError):
                        admission.derive(raw, installed)

    def test_replay_image_signer_and_contract_mismatches_refuse(self):
        changes = [
            lambda r, i: r.update(outcome='FAIL'),
            lambda r, i: r.update(facts={}),
            lambda r, i: r['facts'].update(independent_probe=False),
            lambda r, i: r['facts'].update(independent_probe=1),
            lambda r, i: r.update(errors=['ValueError']),
            lambda r, i: r['image'].update(disk_sha256='2' * 64),
            lambda r, i: r['identity']['binary'].update(sha256='2' * 64),
            lambda r, i: r['identity']['summary_binary'].update(sha256='2' * 64),
            lambda r, i: r['identity'].update(image_manifest_sha256='2' * 64),
            lambda r, i: r.update(inputs_sha256=None),
            lambda r, i: r['record'].update(started_at='not-a-dateZ'),
            lambda r, i: r['record'].update(started_at='2026-11-15Z'),
            lambda r, i: r['record'].update(started_at='2026-11-15T13:00:00+01:00'),
            lambda r, i: r['record'].update(attempt_id='another-component'),
            lambda r, i: r['record']['ready'].pop('guest_contracts'),
            lambda r, i: r['record']['ready']['guest_contracts'].update(secret_revocation='future/2'),
            lambda r, i: r['record']['ready']['guest_contracts'].pop('journal_export'),
            lambda r, i: i.update(signing='unsigned'),
            lambda r, i: i.update(dmg_sha256='not-a-hash'),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                raw, installed = proof()
                change(raw, installed)
                with self.assertRaises(admission.AdmissionError):
                    admission.derive(raw, installed)

    def test_dirty_wrong_toolchain_or_guest_provenance_refuses(self):
        changes = [lambda i: i.update(status='downloaded'),
            lambda i: i.update(source_revision=None),
            lambda i: i['ukai_jail_version']['build'].update(dirty=True),
            lambda i: i['ukai_jail_version']['build'].update(rustc='rustc 1.96.0'),
            lambda i: i['ukai_jail_version']['build'].update(target='x86_64-apple-darwin'),
            lambda i: i['ukai_jail_version']['build'].update(debug_assertions=True),
            lambda i: i['source_sha256'].update({'guest.py': '2' * 64}),
            lambda i: i['jail_candidate'].update(signature_verified=False),
            lambda i: i['jail_candidate'].update(archive_sha256='2' * 64),
            lambda i: (i['jail_candidate'].pop('build_inputs'),
                       i['jail_candidate']['version']['build'].pop('inputs')),
            lambda i: i['jail_candidate']['version']['build'].update(rustc='rustc 1.96.0'),
            lambda i: i['jail_candidate']['version']['build'].update(dirty=True)]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                held = image(); change(held)
                with self.assertRaises(admission.AdmissionError): admission.clean_image(held)

    def test_failed_replay_never_mounts_or_executes_installed_programs(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(admission.revocation, 'replay_raw',
                return_value={'outcome': 'FAIL'}), patch.object(admission, 'verify_signed_install') as verify:
            result = admission.main(['--raw', tmp, '--installed', tmp, '--dmg', tmp,
                                     '--team-id', 'TEAMID1234', '--out', str(Path(tmp) / 'out')])
            self.assertEqual(result, 1)
            verify.assert_not_called()


class ArtifactTests(unittest.TestCase):
    def test_optional_catalog_must_match_manifest_metadata_and_strict_schema(self):
        valid = (Path(__file__).parent / 'fixtures/guest-program-catalog.json').read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / 'payload/image/guest-program-catalog.json'
            path.parent.mkdir(parents=True); path.write_bytes(valid)
            name = path.relative_to(root).as_posix()
            digest = admission.sha(valid)
            admission.verify_catalog_manifest(root, {admission.CATALOG_KEY: digest}, {name: digest})
            for metadata, manifest in (({}, {name: digest}),
                    ({admission.CATALOG_KEY: digest}, {}),
                    ({admission.CATALOG_KEY: None}, {name: digest}),
                    ({admission.CATALOG_KEY: '3' * 64}, {name: digest}),
                    ({admission.CATALOG_KEY: '3' * 64}, {name: '3' * 64})):
                with self.subTest(metadata=metadata, manifest=manifest):
                    with self.assertRaises(admission.AdmissionError):
                        admission.verify_catalog_manifest(root, metadata, manifest)
            for raw in (b'{}', b'{"schema": 1, "schema": 2}'):
                path.write_bytes(raw); digest = admission.sha(raw)
                with self.assertRaises(ValueError):
                    admission.verify_catalog_manifest(root, {admission.CATALOG_KEY: digest}, {name: digest})
            admission.verify_catalog_manifest(root, {}, {})

    def test_manifest_rejects_ambiguous_escaping_and_duplicate_paths(self):
        row = 'a' * 64 + '  payload/bin/ukai-vm\n'
        self.assertEqual(admission.parse_manifest(row.encode()), {'payload/bin/ukai-vm': 'a' * 64})
        for path in ('', '/tmp/x', '../x', 'payload/../x', 'payload//x', 'payload/./x', 'x\\y', 'x\0y'):
            with self.subTest(path=path), self.assertRaises(admission.AdmissionError):
                admission.parse_manifest(('a' * 64 + '  ' + path + '\n').encode())
        for raw in (row + row, '', 'z' * 64 + '  file\n'):
            with self.assertRaises(admission.AdmissionError): admission.parse_manifest(raw.encode())

    def test_hashing_refuses_links_hardlinks_fifo_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); path = root / 'data'; path.write_bytes(b'signed bytes')
            self.assertEqual(admission.digest_file(path), admission.sha(b'signed bytes'))
            with self.assertRaises(admission.AdmissionError): admission.digest_file(path, cap=2)
            linked = root / 'link'; linked.symlink_to(path)
            with self.assertRaises(OSError): admission.digest_file(linked)
            linked.unlink(); os.link(path, linked)
            with self.assertRaises(admission.AdmissionError): admission.digest_file(path)
            linked.unlink(); os.mkfifo(root / 'fifo')
            with self.assertRaises(admission.AdmissionError): admission.digest_file(root / 'fifo')

    def test_unreadable_directory_cannot_be_silently_excluded_from_inventory(self):
        def denied_walk(*args, onerror=None, **kwargs):
            if onerror is not None: onerror(PermissionError('unreadable signed subtree'))
            return iter(())
        with tempfile.TemporaryDirectory() as tmp, patch.object(admission.os, 'walk', side_effect=denied_walk):
            with self.assertRaises(PermissionError): admission.tree_files(Path(tmp))

    @unittest.skipUnless(Path('/usr/bin/csreq').is_file(), 'Apple requirement compiler unavailable')
    def test_real_apple_requirement_compiler_accepts_the_inline_contract(self):
        with patch.object(admission, 'run_tool') as run:
            admission.verify_signature(Path('/unused'), 'TEAMID1234')
            expression = run.call_args.args[0][-2]
        result = subprocess.run(['/usr/bin/csreq', '-r', expression, '-t'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(b'TEAMID1234', result.stdout)
        for invalid in ('', 'bad"team', 'TEAMID1234;'):
            with self.assertRaises(admission.AdmissionError): admission.developer_requirement(invalid)


class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.dmg = self.root / 'candidate.dmg'
        self.dmg.write_bytes(b'dmg')
        self.private = self.root / 'owned'
        self.mount = self.private / 'volume'
        self.images, self.calls = [], []
        self.attach_error = self.inspect_error = self.detach_error = None
        self.after_attach = self.mounted_image
        self.info_after_attach_error = False
        self.keep_after_detach = False
        self.started = False
        for name, replacement in (('verify_signature', lambda *args: None),
                                  ('run_tool', self.run_tool),
                                  ('inspect_volume', self.inspect)):
            held = patch.object(admission, name, side_effect=replacement)
            held.start(); self.addCleanup(held.stop)
        held = patch.object(admission.tempfile, 'mkdtemp', side_effect=self.make_private)
        held.start(); self.addCleanup(held.stop)

    def make_private(self, **kwargs):
        self.private.mkdir(mode=0o700)
        return str(self.private)

    def mounted_image(self, mounted=True, image=None, disk='/dev/disk90'):
        entities = [{'dev-entry': disk}, {'dev-entry': disk + 's1'}]
        if mounted:
            entities[-1]['mount-point'] = str(self.mount)
        return {'image-path': str(image or self.dmg), 'system-entities': entities}

    def run_tool(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        self.calls.append(argv)
        if argv[1] == 'info':
            if self.started and self.info_after_attach_error:
                raise subprocess.TimeoutExpired(argv, 120)
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({'images': self.images}), b'')
        if argv[1] == 'attach':
            self.started = True
            image = self.after_attach()
            if image is not None: self.images.append(image)
            if self.attach_error is not None: raise self.attach_error
        elif argv[1] == 'detach':
            if self.detach_error is not None: raise self.detach_error
            if not self.keep_after_detach: self.images.clear()
        else:
            self.fail('unexpected external command')
        return subprocess.CompletedProcess(argv, 0, b'', b'')

    def inspect(self, *args):
        if self.inspect_error is not None: raise self.inspect_error
        return {'payload': 'verified'}

    def verify(self):
        return admission.verify_signed_install(self.root, self.dmg, 'TEAMID1234')

    def detaches(self):
        return [argv[-1] for argv in self.calls if argv[1] == 'detach']

    def test_success_has_exact_mount_and_verified_absence_before_empty_directory_cleanup(self):
        result = self.verify()
        self.assertEqual(result['payload'], 'verified')
        self.assertEqual(result['dmg_sha256'], admission.sha(b'dmg'))
        self.assertEqual(self.detaches(), [str(self.mount)])
        self.assertEqual([argv[1] for argv in self.calls], ['info', 'attach', 'info', 'info', 'detach', 'info'])
        self.assertFalse(self.private.exists())

    def test_payload_failure_detaches_and_preserves_original_exception(self):
        self.inspect_error = admission.AdmissionError('bad payload')
        with self.assertRaises(admission.AdmissionError) as caught: self.verify()
        self.assertIs(caught.exception, self.inspect_error)
        self.assertEqual(self.detaches(), [str(self.mount)])
        self.assertFalse(self.private.exists())

    def test_attach_timeout_with_partial_mount_is_cleaned_without_masking_original(self):
        self.attach_error = subprocess.TimeoutExpired(['hdiutil', 'attach'], 120)
        with self.assertRaises(subprocess.TimeoutExpired) as caught: self.verify()
        self.assertIs(caught.exception, self.attach_error)
        self.assertEqual(self.detaches(), [str(self.mount)])
        self.assertFalse(self.private.exists())

    def test_failed_attach_with_only_new_unmounted_device_is_cleaned(self):
        self.after_attach = lambda: self.mounted_image(mounted=False)
        self.attach_error = subprocess.CalledProcessError(1, ['hdiutil', 'attach'])
        with self.assertRaises(subprocess.CalledProcessError) as caught: self.verify()
        self.assertIs(caught.exception, self.attach_error)
        self.assertEqual(self.detaches(), ['/dev/disk90'])
        self.assertFalse(self.private.exists())

    def test_failed_attach_without_device_does_not_detach(self):
        self.after_attach = lambda: None
        self.attach_error = subprocess.CalledProcessError(1, ['hdiutil', 'attach'])
        with self.assertRaises(subprocess.CalledProcessError): self.verify()
        self.assertEqual(self.detaches(), [])
        self.assertFalse(self.private.exists())

    def test_success_exit_without_owned_mount_refuses_payload_inspection(self):
        self.after_attach = lambda: None
        with patch.object(admission, 'inspect_volume') as inspect:
            with self.assertRaisesRegex(admission.AdmissionError, 'did not attach'): self.verify()
            inspect.assert_not_called()
        self.assertEqual(self.detaches(), [])
        self.assertFalse(self.private.exists())

    def test_unlisted_mount_is_retained_without_guessing_a_detach_target(self):
        self.after_attach = lambda: None
        self.attach_error = subprocess.CalledProcessError(1, ['hdiutil', 'attach'])
        original = Path.is_mount
        with patch.object(Path, 'is_mount', lambda path: path == self.mount or original(path)):
            with self.assertRaisesRegex(admission.AdmissionError, 'cleanup uncertain'): self.verify()
        self.assertEqual(self.detaches(), [])
        self.assertTrue(self.mount.is_dir())

    def test_preexisting_exact_image_or_canonical_alias_never_attaches_or_detaches(self):
        link = self.root / 'alias.dmg'; link.symlink_to(self.dmg)
        for path in (self.dmg, link):
            with self.subTest(path=path):
                self.calls.clear(); self.images = [self.mounted_image(image=path)]
                with self.assertRaisesRegex(admission.AdmissionError, 'already attached'): self.verify()
                self.assertEqual([argv[1] for argv in self.calls], ['info'])
                self.assertFalse(self.private.exists())

    def test_preexisting_device_is_not_detached_when_new_record_claims_it(self):
        self.images = [self.mounted_image(mounted=False, image=self.root / 'other.dmg')]
        self.attach_error = subprocess.CalledProcessError(1, ['hdiutil', 'attach'])
        with self.assertRaisesRegex(admission.AdmissionError, 'cleanup uncertain'): self.verify()
        self.assertEqual(self.detaches(), [])
        self.assertTrue(self.private.is_dir())

    def test_unrelated_image_at_private_mount_is_not_detached_or_removed(self):
        self.after_attach = lambda: self.mounted_image(image=self.root / 'other.dmg')
        with self.assertRaisesRegex(admission.AdmissionError, 'cleanup uncertain'): self.verify()
        self.assertEqual(self.detaches(), [])
        self.assertTrue(self.mount.is_dir())

    def test_ambiguous_or_foreign_mounts_preserve_owned_directory(self):
        for change in ('duplicate_image', 'unexpected_mount', 'two_unmounted_disks'):
            with self.subTest(change=change):
                self.calls.clear(); self.images = []; self.started = False
                def changed():
                    image = self.mounted_image(mounted=change != 'two_unmounted_disks')
                    if change == 'duplicate_image': self.images.append(image)
                    elif change == 'unexpected_mount': image['system-entities'][-1]['mount-point'] = '/Volumes/unowned'
                    else: image['system-entities'].append({'dev-entry': '/dev/disk91'})
                    return image
                self.after_attach = changed
                with self.assertRaisesRegex(admission.AdmissionError, 'cleanup uncertain'): self.verify()
                self.assertEqual(self.detaches(), [])
                self.assertTrue(self.mount.is_dir())
                self.mount.rmdir(); self.private.rmdir()

    def test_detach_failure_and_inventory_failure_cannot_trigger_directory_deletion(self):
        for failure in ('detach', 'inventory', 'still_attached'):
            with self.subTest(failure=failure):
                self.calls.clear(); self.images = []; self.started = False
                self.detach_error = subprocess.CalledProcessError(1, ['hdiutil', 'detach']) if failure == 'detach' else None
                self.info_after_attach_error = failure == 'inventory'
                self.keep_after_detach = failure == 'still_attached'
                with self.assertRaisesRegex(admission.AdmissionError, 'cleanup uncertain'): self.verify()
                self.assertTrue(self.mount.is_dir())
                self.mount.rmdir(); self.private.rmdir()

    def test_replaced_or_nonempty_owned_directory_is_preserved(self):
        moved = self.root / 'original-volume'
        def replace(*args):
            self.mount.rename(moved); self.mount.mkdir()
            return {'payload': 'verified'}
        with patch.object(admission, 'inspect_volume', side_effect=replace):
            with self.assertRaisesRegex(admission.AdmissionError, 'cleanup uncertain'): self.verify()
        self.assertTrue(self.mount.is_dir()); self.assertTrue(moved.is_dir())
        self.mount.rmdir(); self.private.rmdir()
        self.started = False; self.calls.clear()
        def nonempty(*args):
            (self.mount / 'unexpected').write_text('preserve')
            return {'payload': 'verified'}
        with patch.object(admission, 'inspect_volume', side_effect=nonempty):
            with self.assertRaisesRegex(admission.AdmissionError, 'cleanup uncertain'): self.verify()
        self.assertEqual((self.mount / 'unexpected').read_text(), 'preserve')

    def test_inventory_shape_and_size_refuse_before_mount(self):
        invalid = [b'not a plist', b'<?xml version="1.0"?><plist><dict>',
                   plistlib.dumps({}), plistlib.dumps({'images': 'invalid'}),
                   plistlib.dumps({'images': [{'image-path': str(self.dmg), 'system-entities': [{}]}]}),
                   b'x' * (4 * 1024 * 1024 + 1)]
        for raw in invalid:
            with self.subTest(bytes=len(raw)), patch.object(admission, 'run_tool',
                    return_value=subprocess.CompletedProcess([], 0, raw, b'')) as run:
                with self.assertRaises(ValueError): self.verify()
                self.assertEqual(run.call_count, 1)
                self.assertFalse(self.private.exists())


if __name__ == '__main__':
    unittest.main()
