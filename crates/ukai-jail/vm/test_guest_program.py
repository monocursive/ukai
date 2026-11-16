"""Catalog byte contract and anchored synthetic filesystem regressions."""
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import guest_program as gp

FIXTURES = Path(__file__).parent / 'fixtures'
PROFILE = b'''name = "example"
jail = "agent"
state = "persistent"
credentials_one_of = ["token"]
[credentials.token]
mode = "vault"
source = "@config/credentials/token"
binaries = ["@program"]
'''


def elf_bytes():
    loader = b'/lib/ld-linux-aarch64.so.1\0'
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', header, 16, 3, 183, 1)
    struct.pack_into('<Q', header, 32, 64)
    struct.pack_into('<HHH', header, 52, 64, 56, 1)
    return bytes(header) + struct.pack('<IIQQQQQQ', 3, 4, 120, 0, 0, len(loader), len(loader), 1) + loader


def catalog():
    return json.loads((FIXTURES / gp.CATALOG_FILENAME).read_bytes())


def verified_catalog():
    value = catalog()
    return {'catalog': value, 'sha256': 'd' * 64,
            'credentials': {value['entries'][0]['id']: ['token']}}


def intent_for(verified, suffix=(b'-p', b'test')):
    entry = verified['catalog']['entries'][0]
    argv = [entry['executable'].encode(), *suffix]
    intent = {'schema': gp.CONTRACT, 'catalog_sha256': verified['sha256'], 'entry_id': entry['id'],
              'launch_name': entry['alias'], 'profile_sha256': entry['profile_sha256'], 'state': 'attempt',
              'selected_credential_id': 'token', 'argv_suffix': [base64.b64encode(x).decode() for x in suffix],
              'request_argv_digest': gp.argv_digest([entry['alias'].encode(), *suffix]),
              'resolved_argv_digest': gp.argv_digest(argv), 'expected_policy_digest': 'sha256:' + 'e' * 64}
    return intent, [base64.b64encode(x).decode() for x in argv]


class CatalogTests(unittest.TestCase):
    def test_shared_rust_python_vectors(self):
        vectors = json.loads((FIXTURES / 'guest-program-catalog-vectors.json').read_bytes())
        for row in vectors['valid']:
            with self.subTest(valid=row['name']): gp.parse_catalog(row['data'].encode())
        for row in vectors['invalid']:
            with self.subTest(invalid=row['name']), self.assertRaises((ValueError, TypeError)):
                gp.parse_catalog(row['data'].encode())

    def test_utf16_and_duplicate_keys_refused(self):
        raw = json.dumps(catalog())
        for data in (raw.encode('utf-16'), raw.replace('"schema":', '"schema":"duplicate", "schema":').encode()):
            with self.assertRaises(ValueError): gp.parse_catalog(data)

    def test_intent_bytes_and_binding(self):
        verified = verified_catalog(); intent, argv = intent_for(verified, (b'', b'\xff'))
        entry, suffix = gp.validate_intent(intent, argv, verified)
        self.assertEqual(suffix, [b'', b'\xff'])
        bound = gp.native_binding(intent, entry, intent['expected_policy_digest'])
        self.assertNotEqual(bound['resolved_argv_digest'], bound['request_argv_digest'])
        self.assertEqual(bound['executable_sha256'], entry['executable_sha256'])

    def test_identity_changes_and_unknown_intent_fields_refused(self):
        verified = verified_catalog(); good, argv = intent_for(verified)
        changes = {'schema': 'old', 'catalog_sha256': '0' * 64, 'entry_id': 'other', 'launch_name': 'other',
                   'profile_sha256': '0' * 64, 'state': 'persistent', 'selected_credential_id': 'second',
                   'request_argv_digest': 'sha256:' + '0' * 64, 'resolved_argv_digest': 'sha256:' + '0' * 64,
                   'expected_policy_digest': 'no-prefix', 'extra': True}
        for key, value in changes.items():
            with self.subTest(field=key), self.assertRaises(ValueError):
                gp.validate_intent({**good, key: value}, argv, verified)
        with self.assertRaises(ValueError): gp.validate_intent(good, argv[:-1], verified)
        with self.assertRaises(ValueError): gp.native_binding(good, verified['catalog']['entries'][0], 'sha256:' + '0' * 64)

    def test_canonical_padded_base64_and_nul_refusal(self):
        for value in ('YQ', 'YR==', 'YQ===', 'AA==', 'YQ==\n'):
            with self.subTest(value=value), self.assertRaises(ValueError): gp.decode_argv([value])


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.value = catalog(); self.entry = self.value['entries'][0]
        self.exe = self.root / self.entry['executable'].lstrip('/')
        self.profile = self.root / str(gp.PROFILE_DIRECTORY / 'example.toml').lstrip('/')
        self.jail = self.root / str(gp.JAIL_PATH).lstrip('/')
        self.manifest = self.root / str(gp.CATALOG_PATH).lstrip('/')
        for path, data, mode in [(self.exe, elf_bytes(), 0o555), (self.profile, PROFILE, 0o644),
                                 (self.jail, b'pinned-jail-test-bytes', 0o755)]:
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(mode)
        self.exe.parent.chmod(0o555)
        for key, path in [('executable_sha256', self.exe), ('profile_sha256', self.profile), ('guest_jail_sha256', self.jail)]:
            self.entry[key] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.entry['executable_size'] = self.exe.stat().st_size
        self.save(); self.addCleanup(lambda: self.exe.parent.chmod(0o755))

    def save(self):
        self.manifest.parent.mkdir(parents=True, exist_ok=True)
        self.manifest.write_text(json.dumps(self.value))

    def verify(self, **kwargs):
        return gp.verify_catalog(filesystem_root=self.root, owner_uid=os.getuid(), owner_gid=os.getgid(), **kwargs)

    def test_whole_tree_profile_and_jail_verified(self):
        observed = self.verify()
        self.assertEqual(observed['credentials'], {self.entry['id']: ['token']})
        self.assertEqual(observed['sha256'], hashlib.sha256(self.manifest.read_bytes()).hexdigest())

    def test_missing_legacy_but_disappearing_present_refuses(self):
        with mock.patch.object(gp, '_read', side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError): self.verify()
        self.manifest.unlink(); self.assertIsNone(self.verify())

    def test_wrong_owner_and_writable_ancestor_refuse(self):
        with self.assertRaises(ValueError): gp.verify_catalog(filesystem_root=self.root, owner_uid=os.getuid()+1, owner_gid=os.getgid())
        self.exe.parent.parent.chmod(0o777)
        with self.assertRaises(ValueError): self.verify()
        self.exe.parent.parent.chmod(0o755)

    def test_extra_file_refuses(self):
        self.exe.parent.chmod(0o755); (self.exe.parent/'extra').write_text('x'); self.exe.parent.chmod(0o555)
        with self.assertRaises(ValueError): self.verify()

    def test_symlink_hardlink_fifo_refuse(self):
        self.exe.parent.chmod(0o755); self.exe.unlink(); self.exe.symlink_to(self.jail); self.exe.parent.chmod(0o555)
        with self.assertRaises((ValueError, OSError)): self.verify()
        self.exe.parent.chmod(0o755); self.exe.unlink(); os.link(self.jail, self.exe); self.exe.parent.chmod(0o555)
        with self.assertRaises(ValueError): self.verify()
        self.exe.parent.chmod(0o755); self.exe.unlink(); os.mkfifo(self.exe); self.exe.parent.chmod(0o555)
        with self.assertRaises(ValueError): self.verify()

    def test_catalog_link_and_companion_tamper_refuse(self):
        raw = self.manifest.read_bytes(); self.manifest.unlink(); self.manifest.symlink_to(self.profile)
        with self.assertRaises(OSError): self.verify()
        self.manifest.unlink(); self.manifest.write_bytes(raw); self.profile.write_bytes(PROFILE+b'\n# changed')
        with self.assertRaises(ValueError): self.verify()

    def test_program_and_jail_hash_refuse(self):
        self.entry['executable_sha256'] = '0'*64; self.save()
        with self.assertRaises(ValueError): self.verify()
        self.entry['executable_sha256'] = hashlib.sha256(self.exe.read_bytes()).hexdigest(); self.save(); self.jail.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.verify()

    def test_wrong_elf_arch_refuses_even_matching_hash(self):
        data = bytearray(self.exe.read_bytes()); data[18:20] = (62).to_bytes(2, 'little')
        self.exe.chmod(0o755); self.exe.write_bytes(data); self.exe.chmod(0o555)
        self.entry['executable_sha256'] = hashlib.sha256(data).hexdigest(); self.save()
        with self.assertRaisesRegex(ValueError, 'ELF'): self.verify()

    def test_replacement_during_hash_refuses(self):
        real_open = gp._open; seen = 0
        def replace(path, *args, **kwargs):
            nonlocal seen
            if str(path) == self.entry['executable']:
                seen += 1
                if seen == 2:
                    self.exe.parent.chmod(0o755); data = self.exe.read_bytes(); self.exe.unlink()
                    self.exe.write_bytes(data); self.exe.chmod(0o555); self.exe.parent.chmod(0o555)
            return real_open(path, *args, **kwargs)
        with mock.patch.object(gp, '_open', side_effect=replace), self.assertRaises(ValueError): self.verify()

    def test_wrong_profile_source_refuses(self):
        bad = PROFILE.replace(b'@config/credentials/token', b'/tmp/token')
        self.profile.write_bytes(bad); self.entry['profile_sha256'] = hashlib.sha256(bad).hexdigest(); self.save()
        with self.assertRaisesRegex(ValueError, 'credential shape'): self.verify()

    def test_verification_deadline(self):
        with mock.patch.object(gp.time, 'monotonic', side_effect=[0, gp.VERIFY_SECONDS+1]), self.assertRaisesRegex(ValueError, 'deadline'):
            self.verify()
