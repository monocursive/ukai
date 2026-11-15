import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import notices


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.read = notices.read_source(notices.ROOT)
        self.inventory = json.loads(self.read(notices.INVENTORY))

    def altered(self, changes):
        return lambda path: changes[path] if path in changes else self.read(path)

    def test_checked_bundle_preserves_current_upstream_attribution(self):
        data = notices.checked(self.read)
        for required in (b'Copyright 2015-2025 Brian Smith.', b'Copyright (c) 2014, Google Inc.',
                         b'Copyright (c) 2016 Joseph Birr-Pixton', b'Copyright (c) 2018 Carl Lerche',
                         b'Isis Agora Lovecruft', b'Copyright notices for The Rust Standard Library',
                         b'Unicode 17.0.0', 'Copyright © 1991-2026 Unicode, Inc.'.encode(),
                         b'Community Data License Agreement - Permissive - Version 2.0'):
            self.assertIn(required, data)
        self.assertTrue(all(package['targets'] == list(notices.TARGETS) for package in self.inventory['packages']))
        self.assertNotIn('rusqlite', {p['name'] for p in self.inventory['packages']})

    def test_every_guarded_source_change_refuses(self):
        for path in notices.INPUTS:
            with self.subTest(path=path):
                changed = self.read(path) + b'\n'
                with self.assertRaisesRegex(ValueError, 'Stale third-party notices'):
                    notices.checked(self.altered({path: changed}))

    def test_bundle_tamper_refuses(self):
        with self.assertRaisesRegex(ValueError, 'bundle changed'):
            notices.checked(self.altered({notices.BUNDLE: self.read(notices.BUNDLE) + b'changed'}))

    def test_inventory_cannot_drop_package_or_notice(self):
        for key in ('packages', 'documents'):
            value = copy.deepcopy(self.inventory)
            del value[key][0]
            with self.assertRaises(ValueError):
                notices.checked(self.altered({notices.INVENTORY: json.dumps(value).encode()}))

    def test_inventory_cannot_hide_guarded_input_or_target(self):
        for mutate in (lambda v: v['inputs_sha256'].pop('Cargo.lock'), lambda v: v['targets'].pop()):
            value = copy.deepcopy(self.inventory)
            mutate(value)
            with self.assertRaises(ValueError):
                notices.checked(self.altered({notices.INVENTORY: json.dumps(value).encode()}))

    def test_wrong_crate_checksum_or_rust_pin_refuses(self):
        for mutate in (lambda v: v['packages'][0].update(checksum='0' * 64),
                       lambda v: v['rust_standard_library'].update(release='0.0.0')):
            value = copy.deepcopy(self.inventory)
            mutate(value)
            with self.assertRaises(ValueError):
                notices.checked(self.altered({notices.INVENTORY: json.dumps(value).encode()}))

    def test_stale_guard_survives_optimized_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            for name in set(notices.INPUTS) | {notices.BUNDLE, notices.INVENTORY, 'LICENSE'}:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(self.read(name))
            (source / 'Cargo.lock').write_bytes(b'changed')
            result = subprocess.run([sys.executable, '-O', str(notices.ROOT / notices.BASE / 'notices.py'),
                                     'check', '--source', str(source)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Stale third-party notices: Cargo.lock', result.stderr)

    def test_rust_html_conversion_preserves_every_pre_block_and_urls(self):
        parser = notices.LibraryText()
        parser.feed('<html><head><title>ignored</title></head><body><h1>Rust</h1>'
                    '<pre>  Copyright &copy; A\nPermission &lt;all&gt;\n </pre>'
                    '<a href="https://example.invalid/license">license</a>'
                    '<pre>second\n notice\n</pre></body></html>')
        data = parser.text().decode()
        self.assertEqual(len(parser.preformatted), 2)
        for value in parser.preformatted:
            self.assertIn(value, data)
        self.assertIn('https://example.invalid/license', data)
        self.assertNotIn('ignored', data)

    def crate(self, files):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for path, content in files.items():
                member = tarfile.TarInfo('ring-1.0.0/' + path)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        return output.getvalue()

    def test_ring_nested_notices_and_generated_assembly_headers_are_retained(self):
        raw = self.crate({'LICENSE': b'Index: see other files',
                          'src/nested/LICENSE-MIT': b'nested permission', 'third_party/AUTHORS': b'upstream authors',
                          'pregenerated/asm.S': b'// generated\n#include "header.h"\n#if FOO\n\n# Copyright Vendor\n# Permission to use granted.\n',
                          'crypto/example.c': b'/* Copyright C Author\nPermission to use. */\nint main() {}',
                          'asm/arm.S': b'@ Copyright ARM Author\n@ Permission to use.\n'})
        documents = notices.crate_documents(raw, 'ring', '1.0.0')
        self.assertIn('src/nested/LICENSE-MIT', documents)
        self.assertIn('third_party/AUTHORS', documents)
        for required in (b'Copyright Vendor', b'Copyright C Author', b'Copyright ARM Author'):
            self.assertTrue(any(required in value for value in documents.values()))

    def test_crate_archive_path_escape_refuses(self):
        with self.assertRaisesRegex(ValueError, 'Unsafe crate archive path'):
            notices.crate_documents(self.crate({'../LICENSE': b'unsafe'}), 'ring', '1.0.0')

    def test_generation_checks_locked_archive_digest_before_extracting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.98.1"\n')
            (root / 'Cargo.lock').write_text('[[package]]\nname="ring"\nversion="1.0.0"\n'
                'source="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + '0' * 64 + '"\n')
            cache = root / 'registry/cache/fixture'
            cache.mkdir(parents=True)
            (cache / 'ring-1.0.0.crate').write_bytes(self.crate({'LICENSE': b'wrong checksum'}))
            metadata = {'packages': [{'name': 'ring', 'version': '1.0.0', 'source': 'registry', 'license': 'ISC'}]}
            def run(argv, _root):
                return json.dumps(metadata).encode() if 'metadata' in argv else b'ring v1.0.0\n'
            with patch.dict(os.environ, {'CARGO_HOME': str(root)}), patch.object(notices, 'run', side_effect=run), patch.object(notices, 'crate_documents') as extract:
                with self.assertRaisesRegex(ValueError, 'checksum-verified'):
                    notices.generate(root)
                extract.assert_not_called()

    def test_generation_extracts_the_exact_archive_buffer_it_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in notices.INPUTS:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(self.read(name))
            raw = self.crate({'LICENSE': b'Copyright Fixture\nPermission to use.'})
            (root / 'Cargo.lock').write_text('[[package]]\nname="ring"\nversion="1.0.0"\n'
                'source="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + notices.digest(raw) + '"\n')
            archive = root / 'registry/cache/fixture/ring-1.0.0.crate'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(raw)
            sysroot = root / 'toolchain'
            docs = sysroot / 'share/doc/rust'
            (docs / 'licenses').mkdir(parents=True)
            (docs / 'COPYRIGHT-library.html').write_text('<body><p><b>License:</b> Apache-2.0 OR MIT</p>'
                                                        '<pre>Copyright Rust fixture</pre></body>')
            for name in ('MIT.txt', 'Apache-2.0.txt'):
                (docs / 'licenses' / name).write_text('License fixture ' + name)
            metadata = {'packages': [{'name': 'ring', 'version': '1.0.0', 'source': 'registry', 'license': 'ISC'}]}
            def run(argv, _root):
                if 'metadata' in argv:
                    return json.dumps(metadata).encode()
                if argv[0] == 'rustc':
                    return b'release: 1.98.1\n' if '-Vv' in argv else str(sysroot).encode()
                return b'ring v1.0.0\n'
            reads = []
            original = Path.read_bytes
            def changed_cache(path):
                if path == archive:
                    reads.append(path)
                    return raw if len(reads) == 1 else b'concurrently replaced cache'
                return original(path)
            with patch.dict(os.environ, {'CARGO_HOME': str(root)}), patch.object(notices, 'run', side_effect=run), patch.object(Path, 'read_bytes', changed_cache):
                bundle, _ = notices.generate(root)
            self.assertEqual(len(reads), 1)
            self.assertIn(b'Copyright Fixture', bundle)


if __name__ == '__main__':
    unittest.main()
