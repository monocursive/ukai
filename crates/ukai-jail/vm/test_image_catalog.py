"""Image/package boundary controls; never read a catalog guest path on host."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import cli
import run


def catalog_bytes():
    return (Path(__file__).parent / 'fixtures/guest-program-catalog.json').read_bytes()


class ImageCatalogTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.image = Path(temporary.name)
        self.name = self.image / run.CATALOG_FILENAME
        self.metadata = {'status': 'prepared'}
        for filename, key in [('base.raw', 'disk_sha256'), ('seed.iso', 'seed_sha256'),
                              ('vz', 'helper_sha256'), ('custodian', 'custodian_sha256')]:
            data = filename.encode()
            (self.image / filename).write_bytes(data)
            self.metadata[key] = hashlib.sha256(data).hexdigest()

    def bind(self, data):
        self.name.write_bytes(data)
        self.metadata['guest_program_catalog_sha256'] = hashlib.sha256(data).hexdigest()

    def load(self):
        (self.image / 'image.json').write_text(json.dumps(self.metadata))
        return run.load_image(self.image)

    def test_legacy_image_without_catalog_remains_usable(self):
        self.assertEqual(self.load(), self.metadata)
        self.assertIsNone(run.optional_program_catalog(self.image, self.metadata))

    def test_exact_valid_catalog_loads_without_host_program_installation(self):
        data = catalog_bytes()
        self.bind(data)
        self.assertEqual(self.load(), self.metadata)
        self.assertEqual(run.optional_program_catalog(self.image, self.metadata), data)

    def test_catalog_must_be_bound_even_for_legacy_image(self):
        self.name.write_bytes(catalog_bytes())
        with self.assertRaisesRegex(ValueError, 'without an image binding'):
            self.load()
        self.name.unlink()
        self.name.symlink_to(self.image / 'absent')
        with self.assertRaisesRegex(ValueError, 'without an image binding'):
            self.load()

    def test_bound_catalog_cannot_be_missing_or_tampered(self):
        self.bind(catalog_bytes())
        self.name.unlink()
        with self.assertRaises(FileNotFoundError):
            self.load()
        self.name.write_bytes(catalog_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.load()

    def test_digest_type_and_spelling_are_strict(self):
        self.bind(catalog_bytes())
        for bad in (None, True, 1, [], '', 'A' * 64, '0' * 63):
            with self.subTest(value=bad):
                self.metadata['guest_program_catalog_sha256'] = bad
                with self.assertRaisesRegex(ValueError, 'invalid.*digest'):
                    self.load()

    def test_matching_hash_does_not_bypass_catalog_schema(self):
        for data in (b'{}', b'{"schema":"x","schema":"x","entries":[]}',
                     catalog_bytes().replace(b'"program_root": 1', b'"program_root": true')):
            with self.subTest(data=data[:64]):
                self.bind(data)
                with self.assertRaises(ValueError):
                    self.load()

    def test_symlink_hardlink_and_fifo_refuse_without_reading_targets(self):
        data = catalog_bytes()
        outside = self.image / 'outside'
        outside.write_bytes(data)
        self.metadata['guest_program_catalog_sha256'] = hashlib.sha256(data).hexdigest()
        self.name.symlink_to(outside)
        with self.assertRaises(OSError):
            self.load()
        self.name.unlink()
        os.link(outside, self.name)
        with self.assertRaisesRegex(ValueError, 'single-link'):
            self.load()
        self.name.unlink()
        os.mkfifo(self.name)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.load()

    def test_oversize_catalog_refuses_before_parsing(self):
        self.bind(b' ' * (run.MAX_CATALOG_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'bounded'):
            self.load()

    def test_installer_refuses_invalid_catalog_before_expanding_disk(self):
        self.bind(catalog_bytes())
        self.name.write_bytes(b'{}')
        (self.image / 'base.raw').unlink()
        (self.image / 'image.json').write_text(json.dumps(self.metadata))
        with self.assertRaisesRegex(ValueError, 'does not match'):
            cli.expand_image(self.image)
        self.assertFalse((self.image / 'base.raw').exists())

    def test_host_package_obeys_shared_catalog_conformance_vectors(self):
        vectors = json.loads((Path(__file__).parent / 'fixtures/guest-program-catalog-vectors.json').read_bytes())
        for case in vectors['valid']:
            with self.subTest(case=case['name']):
                self.bind(case['data'].encode())
                self.assertEqual(self.load(), self.metadata)
        for case in vectors['invalid']:
            with self.subTest(case=case['name']):
                self.bind(case['data'].encode())
                with self.assertRaises(ValueError):
                    self.load()


if __name__ == '__main__':
    unittest.main()
