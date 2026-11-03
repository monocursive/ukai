"""The VM tooling names the same releases as dist/release.json.

release.json splits the VM version (D11): `vm.version` is what the public
installer pins; `vm.candidate_version` is what package.py builds, what
cli.VERSION reports, and what the DMG's READ-ME names. A missing candidate
fails here, loudly: the package version is never guessed.
"""
from pathlib import Path
import re
import unittest

import cli
import package
import prepare

coordinates = prepare.coordinates


class Coordinates(unittest.TestCase):
    def test_packaged_version_is_the_vm_candidate(self):
        self.assertEqual(cli.VERSION, package.candidate_version())

    def test_package_reads_the_same_release_file_as_the_coordinates(self):
        self.assertEqual(package.RELEASE.resolve(), (Path(prepare.SOURCE).parent / 'dist' / 'release.json').resolve())

    def test_preview_readme_names_the_vm_candidate(self):
        # The DMG carries PREVIEW.txt as its READ-ME.txt, which names the version in its
        # title and in the installed directory it tells users to remove.
        candidate = package.candidate_version()
        text = Path(__file__).with_name('PREVIEW.txt').read_text()
        named = re.findall(r'\b\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', text)
        self.assertTrue(text.startswith(f'Ukai VM {candidate} '))
        self.assertEqual(set(named), {candidate})

    def test_guest_uses_the_public_linux_release_and_its_installer_pin(self):
        version, target = coordinates.JAIL_VERSION, prepare.JAIL_TARGET
        self.assertTrue(prepare.JAIL_URL.endswith(
            f'/releases/download/{coordinates.jail_tag(version)}/ukai-jail-{version}-{target}.tar.gz'))
        script = coordinates.INSTALLER.read_text()
        self.assertIn(f"        {version}:{target}) expected='{prepare.JAIL_SHA256}' ;;\n", script)


if __name__ == '__main__':
    unittest.main()
