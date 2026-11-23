"""The current public release coordinates, read from release.json.

release.json is the one place that names the published versions, the Linux
targets and the preview's unsupported clauses; the packaging scripts, the VM
tooling, the website and their tests read it. The archive SHA-256 pins are not
here: they live in the root install.sh's managed pin block, which is the
installer users run; installer_pin() reads one, and bootstrap.py renders them.

This module imports only the standard library, so tooling outside this
directory can load it by path without putting dist/ (and its package.py) on
sys.path.
"""
import json
from pathlib import Path
import re

_RELEASE = json.loads(Path(__file__).with_name('release.json').read_text())
INSTALLER = Path(__file__).resolve().parents[3] / 'install.sh'
PIN_BLOCK = re.compile(r'    # BEGIN SHA256 PINS\n.*?    # END SHA256 PINS\n', re.DOTALL)
PIN_ENTRY = re.compile(r"        ([^:\n]+):([^\n]+)\) expected='([0-9a-f]{64})' ;;\n")

REPOSITORY = _RELEASE['repository']
JAIL_VERSION = _RELEASE['jail']['version']
JAIL_TAG_PREFIX = _RELEASE['jail']['tag_prefix']
PUBLICATION_SCOPE = _RELEASE['jail']['publication_scope']
UNSUPPORTED_CLAUSES = list(_RELEASE['jail']['unsupported_clauses'])
# Release targets with the ELF e_machine their binaries must carry. Only
# Linux: native macOS execution refuses, so no Darwin archive is released.
ELF_MACHINE = dict(_RELEASE['jail']['elf_machine_by_target'])
LINUX_TARGETS = tuple(ELF_MACHINE)
STABLE_TARGET = _RELEASE['jail']['stable_target']
STABLE_HOST = _RELEASE['jail']['stable_host']
ARM_PREVIEW_VERSION = _RELEASE['jail']['arm_preview_version']
ARM64_TARGET = 'aarch64-unknown-linux-gnu'
# The first stable release with an ARM64 archive, and the configuration that
# release was qualified on; absent until an ARM64 release is qualified, so a
# stable release ships x86_64 alone. Set both, and give `publication_scope`
# its two-target name, only once the ARM64 gates are confirmed.
ARM64_STABLE_VERSION = _RELEASE['jail'].get('arm64_stable_version')
ARM64_STABLE_HOST = _RELEASE['jail'].get('arm64_stable_host')
# The scope of a stable release that ships x86_64 alone, as 0.1.0 was
# published. A stable release with both targets takes PUBLICATION_SCOPE.
X86_64_ONLY_SCOPE = 'linux-x86_64-stable'
VM_VERSION = _RELEASE['vm']['version']
# The VM package the tree builds next: built and smoke-verified, not published.
# VM_VERSION stays the published preview until a release moves it.
VM_CANDIDATE_VERSION = _RELEASE['vm']['candidate_version']
VM_TAG_PREFIX = _RELEASE['vm']['tag_prefix']
VM_TARGET = _RELEASE['vm']['target']


def is_prerelease(version):
    return '-' in version.partition('+')[0]


def _stable_order(version):
    """(major, minor, patch) of a stable version, for comparing stable releases."""
    return tuple(int(part) for part in version.partition('+')[0].split('.'))


def release_targets(version):
    """The Linux targets a release ships: every one for a preview; for a stable
    release, x86_64 and, from arm64_stable_version on, ARM64."""
    if is_prerelease(version):
        return LINUX_TARGETS
    stable = [STABLE_TARGET]
    if ARM64_STABLE_VERSION and _stable_order(version) >= _stable_order(ARM64_STABLE_VERSION):
        stable.append(ARM64_TARGET)
    return tuple(stable)


def stable_hosts(version):
    """The qualified configuration of each target a stable release ships."""
    hosts = {'x86_64': STABLE_HOST}
    if ARM64_TARGET in release_targets(version):
        hosts['aarch64'] = ARM64_STABLE_HOST
    return hosts


def release_scope(version):
    if is_prerelease(version):
        return 'linux-preview'
    return PUBLICATION_SCOPE if ARM64_TARGET in release_targets(version) else X86_64_ONLY_SCOPE


def jail_tag(version):
    return JAIL_TAG_PREFIX + version


def jail_archive(version, target):
    return f'ukai-jail-{version}-{target}.tar.gz'


def jail_archive_url(version, target):
    return f'https://github.com/{REPOSITORY}/releases/download/{jail_tag(version)}/{jail_archive(version, target)}'


def vm_tag(version):
    return VM_TAG_PREFIX + version


def pin_entries(script):
    """(version, target, sha256) rows of an installer's one managed pin block."""
    blocks = PIN_BLOCK.findall(script)
    if len(blocks) != 1:
        raise ValueError('installer must contain exactly one SHA-256 pin block')
    return PIN_ENTRY.findall(blocks[0])


def installer_pin(version, target):
    """The SHA-256 the public installer pins for one release archive."""
    found = [digest for v, t, digest in pin_entries(INSTALLER.read_text()) if (v, t) == (version, target)]
    if len(found) != 1:
        raise ValueError(f'install.sh must pin {version} for {target} exactly once')
    return found[0]
