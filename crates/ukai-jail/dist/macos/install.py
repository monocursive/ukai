#!/usr/bin/env python3
"""Per-user maintainer installer. No native runtime qualification is implied."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile

import native

STATE = '.ukai-installation.json'
JOURNAL = '.ukai-transaction.json'
LOCK = '.ukai-installer.lock'


def exists(path):
    return os.path.lexists(path)


def directory(path, create=False):
    if create:
        path.mkdir(mode=0o755, exist_ok=True)
    value = path.lstat()
    native.require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid()
                   and not value.st_mode & 0o022, f'Unsafe installation directory: {path}')


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.ukai-json-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Installation:
    def __init__(self, home, hook=lambda step: None):
        self.home = Path(home).absolute()
        native.require(self.home == self.home.resolve(), 'Home must be a canonical real directory')
        directory(self.home)
        self.apps = self.home / 'Applications'
        self.app = self.apps / native.APP
        self.state = self.apps / STATE
        self.journal = self.apps / JOURNAL
        self.bin = self.home / '.local/bin'
        self.link = self.bin / 'ukai-jail'
        self.target = str(self.app / native.EXECUTABLE)
        self.hook = hook

    @contextlib.contextmanager
    def locked(self):
        directory(self.apps, create=True)
        fd = os.open(self.apps / LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            value = os.fstat(fd)
            native.require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
                           and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1,
                           'Unsafe installer lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise native.Refused('Another install/remove/recover operation is running') from None
            # The persistent lock inode is never removed, including on failure.
            # Shared directory creation happens only after taking that lock.
            directory(self.home / '.local', create=True)
            directory(self.bin, create=True)
            yield
        finally:
            os.close(fd)

    def record(self):
        if not exists(self.state):
            return None
        value = json.loads(native.read_regular(self.state))
        native.require(value.get('schema') == native.SCHEMA and isinstance(value.get('files'), dict),
                       'Unrecognized installation record')
        return value

    def link_state(self):
        if not exists(self.link):
            return 'absent'
        if self.link.is_symlink() and os.readlink(self.link) == self.target:
            return 'owned'
        return 'unrelated'

    def matches(self, app, record):
        return record is not None and exists(app) and native.bundle_files(app) == record['files']

    def matches_cleanup(self, app, record):
        if record is None:
            return False
        remaining = native.bundle_files(app, partial_manifest=record['files'])
        return all(record['files'].get(path) == value for path, value in remaining.items())

    def preflight(self, installing):
        native.require(not exists(self.journal), 'Interrupted transaction: run recover before changing installation')
        record = self.record()
        if exists(self.app):
            native.require(self.matches(self.app, record), 'Existing Ukai.app is unmanaged or has changed')
        else:
            native.require(record is None, 'Installation record exists but Ukai.app is missing')
        native.require(not installing or self.link_state() != 'unrelated',
                       'Refusing to replace an unrelated ~/.local/bin/ukai-jail')
        return record

    def set_link(self, wanted):
        current = self.link_state()
        if wanted == 'owned' and current != 'owned':
            native.require(current == 'absent', 'Command changed during transaction; refusing to replace it')
            # symlink creation fails atomically if another command appeared.
            os.symlink(self.target, self.link)
        elif wanted != 'owned' and current == 'owned':
            self.link.unlink()
        sync_directory(self.bin)

    def set_record(self, wanted, allowed):
        current = self.record()
        native.require(current is None or current in allowed, 'Installation record changed during transaction')
        if wanted is None:
            self.state.unlink(missing_ok=True)
            sync_directory(self.apps)
        else:
            atomic_json(self.state, wanted)

    def cleanup(self, work):
        # This is our private transaction directory, whose contents were checked
        # during recovery or created in this operation, never an operator path.
        shutil.rmtree(work)
        self.journal.unlink()
        sync_directory(self.apps)

    def recover_locked(self):
        data = json.loads(native.read_regular(self.journal))
        native.require(data.get('schema') == 'ukai.macos.transaction/1'
                       and re.fullmatch(r'\.ukai-install-[a-z0-9_]+', data.get('work', ''))
                       and data.get('phase') in ('prepared', 'committed', 'rolled-back')
                       and data.get('link') in ('owned', 'absent', 'unrelated'), 'Invalid transaction journal')
        work = self.apps / data['work']
        settled = data['new'] if data['phase'] == 'committed' else data['old']
        if data['phase'] != 'prepared' and not exists(work):
            native.require(self.record() == settled and (
                self.matches(self.app, settled) if settled else not exists(self.app)),
                'Settled installation changed; recovery refused')
            self.journal.unlink()
            sync_directory(self.apps)
            return
        directory(work)
        native.require(stat.S_IMODE(work.stat().st_mode) == 0o700, 'Unsafe transaction directory')
        native.require(set(p.name for p in work.iterdir()) <= {'previous.app', 'candidate.app'},
                       'Unrecognized transaction contents')
        old, new = data['old'], data['new']
        previous = work / 'previous.app'
        candidate = work / 'candidate.app'
        check = self.matches if data['phase'] == 'prepared' else self.matches_cleanup
        if exists(previous):
            native.require(check(previous, old), 'Saved application has changed; recovery refused')
        if exists(candidate):
            native.require(check(candidate, new), 'Staged application has changed; recovery refused')
        current = self.record()
        native.require(current is None or current in (old, new), 'Installation record changed; recovery refused')
        if data['phase'] != 'prepared':
            native.require(self.matches(self.app, settled) if settled else not exists(self.app),
                           'Settled application changed; recovery refused')
            native.require(current == settled, 'Settled installation record changed; recovery refused')
            self.cleanup(work)
            return
        # Validate every owned path before removing or restoring any of them.
        app_old = self.matches(self.app, old) if exists(self.app) else False
        app_new = self.matches(self.app, new) if exists(self.app) else False
        native.require(not exists(self.app) or app_old or app_new,
                       'Application changed; recovery will not remove it')
        native.require(old is None or app_old or exists(previous), 'Previous application is missing')
        native.require(not (app_old and exists(previous) and not app_new), 'Ambiguous previous application')
        native.require(data['link'] != 'owned' or self.link_state() != 'unrelated',
                       'Command changed; recovery will not replace it')
        if exists(previous):
            if exists(self.app):
                native.require(not exists(candidate), 'Ambiguous staged application')
                os.rename(self.app, candidate)
            os.rename(previous, self.app)
        elif old is None and exists(self.app):
            native.require(not exists(candidate), 'Ambiguous staged application')
            os.rename(self.app, candidate)
        self.set_link(data['link'])
        self.set_record(old, (old, new))
        data['phase'] = 'rolled-back'
        atomic_json(self.journal, data)
        self.cleanup(work)

    def transaction(self, old, new, work):
        journal = {'schema': 'ukai.macos.transaction/1', 'work': work.name,
                   'phase': 'prepared', 'old': old, 'new': new, 'link': self.link_state()}
        atomic_json(self.journal, journal)
        try:
            if old is not None:
                os.rename(self.app, work / 'previous.app')
            if new is not None:
                os.rename(work / 'candidate.app', self.app)
            sync_directory(self.apps)
            self.hook('published')
            self.set_link('owned' if new else 'absent')
            self.hook('activated')
            self.set_record(new, (old, new))
            journal['phase'] = 'committed'
            atomic_json(self.journal, journal)
        except BaseException:
            self.recover_locked()
            raise
        self.cleanup(work)

    def install(self, package, allow_unsigned=False):
        with self.locked():
            old = self.preflight(installing=True)
            report = native.load_package(package)
            native.require(report['signing'] == 'developer-id' or allow_unsigned,
                           'Unsigned staging requires explicit --allow-unsigned; it is not release qualified')
            work = Path(tempfile.mkdtemp(prefix='.ukai-install-', dir=self.apps))
            try:
                native.copy_bundle(package / native.APP, work / 'candidate.app', report['files'])
                if report['signing'] == 'developer-id':
                    native.verify_signature(work / 'candidate.app', report, distribution=True)
                self.hook('validated')
            except BaseException:
                shutil.rmtree(work)
                raise
            self.transaction(old, report, work)

    def remove(self):
        with self.locked():
            old = self.preflight(installing=False)
            if old is None:
                native.require(self.link_state() != 'owned', 'Owned command exists without an installation record')
                return
            work = Path(tempfile.mkdtemp(prefix='.ukai-install-', dir=self.apps))
            self.transaction(old, None, work)

    def recover(self):
        with self.locked():
            native.require(exists(self.journal), 'No interrupted transaction to recover')
            self.recover_locked()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home())
    commands = parser.add_subparsers(dest='action', required=True)
    install = commands.add_parser('install')
    install.add_argument('--package', type=Path, required=True)
    install.add_argument('--allow-unsigned', action='store_true')
    commands.add_parser('remove')
    commands.add_parser('recover')
    args = parser.parse_args()
    try:
        native.require(os.getuid() != 0, 'Run as the installing user, without sudo')
        native.require(platform.system() == 'Darwin' and platform.machine() == 'arm64'
                       and int(platform.mac_ver()[0].split('.')[0]) >= 27,
                       'Native candidate installation requires Apple Silicon and macOS 27 or newer')
        installation = Installation(args.home)
        if args.action == 'install':
            installation.install(args.package, args.allow_unsigned)
        else:
            getattr(installation, args.action)()
        print(json.dumps({'action': args.action, 'qualified': False, 'native_execution': 'disabled-by-default'}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Refused: {error}\n')


if __name__ == '__main__':
    main()
