#!/usr/bin/env python3
"""Explicit network/mutation steps; validation never submits or staples."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import native


def submit(package, out, keychain_profile, run=native.execute):
    report = native.load_package(package)
    native.require(report['notarization'] == 'not-submitted', 'Submit an unstapled signed candidate')
    native.verify_signature(package / native.APP, report, run)
    out.mkdir(parents=True, exist_ok=False)
    archive = out / 'Ukai.zip'
    run(['/usr/bin/ditto', '-c', '-k', '--keepParent', package / native.APP, archive])
    # Only a previously configured keychain profile is accepted; credentials
    # never become command-line arguments or a package file.
    try:
        response = run(['/usr/bin/xcrun', 'notarytool', 'submit', archive,
                        '--keychain-profile', keychain_profile, '--wait', '--timeout', '20m',
                        '--output-format', 'json'], timeout=1500)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (out / 'notarytool.stdout').write_bytes(error.stdout or b'')
        (out / 'notarytool.stderr').write_bytes(error.stderr or b'')
        raise
    (out / 'notarytool.json').write_bytes(response.stdout)
    reply = json.loads(response.stdout)
    receipt = {'schema': 'ukai.macos.notary/1', 'id': reply['id'], 'status': reply['status'],
               'package_sha256': native.digest(native.read_regular(package / 'package.json')),
               'archive_sha256': native.digest(native.read_regular(archive))}
    native.write_json(out / 'receipt.json', receipt)
    native.require(reply['status'] == 'Accepted', 'Apple did not accept this submission; see notarytool.json')
    return receipt


def staple(package, receipt_path, out, run=native.execute):
    report = native.load_package(package)
    receipt = json.loads(native.read_regular(receipt_path))
    native.require(receipt.get('schema') == 'ukai.macos.notary/1' and receipt.get('status') == 'Accepted'
                   and receipt.get('package_sha256') == native.digest(native.read_regular(package / 'package.json')),
                   'Notarization receipt does not name this package')
    native.verify_signature(package / native.APP, report, run)
    out.mkdir(parents=True, exist_ok=False)
    app = out / native.APP
    native.copy_bundle(package / native.APP, app, report['files'])
    try:
        run(['/usr/bin/xcrun', 'stapler', 'staple', app])
        native.verify_signature(app, report, run, distribution=True)
        report.update(notarization='stapled', notary_id=receipt['id'], files=native.bundle_files(app))
        for name in ('native.py', 'install.py', 'notarize.py', 'README.md'):
            shutil.copyfile(native.HERE / name, out / name)
        native.write_json(out / 'package.json', report)
        native.load_package(out)
    except BaseException:
        (out / 'package.json').unlink(missing_ok=True)
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    submission = commands.add_parser('submit')
    submission.add_argument('--keychain-profile', required=True)
    stapling = commands.add_parser('staple')
    stapling.add_argument('--receipt', type=Path, required=True)
    for command in (submission, stapling):
        command.add_argument('--package', type=Path, required=True)
        command.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'submit':
            result = submit(args.package, args.out, args.keychain_profile)
        else:
            result = staple(args.package, args.receipt, args.out)
        print(json.dumps({'status': result.get('status', result.get('notarization')), 'qualified': False}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Refused: {error}\n')


if __name__ == '__main__':
    main()
