#!/usr/bin/env python3
"""Notarize and staple a packaged DMG, retaining every result as evidence.

Notarization is the one packaging step that needs the operator's Apple
credentials, so it is separate from `package.py` (whose report honestly
says `notarization: pending`) and refuses to invent a result. Credentials
arrive only as arguments — an App Store Connect API key (`.p8` path, key
id and issuer id) or a keychain profile `xcrun notarytool
store-credentials` made — and never enter the record or the repository.

The flow is the one vm/README.md names: submit and wait, staple, validate
the staple, `spctl --assess`, then the DMG's final SHA-256 (which changes
when the ticket is stapled). `notarization.json` retains each step's raw
output; `package.json`'s `notarization` field becomes the Apple submission
id only after every check passed. A failed or rejected submission exits
non-zero and records the log verbatim.

    python3 notarize.py --package /tmp/ukai-vm-pkg \
        [--key ~/private_keys/AuthKey_<ID>.p8 --key-id <ID> --issuer <ISSUER>] |
        [--profile <keychain-profile>]
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


def command(*args, timeout=None):
    """Runs a command, capturing stdout/stderr verbatim for the record."""
    done = subprocess.run([str(arg) for arg in args], capture_output=True,
                          text=True, timeout=timeout)
    return {'argv': [str(arg) for arg in args if not str(arg).endswith('.p8')],
            'exit': done.returncode,
            'stdout': done.stdout[-20_000:], 'stderr': done.stderr[-20_000:]}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def credential_arguments(args):
    """The notarytool credential flags; the key path itself never logs."""
    if args.profile:
        return ['--keychain-profile', args.profile]
    return ['--key', args.key, '--key-id', args.key_id, '--issuer', args.issuer]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True, type=Path,
                        help='the directory package.py wrote (holds the DMG and package.json)')
    parser.add_argument('--key', type=Path, help='App Store Connect API key (.p8)')
    parser.add_argument('--key-id', help='the API key id')
    parser.add_argument('--issuer', help='the issuer id')
    parser.add_argument('--profile', help='a keychain profile notarytool stored')
    args = parser.parse_args()
    root = args.package.resolve()
    report = json.loads((root / 'package.json').read_text())
    if report.get('notarization') not in (None, 'pending'):
        parser.error(f"package.json already records notarization "
                     f"{report['notarization']!r}; this step is not idempotent")
    if args.profile:
        credentials = ['--keychain-profile', args.profile]
    elif args.key and args.key_id and args.issuer:
        if not args.key.is_file():
            parser.error(f'{args.key} does not exist')
        credentials = credential_arguments(args)
    else:
        parser.error('notarytool needs --profile, or --key/--key-id/--issuer together')

    dmg = root / report['dmg']
    steps = []
    record = {'schema': 'ukai.vm.notarization/1', 'dmg': report['dmg'],
              'dmg_sha256_before': digest(dmg), 'steps': steps,
              'submitted_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}

    def run(step, *call, timeout=None):
        result = command(*call, timeout=timeout)
        steps.append({'step': step, **result})
        print(f"{step}: exit {result['exit']}", flush=True)
        return result

    submit = run('submit', 'xcrun', 'notarytool', 'submit', dmg,
                 *credentials, '--wait', timeout=3 * 60 * 60)
    if submit['exit'] != 0:
        record['outcome'] = 'submit-failed'
        (root / 'notarization.json').write_text(json.dumps(record, indent=2) + '\n')
        print(submit['stdout'][-2000:], file=sys.stderr)
        return 1
    # The wait's final block ends with `id: <uuid>` and `status: <word>`;
    # earlier progress lines ("Submission ID received: …") must not win.
    for line in submit['stdout'].splitlines():
        text = line.strip()
        if text.startswith('id:') and 'received' not in text:
            record['submission_id'] = text[len('id:'):].strip()
        elif text.startswith('status:'):
            record['status'] = text[len('status:'):].strip()
    if record.get('status') != 'Accepted' or 'submission_id' not in record:
        record['outcome'] = f"not-accepted: {record.get('status', 'unknown')}"
        (root / 'notarization.json').write_text(json.dumps(record, indent=2) + '\n')
        return 1

    staple = run('staple', 'xcrun', 'stapler', 'staple', dmg, timeout=600)
    validate = run('stapler-validate', 'xcrun', 'stapler', 'validate', dmg, timeout=600)
    assess = run('spctl-assess', 'spctl', '--assess', '--type', 'open',
                 '--context', 'context:primary-signature', '-v', dmg, timeout=600)
    checks = {'stapled': staple['exit'] == 0,
              'staple_valid': validate['exit'] == 0 and 'The validate action worked' in validate['stdout'],
              'gatekeeper_assesses': assess['exit'] == 0}
    record.update(checks)
    record['dmg_sha256_after_stapling'] = digest(dmg)
    record['outcome'] = ('notarized' if all(checks.values())
                         else 'incomplete: ' + ', '.join(k for k, v in checks.items() if not v))
    (root / 'notarization.json').write_text(json.dumps(record, indent=2) + '\n')
    if record['outcome'] == 'notarized':
        report['notarization'] = record['submission_id']
        report['dmg_sha256_notarized'] = record['dmg_sha256_after_stapling']
        (root / 'package.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'outcome': 'notarized',
                          'submission': record['submission_id'],
                          'dmg_sha256': record['dmg_sha256_after_stapling']}))
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
