#!/usr/bin/env python3
"""Notarize and staple a packaged DMG, retaining every result as evidence.

Notarization is the one packaging step that needs the operator's Apple
credentials, so it is separate from `package.py` (whose report honestly
says `notarization: pending`) and refuses to invent a result. Credentials
arrive only as arguments — an App Store Connect API key (`.p8` path, key
id and issuer id) or a keychain profile `xcrun notarytool
store-credentials` made — and never enter the record or the repository:
every value given to a credential flag is redacted from each recorded argv
and from the recorded output, whatever the file is called.

The flow is the one vm/README.md names: check the DMG is still the bytes
package.json recorded (`dmg_sha256_before_notarization`; a DMG stapled by an
earlier run, or changed in any other way, is never submitted), submit and
wait, fetch `notarytool log` for any submission id Apple returned (accepted
or not), staple, validate the staple, `spctl --assess`, then the DMG's final
SHA-256 (which changes when the ticket is stapled). Each run writes its own
record — `notarization.json`, then `notarization.2.json`, … — and never
replaces an earlier one; a timeout is recorded like any other result.
`package.json`'s `notarization` field becomes the Apple submission id only
after every check passed. A failed, timed-out or rejected submission exits
non-zero.

    python3 notarize.py --package /tmp/ukai-vm-pkg \
        [--key ~/private_keys/AuthKey_<ID>.p8 --key-id <ID> --issuer <ISSUER>] |
        [--profile <keychain-profile>]
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REDACTED = '<redacted>'
CREDENTIAL_FLAGS = ('--key', '--key-id', '--issuer', '--keychain-profile', '--apple-id',
                    '--password', '--team-id', '-p')


def scrub(argv, secrets=()):
    """argv with every credential flag's value, and every secret, redacted."""
    secrets = [str(value) for value in secrets if str(value)]
    cleaned, hide_next = [], False
    for argument in (str(arg) for arg in argv):
        if hide_next:
            cleaned.append(REDACTED)
            hide_next = False
            continue
        flag, equals, _ = argument.partition('=')
        if flag in CREDENTIAL_FLAGS and equals:
            cleaned.append(flag + '=' + REDACTED)
            continue
        if argument in CREDENTIAL_FLAGS:
            hide_next = True
        cleaned.append(scrub_text(argument, secrets))
    return cleaned


def scrub_text(text, secrets=()):
    for value in sorted((str(v) for v in secrets if str(v)), key=len, reverse=True):
        text = text.replace(value, REDACTED)
    return text


def command(*args, timeout=None, secrets=()):
    """Runs a command, capturing stdout/stderr verbatim (credentials redacted) for the record."""
    argv = [str(arg) for arg in args]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        exit_code, stdout, stderr, timed_out = done.returncode, done.stdout, done.stderr, False
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
        exit_code, stdout, stderr, timed_out = None, text(error.stdout), text(error.stderr), True
    return {'argv': scrub(argv, secrets), 'exit': exit_code, 'timed_out': timed_out,
            'stdout': scrub_text(stdout, secrets)[-20_000:], 'stderr': scrub_text(stderr, secrets)[-20_000:]}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def credential_arguments(args):
    """The notarytool credential flags; their values never log."""
    if args.profile:
        return ['--keychain-profile', args.profile]
    return ['--key', args.key, '--key-id', args.key_id, '--issuer', args.issuer]


def record_path(root):
    """The first unused record name: an earlier run's record is never replaced."""
    path = root / 'notarization.json'
    number = 1
    while path.exists():
        number += 1
        path = root / f'notarization.{number}.json'
    return path


UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')


def submission(stdout):
    """{submission_id, status} from notarytool's wait output.

    Every `id: <uuid>` line names the one submission (the block after
    `Submission ID received` arrives first, so a timed-out wait still names
    the submission it left running); `status:` comes only with the final
    block. A progress line is never taken for an id.
    """
    found = {}
    for line in stdout.splitlines():
        text = line.strip()
        if text.startswith('id:') and UUID.fullmatch(text[len('id:'):].strip()):
            found['submission_id'] = text[len('id:'):].strip()
        elif text.startswith('status:'):
            found['status'] = text[len('status:'):].strip()
    return found


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
            parser.error('the --key file does not exist')
        credentials = credential_arguments(args)
    else:
        parser.error('notarytool needs --profile, or --key/--key-id/--issuer together')
    secrets = [value for value in (args.key, args.key and args.key.resolve(), args.key_id,
                                   args.issuer, args.profile) if value]

    dmg = root / report['dmg']
    before = digest(dmg)
    expected = report.get('dmg_sha256_before_notarization')
    if not expected or before != expected:
        parser.error(f'{dmg.name} is not the DMG package.json recorded ({before} != {expected}); '
                     'a stapled or changed DMG is never submitted: rebuild the package')
    path = record_path(root)
    steps = []
    record = {'schema': 'ukai.vm.notarization/1', 'dmg': report['dmg'],
              'dmg_sha256_before': before, 'steps': steps,
              'submitted_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}

    def save():
        with open(path, 'x') as output:
            output.write(json.dumps(record, indent=2) + '\n')

    def run(step, *call, timeout=None):
        result = command(*call, timeout=timeout, secrets=secrets)
        steps.append({'step': step, **result})
        print(f"{step}: exit {result['exit']}{' (timed out)' if result['timed_out'] else ''}", flush=True)
        return result

    submit = run('submit', 'xcrun', 'notarytool', 'submit', dmg, *credentials, '--wait',
                 timeout=3 * 60 * 60)
    record.update(submission(submit['stdout']))
    submission_id = record.get('submission_id')
    if submission_id:
        # Apple's per-submission log: the reasons for a rejection, the
        # warnings of an acceptance. Fetched whenever there is an id.
        run('log', 'xcrun', 'notarytool', 'log', submission_id, *credentials, timeout=600)
    if submit['timed_out']:
        record['outcome'] = 'submit-timeout'
    elif submit['exit'] != 0:
        record['outcome'] = 'submit-failed'
    elif record.get('status') != 'Accepted' or 'submission_id' not in record:
        record['outcome'] = f"not-accepted: {record.get('status', 'unknown')}"
    if 'outcome' in record:
        record['dmg_sha256_after'] = digest(dmg)
        save()
        print(submit['stdout'][-2000:], file=sys.stderr)
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
    record['dmg_changed'] = record['dmg_sha256_after_stapling'] != before
    record['outcome'] = ('notarized' if all(checks.values())
                         else 'incomplete: ' + ', '.join(k for k, v in checks.items() if not v))
    save()
    if record['outcome'] == 'notarized':
        report['notarization'] = record['submission_id']
        report['dmg_sha256_notarized'] = record['dmg_sha256_after_stapling']
        report['notarization_record'] = path.name
        (root / 'package.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'outcome': 'notarized',
                          'submission': record['submission_id'],
                          'dmg_sha256': record['dmg_sha256_after_stapling']}))
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
