#!/usr/bin/env python3
"""Read-only relocated component replay; never boot, sign, mount or call a provider."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent

def require(held, message):
    if held is not True:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read(name):
    path = ROOT / name
    require(stat.S_ISREG(path.lstat().st_mode), 'nonregular bundle file: ' + name)
    return path.read_bytes()

def load(name):
    return json.loads(read(name))

def verify_common_image(cap, bound, image, boundary_attempts):
    """All components must have actually used the same installed signed image.

    Replaying each component internally is insufficient: an intact old
    capability/boundary pair could otherwise be transplanted beside fresh
    vault/program evidence after regenerating the outer integrity inventory.
    """
    common = ('disk_sha256', 'seed_sha256', 'helper_sha256', 'custodian_sha256')
    contracts = {
        'secret_revocation': 'ukai.vm.secret-revocation/1',
        'journal_export': 'ukai.vm.guest-journal/1',
        'native_program': 'ukai.vm.guest-native-launch/1',
        'sampled_exposure': 'ukai.vm.sampled-exposure/2',
    }
    require(cap['binary']['sha256'] == image['ukai_vm_sha256'],
            'capability service binary differs from signed image')
    require(all(cap['status'][key] == image[key] for key in common),
            'capability status differs from signed image')
    require(type(cap['status']['boot_id']) is str and bool(cap['status']['boot_id']),
            'capability service boot missing')
    for attempt in cap['results'].values():
        ready = attempt['ready']
        require(all(ready[key] == image[key] for key in common)
                and ready['guest_program_catalog_sha256'] == image['guest_program_catalog_sha256'],
                'capability attempt used another image or catalog')
        require(ready['guest_contracts'] == contracts,
                'capability attempt contract differs')
        require(ready['boot_id'] == attempt['boot_id'] == cap['status']['boot_id'],
                'capability attempt service boot differs')
    require(bound['binary'] == cap['binary'] and bound['status'] == cap['status'],
            'boundary metadata differs from its capability source')
    attempts = [cap['results'][name] for name in boundary_attempts]
    measured = bound['measurements']['execution_boundary']
    require(measured['verdict'] is True and measured['capability'] == 'execution_boundary'
            and measured['attempt_id'] == attempts[0]['attempt_id']
            and measured['measured_at'] == attempts[0]['started_at']
            and measured['attempt_ids'] == [row['attempt_id'] for row in attempts],
            'boundary measurement identity differs from capability source')

def main():
    manifest = {}
    for line in read('SHA256SUMS').decode().splitlines():
        digest, sep, name = line.partition('  ')
        parts = PurePosixPath(name).parts
        require(bool(sep) and re.fullmatch(r'[0-9a-f]{64}', digest) is not None
                and name not in manifest and not name.startswith('/')
                and all(p not in ('', '.', '..') for p in parts), 'invalid bundle manifest')
        manifest[name] = digest
    actual = set()
    for path in ROOT.rglob('*'):
        require(not path.is_symlink(), 'bundle link refused')
        if path.is_file():
            actual.add(path.relative_to(ROOT).as_posix())
    require(actual == set(manifest) | {'SHA256SUMS'}, 'bundle file set differs')
    for name, digest in manifest.items():
        require(sha(read(name)) == digest, 'bundle hash differs: ' + name)
    inventory = load('inventory.json')
    require(set(inventory['files']) == set(manifest) - {'inventory.json'}, 'inventory file set differs')
    for name, row in inventory['files'].items():
        require(row == {'bytes': len(read(name)), 'sha256': manifest[name]}, 'inventory differs')
    provenance = load('provenance.json')
    for name, row in provenance['sources'].items():
        require(sha(read(name)) == row['sha256'] and len(read(name)) == row['bytes'], 'copied bytes differ')
    # Detect the generated synthetic-value format and its encodings in retained
    # bytes. Original live scans remain observations; this does not rescan a VM.
    for prefix in (b'ukai-raw-revoke-', b'ukai-program-binding-'):
        token = re.compile(re.escape(prefix) + rb'[0-9a-f]{48}')
        byte_count = len(prefix) + 48
        hex_token = re.compile(re.escape(prefix.hex().encode()) + rb'[0-9a-fA-F]{96}')
        stable = base64.b64encode(prefix[:len(prefix) // 3 * 3])
        remainder = ((byte_count + 2) // 3 * 4) - len(stable)
        encoded_token = re.compile(re.escape(stable) + rb'[A-Za-z0-9+/_=-]{' + str(remainder).encode() + rb'}')
        for name in manifest:
            data = read(name)
            require(token.search(data) is None, 'synthetic value retained')
            for candidate in hex_token.findall(data):
                require(token.fullmatch(bytes.fromhex(candidate.decode())) is None, 'encoded synthetic value retained')
            for candidate in encoded_token.findall(data):
                try:
                    decoded = base64.b64decode(candidate, altchars=b'-_', validate=True)
                except ValueError:
                    continue
                require(token.fullmatch(decoded) is None, 'encoded synthetic value retained')
    sys.path.insert(0, str(ROOT / 'tools'))
    import capabilities
    import credential_revocation_measurement as raw_tool
    import credential_staging_measurement as admission
    import execution_boundary_measurement as boundary
    import guest_program
    import program_binding_measurement
    cap = load('capabilities/capabilities.json')
    facts, summary = capabilities.judge(cap, cap['status'], cap['summary']['git_config_untouched'], cap['service_exit'])
    require(facts == cap['facts'] and summary == cap['summary'] and summary['outcome'] == 'PASS', 'capability replay failed')
    require(capabilities.measurements(cap, summary) == cap['measurements']
            and len(cap['measurements']) == 10, 'capability row binding differs')
    bound = load('execution-boundary/execution-boundary.json')
    bound_facts, verdict = boundary.judge(cap)
    require(verdict and len(bound_facts) == 121 and bound_facts == bound['facts']
            and bound['outcome'] == 'PASS', 'boundary replay failed')
    require(bound['source_record_sha256'] == sha(read('capabilities/capabilities.json')), 'boundary input digest differs')
    raw = raw_tool.replay_raw(ROOT / 'raw-vault')
    require(raw['outcome'] == 'PASS' and not raw['errors'] and len(raw['facts']) == 24
            and all(v is True for v in raw['facts'].values()), 'raw replay failed')
    staged = load('credential-staging/credential-staging.json')
    # The original actual signed-install verification is retained. Without the
    # excluded DMG/binaries, this rechecks its bindings, not Apple signatures.
    derived = admission.derive(raw, staged['installation'])
    require(derived == staged, 'credential derivation differs')
    require(staged['qualified'] is False and staged['guest_contract_observation']['native_launch_or_sampling_qualified'] is False,
            'component scope was promoted')
    program = program_binding_measurement.replay(ROOT / 'program-binding')
    require(program['outcome'] == 'PASS' and program['qualified'] is False
            and len(program['facts']) == 24 and all(v is True for v in program['facts'].values()), 'program binding replay failed')
    program_inputs = load('program-binding/inputs.json')
    require(program_inputs['identity_before']['image'] == raw['image'], 'program binding used another image')
    image = raw['image']
    verify_common_image(cap, bound, image, boundary.ATTEMPTS)
    prepared = load('image/prepared-image.json')
    catalog = read('image/guest-program-catalog.json')
    guest_program.parse_catalog(catalog)
    require(sha(catalog) == prepared['guest_program_catalog_sha256'] == image['guest_program_catalog_sha256'], 'catalog differs')
    for key in ('disk_sha256', 'seed_sha256', 'source_sha256', 'guest_program_inputs'):
        require(prepared[key] == image[key], 'prepared/installed image differs: ' + key)
    for name, digest in prepared['source_sha256'].items():
        require(sha(read('tools/' + name)) == digest, 'guest image source differs: ' + name)
    control = load('image/guest-exposure-control.json')
    require(control == prepared['guest_exposure_control'] == image['guest_exposure_control'], 'detector record differs')
    require(sha(read('image/guest-exposure-control.json')) == prepared['guest_exposure_control_sha256'], 'detector digest differs')
    require(control['passed'] is True and control['actual_values_retained'] is False
            and control['jail_execution_claimed'] is False and len(control['facts']) == 7
            and all(v is True for v in control['facts'].values()) and control['errors'] == []
            and control['sampling']['scan_errors'] == {}, 'detector control failed')
    require(control['sampler_sha256'] == prepared['source_sha256']['guest_exposure.py']
            and control['control_source_sha256'] == prepared['source_sha256']['guest_exposure_control.py'], 'detector source differs')
    for entry in guest_program.parse_catalog(catalog)['entries']:
        require(entry['profile_sha256'] == sha(read('image/profile-metadata/' + entry['alias'] + '.toml')), 'profile metadata differs')
    pkg = load('package/package.json')
    installed = load('package/installed-identity.json')
    independent = load('package/independent-review.json')
    require(pkg['image'] == installed['image'] == image and pkg['source_revision'] == installed['source_revision'] == provenance['package_source_revision'], 'package source differs')
    require(independent['source_revision'] == provenance['package_source_revision']
            and independent['outcome'] == 'PASS' and all(v is True for v in independent['facts'].values()), 'independent package observation failed')
    require(independent['dmg_sha256'] == pkg['dmg_sha256_before_notarization'] == staged['installation']['dmg_sha256'], 'DMG identities differ')
    payload = admission.parse_manifest(read('package/SHA256SUMS'))
    require(sha(read('package/SHA256SUMS')) == pkg['manifest_sha256'] == staged['installation']['manifest_sha256'], 'signed manifest differs')
    require(payload['payload/image/image.json'] == sha(read('raw-vault/image.json'))
            and payload['payload/image/guest-program-catalog.json'] == sha(catalog), 'signed metadata binding differs')
    require(installed['files_sha256']['bin/ukai-jail'] == image['ukai_jail_sha256'] == payload['payload/bin/ukai-jail']
            and installed['files_sha256']['bin/ukai-vm'] == image['ukai_vm_sha256'] == payload['payload/bin/ukai-vm'], 'installed binary identities differ')
    client_version = load('package/client-version.json')
    require(client_version['build'] == staged['installation']['client_build'] == image['ukai_jail_version']['build']
            and client_version['build']['revision'] == provenance['package_source_revision']
            and client_version['build']['dirty'] is False, 'installed clean client version differs')
    installer = load('package/installer-summary.json')
    require(installer['passed'] is True and len(installer['results']) == 7
            and all(row['passed'] is True and row['failed_checks'] == [] for row in installer['results']), 'installer observations failed')
    signatures = load('package/signatures.json')
    require(signatures['passed'] is True and len(signatures['checks']) == 6, 'signature observations failed')
    signature_requirement = '=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "64SGQ348QJ"'
    require(all(type(row['exit_code']) is int and row['exit_code'] == 0
                and row['argv'] == ['/usr/bin/codesign', '--verify', '--strict', '-R', signature_requirement, row['path']]
                for row in signatures['checks']), 'signature verification observations differ')
    expected_signed = {'dmg': pkg['dmg_sha256_before_notarization'], **{
        name: payload['payload/' + path] for name, path in {
            'installer': 'bin/ukai-vm-install', 'service': 'bin/ukai-vm', 'client': 'bin/ukai-jail',
            'vz': 'image/vz', 'custodian': 'image/custodian'}.items()}}
    require({row['name']: row['sha256'] for row in signatures['checks']} == expected_signed, 'signature payload hash differs')
    native = load('native-admission.json')
    require(native['schema'] == 'ukai.vm.native-program-admission/1', 'native admission schema differs')
    entries = guest_program.parse_catalog(catalog)['entries']
    require(len(entries) == 1, 'native admission needs the exact single entry')
    entry = entries[0]
    require(native['required_guest_image'] == {key: image[key] for key in ('disk_sha256', 'seed_sha256')}, 'native image pins differ')
    require(native['native_program'] == {
        'catalog_sha256': sha(catalog), 'entry_id_sha256': sha(entry['id'].encode()),
        'profile_sha256': entry['profile_sha256'], 'executable_sha256': entry['executable_sha256']}, 'native program pins differ')
    require(native['measured_at'] == program_inputs['record']['started_at'], 'native measurement time differs')
    row = native['measurements']['native_program']
    require(row['verdict'] == 'PASS' and row['attempt_id'] == program_inputs['record']['attempt_id']
            and row['guest_attempt_id'] == program_inputs['record']['receipt']['attempt_id']
            and type(row['program_binding_facts']) is int and row['program_binding_facts'] == len(program['facts'])
            and type(row['vault_staging_facts']) is int and row['vault_staging_facts'] == len(raw['facts'])
            and len(row['not_measured']) == 5, 'native component measurement binding differs')
    require(native['qualification'] == {'native_vendor': False, 'k113': False, 'release': False, 'new_host_runtime': False}
            and all(value is False for value in native['qualification'].values()), 'native qualification scope changed')
    require(native['compatibility']['measured_host_source'] == provenance['package_source_revision']
            and native['compatibility']['measured_guest_jail_source'] == image['jail_candidate']['source_revision']
            and native['compatibility']['older_or_changed_guest_images_inherit_admission'] is False, 'native source scope differs')
    require(type(native['evidence']) is dict and len(native['evidence']) == 24, 'native evidence references differ')
    for ref in native['evidence'].values():
        require(type(ref) is dict and set(ref) == {'path', 'sha256'}, 'native evidence reference malformed')
        name = ref['path']
        require(type(name) is str and name in manifest and '\\' not in name
                and PurePosixPath(name).as_posix() == name and not name.startswith('/')
                and all(part not in ('', '.', '..') for part in name.split('/')), 'native reference is unsafe')
        require(ref['sha256'] == sha(read(name)), 'native reference hash differs')
    require(native['evidence']['generic_credential_staging']['sha256'] == sha(read('credential-staging/credential-staging.json'))
            and native['evidence']['program_inputs']['sha256'] == program['inputs_sha256'], 'native component references differ')
    review = load('native-admission-review.json')
    require(review['schema'] == 'ukai.vm.native-program-admission-review/1' and review['outcome'] == 'PASS'
            and review['record'] == {'path': 'native-admission.json', 'sha256': sha(read('native-admission.json'))}
            and review['qualification'] == native['qualification']
            and all(value is True for value in review['checks'].values()), 'native review binding differs')
    result = {'schema': 'ukai.vm.component-proof-replay/1', 'outcome': 'PASS',
              'bundle_files_verified': len(manifest), 'capability_rows': len(cap['measurements']),
              'boundary_facts': len(bound_facts), 'raw_credential_facts': len(raw['facts']),
              'literal_program_binding_facts': len(program['facts']),
              'native_component_admission_pins': 6, 'native_component_evidence_references': len(native['evidence']),
              'source_record_sha256': raw['inputs_sha256'], 'catalog_sha256': sha(catalog),
              'native_launch_or_sampling_qualified': False, 'vendor_qualified': False, 'k113_qualified': False,
              'scope': 'Relocated retained component evidence replay; no fresh VM, process/disk leak scan, Apple signature verification or release qualification.'}
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
