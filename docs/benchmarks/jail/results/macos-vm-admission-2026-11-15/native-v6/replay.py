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

def verify_installed_records(installed, payload, image, independent):
    """The installed raw disk is decompressed; its signed payload is gzip."""
    names = {'bin/ukai-vm', 'bin/ukai-jail', 'bin/ukai-vm-install', 'image/image.json',
             'image/seed.iso', 'image/guest-program-catalog.json', 'image/vz',
             'image/custodian', 'image/base.raw'}
    rows = installed['installed']
    if set(rows) != names or 'payload/image/base.raw' in payload or 'payload/image/base.raw.gz' not in payload:
        raise ValueError('installed observed file set differs')
    for name in names - {'image/base.raw'}:
        if rows[name]['sha256'] != payload['payload/' + name]:
            raise ValueError('installed payload hash differs')
    for name, key in {'payload/image/base.raw.gz': 'compressed_disk_sha256',
                      'preview-source.tar.gz': 'source_archive_sha256',
                      'payload/image/seed.iso': 'seed_sha256', 'payload/image/vz': 'helper_sha256',
                      'payload/image/custodian': 'custodian_sha256'}.items():
        if payload[name] != image[key]:
            raise ValueError('signed image payload linkage differs')
    raw = rows['image/base.raw']; observed = independent['installed_disk']
    if (raw['sha256_verified_by_owning_installer'] != image['disk_sha256']
            or observed['sha256'] != image['disk_sha256']
            or type(raw['logical_bytes']) is not int or raw['logical_bytes'] != 6 * 1024 ** 3
            or type(observed['logical_bytes']) is not int or observed['logical_bytes'] != raw['logical_bytes']
            or type(raw['allocated_bytes']) is not int or not 0 < raw['allocated_bytes'] <= raw['logical_bytes']
            or type(observed['allocated_bytes']) is not int or observed['allocated_bytes'] != raw['allocated_bytes']):
        raise ValueError('installed decompressed disk observation differs')
    return True

def verify_signature_records(signatures, executions, signing_plan, expected_signed):
    """Validate actual c25 list + execution records; do not invent legacy shapes."""
    def insist(ok, message):
        if ok is not True: raise ValueError(message)
    requirement = '=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "64SGQ348QJ"'
    names = {'dmg', 'installer', 'service', 'client', 'vz', 'custodian'}
    insist(type(signatures) is list and len(signatures) == 6 and all(type(r) is dict and set(r) == {'name', 'sha256', 'passed'} for r in signatures), 'signature observation shape differs')
    insist({r['name'] for r in signatures} == names and all(r['passed'] is True and r['sha256'] == expected_signed[r['name']] for r in signatures), 'signature payload hash differs')
    planned = signing_plan['signature_checks']
    insist(type(planned) is list and len(planned) == 6 and {r['name'] for r in planned} == names and set(executions) == names, 'signature plan set differs')
    paths = {'dmg': signing_plan['dmg'], **{name: str(Path(signing_plan['mountpoint']) / 'payload' / relative) for name, relative in {'installer':'bin/ukai-vm-install', 'service':'bin/ukai-vm', 'client':'bin/ukai-jail', 'vz':'image/vz', 'custodian':'image/custodian'}.items()}}
    for item in planned:
        name = item['name']; run = executions[name]
        argv = ['/usr/bin/codesign', '--verify', '--strict', '-R', requirement, paths[name]]
        insist(item['argv'] == argv and run['command'] == argv, 'signature verification argv differs')
        insist(type(run['returncode']) is int and run['returncode'] == 0 and run['outcome'] == 'PASS' and run['returncode_accepted'] is True and run['error_type'] is None, 'signature execution failed')
        insist(run['allowed_returncodes'] == [0] and type(run['allowed_returncodes'][0]) is int and run['cleanup'] == {'process_started': True, 'leader_reaped': True, 'group_absent': True} and all(type(v) is bool for v in run['cleanup'].values()), 'signature cleanup or status differs')
    return True

def required_true_checks(value, required):
    return type(value) is dict and bool(required) and set(required) <= set(value) and all(v is True for v in value.values())

REQUIRED_COMPLETION_CHECKS = {
    'artifact:guest-native-installer-c25c297fc/summary.json',
    'artifact:guest-native-package-build-c25c297fc/completion.json',
    'artifact:guest-native-package-build-c25c297fc/installed-identity.json',
    'artifact:guest-native-package-build-c25c297fc/retained-package/preview-source.tar.gz',
    'artifact:guest-native-package-build-c25c297fc/signatures.json',
    'artifact:guest-native-package-build-c25c297fc/source-snapshot.json',
    'artifact:guest-native-package-build-c25c297fc/stage-cleanup.json',
    'artifact:guest-native-package-build-c25c297fc/stage-verification.json',
    'artifact:guest-native-package-c25c297fc/package.json',
    'artifact:guest-native-package-c25c297fc/ukai-vm-0.1.0-preview.2-macos-arm64.dmg',
    'artifact:guest-native-package-independent-c25c297fc/verification.json',
    'artifact:native-v6-independent-review/prepared-review-v2.json',
    'boundary:owning_replay_cleanup',
    'capabilities:owning_replay_cleanup',
    'exact_finite_attempts',
    'exact_three_boots',
    'frozen_source_clean',
    'helper:capabilities.py',
    'helper:claude_vm_row.py',
    'helper:credential_revocation_measurement.py',
    'helper:credential_staging_measurement.py',
    'helper:execution_boundary_measurement.py',
    'helper:guest.py',
    'helper:guest_exposure.py',
    'helper:guest_program.py',
    'helper:harness.py',
    'helper:program_binding_measurement.py',
    'helper:run.py',
    'helper:stream_peer.py',
    'helper:vault_measurement.py',
    'helper:vm_summary_check.py',
    'installed:bin/ukai-jail',
    'installed:bin/ukai-vm',
    'installed:image/base.raw',
    'installed:image/custodian',
    'installed:image/guest-program-catalog.json',
    'installed:image/image.json',
    'installed:image/seed.iso',
    'installed:image/vz',
    'new_redundant_stage_still_absent',
    'no_vm_or_compiler',
    'owned_dmg_and_workspace_attachments_absent',
    'prepared:base.raw',
    'prepared:guest-program-catalog.json',
    'prepared:seed.iso',
    'program:owning_replay_cleanup',
    'reserve_preserved',
    'staging:owning_replay_cleanup',
    'vault:owning_replay_cleanup',
    'workspace_detached',
}
REQUIRED_PHASE_CHECKS = {
    'capabilities_holders_absent',
    'frozen_source_clean',
    'no_vm_or_compiler',
    'owned_group_reaped_absent',
    'owning_process_succeeded',
    'private_tmp_holders_absent',
    'program_holders_absent',
    'runtime_capacity_preserved',
    'vault_holders_absent',
}
PHASES = {'capabilities', 'boundary', 'vault', 'staging', 'program'}
FIXTURE_NAMES = {'manifest-tamper', 'payload-tamper', 'payload-extra'}

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
    require(installed['schema'] == 'ukai.private-installed-identity/1' and pkg['image'] == image and pkg['source_revision'] == installed['source_revision'] == provenance['package_source_revision'] and installed['dmg_sha256'] == pkg['dmg_sha256_before_notarization'], 'package source differs')
    require(independent['source_revision'] == provenance['package_source_revision']
            and independent['outcome'] == 'PASS' and required_true_checks(independent['facts'], {'complete_source_bytes_and_modes', 'six_signatures', 'installed_exact_hashes', 'all_seven_actual_installer_cases', 'owned_dmg_detached'}), 'independent package observation failed')
    require(independent['dmg_sha256'] == pkg['dmg_sha256_before_notarization'] == staged['installation']['dmg_sha256'], 'DMG identities differ')
    payload = admission.parse_manifest(read('package/SHA256SUMS'))
    require(sha(read('package/SHA256SUMS')) == pkg['manifest_sha256'] == staged['installation']['manifest_sha256'], 'signed manifest differs')
    require(payload['payload/image/image.json'] == sha(read('raw-vault/image.json'))
            and payload['payload/image/guest-program-catalog.json'] == sha(catalog), 'signed metadata binding differs')
    require(installed['installed']['bin/ukai-jail']['sha256'] == image['ukai_jail_sha256'] == payload['payload/bin/ukai-jail']
            and installed['installed']['bin/ukai-vm']['sha256'] == image['ukai_vm_sha256'] == payload['payload/bin/ukai-vm'], 'installed binary identities differ')
    client_version = load('package/client-version.json')
    require(client_version['build'] == staged['installation']['client_build'] == image['ukai_jail_version']['build']
            and client_version['build']['revision'] == provenance['package_source_revision']
            and client_version['build']['dirty'] is False, 'installed clean client version differs')
    installer = load('package/installer-summary.json')
    require(installer['passed'] is True and len(installer['results']) == 7
            and all(row['passed'] is True and row['failed_checks'] == [] for row in installer['results']), 'installer observations failed')
    signatures = load('package/signatures.json')
    expected_signed = {'dmg': pkg['dmg_sha256_before_notarization'], **{
        name: payload['payload/' + path] for name, path in {
            'installer': 'bin/ukai-vm-install', 'service': 'bin/ukai-vm', 'client': 'bin/ukai-jail',
            'vz': 'image/vz', 'custodian': 'image/custodian'}.items()}}
    signing_plan = load('package/signing-plan.json')
    require(signing_plan['source_revision'] == provenance['package_source_revision'] and signing_plan['dmg'] == str(Path(provenance['sources']['package/package.json']['source_path']).parent / pkg['dmg']), 'signature plan source differs')
    executions = {name: load('package/signature-' + name + '.execution.json') for name in expected_signed}
    verify_signature_records(signatures, executions, signing_plan, expected_signed)
    require(installed['client_version'] == client_version and installed['service_version'] == load('package/service-version.json') and installed['installer_summary_sha256'] == sha(read('package/installer-summary.json')), 'installed version observations differ')
    verify_installed_records(installed, payload, image, independent)
    # These are retained cleanup observations, not fresh filesystem checks.
    proof = independent['new_cleanup_proofs']
    stage = load('package/stage-verification.json'); cleanup = load('package/stage-cleanup.json')
    require(proof['stage_verification_sha256'] == sha(read('package/stage-verification.json')) == cleanup['verification_sha256']
            and proof['stage_cleanup_sha256'] == sha(read('package/stage-cleanup.json'))
            and stage['outcome'] == cleanup['outcome'] == 'PASS'
            and stage['dmg_sha256'] == pkg['dmg_sha256_before_notarization']
            and stage['manifest_sha256'] == pkg['manifest_sha256']
            and type(stage['source_files']) is int and stage['source_files'] == independent['source_file_count'] == 848
            and cleanup['old_artifacts_eligible'] is False, 'retained stage cleanup differs')
    require(type(proof['negative_fixtures']) is dict and set(proof['negative_fixtures']) == FIXTURE_NAMES, 'installer fixture set differs')
    for name, pins in proof['negative_fixtures'].items():
        base = 'package/installer-fixtures/' + name
        fixture = load(base + '.fixture.json'); removed = load(base + '.cleanup.json')
        require(pins['proof_sha256'] == sha(read(base + '.fixture.json'))
                and pins['cleanup_sha256'] == sha(read(base + '.cleanup.json'))
                and fixture['case'] in installer['results'] and fixture['case']['passed'] is True and fixture['case']['case'] == name
                and fixture['artifact']['dmg_sha256'] == pkg['dmg_sha256_before_notarization']
                and fixture['artifact']['manifest_sha256'] == pkg['manifest_sha256']
                and fixture['stdout_sha256'] == sha(read(base + '.stdout'))
                and fixture['stderr_sha256'] == sha(read(base + '.stderr'))
                and removed == {'case': name, 'removed': True} and removed['removed'] is True,
                'retained installer fixture cleanup differs')
    completion = load('lifecycle.json'); workspace = load('lifecycle/workspace.json')
    require(completion['source_revision'] == provenance['package_source_revision']
            and completion['outcome'] == workspace['outcome'] == 'PASS'
            and required_true_checks(completion['checks'], REQUIRED_COMPLETION_CHECKS)
            and type(completion['phases']) is dict and set(completion['phases']) == PHASES
            and completion['qualified'] is False and completion['native_vendor_or_k113_qualified'] is False
            and completion['automatic_retry'] is False
            and workspace['workspace_detached'] is True and workspace['owned_processes_none'] is True,
            'retained component lifecycle differs')
    by_origin = {row['source_path']: name for name, row in provenance['sources'].items()}
    for phase, row in completion['phases'].items():
        base = 'component-replay/' + phase
        accepted = load(base + '-acceptance.json')
        require(row['sha256'] == sha(read(by_origin[row['record']]))
                and row['acceptance_sha256'] == sha(read(base + '-acceptance.json'))
                and row['outer_sha256'] == sha(read(base + '-outer.json'))
                and accepted['outcome'] == 'PASS' and accepted['phase'] == phase
                and required_true_checks(accepted['checks'], REQUIRED_PHASE_CHECKS | ({'exact_dmg_attachment_absent'} if phase == 'staging' else set()))
                and accepted['qualified'] is False and accepted['native_vendor_or_k113_qualified'] is False,
                'retained phase linkage differs')
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
            and required_true_checks(review['checks'], {'program_replay_recomputes_24_component_facts', 'raw_vault_replay_recomputes_24_component_facts', 'generic_credential_admission_rederived', 'image_manifest_exact_bytes', 'catalog_bound_to_actual_ready_and_signed_image', 'retained_apple_signature_observations', 'installed_observed_hashes_match_payload'}), 'native review binding differs')
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
