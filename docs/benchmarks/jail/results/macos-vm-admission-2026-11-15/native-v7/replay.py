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
        'sampled_exposure': 'ukai.vm.sampled-exposure/3',
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

Q_VERIFIER_SHA256 = '588e2ed6f9eee7839238c3ef8214044557e3e1f779ff6e96f2a47d673d85d860'
REQUIRED_PACKAGE_FACTS = {'exact_Q_disk_seed', 'portable_tail_compile_fixture_in_archive', 'retained_copy_SHA256SUMS', 'whole_distribution_public_modes', 'payload_component_identities', 'managed_gate_source_fixture_in_archive', 'retained_copy_preview-source.tar.gz', 'retained_copy_install.sh', 'settled_package_metadata_pin', 'no_preexisting_exact_dmg_attachment', 'all_guest_source_pins_match_host_revision', 'image_metadata_exact', 'dmg_hash', 'package_source_and_scope', 'complete_source_bytes_and_modes', 'native_catalog_exact', 'new_stage_preserved', 'clean_exact_source_after', 'upstream_wrapper_result_pinned', 'owning_package_completed_PASS', 'actual_service_version', 'all_manifest_files_exact', 'source_archive_hash', 'six_signatures', 'clean_exact_source_before', 'exact_original_prepared_manifest', 'actual_client_provenance', 'payload_public_distribution_modes', 'new_stage_exact_signed_dmg_inventory', 'exact_payload_inventory', 'retained_copy_READ-ME.txt', 'manifest_and_installer_hashes', 'current_host_notices', 'root_installer_and_network_fixture_in_archive', 'same_prepared_guest_and_detector', 'owned_dmg_detached', 'prepared_image_and_package_records_preserved'}
def verify_installed_records(installed, payload, image, independent):
    """Validate Q's complete, actually hashed fourteen-file installation."""
    executable = {'bin/ukai-vm', 'bin/ukai-jail', 'bin/ukai-vm-install', 'image/vz', 'image/custodian'}
    names = executable | {'image/image.json', 'image/seed.iso', 'image/guest-program-catalog.json', 'image/base.raw',
        'licenses/Linux-Jail-LICENSES.txt', 'licenses/Native-Host-LICENSES.txt', 'licenses/Python-LICENSE.txt',
        'licenses/Ukai-LICENSE.txt', 'licenses/pyinstaller-COPYING.txt'}
    rows = installed['installed']
    require(type(rows) is dict and set(rows) == names and installed['files'] == 14
            and type(installed['files']) is int and installed['outcome'] == 'PASS'
            and installed['image'] == image and 'payload/image/base.raw' not in payload,
            'installed observed file set differs')
    for name, row in rows.items():
        generation = row['generation']; mode = 0o755 if name in executable else 0o644
        require(type(generation) is dict and set(generation) == {'st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink'}
                and all(type(v) is int and v >= 0 for v in generation.values())
                and generation['st_mode'] == stat.S_IFREG | mode and generation['st_nlink'] == 1
                and type(row['mode']) is int and row['mode'] == mode,
                'installed generation or mode differs')
        expected = image['disk_sha256'] if name == 'image/base.raw' else payload['payload/' + name]
        require(row['sha256'] == expected, 'installed payload hash differs')
    for name, key in {'payload/image/base.raw.gz':'compressed_disk_sha256', 'preview-source.tar.gz':'source_archive_sha256',
                      'payload/image/seed.iso':'seed_sha256','payload/image/vz':'helper_sha256','payload/image/custodian':'custodian_sha256'}.items():
        require(payload[name] == image[key], 'signed image payload linkage differs')
    raw = rows['image/base.raw']
    require(raw['generation']['st_size'] == 6 * 1024 ** 3 and type(raw['allocated_bytes']) is int
            and 0 < raw['allocated_bytes'] <= raw['generation']['st_size'], 'installed decompressed disk observation differs')
    return True

def verify_signature_records(signatures, verifier_raw, expected_signed):
    """Replay retained Q strict Developer ID observations, never fabricate command logs."""
    require(sha(verifier_raw) == Q_VERIFIER_SHA256, 'signature verifier source differs')
    require(type(signatures) is list and len(signatures) == 6
            and all(type(row) is dict and set(row) == {'name','sha256','valid'} for row in signatures)
            and {row['name'] for row in signatures} == set(expected_signed)
            and all(row['valid'] is True and row['sha256'] == expected_signed[row['name']] for row in signatures),
            'signature payload observation differs')
    return True

def verify_q_package(image, staged, provenance):
    """Cross-bind real Q observer, installation and cleanup schemas without live paths."""
    pkg = load('package/package.json'); installed = load('package/installed-identity.json')
    independent = load('package/independent-review.json'); installer = load('package/installer-summary.json')
    install_life = load('package/installer-completion.json'); manifest_raw = read('package/SHA256SUMS')
    import credential_staging_measurement as admission
    payload = admission.parse_manifest(manifest_raw)
    require(installed['schema'] == 'ukai.Q.installed-artifact-identity/1' and pkg['image'] == image
            and pkg['source_revision'] == installed['source_revision'] == provenance['package_source_revision']
            and independent['source_revision'] == provenance['package_source_revision']
            and independent['outcome'] == 'PASS' and required_true_checks(independent['facts'], REQUIRED_PACKAGE_FACTS),
            'independent package observation failed')
    require(installed['package_sha256'] == sha(read('package/package.json'))
            and installed['artifact_review_sha256'] == sha(read('package/independent-review.json'))
            and installed['summary_sha256'] == sha(read('package/installer-summary.json'))
            and installed['lifecycle_sha256'] == sha(read('package/installer-completion.json')),
            'installed observation association differs')
    require(pkg['dmg_sha256_before_notarization'] == installed['dmg_sha256'] == independent['dmg_sha256'] == staged['installation']['dmg_sha256']
            and sha(manifest_raw) == pkg['manifest_sha256'] == staged['installation']['manifest_sha256']
            and payload['payload/image/image.json'] == sha(read('raw-vault/image.json'))
            and payload['payload/image/guest-program-catalog.json'] == sha(read('image/guest-program-catalog.json')),
            'signed manifest differs')
    require(staged['installation']['signing'] == 'verified-developer-id' and staged['installation']['team_id'] == '64SGQ348QJ',
            'signed staging verification differs')
    expected = {pkg['dmg']:pkg['dmg_sha256_before_notarization'], **{'payload/'+name:payload['payload/'+name] for name in
        ('bin/ukai-jail','bin/ukai-vm','bin/ukai-vm-install','image/vz','image/custodian')}}
    require(independent['reviewer_sha256'] == sha(read('package/proof-verifier.py')), 'observer source binding differs')
    verify_signature_records(independent['signatures'], read('package/proof-verifier.py'), expected)
    verify_installed_records(installed, payload, image, independent)
    client = load('package/client-version.json')
    require(installed['client_version'] == client and installed['service_version'] == load('package/service-version.json')
            and client['build'] == staged['installation']['client_build'] == image['ukai_jail_version']['build']
            and client['build']['revision'] == provenance['package_source_revision'] and client['build']['dirty'] is False,
            'installed clean client version differs')
    for label, name in [('client','bin/ukai-jail'),('service','bin/ukai-vm')]:
        require(installed['installed'][name]['sha256'] == staged['installation'][label+'_sha256']
                == image['ukai_jail_sha256' if label=='client' else 'ukai_vm_sha256'], 'installed binary identities differ')
    cases = {'install','repeat-refused','unrelated-refused','unrelated-client-refused',*FIXTURE_NAMES}
    require(installer['passed'] is True and type(installer['results']) is list and len(installer['results']) == 7
            and {row['case'] for row in installer['results']} == cases
            and all(row['passed'] is True and row['failed_checks'] == [] for row in installer['results']),
            'installer observations failed')
    require(install_life['outcome'] == 'PASS' and install_life['automatic_retry'] is False and install_life['cleanup_errors'] == []
            and all(install_life.get(k) is True for k in ('dmg_bytes_preserved','installed_no_holders','no_competing_task_process',
                'originals_preserved','owned_attachment_absent','owned_detach_completed','runtime_reserve_preserved','seven_cases_passed','source_preserved'))
            and install_life['summary_sha256'] == sha(read('package/installer-summary.json'))
            and install_life['installed_root'] == installed['root'], 'installer lifecycle differs')
    stage = independent['stage_proof']; cleanup = load('package/stage-cleanup.json')
    require(stage['schema'] == 'ukai.Q.signed-package-stage-equality/1' and stage['source_revision'] == pkg['source_revision']
            and stage['dmg_sha256'] == pkg['dmg_sha256_before_notarization'] and stage['manifest_sha256'] == pkg['manifest_sha256']
            and stage['package_sha256'] == sha(read('package/package.json'))
            and type(stage['source_files']) is int and stage['source_files'] == independent['source_file_count'] == 976
            and stage['source_archive_sha256'] == image['source_archive_sha256']
            and stage['six_signatures'] is True and stage['mounted_filesystem_metadata_names'] == [], 'retained stage proof differs')
    inventory = stage['inventory']; files = {n:r for n,r in inventory.items() if r['kind']=='file'}
    require(len(inventory)==22 and len(files)==18 and all(r['kind'] in ('file','directory') for r in inventory.values())
            and all(files[name]['sha256']==digest for name,digest in payload.items())
            and files['SHA256SUMS']['sha256']==sha(manifest_raw), 'stage manifest inventory differs')
    require(cleanup['verification_sha256'] == sha(read('package/independent-review.json')) and cleanup['outcome']=='PASS'
            and cleanup['errors']==[] and cleanup['stage_absent'] is True
            and cleanup['all_preserved_hashes_and_generations_unchanged'] is True and cleanup['all_held_fds_closed'] is True
            and len(cleanup['removed_files'])==len(files) and set(cleanup['removed_files'])==set(files)
            and len(cleanup['removed_directories'])==5 and set(cleanup['removed_directories'])=={'.',*(set(inventory)-set(files))},
            'retained stage cleanup differs')
    proof = installed['negative_proofs']
    require(type(proof) is dict and set(proof)==FIXTURE_NAMES, 'installer fixture set differs')
    for name,pins in proof.items():
        base='package/installer-fixtures/'+name; fixture=load(base+'.fixture.json'); removed=load(base+'.cleanup.json')
        require(pins['fixture_sha256']==sha(read(base+'.fixture.json')) and pins['cleanup_sha256']==sha(read(base+'.cleanup.json'))
                and fixture['case'] in installer['results'] and fixture['case']['passed'] is True and fixture['case']['case']==name
                and fixture['artifact']['dmg_sha256']==pkg['dmg_sha256_before_notarization']
                and fixture['artifact']['manifest_sha256']==pkg['manifest_sha256']
                and fixture['stdout_sha256']==sha(read(base+'.stdout')) and fixture['stderr_sha256']==sha(read(base+'.stderr'))
                and removed=={'case':name,'removed':True} and removed['removed'] is True, 'retained installer fixture cleanup differs')
    return True

def required_true_checks(value, required):
    return type(value) is dict and bool(required) and set(required) <= set(value) and all(v is True for v in value.values())

REQUIRED_COMPLETION_CHECKS = {'installed:image/seed.iso', 'installed:image/vz', 'artifact:guest-native-Q-journal-review/capabilities/review.json', 'artifact:guest-native-Q-journal-review/prepare/review.json', 'vault:owning_replay_cleanup', 'artifact:guest-native-package-independent-Q-44b5ac4fa/attempt-v2/retained-package/READ-ME.txt', 'boundary:owning_replay_cleanup', 'installed:image/image.json', 'artifact:guest-native-installer-Q-44b5ac4fa/summary.json', 'artifact:guest-native-package-Q-44b5ac4fa/ukai-vm-0.1.0-preview.2-macos-arm64.dmg', 'exact_finite_attempts', 'exact_three_boots', 'helper:execution_boundary_measurement.py', 'artifact:guest-native-package-independent-Q-44b5ac4fa/attempt-v2/retained-package/preview-source.tar.gz', 'installed:bin/ukai-jail', 'installed:image/custodian', 'artifact:guest-native-installer-execution-Q-44b5ac4fa/completion.json', 'helper:stream_peer.py', 'installed:licenses/Native-Host-LICENSES.txt', 'helper:capabilities.py', 'helper:guest.py', 'workspace_detached', 'artifact:guest-native-installer-execution-Q-44b5ac4fa/installed-identity.json', 'helper:guest_exposure.py', 'owned_dmg_and_workspace_attachments_absent', 'installed:licenses/Ukai-LICENSE.txt', 'artifact:guest-native-installer-execution-Q-44b5ac4fa/installer-execution.json', 'installed:bin/ukai-vm-install', 'no_vm_or_compiler', 'prepared:guest-program-catalog.json', 'installed:licenses/pyinstaller-COPYING.txt', 'helper:vault_measurement.py', 'new_redundant_stage_still_absent', 'artifact:guest-native-direct-plan-Q-44b5ac4fa/source-manifest.json', 'prepared:seed.iso', 'frozen_source_clean', 'capabilities:owning_replay_cleanup', 'reserve_preserved', 'installed:licenses/Python-LICENSE.txt', 'staging:owning_replay_cleanup', 'artifact:guest-native-direct-prepare-Q-44b5ac4fa/completion.json', 'helper:harness.py', 'artifact:guest-native-package-independent-Q-44b5ac4fa/attempt-v2/verification.json', 'helper:vm_summary_check.py', 'prepared:base.raw', 'helper:credential_revocation_measurement.py', 'installed:licenses/Linux-Jail-LICENSES.txt', 'helper:run.py', 'helper:claude_vm_row.py', 'helper:program_binding_measurement.py', 'artifact:guest-native-package-independent-Q-44b5ac4fa/attempt-v2/retained-package/SHA256SUMS', 'installed:image/base.raw', 'helper:credential_staging_measurement.py', 'program:owning_replay_cleanup', 'installed:bin/ukai-vm', 'artifact:guest-native-package-plan-Q-44b5ac4fa/completion.json', 'helper:guest_program.py', 'artifact:guest-native-package-independent-Q-44b5ac4fa/attempt-v2/retained-package/install.sh', 'artifact:guest-native-package-independent-Q-44b5ac4fa/stage-cleanup/result.json', 'artifact:guest-native-package-Q-44b5ac4fa/package.json', 'installed:image/guest-program-catalog.json'}
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
    verify_q_package(image, staged, provenance)
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
