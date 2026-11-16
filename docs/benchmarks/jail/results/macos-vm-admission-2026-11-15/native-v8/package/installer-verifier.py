"""One existing seven-case installer check; exact owned readonly DMG cleanup."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
PREP = HERE.parent / 'source-P-builder-pin-plan-J/cache-recovery-2026-11-16/continuation-plan/prepare_phase.py'
PREP_SHA = '539d33f581b0620b723ca8daa9d44fdc0bf270242a6444699a63d2fe99a68b28'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def owned_device(images, dmg, mount):
    matches = [row for row in images if row.get('image-path') == str(dmg)]
    if not matches:
        return None
    if len(matches) != 1:
        raise RuntimeError('ambiguous_exact_image')
    entities = matches[0].get('system-entities', [])
    mounts = [e['mount-point'] for e in entities if 'mount-point' in e]
    devices = [e.get('dev-entry') for e in entities if e.get('content-hint') == 'GUID_partition_scheme']
    if any(p != str(mount) for p in mounts) or len(devices) != 1 or not re.fullmatch(r'/dev/disk[0-9]+', devices[0] or ''):
        raise RuntimeError('ambiguous_owned_device_or_mount')
    return devices[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    args = parser.parse_args()
    if not __debug__ or hashlib.sha256(PREP.read_bytes()).hexdigest() != PREP_SHA:
        raise RuntimeError('owned_runner_pin')
    h = load(PREP, 'p_installer_owned')
    h.require(h.digest(args.plan, 1024**2) == args.plan_sha256, 'plan_pin')
    plan = json.loads(args.plan.read_text())
    h.require(plan['status'] == 'READY' and h.digest(__file__) == plan['wrapper_sha256'], 'ready_wrapper')
    record_dir = Path(plan['record']); output = Path(plan['installer_out']); mount = Path(plan['mountpoint']); dmg = Path(plan['dmg'])
    h.require(not record_dir.exists() and not output.exists() and not mount.exists(), 'fresh_owned_paths')
    os.umask(0o077); record_dir.mkdir(mode=0o700); (record_dir / 'tmp').mkdir(mode=0o700)
    result = {'schema': 'ukai.export-repair.actual-installer-execution/1', 'outcome': 'FAIL', 'plan_sha256': args.plan_sha256,
              'wrapper_sha256': plan['wrapper_sha256'], 'automatic_retry': False, 'cleanup_errors': [],
              'scope': 'One existing seven-case check_install; no VM/provider/admission; historical failures retained.'}
    started = time.monotonic(); attachment_attempted = False; source_verified = False; safe = None; manifest = None
    env = {'HOME': '/Users/monocursive', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(record_dir / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1'}
    for n in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT): signal.signal(n, h.abort)
    signal.alarm(480)

    def command(label, argv, timeout=30, cleanup=False):
        selected = plan
        if cleanup:
            selected = {**plan, 'guards': {**plan['guards'], 'hard_runtime_reserve_bytes': 0, 'stop_margin_bytes': 0}}
        h.run_phase(label, list(map(str, argv)), timeout, selected, safe, record_dir, env)
        path = record_dir / (label + '.stdout')
        h.require(path.stat().st_size <= 4 * 1024**2, 'metadata_output_cap')
        return path.read_bytes()

    def attachments(label, cleanup=False):
        raw = command(label, ['/usr/bin/hdiutil', 'info', '-plist'], 15, cleanup)
        return owned_device(plistlib.loads(raw).get('images', []), dmg, mount)

    try:
        for path, wanted in plan['evidence_pins'].items(): h.require(h.digest(path, 4 * 1024**2) == wanted, 'evidence_pin')
        for path, wanted in plan['tool_pins'].items(): h.require(h.digest(path, 4 * 1024**2) == wanted, 'tool_pin')
        safe = load(Path(plan['cleanup_runner']['path']), 'p_installer_safe')
        manifest = json.loads(Path(plan['source_manifest']).read_text())
        h.require(manifest['revision'] == plan['source_revision'] and len(manifest['files']) == plan['source_archive_files'], 'source_manifest')
        h.source_check(plan, manifest); source_verified = True
        proof = json.loads(Path(plan['artifact_review']).read_text())
        h.require(proof['outcome'] == 'PASS' and proof['completed'] is True and all(proof['facts'].values()), 'artifact_review')
        h.require(plan['stage_policy'] == 'retained_verified_stage' and proof['stage_proof']['stage_path'] == plan['new_stage'], 'retained_stage_policy')
        for name, generation in proof['stage_proof']['stage_generations'].items():
            path = str(Path(plan['new_stage']) / name) if name != '.' else plan['new_stage']
            wanted = plan['original_generations'][path]
            h.require([wanted[k] for k in ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')] == generation, 'retained_stage_proof_binding')
        package = json.loads(Path(plan['package_json']).read_text())
        h.require(package['source_revision'] == plan['source_revision'] and package['dmg_sha256_before_notarization'] == plan['dmg_sha256'], 'package_identity')
        h.require(h.digest(dmg) == plan['dmg_sha256'], 'actual_dmg_bytes')
        h.require(all(h.stamp(path) == row for path, row in plan['original_generations'].items()), 'original_generation')
        result['preflight'] = h.resources(plan); h.write(record_dir / 'preflight.json', result['preflight'])
        h.require(attachments('attachments-before') is None, 'no_preexisting_exact_dmg')
        command('checksum-verify', ['/usr/bin/hdiutil', 'verify', '-nocache', dmg], 90)
        h.require(all(h.stamp(path) == row for path, row in plan['original_generations'].items()), 'post_checksum_original_generation')
        mount.mkdir(mode=0o700); attachment_attempted = True
        command('attach', ['/usr/bin/hdiutil', 'attach', '-readonly', '-noverify', '-nobrowse', '-mountpoint', mount, '-plist', dmg], 60)
        h.require(mount.is_mount() and attachments('attachments-mounted') is not None, 'exact_owned_mount')
        info = plistlib.loads(command('mounted-info', ['/usr/sbin/diskutil', 'info', '-plist', mount], 30))
        result['mounted_global_permissions_enabled'] = info.get('GlobalPermissionsEnabled')
        result['cross_uid_qualification'] = False
        for name, row in proof['stage_proof']['inventory'].items():
            path = mount / name; s = path.lstat()
            h.require(stat.S_IMODE(s.st_mode) == row['mode'], 'mounted_original_modes')
            if row['kind'] == 'directory': h.require(stat.S_ISDIR(s.st_mode), 'mounted_directory')
            else: h.require(stat.S_ISREG(s.st_mode) and s.st_size == row['bytes'] and h.digest(path) == row['sha256'], 'mounted_file_identity')
        h.require(h.digest(mount / 'SHA256SUMS') == package['manifest_sha256'] and h.digest(mount / 'install.sh') == package['installer_sha256'], 'manifest_installer_binding')
        h.require(shutil.disk_usage(record_dir).free >= plan['guards']['minimum_start_available_bytes'], 'installer_start_capacity')
        h.run_phase('installer', plan['command'], 300, plan, safe, record_dir, env)
        sys.path.insert(0, str(Path(plan['source_checkout']) / 'crates/ukai-jail/vm'))
        checker = load(Path(plan['checker']), 'p_installer_checker')
        summary = json.loads((output / 'summary.json').read_text())
        h.require(summary['passed'] is True and tuple(r['case'] for r in summary['results']) == checker.CASES and all(r['passed'] is True and not r['failed_checks'] for r in summary['results']), 'seven_owning_cases')
        h.require(summary['artifact']['dmg_sha256'] == plan['dmg_sha256'] and summary['artifact']['manifest_sha256'] == package['manifest_sha256'] and summary['artifact']['installer_sha256'] == package['installer_sha256'], 'owning_artifact_binding')
        installed = output / 'prefix with spaces/share/ukai-vm' / package['version']
        h.require(checker.installed_tree_matches(mount, installed) and checker.installed_modes_normal(mount, installed), 'installed_bytes_and_modes')
        result['installed_root'] = str(installed); result['installed_raw_allocated_bytes'] = (installed / 'image/base.raw').stat().st_blocks * 512
        result['summary_sha256'] = h.digest(output / 'summary.json'); result['seven_cases_passed'] = True
        for name in checker.CASES[-3:]:
            h.require(json.loads((output / (name + '.cleanup.json')).read_text())['removed'] is True and not (output / name).exists(), 'negative_fixture_cleanup')
        result['outcome'] = 'PASS'
    except BaseException as error:
        result['failure_type'] = type(error).__name__; result['failure_code'] = str(error)
    finally:
        for n in (signal.SIGTERM, signal.SIGINT): signal.signal(n, signal.SIG_IGN)
        signal.alarm(120)
        def final_check(name, action):
            try: action(); result[name] = True
            except BaseException as error:
                result[name] = False; result['outcome'] = 'FAIL'; result['cleanup_errors'].append({'stage': name, 'error_type': type(error).__name__, 'error': str(error)})
        def detach():
            if not attachment_attempted: return
            device = attachments('attachments-final-before', True)
            if device: command('detach', ['/usr/bin/hdiutil', 'detach', device], 45, True)
        final_check('owned_detach_completed', detach)
        def absent():
            if attachment_attempted:
                h.require(attachments('attachments-final-after', True) is None and not mount.is_mount(), 'owned_attachment_remains')
        final_check('owned_attachment_absent', absent)
        if source_verified: final_check('source_preserved', lambda: h.source_check(plan, manifest))
        final_check('originals_preserved', lambda: h.require(all(h.stamp(p) == row for p, row in plan['original_generations'].items()), 'original_changed'))
        final_check('dmg_bytes_preserved', lambda: h.require(h.digest(dmg) == plan['dmg_sha256'], 'dmg_changed'))
        expected_installed = output / 'prefix with spaces/share/ukai-vm/0.1.0-preview.2'
        if expected_installed.exists(): final_check('installed_no_holders', lambda: h.no_holders(expected_installed / 'image'))
        idle_plan = {**plan, 'guards': {**plan['guards'], 'minimum_start_available_bytes': plan['guards']['hard_runtime_reserve_bytes']}}
        final_check('no_competing_task_process', lambda: h.resources(idle_plan))
        result['free_after'] = shutil.disk_usage(record_dir).free; result['elapsed_seconds'] = time.monotonic() - started
        result['attachment_attempted'] = attachment_attempted
        final_check('runtime_reserve_preserved', lambda: h.require(result['free_after'] >= plan['guards']['hard_runtime_reserve_bytes'], 'reserve_crossed'))
        h.write(record_dir / 'completion.json', result); signal.alarm(0)
    print(json.dumps({'outcome': result['outcome'], 'completion': str(record_dir / 'completion.json'), 'sha256': h.digest(record_dir / 'completion.json')}))
    return 0 if result['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
