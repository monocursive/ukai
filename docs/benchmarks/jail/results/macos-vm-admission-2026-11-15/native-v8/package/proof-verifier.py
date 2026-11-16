#!/usr/bin/env python3
"""Independent read-only review of the actual managed-/3 signed DMG and new duplicate stage."""
import ast
import argparse
import hashlib
import json
import os
import plistlib
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import subprocess
import tarfile

BASE = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent / 'attempt'
OUT.mkdir(exist_ok=False)
REV = '934ad33acc5efb2843de8ee9fd5ea3181b6790b3'
REPO = Path('/Users/monocursive/.cache/ukai-guest-export-source-934ad33ac-20261116')
PACKAGE = BASE / 'guest-native-package-export-934ad33ac'
STAGE = PACKAGE / 'volume'
MOUNT = OUT / 'mounted-dmg'
report = {'source_revision': REV, 'scope': 'Provisional934 host package with fresh export-repaired guest: actual read-only DMG, source1094, public POSIX modes and duplicate-stage equality. No installation, stage deletion, managed image admission, runtime qualification, provider or VM action.', 'facts': {}, 'signatures': []}
completed = False
attached = False
attach_attempted = False
digest_cache = {}
parser=argparse.ArgumentParser()
parser.add_argument('--dmg-sha256',required=True)
parser.add_argument('--package-sha256',required=True)
parser.add_argument('--completion-sha256',required=True)
args=parser.parse_args()
if not all(re.fullmatch(r'[0-9a-f]{64}',value) for value in [args.dmg_sha256,args.package_sha256,args.completion_sha256]):raise ValueError('exact settled package and DMG SHA required')
if (OUT/'verification.json').exists():raise FileExistsError('review output already exists')
sys.dont_write_bytecode=True


def run(*args):
    return subprocess.run([str(x) for x in args], check=True, capture_output=True, timeout=90, stdin=subprocess.DEVNULL, env={**{k:os.environ[k] for k in ('HOME','USER','LOGNAME','TMPDIR') if k in os.environ},'PATH':'/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','GIT_OPTIONAL_LOCKS':'0'})

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def digest(path):
    path=Path(path)
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size>16*1024**3:
        raise ValueError('invalid bounded hash input')
    key=(str(path),identity(before))
    if key in digest_cache:
        return digest_cache[key]
    h=hashlib.sha256()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        if identity(os.fstat(f.fileno()))!=identity(before):raise ValueError('hash input changed')
        for data in iter(lambda:f.read(8*1024*1024),b''):h.update(data)
        if identity(os.fstat(f.fileno()))!=identity(before):raise ValueError('hash input changed')
    if identity(path.lstat())!=identity(before):raise ValueError('hash pathname changed')
    digest_cache[key]=h.hexdigest()
    return h.hexdigest()


def owned_attachments(dmg):
    data=plistlib.loads(run('hdiutil','info','-plist').stdout)
    matches=[v for v in data.get('images',[]) if v.get('image-path')==str(dmg)]
    if len(matches)>1:raise ValueError('ambiguous exact DMG attachment')
    return matches

def check(name, value):
    report['facts'][name] = value is True
    if value is not True:
        raise ValueError(name)

def inventory(root):
    result = {}
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('inventory root is not a directory')
    def fail(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        current = Path(directory)
        for name in dirs:
            if not stat.S_ISDIR((current / name).lstat().st_mode):
                raise ValueError('non-directory inventory entry')
        for name in files:
            path = current / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('nonregular inventory entry')
            result[path.relative_to(root).as_posix()] = path
    return result

def directory_modes(root):
    def fail(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        mode = Path(directory).lstat().st_mode
        if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) != 0o755:
            return False
    return True

try:
    check('clean_exact_source_before', run('git', '-C', REPO, 'rev-parse', 'HEAD').stdout.decode().strip() == REV and not run('git', '-C', REPO, 'status', '--porcelain=v1').stdout)
    if (OUT / 'verification.json').exists():
        raise ValueError('review output already exists')
    check('settled_package_metadata_pin',digest(PACKAGE/'package.json')==args.package_sha256)
    metadata = json.loads((PACKAGE / 'package.json').read_text())
    prepared_root=BASE/'guest-native-export-home-934ad33ac/image'
    preserved_paths=[PACKAGE/'package.json',*sorted(path for path in prepared_root.iterdir() if path.is_file())]
    preserved_before={str(path):identity(path.lstat()) for path in preserved_paths}
    check('package_source_and_scope', metadata['source_revision'] == REV and metadata['published'] is False and metadata['notarization'] == 'pending')
    completion_path=BASE/'guest-native-package-plan-export-934ad33ac/completion.json'
    check('upstream_wrapper_result_pinned',digest(completion_path)==args.completion_sha256)
    report['upstream_wrapper_result']=json.loads(completion_path.read_bytes())
    check('owning_package_completed_PASS',report['upstream_wrapper_result']['outcome']=='PASS' and report['upstream_wrapper_result']['package_json_sha256']==args.package_sha256 and report['upstream_wrapper_result']['dmg_sha256']==args.dmg_sha256 and report['upstream_wrapper_result']['cleanup_errors']==[])
    report['upstream_wrapper_result_scope']='Exact provisional934 owning result retained. All historical P/Q/R/S wrapper, observer and runtime failures remain unchanged in their original records.'
    report['mode_scope']='New owned provisional934 stage and mounted distribution entries must have directories/executables0755 and data0644 regardless of caller umask; this does not establish ACL/Gatekeeper or foreign-UID execution qualification.'
    dmg = PACKAGE / metadata['dmg']
    preserved_paths.extend([dmg,completion_path])
    preserved_before.update({str(path):identity(path.lstat()) for path in [dmg,completion_path]})
    report['preserved_generations_before']=preserved_before
    report['dmg_xattr_names_before']=run('/usr/bin/xattr',dmg).stdout.decode().splitlines()
    report['dmg_sha256'] = digest(dmg)
    check('dmg_hash', report['dmg_sha256'] == metadata['dmg_sha256_before_notarization'] == args.dmg_sha256)
    check('no_preexisting_exact_dmg_attachment',not owned_attachments(dmg))
    verify_argv = ['hdiutil', 'verify', '-nocache', str(dmg)]
    report['internal_checksum_verification'] = {'argv': verify_argv, 'timeout_seconds': 90, 'returncode': None}
    try:
        verified = run(*verify_argv)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (OUT / 'checksum-verify.stdout').write_bytes(error.stdout or b'')
        (OUT / 'checksum-verify.stderr').write_bytes(error.stderr or b'')
        report['internal_checksum_verification'].update(returncode=getattr(error, 'returncode', None), error_type=type(error).__name__)
        raise
    (OUT / 'checksum-verify.stdout').write_bytes(verified.stdout)
    (OUT / 'checksum-verify.stderr').write_bytes(verified.stderr)
    report['internal_checksum_verification'].update(returncode=verified.returncode,
        stdout_sha256=digest(OUT / 'checksum-verify.stdout'), stderr_sha256=digest(OUT / 'checksum-verify.stderr'))
    check('internal_dmg_checksum_verified_without_cache', verified.returncode == 0)
    MOUNT.mkdir(exist_ok=False)
    attach_attempted = True
    attach = run('hdiutil', 'attach', '-readonly', '-noverify', '-nobrowse', '-mountpoint', MOUNT, '-plist', dmg)
    attached = True
    (OUT / 'attachment.plist').write_bytes(attach.stdout)
    ownership_raw=run('diskutil','info','-plist',MOUNT).stdout
    (OUT/'mounted-info.plist').write_bytes(ownership_raw)
    ownership=plistlib.loads(ownership_raw)
    ownership_paths=['.','payload','payload/bin','payload/bin/ukai-jail','payload/bin/ukai-vm','payload/image','payload/image/image.json']
    observed_modes={name:{'uid':(MOUNT/name).lstat().st_uid,'gid':(MOUNT/name).lstat().st_gid,'mode':oct(stat.S_IMODE((MOUNT/name).lstat().st_mode))} for name in ownership_paths}
    report['mounted_ownership_observation']={'diskutil_fields':{key:ownership[key] for key in ('GlobalPermissionsEnabled','Owners','FilesystemType','FilesystemName','MountPoint','ReadOnlyMedia','ReadOnlyVolume') if key in ownership},'statvfs_flags':os.statvfs(MOUNT).f_flag,'uid_gid_modes':observed_modes,'scope':'Actual current-user mount observation only; no foreign-UID or shared-attachment test.'}
    report['cross_uid_distribution_qualified']=False
    image = json.loads((MOUNT / 'payload/image/image.json').read_text())
    check('image_metadata_exact', image == metadata['image'] and image['source_revision'] == REV)
    manifest = {}
    for line in (MOUNT / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
        if match is None:
            raise ValueError('malformed manifest')
        sha, name = match.groups()
        p = PurePosixPath(name)
        if p.is_absolute() or any(x in ('', '.', '..') for x in name.split('/')) or name in manifest:
            raise ValueError('unsafe or duplicate manifest path')
        manifest[name] = sha
    check('all_manifest_files_exact', all(digest(MOUNT / name) == sha for name, sha in manifest.items()))
    check('exact_payload_inventory', set(inventory(MOUNT / 'payload')) == {name.removeprefix('payload/') for name in manifest if name.startswith('payload/')})
    check('manifest_and_installer_hashes', digest(MOUNT / 'SHA256SUMS') == metadata['manifest_sha256'] and digest(MOUNT / 'install.sh') == metadata['installer_sha256'])
    for name in [None, 'payload/bin/ukai-jail', 'payload/bin/ukai-vm', 'payload/bin/ukai-vm-install', 'payload/image/vz', 'payload/image/custodian']:
        path = dmg if name is None else MOUNT / name
        requirement = '=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "64SGQ348QJ"'
        run('codesign', '--verify', '--strict', '-R', requirement, path)
        details = run('codesign', '-dv', '--verbose=4', path).stderr.decode()
        valid = 'TeamIdentifier=64SGQ348QJ\n' in details and 'Authority=Developer ID Application: Monocursive (64SGQ348QJ)\n' in details
        report['signatures'].append({'name': name or dmg.name, 'sha256': digest(path), 'valid': valid})
    check('six_signatures', len(report['signatures']) == 6 and all(x['valid'] for x in report['signatures']))
    payload = inventory(MOUNT/'payload')
    identities = {'bin/ukai-jail':'ukai_jail_sha256','bin/ukai-vm':'ukai_vm_sha256','image/vz':'helper_sha256','image/custodian':'custodian_sha256','image/seed.iso':'seed_sha256','image/base.raw.gz':'compressed_disk_sha256'}
    check('payload_component_identities',all(digest(payload[name])==image[key] for name,key in identities.items()))
    executable={'bin/ukai-jail','bin/ukai-vm','bin/ukai-vm-install','image/vz','image/custodian'}
    check('payload_public_distribution_modes',all(stat.S_IMODE(path.stat().st_mode) == (0o755 if name in executable else 0o644) for name,path in payload.items()) and directory_modes(MOUNT/'payload'))
    archive = MOUNT / 'preview-source.tar.gz'
    check('source_archive_hash', digest(archive) == image['source_archive_sha256'])
    input_bytes = run('git', '-C', REPO, 'show', REV + ':crates/ukai-jail/profiles/inputs.rs').stdout.decode()
    paths = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', '.cargo/config.toml', 'install.sh', 'crates', 'docs/benchmarks/jail/results/macos-vm-admission-2026-11-15', 'docs/specs/jail-v1/examples/event-note-learning-read.json', *ast.literal_eval(input_bytes)]
    tree = run('git', '-C', REPO, 'ls-tree', '-r', '-z', REV, '--', *sorted(set(paths))).stdout
    expected_source = {}
    for entry in tree.split(b'\0'):
        if entry:
            meta, name = entry.split(b'\t', 1)
            mode, kind, blob = meta.decode().split()
            if kind != 'blob' or mode not in ('100644', '100755'):
                raise ValueError('unexpected source kind')
            expected_source[os.fsdecode(name)] = (int(mode, 8) & 0o777, blob)
    source_names = set()
    source_total=0
    prefix = 'ukai-vm-0.1.0-preview.2-source/'
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            if not member.isreg() or not member.name.startswith(prefix):
                raise ValueError('unexpected archive member')
            name = member.name[len(prefix):]
            if name in source_names or name not in expected_source:
                raise ValueError('unexpected or duplicate source path')
            if member.size > 64*1024*1024 or source_total+member.size > 256*1024*1024:
                raise ValueError('source archive exceeds bounded review')
            data = source.extractfile(member).read(member.size+1)
            if len(data)!=member.size:raise ValueError('truncated source member')
            source_total+=len(data)
            git_hash = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if (member.mode, git_hash) != expected_source[name]:
                raise ValueError('source bytes or mode mismatch')
            source_names.add(name)
    report['source_file_count'] = len(source_names)
    check('complete_source_bytes_and_modes', source_names == set(expected_source) and len(source_names) == image['source_archive_files'] == 1094)
    prepared_path=prepared_root/'image.json'
    check('exact_original_prepared_manifest',digest(prepared_path)=='c57db83c92bdac161d053ff8eea818d18f002bfdc776ad9d6a370d615cbe631e')
    prepared=json.loads(prepared_path.read_text())
    check('exact_fresh934_disk_seed',image['disk_sha256']=='22ff8df581c05809cf516ab66a56d6655d46f324d7ff3ab61929e77742a0a681' and image['seed_sha256']=='a60149d230084c5cc8987f63b39d87fb8062bc582ced57848480b92115b7ca28')
    expected_guest_sources={'guest.py','guest_program.py','guest_exposure.py','guest_exposure_control.py','prepare.py','vz.swift','custodian.c'}
    check('all_guest_source_pins_match_host_revision',set(image['source_sha256'])==expected_guest_sources and all(hashlib.sha256(run('git','-C',REPO,'show',REV+':crates/ukai-jail/vm/'+name).stdout).hexdigest()==value for name,value in image['source_sha256'].items()))
    check('native_catalog_exact', digest(MOUNT / 'payload/image/guest-program-catalog.json') == prepared['guest_program_catalog_sha256'] == image['guest_program_catalog_sha256'])
    keys = ['disk_sha256', 'seed_sha256', 'source_sha256', 'guest_program_inputs', 'guest_exposure_control', 'guest_exposure_control_sha256']
    check('same_prepared_guest_and_detector', all(image[k] == prepared[k] for k in keys))
    client_version = json.loads(run(MOUNT / 'payload/bin/ukai-jail', 'version', '--json').stdout)
    client = {key: client_version[key] for key in ('component', 'version', 'build')}
    build = client['build']
    check('actual_client_provenance', client == metadata['build']['ukai_jail_version'] == image['ukai_jail_version'] and build['revision'] == REV and build['inputs'] == 'sha256:2c0def0696f2230a0ec69c3b640a09bf7904c6372e2acdaca702aac268081583' and build['dirty'] is False and build['target'] == 'aarch64-apple-darwin' and build['opt_level'] == '3' and build['debug_assertions'] is False and build['rustc'].startswith('rustc 1.98.1 '))
    check('actual_service_version', json.loads(run(MOUNT / 'payload/bin/ukai-vm', 'version').stdout)['version'] == metadata['version'])
    report['client_version'] = client
    current_notices = run(sys.executable, '-B', REPO / 'crates/ukai-jail/dist/notices.py', 'print', '--source', REPO).stdout
    check('current_host_notices', (MOUNT / 'payload/licenses/Native-Host-LICENSES.txt').read_bytes() == current_notices)
    check('portable_tail_compile_fixture_in_archive', 'docs/specs/jail-v1/examples/event-note-learning-read.json' in source_names)
    check('root_installer_and_network_fixture_in_archive',{'install.sh','docs/specs/jail-v1/network-addresses.json'}<=source_names)
    check('managed_gate_source_fixture_in_archive',{'crates/ukai-jail/vm/fixtures/managed-sampled-exposure.json', 'crates/ukai-jail/vm/guest_program.py', 'crates/ukai-jail/vm/guest_exposure.py', 'crates/ukai-jail/vm/test_guest_gate.py'}<=source_names)
    def whole_inventory(root, allow_filesystem_metadata=False):
        values={};generations={'.':identity(root.lstat())};extras=set()
        def fail_walk(error):raise error
        for directory,dirs,files in os.walk(root,followlinks=False,onerror=fail_walk):
            current=Path(directory)
            if current==root and allow_filesystem_metadata:
                extras=set(dirs)&{'.fseventsd','.Trashes','.Spotlight-V100'}
                dirs[:]=[name for name in dirs if name not in extras]
            for name in [*dirs,*files]:
                path=current/name;info=path.lstat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):raise ValueError('nonregular stage or mounted entry')
                rel=path.relative_to(root).as_posix();generations[rel]=identity(info)
                values[rel]={'kind':'directory' if stat.S_ISDIR(info.st_mode) else 'file','mode':stat.S_IMODE(info.st_mode),'bytes':None if stat.S_ISDIR(info.st_mode) else info.st_size,'sha256':None if stat.S_ISDIR(info.st_mode) else digest(path)}
                if len(values)>4096:raise ValueError('whole inventory cap')
        return values,generations,extras
    stage_inventory,stage_generations,_=whole_inventory(STAGE)
    mounted_inventory,_,extras=whole_inventory(MOUNT,True)
    check('new_stage_exact_signed_dmg_inventory',stage_inventory==mounted_inventory and directory_modes(STAGE))
    distribution_executable={'install.sh',*('payload/'+name for name in executable)}
    check('whole_distribution_public_modes',stat.S_IMODE(STAGE.lstat().st_mode)==stat.S_IMODE(MOUNT.lstat().st_mode)==0o755 and all(row['mode']==(0o755 if row['kind']=='directory' or name in distribution_executable else 0o644) for name,row in stage_inventory.items()))
    retained=OUT/'retained-package';retained.mkdir(exist_ok=False)
    copied={}
    for name in ('preview-source.tar.gz','SHA256SUMS','install.sh','READ-ME.txt'):
        source=STAGE/name
        if source.stat().st_size>64*1024*1024:raise ValueError('retained proof copy cap')
        raw=source.read_bytes();target=retained/name
        with target.open('xb') as stream:stream.write(raw)
        target.chmod(stat.S_IMODE(source.stat().st_mode));copied[name]=digest(target)
        check('retained_copy_'+name,copied[name]==digest(source)==digest(MOUNT/name))
    stage_after,stage_generations_after,_=whole_inventory(STAGE)
    check('new_stage_preserved',stage_after==stage_inventory and stage_generations_after==stage_generations)
    preserved_after={str(path):identity(path.lstat()) for path in preserved_paths}
    report['preserved_generations_after']=preserved_after
    report['dmg_xattr_names_after']=run('/usr/bin/xattr',dmg).stdout.decode().splitlines()
    check('prepared_image_and_package_records_preserved',preserved_after==preserved_before)
    check('clean_exact_source_after',run('git','-C',REPO,'rev-parse','HEAD').stdout.decode().strip()==REV and not run('git','-C',REPO,'status','--porcelain=v1').stdout)
    stage_proof={'schema':'ukai.export-repair.signed-package-stage-equality/1','source_revision':REV,'dmg_sha256':report['dmg_sha256'],'package_sha256':args.package_sha256,'manifest_sha256':metadata['manifest_sha256'],'source_archive_sha256':image['source_archive_sha256'],'source_files':len(source_names),'six_signatures':True,'stage_path':str(STAGE),'inventory':stage_inventory,'stage_generations':stage_generations,'mounted_filesystem_metadata_names':sorted(extras),'retained_copies':copied,'prepared_input_generations':preserved_before,'scope':'Proof only; no stage deletion or installed/runtime/admission claim.'}
    report['stage_proof']=stage_proof
    completed = True
except Exception as error:
    report['error'] = {'type': type(error).__name__, 'message': str(error)}
finally:
    if attach_attempted:
        try:
            found=owned_attachments(dmg)
            if found:
                entities=found[0].get('system-entities',[])
                mounts={row['mount-point'] for row in entities if row.get('mount-point')}
                if mounts-{str(MOUNT)}:raise ValueError('unexpected exact image mount')
                devices=[row.get('dev-entry') for row in entities if row.get('content-hint')=='GUID_partition_scheme']
                if len(devices)!=1 or re.fullmatch(r'/dev/disk[0-9]+',devices[0]) is None:raise ValueError('ambiguous exact image device')
                run('hdiutil','detach',devices[0])
            report['facts']['owned_dmg_detached']=not owned_attachments(dmg) and not MOUNT.is_mount()
        except Exception as error:
            report['facts']['owned_dmg_detached'] = False
            report['detach_error_type'] = type(error).__name__
    report['completed'] = completed
    report['outcome'] = 'PASS' if completed and report['facts'] and all(v is True for v in report['facts'].values()) else 'FAIL'
    report['reviewer_sha256']=digest(Path(__file__))
    with (OUT/'verification.json').open('x') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report, indent=2))
if report['outcome'] != 'PASS':
    raise SystemExit(1)
