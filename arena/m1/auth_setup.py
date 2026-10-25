#!/usr/bin/env python3
"""Real API credential setup checks, with no inference or paid-test entrypoint."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import arena as m0
from common import now, manifest, read, regular_bytes, save, sha
from m1.adapters import jsonl
from m1.runtime import (agent_configuration, archive_receipt, auth_policy_check, auth_profile,
                        auth_route, credential_metadata, environment, fresh_output, pin,
                        policy_args, write_profile)
from m1.scoring import UKAI_SHA256, cleanup, policy_check

MODELS = {'claude': 'claude-sonnet-4-5-20250929', 'codex': 'gpt-6-astra'}


def install_on_worker(agent, source):
    """One selected key, SSH stdin only, new private file on the known owned worker."""
    if agent not in MODELS:
        raise ValueError('unknown credential route')
    key=secret_bytes(source)
    destination='/home/ubuntu/.config/ukai/credentials/arena-m1-' + agent + '-api-' + secrets.token_hex(8)
    script='''import os,pathlib,sys,json,stat
p=pathlib.Path(DESTINATION)
assert all(not q.is_symlink() for q in p.parents)
assert p.parent.is_dir() and p.parent.stat().st_uid==os.getuid()
data=sys.stdin.buffer.read(16385)
assert 20<=len(data)<=8192 and all(33<=b<=126 for b in data)
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
print(json.dumps({'installed':True,'path':str(p),'mode':oct(stat.S_IMODE(p.stat().st_mode)),'existing_credentials_overwritten':False}))
'''.replace('DESTINATION',repr(destination))
    result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','ouroboros-vps',
                           'python3 -c '+shlex.quote(script)],input=key,capture_output=True,timeout=30)
    if result.returncode:
        raise ValueError('credential installation failed; remote error body suppressed')
    record=json.loads(result.stdout)
    if record.get('path')!=destination or record.get('mode')!='0o600' or record.get('installed') is not True:
        raise ValueError('invalid installation receipt')
    if key.decode() in json.dumps(record):
        raise ValueError('credential material in installation receipt; do not export')
    return record


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def secret_bytes(source, grants=()):
    if credential_metadata(str(source), grants)['status'] != 'private_file_present':
        raise ValueError('private credential file is missing')
    data = regular_bytes(source, 16384).strip()
    if not 20 <= len(data) <= 8192 or any(c < 33 or c > 126 for c in data):
        raise ValueError('credential is not a bounded single-line ASCII token')
    return data


def metadata_request(agent, key):
    if agent not in MODELS:
        raise ValueError('unknown metadata route')
    model = MODELS[agent]
    host = 'api.anthropic.com' if agent == 'claude' else 'api.openai.com'
    headers = {'Accept':'application/json', 'User-Agent':'Ukai-Arena-M1-auth-metadata/1'}
    if agent == 'claude':
        headers.update({'x-api-key':key.decode('ascii'), 'anthropic-version':'2023-06-01'})
    else:
        headers['Authorization'] = 'Bearer ' + key.decode('ascii')
    # Fixed official endpoint, GET only, no body, no prompt, no fallback model.
    return urllib.request.Request('https://' + host + '/v1/models/' + model, headers=headers, method='GET')


def metadata_probe(agent, source):
    key = secret_bytes(source)
    request = metadata_request(agent, key)
    result = {'schema':'arena.m1.real-auth-metadata/1', 'agent':agent, 'started_at':now(),
              'method':'GET', 'url':request.full_url, 'requested_model':MODELS[agent],
              'inference_requests':0, 'metadata_request_attempts':1, 'redirects_followed':False,
              'credential_content_logged':False, 'credential_digest_retained':False,
              'generation_access':'not_tested', 'grant_credit_attribution':None,
              'provider_bill_cap_verified':False, 'provider_acceptance':'unverified'}
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects(),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with client.open(request, timeout=20) as response:
            result['http_status'] = response.status
            data = response.read(256 * 1024 + 1)
            if len(data) > 256 * 1024:
                raise ValueError('metadata response exceeds bound')
            value = json.loads(data)
            if not isinstance(value, dict) or value.get('id') != MODELS[agent]:
                result['status'] = 'model_identifier_mismatch'
            elif value.get('object', value.get('type')) != 'model':
                result['status'] = 'unexpected_metadata_shape'
            else:
                result.update(status='authenticated_model_metadata', provider_acceptance='accepted_for_metadata',
                              returned_model_id=value['id'])
                # Only lifecycle dates/status are retained, never an arbitrary provider body.
                for name in ('shutdown_date', 'deprecated_at', 'retires_at', 'lifecycle'):
                    v = value.get(name)
                    if isinstance(v, str) and len(v) < 64 and re.fullmatch(r'[a-zA-Z0-9:.+TZ_-]+', v):
                        result[name] = v
    except urllib.error.HTTPError as exc:
        result.update(status='metadata_http_error', http_status=exc.code)
        exc.close()  # Error bodies can contain sensitive data; deliberately do not read them.
    except (urllib.error.URLError, ValueError, OSError) as exc:
        result.update(status='metadata_unavailable', error_type=type(exc).__name__)
    result['ended_at'] = now()
    if key.decode() in json.dumps(result):
        raise ValueError('refusing to emit credential-bearing metadata')
    return result


def real_vault_probe(config, out, agent):
    """Execute only pinned CLI --version using a real host-vault source, no provider call."""
    spec = config['agents'][agent]
    route = spec.get('authentication_route')
    known = agent_configuration(agent, spec)
    jail = pin(config['jail'], 'ukai', UKAI_SHA256)
    binary = pin(spec, agent, known.get('linux_binary_sha256'))
    if Path(binary['path']).name != agent:
        raise ValueError('agent entrypoint name mismatch')
    source = spec.get('credential_source')
    # A real key never becomes an artifact; the source stays outside every grant/output.
    key = secret_bytes(source, ['/usr','/bin','/lib','/lib64',str(out),str(Path(binary['resolved']).parent)])
    m0.validate_neutral_output(out)
    out = fresh_output(out)
    env = environment(out, str(Path(binary['path']).parent) + ':/usr/bin:/bin')
    work = out / 'workspace'; work.mkdir()
    write_profile(out / 'config/launch' / (agent + '.toml'), auth_profile(agent, source, route=route))
    args = policy_args(work, 'agent_clean', agent=agent)
    result = {'schema':'arena.m1.real-vault/1','agent':agent,'authentication_route':auth_route(agent,route)['route'],
              'started_at':now(),'model_sessions':0,'provider_requests':None,'inference_requests':0,
              'provider_acceptance':'not_tested_by_version_probe','credential_content_logged':False,
              'binary':binary, 'jail_sha256':jail['sha256'], 'status':'started'}
    try:
        cap = m0.capture([jail['path'],'explain'] + args + ['--json'], work, env, out / 'explain', 30)
        if cap['exit_code'] or cap['problems'] or auth_policy_check(read(out/'explain/stdout'),agent,binary['resolved'],source,route):
            raise ValueError('real-credential profile resolution failed')
        root = out / 'version-probe'; (root/'raw').mkdir(parents=True)
        cap = m0.capture([jail['path'],'run'] + args + ['--receipt',str(root/'raw/jail.json'),'--','--version'],work,env,root/'capture',60)
        archive_receipt(root,env)
        receipt = read(root/'raw/jail.json'); policy = read(root/'raw/policy.json')
        rows,gaps,_ = jsonl(root/'raw/trace.ndjson')
        result['provider_requests'] = len([e for _,e in rows if e.get('source')=='proxy'])
        errors = auth_policy_check(policy,agent,binary['resolved'],source,route)
        errors += policy_check(receipt,policy,known['allowed_hosts_proposal'],credential_id=auth_route(agent,route)['id'])
        if cap['exit_code'] or cap['problems'] or gaps or errors or not cleanup(receipt) or result['provider_requests']:
            raise ValueError('real-vault isolation/version probe failed')
        version = (root/'capture/stdout').read_text().strip()
        if known['version'] not in version:
            raise ValueError('CLI version mismatch')
        result.update(status='real_vault_loaded_version_verified',version_output=version,
                      cleanup_verified=True,credential_never_staged=True,attempt_id=receipt['attempt_id'])
    except (OSError,ValueError,KeyError) as exc:
        result.update(status='probe_failed',error_type=type(exc).__name__)
    finally:
        # Scan in memory before any archive is exported. Do not persist the real key or its hash.
        exposed = [p for p in out.rglob('*') if p.is_file() and key in p.read_bytes()]
        if exposed:
            raise RuntimeError('Credential exposure detected; evidence quarantined on this host; do not export')
        result.update(ended_at=now(),credential_scan='no_key_bytes_in_evidence')
        save(out/'authentication.json',result)
        manifest(out)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('metadata','vault','install'))
    parser.add_argument('--agent',choices=tuple(MODELS),required=True)
    parser.add_argument('--source',type=Path)
    parser.add_argument('--config',type=Path)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    if args.action in ('metadata','install'):
        if not args.source: parser.error('--source is required')
        # Refuse reuse before making even a metadata request.
        out = fresh_output(args.out)
        result = metadata_probe(args.agent,args.source) if args.action=='metadata' else install_on_worker(args.agent,args.source)
        save(out/'authentication.json',result); manifest(out)
    else:
        if not args.config: parser.error('--config is required')
        result = real_vault_probe(read(args.config),args.out,args.agent)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
