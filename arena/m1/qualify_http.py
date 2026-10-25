#!/usr/bin/env python3
"""Unpaid pinned-Codex HTTP/SSE probe through unchanged Ukai and an owned mock.

Only a synthetic credential and loopback endpoint are used. It cannot contact a
real provider. Plain HTTP is scoped to this mock profile, never the pilot profile.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import secrets
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from common import read, save, manifest, now
from m1 import runtime
from m1.adapters import normalize
from m1.scoring import UKAI_SHA256, cleanup, policy_check

MARKER = 'ARENA_OFFLINE_TRANSPORT_OK'


def qualify(config, out):
    if platform.system() != 'Linux':
        raise ValueError('the pinned Linux lane is required')
    runtime.pin(config['jail'], 'ukai', UKAI_SHA256)
    spec = dict(config['agents']['codex'], transport='http_sse')
    binary = runtime.pin(spec, 'codex')
    out = runtime.fresh_output(out)
    env = runtime.environment(out, str(Path(spec['path']).parent) + ':/usr/bin:/bin')
    work = out/'workspace';work.mkdir()
    key = 'SYNTHETIC-ARENA-HTTP-' + secrets.token_hex(24)
    source = out/'synthetic-credential';source.write_text(key);source.chmod(0o600)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_GET(self):
            requests.append({'method':'GET','path':self.path,'upgrade':self.headers.get('Upgrade')})
            self.send_error(405)

        def do_POST(self):
            size = int(self.headers.get('Content-Length','0'))
            if size < 0 or size > 4*1024*1024:
                self.send_error(413);return
            self.rfile.read(size)
            valid = self.headers.get('Authorization') == 'Bearer ' + key
            requests.append({'method':'POST','path':self.path,'upgrade':self.headers.get('Upgrade'),
                             'synthetic_vault_header_verified':valid,'body_bytes':size})
            if self.path != '/v1/responses' or not valid or len(requests) > 1:
                self.send_error(400);return
            msg={'id':'msg_mock','type':'message','role':'assistant','status':'completed',
                 'content':[{'type':'output_text','text':MARKER,'annotations':[]}]}
            response={'id':'resp_mock','object':'response','created_at':0,'status':'completed',
                'model':'gpt-6-astra','output':[msg],
                'usage':{'input_tokens':1,'output_tokens':1,'total_tokens':2,
                         'input_tokens_details':{'cached_tokens':0},'output_tokens_details':{'reasoning_tokens':0}}}
            events=[{'type':'response.created','response':dict(response,status='in_progress',output=[])},
                {'type':'response.output_item.added','output_index':0,'item':dict(msg,status='in_progress',content=[])},
                {'type':'response.content_part.added','item_id':'msg_mock','output_index':0,'content_index':0,
                 'part':{'type':'output_text','text':'','annotations':[]}},
                {'type':'response.output_text.delta','item_id':'msg_mock','output_index':0,'content_index':0,'delta':MARKER},
                {'type':'response.output_text.done','item_id':'msg_mock','output_index':0,'content_index':0,'text':MARKER},
                {'type':'response.content_part.done','item_id':'msg_mock','output_index':0,'content_index':0,'part':msg['content'][0]},
                {'type':'response.output_item.done','output_index':0,'item':msg},
                {'type':'response.completed','response':response}]
            data=''.join('event: '+e['type']+'\ndata: '+json.dumps(e)+'\n\n' for e in events).encode()
            self.send_response(200);self.send_header('Content-Type','text/event-stream')
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    authority = '127.0.0.1:' + str(server.server_port)
    summary={'started_at':now(),'status':'started','real_provider_requests':0,'real_credentials_read':False,
             'synthetic_response':True,'binary':binary,'jail_sha256':UKAI_SHA256,
             'limitation':'Mock HTTP/SSE selection and synthetic vault only; not live HTTPS, model access, or billing qualification.'}
    try:
        profile=runtime.auth_profile('codex',str(source))
        profile=profile.replace('https://api.openai.com','http://'+authority)
        profile=profile.replace('hosts = ["http://'+authority+'"]','hosts = ["http://'+authority+'"]\nallow_plaintext = true')
        profile=profile.replace('allow = ["api.openai.com"]','allow = ["'+authority+'"]')
        runtime.write_profile(out/'config/launch/codex.toml',profile)
        args=runtime.agent_configuration('codex',spec)['argv_template']
        args=[x.replace('{{WORKSPACE}}',str(work)).replace('{{TASK_PROMPT}}','Return the fixed mock marker; do not call tools.')
              .replace('https://api.openai.com/v1','http://'+authority+'/v1') for x in args]
        policy=runtime.policy_args(work,'agent_clean',agent='codex')
        policy[policy.index('wall=300s')]='wall=30s'
        probe=out/'probe';(probe/'raw').mkdir(parents=True)
        capture=runtime.m0.capture([config['jail']['path'],'run']+policy+['--receipt',str(probe/'raw/jail.json'),'--']+args,
                                  work,env,probe/'capture',45)
        runtime.archive_receipt(probe,env)
        receipt=read(probe/'raw/jail.json');applied=read(probe/'raw/policy.json')
        gaps=policy_check(receipt,applied,[authority],required_limits={'wall':'30000','pids':'128','mem':'1073741824'},credential_id='openai-api')
        t=normalize(probe/'capture/stdout','codex')
        summary.update(capture=capture,requests=requests,cleanup_verified=cleanup(receipt),policy_gaps=gaps,
                       transcript_gaps=t['gaps'],transport_warnings=t['transport_warnings'])
        if (capture['exit_code'] or capture['problems'] or gaps or not cleanup(receipt) or t['gaps'] or t['provider_failed']
                or len(requests)!=1 or requests[0]['method']!='POST' or requests[0]['upgrade']
                or not requests[0]['synthetic_vault_header_verified'] or not any(m['text']==MARKER for m in t['messages'])):
            raise RuntimeError('offline transport probe failed; retain evidence')
        summary['status']='passed'
    except Exception as exc:
        summary.update(status='failed',error_type=type(exc).__name__)
        raise
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)
        summary['ended_at']=now();save(out/'qualification.json',summary);manifest(out)
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();print(json.dumps(qualify(read(a.config),a.out),indent=2))
