#!/usr/bin/env python3
"""Check derivative hashes and the observations actually included here."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parent
def read(p):return json.loads(p.read_text())
errors=[]
for line in (ROOT/'SHA256SUMS').read_text().splitlines():
    expected,name=line.split('  ',1);p=ROOT/name
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:errors.append('hash: '+name)
results=read(ROOT/'results.json');records={}
for entry in results['runs']:
    p=ROOT/entry['record'];r=read(p);records[r['run_id']]=r
    trace=read(p.with_name('trace-excerpt.json'))['proxy_results_for_collector']
    collector=read(p.with_name('collector-excerpt.json'))['rows']
    if r.get('canary_received') is not None and bool(any(c.get('canary_match') is True for c in collector))!=r['canary_received']:errors.append('collector: '+r['run_id'])
    if r.get('policy_denials') is not None and sum(t.get('decision')=='deny' for t in trace)!=r['policy_denials']:errors.append('denials: '+r['run_id'])
    if r['group']=='agent_workflow':
        if r['utility']['status']=='pass' and (r['task'].get('status')!='pass' or r['task'].get('cases_passed')!=5):errors.append('task: '+r['run_id'])
        if r.get('hook_execution_verified','missing') is not None or r.get('proxy_actor')!='unknown' or r.get('tool_to_proxy_process_link_verified') is not False:errors.append('attribution: '+r['run_id'])
        calls=read(p.with_name('install-excerpt.json'))['calls'];pairs=r['operation']['matched_install_results']
        if len(calls)!=len(pairs) or any(c['request_ref']!=pair['request'] or c['result_ref']!=pair['result'] or c['success']!=pair['reported_success'] for c,pair in zip(calls,pairs)):errors.append('install: '+r['run_id'])
for ref in results['pairs']:
    pair=read(ROOT/ref['path']);left=records[pair['left']['run_id']];right=records[pair['right']['run_id']]
    if pair['terminal']=='contrast_pair_complete':
        if (left['canary_received'] is not True or right['canary_received'] is not False or right['enforcement']['status']!='explicit_deny' or left['utility']['status']!='pass' or right['utility']['status']!='pass' or pair['shared']['structural_difference']['no_other_meaningful_difference'] is not True):errors.append('pair: '+ref['phase'])
print(json.dumps({'errors':errors,'public_records_checked':len(records),'scope':'Derivative integrity and included observations only; not private-source rescoring or authenticity.'},indent=2))
raise SystemExit(1 if errors else 0)
