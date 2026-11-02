"""K105--K107: actual ES events and natural path/queue loss, no injected events."""
import json
from pathlib import Path
import sys

from macos_j16_spike_guest import Trial, command, guard, json_lines, save


def run(root, mode, evidence):
    t = Trial(root, 'j17-' + mode + '-' + evidence)
    try:
        t.launch([root/'src/spike-fixture', 'command', t.ws/'births.jsonl',
                  root/'src/j17-workload', mode], wall='45s', evidence=evidence)
        t.finish(timeout=65)
        r=t.result.get('receipt') or {}
        coverage=r.get('coverage',{})
        audit=[e for e in json_lines(t.result.get('trace','')) if e.get('source')=='audit']
        actions={e.get('fields',{}).get('action') for e in audit}
        t.result['actions_observed']=sorted(a for a in actions if a)
        t.result['summary']=t.invoke('tail','--attempt',r['attempt_id'],'--summary','--json')
        summary=t.dir/'summary.json'
        summary.write_text(t.result['summary']['stdout'])
        attempt=next(p.parent for p in (t.dir/'data').rglob('jail.json'))
        t.result['summary_check']=command(['/usr/bin/python3','-I',root/'src/summary_check.py',attempt,summary])
        checks={'tree_verified':r.get('lifetime',{}).get('tree_empty') is True,
                'independent_tree_empty':t.result['before_emergency_cleanup']['empty'] is True,
                'summary_agrees':t.result['summary_check']['exit']==0,
                'set':r.get('observer',{}).get('set')=='macos-closed-v1'}
        if mode=='mutations':
            checks.update(exit_zero=t.result['exit']==0,
                coverage_active=all(coverage.get(c,{}).get('status')=='active' for c in ('exec','fs.write')),
                expected_actions=all(a in actions for a in ('created','modified','renamed','hard_link_created','metadata_changed','unlinked','cloned')))
        else:
            checks.update(observation_degraded=all(coverage.get(c,{}).get('status')=='degraded' for c in ('exec','fs.write')),
                counts_null=all(coverage.get(c,{}).get('observed_count') is None for c in ('exec','fs.write')),
                custody_contiguous=all(r.get('lifetime',{}).get('native',{}).get('details',{}).get(c,{}).get('stream')=='contiguous' for c in ('supervisor','guardian')))
            if evidence=='strict':
                checks['strict_stopped']=r.get('outcome',{}).get('cause')=='evidence_loss'
            else:
                checks['best_effort_completed']=t.result['exit']==0
        t.result['checks']=checks
        t.result['outcome']='PASS' if all(checks.values()) else 'FAIL'
    finally:
        t.cleanup()
    return t.result


if __name__=='__main__':
    import resource
    guard()
    resource.setrlimit(resource.RLIMIT_NPROC, (2000, resource.getrlimit(resource.RLIMIT_NPROC)[1]))
    root=Path(sys.argv[1]).resolve()
    results=[]
    for mode,evidence in [('mutations','strict'),('longpath','best-effort'),('longpath','strict'),('flood','best-effort'),('flood','strict')]:
        results.append(run(root,mode,evidence))
        save(root/'results/j17-live.json',results)
        print(json.dumps({'name':results[-1]['name'],'outcome':results[-1]['outcome'],'checks':results[-1]['checks']}),flush=True)
