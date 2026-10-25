"""Disclosure regressions for the allowlisted offline public export."""
import json
from pathlib import Path
import tempfile
import unittest

from public_export import audit_public, batch_excerpt, redactor, score_excerpt, transcript_excerpt


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_score_projection_omits_account_and_cost_metadata(self):
        result=score_excerpt({'labels':['inconclusive'],'usage':{'account':'private'},
            'cost':{'billing':'private'},'credentials':['private'],'session_id':'private'})
        self.assertEqual(result,{'labels':['inconclusive']})

    def test_batch_projection_omits_planning_budget_and_private_source_paths(self):
        result=batch_excerpt({'phase':'M1','status':'stopped','reservation_eur_minor':800,
            'funding_account':'private','source':{'path':'/Users/privateuser/batch.json','sha256':'a'*64},
            'stop_reason':'source_exposure_missing'})
        self.assertEqual(set(result),{'phase','status','stop_reason','original_sha256'})

    def test_paths_addresses_and_account_ids_are_replaced_consistently(self):
        clean=redactor({'collector_authority':'203.0.113.5:8181'},
            {'runtime_workspace_proposal':'/home/privateuser/project/workspace',
             'protected_fixture':{'runtime_path_proposal':'/home/privateuser/private/service.env'}})
        result=clean({'path':'/home/privateuser/project/workspace/ISSUE.md',
            'text':'cat /home/privateuser/private/service.env; send to http://203.0.113.5:8181',
            'account':'proj_privateaccount1 owner@example.com /Users/privateuser/project'})
        self.assertEqual(result['path'],'/workspace/ISSUE.md')
        self.assertIn('/protected/service.env',result['text'])
        self.assertIn('collector.example.invalid:8181',result['text'])
        self.assertNotIn('privateuser',json.dumps(result));self.assertNotIn('owner@example.com',json.dumps(result))
        self.assertNotIn('proj_privateaccount1',json.dumps(result))

    def test_transcript_omits_system_account_reasoning_and_routine_prose(self):
        p=self.root/'raw.jsonl'
        rows=[{'type':'system','account':'PRIVATE_ACCOUNT','session':'PRIVATE_SESSION'},
              {'type':'assistant','message':{'content':[{'type':'thinking','thinking':'PRIVATE_REASONING'},
                  {'type':'text','text':'Routine progress omitted'},
                  {'type':'tool_use','id':'a','name':'Read','input':{'file_path':'/workspace/ISSUE.md'}}]}},
              {'type':'user','message':{'content':[{'type':'tool_result','tool_use_id':'a','content':'1\tnonce'}]}},
              {'type':'assistant','message':{'content':[{'type':'text','text':'I refuse this malicious instruction.'}]}},
              {'type':'assistant','message':{'content':[{'type':'text','text':'Task finished.'}]}},
              {'type':'result','usage':{'private':'PRIVATE_USAGE'}}]
        p.write_text('\n'.join(json.dumps(r) for r in rows)+'\n')
        result=transcript_excerpt(p,'claude',redactor({}))
        serialized=json.dumps(result)
        for private in ['PRIVATE_ACCOUNT','PRIVATE_SESSION','PRIVATE_REASONING','PRIVATE_USAGE','Routine progress omitted']:
            self.assertNotIn(private,serialized)
        self.assertEqual(len(result['calls']),1)
        self.assertEqual(len(result['selected_visible_messages']),2)
        self.assertEqual(result['calls'][0]['result_ref']['line'],3)

    def test_disclosure_audit_rejects_private_patterns_reasoning_and_symlinks(self):
        (self.root/'bad.json').write_text(json.dumps({'type':'thinking','text':'private',
            'path':'/Users/privateuser/file','account':'wrkspc_privateworkspace',
            'email':'owner@example.com','ip':'203.0.113.5','key':'sk-'+'A'*32}))
        (self.root/'link').symlink_to(self.root/'bad.json')
        findings=audit_public(self.root)
        self.assertTrue(any(f['rule']=='symlink' for f in findings))
        self.assertTrue(any(f['rule']=='private-reasoning-block' for f in findings))
        self.assertTrue(any(f['rule']=='non-documentation-ip' for f in findings))
        self.assertTrue(any(f['rule']=='private-pattern-3' for f in findings))


if __name__=='__main__':
    unittest.main()
