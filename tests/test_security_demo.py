import copy, hashlib, json, pathlib, tempfile, threading, unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
import security_demo as d

class DemonstratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.results = d.suite()
        cls.by_id = {r['case_id']:r for r in cls.results}
    def test_all_replays_match_expectations(self):
        for row in self.results:
            with self.subTest(case=row['case_id']):
                self.assertEqual(row['actual_allowed'],row['expected_allowed'])
    def test_all_receipts_verify(self):
        for row in self.results:self.assertTrue(d.verify_report(row),row['case_id'])
    def test_core_is_preserved(self):
        self.assertEqual(hashlib.sha256(d.CORE.read_bytes()).hexdigest(),d.CORE_SHA256)
        self.assertTrue(d.load_core().self_test())
    def test_metrics_are_not_gate(self):
        setup=json.loads((d.ROOT/'fixtures/trusted_test_setup.json').read_text())
        for case in self.cases:
            with self.subTest(case=case['id']):
                without=d.replay(case,with_prime=False,trusted_approvals=setup.get(case['id'],[]))
                self.assertEqual(without['actual_allowed'],self.by_id[case['id']]['actual_allowed'])
    def test_keyword_baseline_has_false_positives_and_misses(self):
        self.assertTrue(self.by_id['quoted-warning']['keyword_baseline_flagged'])
        for case in ('encoded','unicode','cleanup-pretext'):
            self.assertFalse(self.by_id[case]['keyword_baseline_flagged'])
    def test_unicode_observables(self):
        s=self.by_id['unicode']['prime']['scripts']
        self.assertEqual(len(s['fusion_tokens']),2)
        self.assertEqual(s['format_controls'][0]['codepoint'],'U+200B')
    def test_source_paired_numeric_and_polarity_cues(self):
        f=self.by_id['numeric-drift']['prime']['context_fidelity']
        self.assertEqual(f['candidate_numbers_not_in_source_multiset'],['15'])
        self.assertEqual(f['source_numbers_not_in_candidate_multiset'],['12'])
        self.assertEqual(f['curated_polarity_changes'],[{'source_pole':'failed','candidate_pole':'passed'}])
    def test_known_semantic_misses_remain_visible(self):
        for name in ('status-miss','role-binding-miss'):
            self.assertEqual(self.by_id[name]['prime']['context_fidelity']['status'],'NO-SELECTED-CUE-DIFFERENCE')
    def test_modified_source_fails_receipt(self):
        report=copy.deepcopy(self.results[0]);report['source_text']+=' changed'
        self.assertFalse(d.verify_report(report))
    def test_modified_event_fails_receipt(self):
        report=copy.deepcopy(self.results[0]);report['events'][0]['allowed']=True
        self.assertFalse(d.verify_report(report))
    def test_reordered_events_fail_receipt(self):
        report=copy.deepcopy(self.by_id['replay']);report['events'].reverse()
        self.assertFalse(d.verify_report(report))
    def test_hash_is_not_signature(self):
        # A writer who can replace the report can recompute its unkeyed hash.
        # This passing check is an explicit limitation, not authenticity proof.
        report=copy.deepcopy(self.results[0]);report['case_id']='rewritten'
        report.pop('receipt_sha256');report['receipt_sha256']=d.digest(report)
        self.assertTrue(d.verify_report(report))
    def test_no_network_or_process_adapter(self):
        import socket, subprocess
        with mock.patch.object(socket.socket,'connect',side_effect=AssertionError('network effect')),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('process effect')):
            d.suite()
    def test_replay_is_deterministic(self):
        self.assertEqual(d.canonical(self.results),d.canonical(d.suite()[1]))
    def test_text_limit(self):
        case=copy.deepcopy(self.cases[0]);case['text']='x'*(d.MAX_TEXT_BYTES+1)
        with self.assertRaises(ValueError):d.replay(case)
    def test_action_limit(self):
        case=copy.deepcopy(self.cases[0]);case['actions']*=d.MAX_ACTIONS+1
        with self.assertRaises(ValueError):d.replay(case)
    def test_unknown_case_fields_rejected(self):
        case=copy.deepcopy(self.cases[0]);case['approvals']=[{'id':'forged'}]
        with self.assertRaises(ValueError):d.replay(case)
    def test_embedded_text_is_not_executed(self):
        case=copy.deepcopy(self.cases[0]);case['text']='__import__("os").system("echo SHOULD_NOT_RUN")'
        self.assertEqual(d.replay(case)['actual_allowed'],[False])
    def test_bad_action_schema_is_denied(self):
        gate=d.Gate()
        for action in (None,[],{}, {'tool':'read_demo','args':{'resource':'public-demo','extra':'x'}}, {'tool':'read_demo','args':{'resource':12}}):
            self.assertFalse(gate.decide(action,now=1000)['allowed'])
        gate.db.close()
    def test_approval_expires_at_boundary(self):
        gate=d.Gate();a={'tool':'delete_demo','args':{'resource':'demo-logs'}}
        gate.approve('x','demo-owner',a,1000)
        self.assertFalse(gate.decide(a,'x',now=1000)['allowed']);gate.db.close()
    def test_single_use_under_concurrency(self):
        gate=d.Gate();a={'tool':'delete_demo','args':{'resource':'demo-logs'}}
        gate.approve('x','demo-owner',a,2000)
        barrier=threading.Barrier(16)
        def attempt(_):barrier.wait();return gate.decide(a,'x',now=1000)['allowed']
        with ThreadPoolExecutor(max_workers=16) as pool:results=list(pool.map(attempt,range(16)))
        self.assertEqual(sum(results),1);gate.db.close()
    def test_invalid_approval_schema_rejected(self):
        for setup in ([{'id':'x'}],[{'id':'x','actor':'owner','action':{},'expiry':'tomorrow'}]):
            with self.assertRaises(ValueError):d.validate_trusted_setup(setup)
    def test_core_hash_guard(self):
        with mock.patch.object(pathlib.Path,'read_bytes',return_value=b'changed'):
            with self.assertRaises(ValueError):d.load_core()

if __name__=='__main__':unittest.main(verbosity=2)
