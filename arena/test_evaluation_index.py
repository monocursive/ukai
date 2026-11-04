"""Evaluation-index consistency: dedupe identical copies, refuse conflicts (P02)."""
from copy import deepcopy
import json
import unittest

import evaluation_index as index_module


class EvaluationIndexTests(unittest.TestCase):
    def setUp(self):
        self.index = index_module.load()

    def test_shipped_index_is_consistent(self):
        self.assertEqual(index_module.validate(self.index), [])
        summary = index_module.summary(self.index)
        # Previous 16 outer sessions + 3 twin + 2 replay. The replay's bare
        # slot was skipped; one nested startup log is not another completed session.
        self.assertEqual(summary['agent_attempts'], 21)
        self.assertEqual(summary['scripted_controls'], 81)
        self.assertEqual(summary['by_class']['workflow_containment'], 6)
        self.assertEqual(summary['by_class']['exposure_contrast'], 1)
        self.assertEqual(summary['nested_cli_logs'], 1)
        self.assertEqual(summary['nested_completed_sessions'], 0)

    def test_identical_copies_count_once(self):
        doubled = deepcopy(self.index)
        doubled['runs'] = doubled['runs'] + deepcopy(doubled['runs'])
        self.assertEqual(index_module.validate(doubled), [])
        self.assertEqual(index_module.summary(doubled)['unique_runs'],
                         index_module.summary(self.index)['unique_runs'])
        self.assertEqual(index_module.summary(doubled)['nested_cli_logs'], 1)

    def test_conflicting_records_under_one_id_fail(self):
        conflicting = deepcopy(self.index)
        copy = deepcopy(conflicting['runs'][0])
        copy['original_score'] = dict(copy['original_score'], labels=['forbidden_effect_confirmed'])
        conflicting['runs'].append(copy)
        errors = index_module.validate(conflicting)
        self.assertTrue(any('conflicting records' in e for e in errors))

    def test_unknown_class_is_an_error(self):
        broken = deepcopy(self.index)
        broken['runs'][0]['experiment_class'] = 'safety_score'
        self.assertTrue(index_module.validate(broken))

    def test_cohort_conflict_is_not_silently_deduplicated(self):
        row = deepcopy(self.index['runs'][0])
        row['cohort'] = {'agent': 'different-agent'}
        self.index['runs'].append(row)
        self.assertTrue(any('conflicting records' in e for e in index_module.validate(self.index)))

    def test_install_launch_accounting_cannot_hide_or_duplicate_a_hold(self):
        for mutation in ('remove_batch', 'duplicate_batch', 'change_slots', 'reuse_control'):
            with self.subTest(mutation=mutation):
                index = deepcopy(self.index)
                batches = [b for b in index['batch_slots'] if b.get('experiment_family') == 'arena.install-boundary']
                if mutation == 'remove_batch': index['batch_slots'].remove(batches[0])
                if mutation == 'duplicate_batch': index['batch_slots'].append(deepcopy(batches[0]))
                if mutation == 'change_slots': batches[0]['recorded'] = 2
                if mutation == 'reuse_control': batches[1]['control_run_ids'] = batches[0]['control_run_ids']
                self.assertTrue(index_module.validate(index))

    def test_workflow_needs_original_reference(self):
        row = next(r for r in self.index['runs'] if r['experiment_class'] == 'workflow_containment')
        del row['original_score']['reference']
        self.assertTrue(index_module.validate(self.index))

    def test_skipped_replay_slot_and_new_reservations_stay_visible(self):
        for mutation in ('hide_skipped', 'reuse_controls', 'drop_hold'):
            with self.subTest(mutation=mutation):
                value = deepcopy(self.index)
                batches = [b for b in value['batch_slots'] if b.get('experiment_family') in
                           ('arena.twin-exposure', 'arena.s1ngularity-replay')]
                if mutation == 'hide_skipped': batches[1]['skipped'] = 0
                if mutation == 'reuse_controls': batches[1]['control_run_ids'] = batches[0]['control_run_ids']
                if mutation == 'drop_hold': value['batch_slots'].remove(batches[1])
                self.assertTrue(index_module.validate(value))


class PublicationTests(unittest.TestCase):
    """Publication fields follow what the website serves (review 3 Nov, M4)."""

    def setUp(self):
        self.index = index_module.load()
        self.served = index_module.served_records()

    def entry(self, ident):
        return next(e for e in self.index['runs'] if e['run_id'] == ident)

    def test_every_served_record_reads_public_with_its_served_paths(self):
        self.assertEqual(index_module.publication_errors(self.index, self.served), [])
        # 4 pilot + 13 suite run 2 + 3 launch-4 controls + 2 workflows were served
        # under /arena/evidence/2026-10-26*/ while the index called them private.
        october = [i for i, urls in self.served.items() if any('/2026-10-26' in u for u in urls)]
        self.assertEqual(len(october), 22)
        for ident in october:
            entry = self.entry(ident)
            self.assertNotIn(entry['publication_status'], index_module.PRIVATE_STATUSES)
            self.assertEqual(entry['public_records'], self.served[ident])
        # Run 1 and the stopped launches' controls stay private and claim no page.
        private = [e for e in self.index['runs'] if e['publication_status'] in index_module.PRIVATE_STATUSES]
        self.assertEqual(len(private), 22)
        self.assertTrue(all(not index_module.claimed_records(e) for e in private))

    def test_served_record_marked_private_is_an_error(self):
        entry = self.entry('NET-A-4d26dd48790c0676')
        entry['publication_status'] = 'private_not_published'
        entry.pop('public_record'); entry.pop('public_records')
        errors = index_module.validate(self.index, self.served)
        self.assertIn('served publicly but marked private_not_published: NET-A-4d26dd48790c0676', errors)

    def test_missing_or_wrong_served_copy_is_an_error(self):
        entry = self.entry('8e1d27b3f57cfd22760a063f9bb206a8')  # served in both 26 October exports
        self.assertEqual(len(entry['public_records']), 2)
        for mutation in ('drop_copy', 'wrong_path'):
            with self.subTest(mutation=mutation):
                index = deepcopy(self.index)
                row = next(e for e in index['runs'] if e['run_id'] == entry['run_id'])
                if mutation == 'drop_copy':
                    row['public_records'] = row['public_records'][-1:]
                else:
                    row['public_record'] = row['public_record'].replace('2026-10-26-workflow-v2', '2026-11-01-reader')
                self.assertIn('public record paths disagree with the served copies: ' + entry['run_id'],
                              index_module.validate(index, self.served))

    def test_private_record_claiming_a_page_is_an_error(self):
        entry = self.entry('NET-A-f7f8feb63712c5e7')  # suite run 1, retained privately
        entry['public_record'] = '/arena/evidence/2026-10-26/runs/NET-A-f7f8feb63712c5e7/record.json'
        self.assertTrue(any('without a served record' in e for e in index_module.validate(self.index, self.served)))

    def test_as_of_cannot_predate_the_newest_record(self):
        self.index['as_of_utc'] = '2026-10-26T19:25:04.076685+00:00'
        self.assertIn('as_of_utc predates the newest indexed run', index_module.validate(self.index, self.served))

    def test_sync_regenerates_publication_fields_only_and_is_idempotent(self):
        stale = deepcopy(self.index)
        for entry in stale['runs']:
            if entry['run_id'] in ('NET-A-4d26dd48790c0676', 'ib-cbf614a9c8dc91938ddf8d5d9820ea'):
                entry['publication_status'] = 'not_published'
                entry.pop('public_record'); entry.pop('public_records')
                entry.setdefault('provenance', {})['public_record'] = None
        self.assertTrue(index_module.validate(stale, self.served))
        scores = [json.dumps(e.get('original_score'), sort_keys=True) for e in stale['runs']]
        changed = index_module.sync_publication(stale, self.served, as_of='2026-11-03T00:00:00+00:00')
        self.assertEqual(sorted(changed), ['NET-A-4d26dd48790c0676', 'ib-cbf614a9c8dc91938ddf8d5d9820ea'])
        self.assertEqual(index_module.validate(stale, self.served), [])
        self.assertEqual(scores, [json.dumps(e.get('original_score'), sort_keys=True) for e in stale['runs']])
        self.assertEqual(index_module.sync_publication(stale, self.served, as_of='2026-11-03T00:00:00+00:00'), [])


if __name__ == '__main__':
    unittest.main()
