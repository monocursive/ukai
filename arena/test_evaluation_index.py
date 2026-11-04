"""Evaluation-index consistency: dedupe identical copies, refuse conflicts (P02)."""
from copy import deepcopy
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


if __name__ == '__main__':
    unittest.main()
