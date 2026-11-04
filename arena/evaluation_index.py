"""Validation and honest counting for arena/evaluation-index.json.

Read-only helper: it never edits original results, launches processes or
touches the network. A repeated copy of one run counts once; conflicting
records under one run ID are an error, not a merge.
"""
import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
INDEX = HERE / 'evaluation-index.json'
CLASSES = ('boundary_enforcement', 'workflow_containment', 'prompt_injection_behavior', 'exposure_contrast')


def load(path=None):
    return json.loads(Path(path or INDEX).read_text())


def validate(index):
    """Return an error list; empty means the index is internally consistent."""
    errors = []
    if index.get('schema') != 'arena.evaluation-index/1':
        errors.append('unknown index schema')
    runs = index.get('runs', [])
    if not runs:
        errors.append('empty index')
    by_id = {}
    for entry in runs:
        ident = entry.get('run_id')
        if not ident:
            errors.append('entry without run_id')
            continue
        if entry.get('experiment_class') not in CLASSES:
            errors.append('unknown experiment class: ' + ident)
        if entry.get('cohort', {}).get('agent') and entry.get('cohort', {}).get('scripted'):
            errors.append('cohort is both agent and scripted: ' + ident)
        # The score reference identifies the record; everything else must agree
        # across copies or the run ID is carrying conflicting records.
        identity = json.dumps({k: entry.get(k) for k in (
            'experiment_class', 'scenario_id', 'scenario_version', 'kind', 'phase',
            'started_at_utc', 'original_score', 'cohort', 'nested_observation')}, sort_keys=True)
        if ident in by_id:
            if by_id[ident] != identity:
                errors.append('conflicting records under run ID: ' + ident)
            continue
        by_id[ident] = identity
        if entry.get('experiment_class') == 'workflow_containment':
            if not entry.get('scenario_id') or not entry.get('original_score', {}).get('reference'):
                errors.append('workflow lacks scenario or original score reference: ' + ident)
    controls = {e['run_id'] for e in runs if e.get('cohort', {}).get('scripted')}
    batch_ids, used_controls = set(), set()
    batches = [b for b in index.get('batch_slots', [])
               if b.get('experiment_family') == 'arena.install-boundary']
    for batch in batches:
        ident = batch.get('batch_id')
        if not ident or ident in batch_ids:
            errors.append('missing or duplicate install batch ID')
        batch_ids.add(ident)
        slots = batch.get('slots', [])
        recorded = sum(s.get('model_session', 0) for s in slots)
        claimed = sum(s.get('state') != 'unclaimed' for s in slots)
        if (len(slots) != batch.get('scheduled') or recorded != batch.get('recorded')
                or recorded != batch.get('recorded_model_sessions')
                or claimed != batch.get('attempts_claimed')
                or len(slots) - claimed != batch.get('skipped')):
            errors.append('install batch slot counts disagree: ' + str(ident))
        ids = batch.get('control_run_ids', [])
        if len(ids) != 3 or len(set(ids)) != 3 or not set(ids) <= controls or used_controls.intersection(ids):
            errors.append('install controls missing, duplicated or reused: ' + str(ident))
        used_controls.update(ids)
    budget = index.get('budget_reconciliation')
    if batches and (not budget or
            sum(b.get('reservation_eur_minor', 0) for b in batches) != budget.get('install_holds_minor') or
            sum(b.get('released_eur_minor', 0) for b in batches) != budget.get('released_minor') or
            budget.get('previous_held_minor', 0) + budget.get('install_holds_minor', 0) != budget.get('total_held_minor')):
        errors.append('install reservations do not reconcile')
    november = [b for b in index.get('batch_slots', [])
                if b.get('experiment_family') in ('arena.twin-exposure', 'arena.s1ngularity-replay')]
    for batch in november:
        ident, slots = batch.get('batch_id'), batch.get('slots', [])
        if not ident or ident in batch_ids:
            errors.append('missing or duplicate comparison batch ID')
        batch_ids.add(ident)
        if (len(slots) != 3 or batch.get('scheduled') != 3
                or sum(s.get('model_session', 0) for s in slots) != batch.get('recorded')
                or batch.get('recorded') != batch.get('recorded_model_sessions')
                or sum(s.get('state') != 'unclaimed' for s in slots) != batch.get('attempts_claimed')
                or sum(s.get('state') == 'unclaimed' for s in slots) != batch.get('skipped')):
            errors.append('comparison slot counts disagree: ' + str(ident))
        ids = batch.get('control_run_ids', [])
        if len(ids) != 3 or len(set(ids)) != 3 or not set(ids) <= controls or used_controls.intersection(ids):
            errors.append('comparison controls missing, duplicated or reused: ' + str(ident))
        used_controls.update(ids)
    later_budget = index.get('november_budget_reconciliation')
    if november and (not later_budget
            or sum(b['reservation_eur_minor'] for b in november) != later_budget.get('new_holds_minor')
            or sum(b['released_eur_minor'] for b in november) != later_budget.get('released_minor')
            or budget['total_held_minor'] != later_budget.get('carried_unreconciled_minor')
            or later_budget['carried_unreconciled_minor'] + later_budget['new_holds_minor'] != later_budget.get('total_held_minor')):
        errors.append('November reservations do not reconcile')
    return errors


def summary(index):
    """Unique-sample counts. Replays, rescores and export copies are not samples."""
    runs = index.get('runs', [])
    seen, rows = set(), dict.fromkeys(CLASSES, 0)
    agent_attempts = nested_logs = nested_completed = 0
    for entry in runs:
        ident = entry.get('run_id')
        if ident in seen:
            continue
        seen.add(ident)
        rows[entry['experiment_class']] += 1
        if entry.get('cohort', {}).get('agent'):
            agent_attempts += 1
        nested_logs += entry.get('nested_observation', {}).get('log_captured') is True
        nested_completed += entry.get('nested_observation', {}).get('terminal_present') is True
    return {'unique_runs': len(seen), 'agent_attempts': agent_attempts,
            'scripted_controls': len(seen) - agent_attempts, 'by_class': rows,
            'corrections_attached': sum(1 for e in runs if e.get('corrections')),
            'nested_cli_logs': nested_logs, 'nested_completed_sessions': nested_completed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path)
    args = parser.parse_args()
    index = load(args.index)
    errors = validate(index)
    result = {'schema': 'arena.evaluation-index.check/1', 'errors': errors,
              'summary': summary(index) if not errors else None}
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if errors else 0)


if __name__ == '__main__':
    main()
