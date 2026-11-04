"""Validation and honest counting for arena/evaluation-index.json.

It never edits original results, launches processes or touches the network. A
repeated copy of one run counts once; conflicting records under one run ID are
an error, not a merge. Publication fields must match what the website serves:
`--sync-public --write` regenerates them (and `as_of_utc`) from the public
exports under website/public/arena/evidence/; nothing else is rewritten.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
INDEX = HERE / 'evaluation-index.json'
EVIDENCE = HERE.parent / 'website' / 'public' / 'arena' / 'evidence'
CLASSES = ('boundary_enforcement', 'workflow_containment', 'prompt_injection_behavior', 'exposure_contrast')
PRIVATE_STATUSES = ('private_not_published', 'not_published')


def served_records(evidence=EVIDENCE):
    """Run ID -> URL paths of every served copy of its record, oldest export first."""
    evidence, served = Path(evidence), {}
    for results in sorted(evidence.glob('*/results.json')):
        for run in json.loads(results.read_text()).get('runs', []):
            record = results.parent / run['record']
            if record.is_file():
                url = '/' + record.relative_to(evidence.parent.parent).as_posix()
                served.setdefault(run['run_id'], []).append(url)
    return served


def claimed_records(entry):
    """Every public record path an entry names, as a served URL path."""
    values = [entry.get('provenance', {}).get('public_record'), entry.get('public_record'),
              *entry.get('public_records', [])]
    return {'/' + v.removeprefix('website/public').lstrip('/') for v in values if isinstance(v, str)}


def publication_errors(index, served):
    """A served record never reads as private, and a private one never claims a page."""
    errors, seen = [], set()
    for entry in index.get('runs', []):
        ident = entry.get('run_id')
        if not ident or ident in seen:
            continue
        seen.add(ident)
        urls, claimed = set(served.get(ident, [])), claimed_records(entry)
        status = entry.get('publication_status')
        if urls and status in PRIVATE_STATUSES:
            errors.append('served publicly but marked ' + str(status) + ': ' + ident)
        if urls and claimed != urls:
            errors.append('public record paths disagree with the served copies: ' + ident)
        if not urls and (claimed or status not in PRIVATE_STATUSES):
            errors.append('claims publication without a served record: ' + ident)
    starts = [e['started_at_utc'] for e in index.get('runs', []) if e.get('started_at_utc')]
    try:
        as_of = datetime.fromisoformat(str(index.get('as_of_utc')))
        if starts and as_of < max(datetime.fromisoformat(v) for v in starts):
            errors.append('as_of_utc predates the newest indexed run')
    except ValueError:
        errors.append('as_of_utc missing or not ISO 8601')
    return errors


def sync_publication(index, served, as_of=None):
    """Regenerate publication fields from the served exports; returns the changed run IDs.

    Only `publication_status` (private -> public_derivative), `public_record`
    (the newest served copy), `public_records` (every copy) and a null
    `provenance.public_record` placeholder are touched; scores, provenance and
    limits stay as recorded. `as_of_utc` becomes `as_of` (default: now).
    """
    changed = []
    for entry in index['runs']:
        urls = served.get(entry.get('run_id'))
        if not urls:
            continue
        before = json.dumps(entry, sort_keys=True)
        if entry.get('publication_status') in PRIVATE_STATUSES:
            entry['publication_status'] = 'public_derivative'
        provenance = entry.get('provenance', {})
        if 'public_record' in provenance and provenance['public_record'] is None:
            del provenance['public_record']
        entry['public_record'] = urls[-1]
        entry['public_records'] = list(urls)
        if json.dumps(entry, sort_keys=True) != before:
            changed.append(entry['run_id'])
    index['as_of_utc'] = as_of or datetime.now(timezone.utc).isoformat()
    return changed


def load(path=None):
    return json.loads(Path(path or INDEX).read_text())


def validate(index, served=None):
    """Return an error list; empty means the index is internally consistent."""
    errors = publication_errors(index, served_records() if served is None else served)
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
    parser.add_argument('--evidence', type=Path, default=EVIDENCE)
    parser.add_argument('--sync-public', action='store_true',
                        help='regenerate publication fields and as_of_utc from the served exports')
    parser.add_argument('--write', action='store_true', help='with --sync-public, rewrite the index file')
    args = parser.parse_args()
    path = Path(args.index or INDEX)
    index = load(path)
    served = served_records(args.evidence)
    if args.sync_public:
        changed = sync_publication(index, served)
        if args.write:
            path.write_text(json.dumps(index, indent=2, ensure_ascii=False) + '\n')
        print(json.dumps({'schema': 'arena.evaluation-index.sync/1', 'changed_runs': changed,
                          'written': bool(args.write), 'as_of_utc': index['as_of_utc']}, indent=2))
    errors = validate(index, served)
    result = {'schema': 'arena.evaluation-index.check/1', 'errors': errors,
              'summary': summary(index) if not errors else None}
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if errors else 0)


if __name__ == '__main__':
    main()
