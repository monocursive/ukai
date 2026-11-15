#!/usr/bin/env python3
"""Judge the VM execution boundary from one boot's resource and tree probes.

This reads the raw attempts retained by capabilities.py, not its per-capability
PASS labels. It combines pids/memory enforcement with both descendant end paths,
requiring separate, bound attempts on the same guest and service boot. It does
not change the client's available-capability table or prove owner-loss bounds.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re

import capabilities
import harness

ATTEMPTS = ('pids', 'mem', 'tree_termination', 'tree_wall')
SHA256 = re.compile(r'[0-9a-f]{64}')


def utc_time(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        return False
    try:
        datetime.datetime.fromisoformat(value.removesuffix('Z') + '+00:00')
        return True
    except ValueError:
        return False


def judge(record):
    """Missing, contradictory or malformed evidence never earns a verdict."""
    facts = {'record_schema': record.get('schema') == 'ukai.vm.capabilities/2'}
    try:
        results = {name: record['results'][name] for name in ATTEMPTS}
        status, tag = record['status'], record['tag']
        facts.update(
            service_stopped_cleanly=type(record.get('service_exit')) is int and record['service_exit'] == 0,
            protected_sentinel_unchanged=record['summary'].get('git_config_untouched') is True,
            image_identified=bool(SHA256.fullmatch(status.get('disk_sha256', ''))),
            service_binary_identified=bool(SHA256.fullmatch(record['binary'].get('sha256', ''))),
            distinct_attempts=len({r.get('attempt_id') for r in results.values()}) == len(ATTEMPTS),
            distinct_guest_attempts=len({capabilities.receipt_of(r).get('attempt_id')
                                        for r in results.values()}) == len(ATTEMPTS),
            distinct_execution_cgroups=len({capabilities.lifetime_details(r)
                                            .get('execution_cgroup', {}).get('path')
                                            for r in results.values()}) == len(ATTEMPTS),
            same_guest_boot=len({harness.guest_boot(r) for r in results.values()}) == 1,
            same_service_boot=bool(status.get('boot_id')) and all(
                r.get('boot_id') == status['boot_id'] for r in results.values()),
        )
        for name, attempt in results.items():
            receipt = capabilities.receipt_of(attempt)
            lifetime = receipt.get('lifetime') or {}
            execution = capabilities.lifetime_details(attempt).get('execution_cgroup') or {}
            stop = attempt.get('guest_stop') or {}
            binding = attempt.get('binding') or {}
            guest_boot = (((receipt.get('process') or {}).get('identity') or {}).get('value') or {}).get('boot_id')
            checks = {
                'receipt_bound': harness.receipt_bound(attempt),
                'guest_receipt_identity_bound': bool(receipt.get('attempt_id'))
                    and binding.get('guest_attempt_id') == receipt['attempt_id']
                    and bool(guest_boot) and binding.get('guest_boot_id') == guest_boot,
                'linux_receipt': receipt.get('schema') == 'ukai.jail.receipt/1'
                    and (receipt.get('platform') or {}).get('os') == 'linux',
                'measurement_time': utc_time(attempt.get('started_at')),
                'settled_enforced': receipt.get('phase') == 'settled'
                    and receipt.get('containment') == 'enforced'
                    and receipt.get('child_protection') == 'enforced',
                'cleanup_complete_without_error': receipt.get('state_cleanup') == 'complete'
                    and receipt.get('cleanup_error') is None,
                'receipt_error_free': receipt.get('errors') == [],
                'execution_boundary_required': 'execution_boundary' in (
                    (receipt.get('policy') or {}).get('requirements') or []),
                'tree_empty_verified': lifetime.get('tree_empty') is True
                    and lifetime.get('integrity') == 'verified'
                    and lifetime.get('boundary') == 'pid_namespace'
                    and lifetime.get('verification_scope') == 'attempt_tree',
                'cgroup_under_walked_manager': capabilities.under_user_manager(execution.get('path')),
                'outside_stop_witness': capabilities.guest_stop_reported(stop)
                    and harness.stop_covered_the_attempt(stop)
                    and all(stop.get(key) == [] for key in
                            ('populated_before_kill', 'live_before_kill', 'strays_killed')),
            }
            facts.update({f'{name}:{key}': value for key, value in checks.items()})
        probes = {
            'pids': capabilities.judge_pids(results['pids'], tag),
            'mem': capabilities.judge_mem(results['mem'], tag),
            'tree_exit': capabilities.judge_tree(results['tree_termination'], tag, 'exit',
                                                 record['tree_watch']['tree_termination']),
            'tree_wall': capabilities.judge_tree(results['tree_wall'], tag, 'wall',
                                                 record['tree_watch']['tree_wall']),
        }
        for name, checks in probes.items():
            facts.update({f'probe:{name}:{key}': value is True for key, value in checks.items()})
    except (KeyError, TypeError, ValueError, AttributeError):
        facts['evidence_well_formed'] = False
    return facts, all(value is True for value in facts.values())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    raw = args.record.read_bytes()
    record = json.loads(raw)
    if not isinstance(record, dict):
        parser.error('capability record must be an object')
    facts, verdict = judge(record)
    results = record.get('results') or {}
    first = results.get(ATTEMPTS[0]) or {}
    report = {
        'schema': 'ukai.vm.execution-boundary-measurement/1',
        'source_record_sha256': hashlib.sha256(raw).hexdigest(),
        'binary': record.get('binary'), 'status': record.get('status'),
        'measurements': {'execution_boundary': {
            'verdict': verdict, 'measured_at': first.get('started_at'),
            'attempt_id': first.get('attempt_id'),
            'attempt_ids': [(results.get(name) or {}).get('attempt_id') for name in ATTEMPTS],
            'capability': 'execution_boundary',
            'not_measured': ['owner-loss termination', 'mid-run credential revocation'],
        }},
        'facts': facts, 'outcome': 'PASS' if verdict else 'FAIL',
        'scope': 'Derived guest boundary measurement; no client capability promotion or release qualification.',
    }
    out = harness.fresh_out_dir(args.out)
    harness.write_json(out / 'execution-boundary.json', report)
    print(json.dumps({'outcome': report['outcome'], 'failed': [k for k, v in facts.items() if v is not True]}))
    return 0 if verdict else 1


if __name__ == '__main__':
    raise SystemExit(main())
