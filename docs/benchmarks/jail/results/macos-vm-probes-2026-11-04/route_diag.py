"""Route-control diagnosis on one warm boot (2026-11-04 live phase).

On 2026-11-04 warm_live's route control failed twice (a client timeout, then
the guest proxy's 504 connect_timeout), each after 20 attempts on one boot,
while capabilities.py's control on a fresh boot reached the target. This run
asks whether the guest's egress depends on attempt count or idle time:
route controls at boot, after 20 tool attempts, and after 300 s idle, each
next to the host's own reachability of the same target, for two targets.

usage: route_diag.py VM_DIR HOME WORKSPACE OUT   (UKAI_VM_BINARY set)
"""
import json
import sys
import tempfile
import time
from pathlib import Path

vm = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(vm))
import harness  # noqa: E402

TARGETS = [('1.1.1.1', 443), ('8.8.8.8', 443)]
PROBE_TIMEOUT = 40.0


def text(value):
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return value or ''


def main():
    home, workspace, out = Path(sys.argv[2]).resolve(strict=True), sys.argv[3], sys.argv[4]
    binary = harness.required_binary('UKAI_VM_BINARY')
    workspace = harness.guarded_workspace(workspace)
    out = harness.fresh_out_dir(out)
    harness.clean_workspace(workspace)
    tag = harness.nonce()
    data = Path(tempfile.mkdtemp(prefix='route-diag-')) / 'data'
    data.mkdir(mode=0o700)
    events = []
    started = time.monotonic()

    def route(service, label):
        for host, port in TARGETS:
            reach = harness.host_reachability((host, port))
            name = f'route-{label}-{host.replace(".", "-")}-{tag}'
            probe = f'{tag}-{label}-{host}'
            t0 = time.monotonic()
            record = harness.run_attempt(service.connect, name,
                                         harness.route_argv(probe, (host, port), PROBE_TIMEOUT),
                                         profile='agent', wall=90,
                                         allow_hosts=[harness.route_rule((host, port))])
            events.append({'label': label, 'target': [host, port], 'attempt_id': name,
                           'since_boot_s': round(t0 - started, 1),
                           'attempt_s': round(time.monotonic() - t0, 2),
                           'host_reachability': reach,
                           'route': harness.route_verdict(record['stdout'], probe, (host, port)),
                           'probe_lines': [line for line in text(record.get('stdout')).splitlines()
                                           if line.startswith('UKAI_ROUTE_CONTROL')],
                           'exit_code': record.get('exit_code'), 'error': record.get('error'),
                           'receipt_bound': harness.receipt_bound(record),
                           'stderr_tail': text(record.get('stderr'))[-600:]})
            print(json.dumps(events[-1]['route']), label, host, flush=True)

    with harness.Service(binary, home, workspace, data, extra=('--guest-nat',)) as service:
        status = service.warm_status
        route(service, 'boot')
        for index in range(20):
            t0 = time.monotonic()
            record = harness.run_attempt(service.connect, f'tool-{index}-{tag}', harness.sh('true'), wall=30)
            events.append({'label': f'tool-{index}', 'since_boot_s': round(t0 - started, 1),
                           'attempt_s': round(time.monotonic() - t0, 2),
                           'exit_code': record.get('exit_code'), 'error': record.get('error')})
        route(service, 'after-20')
        time.sleep(300)
        route(service, 'idle-300')
        route(service, 'idle-300-again')
    (out / 'route-diagnosis.json').write_text(json.dumps(
        {'schema': 'ukai.vm.route-diagnosis/1', 'binary': harness.fingerprint(binary),
         'status': status, 'service_exit': service.child.returncode, 'events': events}, indent=1) + '\n')
    print('written', out / 'route-diagnosis.json')


if __name__ == '__main__':
    main()
