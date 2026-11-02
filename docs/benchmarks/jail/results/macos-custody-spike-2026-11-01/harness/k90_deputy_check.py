"""Disambiguate launchctl status from execution, using fresh idle jobs."""
import json
import os
from pathlib import Path
import plistlib
import shlex
import time

from macos_j16_spike_guest import Trial, command, guard, save


def check(root, who, operation):
    t = Trial(root, 'deputy-v2-' + operation + '-' + who)
    labels = []
    result = t.result
    try:
        t.launch([root/'src/spike-fixture', 'command', t.ws/'births.jsonl',
                  '/bin/sh', '-c', 'echo \'{"ready":true}\'; while [ ! -f request.sh ]; do /bin/sleep 0.02; done; /bin/sh request.sh; echo $? > inside.rc; while [ ! -f finish ]; do /bin/sleep 0.02; done'], wall='40s')
        assert t.ready(), 'fixture must start'
        pid = t.proc.pid if who == 'supervisor' else t.guardian
        result['target_pid'] = pid
        for side in ('inside', 'outside'):
            label = f'com.ukai.validation.{operation}.{who}.{side}.{os.getpid()}'
            target = f'gui/{os.getuid()}/{label}'
            labels.append(target)
            marker = t.ws / (side + '.marker')
            plist = t.ws / (side + '.plist')
            plist.write_bytes(plistlib.dumps({'Label': label, 'RunAtLoad': operation == 'load',
                'ProgramArguments': [str(root/'src/live-attack'), 'deputy_cont', str(pid), str(marker)]}))
            entry = {}
            if operation == 'kickstart':
                entry['setup'] = command(['/bin/launchctl', 'bootstrap', f'gui/{os.getuid()}', plist])
                assert entry['setup']['exit'] == 0
                time.sleep(.3)
                entry['idle_before_request'] = command(['/bin/launchctl', 'print', target])
            entry['marker_before_request'] = marker.read_text() if marker.exists() else None
            assert not marker.exists(), 'setup must not execute the job'
            argv = ['/bin/launchctl', operation, target if operation == 'kickstart' else str(plist)]
            if side == 'inside':
                (t.ws/'request.tmp').write_text(shlex.join(argv) + '\n')
                (t.ws/'request.tmp').rename(t.ws/'request.sh')
                until = time.monotonic() + 5
                while not (t.ws/'inside.rc').exists() and time.monotonic() < until:
                    time.sleep(.02)
                entry['exit'] = int((t.ws/'inside.rc').read_text()) if (t.ws/'inside.rc').exists() else None
            else:
                entry['command'] = command(argv, timeout=5)
            until = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < until:
                time.sleep(.02)
            entry['execution_marker'] = marker.read_text() if marker.exists() else None
            entry['job_after_request'] = command(['/bin/launchctl', 'print', target])
            result[side] = entry
        (t.ws/'finish').touch()
        t.finish()
        result['positive_control_reached_target'] = ' rc=0 errno=0' in (result['outside']['execution_marker'] or '')
        result['outcome'] = ('FAIL' if result['inside']['execution_marker'] or result['outcome'] != 'PASS' else
                             'PASS' if result['positive_control_reached_target'] else 'BLOCKED')
    finally:
        for target in labels:
            command(['/bin/launchctl', 'bootout', target])
        t.cleanup()
    return result


if __name__ == '__main__':
    import sys
    import resource
    guard()
    resource.setrlimit(resource.RLIMIT_NPROC, (2000, resource.getrlimit(resource.RLIMIT_NPROC)[1]))
    root = Path(sys.argv[1]).resolve()
    results = []
    for op in ('kickstart', 'load'):
        for who in ('supervisor', 'guardian'):
            results.append(check(root, who, op))
            save(root/'results/k90-deputy-check.json', results)
            print(json.dumps({'name':results[-1]['name'], 'outcome':results[-1]['outcome']}), flush=True)
