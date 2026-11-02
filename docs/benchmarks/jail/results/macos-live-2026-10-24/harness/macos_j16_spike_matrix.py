"""Live K90 matrix in the disposable VM; all jobs/apps/sockets are ours."""
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import signal
import socket
import subprocess
import threading
import time

from macos_j16_spike_guest import Trial, command, snapshot


def matrix(root, target_name):
    t = Trial(root, 'k90-' + target_name)
    probe = root / 'src/live-attack'
    base = root / 'src/defense-probe'
    results = []
    jobs = []
    sockets = []
    try:
        script = '''echo '{"ready":true}'; i=0
while [ ! -f matrix-finish ]; do
  if [ -f "cmd-$i.sh" ]; then
    /bin/bash "cmd-$i.sh" > "out-$i" 2> "err-$i"
    echo $? > "rc-$i"; i=$((i+1))
  else /bin/sleep 0.01; fi
done'''
        t.launch([root/'src/spike-fixture', 'command', t.ws/'births.jsonl', '/bin/bash', '-c', script], wall='240s')
        if not t.ready():
            t.finish(); t.result['outcome'] = 'BLOCKED'
            return t.result
        pid = t.proc.pid if target_name == 'supervisor' else t.guardian
        birth = t.custodian_births[pid]
        t.result['target'] = {'custodian': target_name, 'pid': pid, 'birth': birth}
        counter = 0
        def pair(name, inside, outside=None, category='direct', timeout=8, setup=None, marker=None):
            nonlocal counter
            n = counter; counter += 1
            payload = shlex.join(list(map(str, inside))) + '\n'
            tmp = t.ws/f'cmd-{n}.tmp'; tmp.write_text(payload); tmp.rename(t.ws/f'cmd-{n}.sh')
            start = time.monotonic()
            while not (t.ws/f'rc-{n}').exists() and time.monotonic()-start < timeout and t.proc.poll() is None:
                time.sleep(.02)
            rc = t.ws/f'rc-{n}'
            inside_result = {'argv': list(map(str, inside)), 'elapsed_ms': (time.monotonic()-start)*1000,
                             'exit': int(rc.read_text()) if rc.exists() else None,
                             'stdout': (t.ws/f'out-{n}').read_text(errors='replace') if (t.ws/f'out-{n}').exists() else '',
                             'stderr': (t.ws/f'err-{n}').read_text(errors='replace') if (t.ws/f'err-{n}').exists() else ''}
            time.sleep(.1)
            inside_marker = marker.read_text() if marker and marker.exists() else None
            target_after_inside = snapshot(t.fixture, birth)
            outside_result = command(outside or inside, timeout=timeout, cwd=t.ws)
            row = {'name': name, 'category': category, 'target_custodian': target_name,
                   'inside': inside_result, 'outside': outside_result,
                   'marker_before_outside_control': inside_marker,
                   'target_after_inside': target_after_inside,
                   'denied_inside': inside_result['exit'] not in (None,0),
                   'outside_succeeded': outside_result.get('exit') == 0}
            if setup is not None: row['setup'] = setup
            # System-denied controls do not establish the sandbox's contribution.
            row['outcome'] = 'PASS' if row['denied_inside'] and row['outside_succeeded'] else 'BLOCKED' if row['denied_inside'] else 'FAIL'
            if category == 'direct' and name != 'sigqueue availability':
                row['inside_probe_ran'] = any(field in inside_result['stdout'] for field in ('ret=', 'kr='))
                if not row['inside_probe_ran']:
                    row['outcome'] = 'BLOCKED'
            results.append(row)
            if not rc.exists():
                raise RuntimeError('inside matrix command did not finish: ' + name)
            return row
        for mode in ('kill','killpg','audit_signal','pid_suspend','pid_resume','ptrace','task_for_pid','task_name_for_pid','memorystatus','setpriority','rlimit_control'):
            argv = [probe, mode, pid]
            if mode == 'audit_signal': argv.append(birth['pidversion'])
            pair(mode, argv)
        row = pair('kill(-1,0) permission probe', [probe,'kill_minus1',pid])
        row['outcome'] = 'BLOCKED'
        row['limitation'] = 'Signal 0 can succeed for another member; it does not prove delivery to either custodian.'
        row = pair('sigqueue availability', [probe,'sigqueue',pid])
        if row['inside']['exit']==77 and row['outside'].get('exit')==77:
            row['outcome']='PASS'; row['limitation']='Route unavailable on both sides; no sigqueue symbol.'
        pair('Mach lookup: com.apple.system.logger', [base,'bootstrap','com.apple.system.logger'],category='deputy')
        def listener(family, address):
            server = socket.socket(family, socket.SOCK_STREAM); server.bind(address); server.listen(8); server.settimeout(.2)
            sockets.append(server)
            calls=[]
            def accept():
                while server.fileno()>=0:
                    try:
                        conn,_=server.accept(); os.kill(pid,0); calls.append({'target':pid,'at':time.monotonic()}); conn.close()
                    except socket.timeout: continue
                    except OSError: break
            threading.Thread(target=accept,daemon=True).start()
            return server,calls
        sockpath=root/(target_name+'.sock')
        server,calls=listener(socket.AF_UNIX,str(sockpath))
        row=pair('Unix socket deputy', [base,'unix_connect',sockpath],category='deputy'); row['deputy_target_checks']=calls
        server,calls=listener(socket.AF_INET,('127.0.0.1',0))
        row=pair('loopback TCP deputy', [base,'tcp_connect','127.0.0.1',server.getsockname()[1]],category='deputy'); row['deputy_target_checks']=calls
        domain=f'gui/{os.getuid()}'
        # Each launchd operation uses a distinct test-owned label. Its command
        # queries this live custodian and records execution in a private marker.
        for operation in ('submit','bootstrap','kickstart','kill','bootout','load'):
            label=f'com.ukai.spike.{target_name}.{operation}.{os.getpid()}'
            target=domain+'/'+label; jobs.append(target)
            marker=t.ws/(operation+'.marker'); plist=t.ws/(operation+'.plist')
            program=[str(probe),'deputy',str(pid),str(marker)]
            if operation in ('kill','bootout'):
                program=['/bin/sleep','180']
            plist.write_bytes(plistlib.dumps({'Label':label,'ProgramArguments':program,'RunAtLoad':operation in ('bootstrap','load','kill','bootout')}))
            setup=None
            if operation in ('kickstart','kill','bootout'):
                setup=command(['/bin/launchctl','bootstrap',domain,plist])
            args={'submit':['submit','-l',label,'--',*program], 'bootstrap':['bootstrap',domain,plist],
                  'kickstart':['kickstart',target], 'kill':['kill','SIGCONT',target],
                  'bootout':['bootout',target], 'load':['load',plist]}[operation]
            row=pair('launchctl '+operation,['/bin/launchctl',*args],category='deputy',setup=setup,marker=marker)
            until=time.monotonic()+1
            while operation not in ('kill','bootout') and not marker.exists() and time.monotonic()<until:
                time.sleep(.02)
            row['execution_marker']=marker.read_text() if marker.exists() else None
            row['job_probe']=command(['/bin/launchctl','print',target])
            if setup and setup.get('exit')!=0: row['outcome']='BLOCKED'
            if operation not in ('kill','bootout') and row['outside_succeeded'] and not marker.exists():
                row['outcome']='BLOCKED'
            row['cleanup']=command(['/bin/launchctl','bootout',target])
        app=t.ws/'Deputy.app'; binary=app/'Contents/MacOS/deputy'; binary.parent.mkdir(parents=True)
        shutil.copy2(probe,binary)
        marker=t.ws/'launchservices.marker'
        (binary.parent/'target.txt').write_text(f'{pid} {marker}\n')
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':f'com.ukai.spike.deputy.{target_name}',
            'CFBundleName':'UkaiSpikeDeputy','CFBundleExecutable':'deputy','CFBundlePackageType':'APPL','CFBundleVersion':'1','LSUIElement':True}))
        for name,argv in [('LaunchServices open',['/usr/bin/open','-n',app]),('LaunchServices LSOpenCFURLRef',[probe,'lsopen',app])]:
            if marker.exists(): marker.unlink()
            row=pair(name,argv,category='deputy',marker=marker)
            until=time.monotonic()+2
            while not marker.exists() and time.monotonic()<until: time.sleep(.02)
            row['execution_marker']=marker.read_text() if marker.exists() else None
            if row['outside_succeeded'] and not marker.exists(): row['outcome']='BLOCKED'
        shell=f'/bin/kill -0 {pid}; /usr/bin/touch {shlex.quote(str(t.ws/"apple-event.marker"))}; exit'
        apple='tell application "Terminal" to do script '+json.dumps(shell)
        row=pair('Apple Events / osascript',['/usr/bin/osascript','-e',apple],category='deputy',timeout=6,marker=t.ws/'apple-event.marker')
        row['execution_marker']=(t.ws/'apple-event.marker').exists()
        # A real termination route is last: its outside control deliberately
        # ends this custodian after the inside attempt has been recorded.
        pair('proc_terminate', [probe,'proc_terminate',pid])
        (t.ws/'matrix-finish').touch()
        t.finish(timeout=15)
        t.result['matrix_rows']=results
        t.result['outcome']='FAIL' if any(r['outcome']=='FAIL' for r in results) else 'BLOCKED' if any(r['outcome']=='BLOCKED' for r in results) else 'PASS'
    except Exception as error:
        t.result['matrix_error']=repr(error);t.result['matrix_rows']=results;t.result['outcome']='FAIL'
        if t.proc:
            t.result['before_emergency_cleanup']=t.snapshots();t.artifacts()
    finally:
        for server in sockets: server.close()
        for target in jobs: command(['/bin/launchctl','bootout',target])
        t.cleanup()
    return t.result
