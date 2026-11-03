#!/usr/bin/env python3
"""Shared pieces of the VM-tier live harnesses (K108-K113).

Nothing here boots a VM by itself. These are the parts every harness uses to
drive a `ukai-vm serve` (or `ukai-jail run --vm`) and to judge what it saw,
kept in one place so each judgement is written once and unit-tested once:

- the binaries under test come from the environment or the command line,
  never from a path baked into a script, and every record names them with
  their SHA-256;
- the egress probe (jail-macos §6, fix-wave decision D9) is a python3 socket
  connect to an IP literal with a short timeout, preceded by a positive
  control on loopback inside the same attempt; its verdict is a JSON line the
  host parses, so no shell `&&`/`||` precedence can produce it. A denial is
  only the jail's own errno (DENIAL_ERRNOS), and it proves the JAIL denied
  only with the guest NAT attached and a same-boot route control (an agent
  attempt whose proxy, outside the jail's network namespace, reached the
  same target) — `network_denial` below; an empty netns with no route at all
  gives the same errno, so the errno alone proves nothing;
- a workspace is cleaned only when it is a dedicated, marked harness
  directory (`mark` below creates the marker in an empty directory);
- output directories are never reused: a second run into the same `--out`
  refuses instead of overwriting the first run's evidence;
- each attempt stream has its own frame buffer;
- a receipt backs a verdict only when its digest verified AND its binding
  names this attempt, this argv, this profile and this serve boot
  (`receipt_bound`);
- machine-read record fields carry no absolute host path
  (docs/benchmarks/README.md rule 5): `write_json` rewrites the repository,
  temp and home prefixes (`portable`).

    python3 harness.py mark <empty directory on a case-sensitive volume>
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets as _secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time

REPOSITORY = Path(__file__).resolve().parents[3]
WORKSPACE_MARKER = '.ukai-vm-harness-workspace'
WORKSPACE_MARKER_TEXT = 'ukai.vm.harness-workspace/1\n'

# The guest jail's fixed shape (guest.py run_command): the capability and
# fault harnesses judge against these, so they live in one place.
GUEST_PIDS_LIMIT = 64
GUEST_MEM_LIMIT_MIB = 512

# The egress target: an anycast IP literal (no DNS involved) on a port that
# answers from the open internet. The harness records whether it answers
# from the host, so a denial is never measured against a dead address.
PROBE_TARGET = ('1.1.1.1', 443)
PROBE_TIMEOUT = 3.0
PROBE_TAG = 'UKAI_NET_PROBE'
PYTHON = '/usr/bin/python3'
# The errno the guest jail's own denial gives a direct connect: a `tool` or
# `agent` jail runs in a network namespace with only loopback, so a connect
# to a public address finds no route (measured: ENETUNREACH under tool,
# agent and the dash shell form in a real Linux ukai-jail, 2026-11-03).
# Any other result (a timeout, ECONNREFUSED — a peer answered, so a packet
# left —, EHOSTUNREACH, an unknown errno) is inconclusive, never a denial.
DENIAL_ERRNOS = ('ENETUNREACH',)
ROUTE_TAG = 'UKAI_ROUTE_CONTROL'
ROUTE_TIMEOUT = 10.0


class HarnessError(RuntimeError):
    """A precondition of the measurement does not hold; nothing was measured."""


class StreamEnded(RuntimeError):
    """The peer closed the stream before a complete frame."""


# ---------------------------------------------------------------------------
# Binaries, output, records
# ---------------------------------------------------------------------------

def required_binary(variable, given=None):
    """The binary under test: `given`, else `$variable`; never a default."""
    value = given if given is not None else os.environ.get(variable)
    if not value:
        raise HarnessError(f'name the binary under test with ${variable} or its flag; '
                           'no default is assumed, so a stale build cannot be measured by accident')
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise HarnessError(f'{path} is not an executable file')
    return path


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _prefixes():
    """(absolute prefix, replacement), longest first: repository-relative,
    then $TMPDIR, then ~ (docs/benchmarks/README.md rule 5)."""
    pairs = []
    for root, token in ((REPOSITORY, ''), (Path(tempfile.gettempdir()), '$TMPDIR/'), (Path.home(), '~/')):
        for spelling in {str(root), str(Path(root).resolve())}:
            spelling = spelling.rstrip('/')
            if spelling and spelling != '/':
                pairs.append((spelling, token))
    return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)


def relative_path(path):
    """`path` relative to the repository, else under $TMPDIR/ or ~/, else as given."""
    text = str(path)
    for prefix, token in _prefixes():
        if text == prefix:
            return token.rstrip('/') or '.'
        if text.startswith(prefix + '/'):
            return token + text[len(prefix) + 1:]
    return text


def portable(value):
    """A record with every absolute repository, temp or home path made relative,
    in every string (field values and quoted text alike)."""
    if isinstance(value, dict):
        return {key: portable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [portable(item) for item in value]
    if isinstance(value, str):
        for prefix, token in _prefixes():
            value = value.replace(prefix + '/', token)
            if value == prefix:
                value = token.rstrip('/') or '.'
        return value
    return value


def fingerprint(path):
    """What a record says about a binary it ran: where (relative), and which bytes."""
    path = Path(path)
    return {'path': relative_path(path), 'sha256': sha256_file(path)}


def fresh_out_dir(path):
    """Create `path` for this run; an existing directory is a previous run's evidence."""
    path = Path(path).expanduser().resolve()
    try:
        path.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise HarnessError(f'{path} exists: refusing to overwrite a previous run\'s output; '
                           'choose a new --out') from None
    return path


def write_json(path, value):
    """Write a record once, host paths made relative; an existing file is never replaced."""
    with open(path, 'x') as output:
        output.write(json.dumps(portable(value), indent=2, sort_keys=False) + '\n')


def b64(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.b64encode(value).decode()


def sh(script):
    """argv words for `/bin/sh -c script` (run_attempt encodes them)."""
    return ['/bin/sh', '-c', script]


def nonce():
    return _secrets.token_hex(8)


def rfc3339_now():
    """UTC now, RFC 3339 (a record that backs a requirement states when it ran)."""
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


# ---------------------------------------------------------------------------
# The `ukai-jail run --vm` client (S1's carry rule)
# ---------------------------------------------------------------------------

# The host refuses, before any boot, a `run --vm` whose policy differs from
# what the guest jail applies (vm:not-carried:<field>); until the live phase
# fills GUEST_MEASUREMENTS it also refuses at probing (vm:not-measured:<req>).
VM_REFUSAL = re.compile(r'vm:(?:not-measured|not-carried|owner-loss-not-provided)(?::[A-Za-z0-9_.:/-]+)?')
VM_WALL_MAX = 300


def vm_client_environment(base=None, **values):
    """The environment every harness `ukai-jail run --vm` runs under.

    The guest jail's environment admits LANG=C.UTF-8 only: TERM and TZ (and
    any LC_*) are dropped and LANG set, or the host refuses with
    vm:not-carried:environment.bindings. UKAI_VM_GUEST_NAT never leaks in.
    """
    environment = dict(os.environ if base is None else base)
    for name in list(environment):
        if name in ('TERM', 'TZ', 'UKAI_VM_GUEST_NAT') or name.startswith('LC_'):
            del environment[name]
    environment['LANG'] = 'C.UTF-8'
    environment.update({key: str(value) for key, value in values.items()})
    return environment


def vm_wall(seconds):
    """`--limit wall=Ns`: the one limit a --vm run carries, whole seconds, 1..300."""
    if not isinstance(seconds, int) or not 1 <= seconds <= VM_WALL_MAX:
        raise HarnessError(f'a --vm wall is whole seconds in 1..{VM_WALL_MAX}, not {seconds!r}')
    return ['--limit', f'wall={seconds}s']


def vm_refusals(text):
    """The host's VM-tier refusal codes in a client's output: a recorded
    outcome, never a pass."""
    return sorted(set(VM_REFUSAL.findall(text or '')))


# ---------------------------------------------------------------------------
# Workspace guard
# ---------------------------------------------------------------------------

def guarded_workspace(path):
    """The workspace, only if it is a dedicated, marked harness directory.

    Harnesses delete a workspace's contents and overwrite `.git/config`, so a
    mistyped argument must never reach a real tree: the directory must be
    absolute, not a symlink, outside the home directory's ancestry, the
    repository and the current directory, and carry the marker file `mark`
    writes (a regular, single-link file owned by this user with exact bytes).
    """
    raw = Path(path)
    if not raw.is_absolute():
        raise HarnessError(f'{path}: the workspace must be an absolute path')
    if raw.is_symlink():
        raise HarnessError(f'{path}: the workspace must not be a symlink')
    workspace = raw.resolve(strict=True)
    if not workspace.is_dir():
        raise HarnessError(f'{workspace} is not a directory')
    protected = [Path('/'), Path.home().resolve(), REPOSITORY, Path.cwd().resolve()]
    for anchor in protected:
        if workspace == anchor or workspace in anchor.parents:
            raise HarnessError(f'{workspace} is or contains {anchor}; refusing to clean it')
    if REPOSITORY in workspace.parents:
        raise HarnessError(f'{workspace} is inside the repository; use a dedicated directory')
    if workspace in (Path('/Users'), Path('/Volumes'), Path('/private'), Path('/tmp').resolve()):
        raise HarnessError(f'{workspace} is a system directory')
    marker = workspace / WORKSPACE_MARKER
    try:
        status = os.lstat(marker)
    except FileNotFoundError:
        raise HarnessError(f'{workspace} has no {WORKSPACE_MARKER}: run '
                           f'`python3 harness.py mark {workspace}` on an empty, dedicated '
                           'directory first') from None
    import stat
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_uid != os.getuid():
        raise HarnessError(f'{marker} must be a regular single-link file owned by this user')
    if marker.read_text() != WORKSPACE_MARKER_TEXT:
        raise HarnessError(f'{marker} does not carry the harness marker')
    return workspace


def mark_workspace(path):
    """Mark an EMPTY directory as a harness workspace (the only way to create one)."""
    directory = Path(path).resolve(strict=True)
    if any(directory.iterdir()):
        raise HarnessError(f'{directory} is not empty; a harness workspace starts empty')
    with open(directory / WORKSPACE_MARKER, 'x') as output:
        output.write(WORKSPACE_MARKER_TEXT)
    return guarded_workspace(directory)


def clean_workspace(path, keep=()):
    """Remove every entry but the marker and `keep`; never follows a symlink."""
    import shutil
    workspace = guarded_workspace(path)
    removed = []
    for entry in sorted(workspace.iterdir()):
        if entry.name == WORKSPACE_MARKER or entry.name in keep:
            continue
        if entry.is_symlink() or not entry.is_dir():
            entry.unlink()
        else:
            shutil.rmtree(entry)
        removed.append(entry.name)
    return removed


def protected_sentinel(workspace, text='[core]\n'):
    """Write the protected `.git/config` sentinel the K109 checks compare."""
    git = Path(workspace) / '.git'
    git.mkdir(exist_ok=True)
    (git / 'config').write_text(text)
    return git / 'config'


# ---------------------------------------------------------------------------
# The egress probe (D9)
# ---------------------------------------------------------------------------

PROBE_SOURCE = r'''
import errno, json, socket, sys
nonce, host, port, timeout, dns = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), sys.argv[5]
def connect(address):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(timeout)
    try:
        probe.connect(address)
        return 'connected'
    except socket.timeout:
        return 'timeout'
    except OSError as error:
        return errno.errorcode.get(error.errno, 'errno-%s' % error.errno)
    finally:
        probe.close()
record = {'nonce': nonce, 'target': [host, port]}
try:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(timeout)
    record['control'] = connect(listener.getsockname())
    try:
        listener.accept()[0].close()
        record['control_accepted'] = True
    except OSError:
        record['control_accepted'] = False
    listener.close()
except OSError as error:
    record['control'] = 'listener-' + errno.errorcode.get(error.errno, str(error.errno))
    record['control_accepted'] = False
record['egress'] = connect((host, port))
if dns != '-':
    try:
        socket.getaddrinfo(dns, 443, proto=socket.IPPROTO_TCP)
        record['dns'] = 'resolved'
    except OSError as error:
        record['dns'] = 'unresolved-%s' % getattr(error, 'errno', None)
print('UKAI_NET_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''


def probe_argv(tag, target=None, timeout=PROBE_TIMEOUT, dns=None):
    """The probe as a literal argv (python3 at its absolute guest path).

    `target` defaults to PROBE_TARGET read at call time, so a test can point
    every probe at loopback.
    """
    host, port = target or PROBE_TARGET
    return [PYTHON, '-I', '-c', PROBE_SOURCE, tag, host, str(port), str(timeout), dns or '-']


def probe_shell(tag, target=None, timeout=PROBE_TIMEOUT, dns=None):
    """The probe as one shell command, every word quoted; its exit status is unused."""
    return ' '.join(shlex.quote(word) for word in probe_argv(tag, target, timeout, dns))


def tagged_records(stdout, name, key, value):
    """Every `name {json}` line of `stdout` whose `key` is `value`."""
    records = []
    for line in (stdout or '').splitlines():
        if not line.startswith(name + ' '):
            continue
        try:
            record = json.loads(line[len(name) + 1:])
        except ValueError:
            continue
        if isinstance(record, dict) and record.get(key) == value:
            records.append(record)
    return records


def probe_verdict(stdout, tag):
    """The egress verdict from an attempt's stdout, for exactly this probe.

    `egress_denied` needs exactly one probe line with this tag, a positive
    control that connected AND was accepted on loopback (so the probe could
    have seen a connection), and an egress connect that failed with the
    jail's own denial errno (DENIAL_ERRNOS). `egress_allowed` is a connect;
    every other result — a timeout, ECONNREFUSED, EHOSTUNREACH, any other
    errno, a failed control, no line, two lines — is `inconclusive`,
    `no_probe` or `ambiguous`, never a denial. Even `egress_denied` says only
    that this attempt found no route: `network_denial` decides whether the
    JAIL removed one.
    """
    records = tagged_records(stdout, PROBE_TAG, 'nonce', tag)
    if not records:
        return {'verdict': 'no_probe', 'denied': False}
    if len(records) > 1:
        return {'verdict': 'ambiguous', 'denied': False, 'records': records}
    record = records[0]
    control = record.get('control') == 'connected' and record.get('control_accepted') is True
    if not control:
        verdict = 'inconclusive'
    elif record.get('egress') == 'connected':
        verdict = 'egress_allowed'
    elif record.get('egress') in DENIAL_ERRNOS:
        verdict = 'egress_denied'
    else:
        verdict = 'inconclusive'
    return {'verdict': verdict, 'denied': verdict == 'egress_denied',
            'control': record.get('control'), 'control_accepted': record.get('control_accepted'),
            'egress': record.get('egress'), 'target': record.get('target'), 'dns': record.get('dns')}


# The route control (F-2): the same target, reached on the same guest boot
# from OUTSIDE the jail's network namespace. An `agent` attempt allowed
# exactly the probe target asks its proxy (the jail's own, which runs in the
# guest's namespace, behind the NAT adapter) for a CONNECT tunnel to it; for
# an address destination the proxy connects upstream BEFORE it answers, so
# `200` means the guest reached the target. Without that, a probe's
# ENETUNREACH could be a guest with no route at all rather than the jail.
ROUTE_SOURCE = r'''
import json, os, socket, sys
nonce, host, port, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
record = {'nonce': nonce, 'target': [host, port]}
proxy = os.environ.get('HTTPS_PROXY', '')
record['proxy'] = proxy
try:
    scheme, _, rest = proxy.partition('://')
    address, _, proxy_port = rest.rstrip('/').rpartition(':')
    if scheme != 'http' or not address or not proxy_port.isdigit():
        raise ValueError('HTTPS_PROXY names no http proxy')
    stream = socket.create_connection((address, int(proxy_port)), timeout=timeout)
    try:
        stream.sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n' % (host, port, host, port)).encode())
        reply = b''
        while b'\r\n' not in reply and len(reply) < 4096:
            chunk = stream.recv(4096)
            if not chunk:
                break
            reply += chunk
    finally:
        stream.close()
    record['status_line'] = reply.split(b'\r\n', 1)[0].decode('latin-1')[:200]
except Exception as error:
    record['error'] = type(error).__name__ + ': ' + str(error)[:200]
print('UKAI_ROUTE_CONTROL ' + json.dumps(record, sort_keys=True), flush=True)
'''
ROUTE_REACHED = re.compile(r'HTTP/1\.[01] 200(?: |$)')


def route_rule(target=None):
    """The one `--allow-host` rule the route control needs: the probe target, port explicit."""
    host, port = target or PROBE_TARGET
    return f'{host}:{port}'


def route_argv(tag, target=None, timeout=ROUTE_TIMEOUT):
    host, port = target or PROBE_TARGET
    return [PYTHON, '-I', '-c', ROUTE_SOURCE, tag, host, str(port), str(timeout)]


def route_shell(tag, target=None, timeout=ROUTE_TIMEOUT):
    return ' '.join(shlex.quote(word) for word in route_argv(tag, target, timeout))


def route_verdict(stdout, tag, target=None):
    """`reached` only for exactly one control line with this tag, for this
    target, whose proxy answered `200` to the CONNECT."""
    target = list(target or PROBE_TARGET)
    records = tagged_records(stdout, ROUTE_TAG, 'nonce', tag)
    if not records:
        return {'verdict': 'no_control', 'reached': False}
    if len(records) > 1:
        return {'verdict': 'ambiguous', 'reached': False}
    record = records[0]
    reached = (record.get('target') == target and isinstance(record.get('status_line'), str)
               and bool(ROUTE_REACHED.match(record['status_line'])))
    return {'verdict': 'reached' if reached else 'not_reached', 'reached': reached,
            'status_line': record.get('status_line'), 'error': record.get('error'),
            'target': record.get('target')}


def network_denial(probe, route, guest_nat, probe_guest_boot, route_guest_boot, route_bound):
    """Whether the JAIL denied egress, fact by fact (all must hold).

    The probe saw the jail's denial errno after its loopback control; the
    guest had the NAT adapter attached; and on the same guest kernel boot a
    route control, through a receipt bound to its own attempt, reached the
    same target from outside the jail's namespace.
    """
    return {
        'probe_saw_the_jails_denial': (probe or {}).get('denied') is True,
        'guest_nat_attached': guest_nat is True,
        'route_control_reached_the_target': (route or {}).get('reached') is True,
        'route_control_on_the_same_guest_boot': bool(probe_guest_boot) and probe_guest_boot == route_guest_boot,
        'route_control_receipt_bound': route_bound is True,
    }


def host_reachability(target=None, timeout=PROBE_TIMEOUT):
    """Whether the probe target answers from this host (outside every jail).

    A denial measured against an address that answers nobody proves nothing;
    the live harnesses record this and gate on it.
    """
    target = target or PROBE_TARGET
    started = time.monotonic()
    try:
        with socket.create_connection(target, timeout=timeout):
            result = 'connected'
    except socket.timeout:
        result = 'timeout'
    except OSError as error:
        result = errno.errorcode.get(error.errno, str(error.errno))
    return {'target': list(target), 'result': result, 'answers': result == 'connected',
            'elapsed_ms': round((time.monotonic() - started) * 1000, 1)}


# ---------------------------------------------------------------------------
# Streams and the warm service
# ---------------------------------------------------------------------------

class Channel:
    """One NDJSON stream with its own buffer (never shared between sockets)."""

    def __init__(self, stream):
        self.stream = stream
        self.buffer = b''

    def frame(self):
        while b'\n' not in self.buffer:
            chunk = self.stream.recv(65536)
            if not chunk:
                raise StreamEnded('the stream ended before a complete frame')
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def send(self, **value):
        self.stream.sendall((json.dumps(value) + '\n').encode())

    def close(self):
        try:
            self.stream.close()
        except OSError:
            pass


def connect_unix(path, timeout=120.0, wait=0.0):
    """A Channel on `path`; retries for up to `wait` seconds while it is absent."""
    deadline = time.monotonic() + wait
    while True:
        stream = socket.socket(socket.AF_UNIX)
        stream.settimeout(timeout)
        try:
            stream.connect(str(path))
            return Channel(stream)
        except (FileNotFoundError, ConnectionRefusedError):
            stream.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def answers(path, timeout=2.0):
    """Whether anything accepts a connection on the unix socket `path`."""
    try:
        connect_unix(path, timeout=timeout).close()
        return True
    except OSError:
        return False


class Service:
    """One `ukai-vm serve` this harness started, in its own session.

    Its own session means the harness can signal the service's process group
    (serve, custodian, VZ client) without signalling itself. Its stderr goes
    to a file under the data directory, read back for every record.
    """

    def __init__(self, binary, home, workspace, data, extra=(), environment=None):
        self.binary = Path(binary)
        self.data = Path(data)
        self.workspace = Path(workspace)
        self.runtime = self.data / 'vm'
        self.stderr_path = self.data / 'serve.stderr.log'
        env = dict(os.environ if environment is None else environment,
                   UKAI_VM_HOME=str(home), UKAI_DATA_DIR=str(self.data))
        # The serve reads the adapter choice from its argv; an inherited
        # variable must not change what the record says was requested.
        env.pop('UKAI_VM_GUEST_NAT', None)
        self.argv = [str(self.binary), 'serve', '--live-workspace', str(self.workspace),
                     '--idle-seconds', '0', *extra]
        self._stderr = open(self.stderr_path, 'wb')
        self.child = subprocess.Popen(self.argv, env=env, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=self._stderr,
                                      start_new_session=True)
        self.warm_status = None

    @property
    def pid(self):
        return self.child.pid

    def socket_path(self, name):
        return self.runtime / f'{name}.sock'

    def control(self, op, timeout=5.0):
        channel = connect_unix(self.socket_path('control'), timeout=timeout)
        try:
            channel.send(op=op)
            return channel.frame()
        finally:
            channel.close()

    def status(self):
        return self.control('status')

    def wait_warm(self, timeout=300.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                raise HarnessError(f'the service exited {self.child.returncode} before it was warm: '
                                   f'{self.stderr_text()[-800:]}')
            try:
                status = self.status()
            except (OSError, StreamEnded, ValueError):
                status = None
            if status and status.get('warm') is True:
                self.warm_status = status
                return status
            time.sleep(0.2)
        raise HarnessError('the service never became warm')

    def connect(self, timeout=120.0):
        return connect_unix(self.socket_path('attempt'), timeout=timeout)

    def boot_dir(self):
        if not self.warm_status:
            return None
        return self.runtime / self.warm_status['boot_id']

    def stderr_text(self):
        if not self._stderr.closed:
            self._stderr.flush()
        return self.stderr_path.read_text(errors='replace')

    def stop(self, timeout=30.0):
        """Orderly stop through the control socket, then bounded escalation."""
        if self.child.poll() is None:
            try:
                self.control('stop')
            except (OSError, StreamEnded, ValueError):
                pass
            try:
                self.child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.child.terminate()
                try:
                    self.child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=10)
        self._stderr.close()
        return self.child.returncode

    def __enter__(self):
        try:
            self.wait_warm()
        except BaseException:
            self.stop()
            raise
        return self

    def __exit__(self, *exc):
        self.stop()


def run_attempt(connect, attempt_id, argv, profile='tool', wall=30, secrets=(),
                allow_hosts=None, clock=time.monotonic):
    """One attempt over the §6 attempt socket; every frame and timing recorded.

    `argv` holds plain strings or bytes (encoded here). The record never
    raises for a protocol or transport failure: it carries `error` instead,
    so a harness judges a failed attempt rather than losing it.
    """
    record = {'attempt_id': attempt_id, 'profile': profile, 'wall_seconds': wall,
              'argv_digest': argv_digest(argv), 'started_at': rfc3339_now(), 'stdout': '',
              'stderr': '', 'exit_code': None, 'error': None, 'events': []}
    marks = {}
    stdout, stderr = [], []
    channel = None
    try:
        marks['connect'] = clock()
        channel = connect()
        ready = channel.frame()
        marks['ready'] = clock()
        record['ready'] = ready
        record['boot_id'] = ready.get('boot_id')
        if ready.get('event') != 'ready':
            raise StreamEnded(f'expected ready, got {ready.get("event")}')
        request = {'op': 'prepare', 'attempt_id': attempt_id, 'profile': profile,
                   'wall_seconds': wall, 'argv': [b64(word) for word in argv],
                   'secrets': [{'id': key, 'data': b64(value)} for key, value in secrets]}
        if allow_hosts is not None:
            request['allow_hosts'] = list(allow_hosts)
        marks['prepare'] = clock()
        channel.send(**request)
        prepared = channel.frame()
        marks['prepared'] = clock()
        record['events'].append(prepared.get('event'))
        if prepared.get('event') != 'prepared':
            raise StreamEnded(f'expected prepared, got {prepared}')
        record['staged_secrets'] = prepared.get('staged_secrets', [])
        record['kernel'] = prepared.get('kernel')
        marks['run'] = clock()
        channel.send(op='run')
        while True:
            message = channel.frame()
            event = message.get('event')
            record['events'].append(event)
            if event == 'released':
                marks['released'] = clock()
                record['supervisor_pid'] = message.get('supervisor_pid')
            elif event == 'stdout':
                stdout.append(base64.b64decode(message['data']))
            elif event == 'stderr':
                stderr.append(base64.b64decode(message['data']))
            elif event == 'bound_receipt':
                raw = base64.b64decode(message['data'])
                record['receipt_sha256'] = message.get('sha256')
                record['receipt_digest_ok'] = hashlib.sha256(raw).hexdigest() == message.get('sha256')
                record['binding'] = message.get('binding')
                try:
                    record['receipt'] = json.loads(raw)
                except ValueError:
                    record['receipt'] = None
            elif event == 'done':
                marks['done'] = clock()
                record['exit_code'] = message.get('exit_code')
                break
            elif event == 'error':
                record['error'] = f"guest error: {message.get('message')}"
                break
    except (StreamEnded, OSError, ValueError, KeyError) as error:
        record['error'] = f'{type(error).__name__}: {error}'
    finally:
        if channel is not None:
            channel.close()
    record['stdout'] = b''.join(stdout).decode(errors='replace')
    record['stderr'] = b''.join(stderr).decode(errors='replace')
    record['timings_ms'] = timings(marks)
    return record


def timings(marks):
    def span(start, end):
        if start in marks and end in marks:
            return round((marks[end] - marks[start]) * 1000, 1)
        return None
    return {'connect_to_ready': span('connect', 'ready'),
            'prepare_to_prepared': span('prepare', 'prepared'),
            'run_to_released': span('run', 'released'),
            'prepare_to_released': span('prepare', 'released'),
            'connect_to_released': span('connect', 'released'),
            'released_to_done': span('released', 'done')}


def attempt_dir_bound(attempt, argv):
    """receipt_bound()'s checks for a `ukai-jail run --vm` attempt directory.

    evidence/jail.json hashes to the transport record's guest receipt digest;
    vm-binding.json names this attempt directory, this argv's digest (as the
    guest receipt's own argv_digest does), the transport's serve boot and a
    guest kernel boot.
    """
    attempt = Path(attempt)

    def read(name):
        try:
            return json.loads((attempt / name).read_text())
        except (OSError, ValueError):
            return {}
    guest_path = attempt / 'evidence' / 'jail.json'
    binding, transport, guest = read('evidence/vm-binding.json'), read('vm-transport.json'), read('evidence/jail.json')
    digest = argv_digest(argv)
    return (guest_path.is_file() and bool(transport.get('guest_receipt_sha256'))
            and sha256_file(guest_path) == transport['guest_receipt_sha256']
            and binding.get('attempt_id') == attempt.name and binding.get('argv_digest') == digest
            and guest.get('argv_digest') == digest and bool(binding.get('boot_id'))
            and binding.get('boot_id') == transport.get('boot_id') and bool(binding.get('guest_boot_id')))


def guest_boot(record):
    """The guest kernel's boot id, as the bound receipt binding carries it."""
    binding = record.get('binding') or {}
    return binding.get('guest_boot_id')


def receipt_bound(record):
    """Whether an attempt record's receipt may back a verdict (F-5).

    Its digest verified against the frame's SHA-256, and its binding (and the
    receipt's own argv digest) name exactly this attempt: the attempt id the
    harness sent, the argv it sent, its profile, the serve boot that answered
    `ready`, and a guest kernel boot. A receipt from another attempt, or one
    whose bytes do not match their digest, backs nothing.
    """
    binding = record.get('binding') or {}
    receipt = record.get('receipt') or {}
    digest = record.get('argv_digest')
    return (record.get('receipt_digest_ok') is True
            and bool(record.get('attempt_id')) and binding.get('attempt_id') == record.get('attempt_id')
            and bool(digest) and binding.get('argv_digest') == digest and receipt.get('argv_digest') == digest
            and bool(record.get('profile')) and binding.get('profile') == record.get('profile')
            and bool(record.get('boot_id')) and binding.get('boot_id') == record.get('boot_id')
            and bool(binding.get('guest_boot_id')))


def receipt_limit(receipt, key):
    for entry in ((receipt or {}).get('applied') or {}).get('limits') or []:
        if entry.get('key') == key:
            return entry
    return None


def jail_error_lines(text):
    """`ukai-jail: error …` lines: the guest jail failing, not the workload."""
    return [line for line in text.splitlines() if line.startswith('ukai-jail: error')]


# ---------------------------------------------------------------------------
# Receipts, bindings and summaries (K111, K113)
# ---------------------------------------------------------------------------

def argv_digest(argv):
    """`argv_digest` as ukai-records/src/canonical.rs and guest.py build it."""
    import struct
    words = [word.encode() if isinstance(word, str) else bytes(word) for word in argv]
    preimage = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(words))
    preimage += b''.join(struct.pack('>Q', len(word)) + word for word in words)
    return 'sha256:' + hashlib.sha256(preimage).hexdigest()


def _pointer(value, path):
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


# D5: no host-receipt field may contradict the verified guest receipt. The
# host mirrors the guest's values for these (S1's GuestFacts::CARRIED, named
# in lifetime.native.details.guest_carried; the host keeps only its own
# applied.terminal), and the outcome must agree: each is compared for
# equality, with no marker that excuses a difference.
MIRRORED = (('platform.kernel', ('platform', 'kernel')), ('platform.arch', ('platform', 'arch')),
            ('exec_observed', ('exec_observed',)), ('applied.network', ('applied', 'network')),
            ('applied.syscalls', ('applied', 'syscalls')), ('applied.filesystem', ('applied', 'filesystem')),
            ('applied.limits', ('applied', 'limits')), ('observer', ('observer',)),
            ('coverage', ('coverage',)), ('outcome.code', ('outcome', 'code')))


def receipt_contradictions(host, guest):
    found = []
    for name, path in MIRRORED:
        host_value, guest_value = _pointer(host, path), _pointer(guest, path)
        if host_value != guest_value:
            found.append({'field': name, 'host': host_value, 'guest': guest_value})
    return found


TRANSPORT_LINE = re.compile(r'vm: guest-reported facts in evidence/jail\.json · boot (\S+) '
                            r'· image ([0-9a-f]+) · vsock (\d+) · receipt sha256:([0-9a-f]+)')
SUMMARY_CLASSES = ('exec', 'fs.write', 'fs.deny', 'net', 'proxy.net', 'limits')


def _line_after(text, label):
    lines = [line.split(label, 1)[1] for line in text.splitlines() if label in line]
    return lines[-1].strip() if lines else None


PROXY_COUNTED = re.compile(r'^(?:allowed |denied |proxy, no connections(?: · |$)|'
                           r'proxy, none recorded \(a lower bound\)(?: · |$))')


def proxy_line_is_the_guests(network, guest):
    """A proxied network line that states the guest's facts (summary.rs `network`).

    Never a disagreement between journal and receipt, never another mode's
    line; with the guest's proxy.net class active it is a counted form
    (`allowed …`, `denied …`, `proxy, no connections`, `proxy, none recorded`),
    and with it inactive exactly `proxy, not observed`.
    """
    if not isinstance(network, str) or 'disagree' in network:
        return False
    active = (((guest or {}).get('coverage') or {}).get('proxy.net') or {}).get('status') == 'active'
    if active:
        return bool(PROXY_COUNTED.match(network))
    return network == 'proxy, not observed'


def summary_facts(text, guest, transport):
    """What a run summary (or `tail --summary`) says, against the verified records.

    The transport line's values must be the transport record's; the network
    line must state the guest receipt's applied mode; the evidence line must
    count the guest receipt's active observer classes and agree on whether
    the observer attached.
    """
    transport = transport or {}
    line = TRANSPORT_LINE.search(text)
    facts = {'transport_line_present': bool(line)}
    facts['transport_line_from_record'] = bool(line) and (
        line.group(1) == transport.get('boot_id')
        and line.group(2) == ((transport.get('image') or {}).get('disk_sha256') or '')[:16]
        and int(line.group(3)) == transport.get('vsock_port')
        and line.group(4) == (transport.get('guest_receipt_sha256') or '')[:16])
    mode = _pointer(guest, ('applied', 'network', 'mode'))
    network = _line_after(text, 'network: ')
    if mode == 'none':
        facts['network_line_is_the_guests'] = network == 'none'
    elif mode == 'proxy':
        facts['network_line_is_the_guests'] = proxy_line_is_the_guests(network, guest)
    else:
        facts['network_line_is_the_guests'] = False
    evidence = _line_after(text, 'evidence: ') or ''
    counted = re.search(r'(\d+)/(\d+) classes active', evidence)
    coverage = (guest or {}).get('coverage') or {}
    active = sum(1 for name in SUMMARY_CLASSES if (coverage.get(name) or {}).get('status') == 'active')
    facts['observer_classes_are_the_guests'] = bool(counted) and int(counted.group(1)) == active
    attached = _pointer(guest, ('observer', 'attached'))
    facts['observer_attachment_is_the_guests'] = bool(evidence) and (
        ('observer not attached' in evidence) == (attached is not True))
    return facts


# ---------------------------------------------------------------------------
# Host processes
# ---------------------------------------------------------------------------

VZ_SERVICE = ('/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/'
              'com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/'
              'com.apple.Virtualization.VirtualMachine')


def identity(pid):
    """Start time and command of `pid`, or None: a recycled pid never matches."""
    if not pid:
        return None
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart=', '-o', 'comm='],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def process_table():
    output = subprocess.run(['ps', '-axo', 'pid=,ppid=,pgid=,command='], capture_output=True,
                            text=True, check=True).stdout
    rows = []
    for line in output.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4:
            rows.append({'pid': int(parts[0]), 'ppid': int(parts[1]), 'pgid': int(parts[2]),
                         'command': parts[3]})
    return rows


def boot_processes(boot_dir, table=None):
    """The custodian and VZ client running from this boot's private image copy."""
    table = process_table() if table is None else table
    roots = {str(boot_dir), str(Path(boot_dir).resolve())}
    found = {'custodian': [], 'vz': []}
    for row in table:
        for root in roots:
            for name in found:
                if row['command'].startswith(f'{root}/image/{name} ') or row['command'] == f'{root}/image/{name}':
                    found[name].append(row['pid'])
    return {name: sorted(set(pids)) for name, pids in found.items()}


def vm_services_holding(disk):
    """Virtualization XPC services with `disk` open (the VM itself, not a controller)."""
    paths = {str(disk), str(Path(disk).resolve())}
    holders = []
    for row in process_table():
        if row['command'] != VZ_SERVICE and not row['command'].startswith(VZ_SERVICE + ' '):
            continue
        opened = subprocess.run(['lsof', '-a', '-p', str(row['pid']), '-F', 'n'],
                                capture_output=True, text=True)
        if any(line[1:] in paths for line in opened.stdout.splitlines() if line.startswith('n')):
            holders.append(row['pid'])
    return holders


def signal_checked(pid, expected, sig):
    """Signal `pid` only while it is still the process first identified."""
    if not expected or identity(pid) != expected:
        raise HarnessError(f'pid {pid} is no longer the process identified ({expected}); not signalled')
    os.kill(pid, sig)


def wait_gone(pids_with_identity, timeout, clock=time.monotonic, sleep=time.sleep):
    """Seconds until every (pid, identity) is gone, or None at the timeout."""
    started = clock()
    while True:
        alive = [pid for pid, ident in pids_with_identity if ident and identity(pid) == ident]
        if not alive:
            return round(clock() - started, 2)
        if clock() - started > timeout:
            return None
        sleep(0.1)


# ---------------------------------------------------------------------------
# Heartbeat workloads (K110)
# ---------------------------------------------------------------------------

def heartbeat_script(marker, children=2, beats=None, interval=0.2):
    """A workload with descendants that beat into the live workspace.

    The leader and each background child rewrite `hb-<marker>-<n>` with the
    guest clock every `interval`; `boot-<marker>` records the guest kernel's
    boot id. `beats=None` runs until killed; otherwise every process stops
    after `beats` beats and the leader waits for its children and exits 0.
    """
    limit = 'true' if beats is None else f'[ "$n" -lt {int(beats)} ]'
    loop = (f'n=0; while {limit}; do date +%s%N > hb-{marker}-$1; '
            f'n=$((n+1)); sleep {interval}; done')
    lines = [f'cat /proc/sys/kernel/random/boot_id > boot-{marker}',
             f'beat() {{ {loop}; }}']
    lines += [f'beat {index} &' for index in range(1, children + 1)]
    lines += ['beat 0', 'wait', f'echo hb-{marker}-done']
    return '\n'.join(lines) + '\n'


class BeatWatch:
    """Host-side view of a heartbeat workload through the live share."""

    def __init__(self, workspace, marker, children=2, clock=time.monotonic, sleep=time.sleep):
        self.files = [Path(workspace) / f'hb-{marker}-{index}' for index in range(children + 1)]
        self.boot_file = Path(workspace) / f'boot-{marker}'
        self.clock = clock
        self.sleep = sleep
        self.last = {}
        self.changed_at = {}

    def poll(self):
        now = self.clock()
        for path in self.files:
            try:
                value = path.read_bytes()
            except OSError:
                continue
            if self.last.get(path) != value:
                if path in self.last:
                    self.changed_at[path] = now
                self.last[path] = value
        return now

    def all_beating(self):
        return all(path in self.changed_at for path in self.files)

    def wait_beating(self, timeout, give_up=None):
        """True once every process has beaten at least once after first sight.

        `give_up()` returning true (the client exited, say) ends the wait early.
        """
        deadline = self.clock() + timeout
        while self.clock() < deadline:
            self.poll()
            if self.all_beating():
                return True
            if give_up is not None and give_up():
                return False
            self.sleep(0.05)
        return False

    def last_change(self):
        return max(self.changed_at.values()) if self.changed_at else None

    def wait_quiet(self, quiet, timeout):
        """(quiet reached, last change time): no file changed for `quiet` seconds."""
        deadline = self.clock() + timeout
        while True:
            now = self.poll()
            last = self.last_change()
            if last is not None and now - last >= quiet:
                return True, last
            if now >= deadline:
                return False, last
            self.sleep(0.05)

    def changed_since(self, moment):
        return [path.name for path, at in self.changed_at.items() if at > moment]

    def guest_boot_id(self):
        try:
            return self.boot_file.read_text().strip() or None
        except OSError:
            return None

    def guest_times(self):
        """Each file's last guest timestamp (ns), for guest-clock deltas."""
        values = {}
        for path in self.files:
            try:
                values[path.name] = int(path.read_text().strip())
            except (OSError, ValueError):
                values[path.name] = None
        return values


# ---------------------------------------------------------------------------
# An attempt client in its own process (for kill and Ctrl-Z cases)
# ---------------------------------------------------------------------------

class ClientProcess:
    """`python3 harness.py client`: an attempt client the harness can kill.

    It runs in its own process group of THIS session, as a shell job does:
    a SIGKILL closes the attempt socket by process death (the lease's EOF),
    and a SIGTSTP of its group is a terminal Ctrl-Z of exactly that client.
    (A group in a session of its own is orphaned, and the kernel discards a
    SIGTSTP sent to an orphaned group, so `start_new_session` would turn the
    Ctrl-Z case into a no-op.) Every frame it sees is one NDJSON line on its
    stdout, read here by a thread.
    """

    def __init__(self, socket_path, attempt_id, argv, wall, profile='tool', clock=time.monotonic):
        payload = json.dumps({'socket': str(socket_path), 'attempt_id': attempt_id,
                              'argv': [b64(word) for word in argv], 'wall': wall,
                              'profile': profile})
        self.attempt_id = attempt_id
        self.argv_digest = argv_digest(argv)
        self.profile = profile
        self.clock = clock
        self.process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), 'client'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, process_group=0)
        self.process.stdin.write(payload.encode() + b'\n')
        self.process.stdin.close()
        self.identity = None
        self.timed_out = False
        self.events = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self):
        for line in self.process.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict):
                event['seen_at'] = self.clock()  # when this host read it, for ordering against a kill
            with self._lock:
                self.events.append(event)

    def ended_at(self):
        """When the stream ended or errored (host clock), or None."""
        ends = [event['seen_at'] for event in self.seen('ended') + self.seen('error')]
        return min(ends) if ends else None

    def wait_exit(self, timeout):
        """The exit status within `timeout`, or None; never kills (cf. finish)."""
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def receipt_bound(self):
        """receipt_bound() for the receipt this client received, if any."""
        receipts, ready = self.seen('bound_receipt'), self.seen('ready')
        if len(receipts) != 1 or not ready:
            return False
        frame = receipts[0]
        return receipt_bound({'attempt_id': self.attempt_id, 'argv_digest': self.argv_digest,
                              'profile': self.profile, 'boot_id': ready[0].get('boot_id'),
                              'binding': frame.get('binding'), 'receipt_digest_ok': frame.get('digest_ok'),
                              'receipt': {'argv_digest': frame.get('receipt_argv_digest')}})

    def seen(self, name):
        with self._lock:
            return [event for event in self.events if event.get('event') == name]

    def wait_event(self, name, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.seen(name):
                return self.seen(name)[0]
            if self.process.poll() is not None and not self._reader.is_alive():
                return None
            time.sleep(0.02)
        return None

    def capture_identity(self):
        self.identity = identity(self.process.pid)
        return self.identity

    def finish(self, timeout=10):
        """Wait for the client to end by itself; `timed_out` says if it had to be killed."""
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.timed_out = True
            self.process.kill()
            self.process.wait(timeout=10)
        self._reader.join(timeout=5)
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None and not self._reader.is_alive():
                stream.close()
        return self.process.returncode

    def ended_by_itself(self):
        """It exited on its own after the stream ended or errored, never by our kill."""
        return (not self.timed_out and self.process.returncode is not None
                and bool(self.seen('ended') or self.seen('error')))


def client_main():
    request = json.loads(sys.stdin.readline())

    def emit(**value):
        sys.stdout.write(json.dumps(value) + '\n')
        sys.stdout.flush()

    channel = connect_unix(request['socket'], timeout=None)
    try:
        ready = channel.frame()
        emit(event='ready', boot_id=ready.get('boot_id'))
        channel.send(op='prepare', attempt_id=request['attempt_id'], profile=request['profile'],
                     wall_seconds=request['wall'], argv=request['argv'], secrets=[])
        prepared = channel.frame()
        emit(event=prepared.get('event'))
        if prepared.get('event') != 'prepared':
            return 3
        channel.send(op='run')
        while True:
            message = channel.frame()
            event = message.get('event')
            if event in ('stdout', 'stderr'):
                emit(event=event, text=base64.b64decode(message['data']).decode(errors='replace'))
            elif event == 'bound_receipt':
                raw = base64.b64decode(message['data'])
                try:
                    receipt_digest = (json.loads(raw) or {}).get('argv_digest')
                except (ValueError, AttributeError):
                    receipt_digest = None
                emit(event=event, binding=message.get('binding'),
                     digest_ok=hashlib.sha256(raw).hexdigest() == message.get('sha256'),
                     receipt_argv_digest=receipt_digest)
            elif event == 'done':
                emit(event='done', exit_code=message.get('exit_code'))
                return 0
            elif event == 'error':
                emit(event='error', message=message.get('message'))
                return 2
            else:
                emit(event=event)
    except (StreamEnded, OSError, ValueError) as error:
        emit(event='ended', error=f'{type(error).__name__}: {error}')
        return 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['client']:
        return client_main()
    if len(argv) == 2 and argv[0] == 'mark':
        print(mark_workspace(argv[1]))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
