"""Bounded, value-free periodic Linux /proc exposure evidence.

This module does not authorize a launch or claim continuous coverage. The caller
owns scheduling and supplies the exact receipt/attempt binding at finish. No
controller integration is implied by the existence of this sampler.
"""
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import threading
import urllib.parse

SCHEMA = 'ukai.vm.sampled-exposure/2'
MAX_READ_BYTES = 2 * 1024 * 1024
MAX_PROCESS_COUNT = 4096
MAX_TICK_BYTES = 16 * 1024 * 1024
MAX_TICK_NS = 50_000_000
MAX_HITS = 4096
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 512 * 1024
READ_STATES = ('readable', 'unreadable', 'oversize', 'vanished', 'unstable', 'capped')
SCAN_ERROR_CODES = frozenset(('malformed_stat', 'malformed_status', 'nonregular_proc_file',
    'nonregular_executable', 'oversize', 'identity_changed', 'tick_time_cap', 'tick_byte_cap',
    'identity_cap', 'hit_cap', 'proc_root_changed', 'boot_identity_changed', 'invalid_pid_entry',
    'process_cap', 'supervisor_unobserved', 'inventory_unreadable', 'inventory_vanished',
    'selected_process_unreadable', 'selected_process_vanished', 'proc_root_unreadable', 'proc_root_vanished',
    'monitor_initialization_failed', 'monitor_worker_failed', 'monitor_join_timeout'))
STOP_REASONS = frozenset(('manual', 'requested', 'supervisor_exit', 'worker_failed', 'join_timeout'))
BINDING_KEYS = {'host_attempt_id', 'service_boot_id', 'guest_attempt_id', 'guest_boot_id',
                'catalog_sha256', 'executable_sha256', 'sampler_sha256'}
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class SamplingError(Exception):
    """Only a closed enum code is carried internally, never an OS error string."""


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value < 2**64


def _identity(value):
    if (not isinstance(value, (tuple, list)) or len(value) != 2
            or not all(_integer(x, 1) for x in value)):
        raise ValueError('invalid numeric identity')
    return tuple(value)


def _label(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is not None


def _digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _open_directory(path):
    """Anchor every absolute path component, including the proc root itself."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('proc root must be absolute and non-traversing')
    fd = os.open('/', _DIR)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file_identity(info):
    return info.st_dev, info.st_ino


def _error(error):
    return 'vanished' if isinstance(error, (FileNotFoundError, ProcessLookupError)) else 'unreadable'


def _stat(data, pid):
    # comm can contain spaces and ')' bytes. Do not retain or export it.
    begin, marker, tail = data.rpartition(b')')
    fields = tail.split()
    if not marker or begin.split(b' ', 1)[0] != str(pid).encode() or len(fields) < 20:
        raise SamplingError('malformed_stat')
    try:
        parent, start = int(fields[1]), int(fields[19])
    except ValueError:
        raise SamplingError('malformed_stat') from None
    # Kernel threads born in the first clock tick legitimately report zero.
    # Inventory must include their valid metadata; the selected supervisor's
    # constructor and terminal receipt still require a positive birth tick.
    if not _integer(parent) or not _integer(start):
        raise SamplingError('malformed_stat')
    return parent, start


def _uids(data):
    rows = [line for line in data.splitlines() if line.startswith(b'Uid:')]
    try:
        values = tuple(int(value) for value in rows[0][4:].split())
    except (ValueError, IndexError):
        raise SamplingError('malformed_status') from None
    if len(rows) != 1 or len(values) != 4 or not all(_integer(v) for v in values):
        raise SamplingError('malformed_status')
    return values


def _patterns(values):
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 16:
        raise ValueError('protected values must be a bounded nonempty sequence')
    patterns = []
    for value in values:
        if type(value) is not bytes or not 1 <= len(value) <= 65536:
            raise ValueError('protected value size or type is invalid')
        candidates = {'raw': value, 'base64': base64.b64encode(value),
                      'base64url': base64.urlsafe_b64encode(value).rstrip(b'='),
                      'hex': value.hex().encode(),
                      'url': urllib.parse.quote_from_bytes(value, safe='').encode()}
        try:
            candidates['json'] = json.dumps(value.decode('utf-8'), ensure_ascii=True)[1:-1].encode()
        except UnicodeError:
            pass
        # The representation enum is public; no value, length or value hash is exported.
        encoded_forms = list(candidates.items())
        encoded_forms.extend([('base64', base64.b64encode(value).rstrip(b'=')),
                              ('base64url', base64.urlsafe_b64encode(value)),
                              ('hex', value.hex().upper().encode())])
        for representation, pattern in encoded_forms:
            if (representation, pattern) not in patterns:
                patterns.append((representation, pattern))
    return patterns


def source_sha256():
    path = Path(__file__).absolute()
    parent = _open_directory(path.parent)
    try:
        fd = os.open(path.name, _FILE, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_READ_BYTES:
                raise ValueError('sampler source is not bounded regular bytes')
            data = bytearray()
            while len(data) <= MAX_READ_BYTES:
                part = os.read(fd, min(65536, MAX_READ_BYTES + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            after = os.fstat(fd)
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if (len(data) > MAX_READ_BYTES or signature(before) != signature(after)
                    or signature(before) != signature(current)):
                raise ValueError('sampler source changed')
            return hashlib.sha256(data).hexdigest()
        finally:
            os.close(fd)
    finally:
        os.close(parent)


class Sampler:
    def __init__(self, proc_root, boot_id, supervisor_pid, supervisor_starttime, workload_uid,
                 infrastructure_identities, catalog_executable_identity, protected_values,
                 period_ns=100_000_000):
        if not _label(boot_id) or not _integer(workload_uid) or not _integer(period_ns, 1):
            raise ValueError('invalid sampler identity or period')
        self.supervisor = _identity((supervisor_pid, supervisor_starttime))
        if (not isinstance(catalog_executable_identity, (tuple, list)) or len(catalog_executable_identity) != 2
                or not _integer(catalog_executable_identity[0]) or not _integer(catalog_executable_identity[1], 1)):
            raise ValueError('invalid executable identity')
        self.executable = tuple(catalog_executable_identity)
        if not isinstance(infrastructure_identities, (list, tuple, set)) or len(infrastructure_identities) > 64:
            raise ValueError('invalid infrastructure identities')
        self.infrastructure = {_identity(value) for value in infrastructure_identities}
        if self.supervisor in self.infrastructure:
            raise ValueError('supervisor cannot be excluded')
        self.proc_root = Path(proc_root)
        self.root = _open_directory(proc_root)
        self.root_identity = _file_identity(os.fstat(self.root))
        self.boot_id, self.uid, self.period = boot_id, workload_uid, period_ns
        self.patterns = _patterns(protected_values)
        self.source_digest = source_sha256()
        self._initialize_counts()

    def _initialize_counts(self):
        self.lifecycle = dict(started_ns=None, supervisor_exit_observed_ns=None, stopped_ns=None, stop_reason='manual')
        self.errors = Counter()
        self.counts = {name: Counter({state: 0 for state in READ_STATES}) for name in ('environment', 'argv')}
        self.program_counts = {name: Counter({state: 0 for state in READ_STATES}) for name in self.counts}
        # Bounded identity-indexed catalog reads, retained only as counters.
        # Another vendor process cannot certify the receipt's workload.
        self.program_identity_counts = {}
        self.identities = {}
        self.hits = []
        self.ticks = self.late_polls = self.missed_ticks = self.max_gap = self.max_duration = 0
        self.first = self.last = None
        self.finished = False
        self._remaining = 0
        self._deadline = 0

    def close(self):
        if self.root is not None:
            os.close(self.root)
            self.root = None

    def __del__(self):
        if getattr(self, 'root', None) is not None:
            self.close()

    def _budget(self):
        if time.monotonic_ns() >= self._deadline:
            raise SamplingError('tick_time_cap')
        if self._remaining <= 0:
            raise SamplingError('tick_byte_cap')

    def _read(self, directory, name, limit):
        self._budget()
        fd = os.open(name, _FILE, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SamplingError('nonregular_proc_file')
            data = bytearray()
            while len(data) <= limit:
                self._budget()
                part = os.read(fd, min(65536, limit + 1 - len(data), self._remaining))
                if not part:
                    return bytes(data)
                self._remaining -= len(part)
                data.extend(part)
            raise SamplingError('oversize')
        finally:
            os.close(fd)

    def _check_boot(self):
        fd = os.dup(self.root)
        try:
            for name in ('sys', 'kernel', 'random'):
                child = os.open(name, _DIR, dir_fd=fd)
                os.close(fd)
                fd = child
            if self._read(fd, 'boot_id', 128).strip() != self.boot_id.encode('ascii'):
                raise SamplingError('boot_identity_changed')
        finally:
            os.close(fd)

    def _info(self, fd, pid):
        parent, start = _stat(self._read(fd, 'stat', 65536), pid)
        return parent, start, _uids(self._read(fd, 'status', 65536))

    def _executable(self, fd):
        # proc's exe is intentionally a kernel magic link. Its text is never read.
        opened = os.open('exe', os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(opened)
            if not stat.S_ISREG(info.st_mode):
                raise SamplingError('nonregular_executable')
            return _file_identity(info)
        finally:
            os.close(opened)

    def _retain_identity(self, identity, roles):
        if identity not in self.identities:
            if len(self.identities) >= MAX_PROCESS_COUNT:
                self.errors['identity_cap'] += 1
                return
            self.identities[identity] = set()
        self.identities[identity].update(roles)

    def _scan(self, data, identity, channel, stable):
        for representation, pattern in self.patterns:
            if pattern in data:
                if len(self.hits) >= MAX_HITS:
                    self.errors['hit_cap'] += 1
                    return
                hit = {'pid': identity[0], 'starttime': identity[1], 'channel': channel,
                       'representation': representation, 'identity_stable': stable}
                if hit not in self.hits:
                    self.hits.append(hit)

    def _observe(self, pid, info, roles):
        identity = (pid, info[1])
        data = {}
        states = {}
        candidate = stable = False
        try:
            fd = os.open(str(pid), _DIR, dir_fd=self.root)
        except OSError as error:
            for channel in self.counts:
                self.counts[channel][_error(error)] += 1
            self.errors['selected_process_' + _error(error)] += 1
            return
        try:
            before_dir = _file_identity(os.fstat(fd))
            before = self._info(fd, pid)
            # Selection used parent/UID metadata from this tick's inventory.
            # Those attributes can change without replacing the process; keep
            # observing that selected birth, with its historical roles.
            if before[1] != identity[1]:
                raise SamplingError('identity_changed')
            executable_before = self._executable(fd)
            candidate = executable_before == self.executable
            for channel, name in [('environment', 'environ'), ('argv', 'cmdline')]:
                try:
                    # Birth identity must bracket each sensitive read, not only the tick.
                    if self._info(fd, pid)[1] != identity[1]:
                        raise SamplingError('identity_changed')
                    data[channel] = self._read(fd, name, MAX_READ_BYTES)
                    if self._info(fd, pid)[1] != identity[1]:
                        raise SamplingError('identity_changed')
                    states[channel] = 'readable'
                except OSError as error:
                    states[channel] = _error(error)
                except SamplingError as error:
                    code = error.args[0]
                    states[channel] = ('oversize' if code == 'oversize' else
                                       'capped' if code in ('tick_time_cap', 'tick_byte_cap') else 'unstable')
                    self.errors[code] += 1
            after = self._info(fd, pid)
            executable_after = self._executable(fd)
            current = os.stat(str(pid), dir_fd=self.root, follow_symlinks=False)
            stable = (after[1] == identity[1] and executable_after == executable_before
                      and stat.S_ISDIR(current.st_mode) and _file_identity(current) == before_dir)
            if not stable:
                self.errors['identity_changed'] += 1
        except OSError as error:
            self.errors['selected_process_' + _error(error)] += 1
            states = {channel: _error(error) for channel in self.counts}
        except SamplingError as error:
            self.errors[error.args[0]] += 1
            states = {channel: 'capped' if error.args[0].startswith('tick_') else 'unstable' for channel in self.counts}
        finally:
            os.close(fd)
        if not stable:
            states = {channel: ('unstable' if state == 'readable' else state) for channel, state in states.items()}
        self._retain_identity(identity, roles | ({'catalog_program'} if candidate and stable else set()))
        for channel in self.counts:
            state = states.get(channel, 'unstable')
            self.counts[channel][state] += 1
            if candidate and identity in self.identities:
                self.program_counts[channel][state] += 1
                if identity not in self.program_identity_counts:
                    if len(self.program_identity_counts) >= MAX_PROCESS_COUNT:
                        self.errors['identity_cap'] += 1
                    else:
                        self.program_identity_counts[identity] = {
                            name: Counter({key: 0 for key in READ_STATES}) for name in self.counts}
                if identity in self.program_identity_counts:
                    self.program_identity_counts[identity][channel][state] += 1
            if channel in data:
                self._scan(data[channel], identity, channel, stable)

    def sample(self, now_ns):
        if self.finished or self.root is None or not _integer(now_ns):
            raise ValueError('sampler is closed or timestamp is invalid')
        if self.last is not None and now_ns <= self.last:
            raise ValueError('sample timestamps must increase')
        if self.last is None:
            self.first = now_ns
        else:
            gap = now_ns - self.last
            self.max_gap = max(self.max_gap, gap)
            self.late_polls += int(gap > self.period)
            self.missed_ticks += max(0, gap // self.period - 1)
        self.last = now_ns
        self.ticks += 1
        started = time.monotonic_ns()
        self._deadline = started + MAX_TICK_NS
        self._remaining = MAX_TICK_BYTES
        table = {}
        entries_seen = 0
        try:
            fresh = _open_directory(self.proc_root)
            try:
                if _file_identity(os.fstat(fresh)) != self.root_identity:
                    raise SamplingError('proc_root_changed')
            finally:
                os.close(fresh)
            self._check_boot()
            with os.scandir(self.root) as entries:
                for entry in entries:
                    self._budget()
                    if not entry.name.isascii() or not entry.name.isdigit():
                        continue
                    pid = int(entry.name)
                    if not _integer(pid, 1) or str(pid) != entry.name:
                        self.errors['invalid_pid_entry'] += 1
                        continue
                    entries_seen += 1
                    if entries_seen > MAX_PROCESS_COUNT:
                        raise SamplingError('process_cap')
                    try:
                        fd = os.open(entry.name, _DIR, dir_fd=self.root)
                        try:
                            table[pid] = self._info(fd, pid)
                        finally:
                            os.close(fd)
                    except OSError as error:
                        self.errors['inventory_' + _error(error)] += 1
                    except SamplingError as error:
                        if error.args[0].startswith('tick_'):
                            raise
                        self.errors[error.args[0]] += 1
            supervisor_valid = (self.supervisor[0] in table
                                and table[self.supervisor[0]][1] == self.supervisor[1])
            if not supervisor_valid:
                self.errors['supervisor_unobserved'] += 1
            descendants = {self.supervisor[0]} if supervisor_valid else set()
            children = {}
            for pid, info in table.items():
                children.setdefault(info[0], []).append(pid)
            pending = list(descendants)
            while pending:
                self._budget()
                for child in children.get(pending.pop(), ()):
                    if child not in descendants:
                        descendants.add(child)
                        pending.append(child)
            for pid, info in sorted(table.items()):
                self._budget()
                identity = (pid, info[1])
                if identity in self.infrastructure:
                    continue
                roles = set()
                if pid in descendants:
                    roles.add('supervisor' if identity == self.supervisor else 'descendant')
                if self.uid in info[2]:
                    roles.add('workload_uid')
                if roles:
                    self._observe(pid, info, roles)
        except OSError as error:
            self.errors['proc_root_' + _error(error)] += 1
        except SamplingError as error:
            self.errors[error.args[0]] += 1
        finally:
            duration = time.monotonic_ns() - started
            self.max_duration = max(self.max_duration, duration)
            if duration > MAX_TICK_NS:
                self.errors['tick_time_cap'] += 1

    def finish(self, receipt_bytes, binding):
        if self.finished or type(receipt_bytes) is not bytes or len(receipt_bytes) > MAX_RECEIPT_BYTES:
            raise ValueError('invalid terminal receipt or sampler state')
        if (type(binding) is not dict or set(binding) != BINDING_KEYS
                or any(not _digest(binding[key]) for key in ('catalog_sha256', 'executable_sha256', 'sampler_sha256'))
                or any(not _label(binding[key]) for key in BINDING_KEYS if not key.endswith('_sha256'))
                or binding['guest_boot_id'] != self.boot_id
                or binding['sampler_sha256'] != self.source_digest
                or source_sha256() != self.source_digest):
            raise ValueError('invalid sampler binding')
        if any(pattern in receipt_bytes for _, pattern in self.patterns):
            raise ValueError('protected receipt value withheld')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate receipt key')
                result[key] = value
            return result
        try:
            receipt = json.loads(receipt_bytes.decode('utf-8'), object_pairs_hook=unique)
            identity = receipt['process']['identity']
            if (receipt['attempt_id'] != binding['guest_attempt_id']
                    or identity['kind'] != 'linux_boot_start'
                    or identity['value']['boot_id'] != self.boot_id
                    or not _integer(identity['value']['pid'], 1)
                    or not _integer(identity['value']['start_time_ticks'], 1)):
                raise ValueError('receipt identity differs')
        except (UnicodeError, KeyError, TypeError, RecursionError):
            raise ValueError('invalid receipt identity') from None
        receipt_identity = (identity['value']['pid'], identity['value']['start_time_ticks'])
        receipt_counts = self.program_identity_counts.get(receipt_identity,
            {name: Counter({state: 0 for state in READ_STATES}) for name in self.counts})
        positive = all(self.program_counts[channel]['readable'] > 0 for channel in self.counts)
        receipt_positive = all(receipt_counts[channel]['readable'] > 0 for channel in self.counts)
        if self.supervisor[1] is None and not (self.ticks == 0 and not self.identities
                and self.errors.get('monitor_initialization_failed', 0) > 0
                and not any(value for row in self.counts.values() for value in row.values())):
            raise ValueError('unknown supervisor birth is not initialization failure')
        supervisor_observed = 'supervisor' in self.identities.get(self.supervisor, set())
        incomplete = bool(self.errors) or not positive or not receipt_positive or not supervisor_observed or self.ticks == 0 or any(
            count for row in self.counts.values() for state, count in row.items() if state != 'readable')
        report = dict(schema=SCHEMA, **binding, guest_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
                      finished=True, actual_values_retained=False,
                      scope='periodic-readable-environment-and-argv-only',
                      continuous_coverage_claimed=False, arbitrary_memory_examined=False,
                      period_ns=self.period, first_ns=self.first, last_ns=self.last,
                      observed_interval_ns=0 if self.first is None else self.last - self.first,
                      maximum_gap_ns=self.max_gap, maximum_tick_duration_ns=self.max_duration,
                      tick_count=self.ticks, late_poll_count=self.late_polls, missed_tick_count=self.missed_ticks,
                      reads=self.counts, verified_program_reads=self.program_counts,
                      receipt_program_reads=receipt_counts, receipt_program_observed=receipt_positive,
                      verified_program_observed=positive, observation_incomplete=incomplete,
                      scan_errors=dict(sorted(self.errors.items())), hits=self.hits,
                      processes=[dict(pid=pid, starttime=start, roles=sorted(roles))
                                 for (pid, start), roles in sorted(self.identities.items())],
                      lifecycle=self.lifecycle,
                      supervisor=dict(pid=self.supervisor[0], starttime=self.supervisor[1]),
                      receipt_process=dict(pid=receipt_identity[0], starttime=receipt_identity[1]),
                      catalog_executable_identity=dict(dev=self.executable[0], ino=self.executable[1]),
                      workload_uid=self.uid,
                      limits=dict(read_bytes=MAX_READ_BYTES, process_count=MAX_PROCESS_COUNT,
                                  tick_bytes=MAX_TICK_BYTES, tick_ns=MAX_TICK_NS, hit_count=MAX_HITS))
        if set(self.errors) - SCAN_ERROR_CODES or self.lifecycle['stop_reason'] not in STOP_REASONS:
            raise ValueError('unknown sampler status withheld')
        encoded = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
        if len(encoded) > MAX_REPORT_BYTES or any(pattern in encoded for _, pattern in self.patterns):
            raise ValueError('unsafe or oversized exposure report withheld')
        self.finished = True
        self.patterns.clear()
        self.close()
        # Return a detached JSON value, so later mutation cannot alter sampler history.
        return json.loads(encoded)


class Monitor:
    """One independently scheduled native-attempt observer, never a control writer.

    A worker that does not join is abandoned; no mutable counters are read from
    it. Its eventual finally clears protected references. Python does not offer
    guaranteed zeroization, and this code makes no such claim.
    """
    JOIN_SECONDS = 1.0

    def __init__(self, proc_root, boot_id, process, workload_uid, infrastructure_identities,
                 catalog_executable_path, protected_values):
        self.process, self.boot_id, self.uid = process, boot_id, workload_uid
        self.stop_event = threading.Event()
        self.abandoned = threading.Event()
        self.sampler = self.thread = None
        self.failure = None
        self.started = time.monotonic_ns()
        self.exit_observed = self.stopped = None
        self.reason = 'requested'
        self.executable = (0, 0)
        # Popen is the jail supervisor. The Linux receipt names its launched
        # workload; never borrow that child's birth when initialization fails.
        self.supervisor = (process.pid, None)
        self.source_digest = source_sha256()
        # Required for a safe zero-observation report if proc setup is unavailable.
        self.patterns = _patterns(protected_values)
        try:
            root = _open_directory(proc_root)
            try:
                pidfd = os.open(str(process.pid), _DIR, dir_fd=root)
                try:
                    fd = os.open('stat', _FILE, dir_fd=pidfd)
                    try:
                        _, start = _stat(os.read(fd, 65537), process.pid)
                        self.supervisor = _identity((process.pid, start))
                    finally:
                        os.close(fd)
                finally:
                    os.close(pidfd)
            finally:
                os.close(root)
            path = Path(catalog_executable_path)
            parent = _open_directory(path.parent)
            try:
                fd = os.open(path.name, _FILE, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError('nonregular catalog executable')
                    self.executable = _file_identity(info)
                finally:
                    os.close(fd)
            finally:
                os.close(parent)
            self.sampler = Sampler(proc_root, boot_id, process.pid, start, workload_uid,
                                   infrastructure_identities, self.executable, protected_values)
            self.thread = threading.Thread(target=self._run, name='ukai-proc-exposure', daemon=True)
            self.thread.start()
        except (OSError, ValueError, SamplingError):
            self.failure = 'monitor_initialization_failed'
            if self.sampler is not None:
                self.sampler.close()
            self.sampler = None

    def _run(self):
        deadline = time.monotonic_ns()
        try:
            while not self.stop_event.is_set():
                if self.process.poll() is not None:
                    self.exit_observed = time.monotonic_ns()
                    self.reason = 'supervisor_exit'
                    break
                self.sampler.sample(time.monotonic_ns())
                deadline += self.sampler.period
                self.stop_event.wait(max(0, deadline - time.monotonic_ns()) / 1_000_000_000)
        except BaseException:
            self.failure = 'monitor_worker_failed'
            self.reason = 'worker_failed'
        finally:
            self.stopped = time.monotonic_ns()
            if self.abandoned.is_set():
                self.sampler.patterns.clear()
                self.sampler.close()

    def stop(self):
        if self.abandoned.is_set():
            return False
        # Capture the caller's known completion before waking/joining the worker.
        try:
            if self.exit_observed is None and self.process.poll() is not None:
                self.exit_observed = time.monotonic_ns()
                if self.failure is None:
                    self.reason = 'supervisor_exit'
        except Exception:
            self.failure = 'monitor_worker_failed'
            self.reason = 'worker_failed'
        self.stop_event.set()
        if self.thread is not None:
            try:
                self.thread.join(self.JOIN_SECONDS)
            except RuntimeError:
                self.failure = 'monitor_worker_failed'
                self.reason = 'worker_failed'
                self.abandoned.set()
                return False
            if self.thread.is_alive():
                self.abandoned.set()
                self.failure = 'monitor_join_timeout'
                self.reason = 'join_timeout'
                return False
        if self.stopped is None:
            self.stopped = time.monotonic_ns()
        return True

    def finish(self, receipt_bytes, binding):
        joined = self.stop()
        sampler = self.sampler if joined else None
        if sampler is None:
            # This identifies the receipt, not an observed process. Zero ticks,
            # no program observations and the sticky failure make that explicit.
            sampler = Sampler.__new__(Sampler)
            sampler.root = None
            sampler.supervisor = self.supervisor
            sampler.executable = self.executable
            sampler.boot_id, sampler.uid, sampler.period = self.boot_id, self.uid, 100_000_000
            sampler.patterns = list(self.patterns)
            sampler.source_digest = self.source_digest
            sampler._initialize_counts()
            sampler.errors[self.failure or 'monitor_initialization_failed'] += 1
        elif self.failure:
            sampler.errors[self.failure] += 1
        sampler.lifecycle = dict(started_ns=self.started, supervisor_exit_observed_ns=self.exit_observed,
                                 stopped_ns=self.stopped, stop_reason=self.reason)
        try:
            return sampler.finish(receipt_bytes, binding)
        finally:
            self.patterns.clear()
            if self.sampler is not None and (joined or (self.thread is not None and not self.thread.is_alive())):
                self.sampler.patterns.clear()
                self.sampler.close()

    def discard(self):
        joined = self.stop()
        self.patterns.clear()
        if self.sampler is not None and (joined or (self.thread is not None and not self.thread.is_alive())):
            self.sampler.patterns.clear()
            self.sampler.close()
