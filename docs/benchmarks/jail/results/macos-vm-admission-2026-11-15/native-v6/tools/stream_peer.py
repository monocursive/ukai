#!/usr/bin/env python3
"""Bounded synthetic streaming witness, executable with Python 3.9 stdlib.

The private inherited socket is the only control channel. No token is passed
in argv/environment or emitted in diagnostics. This is test tooling, not a
network-policy workaround or an explanation of host connectivity differences.
"""
import argparse
import base64
import hashlib
import http.server
import json
import math
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import time

SCHEMA = 'ukai.vm.stream-peer/1'
CLOCK = 'clock_gettime:CLOCK_MONOTONIC'
MAX_FRAME = 16384
MAX_EVENTS = 80
MAX_REQUESTS = 32
LIFETIME = 480.0


class PeerError(ValueError):
    pass


def clock():
    # Unlike the historical macOS Python 3.9 monotonic() implementation, this
    # explicitly names the same kernel clock in both interpreter processes.
    return time.clock_gettime(time.CLOCK_MONOTONIC)


def require(condition, reason):
    if not condition:
        raise PeerError(reason)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(PeerError('nonfinite_json')))


def receive(channel, timeout):
    deadline = clock() + timeout
    def exact(size):
        data = bytearray()
        while len(data) < size:
            left = deadline - clock()
            require(left > 0, 'frame_timeout')
            channel.settimeout(left)
            chunk = channel.recv(size - len(data))
            if not chunk:
                raise PeerError('control_eof')
            data.extend(chunk)
        return bytes(data)
    size = struct.unpack('!I', exact(4))[0]
    require(0 < size <= MAX_FRAME, 'frame_size')
    value = strict_json(exact(size))
    require(type(value) is dict, 'frame_shape')
    return value


def send(channel, value):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    require(0 < len(data) <= MAX_FRAME, 'frame_size')
    channel.settimeout(2)
    channel.sendall(struct.pack('!I', len(data)) + data)


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, handler):
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(('0.0.0.0', 0), handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            self.fail('connection_limit')
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, *_):
        self.fail('request_error')


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        self.request.settimeout(3)
        super().setup()

    def log_message(self, *_):
        pass

    def do_GET(self):
        server = self.server
        token = self.headers.get('x-test-token', '')
        matches = token == server.secret
        with server.state_lock:
            server.requests += 1
            allowed = server.requests <= MAX_REQUESTS
        if not allowed:
            server.fail('request_limit')
            self.close_connection = True
            return
        server.emit('request', path=self.path if self.path in ('/stream', '/after') else 'other',
                    credential_matches=matches, credential_sha256=hashlib.sha256(token.encode()).hexdigest())
        if self.path != '/stream' or not matches:
            self.send_response(403)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        with server.state_lock:
            if server.accepted:
                server.fail('duplicate_stream')
                return
            server.accepted = True
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        try:
            self.wfile.write(b'5\r\nready\r\n')
            self.wfile.flush()
            server.emit('accepted')
            deadline = clock() + 40
            while not server.stop.is_set() and clock() < deadline:
                ready, _, _ = select.select([self.connection], [], [], .05)
                if ready and self.connection.recv(1, socket.MSG_PEEK) == b'':
                    server.emit('disconnected')
                    break
            else:
                server.emit('expired')
        except (OSError, ValueError):
            server.emit('disconnected')
        finally:
            self.close_connection = True


def child(fd):
    channel = socket.socket(fileno=fd)
    server = None
    write_lock = threading.Lock()
    sequence = 0
    try:
        initial = receive(channel, 5)
        require(set(initial) == {'schema', 'op', 'secret'} and initial['schema'] == SCHEMA
                and initial['op'] == 'initialize', 'initialize_shape')
        raw = base64.b64decode(initial['secret'], validate=True)
        require(16 <= len(raw) <= 1024 and raw.isascii(), 'synthetic_secret_shape')
        require(all(32 < byte < 127 for byte in raw), 'synthetic_secret_shape')
        server = _Server(_Handler)
        server.secret = raw.decode()
        server.stop = threading.Event()
        server.state_lock = threading.Lock()
        server.requests = 0
        server.accepted = False
        def emit(event, **values):
            nonlocal sequence
            with write_lock:
                sequence += 1
                require(sequence <= MAX_EVENTS, 'event_limit')
                send(channel, dict(schema=SCHEMA, event=event, seq=sequence, at=clock(), **values))
        server.emit = emit
        def fail(code):
            server.stop.set()
            emit('error', code=code)
        server.fail = fail
        emit('ready', port=server.server_port, clock=CLOCK,
             executable=sys.executable, version=sys.version, pid=os.getpid())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        deadline = clock() + LIFETIME
        while not server.stop.is_set() and clock() < deadline:
            ready, _, _ = select.select([channel], [], [], .2)
            if not ready:
                continue
            message = receive(channel, 2)
            require(message == {'schema': SCHEMA, 'op': 'stop'}, 'command_shape')
            server.stop.set()
            break
        else:
            fail('peer_lifetime')
        server.stop.set()
        server.shutdown()
        server.server_close()
        # Stopped is the final event, including when cleanup interrupts an
        # unfinished stream or a client has sent only part of its headers.
        # Each worker releases its slot only after its last witness event.
        joined_by = clock() + 3.5
        for _ in range(4):
            require(server.slots.acquire(timeout=max(0, joined_by - clock())), 'request_join_timeout')
        emit('stopped')
        return 0
    except BaseException:
        # Never print exception text: malformed control frames may contain the
        # synthetic value. Parent gets a bounded failure/EOF and fails its row.
        return 1
    finally:
        if server is not None:
            server.stop.set()
            server.server_close()
        channel.close()


def fingerprint(path):
    path = Path(path).resolve(strict=True)
    info = path.stat()
    require(path.is_file() and info.st_size <= 256 * 1024 * 1024, 'interpreter_file')
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


class PeerProcess:
    """StreamWitness/server adapter; source deletion remains in the parent."""
    def __init__(self, interpreter, secret):
        require(Path(interpreter).is_absolute(), 'interpreter_must_be_absolute')
        self.accepted = threading.Event()
        self.finished = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.requests = []
        self.accepted_at = self.deleted_at = self.disconnected_at = None
        self.revocation_sent_at = None
        self.expired = False
        self.errors = []
        self.closed = False
        self.stopped = False
        self.sequence = 0
        self.last_at = None
        self.clock_bracket = None
        self.ready = None
        self.interpreter = fingerprint(interpreter)
        self.helper = fingerprint(__file__)
        self.after = None
        parent, child_socket = socket.socketpair()
        self.channel = parent
        self.process = None
        self.reader = None
        try:
            self.process = subprocess.Popen([self.interpreter['path'], '-I', str(Path(__file__).resolve()),
                '--fd', str(child_socket.fileno())], pass_fds=(child_socket.fileno(),),
                env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}, cwd='/',
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child_socket.close()
            before = clock()
            send(parent, {'schema': SCHEMA, 'op': 'initialize',
                          'secret': base64.b64encode(secret).decode()})
            ready = receive(parent, 5)
            after = clock()
            self._consume(ready, after)
            require(self.ready is not None and before <= ready['at'] <= after, 'clock_bracket')
            self.clock_bracket = {'clock': CLOCK, 'before': before, 'child': ready['at'], 'after': after}
            self.server_address = ('0.0.0.0', ready['port'])
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.reader.start()
        except BaseException:
            child_socket.close()
            self.shutdown()
            raise PeerError('peer_start_failed') from None

    def _consume(self, event, received_at):
        base = {'schema', 'event', 'seq', 'at'}
        kinds = {'ready': {'port', 'clock', 'executable', 'version', 'pid'},
                 'request': {'path', 'credential_matches', 'credential_sha256'},
                 'accepted': set(), 'disconnected': set(), 'expired': set(),
                 'error': {'code'}, 'stopped': set()}
        kind = event.get('event')
        require(kind in kinds and set(event) == base | kinds[kind], 'event_shape')
        require(event['schema'] == SCHEMA and type(event['seq']) is int
                and event['seq'] == self.sequence + 1 <= MAX_EVENTS, 'event_sequence')
        at = event['at']
        require(type(at) in (int, float) and math.isfinite(at) and 0 <= at <= received_at
                and (self.last_at is None or at >= self.last_at), 'event_clock')
        require(not self.stopped and (self.ready is not None or kind == 'ready'), 'event_order')
        self.sequence, self.last_at = event['seq'], at
        if kind == 'ready':
            require(self.ready is None and event['clock'] == CLOCK and type(event['port']) is int
                    and 0 < event['port'] < 65536 and event['pid'] == self.process.pid
                    and type(event['executable']) is str and type(event['version']) is str
                    and len(event['version']) < 1024, 'ready_shape')
            self.ready = event
        elif kind == 'request':
            require(len(self.requests) < MAX_REQUESTS and event['path'] in ('/stream', '/after', 'other')
                    and type(event['credential_matches']) is bool
                    and type(event['credential_sha256']) is str
                    and len(event['credential_sha256']) == 64
                    and all(c in '0123456789abcdef' for c in event['credential_sha256']), 'request_shape')
            self.requests.append({key: event[key] for key in ('path', 'credential_matches', 'credential_sha256', 'at')})
        elif kind == 'accepted':
            require(self.accepted_at is None and len(self.requests) == 1
                    and self.requests[0]['path'] == '/stream'
                    and self.requests[0]['credential_matches'] is True, 'acceptance_order')
            self.accepted_at = at
            self.accepted.set()
        elif kind == 'disconnected':
            require(self.disconnected_at is None, 'duplicate_disconnect')
            self.disconnected_at = at
            self.finished.set()
        elif kind == 'expired':
            require(not self.expired, 'duplicate_expiry')
            self.expired = True
            self.finished.set()
        elif kind == 'error':
            require(event['code'] in ('connection_limit', 'request_error', 'duplicate_stream',
                                      'request_limit', 'peer_lifetime'), 'error_code')
            self.errors.append(event['code'])
        elif kind == 'stopped':
            require(self.stop.is_set(), 'unexpected_stop')
            self.stopped = True

    def _read(self):
        try:
            deadline = clock() + LIFETIME
            while clock() < deadline:
                ready, _, _ = select.select([self.channel], [], [], .2)
                if not ready:
                    continue
                event = receive(self.channel, 2)
                with self.lock:
                    self._consume(event, clock())
                    if self.stopped:
                        return
            raise PeerError('peer_lifetime')
        except (OSError, ValueError, TypeError, KeyError):
            with self.lock:
                self.errors.append('peer_protocol_failed')
                self.expired = True
            self.finished.set()

    def delete_source(self, source):
        with self.lock:
            require(self.accepted.is_set() and not self.errors and self.deleted_at is None,
                    'peer_not_accepted')
            source.unlink()
            self.deleted_at = clock()

    def snapshot(self):
        with self.lock:
            return {'requests': list(self.requests), 'accepted_at': self.accepted_at,
                    'deleted_at': self.deleted_at, 'disconnected_at': self.disconnected_at,
                    'revocation_sent_at': None, 'expired': self.expired}

    def provenance(self):
        return {'schema': SCHEMA, 'mode': 'explicit_subprocess', 'selected_launcher': self.interpreter,
                'identity_scope': 'Selected launcher and helper bytes; Ready runtime path/version are child-reported, not an independently pinned process image.',
                'helper': self.helper, 'ready': self.ready, 'clock_bracket': self.clock_bracket,
                'after': self.after, 'exit_code': None if self.process is None else self.process.poll(),
                'errors': list(self.errors), 'complete': self.closed and self.stopped and not self.errors
                    and self.process is not None and self.process.returncode == 0
                    and self.after == {'selected_launcher': self.interpreter, 'helper': self.helper}}

    def shutdown(self):
        if self.closed:
            return
        self.stop.set()
        try:
            if self.process is not None and self.process.poll() is None:
                send(self.channel, {'schema': SCHEMA, 'op': 'stop'})
                self.process.wait(timeout=4)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.errors.append('peer_shutdown_failed')
        finally:
            if self.process is not None and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=2)
                self.errors.append('peer_killed')
            if self.reader is not None:
                self.reader.join(timeout=2)
                if self.reader.is_alive():
                    self.errors.append('reader_unsettled')
            self.channel.close()
            try:
                self.after = {'selected_launcher': fingerprint(self.interpreter['path']), 'helper': fingerprint(__file__)}
            except (OSError, ValueError):
                self.errors.append('peer_identity_unavailable')
            self.closed = True

    def server_close(self):
        self.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--fd', type=int, required=True)
    raise SystemExit(child(parser.parse_args().fd))
