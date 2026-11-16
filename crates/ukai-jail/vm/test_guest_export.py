"""Post-stop export over real bounded socketpairs; no VM or provider."""
import base64
import json
import socket
import threading
import time
import unittest

from guest_harness import GuestHarness, complete, hold, load_guest


def wire(value):
    return json.dumps(value, separators=(',', ':')).encode() + b'\n'


class ScriptSocket:
    """Exact partial-write actions with an independently advanced clock."""
    def __init__(self, actions):
        self.actions = iter(actions)
        self.timeout = .25
        self.output = bytearray()
        self.now = 0.0

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value

    def send(self, data):
        elapsed, result = next(self.actions)
        self.now += elapsed
        if isinstance(result, BaseException):
            raise result
        count = len(data) if result is None else min(result, len(data))
        self.output.extend(data[:count])
        return count


class ExportWriterTests(unittest.TestCase):
    def setUp(self):
        self.g = load_guest()
        self.g.clock = time.monotonic
        self.refreshes = []
        self.g.notify = lambda: self.refreshes.append(time.monotonic())

    def sockets(self):
        sender, peer = socket.socketpair()
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        sender.settimeout(.25)
        peer.settimeout(2)
        self.addCleanup(sender.close)
        self.addCleanup(peer.close)
        return sender, peer

    def large_file(self):
        return {'event': 'file', 'group': 'evidence', 'path': 'guest-journal/0000.part',
                'executable': False, 'data': base64.b64encode(b'x' * self.g.MAX_FILE).decode()}

    def test_slow_drain_resumes_exact_frame_and_done_with_watchdog_refresh(self):
        sender, peer = self.sockets()
        self.g.EXPORT_WRITE_SECONDS = 2
        send = self.g.export_sender(sender)
        frames = [self.large_file(), {'event': 'done', 'exit_code': 0}]
        errors = []
        entered = threading.Event()

        def write():
            entered.set()
            try:
                for frame in frames:
                    send(frame)
            except BaseException as error:
                errors.append(error)
            finally:
                sender.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=write)
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            time.sleep(.35)  # Longer than the unchanged receive-poll timeout.
            received = bytearray()
            while chunk := peer.recv(65536):
                received.extend(chunk)
        finally:
            peer.close()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, b''.join(map(wire, frames)))
        self.assertGreater(len(self.refreshes), 2)
        self.assertLess(max(b - a for a, b in zip(self.refreshes, self.refreshes[1:])), .6)
        self.assertEqual(sender.gettimeout(), .25)

    def test_stalled_peer_fails_finitely_and_cannot_append_done(self):
        sender, peer = self.sockets()
        self.g.EXPORT_WRITE_SECONDS = .35
        send = self.g.export_sender(sender)
        frame = self.large_file()
        started = time.monotonic()
        with self.assertRaisesRegex(self.g.Refusal, 'export_write_timeout'):
            send(frame)
        self.assertLess(time.monotonic() - started, 1.5)
        with self.assertRaisesRegex(self.g.Refusal, 'export_transport_failed'):
            send({'event': 'done'})
        sender.shutdown(socket.SHUT_WR)
        partial = bytearray()
        while chunk := peer.recv(65536):
            partial.extend(chunk)
        self.assertTrue(partial)
        self.assertLess(len(partial), len(wire(frame)))
        self.assertEqual(partial, wire(frame)[:len(partial)])
        self.assertNotIn(b'\n', partial)
        self.assertEqual(sender.gettimeout(), .25)

    def test_peer_close_after_partial_write_is_fatal(self):
        sender, peer = self.sockets()
        first = []

        def close_peer():
            first.append(peer.recv(4096))
            peer.close()

        thread = threading.Thread(target=close_peer)
        thread.start()
        send = self.g.export_sender(sender)
        try:
            with self.assertRaises(OSError):
                send(self.large_file())
        finally:
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(first[0])
        self.assertNotIn(b'\n', first[0])
        with self.assertRaisesRegex(self.g.Refusal, 'export_transport_failed'):
            send({'event': 'done'})
        self.assertEqual(sender.gettimeout(), .25)

    def scripted(self, actions, budget=.5):
        sock = ScriptSocket(actions)
        self.g.clock = lambda: sock.now
        self.g.EXPORT_WRITE_SECONDS = budget
        return sock, self.g.export_sender(sock)

    def test_partial_timeout_continues_only_unsent_suffix(self):
        sock, send = self.scripted([(0, 3), (.25, socket.timeout()), (0, 2), (0, None)])
        frame = {'event': 'file', 'data': 'public'}
        send(frame)
        self.assertEqual(sock.output, wire(frame))
        self.assertEqual(sock.timeout, .25)

    def test_one_budget_covers_multiple_frames_and_terminal_done(self):
        sock, send = self.scripted([(.3, None), (.19, 4), (.02, socket.timeout())])
        first, second = {'event': 'file', 'data': 'one'}, {'event': 'file', 'data': 'two'}
        send(first)
        with self.assertRaisesRegex(self.g.Refusal, 'export_write_timeout'):
            send(second)
        with self.assertRaisesRegex(self.g.Refusal, 'export_transport_failed'):
            send({'event': 'done'})
        self.assertEqual(sock.output, wire(first) + wire(second)[:4])
        self.assertEqual(sock.timeout, .25)

        sock, send = self.scripted([(.3, None)])
        send(first)
        sock.now = .5  # Work between frames consumes the same budget.
        with self.assertRaisesRegex(self.g.Refusal, 'export_write_timeout'):
            send({'event': 'done'})
        self.assertEqual(sock.output, wire(first))

    def test_raised_interruption_after_partial_frame_poisons_sender(self):
        sock, send = self.scripted([(0, 4)])
        calls = []

        def interrupted():
            calls.append(True)
            if len(calls) == 2:
                raise KeyboardInterrupt()

        self.g.notify = interrupted
        frame = {'event': 'file', 'data': 'public'}
        with self.assertRaises(KeyboardInterrupt):
            send(frame)
        with self.assertRaisesRegex(self.g.Refusal, 'export_transport_failed'):
            send({'event': 'done'})
        self.assertEqual(sock.output, wire(frame)[:4])
        self.assertEqual(sock.timeout, .25)

    def test_zero_progress_closure_is_fatal_and_restores_original_timeout(self):
        sock, send = self.scripted([(0, 0)])
        sock.timeout = None
        with self.assertRaisesRegex(self.g.Refusal, 'export_transport_closed'):
            send({'event': 'file'})
        self.assertIsNone(sock.timeout)
        self.assertEqual(sock.output, b'')


class ExportSessionTests(unittest.TestCase):
    def test_queued_cancel2_drains_complete_export_done_then_resets_for_next_attempt(self):
        guest = GuestHarness(self, scenarios=[complete(), complete()], start=False)
        original = guest.guest.export_sender
        entered, resume = threading.Event(), threading.Event()
        self.addCleanup(resume.set)
        count = []
        partial = []

        class PausedSocket:
            def __init__(self, conn):
                self.conn = conn

            def __getattr__(self, name):
                return getattr(self.conn, name)

            def send(self, payload):
                if not partial:
                    written = self.conn.send(payload[:5])
                    partial.append(bytes(payload[:written]))
                    entered.set()
                    if not resume.wait(2):
                        raise AssertionError('test never resumed export')
                    return written
                return self.conn.send(payload)

        def sender(conn):
            count.append(True)
            self.assertIn('workload_tree_empty', [name for name, _ in guest.audits])
            return original(PausedSocket(conn))

        guest.guest.export_sender = sender
        guest.thread.start()
        guest.session()
        guest.run2()
        guest.expect('running')
        self.assertTrue(entered.wait(2))
        self.assertEqual(partial, [b'{"eve'])
        guest.send(op='cancel2')
        resume.set()
        cancelled = guest.expect('cancelled')
        events = [frame['event'] for frame in cancelled['_seen']]
        self.assertIn('file', events)
        self.assertEqual(events[-2:], ['done', 'cancelled'])
        guest.run2()
        self.assertEqual(guest.expect('done')['exit_code'], 0)
        self.assertEqual(len(count), 2)

    def test_live_session_control_does_not_use_post_stop_sender(self):
        guest = GuestHarness(self, scenarios=[hold()], start=False)
        guest.guest.export_sender = lambda conn: self.fail('live attempt used export sender')
        guest.thread.start()
        guest.session()
        guest.run2()
        guest.expect('running')
        guest.send(op='ping', sequence=0)
        self.assertEqual(guest.expect('pong')['sequence'], 0)
        guest.send(op='cancel2')
        guest.expect('cancelled')

    def test_legacy_export_keeps_existing_sender(self):
        guest = GuestHarness(self, scenarios=[complete()], start=False)
        guest.guest.export_sender = lambda conn: self.fail('legacy attempt used export sender')
        guest.thread.start()
        guest.expect('ready')
        guest.send(op='run', profile='tool', wall_seconds=30,
                   argv=[base64.b64encode(b'/bin/true').decode()])
        self.assertEqual(guest.expect('done')['exit_code'], 0)
        self.assertEqual(guest.ended(), 'completed')


if __name__ == '__main__':
    unittest.main()
