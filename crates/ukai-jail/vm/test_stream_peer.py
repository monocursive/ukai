"""Real bounded subprocess/HTTP controls; no VM, provider or network changes."""
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

import stream_peer as peer


class PeerProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / 'source'
        self.secret = b'synthetic-independent-stream-value'
        self.source.write_bytes(self.secret)

    def start(self, interpreter=None):
        witness = peer.PeerProcess(interpreter or Path(sys.executable).resolve(), self.secret)
        self.addCleanup(witness.shutdown)
        return witness

    def connect(self, witness, token=None):
        stream = socket.create_connection(('127.0.0.1', witness.server_address[1]), timeout=2)
        self.addCleanup(stream.close)
        token = self.secret.decode() if token is None else token
        stream.sendall(('GET /stream HTTP/1.1\r\nHost: local\r\nx-test-token: ' + token + '\r\n\r\n').encode())
        return stream

    def exercise_stream(self, interpreter=None):
        witness = self.start(interpreter)
        with self.assertRaises(peer.PeerError):
            witness.delete_source(self.source)
        stream = self.connect(witness)
        self.assertTrue(witness.accepted.wait(3))
        self.assertTrue(self.source.exists())
        witness.delete_source(self.source)
        stream.shutdown(socket.SHUT_RDWR); stream.close()
        self.assertTrue(witness.finished.wait(3))
        witness.shutdown()
        facts = witness.snapshot()
        self.assertLess(facts['accepted_at'], facts['deleted_at'])
        self.assertLessEqual(facts['deleted_at'], facts['disconnected_at'])
        self.assertLess(facts['disconnected_at'] - facts['deleted_at'], 3)
        self.assertEqual(len(facts['requests']), 1)
        self.assertEqual(facts['requests'][0]['credential_sha256'], hashlib.sha256(self.secret).hexdigest())
        self.assertFalse(facts['expired'])
        record = witness.provenance()
        self.assertTrue(record['complete'], record)
        bracket = record['clock_bracket']
        self.assertLessEqual(bracket['before'], bracket['child'])
        self.assertLessEqual(bracket['child'], bracket['after'])
        self.assertNotIn(self.secret.decode(), json.dumps([facts, record]))
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', witness.server_address[1]), timeout=.2)

    def test_actual_stream_source_order_clock_and_reaping(self):
        self.exercise_stream()

    @unittest.skipUnless(Path('/Library/Developer/CommandLineTools/usr/bin/python3').exists(),
                         'Apple CLT interpreter is unavailable')
    def test_actual_apple_interpreter_uses_same_bracketed_kernel_clock(self):
        self.exercise_stream(Path('/Library/Developer/CommandLineTools/usr/bin/python3'))

    def test_wrong_header_cannot_authorize_deletion(self):
        witness = self.start()
        stream = self.connect(witness, 'placeholder-not-the-value')
        self.assertIn(b'403', stream.recv(4096))
        stream.close()
        self.assertFalse(witness.accepted.is_set())
        with self.assertRaises(peer.PeerError): witness.delete_source(self.source)
        self.assertTrue(self.source.exists())
        witness.shutdown()
        self.assertTrue(witness.provenance()['complete'])

    def test_partial_request_times_out_without_acceptance(self):
        witness = self.start()
        stream = socket.create_connection(('127.0.0.1', witness.server_address[1]), timeout=5)
        self.addCleanup(stream.close)
        stream.sendall(b'GET /stream HTTP/1.1\r\nHost:')
        started = time.monotonic()
        self.assertEqual(stream.recv(1), b'')
        self.assertLess(time.monotonic() - started, 4.5)
        self.assertFalse(witness.accepted.is_set())
        self.assertEqual(witness.snapshot()['requests'], [])

    def test_killed_child_cannot_leave_a_successful_witness(self):
        witness = self.start()
        witness.process.kill()
        self.assertTrue(witness.finished.wait(2))
        witness.shutdown()
        self.assertIsNotNone(witness.process.poll())
        self.assertFalse(witness.provenance()['complete'])
        self.assertTrue(witness.snapshot()['expired'])

    def test_shutdown_while_streaming_is_bounded_and_not_a_disconnect_proof(self):
        witness = self.start()
        self.connect(witness)
        self.assertTrue(witness.accepted.wait(2))
        started = time.monotonic(); witness.shutdown()
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(witness.snapshot()['expired'])
        self.assertIsNone(witness.snapshot()['deleted_at'])
        self.assertIsNotNone(witness.process.poll())

    def test_wrong_ready_epoch_is_rejected_with_owned_child_reaped(self):
        receive = peer.receive
        created = []
        popen = peer.subprocess.Popen
        def launch(*args, **kwargs):
            child = popen(*args, **kwargs); created.append(child); return child
        def old_clock(*args):
            event = receive(*args); event['at'] = 0; return event
        with mock.patch.object(peer, 'receive', side_effect=old_clock), \
             mock.patch.object(peer.subprocess, 'Popen', side_effect=launch):
            with self.assertRaisesRegex(peer.PeerError, 'peer_start_failed'):
                self.start()
        self.assertEqual(len(created), 1)
        self.assertIsNotNone(created[0].poll())

    def test_unknown_duplicate_and_future_events_refuse(self):
        for mutation in [lambda event: event.update(seq=1),
                         lambda event: event.update(event='unknown'),
                         lambda event: event.update(at=peer.clock() + 100),
                         lambda event: event.update(secret='not permitted'),
                         lambda event: event.update(credential_matches=1)]:
            witness = self.start()
            event = {'schema': peer.SCHEMA, 'seq': 2, 'event': 'request', 'at': peer.clock(),
                     'path': '/stream', 'credential_matches': True,
                     'credential_sha256': hashlib.sha256(self.secret).hexdigest()}
            mutation(event)
            with witness.lock, self.assertRaises((peer.PeerError, TypeError)):
                witness._consume(event, peer.clock())
            witness.shutdown()

    def test_control_frame_bounds_eof_and_duplicate_keys(self):
        duplicate = b'{"x":1,"x":2}'
        for payload in [struct.pack('!I', peer.MAX_FRAME + 1),
                        struct.pack('!I', len(duplicate)) + duplicate, b'\x00']:
            left, right = socket.socketpair()
            try:
                right.sendall(payload); right.shutdown(socket.SHUT_WR)
                with self.assertRaises((peer.PeerError, OSError, ValueError)):
                    peer.receive(left, .2)
            finally:
                left.close(); right.close()

    def test_relative_interpreter_refuses_without_subprocess(self):
        with mock.patch.object(peer.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(peer.PeerError, 'absolute'):
                peer.PeerProcess('python3', self.secret)
            launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
