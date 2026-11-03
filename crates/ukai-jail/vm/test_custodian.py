"""The native custodian's lease (custodian.c), compiled and run against a
stand-in VZ client; never boots a VM.

The custodian kills its VZ client when the caller stops refreshing the
lease for three seconds, on the continuous clock. A suspension of the
custodian itself (SIGSTOP, a host sleep) counts as time on that clock, so
the custodian judges the lease only after reading the heartbeats waiting in
the pipe, and restarts the window after a wake gap; a caller that is really
gone still ends the VM.
"""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).with_name('custodian.c')

STAND_IN_VZ = r'''
import os, sys, time
open(os.environ['VZ_MARKER'], 'w').write(' '.join(sys.argv[1:]))
while True:
    time.sleep(1)
'''


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('clang'),
                     'the custodian is a macOS program (mach continuous time)')
class CustodianLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='ukai-custodian-')
        cls.binary = Path(cls.build.name) / 'custodian'
        subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-O2', str(SOURCE), '-o', str(cls.binary)],
                       check=True, capture_output=True)
        cls.vz = Path(cls.build.name) / 'vz'
        cls.vz.write_text('#!' + sys.executable + '\n' + STAND_IN_VZ)
        cls.vz.chmod(0o700)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def start(self):
        self.lease_read, self.lease_write = os.pipe()
        self.ack_read, ack_write = os.pipe()
        os.set_blocking(self.ack_read, False)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.marker = Path(temporary.name) / 'vz-started'
        argv = [str(self.binary), str(self.lease_read), str(ack_write), str(self.vz),
                'disk', 'seed', 'nvram', 'console', 'run']
        custodian = subprocess.Popen(argv, pass_fds=(self.lease_read, ack_write),
                                     env=dict(os.environ, VZ_MARKER=str(self.marker)))
        os.close(self.lease_read)
        os.close(ack_write)
        self.addCleanup(self.stop, custodian)
        deadline = time.monotonic() + 10
        while not self.marker.exists():
            self.beat()
            if time.monotonic() > deadline or custodian.poll() is not None:
                self.fail('the stand-in VZ client never started')
            time.sleep(.1)
        return custodian

    def stop(self, custodian):
        if custodian.poll() is None:
            custodian.send_signal(signal.SIGCONT)
            custodian.terminate()
            custodian.wait(timeout=10)
        for fd in (self.lease_write, self.ack_read):
            try:
                os.close(fd)
            except OSError:
                pass

    def beat(self):
        os.write(self.lease_write, b'.')

    def beat_for(self, custodian, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.beat()
            time.sleep(.2)
            if custodian.poll() is not None:
                return

    def test_heartbeats_written_while_the_custodian_was_stopped_keep_the_vm(self):
        custodian = self.start()
        custodian.send_signal(signal.SIGSTOP)
        self.beat_for(custodian, 3.6)  # the caller kept refreshing; they wait in the pipe
        custodian.send_signal(signal.SIGCONT)
        self.beat_for(custodian, 1.0)
        self.assertIsNone(custodian.poll(), 'the custodian ended the VM over heartbeats it had not read')

    def test_a_stop_of_custodian_and_caller_together_restarts_the_window(self):
        custodian = self.start()
        custodian.send_signal(signal.SIGSTOP)
        time.sleep(3.6)  # a Ctrl-Z of the whole group: nobody writes
        custodian.send_signal(signal.SIGCONT)
        self.beat_for(custodian, 1.0)
        self.assertIsNone(custodian.poll(), 'the custodian judged a lease it was not awake to watch')

    def test_a_caller_that_stops_refreshing_still_ends_the_vm(self):
        custodian = self.start()
        started = time.monotonic()
        self.assertEqual(custodian.wait(timeout=8), 125)
        self.assertLess(time.monotonic() - started, 4.5)

    def test_a_caller_that_closes_the_lease_ends_the_vm_at_once(self):
        custodian = self.start()
        os.close(self.lease_write)
        started = time.monotonic()
        self.assertEqual(custodian.wait(timeout=5), 125)
        self.assertLess(time.monotonic() - started, 1.0)


if __name__ == '__main__':
    unittest.main()
