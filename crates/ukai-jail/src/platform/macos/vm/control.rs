//! The host side of the two sockets (J18): the control client `ukai-jail vm
//! stop` uses, and the attempt connection the `--vm` execution path drives.
//!
//! The module is standalone (standard library only): the `ukai-vm` binary
//! and the stand-in tests include it by path, so both ends of the socket
//! share one definition of a conversation.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use super::protocol::{self, FrameError, FromControl, FromVm, ToControl, ToVm, decode, encode};

/// How long one connect may take before the peer counts as absent.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long one control round trip may take.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one handshake frame (ready, prepared, released) may take: the
/// staging crosses a live guest, not a cold boot, because `ukai-vm serve`
/// binds the attempt socket only after the guest is up.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The sentinel a bounded read returns on: the caller translates it, and it
/// is never a protocol byte sequence.
const IDLE: &str = "\u{0}idle\u{0}";

/// The control socket's path beneath the runtime state directory.
#[must_use]
pub fn control_socket(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("vm").join("control.sock")
}

/// The attempt socket's path beneath the runtime state directory.
#[must_use]
pub fn attempt_socket(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("vm").join("attempt.sock")
}

/// Whether a socket has a live listener: the file alone says nothing, since
/// a killed `ukai-vm` leaves its socket path behind.
pub fn is_listening(path: &Path) -> bool {
    UnixStream::connect(path).is_ok()
}

/// One control request, answered or not.
///
/// # Errors
/// [`FrameError`] (via [`ControlError`]) when the peer is absent, the
/// exchange fails, or the reply is not the protocol's.
#[derive(Debug)]
pub enum ControlError {
    /// No listener answered: no `ukai-vm` is serving this operator.
    Absent,
    /// The exchange failed or the peer left the protocol.
    Failed(FrameError),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::Absent => f.write_str("no ukai-vm is serving this operator"),
            ControlError::Failed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ControlError {}

/// Asks the control socket one thing and reads one reply.
///
/// # Errors
/// [`ControlError::Absent`] when nothing listens (the caller decides what
/// that means: `vm stop` exits 0); [`ControlError::Failed`] for everything
/// else.
pub fn control_round_trip(path: &Path, request: ToControl) -> Result<FromControl, ControlError> {
    let mut stream = UnixStream::connect(path).map_err(|_| ControlError::Absent)?;
    let _ = stream.set_read_timeout(Some(CONTROL_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONTROL_TIMEOUT));
    let line = encode(&request).map_err(ControlError::Failed)?;
    stream.write_all(&line).map_err(|error| {
        ControlError::Failed(FrameError(format!("the control request failed: {error}")))
    })?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).map_err(|error| {
            ControlError::Failed(FrameError(format!("the control reply failed: {error}")))
        })?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.contains(&b'\n') {
            break;
        }
        if buffer.len() > protocol::MAX_FRAME {
            return Err(ControlError::Failed(FrameError(
                "oversized control reply".to_owned(),
            )));
        }
    }
    let line = buffer
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    decode::<FromControl>(line).map_err(ControlError::Failed)
}

/// One attempt connection, and with it the attempt's lease: the peer
/// cancels the guest attempt when this stream ends before `done`.
pub struct AttemptConnection {
    stream: UnixStream,
    buffer: Vec<u8>,
    total: u64,
    eof: bool,
}

/// What one bounded read established.
#[derive(Debug)]
pub enum Within {
    /// One complete frame.
    Frame(FromVm),
    /// The timeout elapsed with the peer silent; the attempt is neither
    /// over nor failed.
    Idle,
    /// The peer closed its end; no further frame can arrive.
    End,
}

impl AttemptConnection {
    /// Connects to the attempt socket.
    ///
    /// # Errors
    /// [`FrameError`] when the socket does not answer.
    pub fn connect(path: &Path) -> Result<Self, FrameError> {
        let stream = UnixStream::connect(path)
            .map_err(|error| FrameError(format!("the attempt socket does not answer: {error}")))?;
        Ok(AttemptConnection {
            stream,
            buffer: Vec::new(),
            total: 0,
            eof: false,
        })
    }

    /// Sends one frame.
    ///
    /// # Errors
    /// [`FrameError`] when the write fails.
    pub fn send(&mut self, frame: &ToVm) -> Result<(), FrameError> {
        let line = encode(frame)?;
        self.stream
            .write_all(&line)
            .map_err(|error| FrameError(format!("the attempt stream failed to write: {error}")))
    }

    /// Half-closes the write side: the lease's end-of-file, which cancels
    /// the guest attempt while leaving the peer free to report the outcome.
    ///
    /// # Errors
    /// The shutdown error; a caller mid-cancellation ignores it.
    pub fn shutdown_write(&self) -> std::io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Write)
    }

    /// Reads one frame, or reports silence or end, within `timeout`.
    ///
    /// # Errors
    /// [`FrameError`] when the stream fails or the peer leaves the
    /// protocol. A peer error frame decodes as [`FromVm::Error`] and is the
    /// caller's to decide on; only the transport itself errors here.
    pub fn next_frame_within(&mut self, timeout: Duration) -> Result<Within, FrameError> {
        match self.next_line(Some(timeout)) {
            Err(error) if error.0 == IDLE => Ok(Within::Idle),
            Err(error) => Err(error),
            Ok(None) => Ok(Within::End),
            Ok(Some(line)) => decode::<FromVm>(&line).map(Within::Frame),
        }
    }

    /// Reads one frame, blocking until the peer answers, ends, or fails:
    /// the handshake's shape, bounded by [`HANDSHAKE_TIMEOUT`].
    ///
    /// # Errors
    /// [`FrameError`] when the stream fails, the peer leaves the protocol,
    /// or it stays silent past the handshake budget.
    pub fn next_frame(&mut self) -> Result<Option<FromVm>, FrameError> {
        match self.next_line(Some(HANDSHAKE_TIMEOUT)) {
            Err(error) if error.0 == IDLE => Err(FrameError(format!(
                "the peer answered no frame within {}s",
                HANDSHAKE_TIMEOUT.as_secs()
            ))),
            Err(error) => Err(error),
            Ok(None) => Ok(None),
            Ok(Some(line)) => decode::<FromVm>(&line).map(Some),
        }
    }

    fn next_line(&mut self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, FrameError> {
        loop {
            if let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let mut line: Vec<u8> = self.buffer.drain(..=position).collect();
                line.pop();
                if line.len() > protocol::MAX_FRAME {
                    return Err(FrameError("oversized frame".to_owned()));
                }
                return Ok(Some(line));
            }
            if self.buffer.len() > protocol::MAX_FRAME {
                return Err(FrameError("oversized frame".to_owned()));
            }
            if self.eof {
                return Ok(None);
            }
            self.stream
                .set_read_timeout(timeout)
                .map_err(|error| FrameError(format!("the attempt stream failed: {error}")))?;
            let mut chunk = [0u8; 16384];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(None);
                }
                Ok(read) => {
                    self.total += read as u64;
                    if self.total > protocol::MAX_TOTAL {
                        return Err(FrameError("total transport limit exceeded".to_owned()));
                    }
                    self.buffer.extend_from_slice(&chunk[..read]);
                }
                // One bounded read's silence is not a failure; the caller
                // decides between idle and expired.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(FrameError(IDLE.to_owned()));
                }
                Err(error) => {
                    return Err(FrameError(format!("the attempt stream failed: {error}")));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// Stands in for `ukai-vm`: answers one control request with a scripted
    /// reply, the Rust form of `test_attempt.py`'s fake custodian.
    struct FakeServer {
        path: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    impl FakeServer {
        fn answering(reply: &'static str) -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("permissions");
            let path = dir.path().join("control.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path).expect("binds");
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buffer = [0u8; 512];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write_all(reply.as_bytes());
                }
            });
            FakeServer { path, _dir: dir }
        }
    }

    #[test]
    fn a_stop_request_is_answered_by_the_scripted_peer() {
        let server = FakeServer::answering(
            "{\"event\":\"stopping\",\"schema\":\"ukai.jail.vm-control/1\"}\n",
        );
        let reply = control_round_trip(&server.path, ToControl::Stop).expect("replies");
        assert_eq!(
            reply,
            FromControl::Stopping {
                schema: protocol::SCHEMA_CONTROL.to_owned(),
            }
        );
    }

    #[test]
    fn an_absent_socket_is_absent_and_not_a_protocol_failure() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("control.sock");
        assert!(matches!(
            control_round_trip(&path, ToControl::Status),
            Err(ControlError::Absent)
        ));
    }

    #[test]
    fn a_peer_that_leaves_the_protocol_is_a_failure_not_absence() {
        let server = FakeServer::answering("not the protocol\n");
        assert!(matches!(
            control_round_trip(&server.path, ToControl::Status),
            Err(ControlError::Failed(_))
        ));
    }

    #[test]
    fn an_attempt_connection_frames_both_directions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("attempt.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("binds");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let read = stream.read(&mut chunk).expect("reads");
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.windows(1).any(|window| window == b"\n") {
                    break;
                }
            }
            let frame = decode::<ToVm>(&buffer).expect("the host spoke the protocol");
            assert_eq!(frame, ToVm::Run);
            let ready = FromVm::Ready {
                schema: protocol::SCHEMA_ATTEMPT.to_owned(),
                boot_id: "boot-1".to_owned(),
                disk_sha256: "d".repeat(64),
                helper_sha256: "h".repeat(64),
                custodian_sha256: "c".repeat(64),
                seed_sha256: "s".repeat(64),
                vsock_port: 1024,
            };
            let line = encode(&ready).expect("encodes");
            stream.write_all(&line).expect("writes");
        });
        let mut connection = AttemptConnection::connect(&path).expect("connects");
        connection.send(&ToVm::Run).expect("sends");
        let frame = connection.next_frame().expect("reads").expect("a frame");
        assert!(matches!(frame, FromVm::Ready { .. }));
    }
}
