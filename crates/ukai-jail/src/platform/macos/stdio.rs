//! jail-v1 §8.3 on the native tier: stdio validation and the relays for
//! regular-file and socket streams.
//!
//! The Linux module (`platform/linux/stdio.rs`) is the reference: the rules
//! and the relay are the same, and the differences are the platform's.
//!
//! - The path behind a descriptor comes from `fcntl(F_GETPATH)`, not
//!   `/proc`. It returns the name as stored on disk, while `realpath` keeps
//!   the case it was given (measured on APFS), so the state root and the
//!   config directory are resolved through `F_GETPATH` too: both sides of
//!   the comparison are the kernel's spelling.
//! - There is no `anon_inode:` class, but a descriptor can have no file
//!   type at all: a POSIX shared-memory object reports type 0 (measured).
//!   Only the known pass-through kinds (pipes, character and block devices)
//!   pass; any other kind refuses, like a descriptor that cannot be
//!   inspected.
//! - Nothing relies on `SIGPIPE` being ignored: socket writes carry
//!   `MSG_NOSIGNAL` and the supervisor's pipe ends are `F_SETNOSIGPIPE`, so
//!   a closed peer is `EPIPE` even where `SIGPIPE` keeps its default.
//! - `MSG_DONTWAIT` is honoured by `recv` but not while a stream `send`
//!   waits for room (measured: a 64 KiB send to an unread socketpair
//!   blocks). Linux's per-call nonblocking writes do not port, so a socket
//!   output origin is written by its own thread ([`SocketWriter`]).
//!
//! Without the relay, a member holds the operator's file itself. It can
//! learn the file's path (`F_GETPATH`), truncate it, and write at any
//! offset. LLVM tools also look up the path behind their standard
//! descriptors: with a file outside the grants, `clang -c` exits 1 without
//! a word. That was measured as the K93 spike build under the production
//! profile. A pipe end has no path and no offset.

use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

/// What the child inherits on one stdio stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StdioPlan {
    /// Passed through untouched: a tty, a pipe, `/dev/null`.
    Pass,
    /// A regular file or socket, relayed through a supervisor-owned pipe.
    Relay { socket: bool },
}

fn invalid_fd(message: String) -> JailError {
    JailError::new(
        ErrorCode::InvalidFd,
        ErrorStage::Preparing,
        Remediation::Configuration,
        message,
    )
}

/// `fcntl` command 73 in `<sys/fcntl.h>`: a write to this pipe end with no
/// reader is `EPIPE`, never `SIGPIPE`.
const F_SETNOSIGPIPE: libc::c_int = 73;

/// The supervisor's standard descriptors, as [`plan_stdio`] inspects them.
pub(super) fn standard_descriptors() -> [BorrowedFd<'static>; 3] {
    // SAFETY: descriptors 0–2 are only inspected and duplicated during
    // preparation; an unopened one fails the fstat in `plan_for` and
    // refuses.
    [0, 1, 2].map(|fd| unsafe { BorrowedFd::borrow_raw(fd) })
}

/// §8.3 and §9.2: reject directory stdio, and regular-file stdio that
/// resolves into protected supervisor state (the whole runtime state root,
/// not only this attempt's directory) or into the operator's trusted config
/// directory. Every other regular file, and every socket, is relayed; pipes
/// and devices pass through untouched. A descriptor that cannot be
/// inspected, or a root that cannot be resolved, refuses rather than
/// passing. In terminal mode the child gets only the relay's pty slave, so
/// the operator's descriptors are not inspected at all.
pub(super) fn plan_stdio(
    terminal: bool,
    fds: [BorrowedFd<'_>; 3],
    state_root: &Path,
    config_dir: &Path,
) -> Result<[StdioPlan; 3], JailError> {
    if terminal {
        return Ok([StdioPlan::Pass; 3]);
    }
    let resolve = |dir: &Path, what: &str| {
        kernel_spelling(dir).map_err(|error| {
            invalid_fd(format!(
                "the {what} cannot be resolved ({error}), so a stdio redirect into it cannot \
                 be ruled out"
            ))
        })
    };
    let state_root = resolve(state_root, "runtime state root")?;
    let config_dir = resolve(config_dir, "config directory")?;
    let mut plans = [StdioPlan::Pass; 3];
    for ((plan, fd), name) in plans.iter_mut().zip(fds).zip(["stdin", "stdout", "stderr"]) {
        *plan =
            plan_for(fd, name, state_root.as_deref(), config_dir.as_deref()).map_err(invalid_fd)?;
    }
    Ok(plans)
}

/// The plan for one descriptor; the message names the refusal.
fn plan_for(
    fd: BorrowedFd<'_>,
    name: &str,
    state_root: Option<&Path>,
    config_dir: Option<&Path>,
) -> Result<StdioPlan, String> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is writable storage for a stat buffer; fstat
    // dereferences nothing else.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(format!(
            "{name} cannot be inspected ({}), so what the child would inherit is unknown",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstat returned 0, so it filled the buffer.
    let kind = unsafe { st.assume_init() }.st_mode & libc::S_IFMT;
    match kind {
        libc::S_IFDIR => Err(format!(
            "{name} is a directory, which a contained run refuses"
        )),
        libc::S_IFSOCK => Ok(StdioPlan::Relay { socket: true }),
        libc::S_IFREG => {
            let target = descriptor_path(fd)
                .map_err(|error| format!("{name} is a file whose path cannot be read ({error})"))?;
            if state_root.is_some_and(|root| target.starts_with(root)) {
                return Err(format!("{name} resolves into the runtime state root"));
            }
            if config_dir.is_some_and(|dir| target.starts_with(dir)) {
                return Err(format!(
                    "{name} resolves into the trusted config directory (config.toml and \
                     launch profiles are trusted input)"
                ));
            }
            Ok(StdioPlan::Relay { socket: false })
        }
        libc::S_IFIFO | libc::S_IFCHR | libc::S_IFBLK => Ok(StdioPlan::Pass),
        other => Err(format!(
            "{name} is a descriptor of an unknown kind (file type {other:#o}, such as a \
             shared-memory object), which a contained run refuses"
        )),
    }
}

/// The kernel's path for an open descriptor (`F_GETPATH`).
fn descriptor_path(fd: BorrowedFd<'_>) -> std::io::Result<PathBuf> {
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most MAXPATHLEN (PATH_MAX) bytes, NUL
    // included, into this buffer.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let len = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);
    Ok(PathBuf::from(OsStr::from_bytes(&buffer[..len])))
}

/// A directory as the kernel spells it; `Ok(None)` when it does not exist,
/// since nothing can resolve into it then. It is opened for search only
/// (`O_SEARCH`), so a root the operator cannot list still resolves, and
/// nonblocking, so a FIFO planted at the path cannot stall preparation.
fn kernel_spelling(dir: &Path) -> std::io::Result<Option<PathBuf>> {
    let path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: a NUL-terminated path; these flags take no mode argument.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_SEARCH | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return match error.kind() {
            std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(error),
        };
    }
    // SAFETY: open returned a new descriptor, owned from here.
    let dir = unsafe { OwnedFd::from_raw_fd(fd) };
    descriptor_path(dir.as_fd()).map(Some)
}

/// One relayed stdio stream: the child holds one end of a supervisor-owned
/// pipe, and the supervisor copies between the pipe and the operator's
/// original descriptor, which keeps its open mode and offset.
pub(super) struct StdioRelay {
    /// A duplicate of the operator's descriptor, taken at preparation, before
    /// the supervisor points its own stdout elsewhere (§8.3).
    origin: OwnedFd,
    /// A socket origin is read with per-call nonblocking `recv`, without
    /// changing the shared descriptor's flags.
    origin_socket: bool,
    /// The writer of a socket output origin; `None` otherwise.
    writer: Option<SocketWriter>,
    /// This side of the pipe, nonblocking; `None` once closed.
    ours: Option<OwnedFd>,
    /// `true` for stdin (origin → child); `false` for stdout/stderr.
    to_child: bool,
    /// Staged bytes between the two sides, bounded by [`RELAY_BUFFER`].
    buffer: Vec<u8>,
    /// The origin reached end-of-file (stdin direction).
    origin_eof: bool,
    /// Nothing more to move from the pipe side.
    finished: bool,
}

/// The staging bound per relayed stream: one pipe capacity.
const RELAY_BUFFER: usize = 1 << 16;

/// Once the tree has ended, relayed output drains for as long as it keeps
/// moving (jail-v1 §8.3): the drain gives up when no byte has moved for
/// this long, so a reader that stopped costs no more than before…
pub(super) const OUTPUT_DRAIN_IDLE: Duration = Duration::from_millis(250);

/// …and in any case this long after it began, so a reader that keeps
/// trickling cannot hold the settlement indefinitely.
pub(super) const OUTPUT_DRAIN_CAP: Duration = Duration::from_secs(10);

/// What a socket writer sends per call, so its progress is visible to the
/// drain at this granularity instead of once per staged chunk.
const WRITER_SLICE: usize = 8 * 1024;

impl StdioRelay {
    /// The relay for standard descriptor `fd`, and the pipe end the child
    /// gets in its place. Both pipe ends are close-on-exec: the guardian's
    /// spawn inherits the child's end by an explicit list.
    pub(super) fn attach(fd: RawFd, socket: bool) -> Result<(Self, OwnedFd), JailError> {
        let to_child = fd == 0;
        let (read_end, write_end) = pipe().map_err(|error| {
            invalid_fd(format!(
                "a stdio stream could not be relayed through a pipe: {error}"
            ))
        })?;
        let (child_end, ours) = if to_child {
            (read_end, write_end)
        } else {
            (write_end, read_end)
        };
        // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor or -1, checked
        // before it is owned.
        let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duped < 0 {
            return Err(invalid_fd(
                "the operator's stdio descriptor could not be kept for the relay".to_owned(),
            ));
        }
        // SAFETY: `duped` was just created and is owned here.
        let origin = unsafe { OwnedFd::from_raw_fd(duped) };
        set_nonblocking(ours.as_fd())
            .and_then(|()| no_sigpipe(ours.as_fd()))
            .map_err(|error| {
                invalid_fd(format!(
                    "a stdio relay pipe could not be configured: {error}"
                ))
            })?;
        let writer = (socket && !to_child)
            .then(|| SocketWriter::start(&origin))
            .transpose()
            .map_err(|error| {
                invalid_fd(format!(
                    "a socket stdio stream could not get its writer: {error}"
                ))
            })?;
        Ok((
            Self {
                origin,
                origin_socket: socket,
                writer,
                ours: Some(ours),
                to_child,
                buffer: Vec::with_capacity(RELAY_BUFFER),
                origin_eof: false,
                finished: false,
            },
            child_end,
        ))
    }

    /// Move as much as both sides accept right now; `true` when anything
    /// moved. Regular-file I/O completes within one buffer; pipe and socket
    /// operations never block, and a socket output origin's sends happen on
    /// its writer's thread.
    fn pump(&mut self) -> std::io::Result<bool> {
        let mut progress = false;
        if self.to_child {
            while !self.origin_eof && self.buffer.len() < RELAY_BUFFER {
                if !origin_ready(self.origin.as_fd(), true) {
                    break;
                }
                let mut chunk = [0u8; RELAY_BUFFER];
                let room = RELAY_BUFFER - self.buffer.len();
                let read = match relay_read(
                    self.origin.as_raw_fd(),
                    &mut chunk[..room],
                    self.origin_socket,
                ) {
                    Ok(read) => read,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                };
                if read == 0 {
                    self.origin_eof = true;
                    break;
                }
                self.buffer.extend_from_slice(&chunk[..read]);
                progress = true;
            }
            if !self.buffer.is_empty()
                && let Some(ours) = self.ours.as_ref()
            {
                match relay_write(ours.as_raw_fd(), &self.buffer) {
                    Ok(written) => {
                        self.buffer.drain(..written);
                        progress = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                        // A child may legitimately stop consuming stdin.
                        self.buffer.clear();
                        self.origin_eof = true;
                    }
                    Err(error) => return Err(error),
                }
            }
            if self.origin_eof && self.buffer.is_empty() {
                // Closing this side gives the child its end-of-file.
                self.ours = None;
                self.finished = true;
            }
        } else {
            while let Some(ours) = self.ours.as_ref() {
                if self.buffer.len() >= RELAY_BUFFER {
                    break;
                }
                let mut chunk = [0u8; RELAY_BUFFER];
                let room = RELAY_BUFFER - self.buffer.len();
                let read = match relay_read(ours.as_raw_fd(), &mut chunk[..room], false) {
                    Ok(read) => read,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                };
                if read == 0 {
                    self.ours = None;
                    self.finished = true;
                    break;
                }
                self.buffer.extend_from_slice(&chunk[..read]);
                progress = true;
            }
            if let Some(writer) = self.writer.as_mut() {
                writer.clear_wake();
                if let Some(error) = writer.failure() {
                    return Err(error);
                }
                progress |= writer.delivered_since_last_look();
                progress |= writer.offer(&mut self.buffer);
            } else if !self.buffer.is_empty() && origin_ready(self.origin.as_fd(), false) {
                match relay_write(self.origin.as_raw_fd(), &self.buffer) {
                    Ok(written) => {
                        self.buffer.drain(..written);
                        progress = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(progress)
    }

    /// Output bytes not yet written to the origin: staged here, or held by
    /// the socket writer.
    fn undelivered(&self) -> usize {
        self.buffer.len() + self.writer.as_ref().map_or(0, SocketWriter::in_flight)
    }

    /// Whether both sides are done and nothing is staged.
    fn done(&self) -> bool {
        self.finished && self.undelivered() == 0
    }
}

/// The writer of a socket output origin. macOS does not honour
/// `MSG_DONTWAIT` while a stream send waits for room, and libuv parents hand
/// their children socketpairs as stdout and stderr, so a slow reader would
/// block the supervision loop. Setting `O_NONBLOCK` would change the
/// operator's shared descriptor, which §8.3 keeps as it is. This thread does
/// the blocking sends instead: the loop hands it one chunk at a time and
/// never waits on it. Once the relay is dropped the thread sends nothing
/// past its current slice; a thread still blocked in that slice when the
/// supervisor exits ends with the process, and the bytes it held were
/// reported undelivered.
struct SocketWriter {
    /// Dropping the sender (and marking the writer abandoned) ends the
    /// thread after its current slice.
    queue: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    shared: Arc<WriterShared>,
    /// The read end of a pipe the thread writes a byte to whenever a slice
    /// is sent or a send fails, so a drain waiting in `poll` wakes for it.
    wake: OwnedFd,
    /// `in_flight` when the loop last looked: a smaller value since is
    /// delivery.
    seen: usize,
}

#[derive(Default)]
struct WriterShared {
    /// Bytes handed to the thread and not yet written.
    in_flight: AtomicUsize,
    /// The send failure that ended the thread.
    failure: Mutex<Option<std::io::Error>>,
    /// The relay is gone: what the drain gave up on is not sent after it,
    /// beyond the slice already being sent.
    abandoned: AtomicBool,
}

impl SocketWriter {
    fn start(origin: &OwnedFd) -> std::io::Result<Self> {
        let socket = origin.try_clone()?;
        let (wake, wake_write) = pipe()?;
        set_nonblocking(wake.as_fd())?;
        // The thread never blocks on a wake: a full pipe has woken already.
        set_nonblocking(wake_write.as_fd())?;
        no_sigpipe(wake_write.as_fd())?;
        let (queue, chunks) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        let shared = Arc::new(WriterShared::default());
        let thread = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("ukai-stdio-socket".to_owned())
            .spawn(move || {
                for chunk in chunks {
                    for slice in chunk.chunks(WRITER_SLICE) {
                        if thread.abandoned.load(Ordering::Acquire) {
                            return;
                        }
                        if let Err(error) = send_all(socket.as_fd(), slice) {
                            if let Ok(mut failure) = thread.failure.lock() {
                                *failure = Some(error);
                            }
                            let _ = relay_write(wake_write.as_raw_fd(), &[1]);
                            return;
                        }
                        thread.in_flight.fetch_sub(slice.len(), Ordering::AcqRel);
                        let _ = relay_write(wake_write.as_raw_fd(), &[1]);
                    }
                }
            })?;
        Ok(Self {
            queue: Some(queue),
            shared,
            wake,
            seen: 0,
        })
    }

    /// Whether the thread delivered bytes since the loop last looked.
    fn delivered_since_last_look(&mut self) -> bool {
        let in_flight = self.in_flight();
        let delivered = in_flight < self.seen;
        self.seen = in_flight;
        delivered
    }

    fn in_flight(&self) -> usize {
        self.shared.in_flight.load(Ordering::Acquire)
    }

    /// The failure that ended the thread, as often as it is asked for.
    fn failure(&self) -> Option<std::io::Error> {
        let failure = self.shared.failure.lock().ok()?;
        failure.as_ref().map(|error| {
            error.raw_os_error().map_or_else(
                || std::io::Error::new(error.kind(), error.to_string()),
                std::io::Error::from_raw_os_error,
            )
        })
    }

    /// Hands the staged bytes to the thread when it holds none; `true` when
    /// it took them.
    fn offer(&mut self, staged: &mut Vec<u8>) -> bool {
        if staged.is_empty() || self.in_flight() > 0 {
            return false;
        }
        let Some(queue) = self.queue.as_ref() else {
            return false;
        };
        let chunk = std::mem::replace(staged, Vec::with_capacity(RELAY_BUFFER));
        self.shared.in_flight.store(chunk.len(), Ordering::Release);
        self.seen = chunk.len();
        match queue.try_send(chunk) {
            Ok(()) => true,
            // The thread exited (its failure is reported on the next pump)
            // or has not taken the previous chunk: keep the bytes staged.
            Err(
                std::sync::mpsc::TrySendError::Full(chunk)
                | std::sync::mpsc::TrySendError::Disconnected(chunk),
            ) => {
                self.shared.in_flight.store(0, Ordering::Release);
                self.seen = 0;
                *staged = chunk;
                false
            }
        }
    }

    fn clear_wake(&self) {
        let mut sink = [0u8; 64];
        while relay_read(self.wake.as_raw_fd(), &mut sink, false).is_ok_and(|read| read > 0) {}
    }
}

impl Drop for SocketWriter {
    fn drop(&mut self) {
        self.shared.abandoned.store(true, Ordering::Release);
        self.queue = None;
    }
}

/// Writes all of `chunk` to a socket, waiting as long as it takes: this runs
/// only on a [`SocketWriter`] thread. An operator socket that is itself
/// nonblocking is waited for with `poll`.
fn send_all(socket: BorrowedFd<'_>, mut chunk: &[u8]) -> std::io::Result<()> {
    while !chunk.is_empty() {
        // SAFETY: send reads only from this live slice.
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                chunk.as_ptr().cast(),
                chunk.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent > 0 {
            chunk = &chunk[sent.unsigned_abs()..];
            continue;
        }
        if sent == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::Interrupted => {}
            std::io::ErrorKind::WouldBlock => {
                let mut wait = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: one live pollfd; this thread may wait indefinitely.
                unsafe { libc::poll(&raw mut wait, 1, -1) };
            }
            _ => return Err(error),
        }
    }
    Ok(())
}

/// Visit every stream, including when an earlier one failed or moved bytes;
/// the first failure is returned after all were visited.
pub(super) fn pump_stdio_relays(relays: &mut [StdioRelay]) -> std::io::Result<bool> {
    let mut progress = false;
    let mut failure = None;
    for relay in relays {
        match relay.pump() {
            Ok(moved) => progress |= moved,
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    failure.map_or(Ok(progress), Err)
}

/// Delivers what the child wrote through the output relays for as long as
/// it keeps moving: until every output stream has ended, until `idle`
/// passes with no byte moved, or until `cap` after the start, whichever
/// comes first. Then it names what could not be delivered. Only output
/// relays are waited for: a stdin relay finishes only at its origin's
/// end-of-file, which the tree's end does not bring. A pass that moves
/// nothing waits in `poll`.
pub(super) fn drain_output_relays(
    relays: &mut Vec<StdioRelay>,
    idle: Duration,
    cap: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    let cap_at = started + cap;
    let mut idle_at = started + idle;
    loop {
        let progress = match pump_stdio_relays(relays) {
            Ok(progress) => progress,
            Err(error) => {
                relays.clear();
                return Err(format!("a stdio relay failed: {error}"));
            }
        };
        let mut waits = output_waits(relays);
        let now = Instant::now();
        if progress {
            idle_at = now + idle;
        }
        let deadline = idle_at.min(cap_at);
        if waits.is_empty() || now >= deadline {
            break;
        }
        if !progress {
            let millis = deadline.saturating_duration_since(now).as_millis();
            let timeout = i32::try_from(millis).unwrap_or(i32::MAX).max(1);
            // SAFETY: `waits` is a live, correctly sized pollfd array.
            let ready = unsafe {
                libc::poll(
                    waits.as_mut_ptr(),
                    libc::nfds_t::try_from(waits.len()).unwrap_or(libc::nfds_t::MAX),
                    timeout,
                )
            };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    relays.clear();
                    return Err(format!("a stdio relay could not wait: {error}"));
                }
            }
        }
    }
    if relays
        .iter()
        .any(|relay| !relay.to_child && relay.undelivered() > 0)
    {
        relays.clear();
        let why = if Instant::now() >= cap_at {
            format!(
                "the {} s limit after the tree's end passed",
                cap.as_secs_f32()
            )
        } else {
            format!("no byte moved for {} ms", idle.as_millis())
        };
        return Err(format!("a stdio relay could not drain its output: {why}"));
    }
    Ok(())
}

/// What an unfinished output relay waits for: its pipe to be readable while
/// there is room to stage, and its origin to be writable while bytes are
/// staged, or its socket writer's wake while the writer holds bytes. A
/// closed pipe end reports `POLLHUP`, which wakes the wait too.
fn output_waits(relays: &[StdioRelay]) -> Vec<libc::pollfd> {
    let mut waits = Vec::new();
    for relay in relays
        .iter()
        .filter(|relay| !relay.to_child && !relay.done())
    {
        if let Some(ours) = relay.ours.as_ref()
            && relay.buffer.len() < RELAY_BUFFER
        {
            waits.push(libc::pollfd {
                fd: ours.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if let Some(writer) = relay.writer.as_ref() {
            if writer.in_flight() > 0 {
                waits.push(libc::pollfd {
                    fd: writer.wake.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
        } else if !relay.buffer.is_empty() {
            waits.push(libc::pollfd {
                fd: relay.origin.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            });
        }
    }
    waits
}

/// Whether a relay origin is ready to read (`for_read`) or write right now,
/// asked with a zero-timeout poll so a socket origin never blocks the loop.
/// A regular file is always ready.
fn origin_ready(fd: BorrowedFd<'_>, for_read: bool) -> bool {
    let events = if for_read {
        libc::POLLIN
    } else {
        libc::POLLOUT
    };
    let mut wait = libc::pollfd {
        fd: fd.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: one live pollfd, zero timeout.
    let ready = unsafe { libc::poll(&raw mut wait, 1, 0) };
    ready > 0 && wait.revents & (libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0
}

fn relay_read(fd: RawFd, buffer: &mut [u8], socket: bool) -> std::io::Result<usize> {
    loop {
        // SAFETY: read writes only into this live writable slice.
        let read = unsafe {
            if socket {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            } else {
                libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len())
            }
        };
        if read >= 0 {
            return Ok(read.unsigned_abs());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// One write to a pipe or a regular file (a socket origin goes through its
/// [`SocketWriter`]).
fn relay_write(fd: RawFd, buffer: &[u8]) -> std::io::Result<usize> {
    loop {
        // SAFETY: write reads only from this live slice.
        let written = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
        if written > 0 {
            return Ok(written.unsigned_abs());
        }
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// A pipe, both ends close-on-exec (Darwin has no `pipe2`; every native
/// spawn uses `POSIX_SPAWN_CLOEXEC_DEFAULT` with an explicit inheritance
/// list, so the window before the flag is set is never a fork window).
fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid out array for `pipe`.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe returned two new descriptors, owned from here.
    let ends = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in fds {
        // SAFETY: F_SETFD takes scalars and dereferences nothing.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(ends)
}

/// A write to this pipe end with no reader fails with `EPIPE` instead of
/// raising `SIGPIPE`.
fn no_sigpipe(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    // SAFETY: F_SETNOSIGPIPE takes scalars and dereferences nothing.
    if unsafe { libc::fcntl(fd.as_raw_fd(), F_SETNOSIGPIPE, 1) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_nonblocking(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    // SAFETY: F_GETFL takes a descriptor number and dereferences nothing.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: F_SETFL takes scalars and dereferences nothing.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Seek as _, Write as _};

    use super::*;

    struct Roots {
        _dir: tempfile::TempDir,
        root: PathBuf,
        state: PathBuf,
        config: PathBuf,
    }

    fn roots() -> Roots {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let state = root.join("Data");
        let config = root.join("Config");
        std::fs::create_dir_all(state.join("attempts/one")).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        Roots {
            _dir: dir,
            root,
            state,
            config,
        }
    }

    /// The plan for one descriptor offered as stdout, through the production
    /// entry point (stdin and stderr are `/dev/null`).
    fn plan_stdout(
        fd: BorrowedFd<'_>,
        state: &Path,
        config: &Path,
    ) -> Result<StdioPlan, JailError> {
        let null = std::fs::File::open("/dev/null").unwrap();
        plan_stdio(false, [null.as_fd(), fd, null.as_fd()], state, config).map(|plans| {
            assert_eq!(plans[0], StdioPlan::Pass);
            assert_eq!(plans[2], StdioPlan::Pass);
            plans[1]
        })
    }

    fn refusal(result: Result<StdioPlan, JailError>) -> String {
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidFd);
        assert_eq!(error.stage, ErrorStage::Preparing);
        assert_eq!(error.remediation, Remediation::Configuration);
        error.message
    }

    /// An output relay over an existing origin, as `attach` builds it.
    fn output_relay(origin: OwnedFd, socket: bool) -> (StdioRelay, OwnedFd) {
        let (ours, child) = pipe().unwrap();
        set_nonblocking(ours.as_fd()).unwrap();
        let writer = socket.then(|| SocketWriter::start(&origin).unwrap());
        (
            StdioRelay {
                origin,
                origin_socket: socket,
                writer,
                ours: Some(ours),
                to_child: false,
                buffer: Vec::new(),
                origin_eof: false,
                finished: false,
            },
            child,
        )
    }

    /// An input relay over an existing origin; the child reads the first end.
    fn input_relay(origin: OwnedFd, socket: bool) -> (StdioRelay, OwnedFd) {
        let (child, ours) = pipe().unwrap();
        set_nonblocking(ours.as_fd()).unwrap();
        no_sigpipe(ours.as_fd()).unwrap();
        (
            StdioRelay {
                origin,
                origin_socket: socket,
                writer: None,
                ours: Some(ours),
                to_child: true,
                buffer: Vec::new(),
                origin_eof: false,
                finished: false,
            },
            child,
        )
    }

    #[test]
    fn stdio_kinds_are_planned_as_on_linux() {
        let roots = roots();
        let file = std::fs::File::create(roots.root.join("out.log")).unwrap();
        assert_eq!(
            plan_stdout(file.as_fd(), &roots.state, &roots.config).unwrap(),
            StdioPlan::Relay { socket: false }
        );
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            plan_stdout(socket.as_fd(), &roots.state, &roots.config).unwrap(),
            StdioPlan::Relay { socket: true }
        );
        let (read_end, _write_end) = pipe().unwrap();
        assert_eq!(
            plan_stdout(read_end.as_fd(), &roots.state, &roots.config).unwrap(),
            StdioPlan::Pass
        );
        let directory = std::fs::File::open(&roots.root).unwrap();
        let message = refusal(plan_stdout(directory.as_fd(), &roots.state, &roots.config));
        assert!(message.contains("stdout is a directory"), "{message}");
    }

    /// Terminal mode inspects nothing: the child gets only the pty slave.
    #[test]
    fn terminal_mode_inspects_no_operator_descriptor() {
        let roots = roots();
        let directory = std::fs::File::open(&roots.root).unwrap();
        let fds = [directory.as_fd(); 3];
        assert_eq!(
            plan_stdio(true, fds, &roots.state, &roots.config).unwrap(),
            [StdioPlan::Pass; 3]
        );
        assert!(plan_stdio(false, fds, &roots.state, &roots.config).is_err());
    }

    /// A descriptor that cannot be inspected, or that has no known kind (a
    /// POSIX shared-memory object reports file type 0), refuses.
    #[test]
    fn uninspectable_and_unknown_descriptors_refuse() {
        let roots = roots();
        // SAFETY: a descriptor number this test never opens; fstat on it is
        // EBADF.
        let closed = unsafe { BorrowedFd::borrow_raw(9_999) };
        let message = refusal(plan_stdout(closed, &roots.state, &roots.config));
        assert!(message.contains("cannot be inspected"), "{message}");

        let name = CString::new(format!("/ukai-stdio-{}", std::process::id())).unwrap();
        // SAFETY: a NUL-terminated name; the mode is the variadic argument.
        let shm = unsafe {
            libc::shm_open(
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600 as libc::c_uint,
            )
        };
        assert!(shm >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: shm_open returned a new descriptor, owned from here.
        let shm = unsafe { OwnedFd::from_raw_fd(shm) };
        // SAFETY: the name created above.
        unsafe { libc::shm_unlink(name.as_ptr()) };
        let message = refusal(plan_stdout(shm.as_fd(), &roots.state, &roots.config));
        assert!(message.contains("unknown kind"), "{message}");
    }

    /// A regular file whose path the kernel cannot report refuses rather
    /// than relaying unchecked: `F_GETPATH` past `MAXPATHLEN` is `ENOSPC`.
    #[test]
    fn a_file_whose_path_cannot_be_read_refuses() {
        let roots = roots();
        let component = CString::new("d".repeat(200)).unwrap();
        // SAFETY: a NUL-terminated path; these flags take no mode argument.
        let mut dir = unsafe {
            let path = CString::new(roots.root.as_os_str().as_bytes()).unwrap();
            OwnedFd::from_raw_fd(libc::open(path.as_ptr(), libc::O_SEARCH | libc::O_CLOEXEC))
        };
        for _ in 0..6 {
            // SAFETY: a live directory descriptor and a NUL-terminated name.
            unsafe {
                assert_eq!(libc::mkdirat(dir.as_raw_fd(), component.as_ptr(), 0o700), 0);
                let next = libc::openat(
                    dir.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_SEARCH | libc::O_CLOEXEC,
                );
                assert!(next >= 0);
                dir = OwnedFd::from_raw_fd(next);
            }
        }
        let leaf = CString::new("out.log").unwrap();
        // SAFETY: a live directory descriptor, a NUL-terminated name and the
        // variadic mode.
        let file = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        assert!(file >= 0);
        // SAFETY: openat returned a new descriptor, owned from here.
        let file = unsafe { OwnedFd::from_raw_fd(file) };
        let message = refusal(plan_stdout(file.as_fd(), &roots.state, &roots.config));
        assert!(message.contains("path cannot be read"), "{message}");
    }

    /// A redirect into any attempt's state, or into the trusted config,
    /// refuses; so does the same path when the root is spelled in another
    /// case, which APFS resolves to the same directory.
    #[test]
    fn redirects_into_state_or_config_refuse_in_any_case_spelling() {
        let roots = roots();
        let receipt = roots.state.join("attempts/one/receipt.json");
        let config = roots.config.join("config.toml");
        for path in [&receipt, &config] {
            let file = std::fs::File::create(path).unwrap();
            let message = refusal(plan_stdout(file.as_fd(), &roots.state, &roots.config));
            assert!(message.contains("resolves into"), "{message}");
        }
        let file = std::fs::File::open(&receipt).unwrap();
        let shouted = PathBuf::from(roots.state.to_str().unwrap().to_uppercase());
        if shouted.exists() {
            let message = refusal(plan_stdout(file.as_fd(), &shouted, &roots.config));
            assert!(message.contains("state root"), "{message}");
        } else {
            eprintln!("case-sensitive volume: the case-spelling row is unexercised");
        }
        // A sibling whose name only extends the root's is not inside it.
        let sibling = roots.root.join("DataX");
        std::fs::create_dir_all(&sibling).unwrap();
        let file = std::fs::File::create(sibling.join("out.log")).unwrap();
        assert_eq!(
            plan_stdout(file.as_fd(), &roots.state, &roots.config).unwrap(),
            StdioPlan::Relay { socket: false }
        );
    }

    /// A root the operator may search but not list still protects what is
    /// in it; a root that is missing protects nothing and refuses nothing;
    /// a root that cannot be resolved refuses.
    #[test]
    fn roots_resolve_by_search_and_an_unresolvable_root_refuses() {
        use std::os::unix::fs::PermissionsExt as _;
        let roots = roots();
        let config = roots.config.join("config.toml");
        std::fs::write(&config, b"").unwrap();
        let file = std::fs::File::open(&config).unwrap();
        std::fs::set_permissions(&roots.config, std::fs::Permissions::from_mode(0o311)).unwrap();
        let searched = plan_stdout(file.as_fd(), &roots.state, &roots.config);
        std::fs::set_permissions(&roots.config, std::fs::Permissions::from_mode(0o700)).unwrap();
        let message = refusal(searched);
        assert!(message.contains("config directory"), "{message}");

        let outside = std::fs::File::create(roots.root.join("out.log")).unwrap();
        assert_eq!(
            plan_stdout(outside.as_fd(), &roots.root.join("missing"), &roots.config).unwrap(),
            StdioPlan::Relay { socket: false }
        );
        let not_a_dir = roots.root.join("out.log");
        let message = refusal(plan_stdout(outside.as_fd(), &roots.state, &not_a_dir));
        assert!(message.contains("cannot be resolved"), "{message}");
    }

    /// Output reaches the operator's file at its own offset, and the child's
    /// close lets the drain finish well inside the budget.
    #[test]
    fn output_is_delivered_to_the_operators_file_and_finishes() {
        let roots = roots();
        let path = roots.root.join("out.log");
        let mut operator = std::fs::File::create(&path).unwrap();
        operator.write_all(b"before\n").unwrap();
        // Any descriptor but 0 is an output stream.
        let (relay, child_end) = StdioRelay::attach(operator.as_raw_fd(), false).unwrap();
        assert!(!relay.to_child);
        let mut relays = vec![relay];
        let mut child = std::fs::File::from(child_end);
        child.write_all(b"from the child\n").unwrap();
        drop(child);
        let started = Instant::now();
        drain_output_relays(&mut relays, OUTPUT_DRAIN_IDLE, OUTPUT_DRAIN_CAP).unwrap();
        assert!(started.elapsed() < OUTPUT_DRAIN_IDLE);
        assert!(relays[0].done());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "before\nfrom the child\n"
        );
    }

    /// The stdin direction copies the operator's file to the child and closes
    /// the child's end at the file's end.
    #[test]
    fn input_reaches_the_child_and_ends_with_the_file() {
        let roots = roots();
        let path = roots.root.join("in.txt");
        std::fs::write(&path, b"input bytes").unwrap();
        let operator = std::fs::File::open(&path).unwrap();
        let (relay, child_end) = input_relay(operator.into(), false);
        let mut relays = vec![relay];
        let mut child = std::fs::File::from(child_end);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !relays[0].done() && Instant::now() < deadline {
            pump_stdio_relays(&mut relays).unwrap();
        }
        let mut received = String::new();
        child.read_to_string(&mut received).unwrap();
        assert_eq!(received, "input bytes");
    }

    /// A child that stops reading stdin ends the stdin stream; it is not a
    /// relay failure, and no `SIGPIPE` reaches the supervisor.
    #[test]
    fn a_child_that_closes_stdin_ends_the_stream_quietly() {
        let roots = roots();
        let path = roots.root.join("in.txt");
        std::fs::write(&path, vec![b'x'; 4 * RELAY_BUFFER]).unwrap();
        let (mut relay, child_end) = input_relay(std::fs::File::open(&path).unwrap().into(), false);
        drop(child_end);
        assert!(relay.pump().is_ok());
        assert!(
            relay.done(),
            "the stdin stream ends when the child stops reading"
        );
    }

    /// An input error is a failure, not the end of the input.
    #[test]
    fn relay_input_errors_are_not_eof() {
        let roots = roots();
        let origin = std::fs::File::create(roots.root.join("write-only")).unwrap();
        let (mut relay, _child) = input_relay(origin.into(), false);
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert!(!relay.origin_eof);
    }

    /// An output error keeps the bytes it could not deliver.
    #[test]
    fn relay_output_errors_preserve_undelivered_bytes() {
        let roots = roots();
        let path = roots.root.join("read-only");
        std::fs::write(&path, b"original").unwrap();
        let (mut relay, writer) = output_relay(std::fs::File::open(&path).unwrap().into(), false);
        relay_write(writer.as_raw_fd(), b"undelivered").unwrap();
        drop(writer);
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert_eq!(relay.buffer, b"undelivered");
        assert!(!relay.done());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }

    /// A socket origin whose peer does not read never blocks the relay, and
    /// its shared flags are left as the operator set them.
    #[test]
    fn blocking_socket_output_retains_backpressure_without_blocking_the_relay() {
        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: a live socket and a correctly sized, initialized option.
        let set = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const size).cast(),
                libc::socklen_t::try_from(std::mem::size_of_val(&size)).unwrap(),
            )
        };
        assert_eq!(set, 0);
        let (mut relay, writer) = output_relay(socket.into(), true);
        relay.buffer = vec![b'x'; RELAY_BUFFER];
        drop(writer);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            tx.send((relay.pump(), relay)).unwrap();
        });
        let Ok((result, mut relay)) = rx.recv_timeout(Duration::from_secs(1)) else {
            drop(peer);
            worker.join().unwrap();
            panic!("a socket write must not block supervision");
        };
        worker.join().unwrap();
        assert!(result.unwrap());
        assert!(
            relay.undelivered() > 0,
            "backpressure retains undelivered output"
        );
        // SAFETY: querying flags on the live origin descriptor.
        let flags = unsafe { libc::fcntl(relay.origin.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(
            flags & libc::O_NONBLOCK,
            0,
            "shared origin flags stay unchanged"
        );
        peer.set_nonblocking(true).unwrap();
        let mut delivered = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        while delivered.len() < RELAY_BUFFER {
            let mut chunk = [0u8; 8192];
            match peer.read(&mut chunk) {
                Ok(read) => delivered.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("socket delivery failed: {error}"),
            }
            relay.pump().unwrap();
            assert!(Instant::now() < deadline, "output did not drain");
        }
        assert_eq!(delivered, vec![b'x'; RELAY_BUFFER]);
        assert!(relay.done());
    }

    /// A socket whose peer is gone is `EPIPE`, not a `SIGPIPE` that would
    /// kill a host keeping the default disposition.
    #[test]
    fn a_closed_socket_peer_is_epipe_not_sigpipe() {
        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(peer);
        // SAFETY: restoring the default disposition only for this check;
        // the previous one is put back below.
        let previous = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        let result = send_all(socket.as_fd(), b"x");
        // SAFETY: the disposition saved above.
        unsafe { libc::signal(libc::SIGPIPE, previous) };
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPIPE));
    }

    /// A send the writer thread could not complete is the relay's failure,
    /// reported by the loop's next pump and on every pump after it.
    #[test]
    fn a_socket_writer_failure_is_the_relays_failure() {
        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (mut relay, writer) = output_relay(socket.into(), true);
        relay_write(writer.as_raw_fd(), b"to a peer that leaves").unwrap();
        drop(peer);
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = loop {
            match relay.pump() {
                Err(error) => break error,
                Ok(_) => assert!(Instant::now() < deadline, "the failure never surfaced"),
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
        assert_eq!(relay.pump().unwrap_err().raw_os_error(), Some(libc::EPIPE));
        drop(writer);
    }

    #[test]
    fn relay_batch_services_stderr_while_stdout_is_active() {
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let (out, out_writer) = output_relay(stdout.try_clone().unwrap().into(), false);
        let (err, err_writer) = output_relay(stderr.try_clone().unwrap().into(), false);
        relay_write(out_writer.as_raw_fd(), b"stdout remains active").unwrap();
        relay_write(err_writer.as_raw_fd(), b"stderr must arrive now").unwrap();
        let mut relays = [out, err];
        assert!(pump_stdio_relays(&mut relays).unwrap());
        let mut text = String::new();
        stderr.rewind().unwrap();
        stderr.read_to_string(&mut text).unwrap();
        assert_eq!(text, "stderr must arrive now");
        text.clear();
        stdout.rewind().unwrap();
        stdout.read_to_string(&mut text).unwrap();
        assert_eq!(text, "stdout remains active");
    }

    /// The drain waits for output only: a stdin relay the tree's end cannot
    /// finish neither holds it to the budget nor counts as undelivered.
    #[test]
    fn the_output_drain_waits_for_output_only() {
        let mut stdout = tempfile::tempfile().unwrap();
        let (out, writer) = output_relay(stdout.try_clone().unwrap().into(), false);
        relay_write(writer.as_raw_fd(), b"last words").unwrap();
        drop(writer);
        // A stdin origin that never reaches end-of-file while its peer
        // lives, with input staged that the child never reads.
        let (origin, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (mut stdin, _child) = input_relay(origin.into(), true);
        // The child's pipe is full, so the staged input stays staged.
        let ours = stdin.ours.as_ref().unwrap().as_raw_fd();
        while relay_write(ours, &[0u8; 4096]).is_ok() {}
        stdin.buffer = b"unread input".to_vec();
        let mut relays = vec![out, stdin];
        let started = Instant::now();
        drain_output_relays(&mut relays, Duration::from_secs(5), Duration::from_secs(5)).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the drain waited for a stdin relay the tree's end cannot finish"
        );
        assert!(relays[0].done());
        assert!(!relays[1].done(), "stdin stays open, unwaited for");
        let mut text = String::new();
        stdout.rewind().unwrap();
        stdout.read_to_string(&mut text).unwrap();
        assert_eq!(text, "last words");
    }

    /// Output that stops moving is named once the idle window passes,
    /// however long the cap, and never counted as delivered.
    #[test]
    fn output_that_stops_moving_is_undelivered_after_the_idle_window() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (mut relay, child_end) = output_relay(socket.into(), true);
        // More than the unread peer's buffers can take.
        relay.buffer = vec![b'x'; RELAY_BUFFER];
        let mut relays = vec![relay];
        let mut child = std::fs::File::from(child_end);
        child.write_all(b"cannot be delivered").unwrap();
        drop(child);
        let started = Instant::now();
        let error = drain_output_relays(&mut relays, Duration::from_millis(50), OUTPUT_DRAIN_CAP)
            .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the cap was waited for"
        );
        assert!(
            error.contains("could not drain") && error.contains("no byte moved"),
            "{error}"
        );
        assert!(relays.is_empty());
    }

    /// A reader that drains a 64 KiB staged chunk at about 80 KB/s, so
    /// delivery takes several idle windows, and the bytes it received.
    fn slow_reader(relay_buffer: usize) -> (StdioRelay, std::thread::JoinHandle<usize>) {
        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let (mut relay, child_end) = output_relay(socket.into(), true);
        relay.buffer = vec![b'x'; relay_buffer];
        drop(child_end);
        let reader = std::thread::spawn(move || {
            let mut peer = peer;
            let mut received = 0;
            let mut chunk = [0u8; 2048];
            loop {
                match peer.read(&mut chunk) {
                    Ok(0) | Err(_) => return received,
                    Ok(read) => received += read,
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        (relay, reader)
    }

    /// A slow reader that keeps accepting bytes gets all of them, although
    /// delivery outlasts the idle window several times over.
    #[test]
    fn a_slow_reader_that_keeps_moving_gets_everything() {
        let idle = Duration::from_millis(500);
        let (relay, reader) = slow_reader(RELAY_BUFFER);
        let mut relays = vec![relay];
        let started = Instant::now();
        drain_output_relays(&mut relays, idle, OUTPUT_DRAIN_CAP).unwrap();
        assert!(
            started.elapsed() > idle,
            "delivery should outlast one idle window"
        );
        drop(relays);
        assert_eq!(reader.join().unwrap(), RELAY_BUFFER);
    }

    /// The cap ends delivery to a reader that is still moving.
    #[test]
    fn the_cap_ends_delivery_to_a_reader_still_moving() {
        let (relay, reader) = slow_reader(RELAY_BUFFER);
        let mut relays = vec![relay];
        let error = drain_output_relays(
            &mut relays,
            Duration::from_millis(500),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(error.contains("limit after the tree's end"), "{error}");
        drop(relays);
        assert!(reader.join().unwrap() < RELAY_BUFFER);
    }

    #[test]
    fn relay_descriptors_are_close_on_exec() {
        let file = tempfile::tempfile().unwrap();
        let (relay, child_end) = StdioRelay::attach(file.as_raw_fd(), false).unwrap();
        for fd in [
            relay.origin.as_raw_fd(),
            relay.ours.as_ref().unwrap().as_raw_fd(),
            child_end.as_raw_fd(),
        ] {
            // SAFETY: F_GETFD takes a descriptor number and dereferences nothing.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC, "fd {fd}");
        }
    }
}
