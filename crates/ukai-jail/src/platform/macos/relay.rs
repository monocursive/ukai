//! J16: the macOS pty relay (jail-macos.md §4.11; J14
//! jail-interactive-sessions.md §3.3 option (b)).
//!
//! macOS has no PID namespace, so J14's shared process group cannot confine
//! the command: a member can change its group through `posix_spawn`
//! attributes even with `setpgid` denied, and Seatbelt's filtering of the
//! terminal ioctls is unproven. Terminal mode therefore allocates a pty and
//! gives its slave to the launcher as controlling terminal in a new session.
//! The workload never holds the operator's terminal, so J14 §3.5's rows 1–6
//! and 10 are unreachable on every macOS release.
//!
//! What this costs (J14 §3.3 (b)): every byte passes through here; X05's
//! byte equality no longer holds for terminal runs; raw mode, window-size
//! propagation, end-of-file and flow control become jail code. That is what
//! [`TerminalRelay`] is: a bounded byte pump, a window-size propagator, the
//! raw-mode save and restore of J14 §3.6, and the terminal half of the stop
//! relay of §3.4.
//!
//! The supervisor drives everything from its poll loop: `pump` copies bytes
//! one nonblocking pass at a time, `propagate_window` answers `SIGWINCH`,
//! and the stop's *detection* comes from a [`TargetStopSource`] the boundary
//! slice feeds. The end-to-end supervisor wiring (spawn, poll loop, the
//! `applied.terminal` record) lands with the boundary integration slice;
//! this module owns the pty mechanics and their tests.

use std::os::fd::RawFd;

use crate::records::TerminalRestored;
use crate::terminal::{RESET_BOUND, StepFailure, TERMINAL_FD, errno_name, with_sigttou_blocked};

/// The bytes one pump direction may hold while its destination is not
/// taking them (J14 §3.3 (b): flow control becomes jail code). When the
/// master's queue or the operator's terminal is full, the pump stops reading
/// the source and keeps at most this much pending, so the supervisor's
/// memory stays bounded whatever the workload writes.
pub const BUFFER_BYTES: usize = 64 * 1024;

/// The receipt's `applied.terminal.session` value (jail-macos.md §4.11).
pub const RELAY_SESSION: &str = "relay";

/// XNU's `P_LIST_STOPPED` (`bsd/sys/proc_internal.h`): the bit of
/// `proc_bsdinfo.pbi_status` that marks a stopped process.
const P_LIST_STOPPED: u32 = 0x4;

// `ptsname_r(3)`: the slave path of the pty whose master `fd` names.
// Declared here because the `libc` crate does not expose it on macOS;
// libSystem has had it since 10.13.4.
unsafe extern "C" {
    fn ptsname_r(fd: libc::c_int, buffer: *mut libc::c_char, length: libc::size_t) -> libc::c_int;
}

/// Where the stop relay learns that the target's group stopped (§4.11). ES
/// reports no group-stop event, so the boundary slice feeds this from
/// polling ([`target_stopped`], the J14 §3.4 100 ms cadence) or from
/// whatever the integration observes.
pub trait TargetStopSource {
    /// The signal that stopped the target's group, or `None` while it runs.
    fn stopped_signal(&self) -> Option<libc::c_int>;
}

/// The reference [`TargetStopSource`]: one poll of the target's state, at
/// the J14 §3.4 cadence (initially at most 100 ms apart in terminal mode).
/// Reads `pbi_status` through `proc_pidinfo(PROC_PIDTBSDINFO)` and reports
/// the `P_LIST_STOPPED` bit.
///
/// The poll cannot see *which* signal stopped the process; terminal `^Z`
/// sends `SIGTSTP`, the signal the stop relay re-delivers to the
/// supervisor's own group, so that is what a stop reports.
#[must_use]
pub fn target_stopped(pid: libc::pid_t) -> Option<libc::c_int> {
    // SAFETY: `info` is writable storage of exactly the size passed.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is writable storage of exactly the size passed.
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast::<libc::c_void>(),
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if read as usize != std::mem::size_of::<libc::proc_bsdinfo>() {
        return None;
    }
    (info.pbi_status & P_LIST_STOPPED != 0).then_some(libc::SIGTSTP)
}

/// What one [`TerminalRelay::pump`] pass did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelayEvent {
    /// Bytes moved this pass, per direction. Either count may be 0.
    Relayed {
        /// Bytes that travelled operator tty → master.
        tty_to_master: usize,
        /// Bytes that travelled master → operator tty.
        master_to_tty: usize,
    },
    /// Nothing was ready; the supervisor's poll loop may call again.
    Idle,
    /// The master reached end of stream: the read answered 0 or `EIO`,
    /// which is what a pty master answers once every slave descriptor is
    /// closed. Nothing is pending either way.
    EndOfStream,
    /// The operator's terminal hung up or errored (`POLLHUP`, `POLLERR`,
    /// `POLLNVAL`): J14 §3.4's hangup row, a stop request for the
    /// supervisor.
    OperatorHungUp,
}

/// A fixed pending buffer of one pump direction: at most [`BUFFER_BYTES`].
struct Pending {
    bytes: Vec<u8>,
}

impl Pending {
    fn new() -> Pending {
        Pending {
            bytes: Vec::with_capacity(BUFFER_BYTES),
        }
    }

    /// Room left before the direction's bound.
    fn free(&self) -> usize {
        BUFFER_BYTES - self.bytes.len()
    }

    /// Takes everything from `fd` while data is ready and there is room.
    /// `Ok(true)` when end of stream was seen (`read` answered 0, or `EIO`,
    /// what a pty master answers with every slave closed).
    fn read_into(&mut self, fd: RawFd) -> std::io::Result<bool> {
        let mut eof = false;
        while self.free() > 0 {
            let mut chunk = [0_u8; 8192];
            let want = chunk.len().min(self.free());
            // SAFETY: the slice is live and its length is passed.
            let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), want) };
            if n < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                // A pty master whose slave side is gone answers EIO: end of
                // stream, not a fault.
                if error.raw_os_error() == Some(libc::EIO) {
                    eof = true;
                }
                break;
            }
            if n == 0 {
                eof = true;
                break;
            }
            self.bytes
                .extend_from_slice(&chunk[..usize::try_from(n).unwrap_or(0)]);
            if usize::try_from(n).unwrap_or(0) < want {
                break;
            }
        }
        Ok(eof)
    }

    /// Writes what it holds to `fd`, nonblocking, keeping what would not
    /// fit. Returns the bytes that moved.
    fn write_from(&mut self, fd: RawFd) -> std::io::Result<usize> {
        let mut moved = 0;
        while !self.bytes.is_empty() {
            // SAFETY: the slice is live and its length is passed.
            let n = unsafe { libc::write(fd, self.bytes.as_ptr().cast(), self.bytes.len()) };
            if n < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            let n = usize::try_from(n).unwrap_or(0);
            self.bytes.drain(..n);
            moved += n;
        }
        Ok(moved)
    }

    /// Drains what it holds to `fd`, waiting at most `bound` in all
    /// (`poll` for `POLLOUT` before each write), draining as the terminal
    /// takes the bytes and keeping the rest pending. The operator's
    /// terminal is shared with its shell, so its descriptor is never made
    /// nonblocking; this is what keeps a terminal whose output the workload
    /// suspended from holding the supervisor (J14 review F2). Returns the
    /// bytes that moved; only a `poll` failure is an error.
    fn write_from_bounded(
        &mut self,
        fd: RawFd,
        bound: std::time::Duration,
    ) -> std::io::Result<usize> {
        let deadline = std::time::Instant::now() + bound;
        let mut moved = 0;
        while !self.bytes.is_empty() {
            let wait = deadline.saturating_duration_since(std::time::Instant::now());
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let ms = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
            // SAFETY: one live pollfd.
            let ready = unsafe { libc::poll(&raw mut pollfd, 1, ms) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 || pollfd.revents & libc::POLLOUT == 0 {
                break;
            }
            // SAFETY: a write from a live slice to a descriptor that had room.
            let n = unsafe { libc::write(fd, self.bytes.as_ptr().cast(), self.bytes.len()) };
            if n < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            let n = usize::try_from(n).unwrap_or(0);
            self.bytes.drain(..n);
            moved += n;
        }
        Ok(moved)
    }
}

/// The pty relay of one terminal run: the master, the slave for the launch
/// block, and the operator terminal's saved `termios`.
///
/// The relay owns both pty descriptors and closes them when dropped; it
/// never restores the operator's `termios` on drop — the supervisor runs
/// [`TerminalRelay::settle`] explicitly (J14 §3.6), and a dropped relay
/// whose steps did not run is the recorded `restored: null` case.
pub struct TerminalRelay {
    master: RawFd,
    slave: Option<RawFd>,
    /// The slave's path, for the pre-exec line.
    slave_path: String,
    /// The operator terminal: standard input in production, a fake pty in
    /// the tests.
    operator: RawFd,
    /// The `termios` saved at attach (or at the last continue), the copy
    /// every restore puts back.
    saved: libc::termios,
    /// The window size last propagated to the master, so a `SIGWINCH` whose
    /// size did not change propagates nothing.
    window: libc::winsize,
    /// The stops relayed so far (`applied.terminal.stops`).
    pub stops: u64,
    /// What the settlement restore did, once it ran.
    pub restored: Option<TerminalRestored>,
    /// Operator tty → master, pending while the master's queue is full.
    to_master: Pending,
    /// Master → operator tty, pending while the operator's terminal will
    /// not take more (its output suspended, its queue full).
    to_tty: Pending,
}

impl Drop for TerminalRelay {
    fn drop(&mut self) {
        // SAFETY: both descriptors are numbers this struct owns.
        unsafe {
            libc::close(self.master);
            if let Some(slave) = self.slave {
                libc::close(slave);
            }
        }
    }
}

impl TerminalRelay {
    /// Allocates the pty and takes the operator terminal into raw-ish mode.
    ///
    /// `posix_openpt` + `grantpt` + `unlockpt` name the slave; the master is
    /// made nonblocking, so the pump never blocks on a workload that stopped
    /// reading. The operator's `termios` is saved — the copy
    /// [`TerminalRelay::settle`] restores — and replaced with `cfmakeraw`
    /// **except `OPOST|ONLCR`, which are kept**: `ISIG`, `ICANON` and `ECHO`
    /// are cleared, so `^C` and `^Z` arrive as bytes at the master and the
    /// slave's line discipline — whose defaults the jail does not touch —
    /// turns them into signals for the workload's group and echoes the
    /// workload's input, and the agent's bytes are read unbuffered;
    /// `OPOST|ONLCR` stay so the supervisor's own lines still render their
    /// newlines (`sudo` keeps output processing the same way). The
    /// operator's window size is propagated to the master once, so the
    /// workload starts with the real size.
    ///
    /// # Errors
    /// The errno of `posix_openpt`, `grantpt`, `unlockpt`, `ptsname_r`,
    /// `open`, `tcgetattr`, `tcsetattr` or `ioctl`.
    pub fn allocate(operator: RawFd) -> std::io::Result<TerminalRelay> {
        // SAFETY: posix_openpt takes a flag mask and returns a descriptor.
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the descriptor is live; both calls take it alone.
        let unlocked = unsafe { libc::grantpt(master) == 0 && libc::unlockpt(master) == 0 };
        if !unlocked {
            let error = std::io::Error::last_os_error();
            // SAFETY: the descriptor this allocation owns.
            unsafe { libc::close(master) };
            return Err(error);
        }
        let mut path = [0 as libc::c_char; 128];
        // SAFETY: the buffer is live and its length passed; on success it
        // holds a NUL-terminated path.
        if unsafe { ptsname_r(master, path.as_mut_ptr(), path.len()) } != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: as above.
            unsafe { libc::close(master) };
            return Err(error);
        }
        let slave_path = {
            // SAFETY: on success the buffer holds a NUL-terminated string.
            let name = unsafe { std::ffi::CStr::from_ptr(path.as_ptr()) };
            name.to_string_lossy().into_owned()
        };
        // SAFETY: open takes the NUL-terminated path a pointer points at.
        let slave = unsafe {
            libc::open(
                // SAFETY: as above; the path has no interior NUL.
                std::ffi::CString::new(slave_path.as_str())
                    .unwrap_or_default()
                    .as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY,
            )
        };
        if slave < 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: as above.
            unsafe { libc::close(master) };
            return Err(error);
        }
        // SAFETY: fcntl takes scalars on a live descriptor.
        let flags = unsafe { libc::fcntl(master, libc::F_GETFL) };
        // SAFETY: as above; the flags came back from F_GETFL.
        if flags < 0 || unsafe { libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
        {
            let error = std::io::Error::last_os_error();
            // SAFETY: as above.
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return Err(error);
        }
        // SAFETY: `termios` is writable storage tcgetattr fills.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is a number.
        if unsafe { libc::tcgetattr(operator, &raw mut saved) } != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: as above.
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return Err(error);
        }
        let mut raw = saved;
        // SAFETY: cfmakeraw writes the storage given.
        unsafe { libc::cfmakeraw(&raw mut raw) };
        // Keep output processing: the supervisor's diagnostics and the pty's
        // `\r\n` must render as newlines on the operator's terminal.
        raw.c_oflag |= libc::OPOST | libc::ONLCR;
        // SAFETY: tcsetattr takes scalars; this thread is the supervisor's
        // own and its group holds the foreground at attach, so no `SIGTTOU`
        // is pending for it.
        if unsafe { libc::tcsetattr(operator, libc::TCSANOW, &raw) } != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: as above.
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return Err(error);
        }
        let mut window: libc::winsize = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `window` is writable storage TIOCGWINSZ fills; ENOTTY
        // (a terminal without a size) leaves zeroes.
        if unsafe { libc::ioctl(operator, libc::TIOCGWINSZ, &raw mut window) } != 0 {
            window = libc::winsize {
                ws_row: 0,
                ws_col: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
        }
        // SAFETY: TIOCSWINSZ reads the storage given; the kernel signals the
        // slave's foreground group when the size changes.
        unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &raw const window) };
        Ok(TerminalRelay {
            master,
            slave: Some(slave),
            slave_path,
            operator,
            saved,
            window,
            stops: 0,
            restored: None,
            to_master: Pending::new(),
            to_tty: Pending::new(),
        })
    }

    /// The master, for the supervisor's poll loop.
    #[must_use]
    pub fn master_fd(&self) -> RawFd {
        self.master
    }

    /// The slave, for the launch block's stdio and controlling terminal;
    /// `None` after [`TerminalRelay::close_slave`].
    #[must_use]
    pub fn slave_fd(&self) -> Option<RawFd> {
        self.slave
    }

    /// Closes the relay's own slave descriptor once the launch block holds
    /// it: until every slave descriptor is closed, the master never reports
    /// end of stream.
    pub fn close_slave(&mut self) {
        if let Some(slave) = self.slave.take() {
            // SAFETY: the descriptor this struct owned.
            unsafe { libc::close(slave) };
        }
    }

    /// The receipt's `applied.terminal.session` (§4.11).
    #[must_use]
    pub fn session(&self) -> &'static str {
        RELAY_SESSION
    }

    /// The slave's path, for the pre-exec line.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.slave_path
    }

    /// The attached pre-exec line of a relayed run (J14 §3.7 adapted for
    /// §4.11), without the `ukai-jail: ` prefix; the run flow prints it.
    #[must_use]
    pub fn pre_exec_line(&self, name: &str, supervisor: u32, wall: Option<&str>) -> String {
        let wall = wall.map_or_else(|| "no wall".to_owned(), |wall| format!("wall {wall}"));
        format!(
            "terminal: relay ({}) · {wall} · ^C and ^Z go to {name}'s session on the relay; to \
             end the attempt, exit {name} or run kill -INT {supervisor}",
            self.slave_path
        )
    }

    /// One nonblocking pump pass: bytes each way, with backpressure held in
    /// at most [`BUFFER_BYTES`] pending per direction. The supervisor calls
    /// this from its poll loop whenever [`RelayEvent::Idle`] has not ended
    /// the run.
    ///
    /// # Errors
    /// The errno of `poll` when the wait itself failed; byte movement never
    /// fails the pass — errors surface as [`RelayEvent`] values.
    pub fn pump(&mut self, operator_tty: RawFd) -> std::io::Result<RelayEvent> {
        let tty = if operator_tty < 0 {
            TERMINAL_FD
        } else {
            operator_tty
        };
        let mut pollfd = [
            libc::pollfd {
                fd: self.master,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: tty,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two live pollfds, a zero timeout.
        let ready = unsafe { libc::poll(pollfd.as_mut_ptr(), 2, 0) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if pollfd[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(RelayEvent::OperatorHungUp);
        }
        let mut tty_to_master = 0;
        let mut master_to_tty = 0;
        let mut eof = false;

        // Master → operator tty: flush what is pending first, then take
        // more from the master (a read here also answers with the end of
        // stream when every slave descriptor is closed), then try the rest.
        master_to_tty += self
            .to_tty
            .write_from_bounded(tty, RESET_BOUND)
            .unwrap_or(0);
        if self.to_tty.free() > 0
            && pollfd[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            eof = self.to_tty.read_into(self.master).unwrap_or(false);
        }
        master_to_tty += self
            .to_tty
            .write_from_bounded(tty, RESET_BOUND)
            .unwrap_or(0);

        // Operator tty → master.
        if self.to_master.bytes.is_empty() && pollfd[1].revents & libc::POLLIN != 0 {
            let _ = self.to_master.read_into(tty)?;
        }
        tty_to_master += self.to_master.write_from(self.master).unwrap_or(0);

        if self.to_tty.bytes.is_empty() && eof && self.to_master.bytes.is_empty() {
            return Ok(RelayEvent::EndOfStream);
        }
        if tty_to_master == 0 && master_to_tty == 0 {
            return Ok(RelayEvent::Idle);
        }
        Ok(RelayEvent::Relayed {
            tty_to_master,
            master_to_tty,
        })
    }

    /// Propagates the operator terminal's window size to the master,
    /// which makes the kernel signal the slave's foreground group with
    /// `SIGWINCH`. `Ok(true)` when the size changed and was propagated.
    ///
    /// # Errors
    /// The errno of `ioctl` on the operator tty.
    pub fn propagate_window(&mut self) -> std::io::Result<bool> {
        let mut window: libc::winsize = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `window` is writable storage TIOCGWINSZ fills.
        if unsafe { libc::ioctl(self.operator, libc::TIOCGWINSZ, &raw mut window) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if (
            window.ws_row,
            window.ws_col,
            window.ws_xpixel,
            window.ws_ypixel,
        ) == (
            self.window.ws_row,
            self.window.ws_col,
            self.window.ws_xpixel,
            self.window.ws_ypixel,
        ) {
            return Ok(false);
        }
        // SAFETY: TIOCSWINSZ reads the storage given.
        if unsafe { libc::ioctl(self.master, libc::TIOCSWINSZ, &raw const window) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.window = window;
        Ok(true)
    }

    /// Puts the raw-ish mode back after a continue (§3.4 step 4).
    ///
    /// # Errors
    /// The errno of `tcsetattr`.
    fn set_raw(&self) -> std::io::Result<()> {
        let mut raw = self.saved;
        // SAFETY: cfmakeraw writes the storage given.
        unsafe { libc::cfmakeraw(&raw mut raw) };
        raw.c_oflag |= libc::OPOST | libc::ONLCR;
        with_sigttou_blocked(|| {
            // SAFETY: `raw` is a termios a tcgetattr filled.
            check(unsafe { libc::tcsetattr(self.operator, libc::TCSANOW, &raw) })
        })
    }

    /// §3.4 step 4, the relay half: on the shell's `fg` or `bg` the
    /// supervisor saves the `termios` again — the shell may have changed it
    /// — and re-applies the raw-ish mode. (Restarting the no-progress
    /// clocks and continuing the target's group are the supervisor's;
    /// giving the foreground back after `fg` is
    /// [`TerminalRelay::give_foreground`].)
    ///
    /// # Errors
    /// The errno of `tcgetattr` or `tcsetattr`.
    pub fn continued(&mut self) -> std::io::Result<()> {
        // SAFETY: `termios` is writable storage tcgetattr fills.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is a number.
        if unsafe { libc::tcgetattr(self.operator, &raw mut saved) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.saved = saved;
        self.set_raw()
    }

    /// Gives the terminal's foreground to `group`, with `SIGTTOU` blocked:
    /// the supervisor's return of the foreground to the target's group
    /// after a `fg` (§3.4 step 4).
    ///
    /// # Errors
    /// The errno of `tcsetpgrp`.
    pub fn give_foreground(&self, group: libc::pid_t) -> std::io::Result<()> {
        with_sigttou_blocked(|| {
            // SAFETY: tcsetpgrp takes scalars.
            check(unsafe { libc::tcsetpgrp(self.operator, group) })
        })
    }

    /// §3.4 steps 3–4, the stop relay. `signal` is the signal the
    /// [`TargetStopSource`] saw. The relay takes the operator terminal's
    /// foreground back for the supervisor's own group (with `SIGTTOU`
    /// blocked), restores the saved `termios`, counts the stop
    /// (`applied.terminal.stops`), and — unless `signal` is 0, which the
    /// tests use to exercise only the terminal steps — stops the
    /// supervisor's own process group with the same signal, so the
    /// operator's shell sees its job stop and gives the prompt back. The
    /// quiesce of §3.4 step 2 (no new persistence step; the in-flight one
    /// under its no-progress budget; the `terminal_stopped` journal note)
    /// is the supervisor's, before this call.
    ///
    /// # Errors
    /// The errno of the terminal steps or the `kill`. The foreground and
    /// the `termios` step are attempted whatever the other did; the first
    /// error is returned. (In the tests, where the operator tty is not the
    /// caller's controlling terminal, the foreground step answers `ENOTTY`;
    /// a real supervisor passes condition 3 of §3.2, so its operator tty
    /// is its own.)
    pub fn relayed_stop(&mut self, signal: libc::c_int) -> std::io::Result<()> {
        self.stops += 1;
        let mut first = None;
        if with_sigttou_blocked(|| {
            // SAFETY: tcsetpgrp takes scalars.
            check(unsafe { libc::tcsetpgrp(self.operator, group_of_own()) })
        })
        .is_err()
        {
            first = std::io::Error::last_os_error().into();
        }
        if with_sigttou_blocked(|| {
            // SAFETY: `saved` is a termios a tcgetattr filled.
            check(unsafe { libc::tcsetattr(self.operator, libc::TCSANOW, &self.saved) })
        })
        .is_err()
        {
            first = first.or_else(|| std::io::Error::last_os_error().into());
        }
        if let Some(error) = first {
            return Err(error);
        }
        if signal != 0 {
            // SAFETY: kill takes scalars; 0 means this process's group.
            check(unsafe { libc::kill(0, signal) })?;
        }
        Ok(())
    }

    /// §3.6: the settlement restore, after the tree's end, in order, each
    /// step attempted whatever the one before did: take the foreground back
    /// for the supervisor's group, restore the saved `termios`
    /// (`TCSANOW`), flush pending input (`TCIFLUSH`), and write
    /// `ESC[0m ESC[?25h` to stderr when it is a terminal. The window size
    /// is never restored: it reflects the real terminal. A failed step does
    /// not change the exit code; it is recorded here for the cleanup line.
    ///
    /// The foreground step can fail with `EPERM` when a process of another
    /// session holds the terminal (the operator's shell after `bg`); then
    /// the terminal is the shell's, and the remaining steps still run —
    /// `tcsetattr` and `tcflush` of a terminal that is not in this
    /// session's foreground are allowed.
    pub fn settle(&mut self, after_tree_death: bool) -> (TerminalRestored, Vec<StepFailure>) {
        let mut failures = Vec::new();
        let mut step = |name: &'static str, result: std::io::Result<()>| match result {
            Ok(()) => true,
            Err(error) => {
                failures.push(StepFailure {
                    step: name,
                    errno: errno_name(&error),
                });
                false
            }
        };
        let foreground = step(
            "foreground",
            with_sigttou_blocked(|| {
                // SAFETY: tcsetpgrp takes scalars.
                check(unsafe { libc::tcsetpgrp(self.operator, group_of_own()) })
            }),
        );
        let termios = step(
            "termios",
            with_sigttou_blocked(|| {
                // SAFETY: `saved` is a termios a tcgetattr filled.
                check(unsafe { libc::tcsetattr(self.operator, libc::TCSANOW, &self.saved) })
            }),
        );
        let input_flushed = step(
            "input",
            with_sigttou_blocked(|| {
                // SAFETY: tcflush takes scalars.
                check(unsafe { libc::tcflush(self.operator, libc::TCIFLUSH) })
            }),
        );
        let reset_written = match self.write_reset() {
            Ok(written) => written,
            Err(error) => step("reset", Err(error)),
        };
        let restored = TerminalRestored {
            foreground,
            termios,
            input_flushed,
            reset_written,
            after_tree_death,
        };
        self.restored = Some(restored);
        (restored, failures)
    }

    /// §3.6 step 4: `ESC[0m ESC[?25h` to stderr when it is a terminal.
    /// `Ok(false)` when stderr is not a terminal: nothing to reset.
    ///
    /// # Errors
    /// The errno of the write.
    pub fn write_reset(&self) -> std::io::Result<bool> {
        // SAFETY: isatty takes a descriptor number.
        if unsafe { libc::isatty(2) } != 1 {
            return Ok(false);
        }
        with_sigttou_blocked(|| {
            crate::terminal::write_bounded(2, b"\x1b[0m\x1b[?25h", RESET_BOUND)
        })?;
        Ok(true)
    }
}

fn group_of_own() -> libc::pid_t {
    // SAFETY: getpgrp takes no argument and cannot fail.
    unsafe { libc::getpgrp() }
}

fn check(rc: libc::c_int) -> std::io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
