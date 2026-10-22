//! J14: terminal mode (`docs/specs/jail-interactive-sessions.md` §3).
//!
//! When standard input is the operator's controlling pseudo-terminal and the
//! jail is the foreground job, a contained `run` attaches it: the command
//! runs in the caller's session, in a process group of its own that the
//! trusted launcher makes the terminal's foreground group, so resizes,
//! `/dev/tty`, terminal signals and job control reach it. Off a terminal,
//! nothing changes.
//!
//! This module holds the parts that are the same wherever a run is decided:
//! the five conditions of §3.2 ([`decide`] over measured [`Facts`]), the
//! pre-exec lines of §3.7, and the supervisor's own terminal calls
//! ([`Session`]): taking the foreground back, restoring and re-saving
//! `termios`, discarding pending input and the attribute reset of §3.6, each
//! with `SIGTTOU` blocked on the calling thread only, so the mask the target
//! inherits never carries it (§3.3 step 4).
//!
//! On macOS the mode is J14's option (b), the pty relay (jail-macos.md
//! §4.11): [`decide`] picks the mode, and
//! [`platform::macos::relay`](crate::platform::macos::relay) owns the relay
//! itself.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::records::TerminalRestored;

/// The descriptor terminal mode attaches: standard input (§3.2).
pub const TERMINAL_FD: RawFd = 0;

/// The wall an attached run gets when no operator layer sets one (§7,
/// decision 8), in milliseconds.
pub const ATTACHED_WALL_MS: u64 = 8 * 60 * 60 * 1000;

/// The spelling of [`ATTACHED_WALL_MS`] in the receipt's `requested`.
pub const ATTACHED_WALL: &str = "8h";

/// The test seam that stands in for a terminal of another kind: the device
/// major the mode decision reads instead of the real one (a virtual console
/// is 4, a serial line 4 or 204). Recorded like every `UKAI_JAIL_TEST_*`.
pub const SEAM_MAJOR: &str = "UKAI_JAIL_TEST_TERMINAL_MAJOR";

/// The test seam that forces one settlement step to fail (`foreground`,
/// `termios`, `input` or `reset`), so a failed step's record and its
/// cleanup line are produced without a broken terminal.
pub const SEAM_FAIL: &str = "UKAI_JAIL_TEST_TERMINAL_FAIL";

/// How long the settlement's reset write may wait for the terminal.
pub const RESET_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

/// The Unix98 pseudo-terminal slaves' device majors (by reading of the
/// kernel's device list: 136 to 143).
pub const PTY_SLAVE_MAJORS: std::ops::RangeInclusive<u32> = 136..=143;

/// What the operator asked for: `--terminal` and `[jail] terminal`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    /// Attach when the five conditions of §3.2 hold.
    #[default]
    Auto,
    /// Never attach: today's detached run.
    Detach,
}

/// Why a run that could have attached stayed detached: conditions 3 to 5 of
/// §3.2, the ones that are not the operator's own choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Detached {
    /// Standard input is not a terminal.
    NotATerminal,
    /// Standard input is a terminal, but not this session's controlling
    /// terminal.
    NotControlling,
    /// The jail is not the terminal's foreground job (`… &`).
    Background,
    /// The terminal is not a pseudo-terminal slave: a virtual console, a
    /// serial line or anything else.
    NotPty,
}

impl Detached {
    /// The reason as the pre-exec line and `explain` print it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Detached::NotATerminal => "stdin is not a terminal",
            Detached::NotControlling => "stdin is not this session's controlling terminal",
            Detached::Background => "not the foreground job",
            Detached::NotPty => "not a pseudo-terminal",
        }
    }
}

/// The mode a run gets.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Attached to the pseudo-terminal named here (`ttyname(0)`, or
    /// `/dev/pts/?` when it cannot be named).
    Attached {
        /// The terminal's name, for the pre-exec line.
        device: String,
    },
    /// Detached. `None` when the operator chose it or the run cannot attach
    /// (not `run`, not contained, `--gate-fd`, `--terminal detach`, a
    /// platform without terminal mode): nothing is printed. `Some` when
    /// condition 3, 4 or 5 failed: the pre-exec line names it.
    Detached(Option<Detached>),
}

impl Decision {
    /// Whether the terminal attaches.
    #[must_use]
    pub fn attached(&self) -> bool {
        matches!(self, Decision::Attached { .. })
    }
}

/// What §3.2's conditions 3 to 5 read from standard input.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Facts {
    /// `isatty(0)`.
    pub is_terminal: bool,
    /// `tcgetsid(0) == getsid(0)`.
    pub controlling: bool,
    /// `tcgetpgrp(0) == getpgrp()`.
    pub foreground: bool,
    /// The device major of standard input, when it is a character device.
    pub major: Option<u32>,
    /// `ttyname(0)`.
    pub name: Option<String>,
    /// A readable `termios` on standard input. macOS's terminal mode (the
    /// pty relay, §4.11) asks for a real tty: `isatty` plus a `tcgetattr`
    /// that answers, in place of Linux's device-major check — macOS pty
    /// slaves (`/dev/ttysNNN`) carry other majors. Linux keeps the major
    /// check and reads nothing extra.
    pub tty_settings: bool,
}

impl Facts {
    /// Measures standard input. The device major is the seam's when
    /// [`SEAM_MAJOR`] is set.
    #[must_use]
    pub fn measure() -> Facts {
        Self::measure_fd(TERMINAL_FD, std::env::var(SEAM_MAJOR).ok().as_deref())
    }

    fn measure_fd(fd: RawFd, seam_major: Option<&str>) -> Facts {
        // SAFETY: isatty takes a descriptor number and dereferences nothing.
        let is_terminal = unsafe { libc::isatty(fd) } == 1;
        if !is_terminal {
            return Facts::default();
        }
        // SAFETY: as above; these calls read scalars only.
        let (session, terminal_session, group, foreground_group) = unsafe {
            (
                libc::getsid(0),
                libc::tcgetsid(fd),
                libc::getpgrp(),
                libc::tcgetpgrp(fd),
            )
        };
        let (controlling, foreground) =
            session_facts(session, terminal_session, group, foreground_group);
        let major = match seam_major.map(str::parse::<u32>) {
            Some(Ok(major)) => Some(major),
            _ => device_major(fd),
        };
        #[cfg(target_os = "macos")]
        let tty_settings = {
            // SAFETY: `termios` is writable storage tcgetattr fills.
            let mut termios: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: the descriptor is a number.
            (unsafe { libc::tcgetattr(fd, &raw mut termios) }) == 0
        };
        #[cfg(not(target_os = "macos"))]
        let tty_settings = true;
        Facts {
            is_terminal,
            controlling,
            foreground,
            major,
            name: terminal_name(fd),
            tty_settings,
        }
    }

    /// §3.2 condition 5, per platform: Linux wants a Unix98 pty slave
    /// (majors 136–143; a virtual console or a serial line stays detached);
    /// macOS wants a real tty — `isatty` (already in `is_terminal`) plus a
    /// readable `termios` (`tty_settings`), because its pty slaves,
    /// `/dev/ttysNNN`, carry other majors than Linux's.
    fn is_pty(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.major
                .is_some_and(|major| PTY_SLAVE_MAJORS.contains(&major))
        }
        #[cfg(target_os = "macos")]
        {
            self.tty_settings
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }
}

/// Conditions 3 and 4 of §3.2 from the ids `getsid(0)`, `tcgetsid(0)`,
/// `getpgrp()` and `tcgetpgrp(0)` returned: `(controlling, foreground)`.
///
/// Review finding 6: every id must name something. In a PID namespace that
/// cannot name the session's leader or the job's group (`unshare -pf
/// ukai-jail …` from an interactive shell), each of these calls answers 0,
/// so equal ids would attach even a background job, and a supervisor whose
/// own group is 0 could never tell whose the terminal is. Such a run stays
/// detached: stdin is not a controlling terminal it can name.
fn session_facts(
    session: libc::pid_t,
    terminal_session: libc::pid_t,
    group: libc::pid_t,
    foreground_group: libc::pid_t,
) -> (bool, bool) {
    let controlling = session > 0 && terminal_session == session && group > 0;
    let foreground = controlling && foreground_group == group;
    (controlling, foreground)
}

/// The device major of a character device on `fd`.
fn device_major(fd: RawFd) -> Option<u32> {
    // SAFETY: `stat` is writable storage fstat fills.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes the buffer it is given and nothing else.
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return None;
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFCHR {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(libc::major(stat.st_rdev))
    }
    #[cfg(not(target_os = "linux"))]
    {
        u32::try_from(libc::major(stat.st_rdev)).ok()
    }
}

/// `ttyname(fd)`, as text.
fn terminal_name(fd: RawFd) -> Option<String> {
    let mut buffer = [0 as libc::c_char; 256];
    // SAFETY: the buffer is live and its length is passed; ttyname_r writes
    // a NUL-terminated name into it or returns an error.
    let rc = unsafe { libc::ttyname_r(fd, buffer.as_mut_ptr(), buffer.len()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: on success the buffer holds a NUL-terminated string.
    let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

/// §3.2. `applies` is conditions 1 and 2: the verb is `run`, the profile is
/// contained, and neither `--gate-fd`, `--terminal detach` nor `[jail]
/// terminal = "detach"` is in force. Conditions 3 to 5 are read from
/// `facts`. Linux attaches with J14's shared group; macOS attaches through
/// the pty relay (§4.11), whose condition 5 is a real tty rather than a
/// device major. Any other platform stays detached.
#[must_use]
pub fn decide(applies: bool, facts: &Facts) -> Decision {
    if !applies {
        return Decision::Detached(None);
    }
    let reason = if !facts.is_terminal {
        Some(Detached::NotATerminal)
    } else if !facts.controlling {
        Some(Detached::NotControlling)
    } else if !facts.foreground {
        Some(Detached::Background)
    } else if !facts.is_pty() {
        Some(Detached::NotPty)
    } else {
        None
    };
    match reason {
        Some(reason) => Decision::Detached(Some(reason)),
        None => Decision::Attached {
            device: facts
                .name
                .clone()
                .unwrap_or_else(|| fallback_device().to_owned()),
        },
    }
}

/// The device name an attached pre-exec line prints when `ttyname` failed.
fn fallback_device() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "/dev/pts/?"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "/dev/ttys?"
    }
}

/// The attached pre-exec line (§3.7), without the `ukai-jail: ` prefix.
/// `name` is what [`target_name`] calls the target and `wall` the applied
/// wall's spelling; the caller escapes the line like every diagnostic.
#[must_use]
pub fn attached_line(device: &str, wall: Option<&str>, name: &str, supervisor: u32) -> String {
    let wall = wall.map_or_else(|| "no wall".to_owned(), |wall| format!("wall {wall}"));
    format!(
        "terminal: attached ({device}) · {wall} · ^C and ^Z go to {name}, not the jail; to end \
         the attempt, exit {name} or run `kill -INT {supervisor}`"
    )
}

/// The detached pre-exec line (§3.2), without the `ukai-jail: ` prefix.
#[must_use]
pub fn detached_line(reason: Detached) -> String {
    format!("terminal: detached ({})", reason.as_str())
}

/// What the attached pre-exec line calls the target: the launch profile's
/// name when the run comes from one (`ukai-jail NAME`, `run --launch
/// NAME`), since an installed agent can be a version-named binary (a native
/// install that runs `…/versions/2.1.302`); otherwise the final component
/// of argv 0.
#[must_use]
pub fn target_name(launch: Option<&str>, argv0: Option<&[u8]>) -> String {
    match (launch, argv0) {
        (Some(launch), _) => launch.to_owned(),
        (None, Some(argv0)) => program_name(argv0),
        (None, None) => String::new(),
    }
}

/// The final component of argv 0, for the pre-exec line.
#[must_use]
pub fn program_name(argv0: &[u8]) -> String {
    let name = argv0
        .rsplit(|byte| *byte == b'/')
        .find(|part| !part.is_empty())
        .unwrap_or(argv0);
    String::from_utf8_lossy(name).into_owned()
}

// ---------------------------------------------------------------------------
// SIGTTOU around the supervisor's own terminal calls (§3.3 step 4)
// ---------------------------------------------------------------------------

/// Set while an attached run's command may hold the foreground: the
/// supervisor's diagnostics then block `SIGTTOU` on their thread around the
/// write, so a terminal with `TOSTOP` set cannot stop the supervisor for
/// writing while another group is in the foreground.
static ATTACHED: AtomicBool = AtomicBool::new(false);

/// Marks this process as running an attached command.
pub fn set_attached(attached: bool) {
    ATTACHED.store(attached, Ordering::SeqCst);
}

/// Whether this process runs an attached command.
#[must_use]
pub fn attached() -> bool {
    ATTACHED.load(Ordering::SeqCst)
}

/// Runs `call` with `SIGTTOU` blocked on the calling thread, then puts the
/// thread's mask back. The kernel lets a background caller that blocks
/// `SIGTTOU` change the terminal instead of stopping it (`is_ignored` in
/// `tty_check_change` reads the calling thread's mask), and no other
/// thread's mask, nor the one the target inherits, changes.
pub fn with_sigttou_blocked<T>(call: impl FnOnce() -> T) -> T {
    // SAFETY: `set` and `old` are plain stack data that sigemptyset,
    // sigaddset and pthread_sigmask fill or read.
    let old = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGTTOU);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, &raw mut old) != 0 {
            None
        } else {
            Some(old)
        }
    };
    let result = call();
    if let Some(old) = old {
        // SAFETY: `old` is the mask pthread_sigmask returned above.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &raw const old, std::ptr::null_mut());
        }
    }
    result
}

// ---------------------------------------------------------------------------
// The supervisor's terminal (§3.3, §3.4, §3.6)
// ---------------------------------------------------------------------------

/// The attached terminal, as the supervisor holds it from preparation to
/// settlement: the `termios` saved before release (or at the last
/// continue) and the supervisor's own process group.
pub struct Session {
    fd: RawFd,
    saved: Option<libc::termios>,
    group: libc::pid_t,
    /// The stops relayed so far (`applied.terminal.stops`).
    pub stops: u64,
    /// A hangup of the terminal was already turned into a stop request.
    pub hangup_seen: bool,
    /// What the settlement restore did, once it ran.
    pub restored: Option<TerminalRestored>,
    /// The step [`SEAM_FAIL`] forces to fail.
    fail: Option<String>,
    /// The [`continued`] count the supervisor last acted on.
    pub continues_seen: u64,
}

/// One settlement step that failed, and the errno it failed with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepFailure {
    /// `foreground`, `termios`, `input` or `reset`.
    pub step: &'static str,
    /// The errno name.
    pub errno: String,
}

impl Session {
    /// §3.3 step 1: records the supervisor's process group and saves the
    /// terminal's `termios`.
    ///
    /// # Errors
    /// The errno of `tcgetattr` when standard input is no longer a terminal.
    pub fn prepare() -> std::io::Result<Session> {
        let mut session = Session {
            fd: TERMINAL_FD,
            saved: None,
            // SAFETY: getpgrp takes no argument and cannot fail.
            group: unsafe { libc::getpgrp() },
            stops: 0,
            hangup_seen: false,
            restored: None,
            fail: std::env::var(SEAM_FAIL).ok(),
            continues_seen: continued(),
        };
        session.save()?;
        Ok(session)
    }

    /// Saves the terminal's current `termios` as the copy to restore.
    ///
    /// # Errors
    /// The errno of `tcgetattr`.
    pub fn save(&mut self) -> std::io::Result<()> {
        // SAFETY: `termios` is writable storage tcgetattr fills.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: as above; the descriptor is a number.
        if unsafe { libc::tcgetattr(self.fd, &raw mut termios) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.saved = Some(termios);
        Ok(())
    }

    /// The supervisor's own process group.
    #[must_use]
    pub fn group(&self) -> libc::pid_t {
        self.group
    }

    /// Whether the supervisor's group holds the terminal's foreground.
    #[must_use]
    pub fn in_foreground(&self) -> bool {
        self.foreground_group() == self.group
    }

    /// The terminal's foreground process group (`tcgetpgrp`), or -1.
    #[must_use]
    pub fn foreground_group(&self) -> libc::pid_t {
        // SAFETY: tcgetpgrp takes a descriptor number.
        unsafe { libc::tcgetpgrp(self.fd) }
    }

    /// Whether a job outside the jail holds the terminal: a foreground group
    /// other than the supervisor's and `command`'s whose leader runs in the
    /// supervisor's own PID namespace. That is the operator's shell (after
    /// `bg`) or another of its jobs; every group the command makes lives in
    /// the jail's namespace. The terminal is then not the jail's to take
    /// back (review F6): taking it would leave the shell reading a terminal
    /// it no longer holds.
    ///
    /// Review finding 5: a group whose leader is gone (`cat small | less`
    /// once `cat` exited and was reaped) is judged by a member's namespace,
    /// and one whose namespace cannot be read (another user's process) is
    /// not the jail's: since the terminal filter, no group of the jail but
    /// the command's can hold the terminal. Only a group with no process
    /// left is taken.
    #[must_use]
    pub fn held_outside(&self, command: Option<libc::pid_t>) -> bool {
        let group = self.foreground_group();
        if group <= 0 || group == self.group || Some(group) == command {
            return false;
        }
        let Ok(ours) = std::fs::read_link("/proc/self/ns/pid") else {
            return true;
        };
        match group_namespace(group) {
            GroupNamespace::Of(theirs) => theirs == ours,
            GroupNamespace::Empty => false,
            GroupNamespace::Unknown => true,
        }
    }

    /// Gives the terminal's foreground to `group`, with `SIGTTOU` blocked.
    ///
    /// # Errors
    /// The errno of `tcsetpgrp`.
    pub fn give_foreground(&self, group: libc::pid_t) -> std::io::Result<()> {
        // SAFETY: tcsetpgrp takes scalars.
        with_sigttou_blocked(|| check(unsafe { libc::tcsetpgrp(self.fd, group) }))
    }

    /// §3.6 step 1, and the stop relay's hand back: the supervisor's group
    /// takes the foreground.
    ///
    /// # Errors
    /// The errno of `tcsetpgrp`.
    pub fn take_foreground(&self) -> std::io::Result<()> {
        self.forced("foreground")?;
        self.give_foreground(self.group)
    }

    /// §3.6 step 2: the saved `termios`, now (`TCSANOW`); and the two
    /// terminal states `termios` does not hold that the filter lets the
    /// command change (review F2): output suspended with `TCOOFF`, which
    /// `^Q` cannot undo and which would block every later write, is
    /// resumed (`TCOON`), and exclusive mode (`TIOCEXCL`), which makes every
    /// later open of the terminal fail, is cleared (`TIOCNXCL`).
    ///
    /// # Errors
    /// The errno of `tcsetattr`, `tcflow` or the `ioctl`, or `EINVAL` when
    /// nothing was saved.
    pub fn restore_termios(&self) -> std::io::Result<()> {
        // Each of the three is attempted whatever the others did: output
        // left suspended would block every later write.
        let settings = self.forced("termios").and_then(|()| {
            let Some(saved) = self.saved.as_ref() else {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            };
            with_sigttou_blocked(|| {
                // SAFETY: `saved` is a termios tcgetattr filled.
                check(unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, saved) })
            })
        });
        settings.and(self.unblock())
    }

    /// Resumes output a command suspended (`TCOON`) and clears exclusive
    /// mode (`TIOCNXCL`): neither changes the settings, so this is done even
    /// when another job holds the terminal.
    ///
    /// # Errors
    /// The first errno of `tcflow` and the `ioctl`; both are attempted.
    fn unblock(&self) -> std::io::Result<()> {
        // SAFETY: tcflow takes scalars.
        let flow = with_sigttou_blocked(|| check(unsafe { libc::tcflow(self.fd, libc::TCOON) }));
        // Terminal mode attaches only on Linux.
        #[cfg(target_os = "linux")]
        // SAFETY: TIOCNXCL takes no argument.
        let exclusive = check(unsafe { libc::ioctl(self.fd, libc::TIOCNXCL) });
        #[cfg(not(target_os = "linux"))]
        let exclusive = Ok(());
        flow.and(exclusive)
    }

    /// §3.6 step 3: discards pending input (`TCIFLUSH`).
    ///
    /// # Errors
    /// The errno of `tcflush`.
    pub fn flush_input(&self) -> std::io::Result<()> {
        self.forced("input")?;
        // SAFETY: tcflush takes scalars.
        with_sigttou_blocked(|| check(unsafe { libc::tcflush(self.fd, libc::TCIFLUSH) }))
    }

    /// §3.6 step 4: `ESC [ 0 m` and `ESC [ ? 25 h` to stderr when it is a
    /// terminal. `Ok(false)` when stderr is not a terminal: nothing to reset.
    ///
    /// # Errors
    /// The errno of the write.
    ///
    /// Bounded (review F2): the write waits at most [`RESET_BOUND`] for the
    /// terminal to take the bytes, so a terminal whose output stays stopped
    /// cannot hold the supervisor before its release and receipt.
    pub fn write_reset(&self) -> std::io::Result<bool> {
        self.forced("reset")?;
        // SAFETY: isatty takes a descriptor number.
        if unsafe { libc::isatty(2) } != 1 {
            return Ok(false);
        }
        with_sigttou_blocked(|| write_bounded(2, b"\x1b[0m\x1b[?25h", RESET_BOUND))?;
        Ok(true)
    }

    /// Whether the terminal reported a hangup or an error (§3.4): `poll`
    /// with no requested events still reports `POLLHUP` and `POLLERR`.
    #[must_use]
    pub fn hung_up(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: 0,
            revents: 0,
        };
        // SAFETY: one live pollfd, a zero timeout.
        let rc = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
        rc > 0 && pollfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
    }

    /// §3.6: the four steps in order, each attempted whatever the one before
    /// did. `after_tree_death` is false when they run without verified tree
    /// death. Returns the record and the steps that failed.
    ///
    /// When a job outside the jail holds the terminal (`command` is the
    /// command's group), the first three steps are not taken and are
    /// recorded as not done: the terminal is the shell's then, not the
    /// jail's (review F6).
    pub fn settle(
        &mut self,
        after_tree_death: bool,
        command: Option<libc::pid_t>,
    ) -> (TerminalRestored, Vec<StepFailure>) {
        let mut failures = Vec::new();
        if self.held_outside(command) {
            let _ = self.unblock();
            for step in ["foreground", "termios", "input"] {
                failures.push(StepFailure {
                    step,
                    errno: "another job holds the terminal".to_owned(),
                });
            }
            let reset_written = match self.write_reset() {
                Ok(written) => written,
                Err(error) => {
                    failures.push(StepFailure {
                        step: "reset",
                        errno: errno_name(&error),
                    });
                    false
                }
            };
            let restored = TerminalRestored {
                foreground: false,
                termios: false,
                input_flushed: false,
                reset_written,
                after_tree_death,
            };
            self.restored = Some(restored);
            return (restored, failures);
        }
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
        let foreground = step("foreground", self.take_foreground());
        let termios = step("termios", self.restore_termios());
        let input_flushed = step("input", self.flush_input());
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

    /// The failure [`SEAM_FAIL`] forces on `step`.
    fn forced(&self, step: &str) -> std::io::Result<()> {
        if self.fail.as_deref() == Some(step) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }
}

/// The PID namespace of a process group's members, as [`group_namespace`]
/// finds it.
enum GroupNamespace {
    /// The leader's, or the first member's that could be read.
    Of(std::path::PathBuf),
    /// No process is left in the group.
    Empty,
    /// The group has members, and none of their namespaces can be read.
    Unknown,
}

/// The namespace of `group`'s leader, or, when the leader is gone or cannot
/// be read, of a member found in `/proc` (review finding 5).
fn group_namespace(group: libc::pid_t) -> GroupNamespace {
    if let Ok(theirs) = std::fs::read_link(format!("/proc/{group}/ns/pid")) {
        return GroupNamespace::Of(theirs);
    }
    // SAFETY: signal 0 to a process group only checks that it has members.
    if unsafe { libc::kill(-group, 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    {
        return GroupNamespace::Empty;
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return GroupNamespace::Unknown;
    };
    let mut member = false;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        if stat_field(pid, 2) != Some(group) {
            continue;
        }
        member = true;
        if let Ok(theirs) = std::fs::read_link(format!("/proc/{pid}/ns/pid")) {
            return GroupNamespace::Of(theirs);
        }
    }
    if member {
        GroupNamespace::Unknown
    } else {
        GroupNamespace::Empty
    }
}

/// Writes all of `bytes` to `fd`, waiting at most `bound` in all for the
/// terminal to take them (`poll` for `POLLOUT` before each write), so a
/// terminal whose output the command suspended cannot block the supervisor
/// (review F2). `ETIMEDOUT` when the bound passed first.
///
/// # Errors
/// The errno of `poll` or `write`, or `ETIMEDOUT`.
pub fn write_bounded(fd: RawFd, bytes: &[u8], bound: std::time::Duration) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + bound;
    let mut left = bytes;
    while !left.is_empty() {
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
            return Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        // SAFETY: a write from a live slice to a descriptor that had room.
        let n = unsafe { libc::write(fd, left.as_ptr().cast(), left.len()) };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        left = &left[usize::try_from(n).unwrap_or(0)..];
    }
    Ok(())
}

fn check(rc: libc::c_int) -> std::io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The errno's symbolic name, or the error's text.
pub(crate) fn errno_name(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::EIO) => "EIO".to_owned(),
        Some(libc::ENOTTY) => "ENOTTY".to_owned(),
        Some(libc::EINVAL) => "EINVAL".to_owned(),
        Some(libc::EPERM) => "EPERM".to_owned(),
        Some(libc::EBADF) => "EBADF".to_owned(),
        Some(libc::ENXIO) => "ENXIO".to_owned(),
        Some(libc::EINTR) => "EINTR".to_owned(),
        Some(libc::ETIMEDOUT) => "ETIMEDOUT".to_owned(),
        Some(code) => format!("errno {code}"),
        None => error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// The stop relay's wakeup (§3.4 step 4)
// ---------------------------------------------------------------------------

/// Counts `SIGCONT` deliveries to this process.
static CONTINUED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

extern "C" fn on_continue(_signal: libc::c_int) {
    CONTINUED.fetch_add(1, Ordering::SeqCst);
}

/// Installs the `SIGCONT` counter. Catching `SIGCONT` never prevents the
/// continue itself, and a caught disposition resets to the default in every
/// child at exec, so the target is unaffected.
///
/// # Errors
/// The errno of `sigaction`.
pub fn install_continue_counter() -> std::io::Result<()> {
    // SAFETY: a zeroed, fully initialized action whose handler is an
    // `extern "C"` function with the right signature; it only touches an
    // atomic, which is async-signal-safe.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_continue as *const () as usize;
        libc::sigemptyset(&raw mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        check(libc::sigaction(
            libc::SIGCONT,
            &raw const action,
            std::ptr::null_mut(),
        ))
    }
}

/// Whether this process's group is orphaned in the kernel's sense, so no
/// job-control shell can continue it: no ancestor outside the group is in
/// the same session. The walk climbs past ancestors in the group itself (a
/// wrapper such as `sh -c 'ukai-jail …'` shares the job's group) to the
/// first one outside it; the supervisor's own children (bubblewrap's outer
/// process and the watcher) have their parents in the group.
#[must_use]
pub fn group_orphaned() -> bool {
    // SAFETY: getpgrp and getsid take scalars.
    let (group, session) = unsafe { (libc::getpgrp(), libc::getsid(0)) };
    // SAFETY: getppid takes no argument.
    let mut ancestor = unsafe { libc::getppid() };
    // The depth is bounded; a chain this long in one group is not a shell.
    for _ in 0..64 {
        if ancestor <= 1 {
            return true;
        }
        // SAFETY: getpgid and getsid take scalars.
        let (theirs, their_session) = unsafe { (libc::getpgid(ancestor), libc::getsid(ancestor)) };
        if theirs < 0 || their_session != session {
            return true;
        }
        if theirs != group {
            return false;
        }
        match parent_of(ancestor) {
            Some(parent) => ancestor = parent,
            None => return true,
        }
    }
    true
}

/// A process's parent, from `/proc/<pid>/stat`.
fn parent_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    stat_field(pid, 1)
}

/// The `index`th field of `/proc/<pid>/stat` after the command name's
/// closing parenthesis: 0 is the state, 1 the parent, 2 the process group.
fn stat_field(pid: libc::pid_t, index: usize) -> Option<libc::pid_t> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_ascii_whitespace().nth(index)?.parse().ok()
}

/// J14 review finding 7: ignores `SIGQUIT` and `SIGTSTP` in this process,
/// for its settlement: the terminal's foreground is then its own group, so
/// `^\` and `^Z` reach it, and neither may end or stop it before its
/// receipt and its release. No child is started after this.
pub fn ignore_job_control_keys() {
    for signal in [libc::SIGQUIT, libc::SIGTSTP] {
        // SAFETY: SIG_IGN for a signal this process may ignore; no handler.
        unsafe {
            libc::signal(signal, libc::SIG_IGN);
        }
    }
}

/// How many `SIGCONT`s this process received.
#[must_use]
pub fn continued() -> u64 {
    CONTINUED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(major: u32) -> Facts {
        Facts {
            is_terminal: true,
            controlling: true,
            foreground: true,
            major: Some(major),
            name: Some("/dev/pts/7".to_owned()),
            tty_settings: true,
        }
    }

    #[test]
    fn every_condition_must_hold_to_attach() {
        let attached = decide(true, &facts(136));
        assert_eq!(
            attached,
            Decision::Attached {
                device: "/dev/pts/7".to_owned()
            }
        );
        assert_eq!(decide(false, &facts(136)), Decision::Detached(None));
        for (change, reason) in [
            (
                (|f: &mut Facts| f.is_terminal = false) as fn(&mut Facts),
                Detached::NotATerminal,
            ),
            (
                |f: &mut Facts| f.controlling = false,
                Detached::NotControlling,
            ),
            (|f: &mut Facts| f.foreground = false, Detached::Background),
        ] {
            let mut measured = facts(136);
            change(&mut measured);
            assert_eq!(decide(true, &measured), Decision::Detached(Some(reason)));
        }
        assert!(decide(true, &facts(143)).attached());
        // Condition 5, per platform: Linux wants a Unix98 pty slave major;
        // macOS wants a real tty — `is_terminal` plus a readable `termios`
        // (`tty_settings`), so the major is irrelevant there.
        if cfg!(target_os = "linux") {
            for major in [Some(4), Some(204), None, Some(135), Some(144)] {
                let mut measured = facts(136);
                measured.major = major;
                assert_eq!(
                    decide(true, &measured),
                    Decision::Detached(Some(Detached::NotPty)),
                    "{major:?}"
                );
            }
        } else {
            let mut measured = facts(136);
            measured.major = Some(4);
            assert!(decide(true, &measured).attached());
            measured.tty_settings = false;
            assert_eq!(
                decide(true, &measured),
                Decision::Detached(Some(Detached::NotPty))
            );
        }
    }

    #[test]
    fn the_lines_name_the_wall_the_target_and_the_supervisor() {
        assert_eq!(
            attached_line("/dev/pts/3", Some("8h"), "assistant", 41234),
            "terminal: attached (/dev/pts/3) · wall 8h · ^C and ^Z go to assistant, not the jail; \
             to end the attempt, exit assistant or run `kill -INT 41234`"
        );
        assert_eq!(
            detached_line(Detached::Background),
            "terminal: detached (not the foreground job)"
        );
        assert_eq!(program_name(b"/usr/local/bin/assistant"), "assistant");
        assert_eq!(program_name(b"assistant"), "assistant");
        assert_eq!(program_name(b"/opt/x/"), "x");
        // A run from a launch profile is named by the profile, not by a
        // version-named binary.
        assert_eq!(
            target_name(
                Some("assistant"),
                Some(b"/home/u/.local/share/assistant/versions/2.1.302")
            ),
            "assistant"
        );
        assert_eq!(
            target_name(None, Some(b"/usr/local/bin/assistant")),
            "assistant"
        );
        assert_eq!(target_name(None, None), "");
    }

    /// Review finding 6: ids a PID namespace cannot name (0) never attach,
    /// whatever they equal; ids that name the session and the group decide as
    /// before; an error (-1) never attaches.
    #[test]
    fn ids_this_namespace_cannot_name_never_attach() {
        // (session, terminal session, group, foreground group)
        for (ids, expected) in [
            ((0, 0, 0, 0), (false, false)),
            ((0, 0, 41, 41), (false, false)),
            ((40, 40, 0, 0), (false, false)),
            ((40, 40, 41, 41), (true, true)),
            ((40, 40, 41, 0), (true, false)),
            ((40, 40, 41, 42), (true, false)),
            ((40, 39, 41, 41), (false, false)),
            ((40, -1, 41, 41), (false, false)),
            ((-1, -1, 41, 41), (false, false)),
            ((40, 40, 41, -1), (true, false)),
        ] {
            assert_eq!(
                session_facts(ids.0, ids.1, ids.2, ids.3),
                expected,
                "{ids:?}"
            );
        }
        let mut measured = facts(136);
        (measured.controlling, measured.foreground) = session_facts(0, 0, 0, 0);
        assert_eq!(
            decide(true, &measured),
            Decision::Detached(Some(Detached::NotControlling))
        );
    }

    #[test]
    fn a_descriptor_that_is_no_terminal_measures_as_none() {
        let file = tempfile::tempfile().expect("a file");
        use std::os::fd::AsRawFd as _;
        assert_eq!(Facts::measure_fd(file.as_raw_fd(), None), Facts::default());
    }
}
