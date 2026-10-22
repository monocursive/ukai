//! J16: the macOS pty relay, live (jail-macos.md §4.11; J14 §3.3 option
//! (b), §3.4, §3.6, §3.7). No entitlement is needed: the relay is plain
//! `ukai-jail` code, not ES client code.
//!
//! Every fixture runs real processes against real ptys: a `/bin/sh` made a
//! session leader with the relay's slave as its controlling terminal, and a
//! second pty standing in for the operator's terminal. Forked children that
//! exec shells share the test process's fds where the fixture says so; the
//! tests are serialized (`--test-threads=1`) because of the forks.
#![cfg(target_os = "macos")]

use std::os::fd::{AsRawFd as _, RawFd};
use std::time::Duration;

use libc::{c_char, c_int, pid_t};

use ukai_jail::platform::macos::relay::{RelayEvent, TerminalRelay, target_stopped};

mod common;

// `ptsname_r(3)`: not in the `libc` crate on macOS; libSystem has had it
// since 10.13.4.
unsafe extern "C" {
    fn ptsname_r(fd: c_int, buffer: *mut c_char, length: libc::size_t) -> c_int;
}

/// How long any fixture may wait for its counterpart.
const BOUND: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// pty and process fixtures
// ---------------------------------------------------------------------------

/// A pty pair from `posix_openpt`: the master this process reads and
/// writes, and the slave path and descriptor.
struct Pty {
    master: RawFd,
    slave: RawFd,
    #[allow(dead_code)]
    path: String,
}

impl Drop for Pty {
    fn drop(&mut self) {
        // SAFETY: both descriptors this struct owns.
        unsafe {
            libc::close(self.master);
            libc::close(self.slave);
        }
    }
}

/// Allocates a pty pair (the same calls the relay makes).
fn open_pty() -> Pty {
    // SAFETY: posix_openpt takes a flag mask and returns a descriptor.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(
        master >= 0,
        "posix_openpt: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the descriptor is live.
    assert_eq!(unsafe { libc::grantpt(master) }, 0, "grantpt");
    // SAFETY: the descriptor is live; the call takes it alone.
    assert_eq!(unsafe { libc::unlockpt(master) }, 0, "unlockpt");
    let mut buffer = [0 as c_char; 128];
    // SAFETY: the buffer is live and its length passed.
    let named = unsafe { ptsname_r(master, buffer.as_mut_ptr(), buffer.len()) };
    assert_eq!(named, 0, "ptsname_r");
    let path = {
        // SAFETY: on success the buffer holds a NUL-terminated string.
        let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) };
        name.to_string_lossy().into_owned()
    };
    // SAFETY: open takes the NUL-terminated path a pointer points at.
    let slave = unsafe {
        libc::open(
            // SAFETY: the path has no interior NUL.
            std::ffi::CString::new(path.as_str()).unwrap().as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY,
        )
    };
    assert!(
        slave >= 0,
        "open {path}: {}",
        std::io::Error::last_os_error()
    );
    // The fixture reads the master with "whatever is ready" semantics, so
    // the descriptor is made nonblocking (it is the test's own).
    // SAFETY: fcntl takes scalars on a live descriptor.
    // SAFETY: fcntl takes scalars on a live descriptor.
    let flags = unsafe { libc::fcntl(master, libc::F_GETFL) };
    assert!(flags >= 0, "F_GETFL");
    // SAFETY: as above; the flags came back from F_GETFL.
    let set = unsafe { libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_ne!(set, -1, "F_SETFL");
    Pty {
        master,
        slave,
        path,
    }
}

/// Forks a child that becomes a session leader with `path` as its
/// controlling terminal on descriptors 0, 1 and 2, then execs `argv`.
/// The child never returns; on an exec failure it exits 127.
fn spawn_session_leader(path: &str, argv: &[&str]) -> pid_t {
    // SAFETY: fork; the child below touches only async-signal-fine calls
    // before exec, and the parent only records the pid.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        // SAFETY: each call takes scalars or pointers to live storage; the
        // child never returns.
        unsafe {
            let _ = libc::setsid();
            let c_path = std::ffi::CString::new(path).unwrap();
            let fd = libc::open(c_path.as_ptr(), libc::O_RDWR);
            if fd < 0 {
                libc::_exit(126);
            }
            // The controlling terminal of the new session (BSD takes a
            // null argument).
            let _ = libc::ioctl(
                fd,
                libc::TIOCSCTTY as libc::c_ulong,
                std::ptr::null_mut::<c_char>(),
            );
            for target in [0, 1, 2] {
                libc::dup2(fd, target);
            }
            if fd > 2 {
                libc::close(fd);
            }
            let program = std::ffi::CString::new(argv[0]).unwrap();
            let args: Vec<std::ffi::CString> = argv
                .iter()
                .map(|a| std::ffi::CString::new(*a).unwrap())
                .collect();
            let mut pointers: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
            pointers.push(std::ptr::null());
            libc::execvp(program.as_ptr(), pointers.as_ptr());
            libc::_exit(127);
        }
    }
    pid
}

/// The exit status of `pid`, once it is gone.
fn wait_for(pid: pid_t) -> c_int {
    let mut status: c_int = 0;
    // SAFETY: waitpid takes scalars and writable storage.
    let got = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(got, pid, "waitpid");
    status
}

/// Whether `status` reports exit code `code`.
fn exited_with(status: c_int, code: c_int) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == code
}

/// Pumps the relay until `seen` holds over the text that crossed
/// master → operator tty, or `None` when `BOUND` passed first.
fn pump_until(
    relay: &mut TerminalRelay,
    operator: &Pty,
    mut seen: impl FnMut(&str) -> bool,
) -> bool {
    let mut text = Vec::new();
    let deadline = std::time::Instant::now() + BOUND;
    loop {
        if seen(&String::from_utf8_lossy(&text)) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        match relay.pump(operator.slave.as_raw_fd()) {
            Ok(RelayEvent::Relayed { master_to_tty, .. }) => {
                if master_to_tty > 0 {
                    read_available(operator.master, &mut text);
                }
            }
            Ok(_) => {}
            Err(error) => panic!("pump: {error}"),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Reads whatever is ready on `fd` into `out`, nonblocking-ish.
fn read_available(fd: RawFd, out: &mut Vec<u8>) {
    let mut chunk = [0_u8; 4096];
    loop {
        // SAFETY: the slice is live and its length passed.
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n <= 0 {
            return;
        }
        out.extend_from_slice(&chunk[..usize::try_from(n).unwrap_or(0)]);
    }
}

/// Writes `bytes` to `fd`, asserting they were taken.
fn write_all(fd: RawFd, bytes: &[u8]) {
    // SAFETY: the slice is live and its length passed.
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    assert_eq!(usize::try_from(n).unwrap_or(0), bytes.len(), "write");
}

/// The `termios` of `fd`.
fn termios_of(fd: RawFd) -> libc::termios {
    // SAFETY: `termios` is writable storage tcgetattr fills.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is a number.
    let read = unsafe { libc::tcgetattr(fd, &raw mut termios) };
    assert_eq!(read, 0, "tcgetattr: {}", std::io::Error::last_os_error());
    termios
}

/// The exit status of `pid` if it is gone, without blocking.
fn wait_nohang(pid: pid_t) -> Option<c_int> {
    let mut status: c_int = 0;
    // SAFETY: waitpid takes scalars and writable storage.
    ((unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) }) == pid).then_some(status)
}

// ---------------------------------------------------------------------------
// §3.3 (b): bytes and windows through the relay
// ---------------------------------------------------------------------------

/// A shell on the relay's slave echoes what the operator types, and the
/// `^C` byte reaches the shell's group as `SIGINT` through the slave's
/// line discipline — the operator tty's raw mode holds the byte back no
/// longer than the pump.
#[test]
fn bytes_round_trip_and_a_control_c_reaches_the_slaves_group() {
    let operator = open_pty();
    let mut relay = TerminalRelay::allocate(operator.slave.as_raw_fd()).expect("allocate");
    // An interactive shell: it reads its commands from the slave, the way
    // a real workload reads the operator's keystrokes.
    let shell = spawn_session_leader(relay.device(), &["/bin/sh"]);

    // Type the ^Z trap first, then the command: operator → master → slave.
    write_all(operator.master, b"trap 'echo INTERRUPTED; exit 7' INT\n");
    write_all(operator.master, b"echo ok-$((1+1))\n");
    assert!(
        pump_until(&mut relay, &operator, |text| text.contains("ok-2")),
        "the shell's output never came back through the relay"
    );

    // ^C as the raw byte 0x03: the operator tty has ISIG cleared, so the
    // byte travels to the slave, whose line discipline signals the shell's
    // foreground group.
    write_all(operator.master, b"\x03");
    assert!(
        pump_until(&mut relay, &operator, |text| text.contains("INTERRUPTED")),
        "the ^C byte never became a SIGINT in the slave's group"
    );
    let status = common::eventually_some("the trapped shell to exit", BOUND, || wait_nohang(shell));
    assert!(
        exited_with(status, 7),
        "the trapped shell never exited 7: status {status}"
    );
}

/// The window size propagates: `TIOCSWINSZ` on the operator side shows up
/// on the slave, and a `SIGWINCH` reaches the slave's foreground group.
#[test]
fn window_sizes_propagate_to_the_slave() {
    let operator = open_pty();
    let mut relay = TerminalRelay::allocate(operator.slave.as_raw_fd()).expect("allocate");
    let mut winsize: libc::winsize = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let set = libc::winsize {
        ws_row: 33,
        ws_col: 99,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: both ioctls read or write the storage given.
    unsafe {
        libc::ioctl(operator.slave.as_raw_fd(), libc::TIOCSWINSZ, &raw const set);
    }
    assert!(
        relay.propagate_window().expect("propagate_window"),
        "a changed size must propagate"
    );
    assert!(
        !relay.propagate_window().expect("propagate_window"),
        "an unchanged size propagates nothing"
    );
    // SAFETY: as above.
    unsafe {
        libc::ioctl(
            relay.slave_fd().expect("slave"),
            libc::TIOCGWINSZ,
            &raw mut winsize,
        );
    }
    assert_eq!((winsize.ws_row, winsize.ws_col), (33, 99));
    // `TIOCSWINSZ` on the master is what makes the kernel signal the
    // slave's foreground group with `SIGWINCH`; the delivery itself is the
    // kernel's, and the size read back above is the relay's part.
}

// ---------------------------------------------------------------------------
// §3.3 step 1 / §3.6: raw mode saved, restored
// ---------------------------------------------------------------------------

/// `allocate` clears `ISIG`, `ICANON` and `ECHO` and keeps `OPOST|ONLCR`;
/// the settlement restore puts the saved `termios` back byte for byte and
/// flushes pending input.
#[test]
fn raw_mode_and_restore_round_trip() {
    let operator = open_pty();
    let before = termios_of(operator.slave.as_raw_fd());
    let mut relay = relay_on(&operator);
    let raw = termios_of(operator.slave.as_raw_fd());
    assert_eq!(raw.c_iflag & libc::ICRNL, 0, "cfmakeraw applied");
    assert_eq!(raw.c_lflag & (libc::ISIG | libc::ICANON | libc::ECHO), 0);
    assert_ne!(raw.c_oflag & libc::OPOST, 0, "OPOST must stay");
    assert_ne!(raw.c_oflag & libc::ONLCR, 0);

    // Type-ahead pending on the operator tty is discarded by the restore.
    write_all(operator.master, b"stale\n");
    let (restored, failures) = relay.settle(true);
    // The fixture's operator tty is not this process's controlling
    // terminal, so the foreground step answers ENOTTY here; every other
    // step must succeed. (A real supervisor passes condition 3 of §3.2.)
    assert!(restored.foreground || is_enotty(&failures, "foreground"));
    assert!(
        !restored.foreground || failures.is_empty(),
        "unexpected failures: {failures:?}"
    );
    assert!(restored.termios && restored.input_flushed);
    assert!(restored.after_tree_death);
    assert_eq!(relay.restored, Some(restored));
    assert_eq!(relay.stops, 0);
    let after = termios_of(operator.slave.as_raw_fd());
    assert_eq!(
        (
            after.c_iflag,
            after.c_oflag,
            after.c_lflag,
            after.c_cflag,
            after.c_cc
        ),
        (
            before.c_iflag,
            before.c_oflag,
            before.c_lflag,
            before.c_cflag,
            before.c_cc
        ),
        "the saved termios must come back"
    );
}

/// A relay whose operator tty is the fixture's.
fn relay_on(operator: &Pty) -> TerminalRelay {
    TerminalRelay::allocate(operator.slave.as_raw_fd()).expect("allocate")
}

/// The reset sequence reaches stderr only when stderr is a terminal; here
/// it usually is not (the harness captures it), and that is `Ok(false)`.
#[test]
fn write_reset_answers_whether_stderr_is_a_terminal() {
    let operator = open_pty();
    let relay = relay_on(&operator);
    // SAFETY: isatty takes a descriptor number.
    let stderr_is_tty = (unsafe { libc::isatty(2) }) == 1;
    assert_eq!(relay.write_reset().expect("write_reset"), stderr_is_tty);
}

// ---------------------------------------------------------------------------
// §3.4: the stop relay and its detection
// ---------------------------------------------------------------------------

/// `target_stopped` sees a child stopped with `SIGSTOP` and cleared again
/// by `SIGCONT`, at the J14 §3.4 polling cadence.
#[test]
fn target_stopped_polls_the_bsd_info() {
    // SAFETY: fork; the child pauses until signalled, then exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        loop {
            // SAFETY: pause takes no argument.
            unsafe { libc::pause() };
        }
    }
    assert_eq!(target_stopped(pid), None, "a running child is not stopped");
    // SAFETY: the child is this test's.
    unsafe { libc::kill(pid, libc::SIGSTOP) };
    common::eventually("the child to show stopped", BOUND, || {
        target_stopped(pid) == Some(libc::SIGTSTP)
    });
    // SAFETY: as above.
    unsafe { libc::kill(pid, libc::SIGCONT) };
    common::eventually("the child to run again", BOUND, || {
        target_stopped(pid).is_none()
    });
    // SAFETY: as above.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let _ = wait_for(pid);
}

/// The stop relay's terminal half: foreground back, saved `termios`
/// restored, the stop counted, and the own-group stop only when the caller
/// asks for it (signal 0 is the tests' "terminal steps only").
#[test]
fn relayed_stop_takes_back_the_terminal_and_counts() {
    let operator = open_pty();
    let before = termios_of(operator.slave.as_raw_fd());
    let mut relay = relay_on(&operator);
    // The workload changes the terminal; the relay holds the old copy.
    // The fixture's operator tty is not this process's controlling
    // terminal, so the foreground step may answer ENOTTY; the `termios`
    // step is attempted whatever it did.
    if let Err(error) = relay.relayed_stop(0) {
        assert_eq!(error.raw_os_error(), Some(libc::ENOTTY), "{error}");
    }
    assert_eq!(relay.stops, 1);
    // The stop restored the copy saved at attach. (From a background
    // caller — the fixture, which does not hold the terminal — Darwin
    // defers a `tcsetattr` until the next drain or flush, so flush first;
    // a real supervisor has taken the foreground back by then and needs
    // no flush for the change to apply.)
    // SAFETY: tcflush takes scalars.
    unsafe { libc::tcflush(operator.slave.as_raw_fd(), libc::TCIFLUSH) };
    let now = termios_of(operator.slave.as_raw_fd());
    assert_eq!(
        now.c_lflag, before.c_lflag,
        "the stop restored the saved copy"
    );
    // The shell's fg changes the terminal again; `continued` re-saves that
    // copy and re-applies the raw mode.
    let mut altered = before;
    altered.c_lflag &= !libc::ECHO;
    // SAFETY: tcsetattr takes scalars; the fixture pty has no background
    // group of this session to stop.
    unsafe { libc::tcsetattr(operator.slave.as_raw_fd(), libc::TCSANOW, &altered) };
    relay.continued().expect("continued");
    let raw = termios_of(operator.slave.as_raw_fd());
    assert_eq!(
        raw.c_lflag & libc::ECHO,
        0,
        "raw-ish mode is back after the continue"
    );
    let (restored, failures) = relay.settle(false);
    assert!(
        restored.foreground || is_enotty(&failures, "foreground"),
        "settle failed: {failures:?}"
    );
    assert!(restored.termios && restored.input_flushed && !restored.after_tree_death);
    assert_eq!(relay.stops, 1);
    let after = termios_of(operator.slave.as_raw_fd());
    // The continue re-saved the shell's (altered) copy, and settle puts
    // that copy back — not the one from before the stop.
    assert_eq!(
        after.c_lflag, altered.c_lflag,
        "settle restored the last saved copy"
    );
}

// ---------------------------------------------------------------------------
// §3.7: the pre-exec line; and the killed agent
// ---------------------------------------------------------------------------

/// The pre-exec line names the relay device, the wall, the target and the
/// supervisor's pid.
#[test]
fn the_pre_exec_line_names_device_wall_target_and_supervisor() {
    let operator = open_pty();
    let relay = relay_on(&operator);
    assert_eq!(
        relay.pre_exec_line("assistant", 41234, Some("8h")),
        format!(
            "terminal: relay ({}) · wall 8h · ^C and ^Z go to assistant's session on the \
             relay; to end the attempt, exit assistant or run kill -INT 41234",
            relay.device()
        )
    );
    assert_eq!(relay.session(), "relay");
    assert!(
        relay.device().starts_with("/dev/ttys"),
        "a macOS pty slave path"
    );
}

/// A killed agent is an end of stream the pump reports as an event, never a
/// panic, and the settlement restore still runs complete.
#[test]
fn a_killed_agent_ends_the_relay_without_a_panic() {
    let operator = open_pty();
    let mut relay = TerminalRelay::allocate(operator.slave.as_raw_fd()).expect("allocate");
    let shell = spawn_session_leader(relay.device(), &["/bin/sh", "-c", "echo alive; sleep 30"]);
    assert!(
        pump_until(&mut relay, &operator, |text| text.contains("alive")),
        "the shell's first output never arrived"
    );
    // SAFETY: the child is this test's.
    unsafe { libc::kill(shell, libc::SIGKILL) };
    let _ = wait_for(shell);
    // Until every slave descriptor is closed the master never ends; the
    // relay's own copy is the last one.
    relay.close_slave();
    let mut event = RelayEvent::Idle;
    let deadline = std::time::Instant::now() + BOUND;
    while event != RelayEvent::EndOfStream {
        assert!(
            std::time::Instant::now() < deadline,
            "no end of stream after the kill"
        );
        match relay.pump(operator.slave.as_raw_fd()).expect("pump") {
            RelayEvent::EndOfStream => {
                event = RelayEvent::EndOfStream;
                break;
            }
            other => event = other,
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(event, RelayEvent::EndOfStream);
    let (restored, failures) = relay.settle(true);
    assert!(
        restored.foreground || is_enotty(&failures, "foreground"),
        "settle failed: {failures:?}"
    );
    assert!(restored.termios && restored.input_flushed);
    assert!(relay.restored.is_some());
}

/// The relay's receipt facts line up with `applied.terminal` (§4.11): the
/// session constant, the stop count, and the restored struct the boundary
/// slice writes.
#[test]
fn receipt_facts_carry_session_stops_and_restore() {
    let operator = open_pty();
    let mut relay = relay_on(&operator);
    assert_eq!(relay.session(), "relay");
    for _ in 0..2 {
        // The fixture's operator tty is not this process's controlling
        // terminal; the foreground step may answer ENOTTY.
        if let Err(error) = relay.relayed_stop(0) {
            assert_eq!(error.raw_os_error(), Some(libc::ENOTTY), "{error}");
        }
    }
    assert_eq!(relay.stops, 2);
    let (restored, failures) = relay.settle(false);
    assert_eq!(
        restored,
        ukai_jail::records::TerminalRestored {
            // ENOTTY in the fixture; a real supervisor takes it back.
            foreground: restored.foreground,
            termios: true,
            input_flushed: true,
            // SAFETY: isatty takes a descriptor number.
            reset_written: (unsafe { libc::isatty(2) }) == 1,
            after_tree_death: false,
        }
    );
    assert!(restored.foreground || is_enotty(&failures, "foreground"));
}

/// Whether `failures` is exactly the fixture's `ENOTTY` foreground step.
fn is_enotty(failures: &[ukai_jail::terminal::StepFailure], step: &str) -> bool {
    failures.len() == 1 && failures[0].step == step && failures[0].errno == "ENOTTY"
}

/// The settlement restore in the caller's session: a forked child makes the
/// operator tty its controlling terminal (condition 3 of §3.2, as a real
/// supervisor has), and every step then succeeds — foreground, `termios`,
/// input flush — with the steps reported back in the exit status.
#[test]
fn settle_succeeds_when_the_terminal_is_the_callers_own() {
    let operator = open_pty();
    let before = termios_of(operator.slave.as_raw_fd());
    let path = std::ffi::CString::new(operator.path.as_str()).unwrap();
    // SAFETY: fork; the child below stays to async-signal-fine calls until
    // its own relay work, then exits with a bitmap; the parent only waits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: each call takes scalars or pointers to live storage; the
        // child never returns.
        unsafe {
            if libc::setsid() < 0 {
                libc::_exit(120);
            }
            let fd = libc::open(path.as_ptr(), libc::O_RDWR);
            if fd < 0 {
                libc::_exit(121);
            }
            if libc::ioctl(
                fd,
                libc::TIOCSCTTY as libc::c_ulong,
                std::ptr::null_mut::<c_char>(),
            ) != 0
            {
                libc::_exit(122);
            }
            let Ok(mut relay) = TerminalRelay::allocate(fd) else {
                libc::_exit(123);
            };
            let mut altered = before;
            altered.c_lflag &= !libc::ECHO;
            libc::tcsetattr(fd, libc::TCSANOW, &altered);
            if relay.relayed_stop(0).is_err() {
                libc::_exit(124);
            }
            let (restored, failures) = relay.settle(true);
            if !failures.is_empty() {
                libc::_exit(125);
            }
            // Bit 0 foreground, 1 termios, 2 input flushed, 3 the saved
            // `termios` read back equal, 4 the child's group in the
            // foreground.
            let after_readback = {
                let mut t: libc::termios = std::mem::zeroed();
                libc::tcgetattr(fd, &raw mut t) == 0
                    && (t.c_iflag, t.c_oflag, t.c_lflag, t.c_cflag, t.c_cc)
                        == (
                            before.c_iflag,
                            before.c_oflag,
                            before.c_lflag,
                            before.c_cflag,
                            before.c_cc,
                        )
            };
            libc::_exit(
                i32::from(restored.foreground)
                    | i32::from(restored.termios) << 1
                    | i32::from(restored.input_flushed) << 2
                    | i32::from(after_readback) << 3
                    | i32::from(libc::tcgetpgrp(fd) == libc::getpgrp()) << 4,
            );
        }
    }
    let status = wait_for(pid);
    // 0b11111 is the child's bitmap: foreground, termios, input flushed,
    // the saved `termios` read back equal, and its own group in the
    // foreground.
    assert!(
        exited_with(status, 0b11111),
        "the child's settle did not run complete: status {status}"
    );
}
