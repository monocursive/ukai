//! The terminal modes (J14, `docs/specs/jail-interactive-sessions.md` §6.1):
//! what a contained process sees of an attached terminal, the vectors §3.5
//! lists against the operator's terminal, and, outside the jail, a small
//! job-control shell and a pipeline member that log every signal they get.
//!
//! The probes run inside the jail and report on their standard output, which
//! is the terminal under test; the shell and the pipeline member run outside
//! it and report on a descriptor of their own.

use std::ffi::{CString, OsString, c_int};
use std::os::unix::ffi::OsStrExt as _;

use serde_json::{Value, json};

use crate::cli::{TtyMode, TtyTarget};
use crate::report::{OpReport, Reporter, write_all};

use super::{Stop, raw_errno};

/// Run one terminal mode.
pub(crate) fn run(rep: &Reporter, mode: TtyMode) -> Result<bool, Stop> {
    match mode {
        TtyMode::TtyProbe {
            wait_winch_ms,
            cbreak,
        } => Ok(probe(rep, wait_winch_ms, cbreak)),
        TtyMode::TtyIoctl { request, on } => Ok(tty_ioctl(rep, &request, on)),
        TtyMode::TtyKillProbe { signal } => Ok(kill_probe(rep, &signal)),
        TtyMode::TtyMess { hold_ms } => Ok(mess(rep, hold_ms)),
        TtyMode::TtyStray { dir, ms } => stray(rep, &dir, ms),
        TtyMode::TtySteal { stop_after_ms, ms } => Ok(steal(rep, stop_after_ms, ms)),
        TtyMode::TtyQueryStop { wait_ms } => Ok(query_stop(rep, wait_ms)),
        TtyMode::TrapAll { log } => trap_all(&log),
        TtyMode::JobShell {
            control_fd,
            status_fd,
            member,
            background,
            stdin_path,
            block,
            gate_pipe,
            argv,
        } => job_shell(
            control_fd,
            status_fd,
            &Job {
                member: member.as_deref(),
                background,
                stdin_path: stdin_path.as_deref(),
                block: &block,
                gate_pipe,
            },
            &argv,
        ),
    }
}

fn errno_value(ret: c_int) -> Value {
    if ret < 0 {
        Value::from(crate::errno::spelling(raw_errno()))
    } else {
        Value::Null
    }
}

/// `SigBlk` of `/proc/self/status`, as its hex text (Linux).
fn sig_blocked() -> Value {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("SigBlk:").map(|v| v.trim().to_owned()))
        })
        .map_or(Value::Null, Value::from)
}

fn winsize(fd: c_int) -> (Value, Value) {
    // SAFETY: `size` is plain stack data TIOCGWINSZ fills.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: an ioctl on a descriptor number with a pointer to `size`.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &raw mut size) } == 0 {
        (Value::from(size.ws_row), Value::from(size.ws_col))
    } else {
        (Value::Null, Value::Null)
    }
}

static WINCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

extern "C" fn on_winch(_signal: c_int) {
    WINCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// What standard input is, as terminal mode attaches it: `/dev/tty`, the
/// window size, the process and foreground groups, the session, and the
/// blocked signal set. With `wait_winch_ms`, a `ready` line, then the
/// first `SIGWINCH` (and the new size) within that long.
fn probe(rep: &Reporter, wait_winch_ms: Option<u64>, cbreak: bool) -> bool {
    if wait_winch_ms.is_some() {
        // SAFETY: a zeroed action with an `extern "C"` handler that only
        // touches an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_winch as *const () as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            libc::sigaction(libc::SIGWINCH, &raw const action, std::ptr::null_mut());
        }
    }
    let mut r = OpReport::new("tty-probe");
    // SAFETY: isatty and the group calls take scalars.
    let (is_tty, pgrp, fg, sid, tsid) = unsafe {
        (
            libc::isatty(0) == 1,
            libc::getpgrp(),
            libc::tcgetpgrp(0),
            libc::getsid(0),
            libc::tcgetsid(0),
        )
    };
    r.set("stdin_isatty", is_tty);
    // SAFETY: a NUL-terminated literal; the descriptor is closed below.
    let tty = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    r.set(
        "dev_tty",
        if tty >= 0 {
            Value::Null
        } else {
            errno_value(tty)
        },
    );
    let (rows, cols) = winsize(0);
    if tty >= 0 {
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(tty) };
    }
    r.set("rows", rows);
    r.set("cols", cols);
    r.set("pgrp", pgrp);
    r.set("foreground_pgrp", fg);
    r.set("foreground", fg == pgrp);
    r.set("sid", sid);
    r.set("terminal_sid", tsid);
    r.set("sig_blocked", sig_blocked());
    rep.emit(&r);
    let Some(ms) = wait_winch_ms else {
        return true;
    };
    if cbreak {
        // SAFETY: `t` is plain stack data tcgetattr fills and tcsetattr
        // reads.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &raw mut t) == 0 {
                t.c_lflag &= !(libc::ICANON | libc::ECHO);
                libc::tcsetattr(0, libc::TCSANOW, &raw const t);
            }
        }
    }
    let mut ready = OpReport::new("tty-ready");
    ready.set(
        "winch_before",
        WINCH.load(std::sync::atomic::Ordering::SeqCst),
    );
    rep.emit(&ready);
    let start = std::time::Instant::now();
    while WINCH.load(std::sync::atomic::Ordering::SeqCst) == 0
        && start.elapsed() < std::time::Duration::from_millis(ms)
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let mut w = OpReport::new("tty-winch");
    let count = WINCH.load(std::sync::atomic::Ordering::SeqCst);
    w.set("received", count > 0);
    let (rows, cols) = winsize(0);
    w.set("rows", rows);
    w.set("cols", cols);
    rep.emit(&w);
    count > 0
}

/// The ioctl request numbers the probes name (the asm-generic values every
/// architecture this project builds for uses).
fn request_number(name: &str) -> Option<u64> {
    Some(match name {
        "tiocsti" => 0x5412,
        "tioclinux" => 0x541c,
        "tiocsetd" => 0x5423,
        "tcgets" => 0x5401,
        "tiocgwinsz" => 0x5413,
        "tiocgpgrp" => 0x540f,
        "tiocspgrp" => 0x5410,
        "kdgkbmode" => 0x4b44,
        "kdskbmode" => 0x4b45,
        "kdskbent" => 0x4b47,
        _ => return None,
    })
}

/// One ioctl on standard input, `/dev/null` or `/dev/tty`, with a harmless
/// argument: the byte `x` for `TIOCSTI`, a read-only subcommand (12) for
/// `TIOCLINUX`, `N_TTY` for `TIOCSETD`, group 0 (which names no group) for
/// `TIOCSPGRP`, a buffer for the getters.
fn tty_ioctl(rep: &Reporter, request: &str, on: TtyTarget) -> bool {
    let mut r = OpReport::new("tty-ioctl");
    r.set("request", request);
    let Some(number) = request_number(request) else {
        r.set("refused", "unknown request");
        r.result(-1, None);
        rep.emit(&r);
        return false;
    };
    let (fd, close) = match on {
        TtyTarget::Stdin => (0, false),
        // SAFETY: NUL-terminated literals; closed below.
        TtyTarget::Devnull => (
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) },
            true,
        ),
        TtyTarget::Devtty => (
            // SAFETY: as above.
            unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY) },
            true,
        ),
    };
    r.set(
        "on",
        match on {
            TtyTarget::Stdin => "stdin",
            TtyTarget::Devnull => "devnull",
            TtyTarget::Devtty => "devtty",
        },
    );
    let mut buffer = [0u8; 64];
    buffer[0] = match request {
        "tiocsti" => b'x',
        "tioclinux" => 12,
        _ => 0,
    };
    // SAFETY: an ioctl with a pointer to a 64-byte buffer, larger than any
    // argument these requests read or write.
    let ret = unsafe { libc::ioctl(fd, number as _, buffer.as_mut_ptr()) };
    let errno = (ret < 0).then(raw_errno);
    if close && fd >= 0 {
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(fd) };
    }
    r.result(i64::from(ret), errno);
    rep.emit(&r);
    true
}

/// Every signal route out of the command's group (§3.5 row 7, K57), with
/// `signal` (default `TERM`, ignored here first): `kill(0)`, `kill(-pgid)`
/// for every group visible in this PID namespace, `kill(-1)`, then
/// `setpgid` and `tcsetpgrp` toward every visible group. One line each.
fn kill_probe(rep: &Reporter, signal: &str) -> bool {
    let number = match signal {
        "TERM" => libc::SIGTERM,
        "URG" => libc::SIGURG,
        "USR1" => libc::SIGUSR1,
        _ => libc::SIGTERM,
    };
    // SAFETY: SIG_IGN for the signal this probe sends to its own group.
    unsafe { libc::signal(number, libc::SIG_IGN) };
    // SAFETY: getpgrp takes no argument.
    let own = unsafe { libc::getpgrp() };
    let mut groups: Vec<c_int> = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<c_int>().ok())
        else {
            continue;
        };
        // SAFETY: getpgid takes a pid.
        let group = unsafe { libc::getpgid(pid) };
        if group > 0 && !groups.contains(&group) {
            groups.push(group);
        }
    }
    groups.sort_unstable();
    let emit = |op: &str, target: Value, ret: c_int| {
        let mut r = OpReport::new(op);
        r.set("target", target);
        r.set("own_pgrp", own);
        r.result(i64::from(ret), (ret < 0).then(raw_errno));
        rep.emit(&r);
    };
    // SAFETY: kill, setpgid and tcsetpgrp take scalars.
    unsafe {
        emit("kill", json!(0), libc::kill(0, number));
        for group in &groups {
            emit("kill", json!(-group), libc::kill(-group, number));
        }
        emit("kill", json!(-1), libc::kill(-1, number));
        for group in &groups {
            if *group != own {
                emit("setpgid", json!(group), libc::setpgid(0, *group));
                emit("tcsetpgrp", json!(group), libc::tcsetpgrp(0, *group));
            }
        }
        // A group number that names nothing here (the outside groups have
        // none inside the namespace).
        emit(
            "tcsetpgrp",
            json!(0x7fff_fff0),
            libc::tcsetpgrp(0, 0x7fff_fff0),
        );
        emit("setpgid", json!(0x7fff_fff0), libc::setpgid(0, 0x7fff_fff0));
    }
    let mut r = OpReport::new("groups");
    r.set("visible", groups.clone());
    rep.emit(&r);
    true
}

/// §3.5 rows 1 to 7 and 9 against the attached terminal (K61, K62): try to
/// inject bytes (`TIOCSTI`, `TIOCLINUX` paste), change the line discipline,
/// console keyboard ioctls, raw mode and echo off, give the foreground to
/// another group of its own, conceal text (`SGR 8`) and hide the pointer,
/// and ask the terminal for a cursor report it never reads, so the reply is
/// left in the input queue; then hold `hold_ms` and exit, leaving the child
/// group behind for the settlement to end.
fn mess(rep: &Reporter, hold_ms: u64) -> bool {
    let emit = |op: &str, ret: c_int| {
        let mut r = OpReport::new(op);
        r.result(i64::from(ret), (ret < 0).then(raw_errno));
        rep.emit(&r);
    };
    // Row 1: one byte at a time, as TIOCSTI takes it.
    for byte in b"INJECTED\n" {
        // SAFETY: TIOCSTI reads one byte from the pointer.
        let ret = unsafe { libc::ioctl(0, 0x5412 as _, byte as *const u8) };
        emit("tiocsti", ret);
    }
    // Row 2: TIOCLINUX paste of a selection (subcommand 3).
    let mut paste = [3u8; 8];
    // SAFETY: TIOCLINUX reads its subcommand from the buffer.
    emit("tioclinux", unsafe {
        libc::ioctl(0, 0x541c as _, paste.as_mut_ptr())
    });
    // Row 4: the line discipline (N_TTY again).
    let ldisc: c_int = 0;
    // SAFETY: TIOCSETD reads an int.
    emit("tiocsetd", unsafe {
        libc::ioctl(0, 0x5423 as _, &raw const ldisc)
    });
    // Row 3: console keyboard modes (a pty answers ENOTTY or EINVAL).
    let mode: c_int = 0;
    // SAFETY: KDSKBMODE takes an int by value.
    emit("kdskbmode", unsafe { libc::ioctl(0, 0x4b45 as _, mode) });
    // Row 5: raw mode and echo off.
    // SAFETY: `t` is plain stack data tcgetattr fills and tcsetattr reads.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &raw mut t) == 0 {
            libc::cfmakeraw(&raw mut t);
            t.c_lflag &= !libc::ECHO;
            emit("tcsetattr", libc::tcsetattr(0, libc::TCSANOW, &raw const t));
        } else {
            emit("tcsetattr", -1);
        }
    }
    // Row 9: conceal, hide the pointer, and a status query whose reply is
    // never read. Written raw: the mode is raw now.
    write_all(1, b"\x1b[8m\x1b[?25l\x1b[6n");
    // Row 6: the foreground to another group of this command's own, which
    // the terminal filter refuses (J14 review finding 1).
    // SAFETY: fork; the child only calls async-signal-safe functions.
    let child = unsafe { libc::fork() };
    if child == 0 {
        // SAFETY: setpgid and pause take scalars; the child never returns.
        unsafe {
            libc::setpgid(0, 0);
            loop {
                libc::pause();
            }
        }
    }
    if child > 0 {
        // SAFETY: setpgid and tcsetpgrp take scalars; SIGTTOU is ignored so
        // a background caller is not stopped.
        unsafe {
            libc::setpgid(child, child);
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            emit("tcsetpgrp", libc::tcsetpgrp(0, child));
        }
    }
    // Exclusive mode, which makes later opens of the terminal fail, then
    // output suspended, which `^Q` cannot undo and which blocks every later
    // write until resumed. Nothing is written after this.
    // SAFETY: TIOCEXCL takes no argument; tcflow takes scalars.
    unsafe {
        emit("tiocexcl", libc::ioctl(0, libc::TIOCEXCL as _));
        libc::tcflow(0, libc::TCOOFF);
    }
    std::thread::sleep(std::time::Duration::from_millis(hold_ms));
    true
}

/// K59: a descendant in a process group of its own that makes one traced
/// call (`mkdir DIR/N`) every few milliseconds for `ms`, logging each
/// completed call's `CLOCK_MONOTONIC` time to `DIR/stray.log`, while this
/// process sleeps as long. A stop of the command's group does not stop it.
fn stray(rep: &Reporter, dir: &std::ffi::OsStr, ms: u64) -> Result<bool, Stop> {
    let dir = std::path::PathBuf::from(dir);
    let log = dir.join("stray.log");
    // SAFETY: fork; the child runs ordinary code in a fresh single-threaded
    // process (the fixture has no other thread here).
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(Stop::Failed("fork failed".to_owned()));
    }
    if child == 0 {
        // SAFETY: setpgid takes scalars.
        unsafe { libc::setpgid(0, 0) };
        let start = std::time::Instant::now();
        let mut lines = String::new();
        let mut n = 0u64;
        while start.elapsed() < std::time::Duration::from_millis(ms) {
            n += 1;
            let path = dir.join(format!("d{n}"));
            if std::fs::create_dir(&path).is_ok() {
                // SAFETY: `now` is plain stack data clock_gettime fills.
                let mut now: libc::timespec = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
                lines.push_str(&format!(
                    "{}\n",
                    now.tv_sec as i128 * 1_000_000_000 + now.tv_nsec as i128
                ));
                let _ = std::fs::write(&log, &lines);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        std::process::exit(0);
    }
    let mut r = OpReport::new("stray");
    r.set("child", child);
    rep.emit(&r);
    std::thread::sleep(std::time::Duration::from_millis(ms));
    Ok(true)
}

/// J14 review finding 1: a helper in a process group of its own, with
/// `SIGTTOU` and `SIGTTIN` ignored, polls the terminal every 5 ms for MS:
/// whenever its foreground group is one this PID namespace cannot name
/// (`tcgetpgrp` answers 0: the supervisor's, or the operator's shell's), it
/// gives the terminal to its own group (`tcsetpgrp`) and, holding it, reads
/// what is typed. This process stops itself after STOP_AFTER_MS, which the
/// supervisor relays to the shell; continued, it waits for the helper and
/// reports its attempts, the errno of the first, whether one succeeded and
/// what it read. Nothing is written to the terminal while stopped: the
/// helper reports through a pipe.
fn steal(rep: &Reporter, stop_after_ms: u64, ms: u64) -> bool {
    let mut fds = [-1 as c_int; 2];
    // SAFETY: pipe fills the two-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: fork; the child runs ordinary code in a fresh single-threaded
    // process (the fixture has no other thread here).
    let child = unsafe { libc::fork() };
    if child < 0 {
        return false;
    }
    if child == 0 {
        // SAFETY: setpgid, signal and close take scalars.
        unsafe {
            libc::close(fds[0]);
            libc::setpgid(0, 0);
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        }
        let (mut attempts, mut first_errno, mut took) = (0u64, Value::Null, false);
        let mut read = Vec::new();
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(ms) {
            // SAFETY: tcgetpgrp, getpgrp and tcsetpgrp take scalars.
            unsafe {
                if libc::tcgetpgrp(0) == 0 {
                    attempts += 1;
                    let ret = libc::tcsetpgrp(0, libc::getpgrp());
                    if attempts == 1 {
                        first_errno = errno_value(ret);
                    }
                    took |= ret == 0;
                }
            }
            // SAFETY: tcgetpgrp and getpgrp take scalars.
            if unsafe { libc::tcgetpgrp(0) == libc::getpgrp() } {
                let mut pollfd = libc::pollfd {
                    fd: 0,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let mut buffer = [0u8; 256];
                // SAFETY: one live pollfd; a read into a live buffer.
                unsafe {
                    if libc::poll(&raw mut pollfd, 1, 5) > 0 {
                        let n = libc::read(0, buffer.as_mut_ptr().cast(), buffer.len());
                        if n > 0 {
                            read.extend_from_slice(&buffer[..n as usize]);
                        }
                    }
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        let line = json!({
            "attempts": attempts,
            "first_errno": first_errno,
            "took": took,
            "read": String::from_utf8_lossy(&read),
        })
        .to_string();
        write_all(fds[1], line.as_bytes());
        // SAFETY: _exit takes a scalar and never returns.
        unsafe { libc::_exit(0) };
    }
    // SAFETY: closing this process's copy of the write end.
    unsafe { libc::close(fds[1]) };
    let mut r = OpReport::new("tty-steal");
    r.set("helper", child);
    rep.emit(&r);
    std::thread::sleep(std::time::Duration::from_millis(stop_after_ms));
    // SAFETY: SIGSTOP to this process itself.
    unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
    let mut line = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        // SAFETY: a read into a live buffer from the pipe's read end.
        let n = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
        if n > 0 {
            line.extend_from_slice(&buffer[..n as usize]);
        } else if n == 0 || raw_errno() != libc::EINTR {
            break;
        }
    }
    let mut status: c_int = 0;
    // SAFETY: waitpid writes the status it is given.
    unsafe { libc::waitpid(child, &raw mut status, 0) };
    let mut done = OpReport::new("tty-steal-result");
    done.set(
        "helper",
        serde_json::from_slice::<Value>(&line).unwrap_or(Value::Null),
    );
    rep.emit(&done);
    true
}

/// J14 review finding 3: leaves the terminal raw, concealed (`SGR 8`) and
/// with the reply to a cursor-position query in its input queue, then stops
/// itself after WAIT_MS, so the supervisor relays the stop with all three in
/// place. Continued, it reports and exits.
fn query_stop(rep: &Reporter, wait_ms: u64) -> bool {
    // SAFETY: `t` is plain stack data tcgetattr fills and tcsetattr reads.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &raw mut t) == 0 {
            libc::cfmakeraw(&raw mut t);
            libc::tcsetattr(0, libc::TCSANOW, &raw const t);
        }
    }
    write_all(1, b"\x1b[8m\x1b[6n");
    std::thread::sleep(std::time::Duration::from_millis(wait_ms));
    // SAFETY: SIGSTOP to this process itself.
    unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
    rep.emit(&OpReport::new("tty-query-stop"));
    true
}

static TRAPPED: [std::sync::atomic::AtomicU32; 65] =
    [const { std::sync::atomic::AtomicU32::new(0) }; 65];

extern "C" fn on_trapped(signal: c_int) {
    if let Ok(index) = usize::try_from(signal)
        && index < TRAPPED.len()
    {
        TRAPPED[index].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Catches every catchable signal (but `SIGCHLD` and `SIGWINCH`, which a
/// terminal job gets by design) and counts them.
fn trap_every_signal() {
    for signal in 1..=64 {
        if matches!(
            signal,
            libc::SIGKILL | libc::SIGSTOP | libc::SIGCHLD | libc::SIGWINCH
        ) {
            continue;
        }
        // SAFETY: a zeroed action with an `extern "C"` handler that only
        // touches an atomic; a signal that cannot be caught is refused.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_trapped as *const () as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            libc::sigaction(signal, &raw const action, std::ptr::null_mut());
        }
    }
}

fn trapped() -> Vec<Value> {
    (1..TRAPPED.len())
        .filter_map(|signal| {
            let count = TRAPPED[signal].load(std::sync::atomic::Ordering::SeqCst);
            (count > 0).then(|| json!({"signal": signal, "count": count}))
        })
        .collect()
}

/// A pipeline member (`ukai-jail … | trap-all`): reads its standard input to
/// its end, catching every catchable signal, then writes the signals it got
/// to LOG as JSON. Runs outside the jail.
fn trap_all(log: &std::ffi::OsStr) -> Result<bool, Stop> {
    trap_every_signal();
    let mut buffer = [0u8; 4096];
    loop {
        // SAFETY: a read into a live buffer of the given length.
        let n = unsafe { libc::read(0, buffer.as_mut_ptr().cast(), buffer.len()) };
        if n == 0 {
            break;
        }
        if n < 0 && raw_errno() != libc::EINTR {
            break;
        }
    }
    let text = serde_json::to_string(&json!({"signals": trapped()})).unwrap_or_default();
    std::fs::write(log, text).map_err(|e| Stop::Failed(format!("trap-all log: {e}")))?;
    Ok(true)
}

fn status_line(fd: c_int, value: &Value) {
    let mut line = serde_json::to_string(value).unwrap_or_default();
    line.push('\n');
    write_all(fd, line.as_bytes());
}

fn read_command(fd: c_int) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        // SAFETY: a one-byte read into a live buffer.
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if n == 1 {
            if byte[0] == b'\n' {
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
            line.push(byte[0]);
        } else if n == 0 || raw_errno() != libc::EINTR {
            return None;
        }
    }
}

/// A job-control shell for one job (K55 to K64): the session leader of the
/// terminal on its standard input. It runs ARGV as a foreground job in a
/// process group of its own (with `--member`, a second process in the same
/// group, `ARGV | trap-all --log MEMBER`), and reports on STATUS_FD each
/// change of the job (`stopped` with its signal, `exited` with its status)
/// after taking the terminal back, as an interactive shell does. Commands
/// on CONTROL_FD, one per line: `fg`, `bg`, `drain` (read and report what is
/// left on the terminal), `quit` (report the signals this shell got, exit).
/// Runs outside the jail; ignores the terminal stop signals and `SIGINT` and
/// `SIGQUIT` as an interactive shell does, and counts every other signal.
/// How [`job_shell`] starts its job.
struct Job<'a> {
    member: Option<&'a std::ffi::OsStr>,
    background: bool,
    stdin_path: Option<&'a std::ffi::OsStr>,
    block: &'a [i32],
    gate_pipe: bool,
}

fn job_shell(
    control_fd: c_int,
    status_fd: c_int,
    options: &Job<'_>,
    argv: &[OsString],
) -> Result<bool, Stop> {
    let member = options.member;
    let stdin_path = options
        .stdin_path
        .map(|path| CString::new(path.as_bytes()))
        .transpose()
        .map_err(|_| Stop::Usage("NUL in --stdin-path".into()))?;
    let mut gate = [-1 as c_int; 2];
    if options.gate_pipe {
        // SAFETY: pipe fills the two-element array.
        if unsafe { libc::pipe(gate.as_mut_ptr()) } != 0 {
            return Err(Stop::Failed("pipe failed".to_owned()));
        }
        // SAFETY: closing the write end this process just made: the job
        // reads end-of-file at once.
        unsafe { libc::close(gate[1]) };
    }
    // SAFETY: `blocked` is plain stack data sigemptyset and sigaddset fill.
    let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    unsafe {
        libc::sigemptyset(&raw mut blocked);
        for signal in options.block {
            libc::sigaddset(&raw mut blocked, *signal);
        }
    }
    trap_every_signal();
    for signal in [
        libc::SIGTTOU,
        libc::SIGTTIN,
        libc::SIGTSTP,
        libc::SIGINT,
        libc::SIGQUIT,
    ] {
        // SAFETY: SIG_IGN for the job-control signals, as a shell does.
        unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
    let argv_c: Vec<CString> = argv
        .iter()
        .map(|part| CString::new(part.as_bytes()).map_err(|_| Stop::Usage("NUL in argv".into())))
        .collect::<Result<_, _>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|part| part.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let self_exe = std::env::current_exe().map_err(|e| Stop::Failed(e.to_string()))?;
    let member_argv: Option<Vec<CString>> = member.map(|log| {
        vec![
            CString::new(self_exe.as_os_str().as_bytes()).unwrap_or_default(),
            CString::new("--no-report").unwrap_or_default(),
            CString::new("trap-all").unwrap_or_default(),
            CString::new("--log").unwrap_or_default(),
            CString::new(log.as_bytes()).unwrap_or_default(),
        ]
    });
    let member_ptrs: Option<Vec<*const libc::c_char>> = member_argv.as_ref().map(|parts| {
        let mut ptrs: Vec<*const libc::c_char> = parts.iter().map(|part| part.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        ptrs
    });
    let mut pipe = [-1 as c_int; 2];
    if member.is_some() {
        // SAFETY: pipe fills the two-element array.
        if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
            return Err(Stop::Failed("pipe failed".to_owned()));
        }
    }
    // SAFETY: getpgrp takes no argument.
    let own = unsafe { libc::getpgrp() };
    // SAFETY: fork; the child only calls async-signal-safe functions on
    // data built before the fork, then execs.
    let job = unsafe { libc::fork() };
    if job < 0 {
        return Err(Stop::Failed("fork failed".to_owned()));
    }
    if job == 0 {
        // SAFETY: as above: setpgid, tcsetpgrp, signal, dup2, close and
        // execv are async-signal-safe.
        unsafe {
            libc::setpgid(0, 0);
            if !options.background {
                libc::tcsetpgrp(0, libc::getpid());
            }
            for signal in 1..=64 {
                libc::signal(signal, libc::SIG_DFL);
            }
            libc::sigprocmask(libc::SIG_SETMASK, &raw const blocked, std::ptr::null_mut());
            // The shell's own descriptors go first: the gate may be placed
            // at the number one of them had.
            libc::close(control_fd);
            libc::close(status_fd);
            if let Some(path) = &stdin_path {
                let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
                if fd < 0 {
                    libc::_exit(126);
                }
                libc::dup2(fd, 0);
                libc::close(fd);
            }
            if options.gate_pipe {
                libc::dup2(gate[0], 3);
                libc::close(gate[0]);
            }
            if member.is_some() {
                libc::dup2(pipe[1], 1);
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            libc::execv(argv_ptrs[0], argv_ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    // SAFETY: setpgid and tcsetpgrp take scalars (the race with the child's
    // own calls is the shell's usual one, and both agree).
    unsafe {
        libc::setpgid(job, job);
        if !options.background {
            libc::tcsetpgrp(0, job);
        }
        if options.gate_pipe {
            libc::close(gate[0]);
        }
    }
    let mut member_pid = 0;
    if let Some(ptrs) = &member_ptrs {
        // SAFETY: as for the job.
        member_pid = unsafe { libc::fork() };
        if member_pid == 0 {
            // SAFETY: as for the job.
            unsafe {
                libc::setpgid(0, job);
                for signal in 1..=64 {
                    libc::signal(signal, libc::SIG_DFL);
                }
                libc::dup2(pipe[0], 0);
                libc::close(pipe[0]);
                libc::close(pipe[1]);
                libc::close(control_fd);
                libc::close(status_fd);
                libc::execv(ptrs[0], ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        // SAFETY: setpgid takes scalars; the pipe ends are this process's.
        unsafe {
            libc::setpgid(member_pid, job);
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
    }
    status_line(
        status_fd,
        &json!({"event": "started", "job": job, "member": member_pid, "shell_pgrp": own}),
    );
    let mut exited = false;
    // A job continued in the background (`bg`) is not waited for until `fg`
    // brings it back, so the next command is read while it runs.
    let mut waiting = true;
    loop {
        if !exited && waiting {
            let mut status: c_int = 0;
            // SAFETY: waitpid writes the status it is given.
            let pid = unsafe { libc::waitpid(job, &raw mut status, libc::WUNTRACED) };
            if pid < 0 {
                if raw_errno() == libc::EINTR {
                    continue;
                }
                exited = true;
                status_line(status_fd, &json!({"event": "wait_failed"}));
                continue;
            }
            // The group the job left in the foreground, before the shell
            // takes the terminal back: what the job itself did with it.
            // SAFETY: tcgetpgrp and tcsetpgrp take scalars; SIGTTOU is
            // ignored here.
            let foreground = unsafe { libc::tcgetpgrp(0) };
            // The terminal's flags as the job left them.
            // SAFETY: `t` is plain stack data tcgetattr fills.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            unsafe { libc::tcgetattr(0, &raw mut t) };
            // SAFETY: as above.
            unsafe { libc::tcsetpgrp(0, own) };
            if libc::WIFSTOPPED(status) {
                // A stopped job is waited for again once `fg` continues it,
                // so commands such as `drain` are read meanwhile.
                waiting = false;
                status_line(
                    status_fd,
                    &json!({"event": "stopped", "signal": libc::WSTOPSIG(status),
                            "foreground": foreground, "lflag": t.c_lflag as u64}),
                );
            } else {
                exited = true;
                let (code, signal) = if libc::WIFEXITED(status) {
                    (Some(libc::WEXITSTATUS(status)), None)
                } else {
                    (None, Some(libc::WTERMSIG(status)))
                };
                if member_pid > 0 {
                    let mut member_status: c_int = 0;
                    // SAFETY: as above.
                    unsafe { libc::waitpid(member_pid, &raw mut member_status, 0) };
                }
                status_line(
                    status_fd,
                    &json!({"event": "exited", "code": code, "signal": signal,
                            "foreground": foreground, "lflag": t.c_lflag as u64}),
                );
                continue;
            }
        }
        let Some(command) = read_command(control_fd) else {
            break;
        };
        match command.as_str() {
            "fg" => {
                waiting = true;
                // SAFETY: tcsetpgrp and kill take scalars.
                unsafe {
                    libc::tcsetpgrp(0, job);
                    libc::kill(-job, libc::SIGCONT);
                }
            }
            "tostop" => {
                // SAFETY: `t` is plain stack data tcgetattr fills and
                // tcsetattr reads.
                unsafe {
                    let mut t: libc::termios = std::mem::zeroed();
                    libc::tcgetattr(0, &raw mut t);
                    t.c_lflag |= libc::TOSTOP;
                    libc::tcsetattr(0, libc::TCSANOW, &raw const t);
                }
                status_line(status_fd, &json!({"event": "tostop"}));
            }
            "wait" => {
                // Wait for a job in the background without giving it the
                // terminal.
                waiting = true;
            }
            "bg" => {
                waiting = false;
                // SAFETY: kill takes scalars.
                unsafe { libc::kill(-job, libc::SIGCONT) };
            }
            "drain" => {
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                // SAFETY: fcntl and read on standard input with a live buffer.
                unsafe {
                    let flags = libc::fcntl(0, libc::F_GETFL);
                    libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    loop {
                        let n = libc::read(0, buffer.as_mut_ptr().cast(), buffer.len());
                        if n <= 0 {
                            break;
                        }
                        bytes.extend_from_slice(&buffer[..n as usize]);
                    }
                    libc::fcntl(0, libc::F_SETFL, flags);
                }
                // SAFETY: tcgetpgrp takes a descriptor number.
                let foreground = unsafe { libc::tcgetpgrp(0) };
                // Whether the terminal still opens (exclusive mode refuses).
                // SAFETY: a NUL-terminated literal; the descriptor is closed.
                let dev_tty = unsafe {
                    let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
                    if fd >= 0 {
                        libc::close(fd);
                        Value::from("ok")
                    } else {
                        errno_value(fd)
                    }
                };
                // SAFETY: `t` is plain stack data tcgetattr fills.
                let mut t: libc::termios = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                unsafe { libc::tcgetattr(0, &raw mut t) };
                status_line(
                    status_fd,
                    &json!({
                        "event": "drained",
                        "bytes": bytes,
                        "foreground": foreground,
                        "shell_pgrp": own,
                        "lflag": t.c_lflag as u64,
                        "iflag": t.c_iflag as u64,
                        "oflag": t.c_oflag as u64,
                        "dev_tty": dev_tty,
                    }),
                );
            }
            "quit" => {
                status_line(status_fd, &json!({"event": "quit", "signals": trapped()}));
                break;
            }
            _ => status_line(status_fd, &json!({"event": "unknown_command"})),
        }
    }
    Ok(true)
}
