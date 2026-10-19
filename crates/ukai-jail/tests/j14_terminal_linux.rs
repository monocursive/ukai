//! J14 terminal mode, live (`docs/specs/jail-interactive-sessions.md` §6.1,
//! rows K55 to K64).
//!
//! The pseudo-terminal harness: a fresh pty whose slave is the controlling
//! terminal of a job-control shell (`ukai-fixture job-shell`), which runs
//! `ukai-jail` as its foreground job the way an interactive shell does,
//! reports each change of the job (stopped, exited) after taking the
//! terminal back, and takes `fg`, `bg`, `drain` and `quit` from the test.
//! The test is the terminal emulator: it reads everything written to the
//! master, types keystrokes into it (`^C`, `^\`, `^Z`), resizes it, and
//! answers a cursor-position query when a probe asks for one. Every receipt
//! is held to the re-blessed schemas.
#![cfg(target_os = "linux")]

mod common;

use std::ffi::OsString;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use ukai_fixture::harness;

/// The size the harness's terminal starts with.
const ROWS: u16 = 33;
const COLS: u16 = 101;
/// How long one session may take.
const SESSION: Duration = Duration::from_secs(90);
/// The word in a jail argv that stands for the fixture's copy in the
/// workspace: the build's own copy lies outside every grant.
const FIXTURE: &str = "@fixture";

fn openpty() -> (OwnedFd, OwnedFd) {
    let (mut master, mut slave) = (-1, -1);
    let mut size = libc::winsize {
        ws_row: ROWS,
        ws_col: COLS,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: both pointers are to live integers the call fills; the name and
    // termios arguments may be null, and the window size is live.
    let rc = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut size,
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: openpty returned two fresh descriptors this test now owns.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 fills the two-element array.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: two fresh descriptors this test now owns.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// What one session runs, and how the shell starts it.
#[derive(Default, Clone)]
struct Options {
    /// The words after `ukai-jail`.
    jail: Vec<OsString>,
    /// Extra environment for the jail.
    env: Vec<(String, OsString)>,
    /// A pipeline member that logs the signals it gets.
    member: bool,
    /// Run as a background job.
    background: bool,
    /// The job's standard input instead of the terminal.
    stdin_path: Option<PathBuf>,
    /// Signals the job starts with blocked.
    block: Vec<i32>,
    /// `--gate-fd 3` from a pipe at its end.
    gate_pipe: bool,
    /// Run this program instead of `ukai-jail` (a direct run, for X05).
    program: Option<PathBuf>,
    /// `config.toml` contents.
    config: Option<String>,
}

impl Options {
    /// `ukai-jail run --profile PROFILE --workspace W [EXTRA] -- FIXTURE ARGS`.
    fn run(profile: &str, extra: &[&str], fixture: &[&str]) -> Options {
        let mut jail: Vec<OsString> = ["run", "--profile", profile]
            .iter()
            .map(OsString::from)
            .collect();
        jail.extend(extra.iter().map(OsString::from));
        jail.push("--".into());
        jail.push(FIXTURE.into());
        jail.extend(fixture.iter().map(OsString::from));
        Options {
            jail,
            ..Options::default()
        }
    }

    fn env(mut self, name: &str, value: impl Into<OsString>) -> Options {
        self.env.push((name.to_owned(), value.into()));
        self
    }
}

/// The terminal side: the master, everything read from it, and whether to
/// answer a cursor-position query.
struct Terminal {
    master: Option<Arc<OwnedFd>>,
    output: Arc<Mutex<Vec<u8>>>,
    answer_queries: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Terminal {
    fn start(master: OwnedFd) -> Terminal {
        let master = Arc::new(master);
        let output = Arc::new(Mutex::new(Vec::new()));
        let answer_queries = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let master = Arc::clone(&master);
            let output = Arc::clone(&output);
            let answer = Arc::clone(&answer_queries);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut answered = 0usize;
                let mut buffer = [0u8; 4096];
                loop {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let mut pollfd = libc::pollfd {
                        fd: master.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: one live pollfd, a short timeout.
                    if unsafe { libc::poll(&raw mut pollfd, 1, 50) } <= 0 {
                        continue;
                    }
                    // SAFETY: a read into a live buffer from the master.
                    let n = unsafe {
                        libc::read(master.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len())
                    };
                    if n <= 0 {
                        if n < 0
                            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                        {
                            continue;
                        }
                        break;
                    }
                    let mut seen = output.lock().unwrap();
                    seen.extend_from_slice(&buffer[..usize::try_from(n).unwrap()]);
                    // A terminal answers a cursor-position query (`ESC [ 6
                    // n`) by putting its reply in the input queue.
                    if answer.load(Ordering::SeqCst) {
                        let queries = count(&seen, b"\x1b[6n");
                        while answered < queries {
                            answered += 1;
                            write_master(&master, b"\x1b[24;80R");
                        }
                    }
                }
            })
        };
        Terminal {
            master: Some(master),
            output,
            answer_queries,
            stop,
            reader: Some(reader),
        }
    }

    fn master(&self) -> &OwnedFd {
        self.master.as_ref().expect("the terminal is open")
    }

    /// Hangs the terminal up: the reader stops and the master's last
    /// descriptor closes.
    fn hang_up(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.master = None;
    }

    fn bytes(&self) -> Vec<u8> {
        self.output.lock().unwrap().clone()
    }

    /// What the terminal shows, carriage returns removed.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).replace('\r', "")
    }

    fn type_bytes(&self, bytes: &[u8]) {
        write_master(self.master(), bytes);
    }

    fn resize(&self, rows: u16, cols: u16) {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads the live winsize.
        let rc =
            unsafe { libc::ioctl(self.master().as_raw_fd(), libc::TIOCSWINSZ, &raw const size) };
        assert_eq!(rc, 0, "TIOCSWINSZ: {}", std::io::Error::last_os_error());
    }

    fn wait_for(&self, needle: &str, bound: Duration) -> bool {
        common::within(bound, || self.text().contains(needle))
    }
}

fn write_master(master: &OwnedFd, bytes: &[u8]) {
    let mut file = std::fs::File::from(master.try_clone().expect("a master duplicate"));
    let _ = file.write_all(bytes);
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// One shell session on a fresh terminal.
struct Session {
    root: tempfile::TempDir,
    terminal: Terminal,
    shell: std::process::Child,
    control: std::fs::File,
    status: OwnedFd,
    pending: Vec<u8>,
    /// The job's pid: the supervisor's, for a jail run.
    job: libc::pid_t,
    /// The foreground group the job left on the terminal at its last stop
    /// or its end, as the shell found it before taking the terminal back.
    left_foreground: Option<i64>,
    /// The shell's own process group.
    started_shell: libc::pid_t,
}

impl Session {
    fn start(options: Options) -> Session {
        let root = common::private_tempdir();
        for (name, mode) in [("data", 0o700), ("config", 0o700), ("work", 0o755)] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
                .unwrap();
        }
        if let Some(config) = &options.config {
            let path = root.path().join("config/config.toml");
            std::fs::write(&path, config).unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
        }
        Session::start_in(root, options)
    }

    fn start_in(root: tempfile::TempDir, options: Options) -> Session {
        let (master, slave) = openpty();
        let (control_r, control_w) = pipe();
        let (status_r, status_w) = pipe();
        let work = root.path().join("work");
        let inside = work.join("ukai-fixture");
        if !inside.exists() {
            std::fs::copy(harness::fixture_path(), &inside).expect("the fixture is copied in");
        }
        let mut argv: Vec<OsString> = vec![
            options
                .program
                .clone()
                .unwrap_or_else(harness::jail_path)
                .into_os_string(),
        ];
        let mut jail = options.jail.clone();
        // `--workspace` after the verb, unless the words already name one.
        if options.program.is_none()
            && matches!(jail.first().and_then(|v| v.to_str()), Some("run" | "learn"))
            && !jail.iter().any(|word| word == "--workspace")
        {
            jail.insert(1, work.clone().into_os_string());
            jail.insert(1, "--workspace".into());
        }
        argv.extend(jail.into_iter().map(|word| {
            if word == FIXTURE {
                inside.clone().into_os_string()
            } else {
                word
            }
        }));
        let mut command = std::process::Command::new(harness::fixture_path());
        command
            .args([
                "--no-report",
                "job-shell",
                "--control-fd",
                "3",
                "--status-fd",
                "4",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", root.path())
            .env("UKAI_DATA_DIR", root.path().join("data"))
            .env("UKAI_CONFIG_DIR", root.path().join("config"))
            .env("TERM", "xterm-256color")
            .current_dir(&work);
        for (name, value) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| {
                name.starts_with("UKAI_JAIL_TEST_") || name == "XDG_RUNTIME_DIR"
            }) {
                command.env(name, value);
            }
        }
        for (name, value) in &options.env {
            command.env(name, value);
        }
        if options.member {
            command.arg("--member").arg(root.path().join("member.json"));
        }
        if options.background {
            command.arg("--background");
        }
        if let Some(path) = &options.stdin_path {
            command.arg("--stdin-path").arg(path);
        }
        for signal in &options.block {
            command.arg("--block").arg(signal.to_string());
        }
        if options.gate_pipe {
            command.arg("--gate-pipe");
        }
        command.arg("--").args(&argv);
        let slave_fd = slave.as_raw_fd();
        let (control_fd, status_fd) = (control_r.as_raw_fd(), status_w.as_raw_fd());
        // SAFETY: between fork and exec: setsid, ioctl, dup2 and signal are
        // async-signal-safe, over descriptors opened before the fork.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for target in 0..3 {
                    if libc::dup2(slave_fd, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if libc::dup2(control_fd, 3) < 0 || libc::dup2(status_fd, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP] {
                    libc::signal(signal, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        let shell = command.spawn().expect("the job shell starts");
        drop(command);
        drop(slave);
        drop(control_r);
        drop(status_w);
        let mut session = Session {
            root,
            terminal: Terminal::start(master),
            shell,
            control: std::fs::File::from(control_w),
            status: status_r,
            pending: Vec::new(),
            job: 0,
            left_foreground: None,
            started_shell: 0,
        };
        let started = session.status_event(SESSION);
        assert_eq!(started["event"], "started", "{started}");
        session.job = libc::pid_t::try_from(started["job"].as_i64().unwrap()).unwrap();
        session.started_shell =
            libc::pid_t::try_from(started["shell_pgrp"].as_i64().unwrap()).unwrap();
        session
    }

    fn data(&self) -> PathBuf {
        self.root.path().join("data")
    }

    /// The next status line, within `bound`.
    fn status_event(&mut self, bound: Duration) -> Value {
        let deadline = Instant::now() + bound;
        loop {
            if let Some(at) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=at).collect();
                return serde_json::from_slice(&line[..line.len() - 1]).expect("a status line");
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "no status from the shell; the terminal shows:\n{}",
                self.terminal.text()
            );
            let mut pollfd = libc::pollfd {
                fd: self.status.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = libc::c_int::try_from(left.as_millis().min(500)).unwrap();
            // SAFETY: one live pollfd.
            unsafe { libc::poll(&raw mut pollfd, 1, ms) };
            if pollfd.revents == 0 {
                continue;
            }
            let mut buffer = [0u8; 4096];
            // SAFETY: a read into a live buffer.
            let n = unsafe {
                libc::read(
                    self.status.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            assert!(
                n > 0,
                "the shell's status pipe ended; the terminal shows:\n{}",
                self.terminal.text()
            );
            self.pending
                .extend_from_slice(&buffer[..usize::try_from(n).unwrap()]);
        }
    }

    fn send(&mut self, command: &str) {
        self.control
            .write_all(format!("{command}\n").as_bytes())
            .expect("the shell takes a command");
    }

    /// Waits for the job's end: `(code, signal)`.
    fn wait_exit(&mut self) -> (Option<i64>, Option<i64>) {
        let event = self.status_event(SESSION);
        assert_eq!(
            event["event"],
            "exited",
            "{event}\n{}",
            self.terminal.text()
        );
        self.left_foreground = event["foreground"].as_i64();
        (event["code"].as_i64(), event["signal"].as_i64())
    }

    /// Whatever is left on the terminal for the shell to read, with the
    /// foreground group and the terminal's flags.
    fn drain(&mut self) -> Value {
        self.send("drain");
        let event = self.status_event(SESSION);
        assert_eq!(event["event"], "drained", "{event}");
        event
    }

    /// Ends the shell: the signals it got.
    fn quit(&mut self) -> Vec<Value> {
        self.send("quit");
        let event = self.status_event(SESSION);
        assert_eq!(event["event"], "quit", "{event}");
        let _ = self.shell.wait();
        event["signals"].as_array().cloned().unwrap_or_default()
    }

    fn attempt(&self) -> PathBuf {
        let mut found: Vec<PathBuf> = std::fs::read_dir(self.data().join("attempts"))
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default();
        found.sort();
        assert_eq!(found.len(), 1, "one attempt: {found:?}");
        found.pop().unwrap()
    }

    /// The attempt's receipt, held to the schemas.
    fn receipt(&self) -> Value {
        common::checked_receipt(common::read_receipt(&self.attempt().join("jail.json")))
    }

    /// The attempt's `policy.json` snapshot.
    fn snapshot(&self) -> Value {
        let policy: Value =
            serde_json::from_slice(&std::fs::read(self.attempt().join("policy.json")).unwrap())
                .unwrap();
        policy["snapshot"].clone()
    }

    /// The wrapper's lifecycle transitions, in order.
    fn transitions(&self) -> Vec<String> {
        std::fs::read_to_string(self.attempt().join("trace.ndjson"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|event| event["fields"]["transition"].as_str().map(str::to_owned))
            .collect()
    }

    /// The fixture's report lines on the terminal.
    fn reports(&self, op: &str) -> Vec<Value> {
        self.terminal
            .text()
            .lines()
            .filter_map(|line| {
                let at = line.find("{\"op\":")?;
                serde_json::from_str::<Value>(&line[at..]).ok()
            })
            .filter(|report| report["op"] == op)
            .collect()
    }

    /// What to show when an assertion fails: the transitions, the latest
    /// receipt's outcome and errors, the job's and the target's states, and
    /// the terminal.
    fn diagnose(&self) -> String {
        let attempt = std::fs::read_dir(self.data().join("attempts"))
            .ok()
            .and_then(|mut entries| entries.next())
            .and_then(Result::ok)
            .map(|entry| entry.path());
        let (transitions, receipt) = match &attempt {
            Some(attempt) => (
                std::fs::read_to_string(attempt.join("trace.ndjson"))
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .filter_map(|event| event["fields"]["transition"].as_str().map(str::to_owned))
                    .collect::<Vec<_>>(),
                std::fs::read(attempt.join("jail.json"))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .unwrap_or(Value::Null),
            ),
            None => (Vec::new(), Value::Null),
        };
        let target = receipt["lifetime"]["native"]["details"]["launcher_pid"]
            .as_i64()
            .and_then(|pid| libc::pid_t::try_from(pid).ok());
        format!(
            "transitions {transitions:?}\nphase {} outcome {} errors {} terminal {}\njob {} state \
             {:?}; target {target:?} state {:?}\nterminal:\n{}",
            receipt["phase"],
            receipt["outcome"],
            receipt["errors"],
            receipt["applied"]["terminal"],
            self.job,
            state_of(self.job),
            target.and_then(state_of),
            self.terminal.text()
        )
    }

    /// The shell's report after a `^Z`, with a diagnosis when there is none
    /// within the bound.
    fn stop_event(&mut self) -> Value {
        if !self.pending.contains(&b'\n') {
            let mut pollfd = libc::pollfd {
                fd: self.status.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = libc::c_int::try_from(common::STEP_BOUND.as_millis()).unwrap();
            // SAFETY: one live pollfd.
            let ready = unsafe { libc::poll(&raw mut pollfd, 1, ms) } > 0;
            assert!(ready, "no stop was relayed: {}", self.diagnose());
        }
        let event = self.status_event(common::STEP_BOUND);
        assert_eq!(event["event"], "stopped", "{event}: {}", self.diagnose());
        self.left_foreground = event["foreground"].as_i64();
        event
    }

    fn report(&self, op: &str) -> Value {
        self.reports(op).pop().unwrap_or_else(|| {
            panic!(
                "no `{op}` report; the terminal shows:\n{}",
                self.terminal.text()
            )
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.job > 0 {
            // SAFETY: SIGKILL to the job's group this session started.
            unsafe { libc::kill(-self.job, libc::SIGKILL) };
        }
        let _ = self.shell.kill();
        let _ = self.shell.wait();
        self.terminal.hang_up();
    }
}

/// A process's state letter (`/proc/<pid>/stat` field 3).
fn state_of(pid: libc::pid_t) -> Option<char> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = raw.rfind(')')?;
    raw[close + 1..]
        .split_ascii_whitespace()
        .next()?
        .chars()
        .next()
}

fn launcher_pid(receipt: &Value) -> libc::pid_t {
    libc::pid_t::try_from(
        receipt["lifetime"]["native"]["details"]["launcher_pid"]
            .as_i64()
            .unwrap_or_else(|| panic!("no launcher pid: {receipt:#}")),
    )
    .unwrap()
}

fn assert_settled(receipt: &Value) {
    assert_eq!(receipt["phase"], "settled", "{receipt:#}");
    assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt:#}");
}

fn restored(receipt: &Value) -> Value {
    receipt["applied"]["terminal"]["restored"].clone()
}

fn all_restored(receipt: &Value) {
    for field in [
        "foreground",
        "termios",
        "input_flushed",
        "reset_written",
        "after_tree_death",
    ] {
        assert_eq!(restored(receipt)[field], true, "{field}: {receipt:#}");
    }
}

// ===========================================================================
// K55: when terminal mode applies
// ===========================================================================

#[test]
fn k55_terminal_mode_attaches_exactly_when_its_conditions_hold() {
    if !common::live() {
        return;
    }
    // Attached: every condition holds.
    let mut attached = Session::start(Options::run("tool", &[], &["tty-probe"]));
    assert_eq!(
        attached.wait_exit().0,
        Some(0),
        "{}",
        attached.terminal.text()
    );
    let probe = attached.report("tty-probe");
    assert_eq!(probe["args"]["dev_tty"], Value::Null, "{probe}");
    assert_eq!(probe["args"]["foreground"], true, "{probe}");
    assert_eq!(
        probe["args"]["sid"], probe["args"]["terminal_sid"],
        "{probe}"
    );
    let receipt = attached.receipt();
    assert_settled(&receipt);
    assert_eq!(
        receipt["applied"]["terminal"]["device"], "pty",
        "{receipt:#}"
    );
    assert_eq!(receipt["applied"]["terminal"]["session"], "caller");
    assert_eq!(receipt["applied"]["terminal"]["process_group"], "own");
    all_restored(&receipt);
    assert_eq!(attached.snapshot()["terminal"], "attached");
    let text = attached.terminal.text();
    assert!(
        text.contains("ukai-jail: terminal: attached (/dev/pts/"),
        "{text}"
    );

    // Detached by the operator: `--terminal detach` and `[jail] terminal`.
    let detach = Options::run("tool", &["--terminal", "detach"], &["tty-probe"]);
    let mut configured = Options::run("tool", &[], &["tty-probe"]);
    configured.config = Some("[jail]\nterminal = \"detach\"\n".to_owned());
    for (leg, options) in [("--terminal detach", detach), ("config.toml", configured)] {
        let mut session = Session::start(options);
        assert_eq!(session.wait_exit().0, Some(0), "{leg}");
        let probe = session.report("tty-probe");
        // A new session: no controlling terminal inside.
        assert_eq!(probe["args"]["dev_tty"], "ENXIO", "{leg}: {probe}");
        assert_ne!(probe["args"]["sid"], probe["args"]["terminal_sid"], "{leg}");
        let receipt = session.receipt();
        assert!(
            receipt["applied"].get("terminal").is_none(),
            "{leg}: {receipt:#}"
        );
        assert!(session.snapshot().get("terminal").is_none(), "{leg}");
        assert!(
            !session.terminal.text().contains("ukai-jail: terminal:"),
            "{leg}: the operator's own choice prints nothing:\n{}",
            session.terminal.text()
        );
    }

    // Detached for a reason the pre-exec line names.
    let other = openpty();
    let other_path = std::fs::read_link(format!("/proc/self/fd/{}", other.1.as_raw_fd())).unwrap();
    let mut console = Options::run("tool", &[], &["tty-probe"]);
    console = console.env("UKAI_JAIL_TEST_TERMINAL_MAJOR", "4");
    let serial =
        Options::run("tool", &[], &["tty-probe"]).env("UKAI_JAIL_TEST_TERMINAL_MAJOR", "204");
    let mut background = Options::run("tool", &[], &["tty-probe"]);
    background.background = true;
    let mut foreign = Options::run("tool", &[], &["tty-probe"]);
    foreign.stdin_path = Some(other_path);
    let mut null = Options::run("tool", &[], &["tty-probe"]);
    null.stdin_path = Some(PathBuf::from("/dev/null"));
    for (leg, options, reason) in [
        ("console", console, "not a pseudo-terminal"),
        ("serial", serial, "not a pseudo-terminal"),
        ("background", background, "not the foreground job"),
        (
            "another terminal",
            foreign,
            "stdin is not this session's controlling terminal",
        ),
        ("/dev/null", null, "stdin is not a terminal"),
    ] {
        let mut session = Session::start(options);
        assert_eq!(session.wait_exit().0, Some(0), "{leg}");
        let line = format!("ukai-jail: terminal: detached ({reason})");
        assert!(
            session.terminal.text().contains(&line),
            "{leg}:\n{}",
            session.terminal.text()
        );
        let receipt = session.receipt();
        assert!(
            receipt["applied"].get("terminal").is_none(),
            "{leg}: {receipt:#}"
        );
        assert!(session.snapshot().get("terminal").is_none(), "{leg}");
    }
    drop(other);

    // `--gate-fd` stays detached and prints nothing: a gate at its end
    // refuses after the prepared receipt.
    let mut gate = Options::run("tool", &["--gate-fd", "3"], &["tty-probe"]);
    gate.gate_pipe = true;
    let mut session = Session::start(gate);
    assert_eq!(session.wait_exit().0, Some(125));
    let receipt = session.receipt();
    assert_eq!(receipt["phase"], "refused", "{receipt:#}");
    assert!(receipt["applied"].get("terminal").is_none(), "{receipt:#}");
    assert!(session.snapshot().get("terminal").is_none());
    assert!(!session.terminal.text().contains("ukai-jail: terminal:"));

    // `learn` stays detached and prints nothing.
    let learn = Options {
        jail: ["learn", "--profile", "tool", "--", FIXTURE, "tty-probe"]
            .iter()
            .map(OsString::from)
            .collect(),
        ..Options::default()
    };
    let mut session = Session::start(learn);
    session.wait_exit();
    assert!(!session.terminal.text().contains("ukai-jail: terminal:"));
    let probe = session.report("tty-probe");
    assert_eq!(probe["args"]["dev_tty"], "ENXIO", "{probe}");
}

/// K55: `none` runs uncontained, in a new session of its own, and prints
/// nothing about a terminal.
#[test]
fn k55_none_never_attaches() {
    if !common::profile_live(ukai_jail::policy::ProfileName::None) {
        return;
    }
    let mut session = Session::start(Options::run("none", &[], &["tty-probe"]));
    assert_eq!(session.wait_exit().0, Some(0));
    assert!(!session.terminal.text().contains("ukai-jail: terminal:"));
    let receipt = session.receipt();
    assert!(receipt["applied"].get("terminal").is_none(), "{receipt:#}");
    assert!(session.snapshot().get("terminal").is_none());
}

// ===========================================================================
// K56: what an attached command has
// ===========================================================================

#[test]
fn k56_an_attached_command_has_its_terminal_resizes_and_the_operators_mask() {
    if !common::live() {
        return;
    }
    for profile in ["tool", "agent"] {
        for observe in ["on", "off"] {
            let leg = format!("{profile} observe {observe}");
            let mut options = Options::run(
                profile,
                &["--observe", observe],
                &["tty-probe", "--wait-winch-ms", "20000"],
            );
            // The operator's shell started the jail with SIGUSR2 blocked.
            options.block = vec![libc::SIGUSR2];
            let mut session = Session::start(options);
            assert!(
                session
                    .terminal
                    .wait_for("\"op\":\"tty-ready\"", common::SETTLE_BOUND),
                "{leg}:\n{}",
                session.terminal.text()
            );
            let probe = session.report("tty-probe");
            assert_eq!(probe["args"]["dev_tty"], Value::Null, "{leg}: {probe}");
            assert_eq!(probe["args"]["rows"], ROWS, "{leg}: {probe}");
            assert_eq!(probe["args"]["cols"], COLS, "{leg}: {probe}");
            // The launcher's `tcsetpgrp`, made with SIGTTOU blocked, gave
            // the command's own group the terminal.
            assert_eq!(probe["args"]["foreground"], true, "{leg}: {probe}");
            let blocked =
                u64::from_str_radix(probe["args"]["sig_blocked"].as_str().unwrap(), 16).unwrap();
            assert_eq!(
                blocked,
                1u64 << (libc::SIGUSR2 - 1),
                "{leg}: the target's mask is not the operator's: {probe}"
            );
            // With observation off the supervisor confirms the exec by
            // seeing the new image (§8.1 step 7), so the probe has to outlive
            // that look; it is the same with the terminal detached.
            assert!(
                common::within(common::SETTLE_BOUND, || session
                    .transitions()
                    .iter()
                    .any(|transition| transition == "exec_confirmed")),
                "{leg}: {}",
                session.diagnose()
            );
            session.terminal.resize(40, 120);
            let code = session.wait_exit().0;
            assert_eq!(code, Some(0), "{leg}: {}", session.diagnose());
            let winch = session.report("tty-winch");
            assert_eq!(winch["args"]["received"], true, "{leg}: {winch}");
            assert_eq!(winch["args"]["rows"], 40, "{leg}");
            assert_eq!(winch["args"]["cols"], 120, "{leg}");
            assert_settled(&session.receipt());
        }
    }
}

// ===========================================================================
// K57: nothing outside the namespace is reached
// ===========================================================================

#[test]
fn k57_no_signal_or_group_change_reaches_outside_the_namespace() {
    if !common::live() {
        return;
    }
    for terminal in ["auto", "detach"] {
        let mut options = Options::run("tool", &["--terminal", terminal], &["tty-kill-probe"]);
        options.member = true;
        let mut session = Session::start(options);
        assert_eq!(
            session.wait_exit().0,
            Some(0),
            "{terminal}:\n{}",
            session.terminal.text()
        );
        let receipt = session.receipt();
        assert_settled(&receipt);
        // The supervisor was not asked to stop: the target's own end.
        assert_eq!(
            receipt["outcome"]["kind"], "exited",
            "{terminal}: {receipt:#}"
        );
        assert_eq!(
            receipt["outcome"]["cause"],
            Value::Null,
            "{terminal}: {receipt:#}"
        );
        let member: Value = serde_json::from_slice(
            &std::fs::read(session.root.path().join("member.json")).expect("the member's log"),
        )
        .unwrap();
        assert_eq!(
            member["signals"],
            serde_json::json!([]),
            "{terminal}: the pipeline member was reached"
        );
        let signals = session.quit();
        assert!(
            signals.is_empty(),
            "{terminal}: the shell was reached: {signals:?}"
        );
    }
}

// ===========================================================================
// K58: terminal signals, stop requests and a hangup
// ===========================================================================

const TRAPS: &str = "trap 'echo got-int' INT; trap 'echo got-quit' QUIT; echo ready; i=0; \
                     while [ $i -lt 40 ]; do sleep 0.1; i=$((i+1)); done; echo done";

#[test]
fn k58_terminal_signals_reach_the_command_and_stop_requests_end_the_attempt() {
    if !common::live() {
        return;
    }
    // ^C and ^\ go to the command's group; it survives them and the
    // attempt goes on to its own end.
    let options = Options {
        jail: ["run", "--profile", "tool", "--", "/bin/sh", "-c", TRAPS]
            .iter()
            .map(OsString::from)
            .collect(),
        ..Options::default()
    };
    let mut session = Session::start(options);
    assert!(session.terminal.wait_for("ready", common::SETTLE_BOUND));
    session.terminal.type_bytes(b"\x03");
    assert!(
        session.terminal.wait_for("got-int", common::STEP_BOUND),
        "{}",
        session.terminal.text()
    );
    session.terminal.type_bytes(b"\x1c");
    assert!(
        session.terminal.wait_for("got-quit", common::STEP_BOUND),
        "{}",
        session.terminal.text()
    );
    assert_eq!(
        session.wait_exit().0,
        Some(0),
        "{}",
        session.terminal.text()
    );
    assert!(session.terminal.text().contains("done"));
    let receipt = session.receipt();
    assert_settled(&receipt);
    assert_eq!(receipt["outcome"]["cause"], Value::Null, "{receipt:#}");

    // INT, TERM and HUP sent to the supervisor each end the attempt at
    // verified tree death.
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let mut session = Session::start(Options::run("tool", &[], &["sleep", "30000"]));
        assert!(
            session
                .terminal
                .wait_for("\"op\":\"sleep\"", common::SETTLE_BOUND)
        );
        // SAFETY: a signal to the supervisor this session started.
        unsafe { libc::kill(session.job, signal) };
        session.wait_exit();
        let receipt = session.receipt();
        assert_settled(&receipt);
        assert_eq!(
            receipt["outcome"]["cause"], "operator_signal",
            "{signal}: {receipt:#}"
        );
        all_restored(&receipt);
    }

    // A hangup: the terminal's master closes.
    let mut session = Session::start(Options::run("tool", &[], &["sleep", "30000"]));
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"sleep\"", common::SETTLE_BOUND)
    );
    let attempt = session.attempt();
    session.terminal.hang_up();
    let settled = common::within(common::SETTLE_BOUND, || {
        std::fs::read(attempt.join("jail.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .is_some_and(|receipt| receipt["phase"] == "settled")
    });
    assert!(settled, "a hung-up terminal did not end the attempt");
    let receipt = common::read_receipt(&attempt.join("jail.json"));
    assert_eq!(receipt["lifetime"]["tree_empty"], true, "{receipt:#}");
    assert_eq!(
        receipt["outcome"]["cause"], "operator_signal",
        "{receipt:#}"
    );
}

// ===========================================================================
// K59: job control
// ===========================================================================

#[test]
fn k59_a_stop_is_relayed_to_the_shell_and_fg_and_bg_resume_it() {
    if !common::live() {
        return;
    }
    for observe in ["on", "off"] {
        // ^Z, then fg. The command reads keys one at a time (canonical mode
        // and echo off).
        let mut session = Session::start(Options::run(
            "tool",
            &["--observe", observe],
            &["tty-probe", "--wait-winch-ms", "30000", "--cbreak"],
        ));
        assert!(
            session
                .terminal
                .wait_for("\"op\":\"tty-ready\"", common::SETTLE_BOUND)
        );
        session.terminal.type_bytes(b"\x1a");
        let stopped = session.stop_event();
        assert_eq!(stopped["signal"], libc::SIGTSTP, "{observe}: {stopped}");
        // §3.4 step 3: the supervisor's group took the terminal, with the
        // settings saved before release, before the supervisor stopped.
        assert_eq!(stopped["foreground"], session.job, "{observe}: {stopped}");
        let cooked = u64::from(libc::ECHO | libc::ICANON);
        assert_eq!(
            stopped["lflag"].as_u64().unwrap() & cooked,
            cooked,
            "{observe}: the settings were not restored at the stop: {stopped}"
        );
        assert_eq!(
            state_of(session.job),
            Some('T'),
            "{observe}: the supervisor did not stop"
        );
        let receipt = common::read_receipt(&session.attempt().join("jail.json"));
        let target = launcher_pid(&receipt);
        assert!(
            matches!(state_of(target), Some('T' | 't')),
            "{observe}: the target runs"
        );
        session.send("fg");
        // Back in the foreground: a resize reaches the command.
        std::thread::sleep(Duration::from_millis(300));
        session.terminal.resize(44, 132);
        assert_eq!(
            session.wait_exit().0,
            Some(0),
            "{observe}:\n{}",
            session.terminal.text()
        );
        assert_eq!(session.report("tty-winch")["args"]["received"], true);
        let receipt = session.receipt();
        assert_settled(&receipt);
        assert_eq!(
            receipt["applied"]["terminal"]["stops"], 1,
            "{observe}: {receipt:#}"
        );
        let transitions = session.transitions();
        let stop = transitions.iter().position(|t| t == "terminal_stopped");
        let cont = transitions.iter().position(|t| t == "terminal_continued");
        assert!(
            stop.is_some() && cont.is_some() && stop < cont,
            "{observe}: {transitions:?}"
        );

        // ^Z, then bg: running without the terminal; fg gives it back.
        let mut session = Session::start(Options::run(
            "tool",
            &["--observe", observe],
            &["tty-probe", "--wait-winch-ms", "30000"],
        ));
        assert!(
            session
                .terminal
                .wait_for("\"op\":\"tty-ready\"", common::SETTLE_BOUND)
        );
        session.terminal.type_bytes(b"\x1a");
        session.stop_event();
        session.send("bg");
        let running = common::within(common::STEP_BOUND, || {
            !matches!(state_of(session.job), Some('T'))
        });
        assert!(running, "{observe}: bg did not continue the supervisor");
        // The shell holds the terminal: a resize does not reach the command.
        session.terminal.resize(30, 90);
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            session.reports("tty-winch").is_empty(),
            "{observe}: a background job got SIGWINCH"
        );
        session.send("fg");
        std::thread::sleep(Duration::from_millis(300));
        session.terminal.resize(31, 91);
        assert_eq!(
            session.wait_exit().0,
            Some(0),
            "{observe}:\n{}",
            session.terminal.text()
        );
        assert_eq!(session.report("tty-winch")["args"]["rows"], 31);
        assert_settled(&session.receipt());
    }
}

/// K59, review F5: a jail that leads its own session (no job-control shell
/// above it, as under `script` or `ssh host ukai-jail …`) is in an orphaned
/// group, where the kernel never discards a `SIGSTOP`. A command that stops
/// itself with one is continued at once, and the jail is never left stopped
/// with nobody to continue it. Observation on (the tracer's group-stop) and
/// off (`/proc`).
#[test]
fn k59_a_jail_leading_its_own_session_is_never_left_stopped() {
    if !common::live() {
        return;
    }
    for observe in ["on", "off"] {
        let root = common::private_tempdir();
        for (name, mode) in [("data", 0o700), ("config", 0o700), ("work", 0o755)] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
                .unwrap();
        }
        let work = root.path().join("work");
        let (master, slave) = openpty();
        let terminal = Terminal::start(master);
        let slave_fd = slave.as_raw_fd();
        let mut command = std::process::Command::new(harness::jail_path());
        command
            .args([
                "run",
                "--profile",
                "tool",
                "--observe",
                observe,
                "--workspace",
            ])
            .arg(&work)
            .arg("--")
            // The command outlives the supervisor's look at its new image
            // (observation off confirms the exec that way), then stops
            // itself.
            .args(["/bin/sh", "-c", "sleep 0.3; kill -STOP $$; echo continued"])
            .env("UKAI_DATA_DIR", root.path().join("data"))
            .env("UKAI_CONFIG_DIR", root.path().join("config"));
        // SAFETY: between fork and exec: setsid, ioctl, dup2 and signal are
        // async-signal-safe, over a descriptor opened before the fork.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 || libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for target in 0..3 {
                    if libc::dup2(slave_fd, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP] {
                    libc::signal(signal, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        let mut jail = command.spawn().unwrap();
        drop(slave);
        let ended = common::within(common::SETTLE_BOUND, || {
            matches!(jail.try_wait(), Ok(Some(_)))
        });
        if !ended {
            let _ = jail.kill();
            let _ = jail.wait();
            panic!(
                "observe {observe}: the jail stayed stopped:\n{}",
                terminal.text()
            );
        }
        let status = jail.wait().unwrap();
        assert_eq!(
            status.code(),
            Some(0),
            "observe {observe}:\n{}",
            terminal.text()
        );
        assert!(
            terminal.text().contains("terminal: attached"),
            "{}",
            terminal.text()
        );
        assert!(
            terminal.wait_for("continued", common::STEP_BOUND),
            "{}",
            terminal.text()
        );
    }
}

/// K59: a jail started through a wrapper in the job's own group (`sh -c`)
/// still relays the stop: the group is not orphaned while the shell that
/// started the wrapper watches it.
#[test]
fn k59_a_jail_behind_a_wrapper_in_the_jobs_group_relays_the_stop() {
    if !common::live() {
        return;
    }
    let root = common::private_tempdir();
    for (name, mode) in [("data", 0o700), ("config", 0o700), ("work", 0o755)] {
        let path = root.path().join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .unwrap();
    }
    let work = root.path().join("work");
    let inside = work.join("ukai-fixture");
    std::fs::copy(harness::fixture_path(), &inside).unwrap();
    // `; :` keeps the shell from replacing itself with the jail.
    let script = format!(
        "{} run --profile tool --workspace {} -- {} tty-probe --wait-winch-ms 30000; :",
        harness::jail_path().display(),
        work.display(),
        inside.display()
    );
    let mut session = Session::start_in(
        root,
        Options {
            program: Some(PathBuf::from("/bin/sh")),
            jail: vec!["-c".into(), script.into()],
            ..Options::default()
        },
    );
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"tty-ready\"", common::SETTLE_BOUND),
        "{}",
        session.terminal.text()
    );
    session.terminal.type_bytes(b"\x1a");
    let stopped = session.stop_event();
    assert_eq!(stopped["signal"], libc::SIGTSTP, "{stopped}");
    session.send("fg");
    std::thread::sleep(Duration::from_millis(300));
    session.terminal.resize(44, 132);
    assert_eq!(
        session.wait_exit().0,
        Some(0),
        "{}",
        session.terminal.text()
    );
    assert_eq!(session.report("tty-winch")["args"]["received"], true);
}

/// K59, review F6: a job continued in the background (`bg`) that ends
/// there leaves the terminal to the shell: neither the relay nor the
/// settlement takes it, and the receipt says the steps were not taken.
#[test]
fn k59_a_job_that_ends_in_the_background_leaves_the_shell_its_terminal() {
    if !common::live() {
        return;
    }
    let mut session = Session::start(Options::run("tool", &[], &["sleep", "3000"]));
    let shell = session.started_shell;
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"sleep\"", common::SETTLE_BOUND)
    );
    session.terminal.type_bytes(b"\x1a");
    session.stop_event();
    session.send("bg");
    session.send("wait");
    assert_eq!(session.wait_exit().0, Some(0), "{}", session.diagnose());
    assert_eq!(
        session.left_foreground,
        Some(i64::from(shell)),
        "the job took the shell's terminal: {}",
        session.diagnose()
    );
    let receipt = session.receipt();
    assert_settled(&receipt);
    assert_eq!(
        restored(&receipt),
        serde_json::json!({"foreground": false, "termios": false, "input_flushed": false,
                           "reset_written": true, "after_tree_death": true}),
        "{receipt:#}"
    );
    assert!(
        session
            .terminal
            .text()
            .contains("terminal not restored (foreground: another job holds the terminal"),
        "{}",
        session.terminal.text()
    );
}

/// K59: the wall keeps running while the job is stopped and is acted on
/// once it continues.
#[test]
fn k59_a_wall_that_passes_during_a_stop_is_acted_on_at_continue() {
    if !common::live() {
        return;
    }
    let mut session = Session::start(Options::run(
        "tool",
        &["--limit", "wall=2s"],
        &["sleep", "30000"],
    ));
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"sleep\"", common::SETTLE_BOUND)
    );
    session.terminal.type_bytes(b"\x1a");
    session.stop_event();
    std::thread::sleep(Duration::from_secs(3));
    let continued = Instant::now();
    session.send("fg");
    session.wait_exit();
    assert!(
        continued.elapsed() < Duration::from_secs(10),
        "the passed wall was not acted on at continue"
    );
    let receipt = session.receipt();
    assert_settled(&receipt);
    assert_eq!(receipt["outcome"]["cause"], "wall_expiry", "{receipt:#}");
}

/// K59: a descendant that left the command's group is not stopped, but its
/// observed calls wait while the supervisor is stopped.
#[test]
fn k59_a_stray_descendants_observed_calls_wait_out_the_stop() {
    if !common::live() {
        return;
    }
    let mut options = Options::run("tool", &["--observe", "on"], &[]);
    let root = common::private_tempdir();
    for (name, mode) in [("data", 0o700), ("config", 0o700), ("work", 0o755)] {
        let path = root.path().join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .unwrap();
    }
    let dir = root.path().join("work");
    options.jail.push("tty-stray".into());
    options.jail.push(dir.clone().into_os_string());
    options.jail.push("6000".into());
    let mut session = Session::start_in(root, options);
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"stray\"", common::SETTLE_BOUND)
    );
    std::thread::sleep(Duration::from_millis(800));
    session.terminal.type_bytes(b"\x1a");
    session.stop_event();
    let stopped = monotonic_ns();
    std::thread::sleep(Duration::from_secs(2));
    let resumed = monotonic_ns();
    session.send("fg");
    session.wait_exit();
    let log = std::fs::read_to_string(dir.join("stray.log")).unwrap_or_default();
    let times: Vec<i128> = log.lines().filter_map(|line| line.parse().ok()).collect();
    let during: Vec<&i128> = times
        .iter()
        .filter(|at| **at > stopped + 500_000_000 && **at < resumed)
        .collect();
    assert!(
        during.is_empty(),
        "observed calls completed while the supervisor was stopped: {during:?}"
    );
    assert!(
        times.iter().any(|at| *at > resumed),
        "the descendant never resumed: {times:?}"
    );
}

fn monotonic_ns() -> i128 {
    // SAFETY: `now` is plain stack data clock_gettime fills.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
    i128::from(now.tv_sec) * 1_000_000_000 + i128::from(now.tv_nsec)
}

// ===========================================================================
// K60: the filter
// ===========================================================================

#[test]
fn k60_the_terminal_requests_are_denied_in_every_contained_baseline() {
    if !common::live() {
        return;
    }
    let steps: Vec<Vec<&str>> = vec![
        vec!["tty-ioctl", "tiocsti", "--on", "stdin"],
        vec!["tty-ioctl", "tioclinux", "--on", "stdin"],
        vec!["tty-ioctl", "tiocsetd", "--on", "stdin"],
        vec!["tty-ioctl", "tiocsti", "--on", "devnull"],
        vec!["tty-ioctl", "tioclinux", "--on", "devnull"],
        vec!["tty-ioctl", "tiocsetd", "--on", "devnull"],
        vec!["tty-ioctl", "tcgets", "--on", "stdin"],
        vec!["tty-ioctl", "tiocgwinsz", "--on", "stdin"],
        vec!["tty-ioctl", "tiocgpgrp", "--on", "stdin"],
        vec!["tty-ioctl", "kdgkbmode", "--on", "stdin"],
        vec!["tty-ioctl", "tcgets", "--on", "devnull"],
    ];
    // The storage variants' programs share the rule by construction; the
    // filter's unit tests run it in every baseline.
    for (profile, extra) in [("tool", &[][..]), ("agent", &[][..])] {
        let leg = format!("{profile} {extra:?}");
        let root = common::private_tempdir();
        for (name, mode) in [("data", 0o700), ("config", 0o700), ("work", 0o755)] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
                .unwrap();
        }
        let script = root.path().join("work/steps.json");
        std::fs::write(&script, serde_json::to_vec(&steps).unwrap()).unwrap();
        let mut words: Vec<&str> = extra.to_vec();
        words.push("--terminal");
        words.push("auto");
        let mut options = Options::run(profile, &words, &["script"]);
        options.jail.push(script.into_os_string());
        let mut session = Session::start_in(root, options);
        session.wait_exit();
        assert!(
            session.receipt()["applied"].get("terminal").is_some(),
            "{leg}"
        );
        let reports = session.reports("tty-ioctl");
        assert_eq!(
            reports.len(),
            steps.len(),
            "{leg}:\n{}",
            session.terminal.text()
        );
        for report in &reports {
            let request = report["args"]["request"].as_str().unwrap();
            let on = report["args"]["on"].as_str().unwrap();
            let denied = matches!(request, "tiocsti" | "tioclinux" | "tiocsetd");
            if denied {
                assert_eq!(report["errno"], "EPERM", "{leg}: {report}");
            } else {
                assert_ne!(
                    report["errno"], "EPERM",
                    "{leg}: the kernel's answer: {report}"
                );
                if on == "stdin" && request != "kdgkbmode" {
                    assert_eq!(report["ret"], 0, "{leg}: {report}");
                }
            }
        }
    }
}

// ===========================================================================
// K61, K62: the settlement restore and the injection regression
// ===========================================================================

/// The terminal after a run that left it raw, without echo, with the
/// foreground given away, concealed, and a status reply unread: the restore
/// took everything back and nothing reached the shell.
fn assert_restored_terminal(session: &mut Session, leg: &str) {
    // §3.6 step 1: the supervisor's group held the terminal when the job
    // ended, before the shell took it back.
    assert_eq!(
        session.left_foreground,
        Some(i64::from(session.job)),
        "{leg}: the job did not take the foreground back"
    );
    let drained = session.drain();
    assert_eq!(
        drained["bytes"],
        serde_json::json!([]),
        "{leg}: the shell read the session's bytes: {drained}"
    );
    // Review F2: exclusive mode does not outlive the attempt.
    assert_eq!(drained["dev_tty"], "ok", "{leg}: {drained}");
    let lflag = drained["lflag"].as_u64().unwrap();
    let echo = u64::from(libc::ECHO);
    let icanon = u64::from(libc::ICANON);
    assert_eq!(
        lflag & (echo | icanon),
        echo | icanon,
        "{leg}: termios was not restored: {drained}"
    );
    let bytes = session.terminal.bytes();
    let reset = b"\x1b[0m\x1b[?25h";
    let at = bytes
        .windows(reset.len())
        .rposition(|window| window == reset)
        .unwrap_or_else(|| panic!("{leg}: no reset sequence:\n{}", session.terminal.text()));
    let after = String::from_utf8_lossy(&bytes[at + reset.len()..]).replace('\r', "");
    assert!(
        after.trim_start().starts_with("ukai-jail: "),
        "{leg}: the summary does not follow the reset: {after:?}"
    );
}

#[test]
fn k61_k62_settlement_restores_the_terminal_and_nothing_reaches_the_shell() {
    if !common::live() {
        return;
    }
    // The plain case, then a wall expiry.
    for (leg, extra, hold) in [
        ("plain", &[][..], "300"),
        ("wall", &["--limit", "wall=2s"][..], "20000"),
    ] {
        let mut session = Session::start(Options::run(
            "tool",
            extra,
            &["tty-mess", "--hold-ms", hold],
        ));
        session
            .terminal
            .answer_queries
            .store(true, Ordering::SeqCst);
        session.wait_exit();
        let receipt = session.receipt();
        assert_settled(&receipt);
        all_restored(&receipt);
        if leg == "wall" {
            assert_eq!(receipt["outcome"]["cause"], "wall_expiry", "{receipt:#}");
        }
        // K62: every vector the filter answers was refused.
        for op in ["tiocsti", "tioclinux", "tiocsetd"] {
            for report in session.reports(op) {
                assert_eq!(report["errno"], "EPERM", "{leg}: {report}");
            }
        }
        assert_restored_terminal(&mut session, leg);
        assert!(session.quit().is_empty(), "{leg}");
    }

    // An external SIGKILL of the target.
    let mut session = Session::start(Options::run(
        "tool",
        &[],
        &["tty-mess", "--hold-ms", "30000"],
    ));
    session
        .terminal
        .answer_queries
        .store(true, Ordering::SeqCst);
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"tcsetpgrp\"", common::SETTLE_BOUND)
    );
    let receipt = common::read_receipt(&session.attempt().join("jail.json"));
    // SAFETY: SIGKILL to the target this session started.
    unsafe { libc::kill(launcher_pid(&receipt), libc::SIGKILL) };
    session.wait_exit();
    let receipt = session.receipt();
    assert_settled(&receipt);
    all_restored(&receipt);
    assert_restored_terminal(&mut session, "killed");

    // A step forced to fail: recorded false, said so, exit code unchanged.
    let mut session = Session::start(
        Options::run("tool", &[], &["tty-mess", "--hold-ms", "300"])
            .env("UKAI_JAIL_TEST_TERMINAL_FAIL", "termios"),
    );
    session
        .terminal
        .answer_queries
        .store(true, Ordering::SeqCst);
    assert_eq!(
        session.wait_exit().0,
        Some(0),
        "{}",
        session.terminal.text()
    );
    let receipt = session.receipt();
    assert_eq!(restored(&receipt)["termios"], false, "{receipt:#}");
    assert_eq!(restored(&receipt)["foreground"], true);
    assert_eq!(restored(&receipt)["input_flushed"], true);
    let text = session.terminal.text();
    assert!(
        text.contains("terminal not restored (termios: EIO): run reset"),
        "{text}"
    );
    assert!(
        text.contains("terminal not restored (termios): run reset"),
        "{text}"
    );
}

/// A process of the test's own, moved into the attempt's execution leaf and
/// traced by the test with `PTRACE_O_TRACEEXIT`, as X07.2's test does
/// (`j5_lifetime_linux.rs`): killed, it stops at its exit before it leaves
/// the cgroup, so the leaf stays populated and tree death cannot be verified
/// while the test holds it.
struct HeldMember {
    pid: libc::pid_t,
    released: bool,
}

impl HeldMember {
    fn plant(leaf: &Path) -> HeldMember {
        let child = std::process::Command::new("/bin/sleep")
            .arg("120")
            .spawn()
            .expect("a sleep of the test's own");
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        // The test reaps this pid itself.
        drop(child);
        let held = HeldMember {
            pid,
            released: false,
        };
        std::fs::write(leaf.join("cgroup.procs"), pid.to_string())
            .expect("the test's process moves into the leaf");
        // SAFETY: PTRACE_SEIZE of this test's own child; no pointers.
        let seized = unsafe {
            libc::ptrace(
                libc::PTRACE_SEIZE,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                libc::PTRACE_O_TRACEEXIT as usize as *mut libc::c_void,
            )
        };
        assert_eq!(seized, 0, "seize: {}", std::io::Error::last_os_error());
        held
    }

    /// Lets it finish dying, killing it first if nothing did, and reaps it.
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut status = 0;
        // SAFETY: waitpid on this test's own traced child, without blocking.
        let stopped =
            unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG | libc::__WALL) }
                == self.pid;
        if !stopped {
            // SAFETY: SIGKILL to this test's own child, then waiting for it.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                libc::waitpid(self.pid, &raw mut status, libc::__WALL);
            }
        }
        // SAFETY: PTRACE_DETACH of this test's own stopped tracee, then
        // reaping it.
        unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
            libc::waitpid(self.pid, &raw mut status, libc::__WALL);
        }
    }
}

impl Drop for HeldMember {
    fn drop(&mut self) {
        self.release();
    }
}

/// K61: when tree death cannot be verified, the four steps still run before
/// the supervisor exits, and the receipt says they ran without that proof.
#[test]
fn k61_an_unprovable_tree_death_still_restores_the_terminal_and_says_so() {
    if !common::live() {
        return;
    }
    let mut session = Session::start(Options::run("tool", &[], &["sleep", "60000"]));
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"sleep\"", common::SETTLE_BOUND),
        "{}",
        session.terminal.text()
    );
    let enforced = common::read_receipt(&session.attempt().join("jail.json"));
    let leaf = PathBuf::from(
        enforced["lifetime"]["native"]["details"]["execution_cgroup"]["path"]
            .as_str()
            .unwrap_or_else(|| panic!("no execution leaf: {enforced:#}")),
    );
    let mut member = HeldMember::plant(&leaf);
    // ^C ends the command; the leaf cannot be verified empty.
    session.terminal.type_bytes(b"\x03");
    let (code, _) = session.wait_exit();
    member.release();
    assert_eq!(code, Some(1), "{}", session.diagnose());
    assert_eq!(session.left_foreground, Some(i64::from(session.job)));
    let receipt = session.receipt();
    assert_eq!(receipt["phase"], "enforced", "{receipt:#}");
    assert!(
        receipt["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["code"] == "tree_unknown"),
        "{receipt:#}"
    );
    let restored = restored(&receipt);
    for field in ["foreground", "termios", "input_flushed", "reset_written"] {
        assert_eq!(restored[field], true, "{field}: {receipt:#}");
    }
    assert_eq!(restored["after_tree_death"], false, "{receipt:#}");
    // The released member lets `gc` verify and remove the retained leaf.
    let gc = std::process::Command::new(harness::jail_path())
        .arg("gc")
        .env("UKAI_DATA_DIR", session.data())
        .env("UKAI_CONFIG_DIR", session.root.path().join("config"))
        .output()
        .unwrap();
    assert!(
        gc.status.success(),
        "{}",
        String::from_utf8_lossy(&gc.stderr)
    );
}

// ===========================================================================
// K63: X05 in terminal mode
// ===========================================================================

#[test]
fn k63_the_targets_bytes_reach_the_terminal_unchanged_and_in_order() {
    if !common::live() {
        return;
    }
    let bytes = "70000";
    let direct = Options {
        program: Some(harness::fixture_path()),
        jail: ["--no-report", "stdout-bytes", bytes]
            .iter()
            .map(OsString::from)
            .collect(),
        ..Options::default()
    };
    let mut session = Session::start(direct);
    session.wait_exit();
    let expected = session.terminal.bytes();
    assert!(expected.len() >= 70_000);

    let mut session = Session::start(Options::run(
        "tool",
        &[],
        &["--no-report", "stdout-bytes", bytes],
    ));
    assert_eq!(session.wait_exit().0, Some(0));
    let seen = session.terminal.bytes();
    let reset = b"\x1b[0m\x1b[?25h";
    let end = seen
        .windows(reset.len())
        .rposition(|window| window == reset)
        .expect("a reset");
    // The pre-exec line comes first, then exactly the target's bytes, then
    // the reset and the summary.
    let line_end = seen
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("the pre-exec line");
    let first = String::from_utf8_lossy(&seen[..line_end]);
    assert!(
        first.starts_with("ukai-jail: terminal: attached"),
        "{first}"
    );
    assert_eq!(
        &seen[line_end + 2..end],
        expected.as_slice(),
        "the target's bytes changed"
    );
    assert!(
        String::from_utf8_lossy(&seen[end..]).contains("ukai-jail: settled"),
        "{}",
        String::from_utf8_lossy(&seen[end..])
    );
}

// ===========================================================================
// K64: disclosure
// ===========================================================================

#[test]
fn k64_explain_the_pre_exec_line_the_receipt_and_the_wall_say_what_attached() {
    if !common::live() {
        return;
    }
    // explain, text and JSON, attached and detached.
    for (words, attached) in [
        (vec!["explain", "--profile", "tool"], true),
        (
            vec!["explain", "--profile", "tool", "--terminal", "detach"],
            false,
        ),
    ] {
        let text = Options {
            jail: words.iter().map(OsString::from).collect(),
            ..Options::default()
        };
        let mut session = Session::start(text);
        session.wait_exit();
        let shown = session.terminal.text();
        let expected = if attached {
            "terminal attached (/dev/pts/"
        } else {
            "terminal detached"
        };
        assert!(shown.contains(expected), "{words:?}:\n{shown}");
        let json = Options {
            jail: words
                .iter()
                .chain(&["--json"])
                .map(OsString::from)
                .collect(),
            ..Options::default()
        };
        let mut session = Session::start(json);
        session.wait_exit();
        let shown = session.terminal.text();
        let value: Value = serde_json::from_str(&shown[shown.find('{').unwrap()..]).unwrap();
        assert_eq!(
            value["terminal"]["mode"],
            if attached { "attached" } else { "detached" },
            "{value:#}"
        );
        assert_eq!(
            value["policy"]["snapshot"].get("terminal").is_some(),
            attached,
            "{value:#}"
        );
    }

    // The pre-exec line names the target (escaped), the wall and the
    // supervisor; `kill -INT` on that pid ends the attempt at verified tree
    // death. A name with an escape sequence in it is shown escaped.
    let root = common::private_tempdir();
    for (name, mode) in [("data", 0o700), ("config", 0o700), ("work", 0o755)] {
        let path = root.path().join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .unwrap();
    }
    let link = root.path().join("work/agent\x1b[31mred");
    std::fs::copy(
        harness::fixture_path(),
        root.path().join("work/ukai-fixture"),
    )
    .unwrap();
    std::os::unix::fs::symlink(root.path().join("work/ukai-fixture"), &link).unwrap();
    let options = Options {
        jail: vec![
            "run".into(),
            "--profile".into(),
            "agent".into(),
            "--".into(),
            link.into_os_string(),
            "sleep".into(),
            "30000".into(),
        ],
        ..Options::default()
    };
    let mut session = Session::start_in(root, options);
    assert!(
        session
            .terminal
            .wait_for("\"op\":\"sleep\"", common::SETTLE_BOUND)
    );
    let text = session.terminal.text();
    let line = text
        .lines()
        .find(|line| line.starts_with("ukai-jail: terminal: attached"))
        .unwrap_or_else(|| panic!("no attached line:\n{text}"));
    assert!(line.contains("· wall 8h ·"), "{line}");
    assert!(
        line.contains("go to agent<U+001B>[31mred, not the jail"),
        "{line}"
    );
    assert!(
        !line.contains('\x1b'),
        "a raw escape reached the terminal: {line:?}"
    );
    let pid: libc::pid_t = line
        .rsplit("kill -INT ")
        .next()
        .and_then(|rest| rest.trim_end_matches('`').parse().ok())
        .unwrap_or_else(|| panic!("no pid: {line}"));
    assert_eq!(pid, session.job, "{line}");
    // SAFETY: SIGINT to the supervisor the line names.
    unsafe { libc::kill(pid, libc::SIGINT) };
    session.wait_exit();
    let receipt = session.receipt();
    assert_settled(&receipt);
    assert_eq!(receipt["outcome"]["cause"], "operator_signal");
    // The receipt's `requested` is the wall in canonical milliseconds.
    let wall = |receipt: &Value| {
        receipt["applied"]["limits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|limit| limit["key"] == "wall")
            .map(|limit| limit["requested"].clone())
    };
    assert_eq!(wall(&receipt), Some(Value::from("28800000")), "{receipt:#}");

    // A detached `agent` run keeps the profile's 2 h.
    let mut session = Session::start(Options::run(
        "agent",
        &["--terminal", "detach"],
        &["exit", "0"],
    ));
    session.wait_exit();
    assert_eq!(wall(&session.receipt()), Some(Value::from("7200000")));
}

// Helpers shared with the review's own probes.
#[allow(dead_code)]
fn workspace_of(session: &Session) -> &Path {
    session.root.path()
}
