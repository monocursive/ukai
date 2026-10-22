//! The guardian: the second custodian (jail-macos §4.2–§4.6).
//!
//! The same `ukai-jail` executable, dispatched as `ukai-jail __guardian
//! <record-path> <a-read-fd> <b-write-fd> <r-read-fd> <e-write-fd>
//! <launch-block-fd>` **before any configuration, policy or I/O setup**
//! (§4.1 rule 2): this code path is libc, the ES shim and audit-token
//! signalling, nothing else.
//!
//! # The guardian's contract with its supervisor
//!
//! - The supervisor spawns the guardian with `POSIX_SPAWN_SETPGID`: the
//!   guardian runs in its **own process group**. This module never sets one;
//!   that is the supervisor's spawn job, stated here so the contract is
//!   written down (§4.2).
//! - The supervisor holds pipe **A** (→ guardian) and the guardian holds
//!   **B** (→ supervisor). Only the two custodians hold them (§4.3).
//! - R and E (the launcher's release and error pipes) pass through: the
//!   guardian inherits the launcher's ends (their numbers travel in the
//!   launch block), hands them to `sandbox-exec` in the one spawn, and
//!   closes its own copies right after (§4.3 step 4, jail-v1 §8.3).
//! - The launch block arrives on its own inherited descriptor in the
//!   documented binary grammar ([`launch_block`]); the record file already
//!   exists and the guardian writes it **once**, at the stop's end (§4.4).
//!
//! # The guardian's signals
//!
//! §4.2: `SIGHUP SIGINT SIGQUIT SIGTERM SIGTSTP SIGTTIN SIGTTOU` are
//! ignored. The guardian acts only on A's end-of-file and the wall
//! deadline.
//!
//! # Order of a run
//!
//! 1. Ignore the terminal signals; parse the fd arguments.
//! 2. Create custody client G: descendants scope, unmute, read back the
//!    mute set, refuse naming any event still muted, subscribe the three
//!    custody events (§4.3 step 3, checked as step 1).
//! 3. Create guard client G′: descendants scope, unmute, mute the
//!    guardian's own process, set/read back fail-closed; no subscription until stop.
//! 4. Lower `RLIMIT_NPROC` soft and hard to this operator's process count
//!    plus the headroom (§4.1 rule 6); any failure exits naming it.
//! 5. Spawn `sandbox-exec` once from the launch block, then close the
//!    guardian's copies of R, E, the stdio sources and the pty slave.
//! 6. Write `ready` on B. Read A: `launcher-token` → apply events from G
//!    until the table holds that token, answer `token-seen`;
//!    `release-deadline` → arm the wall watchdog (deadline + grace on the
//!    continuous clock). End-of-file on A runs the stop.
//! 7. Stop: arm G′ (failure proceeds unguarded and records it), then the
//!    freeze/kill/drain machine with the §4.5 budget and tail.
//! 8. Write the guardian record once, send it as the final frame on B, and
//!    exit 0 — the supervisor reaps the guardian (§4.5).
//!
//! Every failure before the stop exits non-zero with one stderr line naming
//! the failing step and the ES or OS result code; once a stop has started,
//! the record is still written.
//!
//! # Live-VM procedure (the rows the unit tests cannot cover)
//!
//! The tests in `tests/macos_guardian.rs` cover the codec, the record shape,
//! the rlimit math and the K98 refusal (no entitlement on this Mac). The
//! live custody rows need the dev VM and the provisioning profile:
//! - K87/K88 (wall expiry, supervisor `SIGKILL`, `SIGSTOP`): run an
//!   attempt, kill the supervisor, assert the fixture empties within the
//!   budget and the record reads `drained`.
//! - K91 (descriptors): `lsof` every member; no member holds A, B, a
//!   guardian stdio copy or the pty slave.
//! - K92 (drain proof): the adversarial fork/`SIGCONT`/exec fixtures; the
//!   stop settles, never a false `tree_empty`.
//! - K93 (event load): a fork/exec storm must drain or produce a real gap;
//!   the guard's load never gaps client G.
//! - K97 (clocks): a wall deadline spanning host sleep expires on the
//!   continuous clock.

// The submodules are `pub` so the conformance tests (tests/macos_guardian.rs)
// can drive the codec, the record and the rlimit math directly.
pub mod frames;
pub mod launch_block;
pub mod record;
pub mod rlimit;
pub mod spawn;
pub mod stop;

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::io::{FromRawFd as _, RawFd};
use std::process::ExitCode;

use crate::platform::macos::custody::Custodian;
use crate::platform::macos::custody_io::{
    self, CustodyClient, MAX_TABLE_CAPACITY, Token, continuous_time_ns, create_custody_client,
    self_token,
};

use frames::{Frame, FrameReader};

/// The launcher-token handshake budget, initial 10 s (§4.3 step 5).
const TOKEN_BUDGET_MS: u64 = 10_000;

/// The event loop's poll slice on A, milliseconds.
const TICK_MS: i32 = 20;

/// The ignored terminal signals of §4.2.
const IGNORED_SIGNALS: [libc::c_int; 7] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
];

/// One-line stderr refusal: `ukai-jail: guardian: <step>: <code>`. X05
/// discipline: the guardian writes nothing else to stderr, ever, and its
/// stdout is never touched.
fn refuse(step: &str, code: impl std::fmt::Display) -> ExitCode {
    let _ = std::io::stdout().flush();
    let _ = writeln!(std::io::stderr(), "ukai-jail: guardian: {step}: {code}");
    ExitCode::from(1)
}

/// The dispatch entry (`main.rs`'s `__guardian` arm). Argument order is in
/// the module header.
pub fn guardian_main(args: &[OsString]) -> ExitCode {
    if args.len() != 6 {
        return refuse(
            "arguments",
            format!(
                "expected 6 (record-path a-read-fd b-write-fd r-read-fd e-write-fd \
                 launch-block-fd), got {}",
                args.len()
            ),
        );
    }
    let record_path = std::path::PathBuf::from(&args[0]);
    let mut fds = [0i32; 5];
    for (slot, raw) in fds.iter_mut().zip(&args[1..]) {
        use std::os::unix::ffi::OsStrExt as _;
        match std::str::from_utf8(raw.as_bytes())
            .ok()
            .and_then(|text| text.parse().ok())
        {
            Some(fd) => *slot = fd,
            None => return refuse("arguments", format!("bad fd argument {raw:?}")),
        }
    }
    for (index, fd) in fds.iter().enumerate() {
        if *fd < 3 || fds[..index].contains(fd) {
            return refuse(
                "arguments",
                "inherited descriptors must be distinct and above stdio",
            );
        }
    }
    let [a_read, b_write, r_read, e_write, launch_block_fd] = fds;
    match run(
        record_path,
        a_read,
        b_write,
        r_read,
        e_write,
        launch_block_fd,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => error,
    }
}

fn run(
    record_path: std::path::PathBuf,
    a_read: RawFd,
    b_write: RawFd,
    r_read: RawFd,
    e_write: RawFd,
    launch_block_fd: RawFd,
) -> Result<(), ExitCode> {
    let started_at = continuous_time_ns();

    // §4.2: the terminal signals are ignored; the process group is the
    // supervisor's spawn job (documented in the module header).
    // SAFETY: `signal` with `SIG_IGN` on named signals; no handlers involved.
    unsafe {
        for signum in IGNORED_SIGNALS {
            libc::signal(signum, libc::SIG_IGN);
        }
    }

    for fd in [a_read, b_write, r_read, e_write, launch_block_fd] {
        spawn::set_close_on_exec(fd).map_err(|error| refuse("guardian descriptors", error))?;
    }

    // Step 2: the custody client G (§4.3 step 3, checked as step 1). A
    // failure refuses naming the result code — `ERR_NOT_ENTITLED` upstream
    // refuses with remediation `unsupported` (K98).
    let custody_client =
        create_custody_client().map_err(|result| refuse("custody client", es_result(&result)))?;
    custody_io::setup_custody(&custody_client).map_err(|error| refuse("custody setup", error))?;

    // Step 3: the guard client G′. Its creation failure is fatal here too:
    // the design promises a guard at every stop, and a guardian that cannot
    // make one must say so before `ready`.
    let guard_client =
        create_custody_client().map_err(|result| refuse("guard client", es_result(&result)))?;
    custody_io::setup_guard(&guard_client).map_err(|error| refuse("guard setup", error))?;

    // Rule 6: the per-UID process ceiling, before anything forks.
    rlimit::apply().map_err(|error| refuse("RLIMIT_NPROC", error))?;

    // Read the launch block once, from its inherited descriptor.
    let block = read_launch_block(launch_block_fd)?;
    if block.launcher_read_fd != r_read
        || block.launcher_error_fd != e_write
        || block.stdio.iter().any(|action| {
            matches!(action, launch_block::FdAction::Fd(fd)
            if [a_read, b_write, launch_block_fd, r_read, e_write].contains(fd))
        })
    {
        return Err(refuse("launch block", "descriptor ownership mismatch"));
    }

    let own = self_token().ok_or_else(|| refuse("self audit token", "unavailable"))?;
    let mut custodian = Custodian::new(custody_io::table_capacity(MAX_TABLE_CAPACITY));
    custodian
        .register_custodian(own)
        .map_err(|_| refuse("custodian registration", "full"))?;
    let record_file = std::fs::OpenOptions::new()
        .write(true)
        .open(&record_path)
        .map_err(|error| refuse("open guardian record", error))?;
    let boot_session = record::boot_session_uuid();

    // Step 3 ends with `ready` (§4.3): the supervisor may proceed as soon
    // as it arrives; the spawn is step 4.
    // SAFETY: B's write end is the guardian's for its whole life.
    let mut b = unsafe { std::fs::File::from_raw_fd(b_write) };
    write_frame(&mut b, &frames::encode_ready())
        .map_err(|error| refuse("write ready on B", error))?;

    // Step 4: the one spawn, then the EOF-semantics closes (the block's R/E
    // numbers are the inherited launcher ends passed in argv; this closes
    // the guardian's copies of them too). A spawn failure after `ready`
    // still exits non-zero naming the step, and the supervisor sees B's
    // end-of-file and refuses (§4.3).
    let launcher_pid =
        spawn::spawn_sandbox_exec(&block).map_err(|error| refuse("sandbox-exec spawn", error))?;
    custodian.expect_root(launcher_pid);
    spawn::close_after_spawn(&block);

    // Step 6: the A/B conversation until a stop trigger.

    let mut guardian = Guardian {
        custody: custody_client,
        guard: Some(guard_client),
        custodian: Some(custodian),
        framer: FrameReader::default(),
        b,
        launcher_token: None,
        release_deadline_ns: None,
        grace_ns: u64::from(block.grace_ms) * 1_000_000,
        started_at,
        record_file,
        boot_session,
        diagnostic_written: false,
        token_seen_sent: false,
        token_wait_until: None,
        members_peak: 0,
        stop_started: false,
    };
    guardian.event_loop(a_read, own);
    Ok(())
}

fn es_result(result: &crate::platform::macos::custody_io::EsNewResult) -> String {
    custody_io::es_new_result_name(*result)
}

/// The live state of one guardian run.
struct Guardian {
    custody: CustodyClient,
    guard: Option<CustodyClient>,
    custodian: Option<Custodian>,
    framer: FrameReader,
    b: std::fs::File,
    launcher_token: Option<Token>,
    release_deadline_ns: Option<u64>,
    grace_ns: u64,
    started_at: u64,
    record_file: std::fs::File,
    boot_session: String,
    diagnostic_written: bool,
    token_seen_sent: bool,
    token_wait_until: Option<u64>,
    members_peak: usize,
    stop_started: bool,
}

/// What one pass over A produced.
enum FromA {
    Frame(Result<Frame, &'static str>),
    Eof,
    Idle,
}

impl Guardian {
    /// The event loop: poll A (end-of-file is the stop trigger, §4.3),
    /// drain G into the custody core, service the token handshake and the
    /// wall watchdog. `poll(2)` on A; the ES ring drains through its own
    /// bounded sync — no async runtime, no dependency beyond libc.
    fn event_loop(&mut self, a_read: RawFd, own: Token) {
        loop {
            match self.read_a(a_read) {
                FromA::Frame(Ok(frame)) => self.on_frame(frame),
                FromA::Frame(Err(name)) => {
                    self.diagnose("frame on A", name);
                    self.stop_and_finish(own);
                    return;
                }
                FromA::Eof => {
                    self.stop_and_finish(own);
                    return;
                }
                FromA::Idle => {}
            }

            self.drain_custody();
            if !self.check_token() {
                self.stop_and_finish(own);
                return;
            }

            // The wall watchdog: deadline + grace on the continuous clock
            // (§4.3 step 6, cause `wall`).
            if let Some(deadline) = self.release_deadline_ns
                && continuous_time_ns() >= deadline.saturating_add(self.grace_ns)
            {
                self.stop_and_finish(own);
                return;
            }

            poll_tick(a_read, TICK_MS);
        }
    }

    /// Read at most one complete frame using only fixed stack storage.
    fn read_a(&mut self, fd: RawFd) -> FromA {
        let mut bytes = [0u8; frames::MAX_FRAME_BYTES];
        loop {
            let wanted = self.framer.wanted();
            match read_once(fd, &mut bytes[..wanted]) {
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    self.diagnose("read A", &error.to_string());
                    return FromA::Eof;
                }
                Ok(None) => return FromA::Idle,
                Ok(Some(count)) => match self.framer.read_one(&bytes[..count], count == 0) {
                    Err(error) => return FromA::Frame(Err(error)),
                    Ok(Some(frame)) => return FromA::Frame(Ok(frame)),
                    Ok(None) if count == 0 => return FromA::Eof,
                    Ok(None) => {}
                },
            }
        }
    }

    fn on_frame(&mut self, frame: Frame) {
        match frame {
            Frame::LauncherToken(token) => {
                self.launcher_token = Some(token);
                self.token_wait_until =
                    Some(continuous_time_ns().saturating_add(TOKEN_BUDGET_MS * 1_000_000));
            }
            Frame::ReleaseDeadline(deadline) => {
                self.release_deadline_ns = frames::wall_deadline(deadline);
            }
        }
    }

    /// Handshake progress never blocks A's EOF or the wall watchdog.
    fn check_token(&mut self) -> bool {
        if self.token_seen_sent {
            return true;
        }
        let Some(token) = self.launcher_token else {
            return true;
        };
        if self
            .custodian
            .as_ref()
            .is_some_and(|c| c.contains_token(&token))
        {
            if let Err(error) = write_frame(&mut self.b, b"token-seen") {
                self.diagnose("write token-seen on B", &error);
                return false;
            }
            self.token_seen_sent = true;
        } else if self
            .token_wait_until
            .is_some_and(|end| continuous_time_ns() >= end)
        {
            self.diagnose("launcher-token handshake", "budget exhausted");
            return false;
        }
        true
    }

    fn diagnose(&mut self, step: &str, error: &str) {
        if !self.diagnostic_written {
            let _ = writeln!(std::io::stderr(), "ukai-jail: guardian: {step}: {error}");
            self.diagnostic_written = true;
        }
    }

    /// Drain the ES ring into the custody core, tracking the membership
    /// peak and mirroring the client's sticky gap flag (§4.4).
    fn drain_custody(&mut self) {
        let Some(custodian) = self.custodian.as_mut() else {
            return;
        };
        for _ in 0..4096 {
            let Some(polled) = self.custody.poll_full() else {
                break;
            };
            custodian.apply_polled(&polled);
            self.members_peak = self.members_peak.max(custodian.live_count());
        }
        if self.custody.ring_overflowed() {
            custodian.note_stream_gap();
        }
    }

    /// The stop (§4.5) and the finish (§4.4): record once, final frame on
    /// B, exit 0. The supervisor reaps the guardian.
    fn stop_and_finish(&mut self, own: Token) {
        if self.stop_started {
            return;
        }
        self.stop_started = true;
        self.drain_custody();
        let Some(custody) = self.custodian.take() else {
            return;
        };
        let stop = stop::GuardianStop::new(custody, self.guard.take());
        let (outcome, guard) = stop.run_with_source(continuous_time_ns(), &self.custody);
        self.guard = guard;
        let ended_at = continuous_time_ns();

        let record = record::from_stop_result(
            &outcome.result,
            record::StopFacts {
                counts: outcome.counts,
                guard_denials: outcome.guard_denials,
                started_at: self.started_at,
                ended_at,
                members_peak: self.members_peak.max(outcome.members_peak),
                guard_armed: outcome.guard_armed,
            },
            own,
            self.launcher_token.unwrap_or([0; 8]),
            std::mem::take(&mut self.boot_session),
        );
        if let Err(error) = record::deliver(&record, &mut self.record_file, &mut self.b) {
            self.diagnose("guardian record delivery", &error.to_string());
        }
    }
}

/// One length-prefixed frame, flushed in full.
fn write_frame(b: &mut std::fs::File, frame: &[u8]) -> Result<(), String> {
    if frame.is_empty() || frame.len() > frames::MAX_FRAME_BYTES {
        return Err("invalid frame length".to_owned());
    }
    b.write_all(&(frame.len() as u32).to_le_bytes())
        .and_then(|()| b.write_all(frame))
        .map_err(|error| error.to_string())
}

/// Read the launch block from its inherited descriptor, to end-of-file.
fn read_launch_block(fd: RawFd) -> Result<launch_block::LaunchBlock, ExitCode> {
    // SAFETY: the fd is the supervisor's inherited descriptor, consumed here.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .map_err(|error| refuse("read launch block", error))?;
    launch_block::decode(&bytes).map_err(|error| refuse("launch block", error))
}

/// One nonblocking read of A. `None` is an idle tick.
fn read_once(fd: RawFd, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll has one valid record and read is bounded by the slice.
    let ready = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    if ready < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if ready == 0 {
        return Ok(None);
    }
    if poll_fd.revents & libc::POLLNVAL != 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EBADF));
    }
    if poll_fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
        return Ok(None);
    }
    // SAFETY: writable stack buffer, no ownership transfer of the inherited fd.
    let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Some(read as usize))
}

/// A bounded wait for A's readability, only an early wake for the next pass.
fn poll_tick(fd: RawFd, timeout_ms: i32) {
    // SAFETY: one poll of one owned descriptor with a one-entry array.
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one poll of one owned descriptor with a one-entry array.
    let _ = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
}
