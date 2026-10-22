//! The guardian: the second custodian (jail-macos §4.2–§4.6).
//!
//! The same `ukai-jail` executable, dispatched as `ukai-jail __guardian
//! <record-path> <a-read-fd> <b-write-fd> <r-write-fd> <e-write-fd>
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
//!    guardian's own process; nothing subscribed until a stop.
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
use std::time::Duration;

use crate::platform::macos::custody::Custodian;
use crate::platform::macos::custody_io::{
    self, CustodyClient, MAX_TABLE_CAPACITY, Token, continuous_time_ns, create_custody_client,
    self_token,
};

use frames::{Feed, Frame, FrameReader};

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
    eprintln!("ukai-jail: guardian: {step}: {code}");
    ExitCode::from(1)
}

/// The dispatch entry (`main.rs`'s `__guardian` arm). Argument order is in
/// the module header.
pub fn guardian_main(args: &[OsString]) -> ExitCode {
    if args.len() != 6 {
        return refuse(
            "arguments",
            format!(
                "expected 6 (record-path a-read-fd b-write-fd r-write-fd e-write-fd \
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
    let [a_read, b_write, _r_write, _e_write, launch_block_fd] = fds;
    match run(record_path, a_read, b_write, launch_block_fd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => error,
    }
}

fn run(
    record_path: std::path::PathBuf,
    a_read: RawFd,
    b_write: RawFd,
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
    spawn::spawn_sandbox_exec(&block).map_err(|error| refuse("sandbox-exec spawn", error))?;
    spawn::close_after_spawn(&block);

    // Step 6: the A/B conversation until a stop trigger.

    let own = self_token().unwrap_or([0; 8]);
    let mut guardian = Guardian {
        custody: custody_client,
        guard: Some(guard_client),
        custodian: Custodian::new(custody_io::table_capacity(MAX_TABLE_CAPACITY)),
        framer: FrameReader::default(),
        b,
        launcher_token: None,
        release_deadline_ns: None,
        grace_ns: u64::from(block.grace_ms) * 1_000_000,
        started_at,
        record_path,
        members_peak: 0,
        stop_started: false,
        eof_a: false,
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
    custodian: Custodian,
    framer: FrameReader,
    b: std::fs::File,
    launcher_token: Option<Token>,
    release_deadline_ns: Option<u64>,
    grace_ns: u64,
    started_at: u64,
    record_path: std::path::PathBuf,
    members_peak: usize,
    stop_started: bool,
    eof_a: bool,
}

/// What one pass over A produced.
enum FromA {
    Frames(Vec<Result<Frame, &'static str>>),
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
                FromA::Frames(framed) => {
                    for frame in framed {
                        match frame {
                            Ok(frame) => self.on_frame(frame),
                            Err(name) => {
                                // The supervisor disagrees about the
                                // grammar: stop the tree rather than guess.
                                let _ = std::io::stdout().flush();
                                eprintln!("ukai-jail: guardian: frame on A: {name}");
                                self.stop_and_finish(own);
                                std::process::exit(1);
                            }
                        }
                    }
                    if self.eof_a {
                        self.stop_and_finish(own);
                        return;
                    }
                }
                FromA::Eof => {
                    self.stop_and_finish(own);
                    return;
                }
                FromA::Idle => {}
            }

            self.drain_custody();

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

    /// One nonblocking pass over A: all readable frames, or end-of-file.
    fn read_a(&mut self, fd: RawFd) -> FromA {
        let mut frames = Vec::new();
        let mut eof = false;
        loop {
            match read_once(fd) {
                Err(error) => {
                    // A read failure on A is fatal in the same sense as EOF:
                    // the pipe can no longer carry the supervisor's will.
                    let _ = std::io::stdout().flush();
                    eprintln!("ukai-jail: guardian: read A: {error}");
                    return FromA::Eof;
                }
                Ok(None) => break,
                Ok(Some(bytes)) => {
                    if bytes.is_empty() {
                        eof = true;
                        break;
                    }
                    match self.framer.read(&bytes, false) {
                        Feed::Eof => unreachable!("eof only feeds on an empty read"),
                        Feed::Frames(mut produced) => frames.append(&mut produced),
                    }
                }
            }
        }
        if eof {
            self.eof_a = true;
        }
        if frames.is_empty() {
            if eof { FromA::Eof } else { FromA::Idle }
        } else {
            FromA::Frames(frames)
        }
    }

    fn on_frame(&mut self, frame: Frame) {
        match frame {
            Frame::LauncherToken(token) => {
                self.launcher_token = Some(token);
                self.wait_for_token(token);
            }
            Frame::ReleaseDeadline(deadline) => {
                self.release_deadline_ns = Some(deadline);
            }
        }
    }

    /// §4.3 step 5: apply events from G until the table holds the
    /// launcher's token, then answer `token-seen` on B. Running out of the
    /// 10 s budget is not a refusal — the wall deadline and A's end-of-file
    /// still govern the attempt — but the missed handshake is named on
    /// stderr.
    fn wait_for_token(&mut self, token: Token) {
        let budget = continuous_time_ns() + TOKEN_BUDGET_MS * 1_000_000;
        loop {
            self.drain_custody();
            if self.custodian.contains_token(&token) {
                if let Err(error) = write_frame(&mut self.b, &frames::encode_token_seen()) {
                    let _ = std::io::stdout().flush();
                    eprintln!("ukai-jail: guardian: write token-seen on B: {error}");
                    return;
                }
                return;
            }
            if continuous_time_ns() >= budget {
                let _ = std::io::stdout().flush();
                eprintln!(
                    "ukai-jail: guardian: launcher-token handshake: budget of {TOKEN_BUDGET_MS} \
                     ms passed without the token"
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Drain the ES ring into the custody core, tracking the membership
    /// peak and mirroring the client's sticky gap flag (§4.4).
    fn drain_custody(&mut self) {
        while let Some(polled) = self.custody.poll_full() {
            if let Some(kind) = custody_io::custody_kind(polled.kind) {
                self.custodian
                    .apply_sequenced(kind, polled.global_seq, polled.seq, &polled.event);
            }
            self.members_peak = self.members_peak.max(self.custodian.live_count());
        }
        if self.custody.ring_overflowed() {
            self.custodian.note_stream_gap();
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
        let counts = self.custodian.seq().counts();
        let custody = std::mem::replace(
            &mut self.custodian,
            Custodian::new(custody_io::table_capacity(MAX_TABLE_CAPACITY)),
        );
        let stop = stop::GuardianStop::new(custody, self.guard.take());
        let (outcome, guard) = stop.run(continuous_time_ns());
        self.guard = guard;
        let ended_at = continuous_time_ns();

        let record = record::from_stop_result(
            &outcome.result,
            record::StopFacts {
                counts,
                guard_denials: outcome.guard_denials,
                started_at: self.started_at,
                ended_at,
                members_peak: self.members_peak,
                guard_armed: outcome.guard_armed,
            },
            own,
            self.launcher_token.unwrap_or([0; 8]),
            record::boot_session_uuid(),
        );
        let json = record::render(&record);

        // The record is written once (§4.4); the same bytes go on B.
        if let Err(error) = std::fs::write(&self.record_path, json.as_bytes()) {
            let _ = std::io::stdout().flush();
            eprintln!("ukai-jail: guardian: write guardian record: {error}");
            std::process::exit(1);
        }
        if let Err(error) = write_frame(&mut self.b, &frames::encode_record(&json)) {
            let _ = std::io::stdout().flush();
            eprintln!("ukai-jail: guardian: write record on B: {error}");
            std::process::exit(1);
        }
    }
}

/// One length-prefixed frame, flushed in full.
fn write_frame(b: &mut std::fs::File, frame: &[u8]) -> Result<(), String> {
    let mut wire = Vec::with_capacity(frame.len() + 4);
    wire.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    wire.extend_from_slice(frame);
    b.write_all(&wire).map_err(|error| error.to_string())
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
fn read_once(fd: RawFd) -> Result<Option<Vec<u8>>, String> {
    // SAFETY: one poll of one owned descriptor with a one-entry array.
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one poll of one owned descriptor with a one-entry array.
    let ready = unsafe { libc::poll(&mut poll_fd, 1, 0) };
    if ready < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if ready == 0 {
        return Ok(None);
    }
    if poll_fd.revents & libc::POLLIN == 0 {
        if poll_fd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            // The supervisor's end closed: the residue read reports EOF.
            return read_bytes(fd).map(Some);
        }
        return Ok(None);
    }
    read_bytes(fd).map(Some)
}

fn read_bytes(fd: RawFd) -> Result<Vec<u8>, String> {
    let mut buffer = [0u8; 4096];
    // SAFETY: read into a stack buffer of an owned descriptor.
    let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if read < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(buffer[..read as usize].to_vec())
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
