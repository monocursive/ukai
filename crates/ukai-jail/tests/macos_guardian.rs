//! Guardian-slice tests (jail-macos §4.2–§4.6).
//!
//! Coverage, by row:
//! - launch-block codec round-trips and refusals (module-local, plus the
//!   guardian-facing `decode` here) — no K row, mechanics;
//! - the guardian record's JSON shape — §4.4, the contract `gc` reads (§4.9);
//! - the rule-6 `RLIMIT_NPROC` math — pure unit tests of
//!   [`lowered_limit`] (the live headroom proof is K92, dev VM);
//! - K98, the refusal before any workload process: with the entitlement
//!   absent on this Mac, a spawned `__guardian` fails fast at custody client
//!   G's creation naming `ERR_NOT_ENTITLED` (K98 evidence). The full live
//!   round-trips (K87–K93, K97) need the dev VM and the provisioning
//!   profile; the procedure is documented in the `guardian` module header.
#![cfg(target_os = "macos")]

use std::process::{Command, Output};

mod common;

use ukai_jail::platform::macos::guardian::launch_block::{
    FdAction, LaunchBlock, MAX_PROFILE_BYTES, decode, encode,
};
use ukai_jail::platform::macos::guardian::rlimit::lowered_limit;

fn sample_block() -> LaunchBlock {
    LaunchBlock {
        sandbox_exec_path: "/usr/bin/sandbox-exec".to_owned(),
        sbpl_profile_source: "(version 1)(allow default)".to_owned(),
        child_argv: vec!["/bin/echo".to_owned()],
        child_envp: vec!["PATH=/usr/bin:/bin".to_owned()],
        working_dir: String::new(),
        stdio: [FdAction::Null, FdAction::Null, FdAction::Null],
        sigdef: vec![1, 2, 3, 17, 18, 20, 21, 22, 23, 24, 28],
        sigmask: 0,
        setsid: true,
        launcher_read_fd: 4,
        launcher_error_fd: 5,
        terminal: false,
        grace_ms: 2000,
    }
}

// The codec round-trips a full block through `decode(encode(..))`, including
// an empty argv — the launcher argv may be empty only in the degenerate test
// case, and the grammar must still carry it.
#[test]
fn launch_block_round_trips_including_empty_argv() {
    let mut block = sample_block();
    assert_eq!(decode(&encode(&block)).unwrap(), block);
    block.child_argv.clear();
    assert_eq!(decode(&encode(&block)).unwrap(), block);
}

// A profile over the documented maximum is refused, not truncated: an
// oversized profile is a supervisor bug.
#[test]
fn launch_block_refuses_oversized_profile() {
    let mut block = sample_block();
    block.sbpl_profile_source = "x".repeat(MAX_PROFILE_BYTES as usize + 1);
    let error = decode(&encode(&block)).unwrap_err();
    assert!(error.to_string().contains("too large"), "{error}");
}

// A profile exactly at the bound still round-trips.
#[test]
fn launch_block_accepts_profile_at_bound() {
    let mut block = sample_block();
    block.sbpl_profile_source = "x".repeat(MAX_PROFILE_BYTES as usize);
    assert_eq!(decode(&encode(&block)).unwrap(), block);
}

// Truncation is refused: a half block must never spawn anything.
#[test]
fn launch_block_refuses_truncation() {
    let encoded = encode(&sample_block());
    assert!(decode(&encoded[..encoded.len() / 2]).is_err());
    assert!(decode(&encoded[..encoded.len() - 1]).is_err());
    assert!(decode(&[]).is_err());
}

// Trailing bytes mean the two ends disagree about the grammar; refused.
#[test]
fn launch_block_refuses_trailing_bytes() {
    let mut encoded = encode(&sample_block());
    encoded.push(0);
    assert!(decode(&encoded).is_err());
}

// Rule 6's math: current + headroom, saturating, never wrapping.
#[test]
fn rlimit_math_saturates() {
    assert_eq!(lowered_limit(312, 1024), 1336);
    assert_eq!(lowered_limit(0, 1024), 1024);
    assert_eq!(lowered_limit(u64::MAX, 1024), i64::MAX as u64);
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_ukai-jail")
}

/// Fabricate the guardian's descriptor set with real, inherited (non-
/// close-on-exec) descriptors, as `posix_spawn` would deliver them: pipe A's
/// read end, pipe B's write end, two fillers for R and E, and a file
/// holding a minimal launch block. Returns the argv tail.
fn fabricated_launch(temp: &tempfile::TempDir) -> (Vec<String>, Vec<std::os::fd::OwnedFd>) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut pipe = [0; 2];
        // SAFETY: writable two-fd array, both descriptors immediately owned.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        for fd in pipe {
            // SAFETY: each fresh pipe end has exactly one owner.
            held.push(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    // Real distinct stand-ins for the launcher's ends; keep their owners.
    let r = std::fs::File::open("/dev/null").unwrap();
    let e = std::fs::File::open("/dev/null").unwrap();
    let mut block = sample_block();
    block.launcher_read_fd = r.as_raw_fd();
    block.launcher_error_fd = e.as_raw_fd();
    let block_path = temp.path().join("launch-block");
    std::fs::write(&block_path, encode(&block)).unwrap();
    held.push(r.into());
    held.push(e.into());
    held.push(std::fs::File::open(block_path).unwrap().into());
    for fd in &held {
        // SAFETY: these test-owned descriptors intentionally cross one spawn.
        assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    }
    let args = vec![
        temp.path()
            .join("guardian.json")
            .to_string_lossy()
            .into_owned(),
        held[0].as_raw_fd().to_string(),
        held[3].as_raw_fd().to_string(),
        held[4].as_raw_fd().to_string(),
        held[5].as_raw_fd().to_string(),
        held[6].as_raw_fd().to_string(),
    ];
    (args, held)
}

fn run_guardian() -> (Output, tempfile::TempDir) {
    let temp = common::private_tempdir();
    let (args, _held) = fabricated_launch(&temp);
    let output = Command::new(binary())
        .args(["__guardian"])
        .args(&args)
        .env("UKAI_CONFORMANCE", "1")
        .output()
        .expect("the guardian runs");
    (output, temp)
}

// K98, refusal evidence on this Mac: before any workload process exists, a
// guardian without the ES entitlement fails **fast** at custody client G's
// creation, one stderr line naming the ES result code, non-zero exit. With
// the shim's bindings compiled in (always, since the ES slice landed) the
// code is `ERR_NOT_ENTITLED`; if the framework were somehow entitled on a
// dev machine, the test still asserts the fast, one-line refusal naming the
// failing step — the entitlement-specific assertion is what this Mac
// exercises.
#[test]
fn guardian_refuses_fast_without_entitlement() {
    let (output, temp) = run_guardian();
    assert!(!output.status.success(), "status {:?}", output.status);
    assert!(
        output
            .status
            .code()
            .is_some_and(|code| (1..=125).contains(&code)),
        "exit code {:?}",
        output.status.code()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly one stderr line, got: {stderr:?} (stdout {:?})",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        lines[0].starts_with("ukai-jail: guardian: custody client: "),
        "names the failing step: {}",
        lines[0]
    );
    if std::env::var_os("UKAI_GUARDIAN_ENTITLED").is_none() {
        assert!(
            lines[0].contains("ERR_NOT_ENTITLED"),
            "this Mac has no ES entitlement: {}",
            lines[0]
        );
    }
    // Nothing was written to the record: the refusal happened before any
    // stop could run.
    assert!(
        !temp.path().join("guardian.json").exists(),
        "no record on a pre-custody refusal"
    );
}

// The `__guardian` dispatch is strict about its argument count: wrong arity
// refuses with the same one-line discipline and never touches stdout.
#[test]
fn guardian_refuses_wrong_arity() {
    let output = Command::new(binary())
        .args(["__guardian", "only-one-arg"])
        .env("UKAI_CONFORMANCE", "1")
        .output()
        .expect("the guardian runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
    assert!(stderr.starts_with("ukai-jail: guardian: arguments: "));
    assert!(output.stdout.is_empty(), "stdout stays silent (X05)");
}

#[test]
fn regression_l2_garbled_frame_length_is_an_error() {
    use ukai_jail::platform::macos::guardian::frames::{Feed, FrameReader};
    let mut reader = FrameReader::default();
    assert!(
        matches!(reader.read(&u32::MAX.to_le_bytes(), false), Feed::Frames(frames) if frames.iter().any(Result::is_err))
    );
}

#[test]
fn regression_c3_count_matches_independent_ps() {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let measured =
        ukai_jail::platform::macos::guardian::rlimit::current_process_count_for_uid(uid).unwrap();
    let ps = Command::new("/bin/ps")
        .args(["-U", &uid.to_string(), "-o", "pid="])
        .output()
        .unwrap();
    assert!(ps.status.success());
    let independent = String::from_utf8(ps.stdout).unwrap().lines().count() as u64;
    let tolerance = 30.max(independent / 10); // Processes may start/exit between snapshots.
    assert!(
        measured.abs_diff(independent) <= tolerance,
        "custody={measured}, ps={independent}"
    );
}

#[test]
fn regression_c1_spawn_inherits_only_launcher_descriptors() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use ukai_jail::platform::macos::guardian::spawn::spawn_sandbox_exec;
    let temp = common::private_tempdir();
    let helper = temp.path().join("fd-probe");
    let source = temp.path().join("fd-probe.c");
    // Also serves as sandbox-exec's stand-in: ignore its argv and inspect
    // the actual descriptors inherited through the production spawn code.
    std::fs::write(&source, "#include <fcntl.h>\n#include <stdio.h>\nint main(void) { for(int fd=0;fd<256;fd++) if(fcntl(fd,F_GETFD)>=0) printf(\"%d\\n\",fd); return 0; }\n").unwrap();
    assert!(
        Command::new("clang")
            .arg(&source)
            .arg("-o")
            .arg(&helper)
            .status()
            .unwrap()
            .success()
    );
    let open = || {
        // SAFETY: static NUL-terminated path, no pointer retained.
        let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        assert!(raw >= 0);
        // SAFETY: open returned a new descriptor, owned only here.
        unsafe { OwnedFd::from_raw_fd(raw) }
    };
    let a = open();
    let b = open();
    let r = open();
    let e = open();
    for fd in [&r, &e] {
        assert_eq!(
            // SAFETY: valid test-owned descriptor, change its exec flag only.
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    let output = std::fs::File::create(temp.path().join("fds")).unwrap();
    let mut block = sample_block();
    block.sandbox_exec_path = helper.to_str().unwrap().to_owned();
    block.stdio[1] = FdAction::Fd(output.as_raw_fd());
    block.launcher_read_fd = r.as_raw_fd();
    block.launcher_error_fd = e.as_raw_fd();
    let child = spawn_sandbox_exec(&block).unwrap();
    let mut status = 0;
    // SAFETY: reap only the child this test spawned into valid status storage.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    let fds: Vec<i32> = std::fs::read_to_string(temp.path().join("fds"))
        .unwrap()
        .lines()
        .map(|s| s.parse().unwrap())
        .collect();
    let mut expected = vec![0, 1, 2, r.as_raw_fd(), e.as_raw_fd()];
    expected.sort();
    assert_eq!(
        fds,
        expected,
        "A={}, B={}, stdio-source={} must stay private",
        a.as_raw_fd(),
        b.as_raw_fd(),
        output.as_raw_fd()
    );
}

struct FakeClock(std::rc::Rc<std::cell::Cell<u64>>);
impl ukai_jail::platform::macos::guardian::stop::StopClock for FakeClock {
    fn now_ns(&mut self) -> u64 {
        self.0.get()
    }
    fn wait_tick(&mut self) {
        self.0.set(self.0.get() + 1_000_000);
    }
}
struct FakeCustody {
    now: std::rc::Rc<std::cell::Cell<u64>>,
    events: std::collections::VecDeque<(u64, ukai_jail::platform::macos::es::EsPoll)>,
    syncs: usize,
    gap: bool,
}
impl ukai_jail::platform::macos::guardian::stop::CustodySource for FakeCustody {
    fn poll(&mut self) -> Option<ukai_jail::platform::macos::es::EsPoll> {
        if self
            .events
            .front()
            .is_some_and(|(at, _)| *at <= self.now.get())
        {
            self.events.pop_front().map(|(_, e)| e)
        } else {
            None
        }
    }
    fn gapped(&self) -> bool {
        self.gap
    }
    fn synchronize(&mut self, _: u32) -> bool {
        self.syncs += 1;
        true
    }
}
#[derive(Default)]
struct FakeSignals {
    calls: Vec<([u32; 8], i32)>,
    at_ns: Vec<u64>,
    clock: Option<std::rc::Rc<std::cell::Cell<u64>>>,
}
impl ukai_jail::platform::macos::custody::Signaller for FakeSignals {
    fn signal(&mut self, token: &[u32; 8], sig: i32) -> i32 {
        self.calls.push((*token, sig));
        self.at_ns
            .push(self.clock.as_ref().map_or(0, |clock| clock.get()));
        if token[7] == 1 { libc::ESRCH } else { 0 }
    }
}
fn stop_event(
    kind: u32,
    global_seq: u64,
    seq: u64,
    token: [u32; 8],
) -> ukai_jail::platform::macos::es::EsPoll {
    use ukai_jail::platform::macos::es::{self, EsEvent, EsPoll};
    let event = match kind {
        es::EVENT_FORK => EsEvent::Fork { token },
        es::EVENT_EXEC => EsEvent::Exec { token },
        _ => EsEvent::Exit { token, status: 9 },
    };
    EsPoll {
        kind,
        global_seq,
        seq,
        event,
    }
}

#[test]
fn stop_polls_custody_retries_exec_and_drains_during_tail() {
    use ukai_jail::platform::macos::{custody::Custodian, es, guardian::stop::GuardianStop};
    let mut old = [0u32; 8];
    old[5] = 100;
    old[7] = 1;
    let mut new = old;
    new[7] = 2;
    let mut child = new;
    child[5] = 101;
    let now = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut source = FakeCustody {
        now: now.clone(),
        events: [
            (0, stop_event(es::EVENT_FORK, 1, 1, old)),
            (7_000_000, stop_event(es::EVENT_EXEC, 2, 1, new)),
            (61_000_000, stop_event(es::EVENT_FORK, 3, 2, child)),
            (62_000_000, stop_event(es::EVENT_EXIT, 4, 1, child)),
            (5_100_000_000, stop_event(es::EVENT_EXIT, 5, 2, new)),
        ]
        .into(),
        syncs: 0,
        gap: false,
    };
    let mut custody = Custodian::new(2);
    custody.expect_root(100);
    let mut signals = FakeSignals {
        clock: Some(now.clone()),
        ..Default::default()
    };
    let (out, _) = GuardianStop::new(custody, None).run_with_io(
        0,
        &mut source,
        &mut FakeClock(now),
        &mut signals,
    );
    assert!(out.result.drained());
    assert_eq!(
        out.result.elapsed_ns(),
        5_100_000_000,
        "tail preserves original start"
    );
    assert_eq!(out.counts, [2, 1, 2]);
    assert_eq!(out.members_peak, 2);
    assert_eq!(source.syncs, 1, "no per-tick ES sync blocks");
    assert!(
        signals
            .calls
            .iter()
            .any(|(token, sig)| token == &new && *sig == libc::SIGSTOP)
    );
    assert!(
        signals
            .calls
            .iter()
            .any(|(token, sig)| token == &new && *sig == libc::SIGKILL)
    );
    assert!(
        signals
            .calls
            .iter()
            .zip(&signals.at_ns)
            .any(|((token, sig), at)| token == &new && *sig == libc::SIGSTOP && *at == 7_000_000),
        "the pending exec retry must be signalled on arrival, before a sweep"
    );
    assert!(
        signals
            .calls
            .iter()
            .zip(&signals.at_ns)
            .any(|((token, sig), at)| token == &child
                && *sig == libc::SIGKILL
                && *at == 61_000_000),
        "a newly reported child in the kill phase must be killed on arrival"
    );
}

#[test]
fn stop_tail_expiry_is_not_drained_and_never_rebegins() {
    use ukai_jail::platform::macos::{
        custody::{Custodian, StopNotDrainedReason, StopResult},
        es,
        guardian::stop::GuardianStop,
    };
    let mut token = [0u32; 8];
    token[5] = 100;
    token[7] = 2;
    let now = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut source = FakeCustody {
        now: now.clone(),
        events: [(0, stop_event(es::EVENT_FORK, 1, 1, token))].into(),
        syncs: 0,
        gap: false,
    };
    let mut custody = Custodian::new(1);
    custody.expect_root(100);
    let (out, _) = GuardianStop::new(custody, None).run_with_io(
        0,
        &mut source,
        &mut FakeClock(now),
        &mut FakeSignals::default(),
    );
    assert!(matches!(
        out.result,
        StopResult::NotDrained {
            reason: StopNotDrainedReason::Budget,
            elapsed_ns: 65_000_000_000,
            ..
        }
    ));
    assert_eq!(out.counts, [1, 0, 0]);
}

#[test]
fn release_without_deadline_leaves_watchdog_unarmed() {
    use ukai_jail::platform::macos::guardian::frames::*;
    let frame = decode_frame(&encode_release_without_deadline())
        .unwrap()
        .unwrap();
    assert_eq!(frame, Frame::ReleaseDeadline(NO_DEADLINE));
    assert_eq!(wall_deadline(NO_DEADLINE), None);
    assert_eq!(wall_deadline(12_000), Some(12_000));
}

#[test]
fn shim_mapping_and_late_sync_wakes_use_sdk_typed_fakes() {
    let temp = common::private_tempdir();
    let executable = temp.path().join("shim-tests");
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/platform/macos/es/shim_tests.c");
    let output = Command::new("clang")
        .args([
            "-fblocks",
            "-std=c11",
            "-Werror",
            "-Wno-deprecated-declarations",
            "-DUKAI_SYNC_REUSE_TEST",
        ])
        .arg(source)
        .args(["-lEndpointSecurity", "-o"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for test in ["mapping", "sync", "invalid-version", "overflow", "guard"] {
        assert!(
            Command::new(&executable)
                .arg(test)
                .status()
                .unwrap()
                .success()
        );
    }
}

#[test]
fn framing_rejects_zero_over_limit_truncation_and_poisoned_streams() {
    use ukai_jail::platform::macos::guardian::frames::*;
    for length in [0, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
        let mut reader = FrameReader::default();
        let bytes = length.to_le_bytes();
        for byte in &bytes[..3] {
            assert!(matches!(reader.read(&[*byte], false), Feed::Frames(f) if f.is_empty()));
        }
        assert!(matches!(reader.read(&bytes[3..], false), Feed::Frames(f) if f[0].is_err()));
        let payload = encode_release_deadline(100);
        let mut wire = (payload.len() as u32).to_le_bytes().to_vec();
        wire.extend(payload);
        assert!(matches!(reader.read(&wire, false), Feed::Frames(f) if f[0].is_err()));
    }
    let mut reader = FrameReader::default();
    reader.read(&[12, 0], false);
    assert!(matches!(reader.read(&[], true), Feed::Frames(f) if f[0].is_err()));
    let mut writer = FrameWriter::default();
    assert!(writer.queue(vec![0; MAX_FRAME_BYTES + 1]).is_err());
    assert!(!writer.pending());
}

#[test]
fn guardian_record_reaches_b_even_when_persistent_write_fails() {
    use ukai_jail::platform::macos::{
        custody::{StopNotDrainedReason, StopResult},
        guardian::record,
    };
    struct FullDisk;
    impl std::io::Write for FullDisk {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let record = record::from_stop_result(
        &StopResult::NotDrained {
            reason: StopNotDrainedReason::Budget,
            elapsed_ns: 65_000_000_000,
            sweeps: 10,
            signalled: 10,
        },
        record::StopFacts {
            counts: [1, 1, 0],
            guard_denials: 0,
            started_at: 0,
            ended_at: 65_000_000_000,
            members_peak: 1,
            guard_armed: false,
        },
        [0; 8],
        [0; 8],
        String::new(),
    );
    let mut b = Vec::new();
    assert_eq!(
        record::deliver(&record, &mut FullDisk, &mut b)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOSPC)
    );
    let length = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    assert_eq!(length + 4, b.len());
    assert_eq!(&b[4..11], b"record ");
    let json: serde_json::Value = serde_json::from_slice(&b[11..]).unwrap();
    assert_eq!(json["drained"], false);
    assert_eq!(json["reason"], "budget");
    let mut file = Vec::new();
    let mut pipe = Vec::new();
    record::deliver(&record, &mut file, &mut pipe).unwrap();
    assert_eq!(file, pipe[11..]);
}

#[test]
fn darwin_target_build_compiles_shims_with_linux_host_cfg() {
    use std::os::unix::fs::PermissionsExt;
    let temp = common::private_tempdir();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Compile the real build script with its HOST-only cfgs resolved as on
    // Linux. This exercises the otherwise unreachable host branch on this
    // Mac; compiler/archiver stand-ins record actions, without a cross SDK.
    let script = std::fs::read_to_string(manifest.join("build.rs"))
        .unwrap()
        .replace(
            "#[cfg(not(target_os = \"macos\"))]",
            "#[cfg(custody_linux_host)]",
        )
        .replace(
            "#[cfg(target_os = \"macos\")]",
            "#[cfg(not(custody_linux_host))]",
        )
        .replace(
            "#[path = \"src/build_provenance.rs\"]",
            &format!("#[path = {:?}]", manifest.join("src/build_provenance.rs")),
        );
    let source = temp.path().join("build_probe.rs");
    std::fs::write(&source, script).unwrap();
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let sha2 = std::fs::read_dir(&deps)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name().is_some_and(|n| {
                n.to_string_lossy().starts_with("libsha2-")
                    && n.to_string_lossy().ends_with(".rlib")
            })
        })
        .unwrap();
    let executable = temp.path().join("build-probe");
    let built = Command::new("rustc")
        .args([
            "--edition=2024",
            "--cfg",
            "custody_linux_host",
            "--crate-name",
            "build_probe",
        ])
        .arg(&source)
        .arg("--extern")
        .arg(format!("sha2={}", sha2.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let driver = temp.path().join("c-driver");
    std::fs::write(
        &driver,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$UKAI_BUILD_PROBE_LOG\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&driver, std::fs::Permissions::from_mode(0o700)).unwrap();
    let log = temp.path().join("actions");
    let output = Command::new(&executable)
        .current_dir(manifest)
        .env("CARGO_MANIFEST_DIR", manifest)
        .env("CARGO_CFG_TARGET_OS", "macos")
        .env("HOST", "x86_64-unknown-linux-gnu")
        .env("TARGET", "aarch64-apple-darwin")
        .env("OUT_DIR", temp.path())
        .env("OPT_LEVEL", "0")
        .env("SDKROOT", temp.path())
        .env("CC_aarch64_apple_darwin", &driver)
        .env("AR_aarch64_apple_darwin", &driver)
        .env("UKAI_BUILD_PROBE_LOG", &log)
        .env_remove("UKAI_BUILD_REVISION")
        .env_remove("UKAI_BUILD_DIRTY")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actions = std::fs::read_to_string(log).unwrap_or_default();
    assert_eq!(
        actions
            .lines()
            .filter(|line| line.contains("-target aarch64-apple-darwin"))
            .count(),
        2,
        "both shims must compile on a non-Darwin host: {actions}"
    );
    assert!(
        actions.lines().any(|line| line.starts_with("crs ")),
        "the shims must be archived: {actions}"
    );
}

#[test]
fn a_gap_keeps_stopping_known_members_without_ever_proving_a_drain() {
    use ukai_jail::platform::macos::{
        custody::{Custodian, StopNotDrainedReason, StopResult},
        es,
        guardian::stop::GuardianStop,
    };
    let mut token = [0u32; 8];
    token[5] = 100;
    token[7] = 2;
    let now = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut source = FakeCustody {
        now: now.clone(),
        events: [
            (0, stop_event(es::EVENT_FORK, 1, 1, token)),
            (41_000_000, stop_event(es::EVENT_EXIT, 2, 1, token)),
        ]
        .into(),
        syncs: 0,
        gap: true,
    };
    let mut custody = Custodian::new(1);
    custody.expect_root(100);
    let mut signals = FakeSignals::default();
    let (out, _) = GuardianStop::new(custody, None).run_with_io(
        0,
        &mut source,
        &mut FakeClock(now),
        &mut signals,
    );
    assert!(matches!(
        out.result,
        StopResult::NotDrained {
            reason: StopNotDrainedReason::Gap,
            elapsed_ns: 41_000_000,
            ..
        }
    ));
    assert!(
        signals
            .calls
            .iter()
            .any(|(_, signal)| *signal == libc::SIGKILL)
    );
    assert_eq!(out.counts, [1, 0, 1]);
}
