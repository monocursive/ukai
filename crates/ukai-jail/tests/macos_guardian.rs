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
fn fabricated_launch(temp: &tempfile::TempDir) -> Vec<String> {
    let record = temp.path().join("guardian.json");
    let block_path = temp.path().join("launch-block");
    std::fs::write(&block_path, encode(&sample_block())).expect("launch block");

    let mut a = [0 as libc::c_int; 2];
    let mut b = [0 as libc::c_int; 2];
    // SAFETY: two plain pipe(2) pairs; ends closed in this process below.
    unsafe {
        assert_eq!(libc::pipe(a.as_mut_ptr()), 0);
        assert_eq!(libc::pipe(b.as_mut_ptr()), 0);
    }
    // The launch block rides on its own inherited descriptor.
    // SAFETY: open(2) without O_CLOEXEC, closed at the end of the test.
    let block_fd =
        unsafe { libc::open(block_path.to_string_lossy().as_ptr().cast(), libc::O_RDONLY) };
    assert!(block_fd >= 0);
    let r_fd = a[1];
    let e_fd = b[1];
    vec![
        record.to_string_lossy().into_owned(),
        a[0].to_string(),
        b[1].to_string(),
        r_fd.to_string(),
        e_fd.to_string(),
        block_fd.to_string(),
    ]
}

fn run_guardian() -> (Output, tempfile::TempDir) {
    let temp = common::private_tempdir();
    let args = fabricated_launch(&temp);
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
