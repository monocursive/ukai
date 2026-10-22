//! J16 supervisor integration (jail-macos.md §4.3–§4.6, §4.8, §4.11): the
//! refusal end-to-end (K98), the launcher and guardian mode grammars, the
//! B-frame codec and the RunEvent mapping.
//!
//! The live custody rows (K87–K97) need the Endpoint Security entitlement
//! and run in the dev VM (docs/benchmarks/jail/macos-development.md); on
//! this Mac the custody client refuses with `ERR_NOT_ENTITLED`, which is
//! exactly what the first test asserts. The rest of the file is gated to
//! macOS like the platform itself.
#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::{Command, Output};

mod common;

use ukai_jail::platform::macos::boundary::{BFrame, decode_b_frames, map_sequence};
use ukai_jail::platform::macos::custody_io::Token;
use ukai_jail::platform::macos::es::{self, EsEvent};
use ukai_jail::platform::macos::launcher::is_blocked_report;

/// A private state root, a private config directory and an empty workspace
/// (the harness of `macos_refusal.rs`, verbatim in shape).
struct Harness {
    temp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

impl Harness {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = common::private_tempdir();
        let make = |name: &str, mode: u32| {
            let path = temp.path().join(name);
            std::fs::create_dir(&path).expect("a directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
            path
        };
        Harness {
            data: make("data", 0o700),
            config: make("config", 0o700),
            work: make("work", 0o755),
            temp,
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.path())
            .env("UKAI_DATA_DIR", &self.data)
            .env("UKAI_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .args(arguments)
            .output()
            .expect("the binary runs")
    }

    fn run_internal(&self, arguments: &[&str]) -> Output {
        let mut all = vec![env!("CARGO_BIN_EXE_ukai-jail").to_owned()];
        all.extend(arguments.iter().map(ToString::to_string));
        let strings: Vec<String> = all;
        let refs: Vec<&str> = strings.iter().map(String::as_str).collect();
        self.run(&refs[1..])
    }

    fn receipts(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(self.data.join("attempts")) {
            Ok(entries) => entries,
            Err(_) => return out,
        };
        for entry in entries.flatten() {
            let path = entry.path().join("jail.json");
            if let Ok(text) = std::fs::read_to_string(path)
                && let Ok(value) = serde_json::from_str(&text)
            {
                out.push(value);
            }
        }
        out.sort_by(|a, b| {
            let key = |value: &serde_json::Value| {
                value["attempt_id"].as_str().unwrap_or_default().to_owned()
            };
            key(a).cmp(&key(b))
        });
        out
    }
}

// ---------------------------------------------------------------------------
// K98: the refusal end-to-end (no entitlement on this Mac)
// ---------------------------------------------------------------------------

#[test]
fn k98_run_refuses_naming_err_not_entitled_and_unsupported() {
    let harness = Harness::new();
    let marker = harness.work.join("marker");
    let output = harness.run(&[
        "run",
        "--profile",
        "none",
        "--",
        "/usr/bin/touch",
        marker.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(125),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "nothing ran: the boundary was refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The requirements probe of §4.10 refuses first on this Mac (K98): the
    // tree_termination row answers unavailable, naming the ES result the
    // custody client creation got. The `unsupported`-remediated refusal of
    // §4.3 step 1 itself is exercised at the platform seam in
    // `boundary::prepare`'s own test.
    assert!(
        stderr.contains("es_not_entitled"),
        "the refusal names the ES result (§4.3 step 1): {stderr}"
    );
    let receipts = harness.receipts();
    assert_eq!(receipts.len(), 1, "exactly one attempt was recorded");
    let receipt = &receipts[0];
    assert_eq!(receipt["phase"], serde_json::json!("refused"));
    let errors = receipt["errors"].as_array().expect("errors[]");
    let refusal = &errors[errors.len() - 1];
    assert_eq!(refusal["code"], serde_json::json!("missing_capability"));
    assert!(
        refusal["message"]
            .as_str()
            .is_some_and(|message| message.contains("es_not_entitled")),
        "the receipt names the ES result: {refusal}"
    );
    // The refusal happened at client S, before any resource existed.
    assert_eq!(receipt["applied"]["filesystem"], serde_json::Value::Null);
    assert_eq!(receipt["lifetime"]["tree_empty"], serde_json::Value::Null);
    assert_eq!(receipt["outcome"]["kind"], serde_json::json!("refused"));
}

#[test]
fn k98_tool_refuses_at_the_requirements_before_any_boundary() {
    let harness = Harness::new();
    let output = harness.run(&["run", "--", "/usr/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported_platform") || stderr.contains("missing_capability"),
        "`tool`'s boundary requirement refuses first: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The launcher and guardian mode grammars
// ---------------------------------------------------------------------------

#[test]
fn the_launcher_mode_refuses_a_bad_grammar_with_usage() {
    let harness = Harness::new();
    let output = harness.run_internal(&["__launch-macos", "--wat", "--", "x"]);
    assert_eq!(output.status.code(), Some(125), "EXIT_USAGE");
    assert!(String::from_utf8_lossy(&output.stderr).contains("__launch-macos"));
}

#[test]
fn the_launcher_mode_refuses_closed_descriptors_with_usage() {
    let harness = Harness::new();
    // Descriptors 98 and 99 are closed in a fresh process: F_GETFD fails.
    let output = harness.run_internal(&[
        "__launch-macos",
        "--release-fd",
        "98",
        "--error-fd",
        "99",
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(125), "EXIT_USAGE");
}

#[test]
fn the_guardian_mode_refuses_fast_on_an_unreadable_launch_block() {
    let harness = Harness::new();
    // A record path in the private temp dir; descriptors 30..35 are closed,
    // so the guardian's first read fails and it exits naming the step.
    let record = harness.temp.path().join("guardian-record.json");
    let output = harness.run_internal(&[
        "__guardian",
        record.to_str().expect("a UTF-8 path"),
        "30",
        "31",
        "32",
        "33",
        "34",
    ]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "the guardian refuses; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("ukai-jail: guardian:"),
        "one line naming the failing step (§4.3 step 3): {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The codecs, without a client
// ---------------------------------------------------------------------------

#[test]
fn the_blocked_report_is_the_eight_zero_bytes_and_only_that() {
    assert!(is_blocked_report(&[0u8; 8]));
    assert!(!is_blocked_report(&[0, 0, 0, 0]));
    // A real exec failure always carries a nonzero errno word.
    let mut report = [0u8; 8];
    report[..4].copy_from_slice(&libc::ENOENT.to_le_bytes());
    report[4..].copy_from_slice(&1u32.to_le_bytes());
    assert!(!is_blocked_report(&report));
    let (errno, detail) = ukai_jail::platform::macos::launcher::exec_failure_parts(&report);
    assert_eq!(errno, "ENOENT");
    assert_eq!(
        detail,
        Some(ukai_jail::platform::ExecFailureDetail::InterpreterMissing)
    );
}

#[test]
fn the_b_frames_decode_and_refuse_like_the_guardian_writes_them() {
    let framed = |payload: &[u8]| {
        let mut out = (payload.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&framed(b"ready"));
    bytes.extend_from_slice(&framed(b"token-seen"));
    let mut record_payload = b"record ".to_vec();
    record_payload.extend_from_slice(br#"{"drained":true}"#);
    let record = framed(&record_payload);
    bytes.extend_from_slice(&record);
    assert_eq!(
        decode_b_frames(&[&bytes]).expect("decodes"),
        vec![
            BFrame::Ready,
            BFrame::TokenSeen,
            BFrame::Record(br#"{"drained":true}"#.to_vec()),
        ]
    );
    // A frame the B grammar does not define stops the run, never guesses.
    let unknown = framed(b"surprise");
    assert!(decode_b_frames(&[&unknown]).is_err());
}

// ---------------------------------------------------------------------------
// The RunEvent mapping from synthetic custody sequences
// ---------------------------------------------------------------------------

fn token(pid: u32) -> Token {
    let mut token = [0u32; 8];
    token[6] = pid;
    token[7] = 1;
    token
}

fn poll(event: EsEvent, global: u64, seq: u64, kind: u32) -> es::EsPoll {
    es::EsPoll {
        event,
        kind,
        global_seq: global,
        seq,
    }
}

#[test]
fn the_mapping_carries_exec_exit_and_signal() {
    let launcher = token(4242);
    // The target is the launcher's process after its exec: same pid, new
    // audit token (the pid version moved).
    let mut target = token(4242);
    target[7] = 2;
    let exited = vec![
        poll(EsEvent::Fork { token: launcher }, 1, 1, es::EVENT_FORK),
        poll(EsEvent::Exec { token: target }, 2, 2, es::EVENT_EXEC),
        poll(
            EsEvent::Exit {
                token: target,
                status: 0,
            },
            3,
            3,
            es::EVENT_EXIT,
        ),
    ];
    assert_eq!(
        map_sequence(&exited, &launcher),
        vec![
            ukai_jail::platform::RunEvent::ExecConfirmed,
            ukai_jail::platform::RunEvent::TargetExited { code: 0 },
        ]
    );
    let signaled = vec![
        poll(EsEvent::Fork { token: launcher }, 1, 1, es::EVENT_FORK),
        poll(EsEvent::Exec { token: target }, 2, 2, es::EVENT_EXEC),
        poll(
            EsEvent::Exit {
                token: target,
                status: 9,
            },
            3,
            3,
            es::EVENT_EXIT,
        ),
    ];
    assert_eq!(
        map_sequence(&signaled, &launcher),
        vec![
            ukai_jail::platform::RunEvent::ExecConfirmed,
            ukai_jail::platform::RunEvent::TargetSignaled { signal: 9 },
        ]
    );
}

#[test]
fn the_mapping_confirms_nothing_without_the_exec() {
    let launcher = token(20);
    let events = vec![poll(
        EsEvent::Exit {
            token: launcher,
            status: 1,
        },
        1,
        1,
        es::EVENT_EXIT,
    )];
    assert!(
        map_sequence(&events, &launcher).is_empty(),
        "an exec that never happened is no ExecConfirmed and no outcome"
    );
}
