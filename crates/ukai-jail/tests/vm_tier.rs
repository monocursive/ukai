//! J18 (jail-macos.md §6, §9.3): the VM tier's portable stand-in tests —
//! the policy key and its refusals, the CLI grammar, the canonical-bytes
//! stability, the transport record, and the attempt protocol against a
//! scripted stand-in server (the Rust form of `vm/test_attempt.py`).
//!
//! No VM boots here. Everything that needs the live guest is the preview
//! fault matrix's (K108–K110), and the README records what stays untested.
//!
//! The wire modules are included by path, exactly as the `ukai-vm` binary
//! includes them: both ends of every socket must agree on one definition,
//! and these tests must run on every host the jail builds for.

// The real backend uses every item; these tests exercise the stand-in
// paths, so unused items here are expected.
#[allow(dead_code)]
#[path = "../src/platform/macos/vm/control.rs"]
mod control;
#[allow(dead_code)]
#[path = "../src/platform/macos/vm/image.rs"]
mod image;
#[allow(dead_code)]
#[path = "../src/platform/macos/vm/protocol.rs"]
mod protocol;
#[allow(dead_code)]
#[path = "../src/platform/macos/vm/record.rs"]
mod record;

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};

mod common;

use protocol::{FromControl, FromVm, ToControl, ToVm};
use record::TransportRecord;

// ---------------------------------------------------------------------------
// The policy key: derivation, refusal, digest stability (§6, K112)
// ---------------------------------------------------------------------------

fn resolved(profile: ukai_jail::policy::ProfileName) -> ukai_jail::policy::Resolved {
    let inputs = ukai_jail::policy::ResolveInputs {
        platform: ukai_jail::records::Os::Linux,
        base_profile: profile,
        policy_name: profile.as_str().to_owned(),
        baseline: ukai_jail::profiles::baseline(profile, ukai_jail::records::Os::Linux, &|_| None),
        workspace: b"/work".to_vec(),
        scratch: ukai_jail::policy::ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: Vec::new(),
    };
    ukai_jail::policy::resolve(&inputs).expect("the built-in baseline resolves")
}

fn with_kernel_bound(resolved: &ukai_jail::policy::Resolved) -> ukai_jail::policy::Resolved {
    let mut narrowed = resolved.clone();
    narrowed.snapshot.lifetime_boundary = Some(ukai_jail::policy::LifetimeBoundary::KernelBound);
    narrowed.digest = narrowed.snapshot.digest().expect("digests");
    narrowed.requirements = ukai_jail::capability::requirements(&narrowed.snapshot);
    narrowed
}

#[test]
fn the_kernel_bound_key_changes_exactly_the_digest_and_the_requirements() {
    use ukai_jail::capability::Requirement;
    let plain = resolved(ukai_jail::policy::ProfileName::Tool);
    let narrowed = with_kernel_bound(&plain);
    assert!(
        !plain
            .requirements
            .contains(&Requirement::OwnerLossTermination)
    );
    assert!(
        narrowed
            .requirements
            .contains(&Requirement::OwnerLossTermination)
    );
    assert_ne!(
        plain.digest, narrowed.digest,
        "a snapshot that sets the key digests it"
    );
    // A snapshot without the key keeps its bytes and digest: the field is
    // absent from the canonical form, not null.
    assert_eq!(plain.digest, plain.snapshot.digest().expect("digests"));
    let canonical = plain.snapshot.canonical_bytes().expect("canonical");
    assert!(
        !windows_like_contains(&canonical, b"lifetime_boundary"),
        "the canonical bytes of a snapshot without the key never name it: {}",
        String::from_utf8_lossy(&canonical)
    );
    let narrowed_bytes = narrowed.snapshot.canonical_bytes().expect("canonical");
    assert!(
        windows_like_contains(&narrowed_bytes, b"\"lifetime_boundary\":\"kernel-bound\""),
        "the canonical bytes of a snapshot with the key carry it: {}",
        String::from_utf8_lossy(&narrowed_bytes)
    );
}

fn windows_like_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn the_wire_spelling_of_the_key_is_the_flags_value() {
    assert_eq!(
        ukai_jail::policy::LifetimeBoundary::KernelBound.as_str(),
        "kernel-bound"
    );
    assert_eq!(
        ukai_jail::policy::LifetimeBoundary::parse("kernel-bound"),
        Some(ukai_jail::policy::LifetimeBoundary::KernelBound)
    );
    assert_eq!(
        ukai_jail::policy::LifetimeBoundary::parse("best-effort"),
        None
    );
}

/// K112's Linux leg: `none`'s boundary is the supervisor's own cgroup
/// (`supervisor_cgroup`), so the key is a narrowing it refuses, with the
/// reason every other unapplied restriction carries. The mapping is the
/// Linux lane's, so the test runs there.
#[test]
#[cfg(target_os = "linux")]
fn the_kernel_bound_key_is_a_narrowing_none_refuses() {
    use ukai_jail::capability::Requirement;
    let mut resolved = resolved(ukai_jail::policy::ProfileName::None);
    resolved.snapshot.lifetime_boundary = Some(ukai_jail::policy::LifetimeBoundary::KernelBound);
    resolved.requirements = ukai_jail::capability::requirements(&resolved.snapshot);
    assert!(
        resolved
            .requirements
            .contains(&Requirement::OwnerLossTermination)
    );
    let results: Vec<ukai_jail::platform::linux::probe::ProbeResult> =
        ukai_jail::platform::linux::probe::PROBE_NAMES
            .iter()
            .map(|&name| ukai_jail::platform::linux::probe::ProbeResult {
                name,
                status: ukai_jail::platform::linux::probe::ProbeStatus::Available,
                mechanism: "test",
                reason_code: "ok",
                evidence: String::new(),
            })
            .collect();
    let measured_at = ukai_jail::records::rfc3339_utc(std::time::SystemTime::now());
    let capability = ukai_jail::platform::linux::uncontained::capability_for(
        ukai_jail::policy::ProfileName::None,
        Requirement::OwnerLossTermination,
        &results,
        &measured_at,
    )
    .expect("the mapping answers the requirement");
    assert!(!capability.satisfies(), "{capability:?}");
    assert_eq!(
        capability.reason_code.as_deref(),
        Some(ukai_jail::capability::REASON_NOT_APPLIED_BY_NONE)
    );
}

// ---------------------------------------------------------------------------
// The CLI grammar: the binary, on a private state root
// ---------------------------------------------------------------------------

struct Harness {
    #[allow(dead_code)]
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
}

#[test]
#[cfg(target_os = "macos")]
fn the_lifetime_flag_and_vm_verb_answer_the_grammar() {
    let harness = Harness::new();
    // `vm stop` with no serving ukai-vm reports and exits 0 (§6.1).
    let output = harness.run(&["vm", "stop"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no VM is running"), "{stderr}");
    // An unknown vm subcommand is a usage error.
    let output = harness.run(&["vm", "start"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
#[cfg(not(target_os = "macos"))]
fn the_vm_verb_refuses_off_macos_like_the_flag() {
    let harness = Harness::new();
    let output = harness.run(&["vm", "stop"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("macOS"), "{stderr}");
}

#[test]
fn a_lifetime_value_other_than_kernel_bound_is_a_usage_error() {
    let harness = Harness::new();
    for value in ["best-effort", "kernel_bound", ""] {
        let output = harness.run(&["run", "--lifetime", value, "--", "/bin/true"]);
        assert_eq!(output.status.code(), Some(2), "{value}: {output:?}");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn the_native_platform_answers_the_kernel_bound_requirement_with_the_vm_reason() {
    // The refusal's words come from the reason code the platform answers
    // with. Native macOS cannot probe a kernel-owned tree end; its answer
    // for `owner_loss_termination` is the one `--vm` provides (§6), and the
    // supervisor's match on that reason is what names `--vm` to the
    // operator.
    use ukai_jail::capability::Requirement;
    use ukai_jail::platform::Platform as _;
    let mut plan = plan_for(ukai_jail::policy::ProfileName::Tool);
    plan.requirements.push(Requirement::OwnerLossTermination);
    let row = ukai_jail::platform::macos::MacosPlatform
        .probe(&plan)
        .into_iter()
        .find(|row| row.name == "owner_loss_termination")
        .expect("the platform answers the requirement");
    assert!(!row.satisfies());
    assert_eq!(
        row.reason_code.as_deref(),
        Some(ukai_jail::capability::REASON_OWNER_LOSS_REQUIRES_VM),
        "{row:?}"
    );
}

#[cfg(target_os = "macos")]
fn plan_for(profile: ukai_jail::policy::ProfileName) -> ukai_jail::platform::PlanRequest {
    let mut resolved = resolved(profile);
    resolved.snapshot.lifetime_boundary = Some(ukai_jail::policy::LifetimeBoundary::KernelBound);
    resolved.requirements = ukai_jail::capability::requirements(&resolved.snapshot);
    ukai_jail::platform::PlanRequest {
        snapshot: resolved.snapshot,
        requirements: resolved.requirements,
    }
}

#[test]
#[cfg(target_os = "macos")]
fn a_kernel_bound_run_without_its_boundary_refuses_before_any_process() {
    // On this host the native probes answer first (`tree_termination` needs
    // the ES entitlement), so the run refuses with that fact; what the test
    // pins is that nothing executes and the refusal is the probing stage's,
    // never a silently weakened policy (§2: a missing guarantee refuses).
    let harness = Harness::new();
    let output = harness.run(&[
        "run",
        "--lifetime",
        "kernel-bound",
        "--terminal",
        "detach",
        "--",
        "/bin/true",
    ]);
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing_capability"), "{stderr}");
    assert!(
        !stderr.contains("exited") && !stderr.contains("settled"),
        "the target never ran: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// The transport record (K111)
// ---------------------------------------------------------------------------

#[test]
fn the_transport_record_carries_the_recorded_facts() {
    let record = TransportRecord::new(
        "att_00000000-0000-4000-8000-000000000001",
        "vm-42",
        "6.14.0",
        record::ImageDigests {
            disk_sha256: "d".repeat(64),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
        },
        1024,
        "/data/vm/control.sock",
        "/data/vm/attempt.sock",
        "2026-10-22T12:00:00Z",
        1.5,
        "a".repeat(64),
    );
    assert_eq!(record.schema, record::SCHEMA_TRANSPORT);
    let value = serde_json::to_value(&record).expect("serializes");
    for name in [
        "schema",
        "attempt_id",
        "boot_id",
        "guest_kernel",
        "image",
        "vsock_port",
        "control_socket",
        "attempt_socket",
        "host_wall_started",
        "elapsed_seconds",
        "guest_receipt_sha256",
    ] {
        assert!(
            value.get(name).is_some(),
            "{name} is on the record: {value}"
        );
    }
    assert_eq!(
        value["image"]["disk_sha256"],
        "d".repeat(64),
        "the image digests are the record's own group"
    );
}

// ---------------------------------------------------------------------------
// The attempt protocol, against a scripted stand-in ukai-vm
// ---------------------------------------------------------------------------

/// Answers one `stop` control request, the way the service would.
fn control_stub(reply: &'static str) -> (PathBuf, std::thread::JoinHandle<()>) {
    let dir = common::private_tempdir();
    let path = dir.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("binds");
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 256];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(reply.as_bytes());
        }
        drop(dir);
    });
    (path, handle)
}

#[test]
fn a_stop_request_gets_the_service_reply_and_absence_is_not_an_error() {
    let (path, handle) =
        control_stub("{\"event\":\"stopping\",\"schema\":\"ukai.jail.vm-control/1\"}\n");
    let reply = control::control_round_trip(&path, ToControl::Stop)
        .map_err(|error| error.to_string())
        .map(|reply| {
            assert_eq!(
                reply,
                FromControl::Stopping {
                    schema: protocol::SCHEMA_CONTROL.to_owned(),
                }
            )
        });
    reply.expect("the stub answers");
    handle.join().expect("the stub ends");

    // Absence: a stale socket path is "no VM is running", not a failure —
    // the wording `vm stop` exits 0 on.
    let absent = common::private_tempdir();
    let error = control::control_round_trip(&absent.path().join("control.sock"), ToControl::Status)
        .expect_err("nothing listens");
    assert!(matches!(error, control::ControlError::Absent), "{error}");
}

#[test]
fn an_attempt_session_frames_both_ways_against_the_stand_in() {
    let dir = common::private_tempdir();
    let path = dir.path().join("attempt.sock");
    let listener = UnixListener::bind(&path).expect("binds");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if stream.read(&mut byte).expect("reads") == 0 || byte[0] == b'\n' {
                break;
            }
            buffer.push(byte[0]);
        }
        // The host's first frame is the staging request.
        let staged = protocol::decode::<ToVm>(&buffer).expect("the host spoke the protocol");
        let protocol::ToVm::Prepare {
            attempt_id: _,
            profile,
            wall_seconds,
            argv,
            secrets,
        } = staged
        else {
            panic!("the host opened with {staged:?}");
        };
        assert_eq!(profile, "tool");
        assert_eq!(wall_seconds, 30);
        assert_eq!(argv.len(), 1);
        assert_eq!(secrets.len(), 1, "the ephemeral credential crossed");
        let mut reply = |frame: &FromVm| {
            let mut line = serde_json::to_vec(frame).expect("encodes");
            line.push(b'\n');
            stream.write_all(&line).expect("writes");
        };
        reply(&FromVm::Ready {
            schema: protocol::SCHEMA_ATTEMPT.to_owned(),
            boot_id: "vm-7".to_owned(),
            disk_sha256: "d".repeat(64),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
            vsock_port: 1024,
        });
        reply(&FromVm::Prepared {
            kernel: "6.14.0".to_owned(),
        });
    });

    let mut connection = control::AttemptConnection::connect(&path).expect("connects");
    connection
        .send(&ToVm::Prepare {
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            profile: "tool".to_owned(),
            wall_seconds: 30,
            argv: vec![protocol::encode_data(b"/bin/true")],
            secrets: vec![protocol::SecretEntry {
                id: "token".to_owned(),
                data: protocol::encode_data(b"s3cret"),
            }],
        })
        .expect("sends");
    let ready = connection.next_frame().expect("reads").expect("a frame");
    assert!(matches!(ready, FromVm::Ready { .. }));
    let prepared = connection.next_frame().expect("reads").expect("a frame");
    assert!(matches!(prepared, FromVm::Prepared { .. }));
    server.join().expect("the stub ends");
}

#[test]
fn the_transport_line_renders_one_escaped_line() {
    let mut facts = TransportRecord::new(
        "att_00000000-0000-4000-8000-000000000001",
        "boot\nnewline",
        "6.14.0",
        record::ImageDigests {
            disk_sha256: "0123456789abcdef0123456789abcdef".to_owned(),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
        },
        1024,
        "/data/vm/control.sock",
        "/data/vm/attempt.sock",
        "2026-10-22T12:00:00Z",
        1.0,
        "a".repeat(64),
    );
    facts.guest_receipt_sha256 = "f".repeat(64);
    let receipt = serde_json::json!({
        "platform": {"os": "linux"},
        "policy": {"name": "tool"},
        "lifetime": {"boundary": "pid_namespace"},
    });
    let line = record::transport_line(&receipt, &facts);
    assert!(
        line.starts_with("vm: guest linux tool boundary=pid_namespace"),
        "{line}"
    );
    assert!(line.contains("U+000A"), "control bytes are escaped: {line}");
    assert_eq!(line.lines().count(), 1);
}
