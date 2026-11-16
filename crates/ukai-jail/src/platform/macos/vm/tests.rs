use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use crate::policy::{
    Ceiling, Ceilings, Layer, LayerOrigin, PolicyDelta, ResolveInputs, ScratchRoot,
};
use crate::records::NativeString;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn binding() -> protocol::ReceiptBinding {
    protocol::ReceiptBinding {
        sampled_exposure_sha256: None,
        native_program: None,
        attempt_id: "host-attempt".into(),
        boot_id: "host-boot".into(),
        guest_attempt_id: "guest-attempt".into(),
        guest_boot_id: "guest-boot".into(),
        profile: "tool".into(),
        argv_digest: "sha256:argv".into(),
    }
}

/// The policy digest the stand-in attempts derive for their guest jail.
const GUEST_POLICY: &str = "sha256:guest-policy";

/// A complete offline guest receipt: every group the host verifies and
/// mirrors, in the guest jail's own shape.
fn receipt() -> Value {
    let class = |status: &str, source: &str, count: Option<u64>| serde_json::json!({"status": status, "sources": if source.is_empty() { vec![] } else { vec![source] }, "observed_count": count, "gaps": []});
    serde_json::json!({
        "schema": "ukai.jail.receipt/1", "attempt_id": "guest-attempt",
        "platform": {"os": "linux", "arch": "aarch64", "kernel": "Linux 7.0.0-38-generic"},
        "policy": {"name": "tool", "digest": GUEST_POLICY}, "argv_digest":"sha256:argv", "containment":"enforced",
        "child_protection":"enforced", "exec_observed":true, "state_cleanup":"complete", "errors":[],
        "outcome": {"kind": "exited", "code": 0, "signal": null, "cause": null, "error": null},
        "process":{"identity":{"value":{"boot_id":"guest-boot"}}},
        "lifetime":{"boundary":"pid_namespace","tree_empty":true,"integrity":"verified"},
        "applied":{
            "filesystem": null,
            "network":{"mode":"none","mechanism":"network-namespace","allowed_hosts":[]},
            "syscalls": {"mechanism": "seccomp-bpf", "digest": "sha256:filter"},
            "environment_names": ["LANG", "PATH", "TMPDIR"],
            "removed_environment_names": [],
            "limits": [
            {"key":"wall","requested":"30000","required":true,"applied":true,"mechanism":"timer","scope":"tree","hit":null},
            {"key":"pids","requested":"64","required":false,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null},
            {"key":"mem","requested":"536870912","required":false,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null},
            {"key":"swap","requested":"0","required":false,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null}
        ]},
        "observer": {"backend": "ptrace", "set": "linux-closed-v1", "attached": true,
            "sources": {"wrapper": "active", "audit": "active", "proxy": "unsupported"}, "gaps": []},
        "coverage": {
            "exec": class("active", "audit", Some(2)), "fs.write": class("active", "audit", Some(4)),
            "fs.deny": class("active", "audit", Some(1)), "net": class("active", "audit", Some(0)),
            "limits": class("active", "wrapper", Some(0)), "proxy.net": class("unsupported", "", None)
        }
    })
}

fn running() -> (VmRunning, UnixStream, tempfile::TempDir) {
    running_with(image::GuestNetwork::requested("none", [], []))
}

#[test]
fn vm_wall_expiry_still_reads_the_cancelled_attempts_eof() {
    let (mut run, mut peer, _root) = running();
    let expired = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        run.wait(Deadline { at: Some(expired) }),
        RunEvent::WallExpired
    ));
    run.request_stop(StopReason::WallExpiry);
    assert_eq!(
        peer.read(&mut [0]).unwrap(),
        0,
        "cancellation ends the lease"
    );
    drop(peer);
    assert!(
        matches!(
            run.wait(Deadline { at: Some(expired) }),
            RunEvent::Unknown { .. }
        ),
        "the supervisor keeps the original wall deadline after requesting stop"
    );
    assert!(run.failed);
    assert!(run.guest_facts().is_none());
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
}

#[test]
fn vm_wall_expiry_drains_a_delayed_receipt_without_relaxing_its_binding() {
    for valid_binding in [true, false] {
        let (mut run, mut peer, _root) = running();
        let expired = Instant::now() - Duration::from_secs(1);
        assert!(matches!(
            run.wait(Deadline { at: Some(expired) }),
            RunEvent::WallExpired
        ));
        let server = std::thread::spawn(move || {
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            let mut held_binding = binding();
            if !valid_binding {
                held_binding.attempt_id = "another-attempt".into();
            }
            let (sha256, data) = encoded(&with_outcome("signaled", None, Some(9)));
            // The result arrives after cancellation, not before the wall.
            std::thread::sleep(Duration::from_millis(20));
            for frame in [
                protocol::FromVm::BoundReceipt {
                    sha256,
                    data,
                    binding: held_binding,
                },
                done(137),
            ] {
                peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
            }
        });
        run.request_stop(StopReason::WallExpiry);
        let event = run.wait(Deadline { at: Some(expired) });
        server.join().unwrap();
        if valid_binding {
            assert!(matches!(event, RunEvent::TargetSignaled { signal: 9 }));
            assert!(run.verified());
            assert!(run.guest_facts().is_some());
            assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, Some(true));
        } else {
            assert!(matches!(event, RunEvent::Unknown { .. }));
            assert!(run.failed);
            assert!(run.guest_facts().is_none());
            assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
        }
    }
}

#[test]
fn vm_stop_has_one_bounded_drain_even_for_a_silent_peer_and_repeated_requests() {
    let (mut run, mut peer, _root) = running();
    run.request_stop(StopReason::WallExpiry);
    let deadline = run.termination_deadline.unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    for reason in [
        StopReason::WallExpiry,
        StopReason::EvidenceLoss,
        StopReason::StdioFailure,
    ] {
        run.request_stop(reason);
        assert_eq!(run.termination_deadline, Some(deadline));
    }
    let event = run.wait(Deadline { at: None });
    assert!(matches!(event, RunEvent::Unknown { reason } if reason.contains("termination budget")));
    assert!(Instant::now() < deadline + Duration::from_secs(1));
    assert!(run.failed);
    assert!(run.guest_facts().is_none());
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
}

#[test]
fn vm_tree_wait_does_not_extend_its_callers_budget_after_stop() {
    let (mut run, _peer, _root) = running();
    run.request_stop(StopReason::WallExpiry);
    let start = Instant::now();
    let tree = run.wait_tree(Duration::ZERO);
    assert!(start.elapsed() < Duration::from_millis(100));
    assert_eq!(tree.tree_empty, None);
    assert_eq!(tree.integrity, Integrity::Lost);
}

#[test]
fn vm_wall_can_hit_once_during_an_earlier_stop_without_extending_it() {
    let (mut run, peer, _root) = running();
    run.request_stop(StopReason::EvidenceLoss);
    let stop_deadline = run.termination_deadline;
    let wall = Instant::now() + Duration::from_millis(20);
    assert!(matches!(
        run.wait(Deadline { at: Some(wall) }),
        RunEvent::WallExpired
    ));
    run.request_stop(StopReason::WallExpiry);
    assert_eq!(run.termination_deadline, stop_deadline);
    drop(peer);
    assert!(matches!(
        run.wait(Deadline { at: Some(wall) }),
        RunEvent::Unknown { .. }
    ));
    assert!(run.failed);
}

#[test]
fn vm_an_earlier_wall_is_reported_even_if_the_host_resumes_after_both_deadlines() {
    for same_deadline in [false, true] {
        let (mut run, _peer, _root) = running();
        run.request_stop(StopReason::EvidenceLoss);
        let stop = Instant::now() - Duration::from_secs(1);
        // Model a scheduling pause without making this test wait for one.
        run.termination_deadline = Some(stop);
        let wall = if same_deadline {
            stop
        } else {
            stop - Duration::from_secs(1)
        };
        assert!(matches!(
            run.wait(Deadline { at: Some(wall) }),
            RunEvent::WallExpired
        ));
        run.request_stop(StopReason::WallExpiry);
        assert_eq!(run.termination_deadline, Some(stop));
        assert!(matches!(
            run.wait(Deadline { at: Some(wall) }),
            RunEvent::Unknown { .. }
        ));
        assert!(run.failed);
        assert!(run.guest_facts().is_none());
    }
}

fn staged_test_source(root: &Path) -> (PathBuf, Arc<crate::vault::Secret>) {
    let source = root.join("private-source");
    std::fs::write(&source, b"source-token").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let source = source.canonicalize().unwrap();
    let secret = crate::vault::Secret::from_source(
        "token".to_owned(),
        crate::vault::Policy {
            hosts: vec!["https://example.com".to_owned()],
            ..Default::default()
        },
        source.as_os_str().as_encoded_bytes().to_vec(),
        Vec::new(),
    )
    .unwrap();
    (source, Arc::new(secret))
}

#[test]
fn vm_staged_source_lease_never_adopts_a_replacement_or_restored_token() {
    for replace_before_capture in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (source, secret) = staged_test_source(root.path());
        let lease = secret.staged_source_lease().unwrap();
        let replacement = root.path().join("replacement");
        std::fs::write(&replacement, b"source-token").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(replacement, &source).unwrap();
        if replace_before_capture {
            assert!(
                secret.staged_source_lease().is_err(),
                "capture must not reload the same bytes from a new source"
            );
        }
        assert!(lease.check().is_err());
        std::fs::remove_file(&source).unwrap();
        std::fs::write(&source, b"source-token").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(lease.check().is_err());
        assert!(secret.staged_source_lease().is_err());
        assert_eq!(
            secret.loaded_values().0.len(),
            1,
            "no replacement load occurred"
        );
    }
}

#[test]
fn vm_revokes_a_removed_source_once_and_requires_the_exact_acknowledgement() {
    use std::io::{BufRead as _, BufReader};
    for wrong_ack in [false, true] {
        let (mut run, mut peer, root) = running();
        let (source, secret) = staged_test_source(root.path());
        run.inner.vault_lease = secret.staged_source_lease().unwrap().into();
        run.revocation = Some(
            revocation::Watch::start(&run.inner.connection, run.inner.vault_lease.clone()).unwrap(),
        );
        peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        std::fs::remove_file(source).unwrap();
        let mut line = String::new();
        BufReader::new(&mut peer).read_line(&mut line).unwrap();
        assert_eq!(
            protocol::decode::<protocol::ToVm>(line.as_bytes()).unwrap(),
            protocol::ToVm::RevokeSecrets {
                ids: vec!["token".to_owned()]
            }
        );
        run.revocation.as_ref().unwrap().check().unwrap();
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        peer.set_nonblocking(false).unwrap();
        peer.write_all(
            &protocol::encode(&protocol::FromVm::SecretsRevoked {
                ids: vec![if wrong_ack { "other" } else { "token" }.to_owned()],
            })
            .unwrap(),
        )
        .unwrap();
        let event = run.wait(Deadline {
            at: Some(Instant::now() + Duration::from_millis(20)),
        });
        if wrong_ack {
            assert!(matches!(event, RunEvent::Unknown { .. }));
            assert!(run.failed);
            assert!(!run.revocation.as_ref().unwrap().acknowledged());
        } else {
            assert!(matches!(event, RunEvent::WallExpired));
            assert!(run.revocation.as_ref().unwrap().acknowledged());
            assert!(run.revocation.as_ref().unwrap().check().is_ok());
        }
    }
}

#[test]
fn vm_unsolicited_revocation_ack_refuses() {
    let (mut run, mut peer, _root) = running();
    peer.write_all(&protocol::encode(&protocol::FromVm::SecretsRevoked { ids: vec![] }).unwrap())
        .unwrap();
    assert!(matches!(run.wait(soon()), RunEvent::Unknown { .. }));
    assert!(run.failed);
}

#[test]
fn vm_revoked_source_refuses_before_sending_run() {
    let (mut run, mut peer, root) = running();
    let (source, secret) = staged_test_source(root.path());
    run.inner.vault_lease = secret.staged_source_lease().unwrap().into();
    std::fs::remove_file(source).unwrap();
    assert!(Box::new(run.inner).release().is_err());
    assert_eq!(
        peer.read(&mut [0]).unwrap(),
        0,
        "the connection closed without a Run frame"
    );
}

#[test]
fn vm_revocation_survives_blocked_stdout_and_stderr_without_changing_output_flags() {
    use std::io::{BufRead as _, BufReader};
    use std::os::fd::{FromRawFd as _, IntoRawFd as _};
    for stderr in [false, true] {
        let (mut run, mut peer, root) = running();
        let (source, secret) = staged_test_source(root.path());
        run.inner.vault_lease = secret.staged_source_lease().unwrap().into();
        run.revocation = Some(
            revocation::Watch::start(&run.inner.connection, run.inner.vault_lease.clone()).unwrap(),
        );
        let (output, held_reader) = UnixStream::pair().unwrap();
        let inspected = output.try_clone().unwrap();
        // Fill the stand-in output, then restore its blocking mode before
        // handing it to the runtime. Runtime operations must preserve it.
        output.set_nonblocking(true).unwrap();
        let buffer = [b'x'; 65536];
        loop {
            // SAFETY: live test socket and fixed input buffer.
            let sent = unsafe {
                libc::send(
                    output.as_raw_fd(),
                    buffer.as_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                break;
            }
        }
        output.set_nonblocking(false).unwrap();
        // SAFETY: F_GETFL reads the live test descriptor's flags.
        let before = unsafe { libc::fcntl(inspected.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(before & libc::O_NONBLOCK, 0);
        // SAFETY: into_raw_fd transfers exactly this owned socket to File.
        let output = unsafe { std::fs::File::from_raw_fd(output.into_raw_fd()) };
        if stderr {
            run.inner.stderr = output;
        } else {
            run.inner.stdout = output;
        }
        let frame = if stderr {
            protocol::FromVm::Stderr {
                data: protocol::encode_data(b"blocked"),
            }
        } else {
            protocol::FromVm::Stdout {
                data: protocol::encode_data(b"blocked"),
            }
        };
        peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
        let (done, observed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let event = run.wait(Deadline { at: None });
            done.send(event).unwrap();
        });
        assert!(
            observed.recv_timeout(Duration::from_millis(50)).is_err(),
            "output should be blocked"
        );
        std::fs::remove_file(source).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        let mut request = String::new();
        BufReader::new(&mut peer).read_line(&mut request).unwrap();
        assert_eq!(
            protocol::decode::<protocol::ToVm>(request.as_bytes()).unwrap(),
            protocol::ToVm::RevokeSecrets {
                ids: vec!["token".into()]
            }
        );
        // Even a correct ACK cannot help until the main reader processes it.
        peer.write_all(
            &protocol::encode(&protocol::FromVm::SecretsRevoked {
                ids: vec!["token".into()],
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            peer.read(&mut [0]).unwrap(),
            0,
            "unprocessed ACK must still cancel by deadline"
        );
        assert!(
            observed.try_recv().is_err(),
            "main stayed blocked throughout revocation"
        );
        assert_eq!(
            // SAFETY: F_GETFL reads the same still-live output description.
            unsafe { libc::fcntl(inspected.as_raw_fd(), libc::F_GETFL) },
            before
        );
        drop(held_reader);
        assert!(matches!(
            observed.recv_timeout(Duration::from_secs(2)).unwrap(),
            RunEvent::Unknown { .. }
        ));
        worker.join().unwrap();
    }
}

#[test]
fn vm_verified_completion_without_a_revocation_ack_is_settlement_not_acknowledgement() {
    use std::io::{BufRead as _, BufReader};
    let (mut run, mut peer, root) = running();
    let (source, secret) = staged_test_source(root.path());
    run.inner.vault_lease = secret.staged_source_lease().unwrap().into();
    run.revocation = Some(
        revocation::Watch::start(&run.inner.connection, run.inner.vault_lease.clone()).unwrap(),
    );
    std::fs::remove_file(source).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut request = String::new();
    BufReader::new(&mut peer).read_line(&mut request).unwrap();
    let (sha256, data) = encoded(&receipt());
    for frame in [
        protocol::FromVm::BoundReceipt {
            sha256,
            data,
            binding: binding(),
        },
        done(0),
    ] {
        peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
    }
    assert!(matches!(
        run.wait(soon()),
        RunEvent::TargetExited { code: 0 }
    ));
    assert!(run.verified());
    assert!(run.revocation.as_ref().unwrap().is_settled());
    assert!(!run.revocation.as_ref().unwrap().acknowledged());
}

fn running_with(network: image::GuestNetwork) -> (VmRunning, UnixStream, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    for name in ["workspace", "evidence"] {
        std::fs::create_dir(dir.path().join(name)).unwrap();
    }
    let socket = dir.path().join("attempt.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let connection = control::AttemptConnection::connect(&socket).unwrap();
    let (peer, _) = listener.accept().unwrap();
    let execution = VmExecution {
        attempt_dir: dir.path().to_path_buf(),
        attempt_id: "host-attempt".into(),
        connection,
        sockets: (dir.path().join("control.sock"), socket),
        boot_id: "host-boot".into(),
        guest_kernel: "guest-kernel".into(),
        image: record::ImageDigests {
            sampler_sha256: None,
            disk_sha256: "d".repeat(64),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
            guest_program_catalog_sha256: None,
        },
        vsock_port: 1024,
        started: Instant::now(),
        started_wall: rfc3339_utc(SystemTime::now()),
        profile: "tool".into(),
        argv_digest: "sha256:argv".into(),
        limits: serde_json::from_value(serde_json::json!({
            "wall":{"value":"30000","required":true},
            "pids":{"value":"256","required":false},"cpu":null
        }))
        .unwrap(),
        network,
        guest_policy_digest: GUEST_POLICY.into(),
        vault_lease: revocation::Sources::default(),
        native_program: None,
        native_binding: None,
        stdout: std::fs::File::create(dir.path().join("stdout")).unwrap(),
        stderr: std::fs::File::create(dir.path().join("stderr")).unwrap(),
    };
    (
        VmRunning {
            inner: execution,
            supervisor_pid: 10,
            receipt: None,
            receipt_binding: None,
            sampling_exports: 0,
            sampling_export_error: None,
            guest: None,
            stop: None,
            termination_deadline: None,
            wall_reported: false,
            finished: false,
            failed: false,
            revocation: None,
        },
        peer,
        dir,
    )
}

fn encoded(receipt: &Value) -> (String, String) {
    let bytes = serde_json::to_vec(receipt).unwrap();
    (
        image::hex(&sha2::Sha256::digest(&bytes)),
        protocol::encode_data(&bytes),
    )
}

fn soon() -> Deadline {
    Deadline {
        at: Some(Instant::now() + Duration::from_secs(1)),
    }
}

/// The admitted environment the guest jail runs under, as a baseline
/// lookup: what [`GUEST_ADMITTED_ENVIRONMENT`] names.
fn guest_lookup(name: &str) -> Option<Vec<u8>> {
    GUEST_ADMITTED_ENVIRONMENT
        .iter()
        .find(|(admitted, _)| *admitted == name)
        .map(|(_, value)| value.as_bytes().to_vec())
}

/// A whole-second wall, as `--limit wall=<seconds>s` writes it.
fn wall(seconds: u64) -> Ceilings {
    Ceilings {
        wall: Some(Ceiling {
            value: seconds * 1000,
            requested: format!("{seconds}s"),
            required: true,
        }),
        ..Ceilings::default()
    }
}

/// The policy `run --vm --profile <profile> <delta>` resolves to, with the
/// environment the guest jail has, on the guest platform: what the
/// supervisor resolves on a Mac whose environment matches the guest's.
fn resolved_with(
    profile: ProfileName,
    lookup: &crate::profiles::EnvLookup,
    delta: PolicyDelta,
) -> crate::policy::Resolved {
    crate::policy::resolve(&ResolveInputs {
        platform: Os::Linux,
        base_profile: profile,
        policy_name: profile.as_str().into(),
        baseline: crate::profiles::baseline(profile, Os::Linux, lookup),
        workspace: b"/work".to_vec(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: vec![Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: Some(b"/work".to_vec()),
            delta,
        }],
    })
    .expect("the policy resolves")
}

fn snapshot(profile: ProfileName, delta: PolicyDelta) -> PolicySnapshot {
    resolved_with(profile, &guest_lookup, delta).snapshot
}

fn tool() -> PolicySnapshot {
    snapshot(
        ProfileName::Tool,
        PolicyDelta {
            limits: wall(60),
            ..PolicyDelta::default()
        },
    )
}

fn agent() -> PolicySnapshot {
    snapshot(
        ProfileName::Agent,
        PolicyDelta {
            limits: wall(60),
            network_allow: vec!["api.example.com".into(), "plain.example.com:8080".into()],
            ..PolicyDelta::default()
        },
    )
}

/// The agent policy with `launch_toml` applied as `--launch svc`.
fn agent_with_launch(launch_toml: &str) -> PolicySnapshot {
    let resolved = resolved_with(
        ProfileName::Agent,
        &guest_lookup,
        PolicyDelta {
            limits: wall(60),
            network_allow: vec!["api.example.com".into()],
            ..PolicyDelta::default()
        },
    );
    let launch = crate::launch_profile::parse(
        launch_toml,
        "svc",
        crate::launch_profile::LaunchSource::Bundled,
        None,
    )
    .expect("the launch profile parses");
    crate::launch_profile::apply(resolved, &launch)
        .expect("the launch profile applies")
        .snapshot
}

const VAULT_LAUNCH: &str = r#"
name = "svc"
jail = "agent"

[credentials."api.token"]
mode = "vault"
source = "/secrets/api-token"
hosts = ["https://api.example.com"]
header = { name = "authorization", prefix = "Bearer " }
paths = ["/v1/"]
env = "API_TOKEN"
"#;

fn field(snapshot: &PolicySnapshot) -> Option<String> {
    not_carried(snapshot).map(|refusal| refusal.field)
}

// ---------------------------------------------------------------------------
// The guest receipt: binding, verification, agreement (D1's second wall)
// ---------------------------------------------------------------------------

#[test]
fn forged_or_replayed_receipts_never_establish_tree_facts() {
    for pointer in [
        "/containment",
        "/lifetime/boundary",
        "/state_cleanup",
        "/argv_digest",
        "/attempt_id",
        "/process/identity/value/boot_id",
    ] {
        let (mut run, _, dir) = running();
        let mut forged = receipt();
        *forged.pointer_mut(pointer).unwrap() = "forged".into();
        let (hash, data) = encoded(&forged);
        assert!(
            run.store_receipt(&hash, &data, &binding()).is_err(),
            "{pointer}"
        );
        assert!(run.receipt.is_none());
        assert!(!dir.path().join("evidence/jail.json").exists());
    }
    for field in [
        "attempt_id",
        "boot_id",
        "profile",
        "argv_digest",
        "guest_attempt_id",
        "guest_boot_id",
    ] {
        let (mut run, _peer, dir) = running();
        let (hash, data) = encoded(&receipt());
        let mut bind = serde_json::to_value(binding()).unwrap();
        bind[field] = "another".into();
        let bind = serde_json::from_value(bind).unwrap();
        assert_eq!(
            run.store_receipt(&hash, &data, &bind).unwrap_err(),
            "guest receipt does not bind to this attempt, argv, profile and boot",
            "{field}"
        );
        assert!(run.receipt.is_none(), "{field}");
        for file in ["jail.json", "vm-binding.json"] {
            assert!(!dir.path().join("evidence").join(file).exists(), "{field}");
        }
        // The very same receipt exports successfully once its binding is
        // correct; a missing TempDir must never stand in for verification.
        run.store_receipt(&hash, &data, &binding()).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("evidence/jail.json")).unwrap(),
            serde_json::to_vec(&receipt()).unwrap(),
            "{field}"
        );
    }
}

#[test]
fn empty_guest_identifiers_never_bind_a_receipt() {
    for (field, pointer) in [
        ("guest_attempt_id", "/attempt_id"),
        ("guest_boot_id", "/process/identity/value/boot_id"),
    ] {
        let (mut run, _peer, dir) = running();
        let mut changed = receipt();
        *changed.pointer_mut(pointer).unwrap() = "".into();
        let mut bind = serde_json::to_value(binding()).unwrap();
        bind[field] = "".into();
        let bind = serde_json::from_value(bind).unwrap();
        let (hash, data) = encoded(&changed);
        assert_eq!(
            run.store_receipt(&hash, &data, &bind).unwrap_err(),
            "guest receipt does not bind to this attempt, argv, profile and boot",
            "{field}"
        );
        assert!(run.receipt.is_none());
        assert!(!dir.path().join("evidence/jail.json").exists());
    }
}

#[test]
fn digest_mismatch_and_duplicate_receipt_refuse() {
    let (mut run, _, dir) = running();
    let (hash, data) = encoded(&receipt());
    assert!(
        run.store_receipt(&"0".repeat(64), &data, &binding())
            .unwrap_err()
            .contains("digest")
    );
    run.store_receipt(&hash, &data, &binding()).unwrap();
    assert_eq!(
        run.store_receipt(&hash, &data, &binding()).unwrap_err(),
        "duplicate guest receipt",
        "refused as a duplicate, not by the export's exclusive create"
    );
    assert_eq!(
        std::fs::read(dir.path().join("evidence/jail.json")).unwrap(),
        serde_json::to_vec(&receipt()).unwrap()
    );
    assert!(
        run.final_limits().is_empty(),
        "no guest row reaches the host before the attempt verified"
    );
}

/// Decision D1's second wall, on the attempt path: the applied network must
/// be the requested one (image.rs's own test covers every set).
#[test]
fn the_receipt_must_report_the_requested_network_applied() {
    let (mut run, _peer, dir) = running();
    let mut proxied = receipt();
    proxied["applied"]["network"] =
        serde_json::json!({"mode": "proxy", "mechanism": "proxy", "allowed_hosts": []});
    let (hash, data) = encoded(&proxied);
    let error = run.store_receipt(&hash, &data, &binding()).unwrap_err();
    assert!(error.contains("not the requested `none`"), "{error}");
    assert!(!dir.path().join("evidence/jail.json").exists());

    let requested = image::GuestNetwork::requested(
        "proxy",
        ["api.example.com:443".to_owned()],
        ["api.example.com:443".to_owned()],
    );
    for (allowed, tls_only, accepted) in [
        (
            vec!["api.example.com:443"],
            vec!["api.example.com:443"],
            true,
        ),
        // The pre-fix guest: the canonical spelling crossed, so the rule
        // was applied with an explicit port (plaintext admitted).
        (vec!["api.example.com:443"], vec![], false),
        (
            vec!["other.example.com:443"],
            vec!["other.example.com:443"],
            false,
        ),
    ] {
        let (mut run, _peer, _dir) = running_with(requested.clone());
        let mut proxied = receipt();
        proxied["applied"]["network"] = serde_json::json!({
            "mode": "proxy", "mechanism": "proxy",
            "allowed_hosts": allowed, "tls_only": tls_only,
        });
        let (hash, data) = encoded(&proxied);
        assert_eq!(
            run.store_receipt(&hash, &data, &binding()).is_ok(),
            accepted,
            "{proxied}"
        );
    }
}

#[test]
fn exports_cannot_climb_or_follow_links_and_evidence_root_exists() {
    let (run, _, dir) = running();
    for path in [
        "../escaped",
        "nested/../../escaped",
        "/absolute",
        "a//b",
        "a/./b",
    ] {
        assert!(
            run.export("workspace", path, false, b"payload").is_err(),
            "{path}"
        );
    }
    std::os::unix::fs::symlink(dir.path(), dir.path().join("workspace/link")).unwrap();
    assert!(
        run.export("workspace", "link/escaped", false, b"payload")
            .is_err()
    );
    run.export("evidence", "trace.ndjson", false, b"evidence")
        .unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("evidence/trace.ndjson")).unwrap(),
        b"evidence"
    );
    assert!(!dir.path().join("escaped").exists());
}

#[test]
fn output_uses_owned_sinks_and_done_requires_verified_receipt_and_record() {
    let (mut run, mut peer, dir) = running();
    for frame in [
        protocol::FromVm::Stdout {
            data: protocol::encode_data(b"visible"),
        },
        protocol::FromVm::Stderr {
            data: protocol::encode_data(b"diagnostic"),
        },
        done(0),
    ] {
        peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
    }
    assert!(matches!(run.wait(soon()), RunEvent::Unknown { .. }));
    assert_eq!(
        std::fs::read(dir.path().join("stdout")).unwrap(),
        b"visible"
    );
    assert_eq!(
        std::fs::read(dir.path().join("stderr")).unwrap(),
        b"diagnostic"
    );
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
    assert_eq!(run.guest_facts(), None);
    let (mut run, mut peer, dir) = running();
    let (sha256, data) = encoded(&receipt());
    std::fs::create_dir(dir.path().join(record::TRANSPORT_FILE)).unwrap();
    peer.write_all(
        &protocol::encode(&protocol::FromVm::BoundReceipt {
            sha256,
            data,
            binding: binding(),
        })
        .unwrap(),
    )
    .unwrap();
    peer.write_all(&protocol::encode(&done(0)).unwrap())
        .unwrap();
    assert!(
        matches!(run.wait(soon()),RunEvent::Unknown {reason} if reason.contains("record write"))
    );
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
    // A verified receipt whose attempt then failed claims no guest facts.
    assert_eq!(run.guest_facts(), None);
}

#[test]
fn unbound_receipt_never_becomes_verified_on_the_cleanup_path() {
    let (mut run, mut peer, _) = running();
    let (sha256, data) = encoded(&receipt());
    peer.write_all(&protocol::encode(&protocol::FromVm::Receipt { sha256, data }).unwrap())
        .unwrap();
    peer.write_all(&protocol::encode(&done(0)).unwrap())
        .unwrap();
    assert!(matches!(run.wait(soon()), RunEvent::Unknown { .. }));
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
}

#[test]
fn ready_must_match_locally_verified_digests() {
    let manifest = image::ImageManifest {
        source_sha256: Default::default(),
        status: "prepared".into(),
        disk_sha256: "d".repeat(64),
        helper_sha256: "h".repeat(64),
        custodian_sha256: "c".repeat(64),
        seed_sha256: "s".repeat(64),
        guest_program_catalog_sha256: None,
    };
    let fresh = || ReadyFrame {
        guest_program_catalog_sha256: None,
        guest_contracts: None,
        boot_id: "boot".into(),
        disk_sha256: manifest.disk_sha256.clone(),
        helper_sha256: manifest.helper_sha256.clone(),
        custodian_sha256: manifest.custodian_sha256.clone(),
        seed_sha256: manifest.seed_sha256.clone(),
        vsock_port: 1024,
    };
    let mut ready = fresh();
    verify_ready(&ready, &manifest).unwrap();
    // Each identity on its own: the client hashes nothing (Install::prepared),
    // so a serve that booted another disk, helper, custodian or seed is caught
    // here or nowhere, and the receipt would name the manifest's digests.
    for name in [
        "disk",
        "helper",
        "custodian",
        "seed",
        "boot id",
        "vsock port",
    ] {
        let mut forged = fresh();
        match name {
            "disk" => forged.disk_sha256 = "e".repeat(64),
            "helper" => forged.helper_sha256 = "e".repeat(64),
            "custodian" => forged.custodian_sha256 = "e".repeat(64),
            "seed" => forged.seed_sha256 = "e".repeat(64),
            "boot id" => forged.boot_id.clear(),
            _ => forged.vsock_port = 1025,
        }
        assert!(verify_ready(&forged, &manifest).is_err(), "{name}");
    }
    ready.disk_sha256 = "forged".into();
    assert!(verify_ready(&ready, &manifest).is_err());
}

#[test]
fn guest_limits_must_match_every_requested_value_and_requirement() {
    for (pointer, reason) in [
        (
            "/applied/limits/0/requested",
            "guest applied wall=wrong; the required ceiling is 30000",
        ),
        (
            "/applied/limits/1/applied",
            "guest did not apply every required limit",
        ),
        (
            "/applied/limits/1/requested",
            "guest applied pids=wrong, looser than the preferred 256",
        ),
        (
            "/applied/limits/0/applied",
            "guest did not apply every required limit",
        ),
    ] {
        let (mut run, _peer, dir) = running();
        let mut changed = receipt();
        let field = changed.pointer_mut(pointer).unwrap();
        *field = if field.is_boolean() {
            Value::Bool(false)
        } else {
            Value::String("wrong".into())
        };
        let (hash, data) = encoded(&changed);
        assert_eq!(
            run.store_receipt(&hash, &data, &binding()).unwrap_err(),
            reason,
            "{pointer}"
        );
        assert!(run.receipt.is_none());
        assert!(!dir.path().join("evidence/jail.json").exists());
    }
}

#[test]
fn extra_guest_limit_rows_are_more_enforcement_not_mismatches() {
    // The guest applies its measured fixed shape on top of the requested
    // ceilings: an extra row is stricter enforcement, accepted; removing
    // the required wall row still refuses.
    for key in ["mem", "cpu", "unknown"] {
        let (mut run, _peer, _dir) = running();
        let mut changed = receipt();
        let rows = changed["applied"]["limits"].as_array_mut().unwrap();
        let mut extra = rows[1].clone();
        extra["key"] = key.into();
        rows.push(extra);
        let (hash, data) = encoded(&changed);
        run.store_receipt(&hash, &data, &binding())
            .unwrap_or_else(|error| panic!("{key}: {error}"));
        assert!(run.receipt.is_some());
        drop(run);
        let (mut run, _peer, _dir) = running();
        let mut changed = receipt();
        changed["applied"]["limits"]
            .as_array_mut()
            .unwrap()
            .retain(|row| row["key"] != "wall");
        let (hash, data) = encoded(&changed);
        // The receipt-level rule fires first: the guest must carry its
        // measured fixed set, all applied.
        assert_eq!(
            run.store_receipt(&hash, &data, &binding()).unwrap_err(),
            "guest did not apply every required limit"
        );
        assert!(run.receipt.is_none());
        let (hash, data) = encoded(&receipt());
        run.store_receipt(&hash, &data, &binding()).unwrap();
        assert!(run.receipt.is_some());
    }
}

// ---------------------------------------------------------------------------
// D5: the guest facts the host receipt mirrors
// ---------------------------------------------------------------------------

/// The verified guest receipt's applied groups, observer, coverage, exec
/// observation and kernel reach the host only once the attempt verified:
/// receipt, `done`, transport record.
#[test]
fn guest_facts_are_the_verified_receipts_and_only_after_done() {
    let (mut run, mut peer, dir) = running();
    let (sha256, data) = encoded(&receipt());
    peer.write_all(
        &protocol::encode(&protocol::FromVm::BoundReceipt {
            sha256: sha256.clone(),
            data,
            binding: binding(),
        })
        .unwrap(),
    )
    .unwrap();
    // The receipt alone: not yet a verified attempt.
    let line = run.inner.connection.next_frame().unwrap().unwrap();
    let protocol::FromVm::BoundReceipt {
        sha256: hash,
        data,
        binding: bind,
    } = line
    else {
        panic!("the bound receipt frame");
    };
    run.store_receipt(&hash, &data, &bind).unwrap();
    assert_eq!(run.guest_facts(), None, "no facts before `done`");
    assert!(run.final_limits().is_empty(), "no rows before `done`");
    peer.write_all(&protocol::encode(&done(0)).unwrap())
        .unwrap();
    assert!(matches!(
        run.wait(soon()),
        RunEvent::TargetExited { code: 0 }
    ));
    let facts = run
        .guest_facts()
        .expect("a verified attempt has guest facts");
    let guest = receipt();
    assert_eq!(facts.kernel, "Linux 7.0.0-38-generic");
    assert_eq!(facts.arch, "aarch64");
    assert!(facts.exec_observed);
    assert_eq!(
        serde_json::to_value(&facts.applied).unwrap()["network"],
        guest["applied"]["network"]
    );
    assert_eq!(
        serde_json::to_value(&facts.observer).unwrap(),
        guest["observer"]
    );
    assert_eq!(
        serde_json::to_value(&facts.coverage).unwrap(),
        guest["coverage"]
    );
    let details = &facts.details;
    assert_eq!(details["guest_receipt"], "evidence/jail.json");
    assert_eq!(details["guest_receipt_sha256"], format!("sha256:{sha256}"));
    assert_eq!(
        details["guest_carried"],
        serde_json::json!(GuestFacts::CARRIED)
    );
    assert!(dir.path().join(record::TRANSPORT_FILE).is_file());
    assert_eq!(
        serde_json::to_value(run.final_limits()).unwrap(),
        guest["applied"]["limits"]
    );
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, Some(true));
}

/// A guest receipt whose groups do not read as the host's receipt types is
/// refused like any other unverifiable one: the host never mirrors a guess.
#[test]
fn a_receipt_whose_groups_do_not_read_is_refused() {
    for pointer in [
        "/observer",
        "/coverage",
        "/platform/kernel",
        "/applied/syscalls",
    ] {
        let (mut run, _peer, dir) = running();
        let mut changed = receipt();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!({"unexpected": true});
        let (hash, data) = encoded(&changed);
        let error = run.store_receipt(&hash, &data, &binding()).unwrap_err();
        assert!(error.contains("does not read"), "{pointer}: {error}");
        assert!(run.guest.is_none());
        assert!(!dir.path().join("evidence/jail.json").exists());
    }
}

/// The summary's transport line is the transport record's (one spelling,
/// cross-platform), and the record's names are the summary's.
#[test]
fn the_summary_reads_the_transport_record_this_tier_writes() {
    assert_eq!(record::TRANSPORT_FILE, crate::summary::VM_TRANSPORT_FILE);
    assert_eq!(
        record::SCHEMA_TRANSPORT,
        crate::summary::VM_TRANSPORT_SCHEMA
    );
    let mut facts = record::TransportRecord::new(
        "att_00000000-0000-4000-8000-000000000001",
        "vm-boot\nforged",
        "7.0.0",
        record::ImageDigests {
            sampler_sha256: None,
            disk_sha256: "0123456789abcdef".repeat(4),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
            guest_program_catalog_sha256: None,
        },
        1024,
        "/data/vm/control.sock",
        "/data/vm/attempt.sock",
        "2026-11-03T12:00:00Z",
        1.0,
        "f".repeat(64),
    );
    facts.vsock_port = 2048;
    let line = crate::summary::vm_transport_line(&serde_json::to_value(&facts).unwrap());
    assert_eq!(
        line,
        "vm: guest-reported facts in evidence/jail.json · boot vm-boot<U+000A>forged · image \
         0123456789abcdef · vsock 2048 · receipt sha256:ffffffffffffffff"
    );
}

#[test]
fn released_supervisor_pid_is_retained_without_replacing_the_workload_identity() {
    let (run, mut peer, root) = running();
    let writer = std::thread::spawn(move || {
        let request = read_line(&mut peer);
        assert_eq!(
            protocol::decode::<protocol::ToVm>(&request).unwrap(),
            protocol::ToVm::Run
        );
        peer.write_all(
            &protocol::encode(&protocol::FromVm::Released {
                supervisor_pid: 640,
            })
            .unwrap(),
        )
        .unwrap();
        let mut value = receipt();
        value["process"]["identity"] = serde_json::json!({
            "kind":"linux_boot_start",
            "value":{"boot_id":"guest-boot","pid":672,"start_time_ticks":2673}
        });
        let (sha256, data) = encoded(&value);
        peer.write_all(
            &protocol::encode(&protocol::FromVm::BoundReceipt {
                sha256,
                data,
                binding: binding(),
            })
            .unwrap(),
        )
        .unwrap();
        peer.write_all(&protocol::encode(&done(0)).unwrap())
            .unwrap();
    });
    let mut released = match Box::new(run.inner).release() {
        Ok(released) => released,
        Err(_) => panic!("valid release refused"),
    };
    assert!(matches!(
        released.wait(soon()),
        RunEvent::TargetExited { code: 0 }
    ));
    assert_eq!(released.wait_tree(Duration::ZERO).tree_empty, Some(true));
    let transport = record::TransportRecord::read_in(root.path()).unwrap();
    assert_eq!(transport.supervisor_pid, Some(640));
    let guest: Value =
        serde_json::from_slice(&std::fs::read(root.path().join("evidence/jail.json")).unwrap())
            .unwrap();
    assert_eq!(
        guest.pointer("/process/identity/value/pid"),
        Some(&Value::from(672))
    );
    writer.join().unwrap();
}

// ---------------------------------------------------------------------------
// D1: what `--vm` carries
// ---------------------------------------------------------------------------

#[test]
fn the_carried_shapes_pass() {
    assert_eq!(field(&tool()), None);
    assert_eq!(field(&agent()), None);
    assert_eq!(field(&agent_with_launch(VAULT_LAUNCH)), None);
    // The agent baseline's preferred pids=512 is honoured by the guest's
    // stricter 64; a required ceiling equal to the guest's is honoured too.
    for limits in [
        Ceilings {
            pids: Some(Ceiling {
                value: 64,
                requested: "64".into(),
                required: true,
            }),
            mem: Some(Ceiling {
                value: 512 * 1024 * 1024,
                requested: "512MiB".into(),
                required: true,
            }),
            swap: Some(Ceiling {
                value: 0,
                requested: "0".into(),
                required: true,
            }),
            ..wall(300)
        },
        Ceilings {
            mem: Some(Ceiling {
                value: 1024 * 1024 * 1024,
                requested: "1GiB".into(),
                required: false,
            }),
            ..wall(1)
        },
    ] {
        let snapshot = snapshot(
            ProfileName::Tool,
            PolicyDelta {
                limits,
                ..PolicyDelta::default()
            },
        );
        assert_eq!(field(&snapshot), None, "{:?}", snapshot.limits);
    }
}

/// The reviewer's probe (C1): every host gate used to pass. Each element
/// now refuses, one at a time, until only the carried shape is left.
#[test]
fn the_reviewer_probe_refuses_each_element_in_turn() {
    let mb = |n: u64| n * 1024 * 1024;
    let mut delta = PolicyDelta {
        deny_read: vec![b"secret".to_vec()],
        limits: Ceilings {
            mem: Some(Ceiling {
                value: mb(256),
                requested: "256MiB".into(),
                required: true,
            }),
            storage: Some(Ceiling {
                value: mb(1024),
                requested: "1GiB".into(),
                required: true,
            }),
            cpu: Some(Ceiling {
                value: 50,
                requested: "50".into(),
                required: true,
            }),
            pids: Some(Ceiling {
                value: 8,
                requested: "8".into(),
                required: true,
            }),
            ..wall(60)
        },
        ..PolicyDelta::default()
    };
    let mut refused = Vec::new();
    loop {
        let snapshot = snapshot(ProfileName::Agent, delta.clone());
        let Some(field) = field(&snapshot) else { break };
        // Every refusal is also the prepare-time one, before any contact.
        let error = validate_policy(&snapshot).unwrap_err();
        assert!(error.message.contains(&format!("`{field}`")), "{error}");
        assert!(error.message.contains("no guest was contacted"), "{error}");
        match field.as_str() {
            "filesystem.deny_read" => delta.deny_read.clear(),
            "limits.pids" => delta.limits.pids = None,
            "limits.mem" => delta.limits.mem = None,
            "limits.storage" => delta.limits.storage = None,
            "limits.cpu" => delta.limits.cpu = None,
            other => panic!("unexpected refusal {other}"),
        }
        refused.push(field);
    }
    assert_eq!(
        refused,
        [
            "filesystem.deny_read",
            "limits.pids",
            "limits.mem",
            "limits.storage",
            "limits.cpu"
        ]
    );
}

/// The reviewer's second probe: `tool` with a read-only narrowing and
/// `protected_coverage = all_descendants` passed with neither field sent.
#[test]
fn narrowed_grants_and_coverage_refuse_for_tool_too() {
    let narrowed = snapshot(
        ProfileName::Tool,
        PolicyDelta {
            read_only: vec![b"docs".to_vec()],
            limits: wall(60),
            ..PolicyDelta::default()
        },
    );
    assert_eq!(field(&narrowed).as_deref(), Some("filesystem.read_only"));
    let covered = snapshot(
        ProfileName::Tool,
        PolicyDelta {
            protected_coverage: Some(crate::policy::ProtectedCoverage::AllDescendants),
            limits: wall(60),
            ..PolicyDelta::default()
        },
    );
    assert_eq!(
        field(&covered).as_deref(),
        Some("filesystem.protected_coverage")
    );
    let deny = snapshot(
        ProfileName::Tool,
        PolicyDelta {
            deny_read: vec![b"private".to_vec()],
            limits: wall(60),
            ..PolicyDelta::default()
        },
    );
    assert_eq!(field(&deny).as_deref(), Some("filesystem.deny_read"));
}

/// Every element outside the carry set refuses with its own field, for the
/// profile that can express it.
#[test]
fn every_element_outside_the_carry_set_refuses_with_its_field() {
    let ceiling = |value: &str, required: bool| LimitCeiling {
        value: value.into(),
        required,
    };
    type Mutate = Box<dyn Fn(&mut PolicySnapshot)>;
    let cases: Vec<(&str, PolicySnapshot, Mutate)> = vec![
        (
            "terminal",
            tool(),
            Box::new(|s| s.terminal = Some(crate::policy::TerminalMode::Attached)),
        ),
        (
            "lifetime_boundary",
            tool(),
            Box::new(|s| {
                s.lifetime_boundary = Some(crate::policy::LifetimeBoundary::KernelBound);
            }),
        ),
        (
            "commands",
            tool(),
            Box::new(|s| s.commands.deny.push("rm -rf".into())),
        ),
        (
            "roots.scratch",
            tool(),
            Box::new(|s| {
                s.roots.scratch = ScratchRoot::Host {
                    path: NativeString::Text("/scratch".into()),
                };
            }),
        ),
        (
            "roots.cwd",
            tool(),
            Box::new(|s| s.roots.cwd = NativeString::Text("sub".into())),
        ),
        (
            "roots.vendor_state",
            tool(),
            Box::new(|s| {
                s.roots.vendor_state = Some(crate::policy::VendorStateRoot::Persistent {
                    profile: "svc".into(),
                });
            }),
        ),
        (
            "filesystem.read_write",
            tool(),
            Box::new(|s| s.filesystem.read_write.pop().map(drop).unwrap_or(())),
        ),
        (
            "filesystem.protected_segments",
            agent(),
            Box::new(|s| s.filesystem.protected_segments.clear()),
        ),
        (
            "network.mode",
            tool(),
            Box::new(|s| s.network.mode = crate::network::NetworkMode::Proxy),
        ),
        (
            "network.mode",
            agent(),
            Box::new(|s| s.network.mode = crate::network::NetworkMode::None),
        ),
        // A TLS-only entry the guest grammar cannot express (an omitted
        // port always means 443), and an allow entry that does not
        // re-parse to itself: what the guest would apply differs.
        (
            "network.tls_only",
            agent(),
            Box::new(|s| s.network.tls_only.push("plain.example.com:8080".into())),
        ),
        (
            "network.allow",
            agent(),
            Box::new(|s| s.network.allow[1] = "PLAIN.example.com:8080".into()),
        ),
        (
            "network.translation_prefixes",
            agent(),
            Box::new(|s| s.network.translation_prefixes.push("64:ff9b::/96".into())),
        ),
        (
            "limits.wall",
            tool(),
            Box::new(move |s| s.limits.wall = None),
        ),
        (
            "limits.wall",
            tool(),
            Box::new(move |s| s.limits.wall = Some(ceiling("301000", true))),
        ),
        (
            "limits.wall",
            tool(),
            Box::new(move |s| s.limits.wall = Some(ceiling("1500", true))),
        ),
        (
            "limits.mem",
            tool(),
            Box::new(move |s| s.limits.mem = Some(ceiling("1073741824", true))),
        ),
        (
            "limits.swap",
            tool(),
            Box::new(move |s| s.limits.swap = Some(ceiling("1048576", true))),
        ),
        (
            "limits.pids",
            tool(),
            Box::new(move |s| s.limits.pids = Some(ceiling("32", false))),
        ),
        (
            "limits.inodes",
            tool(),
            Box::new(move |s| s.limits.inodes = Some(ceiling("1000", false))),
        ),
        (
            "observation.mode",
            tool(),
            Box::new(|s| s.observation.mode = crate::records::ObserveMode::Off),
        ),
        (
            "observation.evidence",
            tool(),
            Box::new(|s| s.observation.evidence = crate::records::EvidenceMode::BestEffort),
        ),
        (
            "observation.learning",
            tool(),
            Box::new(|s| s.observation.learning = true),
        ),
        (
            "environment.inherit_host",
            tool(),
            Box::new(|s| s.environment.inherit_host = true),
        ),
        (
            "environment.bindings",
            tool(),
            Box::new(|s| {
                s.environment.bindings.push(crate::policy::EnvBinding {
                    name: "TERM".into(),
                    value: crate::policy::EnvValue::Native(NativeString::Text("dumb".into())),
                });
            }),
        ),
        (
            "launch",
            tool(),
            Box::new(|s| {
                s.launch = Some(LaunchSnapshot {
                    state_var: None,
                    home_is_state: false,
                    state_subdirs: Vec::new(),
                    credentials: Vec::new(),
                    state_discard: None,
                });
            }),
        ),
    ];
    for (expected, mut snapshot, mutate) in cases {
        assert_eq!(field(&snapshot), None, "{expected}: the base passes");
        mutate(&mut snapshot);
        let refusal = not_carried(&snapshot).unwrap_or_else(|| panic!("{expected} passed"));
        assert_eq!(refusal.field, expected, "{}", refusal.detail);
        assert!(
            refusal.reason().starts_with(REASON_VM_NOT_CARRIED),
            "{}",
            refusal.reason()
        );
    }
}

/// The host's own environment never reaches the guest: a host `TERM`, or a
/// `LANG` other than the guest's, is a binding the guest jail would not
/// apply.
#[test]
fn host_environment_values_the_guest_does_not_have_refuse() {
    let host = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.as_bytes().to_vec())
        }
    };
    let delta = || PolicyDelta {
        limits: wall(60),
        ..PolicyDelta::default()
    };
    for (pairs, carried) in [
        (&[("LANG", "C.UTF-8")][..], true),
        (&[][..], false),
        (&[("LANG", "en_US.UTF-8")][..], false),
        (
            &[("LANG", "C.UTF-8"), ("TERM", "xterm-256color")][..],
            false,
        ),
        (&[("LANG", "C.UTF-8"), ("TZ", "Europe/Paris")][..], false),
    ] {
        let snapshot = resolved_with(ProfileName::Tool, &host(pairs), delta()).snapshot;
        assert_eq!(
            field(&snapshot).as_deref(),
            (!carried).then_some("environment.bindings"),
            "{pairs:?}"
        );
    }
}

#[test]
fn the_launch_group_carries_vault_credentials_only() {
    let staged = |mode: &str| {
        format!(
            "name = \"svc\"\njail = \"agent\"\n[credentials.cfg]\nmode = \"{mode}\"\nsource = \
             \"/secrets/cfg\"\ndest = \"cfg.json\"\n"
        )
    };
    for (text, expected) in [
        (staged("copy_rw"), "launch.credentials.cfg.mode"),
        (staged("bind_ro"), "launch.credentials.cfg.mode"),
        (
            VAULT_LAUNCH.replace("env = \"API_TOKEN\"", "binaries = [\"/usr/bin/curl\"]"),
            "launch.credentials.api.token.vault.binaries",
        ),
        (
            VAULT_LAUNCH.replace("name = \"svc\"", "name = \"svc\"\nstate_var = \"SVC_HOME\""),
            "launch.state_var",
        ),
        (
            VAULT_LAUNCH.replace("name = \"svc\"", "name = \"svc\"\nhome_is_state = true"),
            "launch.home_is_state",
        ),
        (
            VAULT_LAUNCH.replace(
                "name = \"svc\"",
                "name = \"svc\"\nstate_subdirs = [\"cache\"]",
            ),
            "launch.state_subdirs",
        ),
        (
            format!("{VAULT_LAUNCH}\n[environment]\nSVC_MODE = \"quiet\"\n"),
            "environment.bindings",
        ),
    ] {
        let snapshot = agent_with_launch(&text);
        let refusal = not_carried(&snapshot).unwrap_or_else(|| panic!("{text} passed"));
        assert_eq!(refusal.field, expected, "{text}");
    }
    // Refresh and persistent state, set on the snapshot directly.
    let mut refreshed = agent_with_launch(VAULT_LAUNCH);
    refreshed.launch.as_mut().unwrap().credentials[0]
        .vault
        .as_mut()
        .unwrap()
        .refresh = Some(
        serde_json::from_value(serde_json::json!({
            "token_url": "https://auth.example.com/token", "client_id": "svc"
        }))
        .unwrap(),
    );
    assert_eq!(
        field(&refreshed).as_deref(),
        Some("launch.credentials.api.token.vault.refresh")
    );
    let mut persistent = agent_with_launch(VAULT_LAUNCH);
    persistent.launch.as_mut().unwrap().state_discard = Some(Vec::new());
    assert_eq!(field(&persistent).as_deref(), Some("launch.state_discard"));
}

/// A TLS-only grant crosses without its port, so the guest records it
/// TLS-only too; an explicit port crosses as written. The carried shape
/// re-resolves exactly these spellings, so the agent shape above passing is
/// the proof they reproduce the snapshot.
#[test]
fn tls_only_rules_cross_without_their_port() {
    let snapshot = agent();
    assert_eq!(
        snapshot.network.allow,
        ["api.example.com:443", "plain.example.com:8080"]
    );
    assert_eq!(snapshot.network.tls_only, ["api.example.com:443"]);
    assert_eq!(
        guest_allow_hosts(&snapshot.network),
        ["api.example.com", "plain.example.com:8080"]
    );
    let explicit = crate::policy::NetworkSnapshot {
        tls_only: Vec::new(),
        ..snapshot.network.clone()
    };
    assert_eq!(
        guest_allow_hosts(&explicit),
        ["api.example.com:443", "plain.example.com:8080"]
    );
}

#[test]
fn not_carried_reasons_are_in_the_reason_code_alphabet() {
    let refusal = NotCarried::new("launch.credentials.API.Key/x.mode", "why");
    assert_eq!(
        refusal.reason(),
        "vm:not-carried:launch.credentials.api.key-x.mode"
    );
    assert!(
        refusal
            .reason()
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:.-".contains(&b))
    );
    assert!(
        refusal
            .message()
            .contains("`launch.credentials.API.Key/x.mode`")
    );
}

#[test]
fn build_and_none_refuse_with_their_own_reasons() {
    let build = snapshot(
        ProfileName::Build,
        PolicyDelta {
            limits: wall(60),
            ..PolicyDelta::default()
        },
    );
    assert_eq!(
        policy_refusal(&build).unwrap().0,
        "vm:build-profile-refuses-the-live-share"
    );
    let none = snapshot(
        ProfileName::None,
        PolicyDelta {
            limits: wall(60),
            ..PolicyDelta::default()
        },
    );
    assert_eq!(
        policy_refusal(&none).unwrap().0,
        "vm:profile-unsupported:tool-and-agent-only"
    );
    assert!(
        not_carried_hint("limits.wall")
            .unwrap()
            .contains("--limit wall")
    );
}

// ---------------------------------------------------------------------------
// D2: the probe
// ---------------------------------------------------------------------------

fn platform(data_dir: &Path) -> VmPlatform {
    VmPlatform {
        data_dir: data_dir.to_path_buf(),
        install: Install {
            root: data_dir.join("install"),
            manifest: image::ImageManifest {
                source_sha256: Default::default(),
                status: "prepared".into(),
                disk_sha256: "d".repeat(64),
                helper_sha256: "h".repeat(64),
                custodian_sha256: "c".repeat(64),
                seed_sha256: "s".repeat(64),
                guest_program_catalog_sha256: None,
            },
        },
    }
}

#[test]
fn the_client_refuses_an_install_that_is_not_prepared_without_hashing_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut install = platform(dir.path()).install;
    // No artifact exists at all: a client that hashed would refuse on that.
    VmPlatform::from_install(dir.path(), install.clone()).expect("a prepared manifest is enough");
    install.manifest.status = "preparing".into();
    let error = VmPlatform::from_install(dir.path(), install).expect_err("not prepared");
    assert!(
        error.to_string().contains("the manifest is not `prepared`"),
        "{error}"
    );
}

fn request(snapshot: PolicySnapshot) -> PlanRequest {
    let requirements = crate::capability::requirements(&snapshot);
    PlanRequest {
        guest_program: None,
        snapshot,
        requirements,
    }
}

/// Current installed-image probes plus the two separately derived admissions,
/// in the table's order. Their schemas and source records are checked below.
const LIVE_MEASURED: [&str; 12] = [
    "limit:wall",
    "limit:pids",
    "limit:mem",
    "filesystem_containment",
    "network_none",
    "tree_termination",
    "closed_set_observation",
    "syscall_filter",
    "protected_coverage:existing_and_root",
    "network_proxy",
    "execution_boundary",
    "credential_staging",
];

/// Decision D2: exactly the requirements the live phase measured answer
/// available, with their row's time and pointer. Every requirement of a
/// default `tool` or `agent` plan is among them, so such a plan passes
/// probing; any other row of a carried policy is `vm:not-measured`.
#[test]
fn only_the_live_phase_measurements_answer_available() {
    let listed: Vec<&str> = GUEST_MEASUREMENTS
        .iter()
        .map(|row| row.requirement)
        .collect();
    assert_eq!(listed, LIVE_MEASURED);
    let platform = measured_platform();
    let owner = platform
        .owner_identity()
        .expect("VM supervisor is a macOS process");
    assert_eq!(owner.pid, std::process::id());
    for snapshot in [tool(), agent()] {
        let plan = request(snapshot);
        let rows = platform.probe(&plan);
        assert_eq!(rows.len(), plan.requirements.len());
        for row in &rows {
            match GUEST_MEASUREMENTS
                .iter()
                .find(|measured| measured.requirement == row.name)
            {
                Some(measured) => {
                    assert!(row.satisfies(), "{row:?}");
                    assert_eq!(row.reason_code.as_deref(), Some("ok"));
                    assert_eq!(row.measured_at.as_deref(), Some(measured.measured_at));
                    assert_eq!(row.evidence_ref.as_deref(), Some(measured.record));
                }
                None => {
                    assert!(!row.satisfies(), "{row:?}");
                    assert_eq!(
                        row.reason_code.as_deref(),
                        Some(format!("{REASON_VM_NOT_MEASURED}{}", row.name).as_str())
                    );
                    assert_eq!(row.measured_at, None, "never invented: {row:?}");
                    assert_eq!(row.evidence_ref, None);
                }
            }
        }
        let tree = rows
            .iter()
            .find(|row| row.name == "tree_termination")
            .expect("every plan requires tree termination");
        assert!(tree.satisfies(), "measured on 2026-11-15: {tree:?}");
        assert!(
            rows.iter().all(Capability::satisfies),
            "a default plan passes probing: {rows:?}"
        );
    }
    let plan = request(tool());
    assert!(
        platform
            .probe(&plan)
            .iter()
            .any(|row| row.name == "network_none" && row.satisfies())
    );
}

fn measured_platform() -> VmPlatform {
    let mut result = platform(Path::new("/unused"));
    result.install.manifest.disk_sha256 = GUEST_MEASURED_DISK_SHA256.into();
    result.install.manifest.seed_sha256 = GUEST_MEASURED_SEED_SHA256.into();
    result
}

#[test]
fn measured_guest_identity_is_required_before_any_capability_is_available() {
    let mut required = tool();
    required.limits.mem = Some(LimitCeiling {
        value: (512 * 1024 * 1024).to_string(),
        required: true,
    });
    let plans = [
        request(tool()),
        request(required),
        request(agent_with_launch(VAULT_LAUNCH)),
    ];
    for plan in &plans {
        let platform = measured_platform();
        assert!(platform.probe(plan).iter().all(Capability::satisfies));
        // Signing host helpers again changes their signatures, not guest bytes.
        let mut resigned = platform.clone();
        resigned.install.manifest.helper_sha256 = "a".repeat(64);
        resigned.install.manifest.custodian_sha256 = "b".repeat(64);
        assert!(resigned.probe(plan).iter().all(Capability::satisfies));
        for (disk, seed) in [(false, true), (true, false), (false, false)] {
            let mut other = platform.clone();
            if !disk {
                other.install.manifest.disk_sha256 = "0".repeat(64);
            }
            if !seed {
                other.install.manifest.seed_sha256 = "0".repeat(64);
            }
            let rows = other.probe(plan);
            assert!(!rows.is_empty());
            assert!(rows.iter().all(|row| !row.satisfies()
                && row.reason_code.as_deref()
                    == Some(format!("{REASON_VM_NOT_MEASURED}{}", row.name).as_str())
                && row.measured_at.is_none()
                && row.evidence_ref.is_none()));
        }
    }
    // Admission does not invent the still unmeasured swap requirement.
    let mut swap = tool();
    swap.limits.swap = Some(LimitCeiling {
        value: "0".into(),
        required: true,
    });
    assert!(
        measured_platform()
            .probe(&request(swap))
            .iter()
            .any(|row| row.name == "limit:swap" && !row.satisfies())
    );
}

fn native_measured_platform() -> VmPlatform {
    let mut result = platform(Path::new("/unused"));
    result.install.manifest.disk_sha256 = NATIVE_GUEST_MEASURED_DISK_SHA256.into();
    result.install.manifest.seed_sha256 = NATIVE_GUEST_MEASURED_SEED_SHA256.into();
    result.install.manifest.guest_program_catalog_sha256 =
        Some(NATIVE_PROGRAM_ADMISSION.catalog_sha256.into());
    result
}

#[test]
fn second_measured_image_has_its_own_rows_and_mixed_images_have_none() {
    let measured = native_measured_platform();
    for snapshot in [tool(), agent(), agent_with_launch(VAULT_LAUNCH)] {
        let plan = request(snapshot);
        for row in measured.probe(&plan) {
            assert!(row.satisfies(), "{row:?}");
            let proof = NATIVE_GUEST_MEASUREMENTS
                .iter()
                .find(|item| item.requirement == row.name)
                .unwrap();
            assert_eq!(row.evidence_ref.as_deref(), Some(proof.record));
            assert_eq!(row.measured_at.as_deref(), Some(proof.measured_at));
        }
        for (disk, seed) in [
            (
                GUEST_MEASURED_DISK_SHA256,
                NATIVE_GUEST_MEASURED_SEED_SHA256,
            ),
            (
                NATIVE_GUEST_MEASURED_DISK_SHA256,
                GUEST_MEASURED_SEED_SHA256,
            ),
        ] {
            let mut mixed = measured.clone();
            mixed.install.manifest.disk_sha256 = disk.into();
            mixed.install.manifest.seed_sha256 = seed.into();
            assert!(
                mixed
                    .probe(&plan)
                    .iter()
                    .all(|row| !row.satisfies() && row.evidence_ref.is_none())
            );
        }
    }
}

#[test]
fn superseded_intermediate_images_no_longer_admit_literal_or_native_runs() {
    for version in [
        "native-v2",
        "native-v4",
        "native-v5",
        "native-v6",
        "native-v7",
    ] {
        let bundle = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../docs/benchmarks/jail/results/macos-vm-admission-2026-11-15/{version}"
        ));
        let image: Value =
            serde_json::from_slice(&std::fs::read(bundle.join("raw-vault/image.json")).unwrap())
                .unwrap();
        let old_disk = image["disk_sha256"].as_str().unwrap();
        let old_seed = image["seed_sha256"].as_str().unwrap();
        assert_ne!(old_disk, NATIVE_GUEST_MEASURED_DISK_SHA256);
        assert_ne!(old_seed, NATIVE_GUEST_MEASURED_SEED_SHA256);
        let old_catalog_sha256 = image["guest_program_catalog_sha256"].as_str().unwrap();
        let catalog = crate::guest_program::Catalog::parse(
            &std::fs::read(bundle.join("image/guest-program-catalog.json")).unwrap(),
            old_catalog_sha256,
        )
        .unwrap();
        let entry = catalog
            .entries
            .into_iter()
            .find(|entry| {
                crate::guest_program::sha256(entry.id.as_bytes())
                    == NATIVE_PROGRAM_ADMISSION.entry_id_sha256
            })
            .unwrap();
        for (disk, seed) in [
            (old_disk, old_seed),
            (old_disk, NATIVE_GUEST_MEASURED_SEED_SHA256),
            (NATIVE_GUEST_MEASURED_DISK_SHA256, old_seed),
        ] {
            let mut platform = native_measured_platform();
            platform.install.manifest.disk_sha256 = disk.into();
            platform.install.manifest.seed_sha256 = seed.into();
            for snapshot in [tool(), agent(), agent_with_launch(VAULT_LAUNCH)] {
                assert!(
                    platform
                        .probe(&request(snapshot))
                        .iter()
                        .all(|row| { !row.satisfies() && row.evidence_ref.is_none() })
                );
            }
            let program = crate::guest_program::GuestProgram::new(
                old_catalog_sha256.into(),
                disk.into(),
                seed.into(),
                entry.clone(),
            )
            .unwrap();
            assert!(!native_program_admitted(
                &platform.install.manifest,
                &program
            ));
        }
    }
}

#[test]
fn native_admission_requires_every_pin_before_source_staging() {
    let (_dir, mut context, args) = native::tests::context();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bytes = std::fs::read(root.join("docs/benchmarks/jail/results/macos-vm-admission-2026-11-15/native-v8/image/guest-program-catalog.json")).unwrap();
    let mut platform = native_measured_platform();
    platform.data_dir = context.env_settings.data_dir.clone().unwrap();
    platform.install.root = context.cwd.parent().unwrap().join("install");
    std::fs::write(
        platform
            .install
            .root
            .join("image/guest-program-catalog.json"),
        bytes,
    )
    .unwrap();
    context.platform = Box::new(platform.clone());
    let plan = crate::supervisor::resolve_plan(&context, &args).unwrap();
    let request = PlanRequest {
        guest_program: plan.guest_program,
        snapshot: plan.resolved.snapshot,
        requirements: plan.resolved.requirements,
    };
    let program = request.guest_program.as_ref().unwrap();
    assert!(native_program_admitted(&platform.install.manifest, program));
    assert!(platform.probe(&request).iter().all(Capability::satisfies));
    for index in 0..9 {
        let mut altered = platform.clone();
        let mut request = request.clone();
        let program = request.guest_program.as_mut().unwrap();
        match index {
            0 => altered.install.manifest.disk_sha256 = GUEST_MEASURED_DISK_SHA256.into(),
            1 => altered.install.manifest.seed_sha256 = GUEST_MEASURED_SEED_SHA256.into(),
            2 => altered.install.manifest.guest_program_catalog_sha256 = None,
            3 => program.disk_sha256 = GUEST_MEASURED_DISK_SHA256.into(),
            4 => program.seed_sha256 = GUEST_MEASURED_SEED_SHA256.into(),
            5 => program.catalog_sha256 = "0".repeat(64),
            6 => program.entry.id.push_str("-other"),
            7 => program.entry.profile_sha256 = "0".repeat(64),
            8 => program.entry.executable_sha256 = "0".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            !native_program_admitted(&altered.install.manifest, program),
            "pin {index}"
        );
        assert!(
            altered.probe(&request).iter().all(|row| !row.satisfies()),
            "pin {index}"
        );
    }
    let old = measured_platform();
    assert!(old.probe(&request).iter().all(|row| !row.satisfies()));
    let mut narrowing = request.clone();
    narrowing
        .snapshot
        .filesystem
        .deny_read
        .push(crate::policy::PathRef::host(NativeString::Text(
            "/private".into(),
        )));
    assert!(
        platform
            .probe(&narrowing)
            .iter()
            .all(|row| row.reason_code.as_deref() == Some("vm:not-carried:filesystem.deny_read"))
    );
    let mut owner_loss = request.clone();
    owner_loss.snapshot.lifetime_boundary = Some(crate::policy::LifetimeBoundary::KernelBound);
    owner_loss.requirements = crate::capability::requirements(&owner_loss.snapshot);
    let rows = platform.probe(&owner_loss);
    assert!(rows.iter().all(|row| !row.satisfies()));
    assert_eq!(
        rows.iter()
            .find(|row| row.name == "owner_loss_termination")
            .unwrap()
            .reason_code
            .as_deref(),
        Some(REASON_VM_OWNER_LOSS_NOT_PROVIDED)
    );
    assert!(!platform.data_dir.join("attempts").exists());
}

/// Follow each schema's evidence linkage, rather than treating every derived
/// admission as a capabilities.py row or trusting a stored PASS alone.
#[test]
fn every_measurement_row_resolves_in_its_record() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (subdir, cap_path, raw_path, disk, seed, table) in [
        (
            "",
            "handshake-capabilities/capabilities.json",
            "handshake-raw-credential",
            GUEST_MEASURED_DISK_SHA256,
            GUEST_MEASURED_SEED_SHA256,
            GUEST_MEASUREMENTS,
        ),
        (
            "native-v8",
            "capabilities/capabilities.json",
            "raw-vault",
            NATIVE_GUEST_MEASURED_DISK_SHA256,
            NATIVE_GUEST_MEASURED_SEED_SHA256,
            NATIVE_GUEST_MEASUREMENTS,
        ),
    ] {
        assert_eq!(
            table.iter().map(|row| row.requirement).collect::<Vec<_>>(),
            LIVE_MEASURED
        );
        let bundle = root
            .join("docs/benchmarks/jail/results/macos-vm-admission-2026-11-15")
            .join(subdir);
        let read = |path: &Path| -> (Vec<u8>, serde_json::Value) {
            let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let record = serde_json::from_slice(&bytes).unwrap();
            (bytes, record)
        };
        let (cap_bytes, capabilities) = read(&bundle.join(cap_path));
        let (raw_bytes, raw) = read(&bundle.join(raw_path).join("raw-inputs.json"));
        let (_, measured_image) = read(&bundle.join(raw_path).join("image.json"));
        assert_eq!(measured_image["disk_sha256"], disk);
        assert_eq!(measured_image["seed_sha256"], seed);
        assert_eq!(capabilities["status"]["disk_sha256"], disk);
        assert_eq!(capabilities["status"]["seed_sha256"], seed);
        for row in table {
            let (path, pointer) = row.record.split_once('#').expect("path#pointer");
            let (_, record) = read(&root.join(path));
            assert_eq!(
                record.pointer(pointer),
                Some(&serde_json::Value::Bool(true)),
                "{}",
                row.record
            );
            let entry_pointer = pointer.strip_suffix("/verdict").expect("verdict pointer");
            assert_eq!(entry_pointer, format!("/measurements/{}", row.requirement));
            let entry = record.pointer(entry_pointer).unwrap();
            assert_eq!(entry["measured_at"], row.measured_at, "{}", row.record);
            assert!(!entry["attempt_id"].as_str().unwrap().is_empty());
            match record["schema"].as_str().unwrap() {
                "ukai.vm.capabilities/2" => {
                    let capability = entry["capability"].as_str().expect("capability name");
                    let attempt = &record["results"][capability];
                    assert_eq!(attempt["started_at"], row.measured_at);
                    assert_eq!(attempt["attempt_id"], entry["attempt_id"]);
                    assert_eq!(record["summary"][capability], true);
                    assert_eq!(record["summary"]["outcome"], "PASS");
                }
                "ukai.vm.execution-boundary-measurement/1" => {
                    assert_eq!(row.requirement, "execution_boundary");
                    assert_eq!(record["outcome"], "PASS");
                    assert_eq!(
                        record["source_record_sha256"],
                        format!("{:x}", sha2::Sha256::digest(&cap_bytes))
                    );
                    let names = ["pids", "mem", "tree_termination", "tree_wall"];
                    let attempts: Vec<_> = names
                        .iter()
                        .map(|name| capabilities["results"][name]["attempt_id"].clone())
                        .collect();
                    assert_eq!(entry["attempt_ids"], serde_json::json!(attempts));
                    assert_eq!(entry["attempt_id"], attempts[0]);
                    assert_eq!(
                        entry["measured_at"],
                        capabilities["results"]["pids"]["started_at"]
                    );
                    let facts = record["facts"].as_object().unwrap();
                    assert!(!facts.is_empty() && facts.values().all(|value| value == true));
                    assert_eq!(record["status"], capabilities["status"]);
                }
                "ukai.vm.credential-staging-measurement/2" => {
                    assert_eq!(row.requirement, "credential_staging");
                    assert_eq!(record["outcome"], "PASS");
                    assert_eq!(record["qualified"], false);
                    assert_eq!(
                        record["source_record_sha256"],
                        format!("{:x}", sha2::Sha256::digest(&raw_bytes))
                    );
                    assert_eq!(entry["attempt_id"], raw["record"]["attempt_id"]);
                    assert_eq!(
                        entry["guest_attempt_id"],
                        raw["record"]["receipt"]["attempt_id"]
                    );
                    assert_eq!(entry["measured_at"], raw["record"]["started_at"]);
                    assert_eq!(record["installation"]["image"], measured_image);
                    assert_eq!(
                        record["compatibility"]["required_guest_image"],
                        serde_json::json!({
                            "disk_sha256": disk,
                            "seed_sha256": seed,
                        })
                    );
                    assert_eq!(
                        raw["record"]["ready"]["guest_contracts"],
                        if subdir.is_empty() {
                            serde_json::json!({
                                "secret_revocation": protocol::SECRET_REVOCATION_CONTRACT,
                                "journal_export": protocol::JOURNAL_EXPORT_CONTRACT,
                            })
                        } else {
                            serde_json::json!({
                                "secret_revocation": protocol::SECRET_REVOCATION_CONTRACT,
                                "journal_export": protocol::JOURNAL_EXPORT_CONTRACT,
                                "native_program": protocol::NATIVE_PROGRAM_CONTRACT,
                                // Current component evidence advertises managed /3;
                                // this does not qualify native workload sampling.
                                "sampled_exposure": protocol::SAMPLED_EXPOSURE_CONTRACT,
                            })
                        }
                    );
                    let facts = record["recomputed_facts"].as_object().unwrap();
                    assert!(!facts.is_empty() && facts.values().all(|value| value == true));
                    assert!(
                        entry["not_measured"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|value| value == "normal installed-client host-source watch")
                    );
                }
                schema => panic!("unrecognized measurement schema {schema}"),
            }
        }
    }
}

#[test]
fn native_admission_pins_resolve_to_the_exact_retained_component_evidence() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (path, pointer) = NATIVE_PROGRAM_ADMISSION_RECORD.split_once('#').unwrap();
    let path = root.join(path);
    let bundle = path.parent().unwrap();
    let admission: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(admission["schema"], "ukai.vm.native-program-admission/1");
    assert_eq!(admission.pointer(pointer).unwrap(), "PASS");
    assert_eq!(
        admission["required_guest_image"],
        serde_json::json!({
            "disk_sha256": NATIVE_GUEST_MEASURED_DISK_SHA256,
            "seed_sha256": NATIVE_GUEST_MEASURED_SEED_SHA256,
        })
    );
    let pin = &NATIVE_PROGRAM_ADMISSION;
    assert_eq!(
        admission["native_program"],
        serde_json::json!({
            "catalog_sha256": pin.catalog_sha256,
            "entry_id_sha256": pin.entry_id_sha256,
            "profile_sha256": pin.profile_sha256,
            "executable_sha256": pin.executable_sha256,
        })
    );
    assert_eq!(
        admission["qualification"],
        serde_json::json!({
            "native_vendor": false, "k113": false, "release": false, "new_host_runtime": false,
        })
    );
    assert_eq!(
        admission["compatibility"]["older_or_changed_guest_images_inherit_admission"],
        false
    );
    let evidence = admission["evidence"].as_object().unwrap();
    assert_eq!(evidence.len(), 24);
    let mut files = BTreeMap::new();
    for (name, entry) in evidence {
        let relative = Path::new(entry["path"].as_str().unwrap());
        assert!(
            relative
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
            "{name}"
        );
        let bytes = std::fs::read(bundle.join(relative)).unwrap();
        assert_eq!(
            entry["sha256"],
            crate::guest_program::sha256(&bytes),
            "{name}"
        );
        files.insert(name.as_str(), bytes);
    }
    let json = |name: &str| -> Value { serde_json::from_slice(files.get(name).unwrap()).unwrap() };
    let catalog =
        crate::guest_program::Catalog::parse(files.get("catalog").unwrap(), pin.catalog_sha256)
            .unwrap();
    let entry = catalog
        .entries
        .iter()
        .find(|entry| crate::guest_program::sha256(entry.id.as_bytes()) == pin.entry_id_sha256)
        .unwrap();
    assert_eq!(entry.profile_sha256, pin.profile_sha256);
    assert_eq!(entry.executable_sha256, pin.executable_sha256);
    let profile = crate::launch_profile::bundled_profile(&entry.alias).unwrap();
    assert_eq!(
        files.get("bundled_profile").unwrap().as_slice(),
        profile.as_bytes()
    );
    assert_eq!(
        crate::guest_program::sha256(profile.as_bytes()),
        pin.profile_sha256
    );
    for name in ["prepared_image", "signed_image_manifest"] {
        let image = json(name);
        assert_eq!(image["disk_sha256"], NATIVE_GUEST_MEASURED_DISK_SHA256);
        assert_eq!(image["seed_sha256"], NATIVE_GUEST_MEASURED_SEED_SHA256);
        assert_eq!(image["guest_program_catalog_sha256"], pin.catalog_sha256);
    }
    let package = json("package");
    assert_eq!(
        admission["compatibility"]["measured_host_source"],
        package["source_revision"]
    );
    assert_eq!(
        package["source_revision"],
        "934ad33acc5efb2843de8ee9fd5ea3181b6790b3"
    );
    assert_eq!(
        package["image"]["ukai_jail_version"]["build"]["dirty"],
        false
    );
    let inputs = json("program_inputs");
    assert_eq!(inputs["identity_before"]["image"], package["image"]);
    let measurement = &admission["measurements"]["native_program"];
    assert_eq!(measurement["attempt_id"], inputs["record"]["attempt_id"]);
    assert_eq!(
        measurement["guest_attempt_id"],
        inputs["record"]["receipt"]["attempt_id"]
    );
    assert_eq!(admission["measured_at"], inputs["record"]["started_at"]);
    for name in [
        "program_measurement",
        "program_result",
        "program_offline_replay",
    ] {
        let report = json(name);
        assert_eq!(
            report["inputs_sha256"],
            evidence["program_inputs"]["sha256"]
        );
        assert_eq!(report["qualified"], false);
        if name != "program_measurement" {
            assert_eq!(report["outcome"], "PASS");
            let facts = report["facts"].as_object().unwrap();
            assert!(!facts.is_empty() && facts.values().all(|value| value == true));
            assert_eq!(measurement["program_binding_facts"], facts.len());
        }
    }
    let staging = json("generic_credential_staging");
    assert_eq!(
        staging["source_record_sha256"],
        evidence["generic_vault_inputs"]["sha256"]
    );
    assert_eq!(
        staging["compatibility"]["required_guest_image"],
        admission["required_guest_image"]
    );
    assert_eq!(staging["outcome"], "PASS");
    assert_eq!(staging["qualified"], false);
    let facts = staging["recomputed_facts"].as_object().unwrap();
    assert!(!facts.is_empty() && facts.values().all(|value| value == true));
    assert_eq!(measurement["vault_staging_facts"], facts.len());
}

/// The table is the one source of `available`: a listed requirement answers
/// available with the record's own time and pointer, and nothing else does.
#[test]
fn a_measured_record_is_the_only_way_to_available() {
    let table = [GuestMeasurement {
        requirement: "limit:wall",
        record: "fixture/capabilities.json#/results/wall",
        measured_at: "2026-11-04T09:00:00Z",
    }];
    let plan = request(tool());
    let rows = probe_rows(&plan.requirements, None, &table);
    let wall = rows.iter().find(|row| row.name == "limit:wall").unwrap();
    assert!(wall.satisfies());
    assert_eq!(wall.reason_code.as_deref(), Some("ok"));
    assert_eq!(wall.measured_at.as_deref(), Some("2026-11-04T09:00:00Z"));
    assert_eq!(
        wall.evidence_ref.as_deref(),
        Some("fixture/capabilities.json#/results/wall")
    );
    assert_eq!(wall.mechanism.as_deref(), Some(GUEST_MECHANISM));
    assert!(
        rows.iter()
            .filter(|row| row.name != "limit:wall")
            .all(|row| !row.satisfies())
    );
    // A policy `--vm` cannot carry refuses every row with its field, the
    // measured one included; owner loss keeps its own reason.
    let mut lifetime = tool();
    lifetime.lifetime_boundary = Some(crate::policy::LifetimeBoundary::KernelBound);
    let plan = request(lifetime);
    let refusal = policy_refusal(&plan.snapshot).map(|(reason, _)| reason);
    let rows = probe_rows(&plan.requirements, refusal, &table);
    for row in &rows {
        assert!(!row.satisfies(), "{row:?}");
        let expected = if row.name == "owner_loss_termination" {
            REASON_VM_OWNER_LOSS_NOT_PROVIDED
        } else {
            "vm:not-carried:lifetime_boundary"
        };
        assert_eq!(row.reason_code.as_deref(), Some(expected), "{row:?}");
    }
    let mut denied = tool();
    denied
        .filesystem
        .deny_read
        .push(crate::policy::PathRef::host(NativeString::Text(
            "/work/private".into(),
        )));
    let rows = platform(Path::new("/unused")).probe(&request(denied));
    assert!(
        rows.iter().all(|row| {
            row.reason_code.as_deref() == Some("vm:not-carried:filesystem.deny_read")
        })
    );
}

// ---------------------------------------------------------------------------
// D3: the vault hand-off
// ---------------------------------------------------------------------------

fn prepared_plan(
    snapshot: PolicySnapshot,
    launch_name: Option<&str>,
    vault: Vec<Arc<crate::vault::Secret>>,
) -> PreparedPlan {
    PreparedPlan {
        guest_launch: None,
        attempt_id: "att_00000000-0000-4000-8000-000000000001".into(),
        attempt_dir: PathBuf::from("/unused-attempt"),
        request: request(snapshot),
        argv: vec![b"/bin/true".to_vec()],
        prepare_deadline: ContinuousDeadline::after(Duration::from_secs(30)),
        workspace: PathBuf::from("/work"),
        // A config dir holding a different launch file: never read.
        config_dir: PathBuf::from("/unused-config"),
        launch_name: launch_name.map(str::to_owned),
        launch: Some(crate::credentials::LaunchHandoff {
            vault,
            vendor_state: None,
            binds: Vec::new(),
        }),
        proxy: None,
        pinned_roots: Vec::new(),
        exec_pins: Vec::new(),
    }
}

/// The secret the supervisor would have staged for the snapshot's first
/// credential, holding `value`.
fn staged_secret(snapshot: &PolicySnapshot, value: &[u8]) -> Arc<crate::vault::Secret> {
    let credential = &snapshot.launch.as_ref().unwrap().credentials[0];
    Arc::new(
        crate::vault::Secret::new(
            credential.id.clone(),
            credential.vault.clone().unwrap(),
            value.to_vec(),
        )
        .unwrap(),
    )
}

/// The value is the staged secret's (its source does not even exist), the
/// declaration is generated from the snapshot, and the guest's loader reads
/// it back as exactly the snapshot's credentials at the staging path.
#[test]
fn the_vault_hand_off_is_the_staged_secret_and_the_snapshot() {
    let snapshot = agent_with_launch(VAULT_LAUNCH);
    assert!(!Path::new("/secrets/api-token").exists());
    let secret = staged_secret(&snapshot, b"s3cret-value");
    let plan = prepared_plan(snapshot.clone(), Some("svc"), vec![secret]);
    let VaultLaunch {
        declaration,
        parsed: loaded,
        secrets,
    } = vault_launch(&plan).expect("the hand-off");
    let launch = declaration.expect("a declaration");
    assert_eq!(launch.name, "svc");
    assert_eq!(
        secrets,
        [protocol::SecretEntry {
            id: "api.token".into(),
            data: protocol::encode_data(b"s3cret-value"),
        }]
    );
    let parsed = crate::launch_profile::parse(
        &launch.toml,
        "svc",
        crate::launch_profile::LaunchSource::Bundled,
        None,
    )
    .expect("the guest's loader accepts it");
    let declared = &snapshot.launch.as_ref().unwrap().credentials[0];
    assert_eq!(
        parsed.credentials,
        [CredentialDecl {
            source: NativeString::Text(format!("{GUEST_CREDENTIAL_ROOT}/api.token")),
            ..declared.clone()
        }]
    );
    assert_eq!(parsed.jail, ProfileName::Agent);
    assert_eq!(loaded.as_ref(), Some(&parsed), "the loader's own reading");
    assert!(!launch.toml.contains("/secrets/api-token"));
    assert!(!launch.toml.contains("s3cret"));
    // No credentials: no declaration, nothing staged.
    let plan = prepared_plan(agent(), Some("svc"), Vec::new());
    assert_eq!(vault_launch(&plan).unwrap(), VaultLaunch::default());
}

/// Every vault refusal: no staged value, a value the policy does not
/// declare, no launch name, a staged mode or a binding that slipped past
/// the carry rule. All of them before any contact (D3).
#[test]
fn vault_refusals_name_what_is_missing() {
    let snapshot = agent_with_launch(VAULT_LAUNCH);
    let secret = staged_secret(&snapshot, b"s3cret-value");
    let refusal = |plan: &PreparedPlan| vault_launch(plan).unwrap_err().message;
    let missing = refusal(&prepared_plan(snapshot.clone(), Some("svc"), Vec::new()));
    assert!(
        missing.contains("no value the supervisor staged"),
        "{missing}"
    );
    let other = Arc::new(
        crate::vault::Secret::new(
            "other".into(),
            snapshot.launch.as_ref().unwrap().credentials[0]
                .vault
                .clone()
                .unwrap(),
            b"x".to_vec(),
        )
        .unwrap(),
    );
    let extra = refusal(&prepared_plan(
        snapshot.clone(),
        Some("svc"),
        vec![secret.clone(), other.clone()],
    ));
    assert!(extra.contains("does not declare it"), "{extra}");
    let undeclared = refusal(&prepared_plan(agent(), Some("svc"), vec![other]));
    assert!(
        undeclared.contains("declares no credentials"),
        "{undeclared}"
    );
    for name in [None, Some("Not A Name")] {
        let unnamed = refusal(&prepared_plan(snapshot.clone(), name, vec![secret.clone()]));
        assert!(unnamed.contains("launch profile name"), "{unnamed}");
    }
    let mut staged_mode = snapshot.clone();
    staged_mode.launch.as_mut().unwrap().credentials[0].mode = CredentialMode::CopyRw;
    let staged = refusal(&prepared_plan(
        staged_mode,
        Some("svc"),
        vec![secret.clone()],
    ));
    assert!(staged.contains("copy_rw credential"), "{staged}");
    let mut bound = snapshot.clone();
    bound.launch.as_mut().unwrap().credentials[0]
        .vault
        .as_mut()
        .unwrap()
        .binaries = vec!["/usr/bin/curl".into()];
    let binaries = refusal(&prepared_plan(bound, Some("svc"), vec![secret]));
    assert!(binaries.contains("executable bindings"), "{binaries}");
}

/// D1 and D3 refuse before any contact: `prepare` reaches neither the share
/// preflight nor a serve when the policy or the vault refuses, and nothing
/// appears beneath the VM runtime directory.
#[test]
fn prepare_refuses_policy_and_vault_before_any_contact() {
    let data = tempfile::tempdir().unwrap();
    let platform = platform(data.path());
    let workspace = tempfile::tempdir().unwrap();
    // A symlink the share preflight would refuse: neither case reaches it.
    std::os::unix::fs::symlink("/etc/hosts", workspace.path().join("link")).unwrap();
    let mut denied = tool();
    denied
        .filesystem
        .deny_read
        .push(crate::policy::PathRef::host(NativeString::Text(
            "/work/private".into(),
        )));
    let snapshot = agent_with_launch(VAULT_LAUNCH);
    for (plan, expected) in [
        (
            prepared_plan(denied, None, Vec::new()),
            "filesystem.deny_read",
        ),
        (
            prepared_plan(snapshot, Some("svc"), Vec::new()),
            "no value the supervisor staged",
        ),
    ] {
        let plan = PreparedPlan {
            workspace: workspace.path().to_path_buf(),
            ..plan
        };
        let Err(error) = VmExecution::prepare(&platform, plan, Sinks { trace: None }, None) else {
            panic!("{expected}: prepared");
        };
        assert!(error.message.contains(expected), "{error}");
        assert!(!error.message.contains("symlinks"), "{error}");
        assert!(!vm_runtime_dir(data.path()).exists(), "{expected}");
    }
}

// ---------------------------------------------------------------------------
// D4: the serve
// ---------------------------------------------------------------------------

fn status(live_workspace: Option<&Path>, guest_nat: bool) -> protocol::FromControl {
    protocol::FromControl::Status {
        schema: protocol::SCHEMA_CONTROL.into(),
        boot_id: "vm-test".into(),
        warm: true,
        ready: false,
        attempt_live: false,
        kernel: None,
        disk_sha256: "d".repeat(64),
        helper_sha256: "h".repeat(64),
        custodian_sha256: "c".repeat(64),
        seed_sha256: "s".repeat(64),
        vsock_port: 1024,
        idle_seconds: 600,
        live_workspace: live_workspace.map(|path| path.display().to_string()),
        live_workspace_facts: None,
        guest_nat,
    }
}

/// A stand-in serve's control socket: bound after `delay`, answering one
/// `status` with `reply` (connections that send nothing, the listening
/// probes, are skipped).
fn fake_control(
    socket: PathBuf,
    delay: Duration,
    reply: protocol::FromControl,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {
                line.push(byte[0]);
            }
            if line.is_empty() {
                continue;
            }
            let _ = stream.write_all(&protocol::encode(&reply).unwrap());
            break;
        }
    })
}

/// Joins a [`fake_control`] stand-in. If the code under test never sent its
/// `status` (it refused before the status read, or a mutant skipped it),
/// the stand-in is first released with a request of its own, so the test
/// fails on its assertions rather than hanging in the join.
fn join_control(server: std::thread::JoinHandle<()>, socket: &Path) {
    let until = Instant::now() + Duration::from_secs(5);
    while !server.is_finished() && Instant::now() < until {
        let _ = control::control_round_trip_within(
            socket,
            protocol::ToControl::Status,
            Duration::from_millis(200),
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(server.is_finished(), "the stand-in serve never stopped");
    server.join().unwrap();
}

/// A stand-in `ukai-vm` program: a shell script with `body`.
fn serve_script(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("ukai-vm");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// H4: a serve spawned for this run is held to the reused serve's checks.
/// The race the review named: another run's serve, for another tree,
/// answers first.
#[test]
fn a_spawned_serve_gets_the_status_checks_of_a_reused_one() {
    let temp = common_temp();
    let (mine, theirs) = (temp.path().join("mine"), temp.path().join("theirs"));
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::create_dir_all(&theirs).unwrap();
    let script = serve_script(temp.path(), "exec /bin/sleep 2");
    let deadline = ContinuousDeadline::after(Duration::from_secs(20));
    for (answer, nat, expected) in [
        (status(Some(&theirs), false), false, Some("shares")),
        (status(Some(&mine), false), true, Some("NAT adapter")),
        (status(None, false), false, Some("staged attempts")),
        (
            protocol::FromControl::Stopping {
                schema: protocol::SCHEMA_CONTROL.into(),
            },
            false,
            Some("answered `status`"),
        ),
        (status(Some(&mine), true), true, None),
    ] {
        for spawned in [true, false] {
            let data = tempfile::tempdir().unwrap();
            let platform = platform(data.path());
            let socket = platform.control_socket();
            let server = fake_control(
                socket.clone(),
                Duration::from_millis(if spawned { 300 } else { 0 }),
                answer.clone(),
            );
            if !spawned {
                while !control::is_listening(&socket) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let mut ran = false;
            let result = platform.serve_with(&mine, nat, deadline, || {
                ran = true;
                Ok(script.clone())
            });
            assert_eq!(ran, spawned, "the program runs only without a serve");
            match expected {
                Some(text) => {
                    let error = result.unwrap_err();
                    assert!(
                        error.message.contains(text),
                        "{text} (spawned {spawned}): {error}"
                    );
                }
                None => assert_eq!(
                    result.unwrap_or_else(|error| panic!("spawned {spawned}: {error}")),
                    "vm-test",
                    "the checked serve's boot"
                ),
            }
            join_control(server, &socket);
        }
    }
}

/// A serve that dies before it answers is refused with what it wrote, kept
/// in a private file beneath the data directory.
#[test]
fn a_serve_that_exits_first_is_refused_with_its_stderr() {
    let temp = common_temp();
    let data = tempfile::tempdir().unwrap();
    let platform = platform(data.path());
    let script = serve_script(temp.path(), "echo 'ukai-vm: the image is gone' >&2; exit 3");
    let started = Instant::now();
    let error = platform
        .serve_with(
            temp.path(),
            false,
            ContinuousDeadline::after(Duration::from_secs(20)),
            || Ok(script.clone()),
        )
        .unwrap_err();
    assert!(error.message.contains("exited"), "{error}");
    assert!(error.message.contains("the image is gone"), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "noticed, not waited out"
    );
    let stderr = vm_runtime_dir(data.path()).join(SERVE_STDERR_FAILED);
    assert_eq!(
        std::fs::read_to_string(&stderr).unwrap(),
        "ukai-vm: the image is gone\n"
    );
    assert_eq!(
        std::fs::metadata(&stderr).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// The serve wait spends no more than the attempt's preparation budget.
#[test]
fn the_preparation_deadline_bounds_the_serve_wait() {
    let temp = common_temp();
    let data = tempfile::tempdir().unwrap();
    let platform = platform(data.path());
    let script = serve_script(temp.path(), "exec /bin/sleep 2");
    let started = Instant::now();
    let error = platform
        .serve_with(
            temp.path(),
            false,
            ContinuousDeadline::after(Duration::from_millis(200)),
            || Ok(script.clone()),
        )
        .unwrap_err();
    assert!(error.message.contains("no ukai-vm answered"), "{error}");
    assert!(error.message.contains("preparation budget"), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

/// A private temporary directory for a stand-in serve and its workspaces.
fn common_temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

/// A staged bind never crosses, and the generated declaration must read back
/// as the snapshot's own: a credential whose destination the guest's loader
/// would place elsewhere refuses before anything is sent.
#[test]
fn binds_and_declarations_the_loader_reads_differently_refuse() {
    use std::os::fd::OwnedFd;
    let snapshot = agent_with_launch(VAULT_LAUNCH);
    let secret = staged_secret(&snapshot, b"s3cret-value");
    let mut plan = prepared_plan(snapshot.clone(), Some("svc"), vec![secret.clone()]);
    let null: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    plan.launch
        .as_mut()
        .unwrap()
        .binds
        .push(crate::credentials::BindHandle {
            id: "cfg".into(),
            fd: Arc::new(null),
            dest: NativeString::Text("cfg.json".into()),
            identity: (0, 0),
        });
    let error = vault_launch(&plan).unwrap_err();
    assert!(
        error.message.contains("read-only credential binds"),
        "{error}"
    );
    let mut moved = snapshot;
    moved.launch.as_mut().unwrap().credentials[0].dest = NativeString::Text("elsewhere".into());
    let error = vault_launch(&prepared_plan(moved, Some("svc"), vec![secret])).unwrap_err();
    assert!(
        error
            .message
            .contains("reads the generated text back differently"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// D5 end to end: the supervisor settles a guest attempt with its facts
// ---------------------------------------------------------------------------

/// The K113 guest receipt (2026-11-03): a proxied, observed attempt. Read
/// at test time, so the evidence is no build input.
fn k113_guest() -> Value {
    let path = crate::test_evidence::k113_attempt().join("evidence/jail.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// A platform that runs its attempt "in a guest": the target exits at once,
/// the tree is verified, and the verified guest receipt is K113's.
struct GuestSim;

struct GuestPrepared;

struct GuestRunning;

impl Platform for GuestSim {
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Linux,
            arch: "aarch64".into(),
            kernel: "unknown: the guest reports its kernel at prepare".into(),
        }
    }
    fn state_identity(&self) -> PlatformIdentity {
        crate::platform::macos::MacosPlatform.identity()
    }
    fn owner_identity(&self) -> Option<crate::platform::OwnerIdentity> {
        crate::platform::macos::owner_identity()
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        plan.requirements
            .iter()
            .map(|requirement| Capability {
                name: requirement.to_string(),
                status: CapabilityStatus::Available,
                scope: CapabilityScope::Tree,
                mechanism: Some("simulation".into()),
                reason_code: Some("ok".into()),
                measured_at: Some(rfc3339_utc(SystemTime::now())),
                evidence_ref: None,
            })
            .collect()
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        Ok(Box::new(GuestPrepared))
    }
}

impl PreparedExecution for GuestPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: BoundaryKind::PidNamespace,
            verification_scope: VerificationScope::AttemptTree,
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: serde_json::Map::new(),
            }),
            process: None,
            backend: Some("ukai-vm".into()),
            backend_version: None,
        }
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, Box<ReleaseFailure>> {
        Ok(Box::new(GuestRunning))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown { tree: None })
    }
}

impl RunningExecution for GuestRunning {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        RunEvent::TargetExited { code: 0 }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        TreeObservation {
            tree_empty: Some(true),
            verified_at: None,
            verification_scope: VerificationScope::AttemptTree,
            integrity: Integrity::Verified,
        }
    }
    fn observer_summary(&mut self) -> Option<crate::observer::CoverageSummary> {
        None
    }
    fn guest_facts(&self) -> Option<GuestFacts> {
        guest_facts(&k113_guest(), &"5".repeat(64)).ok()
    }
}

/// D5 (K111): the settled host receipt the supervisor writes for a guest
/// attempt carries the guest receipt's network, observer, coverage, exec
/// observation and kernel, not `pending`, `attached: false` and an unknown
/// kernel; the run's summary prints them.
#[test]
fn the_supervisor_settles_a_guest_attempt_with_the_guest_facts() {
    use clap::Parser as _;
    let temp = common_temp();
    let root = temp.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let crate::cli::Command::Run(args) = crate::cli::Cli::parse_from([
        "ukai-jail",
        "run",
        "--profile",
        "agent",
        "--terminal",
        "detach",
        "--limit",
        "wall=60s",
        "--workspace",
        workspace.to_str().unwrap(),
        "--",
        "/bin/true",
    ])
    .command
    else {
        unreachable!()
    };
    let context = crate::supervisor::Context {
        platform: Box::new(GuestSim),
        env_settings: crate::config::EnvSettings {
            config_dir: Some(root.join("config")),
            data_dir: Some(root.join("data")),
            ..Default::default()
        },
        cwd: workspace.clone(),
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let report = crate::supervisor::run(&context, &args);
    assert_eq!(report.exit_code, 0, "{:?}", report.error);
    let receipt_path = report.receipt_path.expect("a receipt");
    let host: Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    let guest: Value = k113_guest();
    assert_eq!(host["phase"], "settled");
    for pointer in [
        "/platform/kernel",
        "/exec_observed",
        "/applied/network",
        "/applied/syscalls",
        "/observer",
        "/coverage",
    ] {
        assert_eq!(host.pointer(pointer), guest.pointer(pointer), "{pointer}");
    }
    assert_eq!(
        host["lifetime"]["native"]["details"]["guest_receipt"],
        "evidence/jail.json"
    );
    assert_eq!(
        host["lifetime"]["native"]["details"]["guest_carried"],
        serde_json::json!(GuestFacts::CARRIED)
    );
}

/// Two declared credentials, one staged: the other never borrows its value.
#[test]
fn every_declared_credential_needs_its_own_staged_value() {
    let two = format!(
        "{VAULT_LAUNCH}\n[credentials.second]\nmode = \"vault\"\nsource = \"/secrets/second\"\n\
         hosts = [\"https://api.example.com\"]\nenv = \"SECOND_TOKEN\"\n"
    );
    let snapshot = agent_with_launch(&two);
    assert_eq!(field(&snapshot), None);
    assert_eq!(snapshot.launch.as_ref().unwrap().credentials.len(), 2);
    let first = staged_secret(&snapshot, b"first-value");
    let error = vault_launch(&prepared_plan(
        snapshot.clone(),
        Some("svc"),
        vec![first.clone()],
    ))
    .unwrap_err();
    assert!(error.message.contains("`second` has no value"), "{error}");
    let second_decl = &snapshot.launch.as_ref().unwrap().credentials[1];
    let second = Arc::new(
        crate::vault::Secret::new(
            second_decl.id.clone(),
            second_decl.vault.clone().unwrap(),
            b"second-value".to_vec(),
        )
        .unwrap(),
    );
    let VaultLaunch { secrets, .. } =
        vault_launch(&prepared_plan(snapshot, Some("svc"), vec![second, first])).unwrap();
    assert_eq!(
        secrets,
        [
            protocol::SecretEntry {
                id: "api.token".into(),
                data: protocol::encode_data(b"first-value"),
            },
            protocol::SecretEntry {
                id: "second".into(),
                data: protocol::encode_data(b"second-value"),
            },
        ]
    );
}

// ---------------------------------------------------------------------------
// Review round 2 (fix-1103/rev-vmhost): the outcome, the wall hit, the serve
// binding, the deadline, the staged secrets, standard input, the guest's
// policy, and the receipt checks the first round left untested.
// ---------------------------------------------------------------------------

/// A `done` whose guest stop (decision D6) found nothing left behind.
fn done(exit_code: i32) -> protocol::FromVm {
    protocol::FromVm::Done {
        exit_code,
        stop: Some(clean_stop()),
    }
}

fn clean_stop() -> protocol::GuestStop {
    protocol::GuestStop {
        boundaries: vec![
            "ukai-attempts.slice/attempt-1".into(),
            "user.slice/user-1001.slice/user@1001.service/app.slice".into(),
        ],
        ..protocol::GuestStop::default()
    }
}

/// Sends a bound, verifying receipt and then `done` carrying `stop`.
fn finish_with_stop(stop: Option<protocol::GuestStop>) -> (RunEvent, VmRunning, tempfile::TempDir) {
    let (mut run, mut peer, dir) = running();
    let (sha256, data) = encoded(&with_outcome("exited", Some(0), None));
    for frame in [
        protocol::FromVm::BoundReceipt {
            sha256,
            data,
            binding: binding(),
        },
        protocol::FromVm::Done { exit_code: 0, stop },
    ] {
        peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
    }
    let event = run.wait(soon());
    (event, run, dir)
}

/// D6: the guest controller's own stop is the check on the guest jail's
/// `tree_empty`. A `done` without one, or one that found anything the guest
/// jail left behind (a boundary still populated, a live process of the
/// account, a stray it killed by pid), settles nothing: no relayed outcome,
/// no mirrored guest facts, no transport record.
#[test]
fn a_guest_stop_that_is_absent_or_found_survivors_settles_nothing() {
    let survivors = [
        protocol::GuestStop {
            populated_before_kill: vec![
                "user.slice/user-1001.slice/user@1001.service/app.slice".into(),
            ],
            ..clean_stop()
        },
        protocol::GuestStop {
            live_before_kill: vec![(
                4242,
                Some("/user.slice/user-1001.slice/session-1.scope".into()),
            )],
            ..clean_stop()
        },
        protocol::GuestStop {
            strays_killed: vec![(4243, None)],
            ..clean_stop()
        },
    ];
    for stop in survivors {
        let (event, mut run, dir) = finish_with_stop(Some(stop.clone()));
        assert!(
            matches!(&event, RunEvent::Unknown { reason } if reason.contains("tree_empty is contradicted")),
            "{stop:?}: {event:?}"
        );
        assert!(run.guest_facts().is_none(), "{stop:?}");
        assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None, "{stop:?}");
        assert!(
            !dir.path().join(record::TRANSPORT_FILE).exists(),
            "{stop:?}"
        );
    }
    let (event, mut run, dir) = finish_with_stop(None);
    assert!(
        matches!(&event, RunEvent::Unknown { reason } if reason.contains("without its own stop")),
        "{event:?}"
    );
    assert!(run.guest_facts().is_none());
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
    assert!(!dir.path().join(record::TRANSPORT_FILE).exists());
    // A stop that found nothing because it looked at nothing: no boundary,
    // only the user manager's slice, or a name that is not an attempt's.
    let uncovered = [
        Vec::new(),
        vec!["user.slice/user-1001.slice/user@1001.service/app.slice".to_owned()],
        vec!["ukai-attempts.slice/attempt-".to_owned()],
        vec!["ukai-attempts.slice/attempt-1/leaf".to_owned()],
        vec!["ukai-attempts.slice".to_owned()],
    ];
    for boundaries in uncovered {
        let stop = protocol::GuestStop {
            boundaries: boundaries.clone(),
            ..protocol::GuestStop::default()
        };
        let (event, mut run, dir) = finish_with_stop(Some(stop));
        assert!(
            matches!(&event, RunEvent::Unknown { reason } if reason.contains("covered no attempt cgroup")),
            "{boundaries:?}: {event:?}"
        );
        assert!(run.guest_facts().is_none(), "{boundaries:?}");
        assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
        assert!(!dir.path().join(record::TRANSPORT_FILE).exists());
    }
}

/// A clean stop settles the attempt, and the transport record names the
/// cgroups that stop covered.
#[test]
fn a_clean_guest_stop_settles_and_its_boundaries_are_recorded() {
    let (event, run, dir) = finish_with_stop(Some(clean_stop()));
    assert!(
        matches!(event, RunEvent::TargetExited { code: 0 }),
        "{event:?}"
    );
    assert!(run.guest_facts().is_some());
    let record = record::TransportRecord::read_in(dir.path()).expect("the transport record");
    assert_eq!(record.guest_stop_boundaries, clean_stop().boundaries);
}

/// Sends `receipt` bound and `done` with `exit_code` to a fresh attempt,
/// and returns what the host relays and whether it mirrors the guest.
fn finish(receipt: &Value, exit_code: i32) -> (RunEvent, Option<GuestFacts>) {
    let (mut run, mut peer, _dir) = running();
    let (sha256, data) = encoded(receipt);
    peer.write_all(
        &protocol::encode(&protocol::FromVm::BoundReceipt {
            sha256,
            data,
            binding: binding(),
        })
        .unwrap(),
    )
    .unwrap();
    peer.write_all(&protocol::encode(&done(exit_code)).unwrap())
        .unwrap();
    let event = run.wait(soon());
    (event, run.guest_facts())
}

fn with_outcome(kind: &str, code: Option<u8>, signal: Option<u32>) -> Value {
    let mut changed = receipt();
    changed["outcome"] = serde_json::json!({
        "kind": kind, "code": code, "signal": signal, "cause": null, "error": null
    });
    changed
}

/// Review X1 (decision D5): the host relays the verified receipt's outcome,
/// and a `done` whose status disagrees with it is refused, so no host
/// receipt records an exit the guest receipt it mirrors contradicts.
#[test]
fn the_relayed_outcome_is_the_verified_receipts() {
    let (event, facts) = finish(&with_outcome("exited", Some(1), None), 0);
    assert!(
        matches!(&event, RunEvent::Unknown { reason } if reason.contains("exit status 0")),
        "{event:?}"
    );
    assert!(facts.is_none(), "nothing mirrored");
    let (event, facts) = finish(&with_outcome("exited", Some(3), None), 3);
    assert!(
        matches!(event, RunEvent::TargetExited { code: 3 }),
        "{event:?}"
    );
    assert!(facts.is_some());
    let (event, facts) = finish(&with_outcome("signaled", None, Some(9)), 137);
    assert!(
        matches!(event, RunEvent::TargetSignaled { signal: 9 }),
        "{event:?}"
    );
    assert_eq!(facts.unwrap().outcome.signal, Some(9));
    // The same outcome read by the tree's verification after a stop.
    let (mut run, mut peer, _dir) = running();
    let (sha256, data) = encoded(&with_outcome("signaled", None, Some(9)));
    for frame in [
        protocol::FromVm::BoundReceipt {
            sha256,
            data,
            binding: binding(),
        },
        done(137),
    ] {
        peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
    }
    assert_eq!(run.wait_tree(Duration::from_secs(1)).tree_empty, Some(true));
    assert!(run.guest_facts().is_some());
    for (receipt, status) in [
        (with_outcome("signaled", None, Some(9)), 9),
        (with_outcome("exited", Some(137), None), 9),
        (with_outcome("exec_error", None, None), 1),
        (with_outcome("exited", None, None), 0),
    ] {
        let (event, facts) = finish(&receipt, status);
        assert!(
            matches!(event, RunEvent::Unknown { .. }),
            "{}: {event:?}",
            receipt["outcome"]
        );
        assert!(facts.is_none());
    }
}

/// Review X2 (decision D5): "a limit hit the host itself observed (its wall
/// deadline) stays a hit". The settle reads the host's hits before any
/// platform row replaces the host's, so the guest's row (hit false) cannot
/// erase the host's own expiry from the settled receipt.
struct WallSim;
struct WallPrepared;
struct WallRunning {
    waits: u32,
    inner: VmRunning,
    _root: tempfile::TempDir,
}

impl Platform for WallSim {
    fn identity(&self) -> PlatformIdentity {
        GuestSim.identity()
    }
    fn state_identity(&self) -> PlatformIdentity {
        GuestSim.state_identity()
    }
    fn owner_identity(&self) -> Option<crate::platform::OwnerIdentity> {
        GuestSim.owner_identity()
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        GuestSim.probe(plan)
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        Ok(Box::new(WallPrepared))
    }
}

impl PreparedExecution for WallPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        GuestPrepared.boundary()
    }
    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, Box<ReleaseFailure>> {
        let (inner, mut peer, root) = running();
        std::thread::spawn(move || {
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            let (sha256, data) = encoded(&with_outcome("signaled", None, Some(9)));
            for frame in [
                protocol::FromVm::BoundReceipt {
                    sha256,
                    data,
                    binding: binding(),
                },
                done(137),
            ] {
                peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
            }
        });
        Ok(Box::new(WallRunning {
            waits: 0,
            inner,
            _root: root,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown { tree: None })
    }
}

impl RunningExecution for WallRunning {
    // The verified guest's rows do not claim the host's wall hit.
    fn final_limits(&self) -> Vec<AppliedLimit> {
        self.inner.final_limits()
    }
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.waits += 1;
        if self.waits > 3 {
            // A regression must fail the outcome assertions, not hang the
            // test supervisor forever on repeated WallExpired events.
            return RunEvent::Unknown {
                reason: "VM wall expiry did not retire".into(),
            };
        }
        self.inner.wait(Deadline {
            at: Some(Instant::now() - Duration::from_secs(1)),
        })
    }
    fn request_stop(&mut self, reason: StopReason) {
        self.inner.request_stop(reason);
    }
    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        self.inner.wait_tree(budget)
    }
    fn observer_summary(&mut self) -> Option<crate::observer::CoverageSummary> {
        None
    }
    fn guest_facts(&self) -> Option<GuestFacts> {
        self.inner.guest_facts()
    }
}

#[test]
fn the_host_wall_hit_survives_settlement() {
    use clap::Parser as _;
    let temp = common_temp();
    let root = temp.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let crate::cli::Command::Run(args) = crate::cli::Cli::parse_from([
        "ukai-jail",
        "run",
        "--profile",
        "agent",
        "--terminal",
        "detach",
        "--limit",
        "wall=60s",
        "--workspace",
        workspace.to_str().unwrap(),
        "--",
        "/bin/true",
    ])
    .command
    else {
        unreachable!()
    };
    let context = crate::supervisor::Context {
        platform: Box::new(WallSim),
        env_settings: crate::config::EnvSettings {
            config_dir: Some(root.join("config")),
            data_dir: Some(root.join("data")),
            ..Default::default()
        },
        cwd: workspace.clone(),
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let report = crate::supervisor::run(&context, &args);
    let receipt_path = report.receipt_path.expect("a receipt");
    let host: Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(host["outcome"]["cause"], "wall_expiry");
    assert_eq!(host["outcome"]["kind"], "signaled");
    assert_eq!(host["outcome"]["signal"], 9);
    assert_eq!(host["lifetime"]["tree_empty"], true);
    let wall = host["applied"]["limits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["key"] == "wall")
        .unwrap()
        .clone();
    assert_eq!(
        wall["hit"], true,
        "the host's wall expired (outcome {}), yet the settled wall row says {wall}",
        host["outcome"]
    );
}

/// A workspace on a case-sensitive volume of its own, which the share
/// preflight accepts (the Mac's default volume folds case).
fn shareable_workspace() -> (share::TestVolume, PathBuf) {
    let volume = share::TestVolume::attach("Case-sensitive APFS")
        .expect("a case-sensitive hdiutil volume for the live share");
    let workspace = volume.mount.join("work");
    std::fs::create_dir(&workspace).unwrap();
    let workspace = workspace.canonicalize().unwrap();
    (volume, workspace)
}

fn ready(boot_id: &str) -> protocol::FromVm {
    protocol::FromVm::Ready {
        guest_program_catalog_sha256: None,
        schema: protocol::SCHEMA_ATTEMPT.into(),
        boot_id: boot_id.into(),
        disk_sha256: "d".repeat(64),
        helper_sha256: "h".repeat(64),
        custodian_sha256: "c".repeat(64),
        seed_sha256: "s".repeat(64),
        vsock_port: 1024,
        guest_contracts: Some(protocol::GuestContracts {
            sampled_exposure: None,
            native_program: None,
            secret_revocation: Some(protocol::SECRET_REVOCATION_CONTRACT.into()),
            journal_export: Some(protocol::JOURNAL_EXPORT_CONTRACT.into()),
        }),
    }
}

/// Reads one line from `stream`, or what arrived before its end.
fn read_line(stream: &mut UnixStream) -> Vec<u8> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    line
}

/// A stand-in serve for `VmExecution::prepare` beneath a fresh data
/// directory: its control socket answers `status` with `status`, and its
/// attempt socket's one connection is handed to `guest`. `prepare` runs on
/// its own thread and its result is returned (the prepared attempt's
/// derived guest policy digest), or `None` when it did not return within
/// `wait` (a wait the deadline does not bound).
fn prepare_against(
    plan: PreparedPlan,
    status: protocol::FromControl,
    guest: impl FnOnce(UnixStream) + Send + 'static,
    wait: Duration,
) -> Option<Result<String, String>> {
    let data = tempfile::tempdir().unwrap();
    let platform = platform(data.path());
    let control_socket = platform.control_socket();
    let server = fake_control(control_socket.clone(), Duration::ZERO, status);
    while !control::is_listening(&control_socket) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let listener = UnixListener::bind(control::attempt_socket(data.path())).unwrap();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            guest(stream);
        }
    });
    let attempt_dir = data.path().join("attempt");
    std::fs::create_dir(&attempt_dir).unwrap();
    let plan = PreparedPlan {
        attempt_dir,
        ..plan
    };
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = VmExecution::prepare(&platform, plan, Sinks { trace: None }, None)
            .map(|execution| execution.guest_policy_digest)
            .map_err(|error| error.message);
        let _ = sender.send(result);
    });
    let result = receiver.recv_timeout(wait).ok();
    if result.is_some() {
        join_control(server, &control_socket);
    }
    drop(data);
    result
}

/// A guest that answers `ready` from `boot_id`, then `prepared` with
/// `staged`, holding the connection a moment.
fn answering(
    boot_id: &'static str,
    staged: Vec<(String, String)>,
) -> impl FnOnce(UnixStream) + Send + 'static {
    move |mut stream| {
        let _ = stream.write_all(&protocol::encode(&ready(boot_id)).unwrap());
        let _ = read_line(&mut stream);
        let _ = stream.write_all(
            &protocol::encode(&protocol::FromVm::Prepared {
                kernel: "guest-kernel".into(),
                staged_secrets: staged,
            })
            .unwrap(),
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Review X3 (decision D4): the attempt connection must come from the very
/// serve whose status was checked. A `ready` from another boot (the checked
/// serve exited and another run's serve, for another tree, took the
/// sockets) is refused before anything is staged.
#[test]
fn the_attempt_connection_must_come_from_the_checked_serve() {
    let (_volume, workspace) = shareable_workspace();
    let plan = || PreparedPlan {
        workspace: workspace.clone(),
        ..prepared_plan(tool(), None, Vec::new())
    };
    let wait = Duration::from_secs(20);
    let error = prepare_against(
        plan(),
        status(Some(&workspace), false),
        answering("vm-another-boot", Vec::new()),
        wait,
    )
    .expect("prepare returned")
    .unwrap_err();
    assert!(error.contains("boot vm-another-boot"), "{error}");
    assert!(error.contains("boot vm-test"), "{error}");
    let digest = prepare_against(
        plan(),
        status(Some(&workspace), false),
        answering("vm-test", Vec::new()),
        wait,
    )
    .expect("prepare returned")
    .expect("the checked serve's own boot prepares");
    // The policy the receipt is held to is the guest jail's, at the share's
    // mount, not the host workspace's.
    assert_eq!(
        digest,
        guest_snapshot(&tool(), 60, None, GUEST_SHARE_MOUNT.as_bytes())
            .unwrap()
            .digest()
            .unwrap()
    );
    // A serve running another image than the verified installation, each
    // artifact on its own: the serve's status is the client's only check of
    // what the serve booted.
    for artifact in ["disk", "helper", "custodian", "seed"] {
        let mut other = status(Some(&workspace), false);
        if let protocol::FromControl::Status {
            disk_sha256,
            helper_sha256,
            custodian_sha256,
            seed_sha256,
            ..
        } = &mut other
        {
            let digest = match artifact {
                "disk" => disk_sha256,
                "helper" => helper_sha256,
                "custodian" => custodian_sha256,
                _ => seed_sha256,
            };
            *digest = "e".repeat(64);
        }
        let error = prepare_against(plan(), other, answering("vm-test", Vec::new()), wait)
            .expect("prepare returned")
            .unwrap_err();
        assert!(error.contains("another image"), "{artifact}: {error}");
    }
}

/// Review F11c (decision D3): the guest must acknowledge exactly the
/// secrets sent, each staged where the generated declaration names its
/// source; a missing, misplaced or extra one is refused before the release.
#[test]
fn the_guest_must_acknowledge_exactly_the_secrets_sent() {
    let (_volume, workspace) = shareable_workspace();
    let snapshot = agent_with_launch(VAULT_LAUNCH);
    let secret = staged_secret(&snapshot, b"s3cret-value");
    let plan = || PreparedPlan {
        workspace: workspace.clone(),
        ..prepared_plan(snapshot.clone(), Some("svc"), vec![secret.clone()])
    };
    let staged = |id: &str, path: &str| (id.to_owned(), path.to_owned());
    let right = format!("{GUEST_CREDENTIAL_ROOT}/api.token");
    for (acknowledged, accepted) in [
        (Vec::new(), false),
        (vec![staged("api.token", "/tmp/api.token")], false),
        (
            vec![staged("api.token", &right), staged("other", "/run/other")],
            false,
        ),
        (vec![staged("api.token", &right)], true),
    ] {
        let shown = format!("{acknowledged:?}");
        let result = prepare_against(
            plan(),
            status(Some(&workspace), true),
            answering("vm-test", acknowledged),
            Duration::from_secs(20),
        )
        .expect("prepare returned");
        match (result, accepted) {
            (Ok(_), true) => {}
            (Err(error), false) => {
                assert!(error.contains("acknowledged the staged secrets"), "{error}");
            }
            (other, _) => panic!("{shown}: {other:?}"),
        }
    }
}

#[test]
fn missing_or_unknown_guest_contracts_refuse_before_secret_prepare_but_allow_plain_runs() {
    let (_volume, workspace) = shareable_workspace();
    let snapshot = agent_with_launch(VAULT_LAUNCH);
    let secret = staged_secret(&snapshot, b"must-not-cross-legacy-transport");
    let required = protocol::GuestContracts {
        sampled_exposure: None,
        native_program: None,
        secret_revocation: Some(protocol::SECRET_REVOCATION_CONTRACT.into()),
        journal_export: Some(protocol::JOURNAL_EXPORT_CONTRACT.into()),
    };
    let unsupported = [
        None,
        Some(protocol::GuestContracts::default()),
        Some(protocol::GuestContracts {
            sampled_exposure: None,
            native_program: None,
            journal_export: None,
            ..required.clone()
        }),
        Some(protocol::GuestContracts {
            sampled_exposure: None,
            native_program: None,
            secret_revocation: None,
            ..required.clone()
        }),
        Some(protocol::GuestContracts {
            sampled_exposure: None,
            native_program: None,
            secret_revocation: Some("ukai.vm.secret-revocation/2".into()),
            ..required.clone()
        }),
        Some(protocol::GuestContracts {
            sampled_exposure: None,
            native_program: None,
            journal_export: Some("ukai.vm.guest-journal/2".into()),
            ..required
        }),
    ];
    for contracts in unsupported {
        for credentials in [false, true] {
            let plan = PreparedPlan {
                workspace: workspace.clone(),
                ..if credentials {
                    prepared_plan(snapshot.clone(), Some("svc"), vec![secret.clone()])
                } else {
                    prepared_plan(tool(), None, Vec::new())
                }
            };
            let (sent, observed) = std::sync::mpsc::channel();
            let contracts = contracts.clone();
            let result = prepare_against(
                plan,
                status(Some(&workspace), credentials),
                move |mut stream| {
                    let mut frame = ready("vm-test");
                    let protocol::FromVm::Ready {
                        guest_contracts, ..
                    } = &mut frame
                    else {
                        unreachable!()
                    };
                    *guest_contracts = contracts;
                    stream
                        .write_all(&protocol::encode(&frame).unwrap())
                        .unwrap();
                    let request = read_line(&mut stream);
                    sent.send(request.clone()).unwrap();
                    if !request.is_empty() {
                        stream
                            .write_all(
                                &protocol::encode(&protocol::FromVm::Prepared {
                                    kernel: "guest-kernel".into(),
                                    staged_secrets: Vec::new(),
                                })
                                .unwrap(),
                            )
                            .unwrap();
                    }
                },
                Duration::from_secs(20),
            )
            .expect("prepare returned");
            let request = observed.recv_timeout(Duration::from_secs(1)).unwrap();
            if credentials {
                assert!(result.unwrap_err().contains("no credential was sent"));
                assert!(
                    request.is_empty(),
                    "legacy peer received a Prepare containing a secret"
                );
            } else {
                assert!(result.is_ok(), "{result:?}");
                assert!(
                    matches!(protocol::decode::<protocol::ToVm>(&request).unwrap(), protocol::ToVm::Prepare { secrets, .. } if secrets.is_empty())
                );
            }
        }
    }
}

/// Review F9 (decision D4): every wait of the preparation is bounded by its
/// deadline: the serve's status, the first frame, the staging's write and
/// the guest's acceptance. Each stand-in stalls one of them; `prepare`
/// returns within a few seconds of a one-second budget, where the fixed
/// bounds would take 5 s, 180 s, 30 s and 30 s.
#[test]
fn the_preparation_deadline_bounds_every_handshake_wait() {
    let (_volume, workspace) = shareable_workspace();
    let budget = Duration::from_secs(1);
    let plan = |argv: Vec<u8>| PreparedPlan {
        workspace: workspace.clone(),
        argv: vec![argv],
        prepare_deadline: ContinuousDeadline::after(budget),
        ..prepared_plan(tool(), None, Vec::new())
    };
    let silent = |mut stream: UnixStream| {
        let _ = read_line(&mut stream);
        std::thread::sleep(Duration::from_secs(40));
    };
    let ready_then = |reads: bool| {
        move |mut stream: UnixStream| {
            let _ = stream.write_all(&protocol::encode(&ready("vm-test")).unwrap());
            if reads {
                let _ = read_line(&mut stream);
            }
            std::thread::sleep(Duration::from_secs(40));
        }
    };
    type Guest = Box<dyn FnOnce(UnixStream) + Send>;
    let cases: Vec<(&str, Vec<u8>, Guest, &str)> = vec![
        (
            "ready",
            b"/bin/true".to_vec(),
            Box::new(silent),
            "did not finish booting",
        ),
        (
            "prepared",
            b"/bin/true".to_vec(),
            Box::new(ready_then(true)),
            "did not accept the staging",
        ),
        (
            "write",
            vec![b'a'; 1024 * 1024],
            Box::new(ready_then(false)),
            "failed to write within",
        ),
    ];
    for (what, argv, guest, expected) in cases {
        let started = Instant::now();
        let error = prepare_against(
            plan(argv),
            status(Some(&workspace), false),
            guest,
            Duration::from_secs(10),
        )
        .unwrap_or_else(|| panic!("{what}: the wait outlived the deadline"))
        .unwrap_err();
        assert!(error.contains(expected), "{what}: {error}");
        assert!(started.elapsed() < Duration::from_secs(5), "{what}");
    }
}

/// The serve's status, too, is read within the deadline: a control socket
/// that accepts and never answers holds `ensure_serving` for what is left
/// of the budget, not the fixed five seconds.
#[test]
fn the_status_read_is_bounded_by_the_deadline() {
    let data = tempfile::tempdir().unwrap();
    let platform = platform(data.path());
    let socket = platform.control_socket();
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    let started = Instant::now();
    let error = platform
        .serve_with(
            data.path(),
            false,
            ContinuousDeadline::after(Duration::from_millis(300)),
            || panic!("a serve answers"),
        )
        .unwrap_err();
    assert!(error.message.contains("timed out"), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    let error = platform
        .serve_with(
            data.path(),
            false,
            ContinuousDeadline::after(Duration::ZERO),
            || panic!("a serve answers"),
        )
        .unwrap_err();
    assert!(error.message.contains("budget was spent"), "{error}");
}

/// Review F11e (decision D4): two serves spawned at once each write their
/// own private file, so a refusal quotes only what its own serve said.
#[test]
fn concurrent_spawns_quote_only_their_own_stderr() {
    let temp = common_temp();
    let data = tempfile::tempdir().unwrap();
    let slow = serve_script(temp.path(), "echo 'alpha said this' >&2; sleep 1; exit 3");
    let fast_dir = temp.path().join("fast");
    std::fs::create_dir(&fast_dir).unwrap();
    let fast = serve_script(&fast_dir, "echo 'bravo' >&2; exit 4");
    let first = {
        let platform = platform(data.path());
        let workspace = temp.path().to_path_buf();
        std::thread::spawn(move || {
            platform
                .serve_with(
                    &workspace,
                    false,
                    ContinuousDeadline::after(Duration::from_secs(20)),
                    || Ok(slow),
                )
                .unwrap_err()
                .message
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    let second = platform(data.path())
        .serve_with(
            temp.path(),
            false,
            ContinuousDeadline::after(Duration::from_secs(20)),
            || Ok(fast),
        )
        .unwrap_err()
        .message;
    let first = first.join().unwrap();
    assert!(first.contains("alpha said this"), "{first}");
    assert!(!first.contains("bravo"), "{first}");
    assert!(second.contains("bravo"), "{second}");
    assert!(!second.contains("alpha"), "{second}");
    let runtime = vm_runtime_dir(data.path());
    let left: Vec<_> = std::fs::read_dir(&runtime)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("serve-") && name != SERVE_STDERR_FAILED)
        .collect();
    assert!(left.is_empty(), "per-spawn files are renamed: {left:?}");
}

/// Review F11d: the guest jail's standard input is /dev/null, so a pipe, a
/// file or a socket on the operator's would be dropped in silence; those
/// are refused, a terminal, /dev/null and a closed descriptor are not.
#[test]
fn standard_input_the_guest_never_reads_is_named() {
    use std::os::fd::AsRawFd as _;
    let (reader, _writer) = std::io::pipe().unwrap();
    assert_eq!(undelivered_stdin(reader.as_raw_fd()), Some("a pipe"));
    let file = tempfile::tempfile().unwrap();
    assert_eq!(undelivered_stdin(file.as_raw_fd()), Some("a file"));
    let (socket, _peer) = UnixStream::pair().unwrap();
    assert_eq!(undelivered_stdin(socket.as_raw_fd()), Some("a socket"));
    let null = std::fs::File::open("/dev/null").unwrap();
    assert_eq!(undelivered_stdin(null.as_raw_fd()), None);
    let zero = std::fs::File::open("/dev/zero").unwrap();
    assert_eq!(
        undelivered_stdin(zero.as_raw_fd()),
        Some("a character device other than /dev/null")
    );
    let (mut primary, mut secondary) = (0, 0);
    // SAFETY: `openpty` writes two descriptors; the name and settings are
    // optional and left null.
    let opened = unsafe {
        libc::openpty(
            &mut primary,
            &mut secondary,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(opened, 0, "a pseudo-terminal");
    assert_eq!(undelivered_stdin(secondary), None);
    // SAFETY: both descriptors were opened above and are closed once.
    unsafe {
        libc::close(primary);
        libc::close(secondary);
    }
    // A descriptor number far past any this process opened: closed.
    assert_eq!(undelivered_stdin(1_000_000), None);
}

/// The refusal comes before any contact, after the policy's own.
#[test]
fn piped_standard_input_refuses_before_any_contact() {
    let data = tempfile::tempdir().unwrap();
    let platform = platform(data.path());
    let workspace = tempfile::tempdir().unwrap();
    let plan = PreparedPlan {
        workspace: workspace.path().to_path_buf(),
        ..prepared_plan(tool(), None, Vec::new())
    };
    let Err(error) = VmExecution::prepare(&platform, plan, Sinks { trace: None }, Some("a pipe"))
    else {
        panic!("prepared with a pipe on standard input");
    };
    assert!(
        error.message.contains("standard input is a pipe"),
        "{error}"
    );
    assert_eq!(error.remediation, Remediation::Configuration);
    assert!(!vm_runtime_dir(data.path()).exists());
}

/// Review F4: the guest receipt must report the policy this host derives
/// for the guest jail; a guest jail of another version, whose policy digest
/// differs, is refused, never mirrored.
#[test]
fn a_receipt_of_another_policy_is_refused() {
    let (mut run, _peer, dir) = running();
    let mut changed = receipt();
    changed["policy"]["digest"] = "sha256:another-version".into();
    let (hash, data) = encoded(&changed);
    let error = run.store_receipt(&hash, &data, &binding()).unwrap_err();
    assert!(error.contains("policy digest"), "{error}");
    assert!(error.contains("sha256:another-version"), "{error}");
    assert!(run.guest.is_none());
    assert!(!dir.path().join("evidence/jail.json").exists());
    let mut absent = receipt();
    absent["policy"].as_object_mut().unwrap().remove("digest");
    let (hash, data) = encoded(&absent);
    assert!(
        run.store_receipt(&hash, &data, &binding())
            .unwrap_err()
            .contains("absent")
    );
}

/// The guest controller's fixed limit arguments are the guest's fixed
/// limits, as the guest jail's own grammar reads them.
#[test]
fn the_guest_limit_arguments_are_the_fixed_limits() {
    let arguments: Vec<String> = GUEST_LIMIT_ARGUMENTS
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect();
    let ceilings = crate::config::ceilings_from_cli(&arguments).unwrap();
    for (key, value) in GUEST_FIXED_LIMITS {
        let ceiling = match key {
            LimitKey::Pids => ceilings.pids.as_ref(),
            LimitKey::Mem => ceilings.mem.as_ref(),
            LimitKey::Swap => ceilings.swap.as_ref(),
            other => panic!("{other:?} is no fixed guest limit"),
        };
        assert_eq!(ceiling.map(|ceiling| ceiling.value), Some(value), "{key:?}");
        assert!(ceiling.unwrap().required);
    }
}

/// Review F4: the policy the host derives for the guest jail is the one the
/// guest jail's own resolution produces from the guest controller's
/// command line, environment and generated declaration: this binary's
/// `resolve_plan`, run as the guest runs it (a Linux identity, the share
/// as workspace and working directory, the declaration in its config
/// directory), gives the same digest.
#[test]
fn the_predicted_guest_policy_is_the_guest_jails_own() {
    use clap::Parser as _;
    use std::os::unix::fs::PermissionsExt as _;
    for (snapshot, launch) in [
        (tool(), None),
        (agent(), None),
        (agent_with_launch(VAULT_LAUNCH), Some("svc")),
    ] {
        let profile = snapshot.profile.as_str().to_owned();
        let temp = common_temp();
        let root = temp.path().canonicalize().unwrap();
        let (workspace, config, home) =
            (root.join("share"), root.join("config"), root.join("home"));
        for dir in [&workspace, &config, &home] {
            std::fs::create_dir(dir).unwrap();
        }
        let vault = match launch {
            Some(name) => {
                let secret = staged_secret(&snapshot, b"s3cret-value");
                vault_launch(&prepared_plan(snapshot.clone(), Some(name), vec![secret])).unwrap()
            }
            None => VaultLaunch::default(),
        };
        if let Some(declaration) = &vault.declaration {
            let directory = config.join("launch");
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = directory.join(format!("{}.toml", declaration.name));
            std::fs::write(&file, &declaration.toml).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // `guest.py` `run_command`, as the guest controller spells it.
        let mut argv: Vec<String> = [
            "ukai-jail",
            "run",
            "--profile",
            &profile,
            "--workspace",
            workspace.to_str().unwrap(),
            "--receipt",
            root.join("evidence/jail.json").to_str().unwrap(),
            "--limit",
            "wall=60s",
        ]
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect();
        for argument in GUEST_LIMIT_ARGUMENTS {
            argv.extend(["--limit".to_owned(), argument.to_owned()]);
        }
        for rule in guest_allow_hosts(&snapshot.network) {
            argv.extend(["--allow-host".to_owned(), rule]);
        }
        if let Some(name) = launch {
            argv.extend(["--launch".to_owned(), name.to_owned()]);
        }
        argv.extend(["--".to_owned(), "/bin/true".to_owned()]);
        let crate::cli::Command::Run(args) = crate::cli::Cli::parse_from(&argv).command else {
            unreachable!()
        };
        // `guest.py` `attempt_environment`.
        let environment: BTreeMap<&str, String> = [
            ("HOME", home.display().to_string()),
            ("USER", "ukai".to_owned()),
            ("LOGNAME", "ukai".to_owned()),
            ("PATH", "/usr/local/bin:/usr/bin:/bin".to_owned()),
            ("LANG", "C.UTF-8".to_owned()),
            ("XDG_RUNTIME_DIR", "/run/user/1000".to_owned()),
            ("UKAI_CONFIG_DIR", config.display().to_string()),
        ]
        .into_iter()
        .collect();
        let context = crate::supervisor::Context {
            platform: Box::new(GuestSim),
            env_settings: crate::config::EnvSettings {
                config_dir: Some(config.clone()),
                data_dir: Some(home.join(".local/share/ukai")),
                ..Default::default()
            },
            cwd: workspace.clone(),
            home: Some(home.clone()),
            env_lookup: Box::new(move |name| {
                environment.get(name).map(|value| value.as_bytes().to_vec())
            }),
        };
        let plan = crate::supervisor::resolve_plan(&context, &args.policy)
            .unwrap_or_else(|error| panic!("{profile}: the guest's resolution: {error}"));
        let predicted = guest_snapshot(
            &snapshot,
            60,
            vault.parsed.as_ref(),
            workspace.as_os_str().as_encoded_bytes(),
        )
        .unwrap();
        assert_eq!(
            predicted, plan.resolved.snapshot,
            "{profile}: the predicted guest snapshot"
        );
        assert_eq!(
            predicted.digest().unwrap(),
            plan.resolved.digest,
            "{profile}"
        );
    }
}

/// The receipt's limit rows: one row per requested ceiling, applied. A
/// duplicate row, or a requested ceiling the guest did not apply, refuses.
#[test]
fn every_requested_ceiling_has_one_applied_row() {
    let (mut run, _peer, _dir) = running();
    let mut duplicated = receipt();
    let rows = duplicated["applied"]["limits"].as_array_mut().unwrap();
    let mut second = rows[0].clone();
    second["requested"] = "60000".into();
    rows.push(second);
    let (hash, data) = encoded(&duplicated);
    assert_eq!(
        run.store_receipt(&hash, &data, &binding()).unwrap_err(),
        "guest did not apply the requested wall ceiling"
    );
    let (mut run, _peer, _dir) = running();
    run.inner.limits = serde_json::from_value(serde_json::json!({
        "wall": {"value": "30000", "required": true},
        "inodes": {"value": "1000", "required": false}
    }))
    .unwrap();
    let mut unapplied = receipt();
    unapplied["applied"]["limits"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "key": "inodes", "requested": "1000", "required": false, "applied": false,
            "mechanism": null, "scope": "tree", "hit": null
        }));
    let (hash, data) = encoded(&unapplied);
    assert_eq!(
        run.store_receipt(&hash, &data, &binding()).unwrap_err(),
        "guest did not apply the requested inodes ceiling"
    );
}

/// A secret crosses with the one value it was staged with: a second loaded
/// value (a source that changed and was read again) or a forgotten one
/// refuses.
#[test]
fn a_secret_crosses_with_its_one_staged_value() {
    let value = |text: &str| zeroize::Zeroizing::new(text.as_bytes().to_vec());
    assert_eq!(
        the_staged_value("api", &[value("one")], true).unwrap(),
        b"one"
    );
    for (values, complete) in [
        (vec![value("one"), value("two")], true),
        (vec![value("one")], false),
        (Vec::new(), true),
    ] {
        let error = the_staged_value("api", &values, complete).unwrap_err();
        assert!(
            error.message.contains("exactly the one staged value"),
            "{error}"
        );
    }
}

/// The limits wall refuses a receipt that applied no limit at all, whatever
/// the requested set: an empty list is never "nothing to compare" (review
/// survivor R7; the image rules also require the four rows, so this pins
/// the attempt-side wall on its own).
#[test]
fn a_receipt_with_no_applied_limits_is_refused() {
    let nothing_requested = crate::policy::LimitsSnapshot::default();
    let error = verify_applied_limits(
        &serde_json::json!({"applied": {"limits": []}}),
        &nothing_requested,
    )
    .unwrap_err();
    assert!(error.contains("no applied limits"), "{error}");
}

/// A run that failed writes no transport record, even with a stored receipt
/// and the guest's `done` read: the record is the host's claim that the
/// attempt verified (review survivor R12; today's callers check `failed`
/// first, so this pins `settle_record` on its own).
#[test]
fn a_failed_run_writes_no_transport_record() {
    let (mut run, _peer, dir) = running();
    let (hash, data) = encoded(&receipt());
    run.store_receipt(&hash, &data, &binding()).unwrap();
    run.finished = true;
    run.failed = true;
    let error = run.settle_record().unwrap_err();
    assert!(!error.is_empty());
    assert!(!dir.path().join(record::TRANSPORT_FILE).exists());
}

/// A ceiling whose value is not a number is never taken as the guest's
/// fixed one. The policy layer validates sizes, so a resolved snapshot never
/// carries one; this pins the carry rule's own wall (review survivor W4).
#[test]
fn a_ceiling_that_is_not_a_number_is_not_carried() {
    for key in ["pids", "mem", "swap"] {
        let limits: crate::policy::LimitsSnapshot = serde_json::from_value(serde_json::json!({
            "wall": {"value": "30000", "required": true},
            key: {"value": "lots", "required": false},
        }))
        .unwrap();
        let refusal = carried_limits(&limits).unwrap_err();
        assert_eq!(refusal.field, format!("limits.{key}"));
        assert!(
            refusal.detail.contains("is not a number"),
            "{}",
            refusal.detail
        );
    }
}

#[test]
fn native_client_contract_gate_and_exact_source_ack_precede_release() {
    let (_volume, workspace) = shareable_workspace();
    for variant in [
        "missing",
        "wrong-catalog",
        "wrong-version",
        "missing-sampling",
        "old-sampling",
        "v2-sampling",
        "future-sampling",
        "wrong-source",
        "valid",
    ] {
        let (_dir, mut context, mut args) = native::tests::context();
        context.cwd = workspace.clone();
        args.selection.workspace = Some(workspace.clone());
        let plan = crate::supervisor::resolve_plan(&context, &args).unwrap();
        let program = plan.guest_program.clone().unwrap();
        let (handoff, _) = crate::credentials::stage_guest_within(
            plan.resolved.snapshot.launch.as_ref().unwrap(),
            &program,
            &[],
            &|| Duration::from_secs(2),
        )
        .unwrap();
        let data = common_temp();
        let platform = VmPlatform {
            data_dir: data.path().to_path_buf(),
            install: Install {
                root: context
                    .env_settings
                    .config_dir
                    .as_ref()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("install"),
                manifest: image::ImageManifest {
                    source_sha256: Default::default(),
                    status: "prepared".into(),
                    disk_sha256: program.disk_sha256.clone(),
                    helper_sha256: "a".repeat(64),
                    custodian_sha256: "c".repeat(64),
                    seed_sha256: program.seed_sha256.clone(),
                    guest_program_catalog_sha256: Some(program.catalog_sha256.clone()),
                },
            },
        };
        let mut service_status = status(Some(&workspace), true);
        if let protocol::FromControl::Status {
            helper_sha256,
            seed_sha256,
            ..
        } = &mut service_status
        {
            *helper_sha256 = "a".repeat(64);
            *seed_sha256 = program.seed_sha256.clone();
        }
        let control_socket = platform.control_socket();
        let server = fake_control(control_socket.clone(), Duration::ZERO, service_status);
        while !control::is_listening(&control_socket) {
            std::thread::yield_now();
        }
        let listener = UnixListener::bind(control::attempt_socket(data.path())).unwrap();
        let (sent, observed) = std::sync::mpsc::channel();
        let catalog = program.catalog_sha256.clone();
        let seed = program.seed_sha256.clone();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut greeting = ready("vm-test");
            if let protocol::FromVm::Ready {
                helper_sha256,
                seed_sha256,
                guest_contracts,
                guest_program_catalog_sha256,
                ..
            } = &mut greeting
            {
                *helper_sha256 = "a".repeat(64);
                *seed_sha256 = seed;
                *guest_program_catalog_sha256 = Some(if variant == "wrong-catalog" {
                    "f".repeat(64)
                } else {
                    catalog
                });
                guest_contracts.as_mut().unwrap().sampled_exposure = match variant {
                    "missing-sampling" => None,
                    "old-sampling" => Some("ukai.vm.sampled-exposure/1".into()),
                    "v2-sampling" => Some(protocol::SAMPLED_EXPOSURE_CONTRACT_V2.into()),
                    "future-sampling" => Some("ukai.vm.sampled-exposure/4".into()),
                    _ => Some(protocol::SAMPLED_EXPOSURE_CONTRACT.into()),
                };
                guest_contracts.as_mut().unwrap().native_program = match variant {
                    "missing" => None,
                    "wrong-version" => Some("ukai.vm.guest-native-launch/2".into()),
                    _ => Some(protocol::NATIVE_PROGRAM_CONTRACT.into()),
                };
            }
            stream
                .write_all(&protocol::encode(&greeting).unwrap())
                .unwrap();
            let request = read_line(&mut stream);
            sent.send(request.clone()).unwrap();
            if !request.is_empty() {
                let source = if variant == "wrong-source" {
                    format!(
                        "/run/ukai-vm/credentials/{}",
                        native::tests::input("primary_credential_id")
                    )
                } else {
                    format!(
                        "/run/ukai-vm/native-config/credentials/{}",
                        native::tests::input("primary_credential_id")
                    )
                };
                stream
                    .write_all(
                        &protocol::encode(&protocol::FromVm::Prepared {
                            kernel: "guest".into(),
                            staged_secrets: vec![(
                                native::tests::input("primary_credential_id"),
                                source,
                            )],
                        })
                        .unwrap(),
                    )
                    .unwrap();
            }
        });
        let attempt_dir = data.path().join("attempt");
        std::fs::create_dir(&attempt_dir).unwrap();
        let mut prepared = prepared_plan(
            plan.resolved.snapshot,
            Some(&native::tests::input("alias")),
            vec![],
        );
        prepared.attempt_dir = attempt_dir.clone();
        prepared.workspace = workspace.clone();
        prepared.launch = None;
        prepared.guest_launch = Some(handoff);
        prepared.request.guest_program = Some(program.clone());
        prepared.argv = vec![
            program.executable.as_bytes().to_vec(),
            b"-p".to_vec(),
            vec![0xff, b'x'],
        ];
        let result = VmExecution::prepare(&platform, prepared, Sinks { trace: None }, None);
        let request = observed.recv_timeout(Duration::from_secs(5)).unwrap();
        if matches!(
            variant,
            "missing"
                | "wrong-catalog"
                | "wrong-version"
                | "missing-sampling"
                | "old-sampling"
                | "v2-sampling"
                | "future-sampling"
        ) {
            assert!(result.is_err());
            assert!(
                request.is_empty(),
                "native secret Prepare crossed an incompatible Session"
            );
        } else if variant == "wrong-source" {
            assert!(result.is_err());
        } else {
            let execution = result.unwrap_or_else(|error| panic!("{error}"));
            let protocol::ToVm::Prepare {
                native_program: Some(intent),
                launch,
                argv,
                secrets,
                allow_hosts,
                ..
            } = protocol::decode(&request).unwrap()
            else {
                panic!("not native prepare")
            };
            assert!(launch.is_none());
            assert!(allow_hosts.is_empty());
            assert_eq!(secrets.len(), 1);
            assert_eq!(
                protocol::decode_data(&intent.argv_suffix[1]).unwrap(),
                [0xff, b'x']
            );
            assert_eq!(intent.resolved_argv_digest, execution.argv_digest);
            assert_ne!(intent.request_argv_digest, intent.resolved_argv_digest);
            assert_eq!(
                argv[0],
                protocol::encode_data(program.executable.as_bytes())
            );
            assert_eq!(
                crate::guest_program::sha256(
                    &std::fs::read(attempt_dir.join("guest-native-catalog.json")).unwrap()
                ),
                program.catalog_sha256
            );
        }
        peer.join().unwrap();
        join_control(server, &control_socket);
    }
}

#[test]
fn native_source_only_handoff_uses_the_independent_revocation_watch() {
    use std::io::{BufRead as _, BufReader};
    let (_dir, context, args) = native::tests::context();
    let plan = crate::supervisor::resolve_plan(&context, &args).unwrap();
    let (handoff, _) = crate::credentials::stage_guest_within(
        plan.resolved.snapshot.launch.as_ref().unwrap(),
        plan.guest_program.as_ref().unwrap(),
        &[],
        &|| Duration::from_secs(2),
    )
    .unwrap();
    let (mut run, mut peer, _root) = running();
    run.inner.vault_lease =
        revocation::Sources::Guest(crate::vault::transport::SourceLease(handoff.sources));
    let watch =
        revocation::Watch::start(&run.inner.connection, run.inner.vault_lease.clone()).unwrap();
    std::fs::remove_file(
        context
            .env_settings
            .config_dir
            .as_ref()
            .unwrap()
            .join("credentials")
            .join(native::tests::input("primary_credential_id")),
    )
    .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let mut line = Vec::new();
    BufReader::new(&mut peer)
        .read_until(b'\n', &mut line)
        .unwrap();
    assert_eq!(
        protocol::decode::<protocol::ToVm>(&line).unwrap(),
        protocol::ToVm::RevokeSecrets {
            ids: vec![native::tests::input("primary_credential_id")]
        }
    );
    watch
        .acknowledge(&[native::tests::input("primary_credential_id")])
        .unwrap();
    assert!(watch.acknowledged());
    assert!(run.inner.vault_lease.check().is_err());
}

#[test]
fn native_receipt_binding_cannot_be_omitted_or_replaced_by_literal_receipt() {
    let (mut run, _peer, _root) = running();
    let expected = protocol::NativeProgramBinding {
        catalog_sha256: "a".repeat(64),
        entry_id: "entry".into(),
        profile_sha256: "b".repeat(64),
        executable_sha256: "c".repeat(64),
        selected_credential_id: native::tests::input("primary_credential_id"),
        state: "attempt".into(),
        request_argv_digest: "sha256:request".into(),
        resolved_argv_digest: run.inner.argv_digest.clone(),
        policy_digest: run.inner.guest_policy_digest.clone(),
    };
    run.inner.native_binding = Some(expected.clone());
    let (hash, data) = encoded(&receipt());
    assert!(run.store_receipt(&hash, &data, &binding()).is_err());
    let mut bound = binding();
    bound.native_program = Some(expected.clone());
    bound
        .native_program
        .as_mut()
        .unwrap()
        .selected_credential_id = "other".into();
    assert!(run.store_receipt(&hash, &data, &bound).is_err());
    bound.native_program = Some(expected);
    run.store_receipt(&hash, &data, &bound).unwrap();
}

#[test]
fn sampling_data_failure_does_not_replace_the_verified_guest_execution_outcome() {
    for variant in [
        "missing",
        "malformed",
        "duplicate",
        "executable",
        "oversize",
        "incomplete",
        "wrong-supervisor",
        "wrong-receipt-process",
        "complete",
    ] {
        let (mut run, mut peer, root) = running();
        let native = protocol::NativeProgramBinding {
            catalog_sha256: "a".repeat(64),
            entry_id: "entry".into(),
            profile_sha256: "b".repeat(64),
            executable_sha256: "c".repeat(64),
            selected_credential_id: "token".into(),
            state: "attempt".into(),
            request_argv_digest: "sha256:request".into(),
            resolved_argv_digest: run.inner.argv_digest.clone(),
            policy_digest: run.inner.guest_policy_digest.clone(),
        };
        run.inner.native_binding = Some(native.clone());
        run.inner.image.sampler_sha256 = Some("e".repeat(64));
        let mut binding = binding();
        binding.native_program = Some(native);
        let mut guest_receipt = receipt();
        guest_receipt["process"]["identity"] = serde_json::json!({"kind":"linux_boot_start", "value":{"boot_id":binding.guest_boot_id,"pid":11,"start_time_ticks":101}});
        let payload = if matches!(
            variant,
            "incomplete" | "wrong-supervisor" | "wrong-receipt-process" | "complete"
        ) {
            let mut report: Value = serde_json::from_slice(include_bytes!(
                "../../../../vm/fixtures/sampled-exposure-report.json"
            ))
            .unwrap();
            report["host_attempt_id"] = Value::String(binding.attempt_id.clone());
            report["service_boot_id"] = Value::String(binding.boot_id.clone());
            report["guest_attempt_id"] = Value::String(binding.guest_attempt_id.clone());
            report["guest_boot_id"] = Value::String(binding.guest_boot_id.clone());
            report["catalog_sha256"] = Value::String("a".repeat(64));
            report["executable_sha256"] = Value::String("c".repeat(64));
            report["sampler_sha256"] = Value::String("e".repeat(64));
            report["guest_receipt_sha256"] = Value::String(encoded(&guest_receipt).0);
            report["supervisor"] = serde_json::json!({"pid":run.supervisor_pid,"starttime":100});
            report["receipt_process"] = serde_json::json!({"pid":11,"starttime":101});
            if variant == "wrong-supervisor" {
                report["supervisor"]["pid"] = Value::from(11);
            } else if variant == "wrong-receipt-process" {
                report["receipt_process"]["pid"] = Value::from(10);
            }
            if variant == "incomplete" {
                report["catalog_executable_identity"] = serde_json::json!({"dev":0,"ino":0});
                report["supervisor"]["starttime"] = Value::Null;
                for key in ["reads", "verified_program_reads", "receipt_program_reads"] {
                    for channel in ["environment", "argv"] {
                        for count in report[key][channel].as_object_mut().unwrap().values_mut() {
                            *count = Value::from(0);
                        }
                    }
                }
                for key in [
                    "tick_count",
                    "observed_interval_ns",
                    "maximum_gap_ns",
                    "maximum_tick_duration_ns",
                    "late_poll_count",
                    "missed_tick_count",
                ] {
                    report[key] = Value::from(0);
                }
                report["first_ns"] = Value::Null;
                report["last_ns"] = Value::Null;
                report["processes"] = serde_json::json!([]);
                report["verified_program_observed"] = Value::Bool(false);
                report["receipt_program_observed"] = Value::Bool(false);
                report["observation_incomplete"] = Value::Bool(true);
                report["scan_errors"] = serde_json::json!({"monitor_initialization_failed":1});
                report["lifecycle"] = serde_json::json!({"started_ns":0,"stopped_ns":1,"supervisor_exit_observed_ns":2,"stop_reason":"worker_failed"});
            }
            serde_json::to_vec(&report).unwrap()
        } else if variant == "oversize" {
            vec![b'x'; protocol::MAX_FILE + 1]
        } else {
            b"{}".to_vec()
        };
        let writer = std::thread::spawn(move || {
            if variant != "missing" {
                binding.sampled_exposure_sha256 = Some(crate::guest_program::sha256(&payload));
                for _ in 0..if variant == "duplicate" { 2 } else { 1 } {
                    peer.write_all(
                        &protocol::encode(&protocol::FromVm::File {
                            group: "evidence".into(),
                            path: sampled::FILE.into(),
                            executable: variant == "executable",
                            data: protocol::encode_data(&payload),
                        })
                        .unwrap(),
                    )
                    .unwrap();
                }
            }
            let (sha256, data) = encoded(&guest_receipt);
            peer.write_all(
                &protocol::encode(&protocol::FromVm::BoundReceipt {
                    sha256,
                    data,
                    binding,
                })
                .unwrap(),
            )
            .unwrap();
            peer.write_all(&protocol::encode(&done(0)).unwrap())
                .unwrap();
        });
        assert!(
            matches!(run.wait(soon()), RunEvent::TargetExited { code: 0 }),
            "{variant}"
        );
        assert_eq!(
            run.wait_tree(Duration::ZERO).tree_empty,
            Some(true),
            "{variant}"
        );
        let transport: Value = serde_json::from_slice(
            &std::fs::read(root.path().join(record::TRANSPORT_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            transport["supervisor_pid"], 10,
            "Released PID is retained independently of receipt workload PID 11"
        );
        assert_eq!(
            transport["sampled_exposure"]["status"],
            if variant == "missing" {
                "unavailable"
            } else {
                // The live native Session requires /3, including when this
                // otherwise well-formed historical /2 report says complete.
                "invalid"
            },
            "{variant}"
        );
        assert_eq!(
            transport["sampled_exposure_contract"],
            protocol::SAMPLED_EXPOSURE_CONTRACT
        );
        assert!(!run.failed);
        writer.join().unwrap();
    }
}
