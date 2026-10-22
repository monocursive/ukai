use super::*;
use std::os::unix::net::{UnixListener, UnixStream};

fn binding() -> protocol::ReceiptBinding {
    protocol::ReceiptBinding {
        attempt_id: "host-attempt".into(),
        boot_id: "host-boot".into(),
        guest_attempt_id: "guest-attempt".into(),
        guest_boot_id: "guest-boot".into(),
        profile: "tool".into(),
        argv_digest: "sha256:argv".into(),
    }
}

fn receipt() -> Value {
    serde_json::json!({
        "schema": "ukai.jail.receipt/1", "attempt_id": "guest-attempt", "platform": {"os": "linux"},
        "policy": {"name":"tool"}, "argv_digest":"sha256:argv", "containment":"enforced",
        "child_protection":"enforced", "exec_observed":true, "state_cleanup":"complete", "errors":[],
        "process":{"identity":{"value":{"boot_id":"guest-boot"}}},
        "lifetime":{"boundary":"pid_namespace","tree_empty":true,"integrity":"verified"},
        "applied":{"network":{"mode":"none"},"limits": [
            {"key":"wall","requested":"30000","required":true,"applied":true,"mechanism":"timer","scope":"tree","hit":null},
            {"key":"pids","requested":"64","required":true,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null},
            {"key":"mem","requested":"536870912","required":true,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null},
            {"key":"swap","requested":"0","required":true,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null}
        ]}
    })
}

fn running() -> (VmRunning, UnixStream, tempfile::TempDir) {
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
            disk_sha256: "d".repeat(64),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
        },
        vsock_port: 1024,
        started: Instant::now(),
        started_wall: rfc3339_utc(SystemTime::now()),
        profile: "tool".into(),
        argv_digest: "sha256:argv".into(),
        limits: serde_json::from_value(serde_json::json!({
            "wall":{"value":"30000","required":true},"mem":{"value":"536870912","required":true},
            "pids":{"value":"64","required":true},"swap":{"value":"0","required":true},"cpu":null
        }))
        .unwrap(),
        stdout: std::fs::File::create(dir.path().join("stdout")).unwrap(),
        stderr: std::fs::File::create(dir.path().join("stderr")).unwrap(),
    };
    (
        VmRunning {
            inner: execution,
            receipt: None,
            finished: false,
            failed: false,
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
    for mutate in [
        |b: &mut protocol::ReceiptBinding| b.attempt_id = "another".into(),
        |b: &mut protocol::ReceiptBinding| b.boot_id = "another".into(),
        |b: &mut protocol::ReceiptBinding| b.profile = "build".into(),
        |b: &mut protocol::ReceiptBinding| b.argv_digest = "another".into(),
        |b: &mut protocol::ReceiptBinding| b.guest_attempt_id = "another".into(),
        |b: &mut protocol::ReceiptBinding| b.guest_boot_id = "another".into(),
    ] {
        let (mut run, _, _) = running();
        let (hash, data) = encoded(&receipt());
        let mut bind = binding();
        mutate(&mut bind);
        assert!(run.store_receipt(&hash, &data, &bind).is_err());
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
    assert!(run.store_receipt(&hash, &data, &binding()).is_err());
    assert_eq!(
        std::fs::read(dir.path().join("evidence/jail.json")).unwrap(),
        serde_json::to_vec(&receipt()).unwrap()
    );
    assert_eq!(
        serde_json::to_value(run.final_limits()).unwrap(),
        receipt()["applied"]["limits"]
    );
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
        protocol::FromVm::Done { exit_code: 0 },
    ] {
        peer.write_all(&protocol::encode(&frame).unwrap()).unwrap();
    }
    assert!(matches!(
        run.wait(Deadline {
            at: Some(Instant::now() + Duration::from_secs(1))
        }),
        RunEvent::Unknown { .. }
    ));
    assert_eq!(
        std::fs::read(dir.path().join("stdout")).unwrap(),
        b"visible"
    );
    assert_eq!(
        std::fs::read(dir.path().join("stderr")).unwrap(),
        b"diagnostic"
    );
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
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
    peer.write_all(&protocol::encode(&protocol::FromVm::Done { exit_code: 0 }).unwrap())
        .unwrap();
    assert!(
        matches!(run.wait(Deadline {at:Some(Instant::now()+Duration::from_secs(1))}),RunEvent::Unknown {reason} if reason.contains("record write"))
    );
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
}

#[test]
fn unbound_receipt_never_becomes_verified_on_the_cleanup_path() {
    let (mut run, mut peer, _) = running();
    let (sha256, data) = encoded(&receipt());
    peer.write_all(&protocol::encode(&protocol::FromVm::Receipt { sha256, data }).unwrap())
        .unwrap();
    peer.write_all(&protocol::encode(&protocol::FromVm::Done { exit_code: 0 }).unwrap())
        .unwrap();
    assert!(matches!(
        run.wait(Deadline {
            at: Some(Instant::now() + Duration::from_secs(1))
        }),
        RunEvent::Unknown { .. }
    ));
    assert_eq!(run.wait_tree(Duration::ZERO).tree_empty, None);
}

#[test]
fn ready_must_match_locally_verified_digests() {
    let manifest = image::ImageManifest {
        status: "prepared".into(),
        disk_sha256: "d".repeat(64),
        helper_sha256: "h".repeat(64),
        custodian_sha256: "c".repeat(64),
        seed_sha256: "s".repeat(64),
    };
    let mut ready = ReadyFrame {
        boot_id: "boot".into(),
        disk_sha256: manifest.disk_sha256.clone(),
        helper_sha256: manifest.helper_sha256.clone(),
        custodian_sha256: manifest.custodian_sha256.clone(),
        seed_sha256: manifest.seed_sha256.clone(),
        vsock_port: 1024,
    };
    verify_ready(&ready, &manifest).unwrap();
    ready.disk_sha256 = "forged".into();
    assert!(verify_ready(&ready, &manifest).is_err());
}

#[test]
fn guest_limits_must_match_every_requested_value_and_requirement() {
    for pointer in [
        "/applied/limits/0/requested",
        "/applied/limits/1/required",
        "/applied/limits/2/requested",
        "/applied/limits/3/applied",
    ] {
        let (mut run, _, _) = running();
        let mut changed = receipt();
        let field = changed.pointer_mut(pointer).unwrap();
        *field = if field.is_boolean() {
            Value::Bool(false)
        } else {
            Value::String("wrong".into())
        };
        let (hash, data) = encoded(&changed);
        assert!(
            run.store_receipt(&hash, &data, &binding()).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn macos_owner_identity_and_unmeasured_capability_refusal_are_explicit() {
    let inputs = crate::policy::ResolveInputs {
        platform: Os::Linux,
        base_profile: crate::policy::ProfileName::Tool,
        policy_name: "tool".into(),
        baseline: crate::profiles::baseline(crate::policy::ProfileName::Tool, Os::Linux, &|_| None),
        workspace: b"/work".to_vec(),
        scratch: crate::policy::ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers: Vec::new(),
    };
    let resolved = crate::policy::resolve(&inputs).unwrap();
    let plan = PlanRequest {
        snapshot: resolved.snapshot,
        requirements: resolved.requirements,
    };
    let platform = VmPlatform {
        data_dir: PathBuf::from("/unused"),
        install: Install {
            root: PathBuf::from("/unused"),
            manifest: image::ImageManifest {
                status: "prepared".into(),
                disk_sha256: "d".into(),
                helper_sha256: "h".into(),
                custodian_sha256: "c".into(),
                seed_sha256: "s".into(),
            },
        },
    };
    let owner = platform
        .owner_identity()
        .expect("VM supervisor is a macOS process");
    assert_eq!(owner.pid, std::process::id());
    let capabilities = platform.probe(&plan);
    assert!(!capabilities.is_empty());
    assert!(
        capabilities
            .iter()
            .all(|row| !row.satisfies() && row.measured_at.is_none())
    );
    assert!(validate_policy(&plan.snapshot).is_err());
}
