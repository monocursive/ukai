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
            {"key":"pids","requested":"64","required":false,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null},
            {"key":"mem","requested":"536870912","required":false,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null},
            {"key":"swap","requested":"0","required":false,"applied":true,"mechanism":"cgroup","scope":"tree","hit":null}
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
            "wall":{"value":"30000","required":true},
            "pids":{"value":"256","required":false},"cpu":null
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
        assert_eq!(
            serde_json::to_value(run.final_limits()).unwrap(),
            receipt()["applied"]["limits"]
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
    // The offline tool shape is the measured one (2026-11-02): every row
    // answers available, names the mechanism and carries the measurement
    // record. An unsupported shape's rows stay unavailable with the reason.
    assert!(capabilities.iter().all(|row| {
        row.satisfies()
            && row.mechanism.as_deref() == Some("linux-bwrap-in-vm")
            && row.evidence_ref.is_some()
            && row.measured_at.is_some()
    }));
    // The baseline's 30m wall exceeds the guest grammar; layer an explicit
    // in-grammar ceiling so the policy shape itself is the tested variable.
    let mut shaped = inputs.clone();
    shaped.layers.push(crate::policy::Layer {
        origin: crate::policy::LayerOrigin::Environment,
        base_dir: None,
        delta: crate::policy::PolicyDelta {
            limits: crate::policy::Ceilings {
                wall: Some(crate::policy::Ceiling {
                    value: 60_000,
                    requested: "60000".into(),
                    required: true,
                }),
                ..Default::default()
            },
            ..Default::default()
        },
    });
    let shaped = crate::policy::resolve(&shaped).unwrap();
    let plan = PlanRequest {
        snapshot: shaped.snapshot.clone(),
        requirements: shaped.requirements,
    };
    let capabilities = platform.probe(&plan);
    assert!(capabilities.iter().all(|row| {
        row.satisfies()
            && row.mechanism.as_deref() == Some("linux-bwrap-in-vm")
            && row.evidence_ref.is_some()
            && row.measured_at.is_some()
    }));
    assert!(validate_policy(&plan.snapshot).is_ok());
    let mut agent = inputs;
    agent.base_profile = crate::policy::ProfileName::Agent;
    let agent = crate::policy::resolve(&agent).unwrap();
    let plan = PlanRequest {
        snapshot: agent.snapshot,
        requirements: agent.requirements,
    };
    let capabilities = platform.probe(&plan);
    assert!(
        capabilities
            .iter()
            .all(|row| !row.satisfies() && row.measured_at.is_none())
    );
    assert!(validate_policy(&plan.snapshot).is_err());
}
