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
        network,
        guest_policy_digest: GUEST_POLICY.into(),
        stdout: std::fs::File::create(dir.path().join("stdout")).unwrap(),
        stderr: std::fs::File::create(dir.path().join("stderr")).unwrap(),
    };
    (
        VmRunning {
            inner: execution,
            receipt: None,
            guest: None,
            stop: None,
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
            disk_sha256: "0123456789abcdef".repeat(4),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
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
                status: "prepared".into(),
                disk_sha256: "d".repeat(64),
                helper_sha256: "h".repeat(64),
                custodian_sha256: "c".repeat(64),
                seed_sha256: "s".repeat(64),
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
        snapshot,
        requirements,
    }
}

/// The requirements the 2026-11-04 live phase measured alone
/// (`macos-vm-live-2026-11-04/capabilities.json`), in the record's order.
const LIVE_MEASURED: [&str; 5] = [
    "limit:wall",
    "limit:pids",
    "limit:mem",
    "filesystem_containment",
    "network_none",
];

/// Decision D2: exactly the requirements the live phase measured alone
/// answer available, with their row's time and pointer. Every other row of a
/// carried policy is `vm:not-measured`, `tree_termination` among them, so a
/// carried `run --vm` still refuses at probing.
#[test]
fn only_the_live_phase_measurements_answer_available() {
    let listed: Vec<&str> = GUEST_MEASUREMENTS
        .iter()
        .map(|row| row.requirement)
        .collect();
    assert_eq!(listed, LIVE_MEASURED);
    let platform = platform(Path::new("/unused"));
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
        assert!(!tree.satisfies(), "no probe measures it yet: {tree:?}");
    }
    let plan = request(tool());
    assert!(
        platform
            .probe(&plan)
            .iter()
            .any(|row| row.name == "network_none" && row.satisfies())
    );
}

/// Each row's record is in the repository: its pointer names a `true`
/// verdict under `/measurements/<requirement>`, its time is the time that
/// entry states and the start of the attempt the entry names, and the record
/// passed as a whole.
#[test]
fn every_measurement_row_resolves_in_its_record() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for row in GUEST_MEASUREMENTS {
        let (path, pointer) = row.record.split_once('#').expect("path#pointer");
        let bytes = std::fs::read(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            record.pointer(pointer),
            Some(&serde_json::Value::Bool(true)),
            "{}",
            row.record
        );
        let entry_pointer = pointer
            .strip_suffix("/verdict")
            .expect("a row points at a verdict");
        assert_eq!(entry_pointer, format!("/measurements/{}", row.requirement));
        let entry = record.pointer(entry_pointer).unwrap();
        assert_eq!(entry["measured_at"], row.measured_at, "{}", row.record);
        let capability = entry["capability"].as_str().expect("capability name");
        let attempt = &record["results"][capability];
        assert_eq!(attempt["started_at"], row.measured_at, "{}", row.record);
        assert_eq!(attempt["attempt_id"], entry["attempt_id"], "{}", row.record);
        assert_eq!(record["summary"][capability], true, "{}", row.record);
        assert_eq!(record["summary"]["outcome"], "PASS");
    }
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
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/benchmarks/jail/results/macos-vm-claude-2026-11-03/k113-attempt/evidence/jail.json"
    );
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
        Ok(Box::new(WallRunning { waits: 0 }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown { tree: None })
    }
}

impl RunningExecution for WallRunning {
    // A platform whose final rows are the guest's (hit false): the order of
    // the settle, not this platform, must keep the host's hit.
    fn final_limits(&self) -> Vec<AppliedLimit> {
        serde_json::from_value(k113_guest()["applied"]["limits"].clone()).unwrap()
    }
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.waits += 1;
        if self.waits == 1 {
            RunEvent::WallExpired
        } else {
            RunEvent::TargetExited { code: 137 }
        }
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
        schema: protocol::SCHEMA_ATTEMPT.into(),
        boot_id: boot_id.into(),
        disk_sha256: "d".repeat(64),
        helper_sha256: "h".repeat(64),
        custodian_sha256: "c".repeat(64),
        seed_sha256: "s".repeat(64),
        vsock_port: 1024,
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
    // A serve running another image than the verified installation.
    let mut other = status(Some(&workspace), false);
    if let protocol::FromControl::Status { disk_sha256, .. } = &mut other {
        *disk_sha256 = "e".repeat(64);
    }
    let error = prepare_against(plan(), other, answering("vm-test", Vec::new()), wait)
        .expect("prepare returned")
        .unwrap_err();
    assert!(error.contains("another image"), "{error}");
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
