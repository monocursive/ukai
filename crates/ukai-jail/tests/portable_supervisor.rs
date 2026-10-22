//! The supervisor's own guarantees over a simulated platform, natively on
//! every host: the §8.2 preparation budget crosses the platform seam, and
//! a claimed attempt always ends with a receipt (I01).
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser as _;
use ukai_jail::capability::{Capability, CapabilityScope, CapabilityStatus};
use ukai_jail::cli;
use ukai_jail::config::EnvSettings;
use ukai_jail::platform::{
    OwnerIdentity, PlanRequest, Platform, PlatformIdentity, PreparedExecution, PreparedPlan, Sinks,
};
use ukai_jail::records::{ErrorCode, ErrorStage, JailError, Remediation, rfc3339_utc};
use ukai_jail::supervisor;

mod common;
use common::sim;

/// A platform whose preparation always refuses, after recording what it
/// was given.
#[derive(Default)]
struct Sim {
    /// How long probing takes: time spent inside the preparation budget
    /// before `prepare` is reached.
    probe_delay: Duration,
    /// What `prepare` saw of the preparation budget.
    prepare_left: Arc<Mutex<Option<Duration>>>,
    /// A state root whose attempts get a directory planted at
    /// `trace.ndjson` while the supervisor claims them: a trace file that
    /// can no longer be created once the claim exists.
    plant_trace_dir_under: Option<PathBuf>,
}

impl Platform for Sim {
    fn identity(&self) -> PlatformIdentity {
        sim::identity()
    }

    fn owner_identity(&self) -> Option<OwnerIdentity> {
        // The claim reads the owner's identity just before it publishes.
        if let Some(data) = &self.plant_trace_dir_under
            && let Ok(entries) = std::fs::read_dir(data.join("attempts"))
        {
            for entry in entries.flatten() {
                let _ = std::fs::create_dir(entry.path().join("trace.ndjson"));
            }
        }
        Some(sim::owner())
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        std::thread::sleep(self.probe_delay);
        plan.requirements
            .iter()
            .map(|name| Capability {
                name: name.to_string(),
                status: CapabilityStatus::Available,
                scope: CapabilityScope::Tree,
                mechanism: Some("simulation".into()),
                reason_code: None,
                measured_at: Some(rfc3339_utc(std::time::SystemTime::now())),
                evidence_ref: None,
            })
            .collect()
    }

    fn prepare(
        &self,
        plan: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        *self.prepare_left.lock().unwrap() = Some(plan.prepare_deadline.remaining());
        Err(JailError::new(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::HostSetup,
            "the simulation prepares nothing".to_owned(),
        ))
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = common::private_tempdir();
        let root = dir.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        Fixture {
            _root: dir,
            root,
            workspace,
        }
    }

    fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    fn run(&self, sim: Sim) -> supervisor::RunReport {
        let cli::Command::Run(args) = cli::Cli::parse_from([
            "ukai-jail",
            "run",
            "--workspace",
            self.workspace.to_str().unwrap(),
            "--",
            "simulated-target",
        ])
        .command
        else {
            unreachable!()
        };
        let context = supervisor::Context {
            platform: Box::new(sim),
            env_settings: EnvSettings {
                config_dir: Some(self.root.join("config")),
                data_dir: Some(self.data()),
                ..Default::default()
            },
            cwd: self.workspace.clone(),
            home: None,
            env_lookup: Box::new(|_| None),
        };
        supervisor::run(&context, &args)
    }

    fn attempts(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.data().join("attempts"))
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default()
    }
}

/// §8.2: the 30-second preparation budget covers steps 1 to 5. The
/// platform's steps 3 to 5 get what resolution, the claim and probing left
/// of it, not a fresh 30 seconds of their own.
#[test]
fn the_platform_prepares_within_what_is_left_of_the_supervisors_budget() {
    let fixture = Fixture::new();
    let prepare_left = Arc::new(Mutex::new(None));
    let probe_delay = Duration::from_millis(300);
    let report = fixture.run(Sim {
        probe_delay,
        prepare_left: Arc::clone(&prepare_left),
        ..Sim::default()
    });
    assert_eq!(
        report.error.as_ref().map(|error| error.code),
        Some(ErrorCode::BackendUnavailable),
        "{:?}",
        report.error
    );
    let left = prepare_left.lock().unwrap().expect("prepare ran");
    assert!(
        left <= supervisor::PREPARE_BUDGET - probe_delay,
        "the platform was given {left:?}, more than the {:?} probing left",
        supervisor::PREPARE_BUDGET - probe_delay
    );
    assert!(
        left > supervisor::PREPARE_BUDGET / 2,
        "the budget is the supervisor's, not an expired one: {left:?}"
    );
}

/// I01: an attempt that is claimed always ends with a receipt. The output
/// channels a refusal needs are opened before the claim, so a trace file
/// that cannot be created at the claim's moment can no longer leave a
/// claimed attempt with nothing to say what became of it.
#[test]
fn a_claimed_attempt_always_has_a_receipt() {
    let fixture = Fixture::new();
    let report = fixture.run(Sim {
        plant_trace_dir_under: Some(fixture.data()),
        ..Sim::default()
    });
    let attempts = fixture.attempts();
    assert_eq!(attempts.len(), 1, "{attempts:?}");
    let attempt = &attempts[0];
    if !attempt.join("jail-state.json").exists() {
        // Refused before the claim: nothing was claimed, nothing is owed.
        assert!(report.receipt.is_none());
        return;
    }
    let receipt_path = attempt.join("jail.json");
    assert!(
        receipt_path.exists(),
        "a claimed attempt has no receipt; the run reported {:?}",
        report.error
    );
    let receipt = common::read_receipt(&receipt_path);
    assert_eq!(receipt["phase"], "refused", "{receipt:#}");
}

/// §14.1: plain `doctor` reports the host; only `--launch` has credential
/// sources whose placement against the writable grants it must judge, so a
/// grant it cannot inspect is no reason for plain `doctor` to fail.
#[test]
fn plain_doctor_never_inspects_credential_placement() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new();
    let config = fixture.root.join("config");
    std::fs::create_dir(&config).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sealed = fixture.root.join("sealed");
    std::fs::create_dir_all(sealed.join("inner")).unwrap();
    let config_file = config.join("config.toml");
    std::fs::write(
        &config_file,
        format!(
            "[jail.filesystem]\nread_write = [{:?}]\n",
            sealed.join("inner").display().to_string()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&config_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // The grant's parent cannot be searched, so its identity cannot be read.
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let context = supervisor::Context {
        platform: Box::new(Sim::default()),
        env_settings: EnvSettings {
            config_dir: Some(config),
            data_dir: Some(fixture.data()),
            ..Default::default()
        },
        cwd: fixture.workspace.clone(),
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let cli::Command::Doctor(args) = cli::Cli::parse_from([
        "ukai-jail",
        "doctor",
        "--workspace",
        fixture.workspace.to_str().unwrap(),
    ])
    .command
    else {
        unreachable!()
    };
    let result = supervisor::doctor(&context, &args);
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
    let report = result.unwrap_or_else(|error| panic!("plain doctor refused: {error:?}"));
    assert!(report.launch.is_none());
}

#[test]
#[cfg(target_os = "macos")]
fn p2_vm_none_is_a_guarantee_refusal_before_probe_or_prepare() {
    struct NoBoundary;
    impl Platform for NoBoundary {
        fn identity(&self) -> PlatformIdentity {
            sim::identity()
        }
        fn owner_identity(&self) -> Option<OwnerIdentity> {
            Some(sim::owner())
        }
        fn probe(&self, _: &PlanRequest) -> Vec<Capability> {
            panic!("the unsupported profile must refuse before probing")
        }
        fn prepare(
            &self,
            _: PreparedPlan,
            _: Sinks,
        ) -> Result<Box<dyn PreparedExecution>, JailError> {
            panic!("the unsupported profile must refuse before staging")
        }
    }
    let fixture = Fixture::new();
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ukai-jail",
        "run",
        "--vm",
        "--profile",
        "none",
        "--terminal",
        "detach",
        "--",
        "must-never-execute",
    ])
    .command
    else {
        unreachable!()
    };
    let ctx = supervisor::Context {
        platform: Box::new(NoBoundary),
        env_settings: EnvSettings {
            config_dir: Some(fixture.root.join("config")),
            data_dir: Some(fixture.data()),
            ..Default::default()
        },
        cwd: fixture.workspace.clone(),
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let report = supervisor::run(&ctx, &args);
    assert_eq!(report.exit_code, 125, "{:?}", report.error);
    let error = report.error.unwrap();
    assert_eq!(
        (error.code, error.stage, error.remediation),
        (
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Resolving,
            Remediation::Unsupported
        )
    );
    assert_eq!(error.key_path.as_deref(), Some("--vm"));
    assert!(fixture.attempts().is_empty());
}

/// The boundary is scripted; the owner is this real macOS process. No VM
/// starts. This exercises persisted state and native gc's birth-time probe.
#[test]
#[cfg(target_os = "macos")]
fn p2_vm_state_and_gc_use_the_host_owner_not_the_guest_policy() {
    use ukai_jail::gc::{self, Host as _};
    use ukai_jail::records::Os;
    struct GuestPolicy;
    impl Platform for GuestPolicy {
        fn identity(&self) -> PlatformIdentity {
            sim::identity()
        }
        fn state_identity(&self) -> PlatformIdentity {
            ukai_jail::platform::current().identity()
        }
        fn owner_identity(&self) -> Option<OwnerIdentity> {
            ukai_jail::platform::current().owner_identity()
        }
        fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
            Sim::default().probe(plan)
        }
        fn prepare(
            &self,
            plan: PreparedPlan,
            sinks: Sinks,
        ) -> Result<Box<dyn PreparedExecution>, JailError> {
            assert_eq!(plan.request.snapshot.platform, Os::Linux);
            Sim::default().prepare(plan, sinks)
        }
    }
    let fixture = Fixture::new();
    let cli::Command::Run(args) = cli::Cli::parse_from([
        "ukai-jail",
        "run",
        "--vm",
        "--profile",
        "tool",
        "--terminal",
        "detach",
        "--workspace",
        fixture.workspace.to_str().unwrap(),
        "--",
        "simulated-target",
    ])
    .command
    else {
        unreachable!()
    };
    let ctx = supervisor::Context {
        platform: Box::new(GuestPolicy),
        env_settings: EnvSettings {
            config_dir: Some(fixture.root.join("config")),
            data_dir: Some(fixture.data()),
            ..Default::default()
        },
        cwd: fixture.workspace.clone(),
        home: None,
        env_lookup: Box::new(|_| None),
    };
    let report = supervisor::run(&ctx, &args);
    assert_eq!(
        report.error.as_ref().map(|e| e.code),
        Some(ErrorCode::BackendUnavailable)
    );
    let attempts = fixture.attempts();
    assert_eq!(attempts.len(), 1);
    let attempt = &attempts[0];
    let state_path = attempt.join("jail-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    let host_owner = ctx
        .platform
        .owner_identity()
        .expect("native process identity");
    let host_platform = ctx.platform.state_identity();
    assert_eq!(state["os"], "macos");
    assert_eq!(state["arch"], host_platform.arch);
    assert_eq!(state["kernel"], host_platform.kernel);
    assert_eq!(state["owner"]["pid"], host_owner.pid);
    assert_eq!(state["owner"]["boot_id"], host_owner.boot_id);
    assert_eq!(
        state["owner"]["start_time_ticks"],
        host_owner.start_time_ticks
    );
    let receipt_path = attempt.join("jail.json");
    let mut receipt = common::read_receipt(&receipt_path);
    assert_eq!(receipt["platform"]["os"], "linux");
    // A guest receipt's process boot differs from the host boot by design.
    // An unverified guest end never authorizes host cleanup or a token kill.
    receipt["phase"] = "enforced".into();
    receipt["lifetime"]["boundary"] = "pid_namespace".into();
    receipt["lifetime"]["integrity"] = "verified".into();
    receipt["lifetime"]["tree_empty"] = serde_json::Value::Null;
    receipt["lifetime"]["native"] = serde_json::json!({"os": "linux", "details": {}});
    receipt["process"] = serde_json::json!({
        "pid": 42,
        "identity": {"kind": "linux_boot_start", "value": {"boot_id": "guest-boot", "start_time_ticks": "3"}}
    });
    std::fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let host = gc::native_host(&ctx);
    assert_eq!(host.identity().os, Os::Macos);
    let args = cli::GcArgs {
        dry_run: false,
        json: false,
        abandon: None,
    };
    let report = gc::gc_with(&ctx, &args, &host, gc::Options::DEFAULT).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].owner.as_deref(),
        Some("alive"),
        "{:?}",
        report.entries
    );
    // macOS checks epoch-second birth time, including reuse; it never reads
    // these as Linux /proc start ticks just because the policy is Linux.
    state["owner"]["start_time_ticks"] = (host_owner.start_time_ticks + 1).into();
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let report = gc::gc_with(&ctx, &args, &host, gc::Options::DEFAULT).unwrap();
    assert_eq!(
        report.entries[0].owner.as_deref(),
        Some("dead: its pid was reused (another birth time)")
    );
    assert!(!report.entries[0].reason.contains("killed_target"));
    assert!(
        report.entries[0]
            .cgroup
            .as_deref()
            .is_some_and(|reason| reason.contains("no target identity")),
        "{:?}",
        report.entries
    );
    assert_eq!(
        gc::orphans::announce(&ctx),
        1,
        "VM planning still scans host orphans"
    );
    state["os"] = "linux".into();
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(
        gc::orphans::announce(&ctx),
        0,
        "a foreign owner is not read as a Mac process"
    );
}
