//! J3 launch profiles, credential staging and cleanup, portable part.
//!
//! These run natively on macOS and on Linux. Resolution is exercised through
//! the real `resolve_plan`; the attempt lifecycle through the real supervisor
//! over a simulated platform, so staging, the hand-off, refusal and cleanup
//! run against the real filesystem while the boundary is scripted. Every
//! credential here is a fixture file this test writes; none is an operator's.
//!
//! Acceptance rows: C01 (sources preserved, provenance without bytes, byte
//! paths lossless, unsafe `state_subdirs` and every `LD_*`/`DYLD_*` key
//! refuse), C02 (normal exit and refusal clean vendor state, an interrupted
//! cleanup resumes, symlinks cannot redirect deletion), P04's credential
//! sub-clause (FIFO, device, socket, symlink, directory and oversize sources
//! refuse before exec) and I02's data-only boundary for the bundled profiles.
//!
//! What this file does not prove: that a real bubblewrap boundary binds the
//! staged objects. `conformance_j3_credentials.rs` does that on Linux.

use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser as _;
use sha2::{Digest as _, Sha256};
use ukai_jail::capability::Capability;
use ukai_jail::cli::{self, PolicyArgs, Selection};
use ukai_jail::config::EnvSettings;
use ukai_jail::credentials::LaunchHandoff;
use ukai_jail::lifecycle::{BoundaryKind, Integrity, VerificationScope};
use ukai_jail::platform::{
    BoundaryIdentity, Deadline, OwnerIdentity, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, RunEvent, RunningExecution, Sinks, StopReason, Teardown,
    TreeObservation,
};
use ukai_jail::policy::{EnvValue, ProfileName, RootToken};
use ukai_jail::records::{
    ErrorCode, JailError, NativeLifetime, Os, Receipt, Remediation, StateCleanup,
};
use ukai_jail::{cleanup, launch_profile, supervisor};

mod common;
use common::sim;

// ---------------------------------------------------------------------------
// Fixture layout
// ---------------------------------------------------------------------------

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
    creds: PathBuf,
    outside: PathBuf,
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

impl Fixture {
    fn new() -> Fixture {
        let dir = common::private_tempdir();
        // Canonical, so that macOS's /var -> /private/var alias is not a
        // symlink on a credential source's no-follow walk.
        let root = dir.path().canonicalize().unwrap();
        let fixture = Fixture {
            config: root.join("config"),
            data: root.join("data"),
            workspace: root.join("workspace"),
            creds: root.join("creds"),
            outside: root.join("outside"),
            root,
            _root: dir,
        };
        for path in [
            &fixture.config,
            &fixture.data,
            &fixture.workspace,
            &fixture.creds,
            &fixture.outside,
        ] {
            private_dir(path);
        }
        private_dir(&fixture.config.join("launch"));
        std::fs::write(fixture.outside.join("precious"), b"outside the attempt").unwrap();
        fixture
    }

    fn launch(&self, name: &str, text: &str) -> PathBuf {
        let path = self.config.join("launch").join(format!("{name}.toml"));
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn credential(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.creds.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn context(&self, platform: Box<dyn Platform>, home: Option<PathBuf>) -> supervisor::Context {
        supervisor::Context {
            platform,
            env_settings: EnvSettings {
                config_dir: Some(self.config.clone()),
                data_dir: Some(self.data.clone()),
                ..Default::default()
            },
            cwd: self.workspace.clone(),
            home,
            env_lookup: Box::new(|_| None),
        }
    }

    fn plan(&self, policy: PolicyArgs) -> Result<supervisor::Plan, JailError> {
        let ctx = self.context(Box::new(Sim::default()), Some(self.root.join("home")));
        supervisor::resolve_plan(&ctx, &policy)
    }

    fn run(&self, sim: Sim, flags: &[&str]) -> supervisor::RunReport {
        let mut argv: Vec<String> = vec!["ukai-jail".into(), "run".into()];
        argv.push("--workspace".into());
        argv.push(self.workspace.display().to_string());
        argv.extend(flags.iter().map(|flag| (*flag).to_owned()));
        argv.push("--".into());
        argv.push("simulated-target".into());
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        let ctx = self.context(Box::new(sim), Some(self.root.join("home")));
        supervisor::run(&ctx, &args)
    }

    fn gc(&self, dry_run: bool) -> Result<ukai_jail::gc::Report, JailError> {
        let ctx = self.context(Box::new(Sim::default()), None);
        ukai_jail::gc::gc(
            &ctx,
            &cli::GcArgs {
                dry_run,
                json: false,
            },
        )
    }
}

fn launch_args(name: &str, workspace: &Path) -> PolicyArgs {
    PolicyArgs {
        selection: Selection {
            launch: Some(name.to_owned()),
            workspace: Some(workspace.to_path_buf()),
            ..Selection::default()
        },
        ..PolicyArgs::default()
    }
}

/// The refusal a resolution must produce (`Plan` has no `Debug`).
fn refused(result: Result<supervisor::Plan, JailError>, label: &str) -> JailError {
    match result {
        Ok(_) => panic!("{label}: resolution must refuse"),
        Err(error) => error,
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::from("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn attempt_dir(report: &supervisor::RunReport) -> PathBuf {
    report
        .receipt_path
        .as_ref()
        .expect("an attempt was allocated")
        .parent()
        .unwrap()
        .to_path_buf()
}

fn jail_state(report: &supervisor::RunReport) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(attempt_dir(report).join("jail-state.json")).unwrap())
        .unwrap()
}

fn receipt_json(report: &supervisor::RunReport) -> serde_json::Value {
    serde_json::to_value(report.receipt.as_ref().expect("a receipt")).unwrap()
}

// ---------------------------------------------------------------------------
// The checked-in schemas
// ---------------------------------------------------------------------------

/// Schema validation; a receipt also keeps the rules the schema cannot state
/// (`common::semantic_receipt`).
fn assert_schema(name: &str, value: &serde_json::Value) {
    let validator = &common::validators()[name];
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{name} rejects {value:#}: {errors:?}");
    if name == "jail-receipt" {
        common::assert_semantic_receipt(value);
    }
}

// ---------------------------------------------------------------------------
// A scripted platform: real staging and cleanup, scripted boundary
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum TreeEnd {
    #[default]
    Verified,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum TargetEnd {
    #[default]
    Exit0,
    ExecError,
}

/// What the simulated platform saw of the hand-off.
#[derive(Clone, Debug, Default)]
struct Seen {
    prepared: bool,
    vendor_path: Option<PathBuf>,
    /// `(id, dest, identity)` of each bind handle, as `fstat` reports it.
    binds: Vec<(String, String, (u64, u64))>,
}

type Activity = Arc<dyn Fn(&Path) + Send + Sync>;
/// `(relative path, bytes, permission bits)` of one staged object.
type Listed = (String, Vec<u8>, u32);
/// Makes one special source object at a path.
type Maker = Box<dyn Fn(&Path)>;
/// Undoes an obstruction.
type Undo = Box<dyn Fn() + Send>;

#[derive(Clone, Default)]
struct Sim {
    /// The network mode the scripted boundary reports as applied.
    network: Arc<Mutex<String>>,
    tree: TreeEnd,
    target: TargetEnd,
    release_fails: bool,
    /// Whether a failed release reports a verified teardown.
    release_teardown_verified: bool,
    /// Whether a failed release reports a teardown that lost integrity.
    release_teardown_lost: bool,
    /// How many bytes of padding the release failure's message carries.
    release_error_padding: usize,
    /// When set, the data directory in whose (single) attempt a
    /// `vendor-state` directory appears during probing: an operator process
    /// racing the claim.
    plant_vendor_state: Option<PathBuf>,
    /// Report no applied mechanisms (the `none` profile applies none).
    unapplied: bool,
    /// What the "child" does in vendor state, given its host path.
    activity: Option<Activity>,
    seen: Arc<Mutex<Seen>>,
}

fn verified_tree() -> TreeObservation {
    sim::verified_tree(VerificationScope::AttemptTree)
}

impl Platform for Sim {
    fn owner_identity(&self) -> Option<OwnerIdentity> {
        Some(sim::owner())
    }
    fn identity(&self) -> PlatformIdentity {
        sim::identity()
    }
    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        if let Some(data) = &self.plant_vendor_state {
            let attempt = std::fs::read_dir(data.join("attempts"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            std::fs::create_dir(attempt.join("vendor-state")).unwrap();
            std::fs::write(attempt.join("vendor-state/precious"), b"not this attempt's").unwrap();
        }
        sim::available(plan, "launch simulation")
    }
    fn prepare(
        &self,
        plan: PreparedPlan,
        _: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        plan.request
            .snapshot
            .network
            .mode
            .as_str()
            .clone_into(&mut self.network.lock().unwrap());
        let mut seen = self.seen.lock().unwrap();
        seen.prepared = true;
        if let Some(handoff) = &plan.launch {
            observe_handoff(handoff, &mut seen);
        }
        drop(seen);
        if let (Some(activity), Some(handoff)) = (&self.activity, &plan.launch)
            && let Some(vendor) = &handoff.vendor_state
        {
            activity(&vendor.host_path);
        }
        Ok(Box::new(SimPrepared { sim: self.clone() }))
    }
}

fn observe_handoff(handoff: &LaunchHandoff, seen: &mut Seen) {
    use std::os::fd::AsFd as _;
    seen.vendor_path = handoff
        .vendor_state
        .as_ref()
        .map(|vendor| vendor.host_path.clone());
    for bind in &handoff.binds {
        let stat = ukai_jail::state::anchored::fstat(bind.fd.as_fd()).unwrap();
        seen.binds
            .push((bind.id.clone(), bind.dest.to_display(), stat.identity()));
    }
}

struct SimPrepared {
    sim: Sim,
}

impl PreparedExecution for SimPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        BoundaryIdentity {
            boundary: BoundaryKind::PidNamespace,
            verification_scope: VerificationScope::AttemptTree,
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: Default::default(),
            }),
            process: Some(ukai_jail::records::ProcessRecord {
                pid: 2,
                identity: ukai_jail::records::ProcessIdentity {
                    kind: "linux_boot_start".into(),
                    value: serde_json::from_value(serde_json::json!({
                        "boot_id": sim::BOOT_ID,
                        "start_time_ticks": 1
                    }))
                    .unwrap(),
                },
            }),
            backend: Some("simulation".into()),
            backend_version: Some("1".into()),
        }
    }
    fn applied(&self) -> Option<ukai_jail::records::Applied> {
        if self.sim.unapplied {
            return None;
        }
        // A scripted application with the shape the receipt contract requires
        // of an enforced boundary; the mechanisms say they are simulated.
        use ukai_jail::records::{Applied, AppliedFilesystem, AppliedNetwork, AppliedSyscalls};
        Some(Applied {
            filesystem: Some(AppliedFilesystem {
                mechanism: "simulation".into(),
                protected_coverage: "none".into(),
                mounts: Vec::new(),
            }),
            network: AppliedNetwork {
                mode: self.sim.network.lock().unwrap().clone(),
                mechanism: Some("simulation".into()),
                allowed_hosts: Vec::new(),
                tls_only: Vec::new(),
            },
            syscalls: Some(AppliedSyscalls {
                mechanism: "simulation".into(),
                digest: sha256(b"simulation"),
            }),
            limits: Vec::new(),
            environment_names: Vec::new(),
            removed_environment_names: Vec::new(),
            terminal: None,
        })
    }
    fn release(
        self: Box<Self>,
    ) -> Result<Box<dyn RunningExecution>, Box<ukai_jail::platform::ReleaseFailure>> {
        if self.sim.release_fails {
            let tree = if self.sim.release_teardown_lost {
                Some(TreeObservation {
                    tree_empty: None,
                    verified_at: None,
                    verification_scope: VerificationScope::AttemptTree,
                    integrity: Integrity::Lost,
                })
            } else {
                self.sim.release_teardown_verified.then(verified_tree)
            };
            return Err(Box::new(ukai_jail::platform::ReleaseFailure {
                error: JailError::new(
                    ErrorCode::BackendUnavailable,
                    ukai_jail::records::ErrorStage::Released,
                    Remediation::Retry,
                    format!(
                        "simulated release failure{}",
                        "x".repeat(self.sim.release_error_padding)
                    ),
                ),
                teardown: tree.map(|tree| Teardown { tree: Some(tree) }),
            }));
        }
        Ok(Box::new(SimRunning {
            sim: self.sim,
            step: 0,
        }))
    }
    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(Teardown {
            tree: Some(verified_tree()),
        })
    }
}

struct SimRunning {
    sim: Sim,
    step: u8,
}

impl RunningExecution for SimRunning {
    fn wait(&mut self, _: Deadline) -> RunEvent {
        self.step += 1;
        match (self.sim.target, self.step) {
            (TargetEnd::ExecError, _) => RunEvent::ExecError {
                errno: "ENOENT".into(),
                detail: None,
            },
            (TargetEnd::Exit0, 1) => RunEvent::ExecConfirmed,
            (TargetEnd::Exit0, _) => RunEvent::TargetExited { code: 0 },
        }
    }
    fn request_stop(&mut self, _: StopReason) {}
    fn wait_tree(&mut self, _: Duration) -> TreeObservation {
        match self.sim.tree {
            TreeEnd::Verified => verified_tree(),
            TreeEnd::Unknown => TreeObservation {
                tree_empty: None,
                verified_at: None,
                verification_scope: VerificationScope::AttemptTree,
                integrity: Integrity::Pending,
            },
        }
    }
    fn observer_summary(&mut self) -> Option<ukai_jail::observer::CoverageSummary> {
        None
    }
}

// A two-credential agent profile over fixture files.
fn agent_profile(fixture: &Fixture, auth: &Path, config: &Path) {
    fixture.launch(
        "fixture",
        &format!(
            r#"
name = "fixture"
jail = "agent"
state_var = "FIXTURE_HOME"
home_is_state = true
state_subdirs = ["sessions/deep", "cache"]

[environment]
FIXTURE_MODE = "batch"
FIXTURE_CACHE = {{ state = "cache" }}

[credentials.auth]
source = "{}"
dest = "auth.json"
mode = "copy_rw"

[credentials.config]
source = "{}"
dest = "conf/config.toml"
mode = "bind_ro"

[network]
allow = ["api.example.test:443"]
"#,
            auth.display(),
            config.display()
        ),
    );
}

// ---------------------------------------------------------------------------
// Bundled data (I02: agent names live only in data)
// ---------------------------------------------------------------------------

#[test]
fn i02_the_bundled_profiles_are_valid_experimental_data_for_the_agent_jail() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/launch");
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 16);
    assert!(names.iter().any(|name| name == "claude-vault.toml"));
    assert!(names.iter().any(|name| name == "opencode-vault.toml"));
    for name in &names {
        let text = std::fs::read_to_string(directory.join(name)).unwrap();
        assert!(
            text.starts_with("# EXPERIMENTAL"),
            "{name} must say it is experimental"
        );
        let stem = name.strip_suffix(".toml").unwrap();
        let profile = launch_profile::parse_with(
            &text,
            stem,
            launch_profile::LaunchSource::Bundled,
            Some(b"/home/op"),
            Some(b"/home/op/.config/ukai"),
        )
        .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(profile.jail, ProfileName::Agent, "{name}");
        assert!(profile.needs_vendor_state(), "{name}");
        for credential in &profile.credentials {
            assert!(
                credential.source.as_bytes().starts_with(b"/home/op/"),
                "{name}: sources are the node's own files beneath the operator home"
            );
            // J12: a bundled vault credential the agent finds under its own
            // name is bound to the resolved program, and says how to provide
            // its source.
            if let Some(vault) = &credential.vault
                && vault.env.is_some()
            {
                assert_eq!(vault.binaries, ["@program"], "{name}: {}", credential.id);
                assert!(profile.hints.contains_key(&credential.id), "{name}");
            }
        }
        // §6.1 keeps credentials and allowed hosts off `tool`; the bundled
        // profiles ship their credential blocks commented out, so the
        // refusal is exercised only where one (or a host list) is declared.
        if !profile.credentials.is_empty() || !profile.network_allow.is_empty() {
            assert!(launch_profile::check_jail_permits(ProfileName::Tool, &profile).is_err());
        }
    }
}

#[test]
fn bundled_resolution_uses_embedded_data_only_when_operator_file_is_absent() {
    let fixture = Fixture::new();
    let plan = fixture
        .plan(launch_args("codex", &fixture.workspace))
        .unwrap();
    assert!(
        plan.resolved
            .provenance
            .iter()
            .any(|p| p.key == "launch.resolution" && p.detail.as_deref() == Some("bundled"))
    );
    fixture.launch(
        "codex",
        r#"name = "codex"
jail = "agent"
"#,
    );
    let plan = fixture
        .plan(launch_args("codex", &fixture.workspace))
        .unwrap();
    // The resolution is the `LaunchSource` spelling `doctor` reports; the
    // shadowing is recorded beside it.
    let detail = |key: &str| {
        plan.resolved
            .provenance
            .iter()
            .find(|p| p.key == key)
            .and_then(|p| p.detail.clone())
    };
    assert_eq!(
        detail("launch.resolution").as_deref(),
        Some("operator file")
    );
    assert_eq!(detail("launch.shadows").as_deref(), Some("bundled"));
}

// ---------------------------------------------------------------------------
// Resolution (C01 validation, §6.1, §6.2, §12)
// ---------------------------------------------------------------------------

#[test]
fn c01_a_launch_profile_resolves_into_the_snapshot_and_validates_against_the_schema() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"{\"token\":\"fixture-secret-1\"}");
    let config = fixture.credential("config.toml", b"model = \"fixture\"\n");
    agent_profile(&fixture, &auth, &config);
    let plan = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .expect("resolves");
    let snapshot = &plan.resolved.snapshot;
    assert_eq!(
        snapshot.profile,
        ProfileName::Agent,
        "the launch default jail"
    );
    assert!(snapshot.roots.vendor_state.is_some());
    let launch = snapshot.launch.as_ref().expect("the launch field group");
    let ids: Vec<&str> = launch.credentials.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["auth", "config"]);
    assert_eq!(
        launch.credentials[0].source.as_bytes(),
        auth.as_os_str().as_bytes()
    );
    let binding = |name: &str| {
        snapshot
            .environment
            .bindings
            .iter()
            .find(|binding| binding.name == name)
            .unwrap_or_else(|| panic!("{name} is bound"))
            .value
            .clone()
    };
    for name in ["FIXTURE_HOME", "HOME", "FIXTURE_CACHE"] {
        assert!(
            matches!(binding(name), EnvValue::Path(ref r) if r.root == RootToken::VendorState),
            "{name} points at vendor state, never a host path"
        );
    }
    assert!(
        plan.resolved
            .requirements
            .contains(&ukai_jail::capability::Requirement::CredentialStaging)
    );
    assert!(
        plan.resolved
            .grants
            .iter()
            .any(|grant| grant.kind == "allow_host")
    );
    let canonical = snapshot.to_canonical_value().unwrap();
    assert_schema("policy-snapshot", &canonical);
}

#[test]
fn c01_equivalent_launch_files_share_a_digest_and_semantic_changes_do_not() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let first = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .unwrap()
        .resolved
        .digest;
    // The same semantics, written in another order with other spelling:
    // keys and tables reordered, a source spelled through `..` and `.`.
    fixture.launch(
        "fixture",
        &format!(
            r#"
home_is_state = true
state_subdirs = ["cache", "sessions/deep"]
state_var = "FIXTURE_HOME"
jail = "agent"
name = "fixture"

[network]
allow = ["api.example.test:443"]

[credentials.config]
mode = "bind_ro"
dest = "conf/config.toml"
source = "{}/../creds/./config.toml"

[credentials.auth]
mode = "copy_rw"
dest = "auth.json"
source = "{}"

[environment]
FIXTURE_CACHE = {{ state = "cache" }}
FIXTURE_MODE = "batch"
"#,
            fixture.creds.display(),
            auth.display()
        ),
    );
    let second = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .unwrap()
        .resolved
        .digest;
    assert_eq!(first, second, "order and spelling are not semantics");

    let changed = std::fs::read_to_string(fixture.config.join("launch/fixture.toml"))
        .unwrap()
        .replace("\"batch\"", "\"interactive\"");
    fixture.launch("fixture", &changed);
    let third = fixture
        .plan(launch_args("fixture", &fixture.workspace))
        .unwrap()
        .resolved
        .digest;
    assert_ne!(first, third, "an environment value is semantics");
}

#[test]
fn c01_non_utf8_source_bytes_survive_into_the_snapshot_losslessly() {
    let fixture = Fixture::new();
    fixture.launch(
        "fixture",
        "name = \"fixture\"\njail = \"agent\"\n[credentials.a]\nsource = \"~/cred\"\n\
         dest = \"a\"\nmode = \"copy_rw\"\n",
    );
    // An operator home whose bytes are not UTF-8: resolution never touches
    // the file, so this works on a filesystem that would refuse the name.
    let mut home = fixture.root.clone().into_os_string().into_vec();
    home.extend_from_slice(b"/h\xffme");
    let home = PathBuf::from(std::ffi::OsString::from_vec(home.clone()));
    let ctx = fixture.context(Box::new(Sim::default()), Some(home.clone()));
    let plan = supervisor::resolve_plan(&ctx, &launch_args("fixture", &fixture.workspace))
        .expect("resolves");
    let canonical = plan.resolved.snapshot.to_canonical_value().unwrap();
    let source = &canonical["launch"]["credentials"][0]["source"];
    assert_eq!(source["encoding"], "base64", "{source}");
    let decoded = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(source["data"].as_str().unwrap())
            .unwrap()
    };
    let mut expected = home.into_os_string().into_vec();
    expected.extend_from_slice(b"/cred");
    assert_eq!(decoded, expected);
    assert_schema("policy-snapshot", &canonical);
}

#[test]
fn c01_every_ld_and_dyld_launch_key_refuses_through_the_file() {
    let fixture = Fixture::new();
    for name in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_BIND_NOW",
        "Ld_Debug",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
        "dyld_fallback_library_path",
    ] {
        for text in [
            format!("name = \"fixture\"\njail = \"tool\"\n[environment]\n{name} = \"/x.so\"\n"),
            format!("name = \"fixture\"\njail = \"tool\"\nstate_var = \"{name}\"\n"),
        ] {
            fixture.launch("fixture", &text);
            let error = refused(
                fixture.plan(launch_args("fixture", &fixture.workspace)),
                &format!("{name} must refuse"),
            );
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{name}");
            assert_eq!(error.exit_code(), 2);
        }
    }
}

#[test]
fn c01_unsafe_state_subdirs_refuse_through_the_file() {
    let fixture = Fixture::new();
    for subdirs in [
        r#"[""]"#,
        r#"["/etc"]"#,
        r#"["../escape"]"#,
        r#"["a/../../b"]"#,
        r#"["."]"#,
        r#"["a", "a"]"#,
        r#"["a//b"]"#,
    ] {
        fixture.launch(
            "fixture",
            &format!("name = \"fixture\"\njail = \"tool\"\nstate_subdirs = {subdirs}\n"),
        );
        let error = refused(
            fixture.plan(launch_args("fixture", &fixture.workspace)),
            subdirs,
        );
        assert_eq!(
            error.key_path.as_deref(),
            Some("launch.state_subdirs"),
            "{subdirs}"
        );
    }
}

#[test]
fn s6_1_tool_and_build_reject_credentials_and_none_rejects_any_launch() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let mut args = launch_args("fixture", &fixture.workspace);
    args.selection.profile = Some("tool".into());
    let error = refused(fixture.plan(args), "tool rejects credentials");
    assert_eq!(error.key_path.as_deref(), Some("launch.credentials"));

    fixture.launch(
        "tooled",
        &format!(
            "name = \"tooled\"\njail = \"tool\"\n[credentials.a]\nsource = \"{}\"\n\
             dest = \"a\"\nmode = \"copy_rw\"\n",
            auth.display()
        ),
    );
    let error = refused(
        fixture.plan(launch_args("tooled", &fixture.workspace)),
        "a tool-jail launch profile rejects credentials",
    );
    assert_eq!(error.key_path.as_deref(), Some("launch.credentials"));

    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_var = \"PLAIN_HOME\"\n",
    );
    let mut args = launch_args("plain", &fixture.workspace);
    args.selection.profile = Some("none".into());
    let error = refused(fixture.plan(args), "none never runs a launch profile");
    assert_eq!(error.code, ErrorCode::PolicyWidening);
    let plan = fixture
        .plan(launch_args("plain", &fixture.workspace))
        .expect("a credential-free tool launch profile resolves");
    assert_eq!(plan.resolved.snapshot.profile, ProfileName::Tool);
    assert!(
        !plan
            .resolved
            .requirements
            .contains(&ukai_jail::capability::Requirement::CredentialStaging)
    );

    let mut args = launch_args("plain", &fixture.workspace);
    args.selection.profile = Some("agent".into());
    assert_eq!(
        fixture.plan(args).unwrap().resolved.snapshot.profile,
        ProfileName::Agent,
        "an explicit profile that permits the launch profile overrides its default"
    );
}

#[test]
fn a_project_file_can_shrink_the_launch_hosts_but_not_add_credentials() {
    let fixture = Fixture::new();
    fixture.launch(
        "hosts",
        "name = \"hosts\"\njail = \"agent\"\n[network]\nallow = [\"a.example.test:443\", \"b.example.test:443\"]\n",
    );
    std::fs::write(
        fixture.workspace.join("ukai.toml"),
        "[jail.network]\nallow = [\"a.example.test:443\"]\n",
    )
    .unwrap();
    let plan = fixture
        .plan(launch_args("hosts", &fixture.workspace))
        .unwrap();
    assert_eq!(plan.resolved.snapshot.network.allow, ["a.example.test:443"]);

    std::fs::write(
        fixture.workspace.join("ukai.toml"),
        "[jail.credentials.x]\nsource = \"/etc/passwd\"\ndest = \"x\"\nmode = \"copy_rw\"\n",
    )
    .unwrap();
    assert!(
        fixture
            .plan(launch_args("hosts", &fixture.workspace))
            .is_err()
    );
}

#[test]
fn a_launch_file_must_be_private_single_linked_regular_and_outside_writable_grants() {
    let fixture = Fixture::new();
    let text = "name = \"fixture\"\njail = \"tool\"\nstate_var = \"F_HOME\"\n";
    let path = fixture.launch("fixture", text);
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_ok()
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_err(),
        "mode 0644 refuses"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let alias = fixture.outside.join("alias.toml");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_err(),
        "a second hard link refuses"
    );
    std::fs::remove_file(&alias).unwrap();

    std::fs::rename(&path, fixture.outside.join("real.toml")).unwrap();
    std::os::unix::fs::symlink(fixture.outside.join("real.toml"), &path).unwrap();
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_err(),
        "a symlinked launch file refuses"
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(fixture.outside.join("real.toml"), &path).unwrap();

    // The configuration directory inside the workspace: the child could
    // rewrite its own launch authority.
    let mut args = launch_args("fixture", &fixture.root);
    args.selection.workspace = Some(fixture.root.clone());
    let error = refused(fixture.plan(args), "inside the workspace refuses");
    assert_eq!(error.key_path.as_deref(), Some("--launch"));

    // ... and inside an explicit writable grant.
    let mut args = launch_args("fixture", &fixture.workspace);
    args.rw = vec![fixture.config.clone()];
    let error = refused(fixture.plan(args), "inside a --rw grant refuses");
    assert_eq!(error.key_path.as_deref(), Some("--launch"));

    // A launch name is a name, never a path.
    for name in ["../fixture", "Fixture", "fix/ture", ""] {
        assert!(
            fixture.plan(launch_args(name, &fixture.workspace)).is_err(),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// The attempt lifecycle over the simulated platform (C01, C02, P04)
// ---------------------------------------------------------------------------

fn plant_child_activity(vendor: &Path, outside: &Path) {
    // Links out of vendor state, to a file and to a directory, a hard link
    // to an outside file, a FIFO, a socket node, an unreadable subtree and a
    // deep one: everything a child could leave for cleanup to trip over.
    std::os::unix::fs::symlink(outside.join("precious"), vendor.join("file-link")).unwrap();
    std::os::unix::fs::symlink(outside, vendor.join("dir-link")).unwrap();
    std::os::unix::fs::symlink("/", vendor.join("sessions/root-link")).unwrap();
    std::fs::hard_link(outside.join("precious"), vendor.join("hard-link")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(vendor.join("fifo"))
            .status()
            .unwrap()
            .success()
    );
    socket_node(&vendor.join("sock"));
    let locked = vendor.join("sessions/deep/locked");
    std::fs::create_dir_all(locked.join("inner")).unwrap();
    std::fs::write(locked.join("inner/file"), b"x").unwrap();
    std::fs::set_permissions(locked.join("inner"), std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o100)).unwrap();
    let mut deep = vendor.join("cache");
    for _ in 0..200 {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).unwrap();
    // The copy is the child's to change; the source never is.
    std::fs::write(vendor.join("auth.json"), b"refreshed-by-the-child").unwrap();
}

/// Leaves a socket node at `path`, which may be longer than `sun_path`:
/// bound under a short directory, then renamed into place.
fn socket_node(path: &Path) {
    let short = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let bound = short.path().join("s");
    drop(std::os::unix::net::UnixListener::bind(&bound).unwrap());
    std::fs::rename(&bound, path).unwrap();
}

fn assert_outside_untouched(fixture: &Fixture) {
    assert_eq!(
        std::fs::read(fixture.outside.join("precious")).unwrap(),
        b"outside the attempt"
    );
    let names: Vec<String> = std::fs::read_dir(&fixture.outside)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        ["precious"],
        "nothing outside was created or removed"
    );
}

#[test]
fn c01_c02_a_normal_exit_stages_both_modes_records_provenance_and_cleans_vendor_state() {
    let fixture = Fixture::new();
    let auth_bytes = b"{\"token\":\"fixture-secret-copy\"}";
    let config_bytes = b"secret = \"fixture-secret-bind\"\n";
    let auth = fixture.credential("auth.json", auth_bytes);
    let config = fixture.credential("config.toml", config_bytes);
    let before = (
        std::fs::metadata(&auth).unwrap(),
        std::fs::metadata(&config).unwrap(),
    );
    agent_profile(&fixture, &auth, &config);

    let outside = fixture.outside.clone();
    let vendor_snapshot: Arc<Mutex<Vec<Listed>>> = Arc::default();
    let listing = Arc::clone(&vendor_snapshot);
    let sim = Sim {
        activity: Some(Arc::new(move |vendor: &Path| {
            // What staging left, before the "child" touches anything.
            let mut rows = Vec::new();
            for relative in ["auth.json", "conf/config.toml"] {
                let path = vendor.join(relative);
                let metadata = std::fs::symlink_metadata(&path).unwrap();
                rows.push((
                    relative.to_owned(),
                    std::fs::read(&path).unwrap(),
                    metadata.mode() & 0o7777,
                ));
            }
            for directory in ["sessions", "sessions/deep", "cache", "conf"] {
                let metadata = std::fs::symlink_metadata(vendor.join(directory)).unwrap();
                rows.push((directory.to_owned(), Vec::new(), metadata.mode() & 0o7777));
            }
            rows.push((
                ".".to_owned(),
                Vec::new(),
                std::fs::symlink_metadata(vendor).unwrap().mode() & 0o7777,
            ));
            *listing.lock().unwrap() = rows;
            plant_child_activity(vendor, &outside);
        })),
        ..Sim::default()
    };
    let seen = Arc::clone(&sim.seen);
    let report = fixture.run(sim, &["--launch", "fixture"]);
    assert_eq!(report.exit_code, 0, "{:?}", report.error);

    // Staging: the copy holds the source bytes at 0600, the bind point is an
    // empty 0600 file, the directories are 0700.
    let rows = vendor_snapshot.lock().unwrap().clone();
    let row = |name: &str| rows.iter().find(|row| row.0 == name).unwrap().clone();
    assert_eq!(row("auth.json").1, auth_bytes);
    assert_eq!(row("auth.json").2, 0o600);
    assert!(
        row("conf/config.toml").1.is_empty(),
        "the bind point is empty"
    );
    for directory in ["sessions", "sessions/deep", "cache", "conf", "."] {
        assert_eq!(row(directory).2, 0o700, "{directory}");
    }
    // The bind handle is the exact source object.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.binds.len(), 1);
    assert_eq!(seen.binds[0].0, "config");
    assert_eq!(seen.binds[0].1, "conf/config.toml");
    assert_eq!(seen.binds[0].2, (before.1.dev(), before.1.ino()));

    // Provenance without bytes, and a receipt the contract accepts.
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "complete");
    assert_eq!(receipt["cleanup_error"], serde_json::Value::Null);
    let credentials = receipt["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0]["id"], "auth");
    assert_eq!(credentials[0]["mode"], "copy_rw");
    // Audit 2026-09-25-2, S6: the receipt carries no verifier of the
    // secret's bytes; the digest stays in jail state.
    assert_eq!(credentials[0]["digest"], serde_json::Value::Null);
    assert_eq!(
        credentials[0]["digest_unavailable_reason"],
        "receipt_verifier_withheld"
    );
    assert_eq!(credentials[1]["id"], "config");
    assert_eq!(credentials[1]["mode"], "bind_ro");
    assert_eq!(
        credentials[1]["digest"],
        serde_json::Value::Null,
        "a live operator file has no stable content to digest"
    );
    assert_eq!(
        credentials[1]["digest_unavailable_reason"],
        "receipt_verifier_withheld"
    );
    let dir = attempt_dir(&report);
    for file in ["jail.json", "trace.ndjson", "jail-state.json"] {
        let text = std::fs::read(dir.join(file)).unwrap_or_default();
        let text = String::from_utf8_lossy(&text);
        for secret in ["fixture-secret-copy", "fixture-secret-bind"] {
            assert!(!text.contains(secret), "{file} carries credential bytes");
        }
        if file != "jail-state.json" {
            assert!(
                !text.contains(&*fixture.creds.to_string_lossy()),
                "{file} carries a credential source path"
            );
        }
    }

    // Sources preserved, byte for byte and in metadata.
    assert_eq!(std::fs::read(&auth).unwrap(), auth_bytes);
    assert_eq!(std::fs::read(&config).unwrap(), config_bytes);
    let after = (
        std::fs::metadata(&auth).unwrap(),
        std::fs::metadata(&config).unwrap(),
    );
    assert_eq!(after.0.mtime(), before.0.mtime());
    assert_eq!(after.1.mtime(), before.1.mtime());
    assert_eq!(after.0.mode(), before.0.mode());

    // Cleanup: vendor state is gone, nothing outside it moved, and jail state
    // agrees with the receipt.
    assert!(cleanup::absent(&dir.join("vendor-state")));
    assert_outside_untouched(&fixture);
    let state = jail_state(&report);
    assert_eq!(state["state_cleanup"], "complete");
    assert_eq!(
        state["vendor_state"]["credentials"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        !serde_json::to_string(&state["vendor_state"])
            .unwrap()
            .contains(&*fixture.creds.to_string_lossy()),
        "private state keeps identities, not paths"
    );
    // The settled receipt was persisted as pending before the removal.
    assert_eq!(
        receipt["revision"], 4,
        "prepared, enforced, settled as pending, then settled as complete"
    );
}

#[test]
fn p04_credential_special_files_and_oversize_refuse_before_the_platform_prepares() {
    let fixture = Fixture::new();
    let good = fixture.credential("good", b"staged before the failure");
    let special = fixture.creds.join("special");
    let cases: Vec<(&str, Maker)> = vec![
        (
            "a FIFO",
            Box::new(|path: &Path| {
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(path)
                        .status()
                        .unwrap()
                        .success()
                );
            }),
        ),
        (
            "a socket",
            Box::new(|path: &Path| {
                socket_node(path);
            }),
        ),
        (
            "a symlink",
            Box::new(|path: &Path| {
                std::os::unix::fs::symlink("/etc/hosts", path).unwrap();
            }),
        ),
        (
            "a directory",
            Box::new(|path: &Path| {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("inside"), b"x").unwrap();
            }),
        ),
        (
            "bytes",
            Box::new(|path: &Path| {
                let file = std::fs::File::create(path).unwrap();
                file.set_len(ukai_jail::credentials::COPY_BUDGET + 1)
                    .unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }),
        ),
        (
            "mode 0666",
            Box::new(|path: &Path| {
                std::fs::write(path, b"x").unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
            }),
        ),
    ];
    for (label, make) in cases {
        let _ = std::fs::remove_dir_all(&special);
        let _ = std::fs::remove_file(&special);
        make(&special);
        fixture.launch(
            "special",
            &format!(
                "name = \"special\"\njail = \"agent\"\n\
                 [credentials.a-good]\nsource = \"{}\"\ndest = \"good\"\nmode = \"copy_rw\"\n\
                 [credentials.b-special]\nsource = \"{}\"\ndest = \"special\"\nmode = \"copy_rw\"\n",
                good.display(),
                special.display()
            ),
        );
        let sim = Sim::default();
        let seen = Arc::clone(&sim.seen);
        let report = fixture.run(sim, &["--launch", "special"]);
        assert_eq!(report.exit_code, 125, "{label}: {:?}", report.error);
        let error = report.error.as_ref().unwrap();
        assert_eq!(error.code, ErrorCode::CredentialUnavailable, "{label}");
        assert!(
            !seen.lock().unwrap().prepared,
            "{label}: refused before prepare"
        );
        let receipt = receipt_json(&report);
        assert_schema("jail-receipt", &receipt);
        assert_eq!(receipt["phase"], "refused", "{label}");
        assert_eq!(receipt["exec_observed"], false);
        assert_eq!(
            receipt["credentials"].as_array().unwrap().len(),
            1,
            "{label}: the input staged before the failure is reported"
        );
        assert_eq!(receipt["credentials"][0]["id"], "a-good");
        assert_eq!(receipt["state_cleanup"], "complete", "{label}");
        // J3 review RM30: the refused receipt was persisted as `pending`
        // before the removal, so a crash during it leaves a receipt `gc` can
        // finish; the final one is the second revision.
        assert_eq!(receipt["revision"], 2, "{label}");
        assert!(cleanup::absent(&attempt_dir(&report).join("vendor-state")));
        assert!(
            !receipt
                .to_string()
                .contains(&*fixture.creds.to_string_lossy()),
            "{label}: the refusal names the id, not the path"
        );
    }
    // A device node: `/dev/null` is a character device on both platforms.
    fixture.launch(
        "device",
        "name = \"device\"\njail = \"agent\"\n[credentials.dev]\nsource = \"/dev/null\"\n\
         dest = \"dev\"\nmode = \"bind_ro\"\n",
    );
    let sim = Sim::default();
    let seen = Arc::clone(&sim.seen);
    let report = fixture.run(sim, &["--launch", "device"]);
    assert_eq!(report.exit_code, 125);
    assert!(
        report
            .error
            .as_ref()
            .unwrap()
            .message
            .contains("character device"),
        "{:?}",
        report.error
    );
    assert!(!seen.lock().unwrap().prepared);
}

#[test]
fn c02_an_unverified_tree_retains_vendor_state_and_gc_will_not_remove_it() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let report = fixture.run(
        Sim {
            tree: TreeEnd::Unknown,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    assert_eq!(report.error.as_ref().unwrap().code, ErrorCode::TreeUnknown);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_ne!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], cleanup::REASON_TREE_UNVERIFIED);
    let vendor = attempt_dir(&report).join("vendor-state");
    assert!(
        vendor.join("auth.json").exists(),
        "retained for a possibly live tree"
    );
    let gc = fixture.gc(false).expect("gc scans");
    assert_eq!(gc.entries.len(), 1);
    assert_eq!(gc.entries[0].action, "retained");
    assert!(
        gc.entries[0]
            .reason
            .contains(cleanup::REASON_TREE_UNVERIFIED)
    );
    assert!(vendor.join("auth.json").exists());
}

#[test]
fn c02_a_release_failure_after_setup_retains_and_an_exec_error_with_verified_teardown_cleans() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);

    let report = fixture.run(
        Sim {
            release_fails: true,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(
        receipt["state_cleanup"], "pending",
        "no teardown was verified"
    );
    assert!(attempt_dir(&report).join("vendor-state").exists());

    // The same failure, from a platform that reports a verified teardown.
    let report = fixture.run(
        Sim {
            release_fails: true,
            release_teardown_verified: true,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
    assert_eq!(receipt["state_cleanup"], "complete");
    assert!(cleanup::absent(&attempt_dir(&report).join("vendor-state")));

    let report = fixture.run(
        Sim {
            target: TargetEnd::ExecError,
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["outcome"]["kind"], "exec_error");
    assert_eq!(receipt["lifetime"]["tree_empty"], true);
    assert_eq!(receipt["state_cleanup"], "complete");
    assert!(cleanup::absent(&attempt_dir(&report).join("vendor-state")));
}

/// A refusal whose own message would take its receipt past the reader bound
/// still cleans up vendor state after a verified teardown: the pending
/// refused receipt written before the removal is fitted (its messages cut,
/// saying so) like the final one, so neither write refuses and the staged
/// credentials do not outlive the attempt.
#[test]
fn an_oversized_refusal_still_cleans_up_vendor_state() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let report = fixture.run(
        Sim {
            release_fails: true,
            release_teardown_verified: true,
            release_error_padding: usize::try_from(cleanup::RECEIPT_MAX).unwrap(),
            ..Sim::default()
        },
        &["--launch", "fixture"],
    );
    assert_eq!(report.exit_code, 125, "{:?}", report.error);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(
        receipt["state_cleanup"], "complete",
        "{}",
        receipt["cleanup_error"]
    );
    assert_eq!(receipt["cleanup_error"], serde_json::Value::Null);
    assert!(cleanup::absent(&attempt_dir(&report).join("vendor-state")));
    let bytes = std::fs::read(report.receipt_path.as_ref().unwrap()).unwrap();
    assert!(u64::try_from(bytes.len()).unwrap() <= cleanup::RECEIPT_MAX);
    assert!(
        receipt["outcome"]["error"]["message"]
            .as_str()
            .unwrap()
            .ends_with("the run that wrote this receipt prints the whole message on stderr]")
    );
}

/// Leaves one entry vendor-state cleanup cannot remove on its first pass.
///
/// macOS: the user-immutable flag, which the owner may set and clear.
/// Linux: more entries than one pass visits, since an unprivileged owner has
/// no immutable flag there.
fn obstruct_first_pass(vendor: &Path) -> Undo {
    if cfg!(target_os = "macos") {
        let pinned = vendor.join("pinned");
        std::fs::write(&pinned, b"x").unwrap();
        assert!(
            std::process::Command::new("chflags")
                .arg("uchg")
                .arg(&pinned)
                .status()
                .unwrap()
                .success()
        );
        Box::new(move || {
            assert!(
                std::process::Command::new("chflags")
                    .arg("nouchg")
                    .arg(&pinned)
                    .status()
                    .unwrap()
                    .success()
            );
        })
    } else {
        let many = vendor.join("many");
        std::fs::create_dir(&many).unwrap();
        for index in 0..=cleanup::DEFAULT_MAX_ENTRIES {
            std::fs::File::create(many.join(index.to_string())).unwrap();
        }
        Box::new(|| {})
    }
}

#[test]
fn c02_an_interrupted_cleanup_stays_pending_and_gc_resumes_it() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let release: Arc<Mutex<Option<Undo>>> = Arc::default();
    let slot = Arc::clone(&release);
    let sim = Sim {
        activity: Some(Arc::new(move |vendor: &Path| {
            *slot.lock().unwrap() = Some(obstruct_first_pass(vendor));
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "fixture"]);
    assert_eq!(
        report.exit_code, 0,
        "cleanup failure never rewrites the exit"
    );
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "pending");
    assert!(receipt["cleanup_error"].is_string());
    assert_eq!(jail_state(&report)["state_cleanup"], "pending");
    let vendor = attempt_dir(&report).join("vendor-state");
    assert!(vendor.exists());

    // The run's journal ends complete on the pending receipt's note.
    let trace = attempt_dir(&report).join("trace.ndjson");
    let journal = std::fs::read(&trace).unwrap();
    let events = |bytes: &[u8]| -> Vec<serde_json::Value> {
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    };
    common::check_trace(&events(&journal), Some(&receipt)).expect("the run's journal");

    let dry = fixture.gc(true).expect("a dry run scans");
    assert_eq!(dry.entries[0].action, "would_remove_vendor_state");
    assert_eq!(dry.entries[0].journal.as_deref(), Some("would_append"));
    assert!(vendor.exists(), "a dry run removes nothing");
    assert_eq!(std::fs::read(&trace).unwrap(), journal, "nor appends");

    if let Some(undo) = release.lock().unwrap().take() {
        undo();
    }
    let resumed = fixture.gc(false).expect("the resumed cleanup completes");
    assert_eq!(resumed.entries[0].action, "removed_vendor_state");
    assert!(cleanup::absent(&vendor));
    let after: Receipt =
        serde_json::from_slice(&std::fs::read(attempt_dir(&report).join("jail.json")).unwrap())
            .unwrap();
    assert_eq!(after.state_cleanup, StateCleanup::Complete);
    assert_eq!(after.revision, receipt["revision"].as_u64().unwrap() + 1);
    assert_schema("jail-receipt", &serde_json::to_value(&after).unwrap());
    assert_eq!(jail_state(&report)["state_cleanup"], "complete");
    // jail-v1 §13.3: gc appended the completed receipt's note to the run's
    // journal, which is complete again with that receipt as its last.
    let appended = std::fs::read(&trace).unwrap();
    assert!(appended.starts_with(&journal));
    let after_events = events(&appended);
    assert_eq!(
        resumed.entries[0].journal.as_deref(),
        Some(
            format!(
                "appended (wrapper source_seq {})",
                after_events.last().unwrap()["source_seq"]
            )
            .as_str()
        )
    );
    let after_value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(attempt_dir(&report).join("jail.json")).unwrap())
            .unwrap();
    common::check_trace(&after_events, Some(&after_value)).expect("the journal after gc");
    assert_eq!(
        ukai_jail::summary::summarize_attempt(&attempt_dir(&report))
            .unwrap()
            .journal,
        ukai_jail::summary::JournalState::Complete
    );
    let again = fixture.gc(false).unwrap();
    assert_eq!(again.entries[0].action, "retained", "nothing left to do");
    assert_eq!(again.entries[0].journal, None);
    assert_eq!(std::fs::read(&trace).unwrap(), appended);
    assert_outside_untouched(&fixture);
}

#[test]
fn c02_a_crash_after_the_removal_but_before_the_record_is_finished_by_gc() {
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a/b\"]\n",
    );
    let report = fixture.run(Sim::default(), &["--launch", "plain"]);
    assert_eq!(report.exit_code, 0, "{:?}", report.error);
    let dir = attempt_dir(&report);
    // Rewind both records to the moment between the removal and its record,
    // as a crash there would leave them.
    let mut receipt: Receipt =
        serde_json::from_slice(&std::fs::read(dir.join("jail.json")).unwrap()).unwrap();
    receipt.state_cleanup = StateCleanup::Pending;
    std::fs::write(dir.join("jail.json"), serde_json::to_vec(&receipt).unwrap()).unwrap();
    let mut state = jail_state(&report);
    state["state_cleanup"] = "pending".into();
    std::fs::write(
        dir.join("jail-state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();

    let resumed = fixture.gc(false).unwrap();
    assert_eq!(resumed.entries[0].action, "removed_vendor_state");
    let after: Receipt =
        serde_json::from_slice(&std::fs::read(dir.join("jail.json")).unwrap()).unwrap();
    assert_eq!(after.state_cleanup, StateCleanup::Complete);
    assert_eq!(jail_state(&report)["state_cleanup"], "complete");
}

#[test]
fn c02_a_replaced_vendor_state_directory_is_never_deleted() {
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a\"]\n",
    );
    let outside = fixture.outside.clone();
    let sim = Sim {
        activity: Some(Arc::new(move |vendor: &Path| {
            // Something with the operator's own rights swaps the registered
            // directory for a link to an outside one.
            let parked = vendor.with_file_name("parked");
            std::fs::rename(vendor, &parked).unwrap();
            std::os::unix::fs::symlink(&outside, vendor).unwrap();
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "plain"]);
    assert_eq!(report.exit_code, 0);
    let receipt = receipt_json(&report);
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], "managed_directory_replaced");
    assert_outside_untouched(&fixture);

    // J3 review RM33: a real replaced directory, not a symlink. The
    // registered one is renamed away and a new directory takes its name;
    // only the recorded identity tells them apart, and neither is removed.
    let sim = Sim {
        activity: Some(Arc::new(|vendor: &Path| {
            let parked = vendor.with_file_name("parked");
            std::fs::rename(vendor, &parked).unwrap();
            std::fs::create_dir(vendor).unwrap();
            std::fs::write(vendor.join("precious"), b"not the registered directory").unwrap();
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "plain"]);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], "managed_directory_replaced");
    let attempt = attempt_dir(&report);
    assert!(attempt.join("vendor-state/precious").exists());
    assert!(attempt.join("parked/a").is_dir());
}

/// A launch profile that stages credentials is refused, when the platform
/// refuses before any boundary, exactly as a plain `--profile agent` run is,
/// and stages nothing first.
///
/// The real platform for this OS refuses here: macOS because execution is
/// not implemented there, Linux because its capability probes run the
/// current executable, which in this test is the test binary rather than
/// `ukai-jail`, so `tree_termination` is reported missing at probing. Both
/// refusals come before staging.
#[test]
fn an_agent_launch_profile_is_refused_before_staging_as_plain_agent_is() {
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let plain = {
        let mut argv: Vec<String> = vec!["ukai-jail".into(), "run".into()];
        argv.extend([
            "--workspace".into(),
            fixture.workspace.display().to_string(),
        ]);
        argv.extend([
            "--profile".into(),
            "agent".into(),
            "--".into(),
            "true".into(),
        ]);
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        supervisor::run(
            &fixture.context(ukai_jail::platform::current(), None),
            &args,
        )
    };
    let launched = {
        let mut argv: Vec<String> = vec!["ukai-jail".into(), "run".into()];
        argv.extend([
            "--workspace".into(),
            fixture.workspace.display().to_string(),
        ]);
        argv.extend([
            "--launch".into(),
            "fixture".into(),
            "--".into(),
            "true".into(),
        ]);
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        supervisor::run(
            &fixture.context(
                ukai_jail::platform::current(),
                Some(fixture.root.join("home")),
            ),
            &args,
        )
    };
    let code = if cfg!(target_os = "linux") {
        ErrorCode::MissingCapability
    } else {
        ErrorCode::UnsupportedPlatform
    };
    let stage = ukai_jail::records::ErrorStage::Probing;
    for (label, report) in [("plain", &plain), ("launched", &launched)] {
        assert_eq!(report.exit_code, 125, "{label}");
        let error = report.error.as_ref().expect("a refusal");
        assert_eq!(
            (error.code, error.stage),
            (code, stage),
            "{label}: {error:?}"
        );
    }
    let receipt = receipt_json(&launched);
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(receipt["state_cleanup"], "not_needed");
    assert_eq!(receipt["credentials"], serde_json::json!([]));
    assert!(cleanup::absent(
        &attempt_dir(&launched).join("vendor-state")
    ));
}

// ---------------------------------------------------------------------------
// Staging, directly (the API the platforms call)
// ---------------------------------------------------------------------------

fn stage_one_source(fixture: &Fixture, source: &Path) -> Result<(), (JailError, usize)> {
    let vendor_path = fixture.root.join("vendor");
    let _ = std::fs::remove_dir_all(&vendor_path);
    private_dir(&vendor_path);
    let vendor = ukai_jail::state::anchored::Dir::open_trusted(&vendor_path).unwrap();
    let launch = ukai_jail::policy::LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        credentials: vec![ukai_jail::policy::CredentialDecl {
            vault: None,
            id: "only".into(),
            source: ukai_jail::records::NativeString::from_bytes(
                source.as_os_str().as_bytes().to_vec(),
            )
            .unwrap(),
            dest: ukai_jail::records::NativeString::Text("only".into()),
            mode: ukai_jail::policy::CredentialMode::CopyRw,
        }],
        state_discard: None,
    };
    ukai_jail::credentials::stage(&launch, vendor.as_fd(), &[])
        .map(|_| ())
        .map_err(|refusal| (refusal.error, refusal.staged.len()))
}

#[test]
fn p04_a_source_reached_through_a_symlinked_directory_refuses() {
    let fixture = Fixture::new();
    let real = fixture.creds.join("real");
    private_dir(&real);
    fixture_file(&real.join("token"), b"t");
    std::os::unix::fs::symlink(&real, fixture.creds.join("alias")).unwrap();
    assert!(stage_one_source(&fixture, &real.join("token")).is_ok());
    let (error, _) = stage_one_source(&fixture, &fixture.creds.join("alias/token"))
        .expect_err("a symlinked component is never followed");
    assert_eq!(error.code, ErrorCode::CredentialUnavailable);
    assert!(error.message.contains("a symlink"), "{}", error.message);
}

#[test]
fn p04_a_source_below_a_directory_others_can_write_refuses() {
    let fixture = Fixture::new();
    let shared = fixture.creds.join("shared");
    private_dir(&shared);
    fixture_file(&shared.join("token"), b"t");
    assert!(stage_one_source(&fixture, &shared.join("token")).is_ok());
    // World-writable: "others" on every host. (A group-writable parent is
    // others only when the group is not the owner's private group, which
    // depends on the host's accounts; state.rs tests that rule.)
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (error, _) = stage_one_source(&fixture, &shared.join("token"))
        .expect_err("a parent anyone can write lets someone else swap the source");
    assert!(
        error.message.contains("writable by others"),
        "{}",
        error.message
    );
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1770)).unwrap();
    assert!(
        stage_one_source(&fixture, &shared.join("token")).is_ok(),
        "a sticky shared directory protects entries its owner made"
    );
}

/// A source whose bytes do not match the size `fstat` reported is changing
/// under the copy; `/proc/<pid>/status` is such a file, owned by this user.
#[cfg(target_os = "linux")]
#[test]
fn c01_a_source_that_changes_under_the_copy_refuses_rather_than_tearing() {
    let fixture = Fixture::new();
    let status = PathBuf::from(format!("/proc/{}/status", std::process::id()));
    let (error, _) = stage_one_source(&fixture, &status)
        .expect_err("a source whose content disagrees with its size refuses");
    assert_eq!(error.code, ErrorCode::CredentialUnavailable);
    assert_eq!(error.remediation, Remediation::Retry);
    assert!(error.message.contains("changed while"), "{}", error.message);
}

// ---------------------------------------------------------------------------
// Inspection output: `explain` and `doctor --launch` (§12, §14.1)
// ---------------------------------------------------------------------------

/// A launch profile with one good, one missing and one special source, all
/// beneath the fixture's own directories, whose paths must never be printed.
fn inspection_fixture() -> Fixture {
    let fixture = Fixture::new();
    let good = fixture.credential("good.json", b"fixture-secret-inspect");
    let fifo = fixture.creds.join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    fixture.launch(
        "inspect",
        &format!(
            "name = \"inspect\"\njail = \"agent\"\nstate_var = \"I_HOME\"\n\
             [credentials.good]\nsource = \"{}\"\ndest = \"good.json\"\nmode = \"copy_rw\"\n\
             [credentials.missing]\nsource = \"{}\"\ndest = \"missing.json\"\nmode = \"copy_rw\"\n\
             [credentials.pipe]\nsource = \"{}\"\ndest = \"conf/pipe\"\nmode = \"bind_ro\"\n",
            good.display(),
            fixture.creds.join("absent.json").display(),
            fifo.display()
        ),
    );
    fixture
}

fn jail_binary(fixture: &Fixture, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
        .args(args)
        .current_dir(&fixture.workspace)
        .env("UKAI_CONFIG_DIR", &fixture.config)
        .env("UKAI_DATA_DIR", &fixture.data)
        .env("HOME", fixture.root.join("home"))
        .output()
        .unwrap()
}

fn assert_no_private_path(fixture: &Fixture, label: &str, text: &str) {
    for private in [
        fixture.creds.to_string_lossy().into_owned(),
        fixture.root.join("home").to_string_lossy().into_owned(),
        "fixture-secret-inspect".to_owned(),
    ] {
        assert!(
            !text.contains(&private),
            "{label} prints {private}:\n{text}"
        );
    }
}

#[test]
fn explain_prints_credentials_by_id_mode_and_dest_never_by_source() {
    let fixture = inspection_fixture();
    let json = jail_binary(&fixture, &["explain", "--launch", "inspect", "--json"]);
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let stdout = String::from_utf8_lossy(&json.stdout).into_owned();
    assert_no_private_path(&fixture, "explain --json", &stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["policy"]["credential_sources"], "omitted");
    let credentials = value["policy"]["snapshot"]["launch"]["credentials"]
        .as_array()
        .unwrap();
    assert_eq!(credentials.len(), 3);
    for credential in credentials {
        let keys: Vec<&str> = credential
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["dest", "id", "mode"], "{credential}");
    }
    // J4-D7: the snapshot's arrays are in canonical-byte order, and a
    // credential's canonical bytes begin with its `dest` (canonicalization.md),
    // so `conf/pipe` (id `pipe`) comes first, not last as it would by id.
    let dests: Vec<&str> = credentials
        .iter()
        .map(|credential| credential["dest"].as_str().unwrap())
        .collect();
    assert_eq!(dests, ["conf/pipe", "good.json", "missing.json"]);

    let text = jail_binary(&fixture, &["explain", "--launch", "inspect"]);
    assert!(text.status.success());
    let stdout = String::from_utf8_lossy(&text.stdout).into_owned();
    assert_no_private_path(&fixture, "explain", &stdout);
    assert!(
        stdout.contains("launch credential good mode=copy_rw dest=good.json source=omitted"),
        "{stdout}"
    );
}

#[test]
fn doctor_launch_checks_each_credential_without_printing_paths_or_values() {
    let fixture = inspection_fixture();
    let json = jail_binary(&fixture, &["doctor", "--launch", "inspect", "--json"]);
    // Not ready: two sources refuse (and macOS refuses execution too).
    assert_eq!(
        json.status.code(),
        Some(125),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let stdout = String::from_utf8_lossy(&json.stdout).into_owned();
    assert_no_private_path(&fixture, "doctor --json", &stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["ready"], false);
    let launch = &value["launch"];
    assert_eq!(launch["name"], "inspect");
    assert_eq!(launch["support"], "experimental");
    assert_eq!(launch["support_reason"], "no_recorded_run");
    let rows: Vec<(String, String, String)> = launch["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["id"].as_str().unwrap().to_owned(),
                row["status"].as_str().unwrap().to_owned(),
                row["reason_code"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("good".into(), "available".into(), "ok".into()),
            (
                "missing".into(),
                "unavailable".into(),
                "source_missing".into()
            ),
            (
                "pipe".into(),
                "unavailable".into(),
                "source_not_regular_file".into()
            ),
        ]
    );

    let text = jail_binary(&fixture, &["doctor", "--launch", "inspect"]);
    let stdout = String::from_utf8_lossy(&text.stdout).into_owned();
    assert_no_private_path(&fixture, "doctor", &stdout);
    assert!(
        stdout.contains("launch inspect experimental reason=no_recorded_run"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "credential missing mode=copy_rw dest=missing.json unavailable reason=source_missing"
        ),
        "{stdout}"
    );
}

#[test]
fn doctor_readiness_needs_every_credential_and_reports_support_apart_from_it() {
    // The scripted platform satisfies every requirement, so readiness here is
    // decided by the credentials alone.
    let fixture = Fixture::new();
    let auth = fixture.credential("auth.json", b"a");
    let config = fixture.credential("config.toml", b"b");
    agent_profile(&fixture, &auth, &config);
    let ctx = fixture.context(Box::new(Sim::default()), Some(fixture.root.join("home")));
    let args = cli::DoctorArgs {
        selection: Selection {
            launch: Some("fixture".into()),
            ..Selection::default()
        },
        json: true,
    };
    let report = supervisor::doctor(&ctx, &args).unwrap();
    assert!(report.ready);
    let launch = report.launch.as_ref().unwrap();
    assert_eq!(
        launch.support, "experimental",
        "support is reported whatever readiness says"
    );
    assert!(launch.credentials.iter().all(|check| check.available));

    std::fs::remove_file(&config).unwrap();
    let report = supervisor::doctor(&ctx, &args).unwrap();
    assert!(
        !report.ready,
        "a missing source makes the launch unavailable"
    );
    assert_eq!(report.launch.as_ref().unwrap().support, "experimental");

    // Oversize copies are caught before exec by the same budget.
    let big = std::fs::File::create(&config).unwrap();
    big.set_len(ukai_jail::credentials::COPY_BUDGET).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    fixture.launch(
        "fixture",
        &format!(
            "name = \"fixture\"\njail = \"agent\"\n\
             [credentials.a]\nsource = \"{}\"\ndest = \"a\"\nmode = \"copy_rw\"\n\
             [credentials.b]\nsource = \"{}\"\ndest = \"b\"\nmode = \"copy_rw\"\n",
            auth.display(),
            config.display()
        ),
    );
    let report = supervisor::doctor(&ctx, &args).unwrap();
    let checks = &report.launch.as_ref().unwrap().credentials;
    assert_eq!(checks[0].reason_code, "ok");
    assert_eq!(checks[1].reason_code, "copy_budget_exceeded");
    assert!(!report.ready);
}

// ---------------------------------------------------------------------------
// J3 review findings, adopted as tests
// ---------------------------------------------------------------------------

#[test]
fn h2_a_preexisting_vendor_state_in_a_managed_attempt_root_refuses_and_survives() {
    // Reviewer's R2: a managed caller's attempt root already holding
    // `vendor-state/` was accepted, the create failed, and the refusal then
    // deleted the directory the attempt never made.
    let fixture = Fixture::new();
    fixture.launch(
        "fixture",
        "name = \"fixture\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
    );
    for artifact in ukai_jail::state::JAIL_OWNED_NAMES {
        let id = format!("att_{}", uuid::Uuid::new_v4());
        private_dir(&fixture.data.join("attempts"));
        let attempt = fixture.data.join("attempts").join(&id);
        private_dir(&attempt);
        let planted = attempt.join(artifact);
        if artifact.contains('.') {
            std::fs::write(&planted, b"not this attempt's").unwrap();
        } else {
            private_dir(&planted);
            std::fs::write(planted.join("precious"), b"not this attempt's").unwrap();
        }
        let (read, write) = std::io::pipe().unwrap();
        let read: std::os::fd::OwnedFd = read.into();
        let gate = std::os::fd::AsRawFd::as_raw_fd(&read).to_string();
        let report = fixture.run(
            Sim::default(),
            &[
                "--launch",
                "fixture",
                "--attempt-id",
                &id,
                "--gate-fd",
                &gate,
            ],
        );
        drop(write);
        let error = report.error.as_ref().expect("a refusal");
        assert_eq!(
            error.code,
            ErrorCode::AttemptExists,
            "{artifact}: {error:?}"
        );
        assert!(
            error.message.contains(artifact),
            "{artifact}: {}",
            error.message
        );
        if artifact.contains('.') {
            assert_eq!(std::fs::read(&planted).unwrap(), b"not this attempt's");
        } else {
            assert!(planted.join("precious").exists(), "{artifact} was touched");
        }
    }
}

#[test]
fn h2_a_vendor_state_appearing_after_the_claim_is_withdrawn_not_deleted() {
    let fixture = Fixture::new();
    fixture.launch(
        "fixture",
        "name = \"fixture\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
    );
    let sim = Sim {
        plant_vendor_state: Some(fixture.data.clone()),
        ..Sim::default()
    };
    let seen = Arc::clone(&sim.seen);
    let report = fixture.run(sim, &["--launch", "fixture"]);
    assert_eq!(report.exit_code, 125, "{:?}", report.error);
    assert!(!seen.lock().unwrap().prepared);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["phase"], "refused");
    assert_eq!(
        receipt["state_cleanup"], "not_needed",
        "not this attempt's to clean"
    );
    let attempt = attempt_dir(&report);
    assert_eq!(
        std::fs::read(attempt.join("vendor-state/precious")).unwrap(),
        b"not this attempt's"
    );
    let state = jail_state(&report);
    assert_eq!(state["vendor_state"], serde_json::Value::Null);
    // And gc will not touch it either.
    let gc = fixture.gc(false).unwrap();
    assert!(gc.incomplete.is_empty());
    assert!(attempt.join("vendor-state/precious").exists());
}

#[test]
fn m2_a_credential_source_inside_a_child_writable_grant_refuses() {
    // Reviewer's R5: sources inside the workspace were staged, so the child
    // could change the operator's credential through the workspace.
    let fixture = Fixture::new();
    let inside = fixture.workspace.join("config.toml");
    std::fs::write(&inside, b"fixture-config").unwrap();
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o600)).unwrap();
    for mode in ["bind_ro", "copy_rw"] {
        fixture.launch(
            "fixture",
            &format!(
                "name = \"fixture\"\njail = \"agent\"\n[credentials.c]\nsource = \"{}\"\n\
                 dest = \"c\"\nmode = \"{mode}\"\n",
                inside.display()
            ),
        );
        let sim = Sim::default();
        let seen = Arc::clone(&sim.seen);
        let report = fixture.run(sim, &["--launch", "fixture"]);
        let error = report.error.as_ref().expect("a refusal");
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{mode}");
        assert_eq!(
            error.key_path.as_deref(),
            Some("launch.credentials.c.source")
        );
        assert!(
            report.receipt.is_none(),
            "refused before any attempt existed"
        );
        assert!(!seen.lock().unwrap().prepared);
    }
    // A writable host grant counts as much as the workspace does.
    let source = fixture.credential("token", b"t");
    fixture.launch(
        "fixture",
        &format!(
            "name = \"fixture\"\njail = \"agent\"\n[credentials.t]\nsource = \"{}\"\n\
             dest = \"t\"\nmode = \"copy_rw\"\n",
            source.display()
        ),
    );
    let creds = fixture.creds.display().to_string();
    let report = fixture.run(Sim::default(), &["--launch", "fixture", "--rw", &creds]);
    assert_eq!(
        report
            .error
            .as_ref()
            .and_then(|error| error.key_path.as_deref()),
        Some("launch.credentials.t.source")
    );
    // Staging repeats the comparison on its own walk, by identity.
    use std::os::unix::fs::MetadataExt as _;
    let grant = std::fs::metadata(&fixture.creds).unwrap();
    let (error, staged) = stage_one_source_with(&fixture, &source, &[(grant.dev(), grant.ino())])
        .expect_err("a grant on the walk refuses");
    assert!(
        error.message.contains("grant the child can write"),
        "{}",
        error.message
    );
    assert_eq!(staged, 0);
}

#[test]
fn m2_a_credential_source_with_another_link_refuses_in_either_mode() {
    // Security audit 2026-09-25 (F5): `copy_rw` refuses a second link too. A
    // second name is another writer into what is copied; the staging's
    // stable-copy check keeps an invariant, not a race to win.
    let fixture = Fixture::new();
    let source = fixture.credential("token", b"fixture-token");
    std::fs::hard_link(&source, fixture.outside.join("alias")).unwrap();
    for mode in ["bind_ro", "copy_rw"] {
        fixture.launch(
            "fixture",
            &format!(
                "name = \"fixture\"\njail = \"agent\"\n[credentials.t]\nsource = \"{}\"\n\
                 dest = \"t\"\nmode = \"{mode}\"\n",
                source.display()
            ),
        );
        let report = fixture.run(Sim::default(), &["--launch", "fixture"]);
        let error = report.error.as_ref().expect("a refusal");
        assert_eq!(error.code, ErrorCode::CredentialUnavailable);
        assert!(
            error.message.contains("exactly one link"),
            "{}",
            error.message
        );
    }
}

#[test]
fn m3_a_configured_profile_is_kept_or_the_conflict_refuses_never_replaced() {
    // Reviewer's R7: `--launch` silently replaced the operator's configured
    // profile and dropped its required ceilings.
    let fixture = Fixture::new();
    std::fs::write(
        fixture.config.join("strict.toml"),
        "schema = \"ukai.jail.policy/1\"\nextends = \"tool\"\n[limits]\npids = 16\nwall = \"1m\"\n",
    )
    .unwrap();
    std::fs::set_permissions(
        fixture.config.join("strict.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let configure = |profile: &str| {
        std::fs::write(
            fixture.config.join("config.toml"),
            format!("[jail]\nschema = \"ukai.jail.policy/1\"\nprofile = \"{profile}\"\n"),
        )
        .unwrap();
        std::fs::set_permissions(
            fixture.config.join("config.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    };
    configure("strict.toml");
    fixture.launch(
        "tooled",
        "name = \"tooled\"\njail = \"tool\"\nstate_var = \"FIX_HOME\"\n",
    );
    fixture.launch(
        "agented",
        "name = \"agented\"\njail = \"agent\"\nstate_var = \"FIX_HOME\"\n",
    );
    let limits =
        |plan: &supervisor::Plan| serde_json::to_value(&plan.resolved.snapshot.limits).unwrap();
    let without = fixture
        .plan(PolicyArgs {
            selection: Selection {
                workspace: Some(fixture.workspace.clone()),
                ..Selection::default()
            },
            ..PolicyArgs::default()
        })
        .unwrap_or_else(|error| panic!("{error:?}"));
    let with = fixture
        .plan(launch_args("tooled", &fixture.workspace))
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(
        limits(&with),
        limits(&without),
        "the configured profile's ceilings stay"
    );
    assert_eq!(
        with.resolved.snapshot.limits.pids.as_ref().unwrap().value,
        "16"
    );

    // Different bases: refuse, naming both and pointing at --profile.
    let error = refused(
        fixture.plan(launch_args("agented", &fixture.workspace)),
        "conflict",
    );
    assert_eq!(error.code, ErrorCode::InvalidConfig);
    assert_eq!(error.key_path.as_deref(), Some("jail.profile"));
    assert!(error.message.contains("strict.toml") && error.message.contains("`agent`"));
    assert!(error.message.contains("--profile"));
    configure("tool");
    let error = refused(
        fixture.plan(launch_args("agented", &fixture.workspace)),
        "conflict",
    );
    assert_eq!(error.key_path.as_deref(), Some("jail.profile"));

    // `--profile` decides; with no configured profile the launch default does.
    let mut args = launch_args("agented", &fixture.workspace);
    args.selection.profile = Some("agent".into());
    assert_eq!(
        fixture.plan(args).unwrap().resolved.snapshot.profile,
        ProfileName::Agent
    );
    std::fs::remove_file(fixture.config.join("config.toml")).unwrap();
    assert_eq!(
        fixture
            .plan(launch_args("agented", &fixture.workspace))
            .unwrap()
            .resolved
            .snapshot
            .profile,
        ProfileName::Agent
    );
}

#[test]
fn l3_credentials_staged_before_a_refusal_reach_private_provenance_too() {
    // Reviewer's R8.
    let fixture = Fixture::new();
    let a = fixture.credential("a", b"fixture-a");
    fixture.launch(
        "fixture",
        &format!(
            "name = \"fixture\"\njail = \"agent\"\n\
             [credentials.a]\nsource = \"{}\"\ndest = \"a\"\nmode = \"copy_rw\"\n\
             [credentials.b]\nsource = \"{}\"\ndest = \"b\"\nmode = \"copy_rw\"\n",
            a.display(),
            fixture.creds.join("missing").display()
        ),
    );
    let report = fixture.run(Sim::default(), &["--launch", "fixture"]);
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    let state = jail_state(&report);
    let private = state["vendor_state"]["credentials"].as_array().cloned();
    // Cleanup withdrew nothing: the registration keeps its history.
    let private = private.unwrap_or_default();
    assert_eq!(receipt["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(private.len(), 1, "{state:#}");
    assert_eq!(private[0]["id"], "a");
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        private[0]["source_ino"],
        std::fs::metadata(&a).unwrap().ino().to_string()
    );
}

#[test]
fn rm16_the_copy_budget_is_cumulative_across_credentials() {
    // Reviewer's R10: two 10 MiB copies must refuse on the second.
    let fixture = Fixture::new();
    let decl = |id: &str| {
        let path = fixture.creds.join(id);
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(10 * 1024 * 1024).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        ukai_jail::policy::CredentialDecl {
            vault: None,
            id: id.into(),
            source: ukai_jail::records::NativeString::from_bytes(
                path.as_os_str().as_bytes().to_vec(),
            )
            .unwrap(),
            dest: ukai_jail::records::NativeString::Text(id.into()),
            mode: ukai_jail::policy::CredentialMode::CopyRw,
        }
    };
    let launch = ukai_jail::policy::LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        credentials: vec![decl("one"), decl("two")],
        state_discard: None,
    };
    let vendor_path = fixture.root.join("vendor");
    private_dir(&vendor_path);
    let vendor = ukai_jail::state::anchored::Dir::open_trusted(&vendor_path).unwrap();
    let refusal = ukai_jail::credentials::stage(&launch, vendor.as_fd(), &[])
        .expect_err("20 MiB under a 16 MiB per-attempt budget");
    assert_eq!(refusal.staged.len(), 1);
    assert!(
        refusal.error.message.contains("already copied"),
        "{}",
        refusal.error.message
    );
    assert_eq!(
        ukai_jail::credentials::inspect(&launch, &[])
            .iter()
            .map(|check| check.reason_code)
            .collect::<Vec<_>>(),
        ["ok", "copy_budget_exceeded"]
    );
}

#[test]
fn m4_names_values_and_ids_outside_their_grammars_refuse_through_the_file() {
    // Reviewer's RM50/RM18: the grammar is what keeps a NUL (and so extra
    // bubblewrap options in the `--args` payload) out of the environment.
    let fixture = Fixture::new();
    for (label, text) in [
        (
            "NUL in a name",
            "[environment]\n\"X\\u0000--ro-bind\\u0000/\\u0000/run/leak\" = \"v\"\n".to_owned(),
        ),
        ("= in a name", "[environment]\n\"A=B\" = \"v\"\n".to_owned()),
        (
            "leading digit",
            "[environment]\n\"1A\" = \"v\"\n".to_owned(),
        ),
        ("dash", "[environment]\n\"A-B\" = \"v\"\n".to_owned()),
        ("empty name", "[environment]\n\"\" = \"v\"\n".to_owned()),
        (
            "NUL in a value",
            "[environment]\nFIX = \"x\\u0000--ro-bind\\u0000/\\u0000/run/leak\"\n".to_owned(),
        ),
        ("NUL in state_var", "state_var = \"A\\u0000B\"\n".to_owned()),
        (
            "credential id with a slash",
            "[credentials.\"../x\"]\nsource = \"/c\"\ndest = \"x\"\nmode = \"copy_rw\"\n"
                .to_owned(),
        ),
        (
            "credential id with a space",
            "[credentials.\"a b\"]\nsource = \"/c\"\ndest = \"x\"\nmode = \"copy_rw\"\n".to_owned(),
        ),
        (
            "hidden credential id",
            "[credentials.\".hidden\"]\nsource = \"/c\"\ndest = \"x\"\nmode = \"copy_rw\"\n"
                .to_owned(),
        ),
        (
            "NUL in a destination",
            "[credentials.a]\nsource = \"/c\"\ndest = \"x\\u0000y\"\nmode = \"copy_rw\"\n"
                .to_owned(),
        ),
    ] {
        fixture.launch(
            "fixture",
            &format!("name = \"fixture\"\njail = \"agent\"\n{text}"),
        );
        let error = refused(
            fixture.plan(launch_args("fixture", &fixture.workspace)),
            label,
        );
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{label}: {error:?}");
    }
}

#[test]
fn rm24_rm25_an_oversized_launch_file_or_a_shared_launch_directory_refuses() {
    let fixture = Fixture::new();
    let padding = format!("# {}\n", "x".repeat(70 * 1024));
    fixture.launch(
        "fixture",
        &format!("{padding}name = \"fixture\"\njail = \"tool\"\n"),
    );
    let error = refused(
        fixture.plan(launch_args("fixture", &fixture.workspace)),
        "oversized",
    );
    assert!(error.message.contains("maximum"), "{}", error.message);

    fixture.launch("fixture", "name = \"fixture\"\njail = \"tool\"\n");
    assert!(
        fixture
            .plan(launch_args("fixture", &fixture.workspace))
            .is_ok()
    );
    let launch_dir = fixture.config.join("launch");
    // World-writable, so it is "others" whatever the host's groups are.
    std::fs::set_permissions(&launch_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = refused(
        fixture.plan(launch_args("fixture", &fixture.workspace)),
        "shared",
    );
    assert!(
        error.message.contains("writable by others"),
        "{}",
        error.message
    );
    std::fs::set_permissions(&launch_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn rm11_a_teardown_that_lost_integrity_retains_vendor_state_and_says_why() {
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a\"]\n",
    );
    let report = fixture.run(
        Sim {
            release_fails: true,
            release_teardown_lost: true,
            ..Sim::default()
        },
        &["--launch", "plain"],
    );
    assert_eq!(report.exit_code, 125);
    let receipt = receipt_json(&report);
    assert_schema("jail-receipt", &receipt);
    assert_eq!(receipt["lifetime"]["integrity"], "lost");
    assert_eq!(receipt["state_cleanup"], "pending");
    assert_eq!(receipt["cleanup_error"], cleanup::REASON_INTEGRITY_LOST);
    assert!(attempt_dir(&report).join("vendor-state/a").is_dir());
}

#[test]
fn l1_gc_prints_its_report_even_when_a_cleanup_stays_pending() {
    // Reviewer's live_gc_json: `gc --json` printed nothing when it exited 1.
    let fixture = Fixture::new();
    fixture.launch(
        "plain",
        "name = \"plain\"\njail = \"tool\"\nstate_subdirs = [\"a\"]\n",
    );
    let sim = Sim {
        activity: Some(Arc::new(|vendor: &Path| {
            let parked = vendor.with_file_name("parked");
            std::fs::rename(vendor, &parked).unwrap();
            std::fs::create_dir(vendor).unwrap();
        })),
        ..Sim::default()
    };
    let report = fixture.run(sim, &["--launch", "plain"]);
    assert_eq!(receipt_json(&report)["state_cleanup"], "pending");
    // J4-G (§14.2 "foreign-platform resources are retained"): the binary's
    // gc runs on this host's platform, so the simulated claim is made this
    // host's before it asks the binary to resume the cleanup.
    let state_path = attempt_dir(&report).join("jail-state.json");
    let mut state = jail_state(&report);
    state["os"] = serde_json::json!(std::env::consts::OS);
    state["arch"] = serde_json::json!(std::env::consts::ARCH);
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    let output = jail_binary(&fixture, &["gc", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("gc printed no JSON report: {error}"));
    assert_eq!(value["entries"][0]["action"], "pending", "{value}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("did not complete"));
    let text = jail_binary(&fixture, &["gc"]);
    assert_eq!(text.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&text.stdout).contains(" pending "));
}

#[test]
fn a_run_that_created_no_managed_scratch_reports_cleanup_not_needed() {
    // Integration finding: settlement said `complete` for a `none` run whose
    // platform created no managed scratch; nothing created is `not_needed`.
    let fixture = Fixture::new();
    let report = fixture.run(
        Sim {
            unapplied: true,
            ..Sim::default()
        },
        &["--profile", "none"],
    );
    assert_eq!(report.exit_code, 0, "{:?}", report.error);
    let receipt = receipt_json(&report);
    assert_eq!(receipt["phase"], "settled");
    assert_eq!(receipt["state_cleanup"], "not_needed");
}

fn stage_one_source_with(
    fixture: &Fixture,
    source: &Path,
    forbidden: &[(u64, u64)],
) -> Result<(), (JailError, usize)> {
    let vendor_path = fixture.root.join("vendor");
    let _ = std::fs::remove_dir_all(&vendor_path);
    private_dir(&vendor_path);
    let vendor = ukai_jail::state::anchored::Dir::open_trusted(&vendor_path).unwrap();
    let launch = ukai_jail::policy::LaunchSnapshot {
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        credentials: vec![ukai_jail::policy::CredentialDecl {
            vault: None,
            id: "only".into(),
            source: ukai_jail::records::NativeString::from_bytes(
                source.as_os_str().as_bytes().to_vec(),
            )
            .unwrap(),
            dest: ukai_jail::records::NativeString::Text("only".into()),
            mode: ukai_jail::policy::CredentialMode::CopyRw,
        }],
        state_discard: None,
    };
    ukai_jail::credentials::stage(&launch, vendor.as_fd(), forbidden)
        .map(|_| ())
        .map_err(|refusal| (refusal.error, refusal.staged.len()))
}

// ===========================================================================
// J14: persistent vendor state (docs/specs/jail-interactive-sessions.md §4,
// rows K65 to K71, K74 and K75), through the real supervisor over the
// simulated platform: acquisition, the hand-off, release and `gc` run
// against the real filesystem.
// ===========================================================================

mod persistent {
    use super::*;
    use ukai_jail::persistent::{
        self as state, Acquisition, FallbackReason, GcRelease, Releaser, Request,
    };

    /// A persistent `agent` profile `keeper` whose release discards a file
    /// and a directory.
    pub(super) fn keeper(fixture: &Fixture, extra: &str) {
        fixture.launch(
            "keeper",
            &format!(
                r#"
name = "keeper"
jail = "agent"
state_var = "KEEPER_HOME"
state = "persistent"
state_discard = [".login.json", "drop-me"]
{extra}
"#
            ),
        );
    }

    pub(super) fn run_keeper(fixture: &Fixture, sim: Sim, extra: &[&str]) -> supervisor::RunReport {
        let mut flags = vec!["--launch", "keeper"];
        flags.extend_from_slice(extra);
        fixture.run(sim, &flags)
    }

    /// The state's key directory for `keeper` in the fixture's workspace.
    pub(super) fn key_dir(fixture: &Fixture, workspace: &Path) -> PathBuf {
        state::key_path(
            &fixture.data,
            "keeper",
            &state::key("keeper", workspace.as_os_str().as_bytes()),
        )
    }

    pub(super) fn record(key_dir: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(key_dir.join("state.json")).unwrap()).unwrap()
    }

    /// The child writes a kept file, the two discard-list entries, a
    /// symlink out of the state, a FIFO and a socket.
    pub(super) fn child_writes(content: &'static str, outside: PathBuf) -> Activity {
        Arc::new(move |vendor: &Path| {
            std::fs::write(vendor.join("kept.txt"), content).unwrap();
            std::fs::write(vendor.join(".login.json"), b"a login made inside").unwrap();
            std::fs::create_dir_all(vendor.join("drop-me/deep")).unwrap();
            std::fs::write(vendor.join("drop-me/deep/x"), b"x").unwrap();
            let _ = std::fs::remove_file(vendor.join("link"));
            std::os::unix::fs::symlink(outside.join("precious"), vendor.join("link")).unwrap();
            let fifo = vendor.join("fifo");
            if !fifo.exists() {
                let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
                // SAFETY: mkfifo of a NUL-terminated path the test owns.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            if !vendor.join("sock").exists() {
                socket_node(&vendor.join("sock"));
            }
        })
    }

    fn vendor_state(receipt: &serde_json::Value) -> serde_json::Value {
        receipt["vendor_state"].clone()
    }

    /// K65: the grammar of `state` and `state_discard`.
    #[test]
    fn k65_the_state_keys_parse_and_refuse() {
        let parse = |extra: &str| {
            launch_profile::parse(
                &format!("name = \"demo\"\njail = \"agent\"\nstate_var = \"X_HOME\"\n{extra}"),
                "demo",
                launch_profile::LaunchSource::Bundled,
                None,
            )
        };
        let profile = parse("state = \"persistent\"\nstate_discard = [\".a.json\", \"b/c\"]\n")
            .expect("a persistent profile");
        assert_eq!(profile.state, launch_profile::StateKind::Persistent);
        assert_eq!(profile.state_discard.len(), 2);
        let default = parse("").expect("the default");
        assert_eq!(default.state, launch_profile::StateKind::Attempt);
        for (extra, key) in [
            ("state = \"shared\"\n", "launch.state"),
            (
                "state = \"persistent\"\nstate_discard = [\"../up\"]\n",
                "launch.state_discard",
            ),
            (
                "state = \"persistent\"\nstate_discard = [\"/abs\"]\n",
                "launch.state_discard",
            ),
            (
                "state = \"persistent\"\nstate_discard = [\"a\", \"a\"]\n",
                "launch.state_discard",
            ),
            (
                "state = \"persistent\"\nstate_discard = [\"a//b\"]\n",
                "launch.state_discard",
            ),
        ] {
            let error = parse(extra).expect_err(extra);
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{extra}");
            assert_eq!(error.key_path.as_deref(), Some(key), "{extra}: {error:?}");
        }
        // §4.5: only vault credentials may reach persistent state.
        for mode in ["copy_rw", "bind_ro"] {
            let error = parse(&format!(
                "state = \"persistent\"\n[credentials.tok]\nsource = \"/etc/hostname\"\n\
                 dest = \"tok\"\nmode = \"{mode}\"\n"
            ))
            .expect_err(mode);
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{mode}");
            assert_eq!(
                error.key_path.as_deref(),
                Some("launch.credentials.tok.mode"),
                "{mode}: {error:?}"
            );
            assert!(!error.message.contains("  "), "{}", error.message);
        }
    }

    /// K65: `--state` overrides the profile; `--state attempt` gives the
    /// snapshot a profile without the keys has (rc.3's bytes); persistent
    /// state refuses copied credentials and the managed gate.
    #[test]
    fn k65_state_attempt_restores_the_attempt_private_snapshot() {
        let fixture = Fixture::new();
        keeper(&fixture, "");
        fixture.launch(
            "plain",
            "\nname = \"plain\"\njail = \"agent\"\nstate_var = \"KEEPER_HOME\"\n",
        );
        let args = |name: &str, state: Option<cli::StateChoice>| PolicyArgs {
            state,
            ..launch_args(name, &fixture.workspace)
        };
        let persistent = fixture.plan(args("keeper", None)).unwrap();
        let snapshot = persistent.resolved.snapshot.to_canonical_value().unwrap();
        assert_eq!(
            snapshot["roots"]["vendor_state"],
            serde_json::json!({"kind": "persistent", "profile": "keeper"})
        );
        assert_eq!(
            snapshot["launch"]["state_discard"],
            serde_json::json!([".login.json", "drop-me"])
        );
        assert_schema("policy-snapshot", &snapshot);
        let attempt = fixture
            .plan(args("keeper", Some(cli::StateChoice::Attempt)))
            .unwrap();
        let plain = fixture.plan(args("plain", None)).unwrap();
        let attempt_bytes = attempt.resolved.snapshot.canonical_bytes().unwrap();
        let plain_bytes = plain.resolved.snapshot.canonical_bytes().unwrap();
        // The launch name is in neither: one profile with the keys and
        // `--state attempt` is byte for byte one without them.
        assert_eq!(
            String::from_utf8_lossy(&attempt_bytes),
            String::from_utf8_lossy(&plain_bytes).replace("\"plain\"", "\"keeper\"")
        );
        assert!(!String::from_utf8_lossy(&attempt_bytes).contains("state_discard"));
        assert!(!String::from_utf8_lossy(&attempt_bytes).contains("persistent"));
        // `--state persistent` on the plain profile.
        let forced = fixture
            .plan(args("plain", Some(cli::StateChoice::Persistent)))
            .unwrap();
        assert!(
            forced
                .resolved
                .snapshot
                .roots
                .vendor_state
                .as_ref()
                .is_some_and(ukai_jail::policy::VendorStateRoot::is_persistent)
        );
        // Without a launch profile.
        let error = refused(
            fixture.plan(PolicyArgs {
                state: Some(cli::StateChoice::Persistent),
                ..PolicyArgs::default()
            }),
            "--state without --launch",
        );
        assert_eq!(error.key_path.as_deref(), Some("--state"));
        // A copied credential and persistent state.
        let source = fixture.credential("tok", b"value");
        fixture.launch(
            "copier",
            &format!(
                "\nname = \"copier\"\njail = \"agent\"\n[credentials.tok]\nsource = \"{}\"\n\
                 dest = \"tok\"\nmode = \"copy_rw\"\n",
                source.display()
            ),
        );
        let error = refused(
            fixture.plan(args("copier", Some(cli::StateChoice::Persistent))),
            "persistent copy_rw",
        );
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        // The managed gate refuses persistent state before any claim.
        let report = fixture.run(Sim::default(), &["--launch", "keeper", "--gate-fd", "0"]);
        let error = report.error.expect("a refusal");
        assert_eq!(error.code, ErrorCode::InvalidConfig, "{error:?}");
        assert_eq!(error.key_path.as_deref(), Some("--gate-fd"));
        assert!(report.receipt_path.is_none(), "nothing was claimed");
    }

    /// K66, K68, K69: the layout, the release (discards without following
    /// a link, a new generation, the log) and the chain from attempt to
    /// attempt; a state another workspace's attempt never sees; no receipt
    /// carries a name below the state or a digest of it.
    #[test]
    fn k66_k68_k69_a_persistent_state_is_released_kept_and_chained() {
        let fixture = Fixture::new();
        keeper(&fixture, "");
        let sim = Sim {
            activity: Some(child_writes("first", fixture.outside.clone())),
            ..Sim::default()
        };
        let first = run_keeper(&fixture, sim.clone(), &[]);
        assert_eq!(first.exit_code, 0, "{:?}", first.error);
        let receipt = receipt_json(&first);
        assert_schema("jail-receipt", &receipt);
        assert_eq!(receipt["state_cleanup"], "released", "{receipt:#}");
        let id = receipt["attempt_id"].as_str().unwrap().to_owned();
        let vs = vendor_state(&receipt);
        assert_eq!(vs["kind"], "persistent");
        assert_eq!(vs["generation_start"], 0);
        assert_eq!(vs["generation_end"], 1);
        assert_eq!(vs["inherited_from"], serde_json::Value::Null);
        assert_eq!(vs["matches_release"], serde_json::Value::Null);
        assert_eq!(vs["matches_release_reason"], "new_state");
        assert_eq!(vs["discarded"], 2);
        assert_eq!(vs["secret_scan"], "clean");
        // The layout: private levels; the platform was handed vendor/.
        let key = key_dir(&fixture, &fixture.workspace);
        for (path, mode) in [
            (fixture.data.join("state"), 0o700),
            (fixture.data.join("state/keeper"), 0o700),
            (key.clone(), 0o700),
            (key.join("vendor"), 0o700),
            (key.join("state.json"), 0o600),
            (key.join("lease"), 0o600),
        ] {
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(metadata.mode() & 0o777, mode, "{}", path.display());
        }
        assert_eq!(
            sim.seen.lock().unwrap().vendor_path.as_deref(),
            Some(key.join("vendor").as_path())
        );
        // The release: discards gone, the link removed as nothing (it is
        // kept) and never followed, the FIFO and socket recorded unopened.
        assert!(key.join("vendor/kept.txt").is_file());
        assert!(!key.join("vendor/.login.json").exists());
        assert!(!key.join("vendor/drop-me").exists());
        assert!(
            std::fs::symlink_metadata(key.join("vendor/link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_outside_untouched(&fixture);
        let first_record = record(&key);
        assert_eq!(first_record["generation"], 1);
        assert_eq!(
            first_record["holder"],
            serde_json::json!({"attempt": id, "released": true})
        );
        assert_eq!(first_record["log"].as_array().unwrap().len(), 1);
        assert!(
            first_record["last_release"]["digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        let state_id = first_record["state_id"].as_str().unwrap().to_owned();
        assert_eq!(vs["state_id"], state_id.as_str());
        let jail = jail_state(&first);
        assert_eq!(jail["persistent_state"]["state_id"], state_id.as_str());
        assert_eq!(jail["state_cleanup"], "released");

        // N+1: inherited, unchanged.
        let second = run_keeper(&fixture, Sim::default(), &[]);
        let receipt = receipt_json(&second);
        assert_schema("jail-receipt", &receipt);
        let vs = vendor_state(&receipt);
        assert_eq!(vs["generation_start"], 1);
        assert_eq!(vs["generation_end"], 2);
        assert_eq!(vs["inherited_from"], id.as_str());
        assert_eq!(vs["matches_release"], true);
        assert_eq!(vs["matches_release_reason"], serde_json::Value::Null);
        let second_id = receipt["attempt_id"].as_str().unwrap().to_owned();

        // An operator edit between two attempts.
        std::fs::write(key.join("vendor/kept.txt"), b"edited outside").unwrap();
        let third = run_keeper(&fixture, Sim::default(), &[]);
        let receipt = receipt_json(&third);
        let vs = vendor_state(&receipt);
        assert_eq!(vs["inherited_from"], second_id.as_str());
        assert_eq!(vs["matches_release"], false);
        let summary = ukai_jail::summary::summarize_attempt(&attempt_dir(&third)).unwrap();
        let state_line = summary
            .lines
            .iter()
            .find(|line| line.line == "state")
            .expect("a state line");
        assert_eq!(
            state_line.text,
            format!(
                "state: kept, generation 3 · CHANGED outside the jail since {second_id} released it"
            )
        );

        // Another workspace: another state, which never saw this one.
        let other = fixture.root.join("other-workspace");
        private_dir(&other);
        let mut argv = vec![
            "ukai-jail".to_owned(),
            "run".to_owned(),
            "--workspace".to_owned(),
        ];
        argv.push(other.display().to_string());
        argv.extend(["--launch", "keeper", "--", "simulated-target"].map(str::to_owned));
        let cli::Command::Run(args) = cli::Cli::parse_from(argv).command else {
            unreachable!()
        };
        let seen = Sim::default();
        let ctx = fixture.context(Box::new(seen.clone()), Some(fixture.root.join("home")));
        let elsewhere = supervisor::run(&ctx, &args);
        let receipt = receipt_json(&elsewhere);
        assert_eq!(
            vendor_state(&receipt)["matches_release_reason"],
            "new_state"
        );
        let other_key = key_dir(&fixture, &other.canonicalize().unwrap());
        assert_ne!(other_key, key);
        assert!(!other_key.join("vendor/kept.txt").exists());

        // No receipt names anything below the state or carries its digest.
        let digest = record(&key)["last_release"]["digest"]
            .as_str()
            .unwrap()
            .to_owned();
        for report in [&first, &second, &third, &elsewhere] {
            let text = std::fs::read_to_string(attempt_dir(report).join("jail.json")).unwrap();
            for secret in ["kept.txt", ".login.json", "drop-me", digest.as_str()] {
                assert!(!text.contains(secret), "a receipt carries {secret}");
            }
        }
    }

    /// K68 (L05): a tree whose death is unproved retains the state
    /// unreleased; the next attempt takes the `unreleased` fallback (or,
    /// with stderr not a terminal, refuses `state_busy`); `gc` finishes the
    /// release under the permission rule, never removes the state, and a dry
    /// run changes nothing; the next attempt acquires it.
    #[test]
    fn k68_k71_an_unproved_tree_retains_the_state_and_gc_finishes_its_release() {
        let fixture = Fixture::new();
        keeper(&fixture, "");
        let unproved = run_keeper(
            &fixture,
            Sim {
                tree: TreeEnd::Unknown,
                activity: Some(child_writes("kept", fixture.outside.clone())),
                ..Sim::default()
            },
            &[],
        );
        let receipt = receipt_json(&unproved);
        assert_schema("jail-receipt", &receipt);
        assert_eq!(receipt["state_cleanup"], "pending", "{receipt:#}");
        assert_eq!(
            vendor_state(&receipt)["generation_end"],
            serde_json::Value::Null
        );
        let unproved_id = receipt["attempt_id"].as_str().unwrap().to_owned();
        let key = key_dir(&fixture, &fixture.workspace);
        assert_eq!(
            record(&key)["holder"],
            serde_json::json!({"attempt": unproved_id, "released": false})
        );

        // The next attempt finds it unreleased.
        let next = run_keeper(&fixture, Sim::default(), &[]);
        // SAFETY: isatty takes a descriptor number.
        let terminal = unsafe { libc::isatty(2) } == 1;
        if terminal {
            let receipt = receipt_json(&next);
            assert_schema("jail-receipt", &receipt);
            assert_eq!(
                vendor_state(&receipt),
                serde_json::json!({
                    "kind": "attempt_fallback",
                    "state_id": record(&key)["state_id"],
                    "reason": "unreleased",
                    "held_by": unproved_id,
                })
            );
            assert_eq!(receipt["state_cleanup"], "complete");
        } else {
            let error = next.error.expect("a refusal");
            assert_eq!(error.code, ErrorCode::StateBusy, "{error:?}");
            assert!(error.message.contains(&unproved_id), "{}", error.message);
            assert!(error.message.contains("ukai-jail gc"), "{}", error.message);
            assert_eq!(next.exit_code, 125);
        }
        // Still held, unreleased, unchanged by that attempt.
        assert_eq!(record(&key)["generation"], 0);

        // While the receipt says the tree is unproved, gc retains it.
        let report = fixture.gc(false).unwrap();
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.attempt_id == unproved_id)
            .unwrap();
        assert_eq!(entry.action, "retained", "{entry:?}");
        assert!(entry.reason.contains("tree_unverified"), "{entry:?}");
        assert_eq!(record(&key)["holder"]["released"], false);

        // Proved dead, the way a dead supervisor's later verification
        // would (its receipt settled), a dry run changes nothing.
        let path = attempt_dir(&unproved).join("jail.json");
        let mut settled = common::read_receipt(&path);
        settled["phase"] = "settled".into();
        settled["lifetime"]["tree_empty"] = true.into();
        settled["lifetime"]["integrity"] = "verified".into();
        settled["lifetime"]["verified_at"] = settled["updated_at"].clone();
        settled["outcome"]["kind"] = "exited".into();
        settled["outcome"]["code"] = 0.into();
        settled["errors"] = serde_json::json!([]);
        std::fs::write(&path, serde_json::to_vec_pretty(&settled).unwrap()).unwrap();
        let before = std::fs::read(key.join("state.json")).unwrap();
        let report = fixture.gc(true).unwrap();
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.attempt_id == unproved_id)
            .unwrap();
        assert_eq!(entry.action, "would_release_persistent_state", "{entry:?}");
        assert_eq!(std::fs::read(key.join("state.json")).unwrap(), before);
        let report = fixture.gc(false).unwrap();
        let entry = report
            .entries
            .iter()
            .find(|entry| entry.attempt_id == unproved_id)
            .unwrap();
        assert_eq!(entry.action, "released_persistent_state", "{entry:?}");
        assert!(
            entry
                .persistent_state
                .as_deref()
                .is_some_and(|detail| detail.contains("scan not_scanned")),
            "{entry:?}"
        );
        let gc_receipt = common::read_receipt(&path);
        assert_schema("jail-receipt", &gc_receipt);
        assert_eq!(gc_receipt["state_cleanup"], "released");
        assert_eq!(vendor_state(&gc_receipt)["generation_end"], 1);
        assert_eq!(vendor_state(&gc_receipt)["secret_scan"], "not_scanned");
        assert_eq!(record(&key)["holder"]["released"], true);
        assert_eq!(record(&key)["log"][0]["by"], "gc");
        // gc never removes the state, and a second pass has nothing to do.
        assert!(key.join("vendor/kept.txt").is_file());
        assert!(
            !key.join("vendor/.login.json").exists(),
            "gc applied the discard list"
        );
        let again = fixture.gc(false).unwrap();
        let entry = again
            .entries
            .iter()
            .find(|entry| entry.attempt_id == unproved_id)
            .unwrap();
        assert_ne!(entry.action, "released_persistent_state", "{entry:?}");

        // The next attempt acquires it.
        let acquired = run_keeper(&fixture, Sim::default(), &[]);
        let receipt = receipt_json(&acquired);
        assert_eq!(vendor_state(&receipt)["kind"], "persistent", "{receipt:#}");
        assert_eq!(vendor_state(&receipt)["generation_start"], 1);
        assert_eq!(
            vendor_state(&receipt)["inherited_from"],
            unproved_id.as_str()
        );
    }

    /// K67: a state another attempt holds gives this one throwaway state
    /// (stderr a terminal) or refuses `state_busy`; the holder's state,
    /// generation and digest are unchanged; a quarantined state refuses.
    #[test]
    fn k67_a_held_state_is_never_shared() {
        let fixture = Fixture::new();
        keeper(&fixture, "");
        let first = run_keeper(&fixture, Sim::default(), &[]);
        assert_eq!(first.exit_code, 0);
        let key = key_dir(&fixture, &fixture.workspace);
        // A live holder: a claimed attempt whose lease is held, recorded
        // as the state's holder, and the state's lease held.
        let holder = ukai_jail::state::AttemptId::generate();
        let holder_dir = fixture.data.join("attempts").join(holder.as_str());
        private_dir(&holder_dir);
        fixture_file(&holder_dir.join("jail.lock"), b"");
        let holder_lease = ukai_jail::state::Lease::acquire(&holder_dir.join("jail.lock"))
            .unwrap()
            .unwrap();
        let mut held = record(&key);
        held["holder"] = serde_json::json!({"attempt": holder.as_str(), "released": false});
        std::fs::write(
            key.join("state.json"),
            serde_json::to_vec_pretty(&held).unwrap(),
        )
        .unwrap();
        let before = std::fs::read(key.join("state.json")).unwrap();
        let levels = state::open_levels(
            &fixture.data,
            "keeper",
            key.file_name().unwrap().to_str().unwrap(),
            false,
        )
        .unwrap()
        .unwrap();
        let lease = state::take_lease(&levels.key_dir, &levels.path)
            .unwrap()
            .unwrap();
        let sim = Sim {
            activity: Some(child_writes("throwaway", fixture.outside.clone())),
            ..Sim::default()
        };
        let second = run_keeper(&fixture, sim.clone(), &[]);
        // SAFETY: isatty takes a descriptor number.
        if unsafe { libc::isatty(2) } == 1 {
            let receipt = receipt_json(&second);
            assert_schema("jail-receipt", &receipt);
            assert_eq!(
                vendor_state(&receipt),
                serde_json::json!({
                    "kind": "attempt_fallback",
                    "state_id": held["state_id"],
                    "reason": "held",
                    "held_by": holder.as_str(),
                })
            );
            assert_eq!(receipt["state_cleanup"], "complete");
            // Throwaway state, at the attempt's own vendor-state.
            let vendor = sim.seen.lock().unwrap().vendor_path.clone().unwrap();
            assert_eq!(vendor, attempt_dir(&second).join("vendor-state"));
            assert!(!vendor.exists(), "throwaway state was removed");
            let summary = ukai_jail::summary::summarize_attempt(&attempt_dir(&second)).unwrap();
            let line = summary
                .lines
                .iter()
                .find(|line| line.line == "state")
                .unwrap();
            assert!(line.text.starts_with("state: NOT kept"), "{}", line.text);
        } else {
            let error = second.error.clone().expect("state_busy");
            assert_eq!(error.code, ErrorCode::StateBusy, "{error:?}");
            assert!(error.message.contains(holder.as_str()), "{}", error.message);
            assert_eq!(second.exit_code, 125);
        }
        assert_eq!(
            std::fs::read(key.join("state.json")).unwrap(),
            before,
            "the holder's state changed"
        );
        assert!(
            !key.join("vendor/kept.txt").exists()
                || std::fs::read(key.join("vendor/kept.txt")).unwrap() != b"throwaway"
        );
        drop(lease);
        drop(holder_lease);

        // Released by its holder: acquired again. Then quarantined: refused.
        held["holder"]["released"] = true.into();
        held["quarantine"] = serde_json::json!({
            "reason": "credential_persisted", "attempt": holder.as_str(),
            "at": "2026-10-19T00:00:00Z", "files": ["x"],
        });
        std::fs::write(
            key.join("state.json"),
            serde_json::to_vec_pretty(&held).unwrap(),
        )
        .unwrap();
        let refused = run_keeper(&fixture, Sim::default(), &[]);
        let error = refused.error.expect("state_quarantined");
        assert_eq!(error.code, ErrorCode::StateQuarantined, "{error:?}");
        assert_eq!(refused.exit_code, 125);
    }

    /// K68: a refusal after the acquisition (here the staging's, a vault
    /// source that is not private) releases the state like any other end:
    /// the receipt says `released` with the generation, the holder is
    /// released durably, `gc` has nothing to finish and the next attempt
    /// inherits it. Before the fix the lease was dropped with the holder
    /// still recorded and a `complete` receipt no remedy could act on.
    #[test]
    fn k68_a_refusal_after_the_acquisition_releases_the_state() {
        let fixture = Fixture::new();
        let source = fixture.credential("token", b"vault-value-0123456789abcdef");
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
        keeper(
            &fixture,
            &format!(
                "\n[credentials.token]\nsource = \"{}\"\nmode = \"vault\"\n\
                 hosts = [\"https://api.example.test\"]\n\n[network]\nallow = [\"api.example.test\"]\n",
                source.display()
            ),
        );
        let refused = run_keeper(&fixture, Sim::default(), &[]);
        let error = refused.error.as_ref().expect("a staging refusal");
        assert_eq!(error.code, ErrorCode::CredentialUnavailable, "{error:?}");
        assert_eq!(refused.exit_code, 125);
        let receipt = receipt_json(&refused);
        assert_schema("jail-receipt", &receipt);
        assert_eq!(receipt["state_cleanup"], "released", "{receipt:#}");
        assert_eq!(vendor_state(&receipt)["kind"], "persistent");
        assert_eq!(vendor_state(&receipt)["generation_end"], 1);
        let refused_id = receipt["attempt_id"].as_str().unwrap().to_owned();
        let key = key_dir(&fixture, &fixture.workspace);
        assert_eq!(
            record(&key)["holder"],
            serde_json::json!({"attempt": refused_id, "released": true})
        );
        assert_eq!(record(&key)["generation"], 1);
        let summary = ukai_jail::summary::summarize_attempt(&attempt_dir(&refused)).unwrap();
        assert!(
            summary.lines.iter().all(|line| !line.text.contains("gc")),
            "{:?}",
            summary.lines
        );
        let report = fixture.gc(false).unwrap();
        assert!(
            report
                .entries
                .iter()
                .all(|entry| entry.attempt_id != refused_id || entry.action != "released"),
            "{:?}",
            report.entries
        );

        // The source made private, the next attempt acquires and inherits.
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let next = run_keeper(&fixture, Sim::default(), &[]);
        assert!(next.error.is_none(), "{:?}", next.error);
        let receipt = receipt_json(&next);
        assert_schema("jail-receipt", &receipt);
        assert_eq!(receipt["state_cleanup"], "released", "{receipt:#}");
        assert_eq!(
            vendor_state(&receipt)["inherited_from"],
            refused_id.as_str()
        );
        assert_eq!(vendor_state(&receipt)["matches_release"], true);
        assert_eq!(vendor_state(&receipt)["generation_end"], 2);
    }

    /// K70 (candidate): a vault credential's value found in the state at
    /// release quarantines it: `credential_persisted`, `secret_scan: found`,
    /// the summary says so, the next acquisition refuses, and the value is
    /// in no receipt, journal or state record.
    #[test]
    fn k70_a_vault_value_in_the_state_quarantines_it() {
        let fixture = Fixture::new();
        let value = "vault-value-0123456789abcdef";
        let source = fixture.credential("token", value.as_bytes());
        keeper(
            &fixture,
            &format!(
                "\n[credentials.token]\nsource = \"{}\"\nmode = \"vault\"\n\
                 hosts = [\"https://api.example.test\"]\n\n[network]\nallow = [\"api.example.test\"]\n",
                source.display()
            ),
        );
        let reflected: Activity = Arc::new(move |vendor: &Path| {
            std::fs::create_dir_all(vendor.join("projects/x")).unwrap();
            std::fs::write(
                vendor.join("projects/x/session.jsonl"),
                format!("{{\"echo\":\"Bearer {value}\"}}\n"),
            )
            .unwrap();
        });
        let report = run_keeper(
            &fixture,
            Sim {
                activity: Some(reflected),
                ..Sim::default()
            },
            &[],
        );
        assert_eq!(report.exit_code, 1, "{:?}", report.error);
        let receipt = receipt_json(&report);
        assert_schema("jail-receipt", &receipt);
        assert_eq!(vendor_state(&receipt)["secret_scan"], "found");
        assert!(
            receipt["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|error| error["code"] == "credential_persisted"),
            "{receipt:#}"
        );
        // The remedy names the verbs as the operator types them.
        let message = &report.error.as_ref().unwrap().message;
        let rm = format!(
            "`ukai-jail state rm keeper --workspace {}`",
            fixture.workspace.display()
        );
        assert!(message.contains(&rm), "{message}");
        let summary = ukai_jail::summary::summarize_attempt(&attempt_dir(&report)).unwrap();
        let line = summary
            .lines
            .iter()
            .find(|line| line.line == "state")
            .unwrap();
        assert_eq!(
            line.text,
            "state: quarantined: a vault credential's value was found in it"
        );
        let key = key_dir(&fixture, &fixture.workspace);
        let quarantine = &record(&key)["quarantine"];
        assert_eq!(quarantine["reason"], "credential_persisted");
        assert_eq!(
            quarantine["files"],
            serde_json::json!(["projects/x/session.jsonl"])
        );
        for file in [
            "jail.json",
            "trace.ndjson",
            "jail-state.json",
            "policy.json",
        ] {
            let path = attempt_dir(&report).join(file);
            if let Ok(text) = std::fs::read_to_string(&path) {
                assert!(!text.contains(value), "{file} carries the value");
            }
        }
        assert!(
            !std::fs::read_to_string(key.join("state.json"))
                .unwrap()
                .contains(value)
        );
        let next = run_keeper(&fixture, Sim::default(), &[]);
        assert_eq!(
            next.error.expect("refused").code,
            ErrorCode::StateQuarantined
        );
    }

    /// K70, review F1: an agent cannot keep a vault value out of the scan by
    /// making the file holding it, or the directory above it, unreadable to
    /// its owner: the release regains the owner's read (and search) bits on
    /// the operator's own entries, finds the value and quarantines the state.
    #[test]
    fn k70_an_unreadable_copy_is_still_found() {
        for locked in ["file", "directory"] {
            let fixture = Fixture::new();
            let value = "vault-value-unreadable-0123456789";
            let source = fixture.credential("token", value.as_bytes());
            keeper(
                &fixture,
                &format!(
                    "\n[credentials.token]\nsource = \"{}\"\nmode = \"vault\"\n\
                     hosts = [\"https://api.example.test\"]\n\n[network]\nallow = [\"api.example.test\"]\n",
                    source.display()
                ),
            );
            let hidden: Activity = Arc::new(move |vendor: &Path| {
                let dir = vendor.join("projects/x");
                std::fs::create_dir_all(&dir).unwrap();
                let file = dir.join("session.jsonl");
                std::fs::write(&file, format!("{{\"echo\":\"Bearer {value}\"}}\n")).unwrap();
                let target = if locked == "file" { file } else { dir };
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();
            });
            let report = run_keeper(
                &fixture,
                Sim {
                    activity: Some(hidden),
                    ..Sim::default()
                },
                &[],
            );
            assert_eq!(report.exit_code, 1, "{locked}: {:?}", report.error);
            let receipt = receipt_json(&report);
            assert_eq!(vendor_state(&receipt)["secret_scan"], "found", "{locked}");
            let key = key_dir(&fixture, &fixture.workspace);
            assert_eq!(
                record(&key)["quarantine"]["reason"],
                "credential_persisted",
                "{locked}"
            );
            // The release gave the owner read and search back, not write:
            // write goes back too, so the fixture's directory can go.
            std::fs::set_permissions(
                key.join("vendor/projects/x"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
    }

    /// K74: a workspace removed and made again at the same path with
    /// another inode refuses `state_workspace_changed`; the same-inode case
    /// is a named limit, recorded and not claimed.
    #[test]
    fn k74_a_workspace_made_again_refuses_unless_its_inode_was_reused() {
        let fixture = Fixture::new();
        keeper(&fixture, "");
        assert_eq!(run_keeper(&fixture, Sim::default(), &[]).exit_code, 0);
        // Another inode for certain: made while the old one still exists.
        let replacement = fixture.root.join("replacement");
        private_dir(&replacement);
        std::fs::remove_dir_all(&fixture.workspace).unwrap();
        std::fs::rename(&replacement, &fixture.workspace).unwrap();
        let report = run_keeper(&fixture, Sim::default(), &[]);
        let error = report.error.expect("refused");
        assert_eq!(error.code, ErrorCode::StateWorkspaceChanged, "{error:?}");
        assert!(
            error.message.contains("ukai-jail state rm"),
            "{}",
            error.message
        );
        // The same path made again at once: the inode may be reused.
        let removed = std::fs::metadata(&fixture.workspace).unwrap().ino();
        std::fs::remove_dir(&fixture.workspace).unwrap();
        private_dir(&fixture.workspace);
        let reused = std::fs::metadata(&fixture.workspace).unwrap().ino() == removed;
        println!("k74: the inode of a workspace made again was reused: {reused} (a named limit)");
    }

    /// K66 (§4.3 "Owner"): an existing level of the layout that is wider
    /// than 0700, a symlink, or not a directory refuses `unsafe_state_path`
    /// before anything is read or bound; `vendor/` may only be a directory
    /// (its mode is the agent's to change, and is reset).
    #[test]
    fn k66_a_level_that_is_not_private_refuses() {
        let acquire = |fixture: &Fixture| {
            let workspace = fixture.workspace.canonicalize().unwrap();
            state::acquire(&Request {
                data_dir: &fixture.data,
                launch: "keeper",
                workspace: &workspace,
                attempt: ukai_jail::state::AttemptId::generate().as_str(),
            })
        };
        let levels = |fixture: &Fixture| {
            let key = key_dir(fixture, &fixture.workspace.canonicalize().unwrap());
            vec![
                fixture.data.join("state"),
                fixture.data.join("state/keeper"),
                key.clone(),
                key.join("vendor"),
            ]
        };
        for (index, kind) in [
            (0, "wide"),
            (1, "wide"),
            (2, "wide"),
            (0, "link"),
            (1, "link"),
            (2, "link"),
            (3, "link"),
            (0, "file"),
            (1, "file"),
            (2, "file"),
            (3, "file"),
        ] {
            let fixture = Fixture::new();
            // The layout exists, as after a first run.
            drop(acquire(&fixture).unwrap());
            let level = levels(&fixture)[index].clone();
            match kind {
                "wide" => std::fs::set_permissions(&level, std::fs::Permissions::from_mode(0o755))
                    .unwrap(),
                "link" => {
                    let real = level.with_extension("real");
                    std::fs::rename(&level, &real).unwrap();
                    std::os::unix::fs::symlink(&real, &level).unwrap();
                }
                _ => {
                    std::fs::remove_dir_all(&level).unwrap();
                    std::fs::write(&level, b"").unwrap();
                    std::fs::set_permissions(&level, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
            }
            let error = match acquire(&fixture) {
                Err(error) => error,
                Ok(_) => panic!("{kind} level {} was accepted", level.display()),
            };
            assert_eq!(
                error.code,
                ErrorCode::UnsafeStatePath,
                "{kind} {}: {error:?}",
                level.display()
            );
        }
    }

    /// K66 (§4.3, review F4): the lease and the record are private regular
    /// files; one that is wider than 0600 or a symlink refuses
    /// `unsafe_state_path`.
    #[test]
    fn k66_a_lease_or_record_that_is_not_private_refuses() {
        let workspace = |fixture: &Fixture| fixture.workspace.canonicalize().unwrap();
        let acquire = |fixture: &Fixture| {
            state::acquire(&Request {
                data_dir: &fixture.data,
                launch: "keeper",
                workspace: &workspace(fixture),
                attempt: ukai_jail::state::AttemptId::generate().as_str(),
            })
        };
        for (file, kind) in [
            ("lease", "wide"),
            ("lease", "link"),
            ("state.json", "wide"),
            ("state.json", "link"),
        ] {
            let fixture = Fixture::new();
            let Acquisition::Held(mut held) = acquire(&fixture).unwrap() else {
                panic!("a fresh state is held");
            };
            // A record exists once the state was held and released.
            let attempt = ukai_jail::state::AttemptId::generate();
            state::hold(&mut held, attempt.as_str()).unwrap();
            state::release(
                *held,
                attempt.as_str(),
                &[],
                &[],
                Releaser::Supervisor { every_value: true },
            )
            .unwrap();
            let path = key_dir(&fixture, &workspace(&fixture)).join(file);
            if kind == "wide" {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            } else {
                let real = path.with_extension("real");
                std::fs::rename(&path, &real).unwrap();
                std::os::unix::fs::symlink(&real, &path).unwrap();
            }
            let error = match acquire(&fixture) {
                Err(error) => error,
                Ok(_) => panic!("{kind} {file} was accepted"),
            };
            assert_eq!(
                error.code,
                ErrorCode::UnsafeStatePath,
                "{kind} {file}: {error:?}"
            );
        }
    }

    /// K67 (review F14): a lease taken for an instant, as `state list`,
    /// `state show` and `doctor` take it, does not send an acquisition to
    /// the throwaway fallback; one still taken past the patience does.
    #[test]
    fn k67_an_instant_on_the_lease_is_not_a_holder() {
        let fixture = Fixture::new();
        let workspace = fixture.workspace.canonicalize().unwrap();
        let key = state::key("keeper", workspace.as_os_str().as_bytes());
        let acquire = || {
            state::acquire(&Request {
                data_dir: &fixture.data,
                launch: "keeper",
                workspace: &workspace,
                attempt: ukai_jail::state::AttemptId::generate().as_str(),
            })
            .unwrap()
        };
        drop(acquire());
        let levels = state::open_levels(&fixture.data, "keeper", &key, false)
            .unwrap()
            .unwrap();
        let brief = state::take_lease(&levels.key_dir, &levels.path)
            .unwrap()
            .unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(brief);
        });
        assert!(
            matches!(acquire(), Acquisition::Held(_)),
            "an instant is not a holder"
        );
        releaser.join().unwrap();
        let long = state::take_lease(&levels.key_dir, &levels.path)
            .unwrap()
            .unwrap();
        assert!(matches!(acquire(), Acquisition::Fallback(_)));
        drop(long);
    }

    /// K68, K71 (§4.6, §4.9, review F8): a release, by the supervisor or by
    /// `gc`, acts only for the attempt the record names as an unreleased
    /// holder; `gc` over an attempt whose integrity was lost quarantines the
    /// state instead of releasing it, and the next acquisition refuses.
    #[test]
    fn k68_k71_only_the_recorded_holder_is_released() {
        let fixture = Fixture::new();
        let workspace = fixture.workspace.canonicalize().unwrap();
        let key = state::key("keeper", workspace.as_os_str().as_bytes());
        let acquire = || match state::acquire(&Request {
            data_dir: &fixture.data,
            launch: "keeper",
            workspace: &workspace,
            attempt: ukai_jail::state::AttemptId::generate().as_str(),
        })
        .unwrap()
        {
            Acquisition::Held(held) => held,
            Acquisition::Fallback(_) => panic!("the state is free"),
        };
        let holder = ukai_jail::state::AttemptId::generate();
        let other = ukai_jail::state::AttemptId::generate();
        let mut held = acquire();
        state::hold(&mut held, holder.as_str()).unwrap();
        // The supervisor's release names another attempt: refused, nothing
        // written.
        assert_eq!(
            state::release(
                *held,
                other.as_str(),
                &[],
                &[],
                Releaser::Supervisor { every_value: true }
            )
            .err(),
            Some("state_not_held_by_this_attempt".to_owned())
        );
        let unchanged = record(&key_dir(&fixture, &workspace));
        assert_eq!(unchanged["generation"], 0, "{unchanged:#}");
        assert_eq!(unchanged["holder"]["attempt"], holder.as_str());
        assert_eq!(unchanged["holder"]["released"], false);
        // gc for another attempt: not this state's holder.
        assert!(matches!(
            state::gc_release(
                &fixture.data,
                "keeper",
                &key,
                other.as_str(),
                &[],
                false,
                false
            ),
            Ok(GcRelease::NotHeld)
        ));
        assert_eq!(record(&key_dir(&fixture, &workspace))["generation"], 0);
        // gc for the holder releases it, unscanned.
        assert!(matches!(
            state::gc_release(
                &fixture.data,
                "keeper",
                &key,
                holder.as_str(),
                &[],
                false,
                false
            ),
            Ok(GcRelease::Released(_))
        ));
        let released = record(&key_dir(&fixture, &workspace));
        assert_eq!(released["generation"], 1, "{released:#}");
        assert_eq!(released["holder"]["released"], true);

        // A supervisor that forgot one of the values it loaded cannot call
        // its scan clean (review F13).
        let forgetful = ukai_jail::state::AttemptId::generate();
        let mut held = acquire();
        state::hold(&mut held, forgetful.as_str()).unwrap();
        let released = state::release(
            *held,
            forgetful.as_str(),
            &[],
            &[b"a-value".as_slice()],
            Releaser::Supervisor { every_value: false },
        )
        .unwrap();
        assert_eq!(released.secret_scan, "not_scanned");

        // Lost integrity: quarantined, never released.
        let lost = ukai_jail::state::AttemptId::generate();
        let mut held = acquire();
        state::hold(&mut held, lost.as_str()).unwrap();
        drop(held);
        assert!(matches!(
            state::gc_release(
                &fixture.data,
                "keeper",
                &key,
                lost.as_str(),
                &[],
                false,
                true
            ),
            Ok(GcRelease::Quarantined)
        ));
        let quarantined = record(&key_dir(&fixture, &workspace));
        assert_eq!(quarantined["quarantine"]["reason"], "integrity_lost");
        assert_eq!(quarantined["generation"], 2, "{quarantined:#}");
        let refused = state::acquire(&Request {
            data_dir: &fixture.data,
            launch: "keeper",
            workspace: &workspace,
            attempt: ukai_jail::state::AttemptId::generate().as_str(),
        });
        assert_eq!(
            refused.err().map(|error| error.code),
            Some(ErrorCode::StateQuarantined)
        );
    }

    /// K66: host-side walks never follow a link nor open a FIFO, socket or
    /// device; `discard` removes a link as a link; the manifest's bounds
    /// make the digest unavailable instead of claiming a match.
    #[test]
    fn k66_k73_host_walks_never_follow_and_their_bounds_claim_nothing() {
        let fixture = Fixture::new();
        let workspace = fixture.workspace.canonicalize().unwrap();
        let attempt = ukai_jail::state::AttemptId::generate();
        let Acquisition::Held(mut held) = state::acquire(&Request {
            data_dir: &fixture.data,
            launch: "keeper",
            workspace: &workspace,
            attempt: attempt.as_str(),
        })
        .unwrap() else {
            panic!("a fresh state is held");
        };
        state::hold(&mut held, attempt.as_str()).unwrap();
        let vendor = held.vendor_path();
        // A discard entry that is a symlink to an outside file, one whose
        // parent is a symlink to an outside directory, a FIFO, a socket.
        std::os::unix::fs::symlink(fixture.outside.join("precious"), vendor.join(".login.json"))
            .unwrap();
        std::os::unix::fs::symlink(&fixture.outside, vendor.join("drop-me")).unwrap();
        let fifo = std::ffi::CString::new(vendor.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: mkfifo of a NUL-terminated path the test owns.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        socket_node(&vendor.join("sock"));
        let released = state::release(
            *held,
            attempt.as_str(),
            &[
                ukai_jail::records::NativeString::Text(".login.json".into()),
                ukai_jail::records::NativeString::Text("drop-me/precious".into()),
            ],
            &[],
            Releaser::Supervisor { every_value: true },
        )
        .unwrap();
        assert_eq!(released.discarded, 1, "only the link itself is removed");
        assert!(!vendor.join(".login.json").exists());
        assert_outside_untouched(&fixture);
        assert!(
            std::fs::symlink_metadata(vendor.join("drop-me"))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // The bounds: past them, no digest and no claim of a match.
        // SAFETY: a test seam read by this process only.
        unsafe { std::env::set_var(state::SEAM_BOUNDS, "2,1048576") };
        let second = ukai_jail::state::AttemptId::generate();
        let Acquisition::Held(held) = state::acquire(&Request {
            data_dir: &fixture.data,
            launch: "keeper",
            workspace: &workspace,
            attempt: second.as_str(),
        })
        .unwrap() else {
            panic!("released, so held");
        };
        // SAFETY: as above.
        unsafe { std::env::remove_var(state::SEAM_BOUNDS) };
        assert_eq!(held.start.matches_release, None);
        assert_eq!(held.start.matches_release_reason, Some("state_too_large"));
        drop(held);

        // `state rm` removes links as links.
        let removed = state::remove(&fixture.data, "keeper", &workspace).unwrap();
        assert!(
            matches!(removed, state::Removed::Removed { .. }),
            "{removed:?}"
        );
        assert_outside_untouched(&fixture);
        assert!(!vendor.exists());
        let _ = FallbackReason::Held;
    }

    /// K73 (§4.4, review F7): the walk's depth and byte bounds. A tree
    /// deeper than the depth bound, or more content than the byte bound, has
    /// no digest, and the search does not claim to have covered it; within
    /// both, it has a digest and covers every file.
    #[test]
    fn k73_the_walk_bounds_its_depth_and_its_bytes() {
        let root = common::private_tempdir();
        let vendor = root.path().join("vendor");
        let mut deep = vendor.clone();
        for _ in 0..=state::DEPTH_MAX {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        let open = || ukai_jail::state::anchored::Dir::open_trusted(&vendor).unwrap();
        let pass = state::manifest(&open(), &[b"needle"]);
        assert_eq!(pass.digest, Err(state::Unavailable::TooLarge));
        assert!(!pass.searched_all);
        std::fs::remove_dir_all(vendor.join("d")).unwrap();

        for name in ["a", "b", "c"] {
            std::fs::write(vendor.join(name), vec![b'x'; 1000]).unwrap();
        }
        // SAFETY: a test seam read by this process only.
        unsafe { std::env::set_var(state::SEAM_BOUNDS, "65536,2048") };
        let past = state::manifest(&open(), &[b"needle"]);
        // SAFETY: as above.
        unsafe { std::env::set_var(state::SEAM_BOUNDS, "65536,4096") };
        let within = state::manifest(&open(), &[b"needle"]);
        // SAFETY: as above.
        unsafe { std::env::remove_var(state::SEAM_BOUNDS) };
        assert_eq!(past.digest, Err(state::Unavailable::TooLarge));
        assert!(!past.searched_all);
        assert!(within.digest.is_ok(), "{within:?}");
        assert!(within.searched_all);
        assert_eq!(within.bytes, 3000);
    }

    /// K71: `state list`, `state show` and `state rm` through the binary;
    /// `rm` refuses while an attempt holds the lease.
    #[test]
    fn k71_the_state_verbs_list_show_and_remove() {
        let fixture = inspection_fixture();
        keeper(&fixture, "");
        assert_eq!(run_keeper(&fixture, Sim::default(), &[]).exit_code, 0);
        let workspace = fixture.workspace.display().to_string();
        let listed = jail_binary(&fixture, &["state", "list", "--json"]);
        assert!(listed.status.success(), "{listed:?}");
        let value: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 1, "{value:#}");
        assert_eq!(value[0]["launch"], "keeper");
        assert_eq!(value[0]["generation"], 1);
        assert_eq!(value[0]["held"], false);
        let shown = jail_binary(
            &fixture,
            &["state", "show", "keeper", "--workspace", &workspace],
        );
        assert!(shown.status.success(), "{shown:?}");
        let text = String::from_utf8_lossy(&shown.stdout);
        assert!(text.contains("generation 1"), "{text}");
        assert!(text.contains("by supervisor"), "{text}");
        let key = key_dir(&fixture, &fixture.workspace.canonicalize().unwrap());
        let levels = state::open_levels(
            &fixture.data,
            "keeper",
            key.file_name().unwrap().to_str().unwrap(),
            false,
        )
        .unwrap()
        .unwrap();
        let lease = state::take_lease(&levels.key_dir, &levels.path)
            .unwrap()
            .unwrap();
        let refused = jail_binary(
            &fixture,
            &["state", "rm", "keeper", "--workspace", &workspace],
        );
        assert_eq!(refused.status.code(), Some(1), "{refused:?}");
        assert!(key.exists());
        drop(lease);
        let removed = jail_binary(
            &fixture,
            &["state", "rm", "keeper", "--workspace", &workspace],
        );
        assert!(removed.status.success(), "{removed:?}");
        assert!(!key.exists());
        let absent = jail_binary(
            &fixture,
            &["state", "show", "keeper", "--workspace", &workspace],
        );
        assert_eq!(absent.status.code(), Some(1));
    }

    /// The state of `keeper` for `workspace`, acquired by a new attempt,
    /// given a `settings.json` and `files` empty files in `vendor/`, and
    /// released: its `vendor/` path.
    fn released_state(fixture: &Fixture, workspace: &Path, files: usize) -> PathBuf {
        let attempt = ukai_jail::state::AttemptId::generate();
        let Acquisition::Held(mut held) = state::acquire(&Request {
            data_dir: &fixture.data,
            launch: "keeper",
            workspace,
            attempt: attempt.as_str(),
        })
        .unwrap() else {
            panic!("the state is free");
        };
        state::hold(&mut held, attempt.as_str()).unwrap();
        let vendor = held.vendor_path();
        std::fs::write(vendor.join("settings.json"), b"{\"hooks\":\"kept\"}").unwrap();
        for index in 0..files {
            let dir = vendor.join(format!("d{}", index / 1000));
            if index % 1000 == 0 {
                std::fs::create_dir(&dir).unwrap();
            }
            std::fs::File::create(dir.join(index.to_string())).unwrap();
        }
        state::release(
            *held,
            attempt.as_str(),
            &[],
            &[],
            Releaser::Supervisor { every_value: true },
        )
        .unwrap();
        vendor
    }

    fn try_acquire(
        fixture: &Fixture,
        workspace: &Path,
    ) -> Result<Acquisition, ukai_jail::records::JailError> {
        state::acquire(&Request {
            data_dir: &fixture.data,
            launch: "keeper",
            workspace,
            attempt: ukai_jail::state::AttemptId::generate().as_str(),
        })
    }

    /// The entries of `<data>/state/keeper/` whose names are not a key.
    fn tombstones(fixture: &Fixture) -> Vec<String> {
        std::fs::read_dir(fixture.data.join("state/keeper"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with('.'))
            .collect()
    }

    /// K71 (review: `state rm` was not atomic): an acquisition racing
    /// `state rm` never holds the directory being removed. What it holds is
    /// still the state at its path once the removal is done, with its
    /// record, and the removal completes.
    #[test]
    fn k71_an_acquisition_racing_state_rm_never_holds_what_it_removes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let fixture = Fixture::new();
        let workspace = fixture.workspace.canonicalize().unwrap();
        released_state(&fixture, &workspace, 30_000);
        let key = key_dir(&fixture, &workspace);
        let removing = AtomicBool::new(true);
        let (removed, held) = std::thread::scope(|scope| {
            let remover = scope.spawn(|| {
                let removed = state::remove(&fixture.data, "keeper", &workspace);
                removing.store(false, Ordering::SeqCst);
                removed
            });
            // The removal takes the lease first; an acquisition holding it
            // would only make `rm` refuse.
            std::thread::sleep(Duration::from_millis(50));
            let mut held = Vec::new();
            while removing.load(Ordering::SeqCst) {
                match try_acquire(&fixture, &workspace) {
                    Ok(Acquisition::Held(state)) => held.push((
                        state.levels.key_dir.stat().unwrap().identity(),
                        state.start.matches_release_reason,
                    )),
                    Ok(Acquisition::Fallback(_)) => {}
                    Err(error) => held.push(((0, 0), Some(error.code.as_str()))),
                }
            }
            (remover.join().unwrap(), held)
        });
        assert!(
            matches!(removed, Ok(state::Removed::Removed { .. })),
            "{removed:?}"
        );
        println!(
            "k71: {} acquisitions held a state while `state rm` ran",
            held.len()
        );
        let now = std::fs::metadata(&key)
            .ok()
            .map(|meta| (meta.dev(), meta.ino()));
        for (identity, reason) in &held {
            assert_eq!(
                now,
                Some(*identity),
                "an acquisition during the removal held a directory the removal took \
                 ({reason:?}; {} acquisitions held)",
                held.len()
            );
            assert!(key.join("state.json").exists());
        }
        assert_eq!(tombstones(&fixture), Vec::<String>::new());
    }

    /// K66 (review: a key directory without its record was adopted as a new
    /// state): a state whose `state.json` and lease are gone but whose
    /// `vendor/` is not, as an interrupted removal of an earlier build or a
    /// hand left it, refuses `unsafe_state_path` naming `state rm`; it never
    /// passes for a new state with the old content visible. `state rm` clears
    /// it.
    #[test]
    fn k66_a_vendor_without_its_record_is_never_a_new_state() {
        let fixture = Fixture::new();
        let workspace = fixture.workspace.canonicalize().unwrap();
        let vendor = released_state(&fixture, &workspace, 0);
        let key = key_dir(&fixture, &workspace);
        std::fs::remove_file(key.join("state.json")).unwrap();
        std::fs::remove_file(key.join("lease")).unwrap();
        let error = match try_acquire(&fixture, &workspace) {
            Err(error) => error,
            Ok(Acquisition::Held(held)) => panic!(
                "adopted as {:?}, generation {}",
                held.start.matches_release_reason, held.start.generation
            ),
            Ok(Acquisition::Fallback(fallback)) => panic!("{fallback:?}"),
        };
        assert_eq!(error.code, ErrorCode::UnsafeStatePath, "{error:?}");
        assert!(
            error
                .message
                .contains("ukai-jail state rm keeper --workspace"),
            "{}",
            error.message
        );
        assert!(vendor.join("settings.json").exists(), "nothing was removed");
        assert!(matches!(
            state::remove(&fixture.data, "keeper", &workspace).unwrap(),
            state::Removed::Removed { .. }
        ));
        let Ok(Acquisition::Held(held)) = try_acquire(&fixture, &workspace) else {
            panic!("a new state");
        };
        assert_eq!(held.start.matches_release_reason, Some("new_state"));
        assert!(!held.vendor_path().join("settings.json").exists());
    }

    /// K71 (review: an interrupted `state rm` left a partial state at its
    /// path, which the next run reported as new): `rm` renames the state
    /// away from its path before removing it, so a removal that stops leaves
    /// a tombstone no acquisition adopts. `state list` reports it, a `gc`
    /// dry run leaves it, and `gc` finishes it.
    #[test]
    fn k71_an_interrupted_state_rm_leaves_a_tombstone_gc_finishes() {
        let fixture = inspection_fixture();
        keeper(&fixture, "");
        let workspace = fixture.workspace.canonicalize().unwrap();
        let vendor = released_state(&fixture, &workspace, 0);
        let undo = obstruct_first_pass(&vendor);
        let key = key_dir(&fixture, &workspace);
        let stopped = state::remove(&fixture.data, "keeper", &workspace);
        let error = stopped.expect_err("the removal stops");
        assert!(error.message.contains("ukai-jail gc"), "{}", error.message);
        assert!(!key.exists(), "the state left its path before its removal");
        assert_eq!(tombstones(&fixture).len(), 1);
        let Ok(Acquisition::Held(held)) = try_acquire(&fixture, &workspace) else {
            panic!("a new state");
        };
        assert_eq!(held.start.matches_release_reason, Some("new_state"));
        assert!(!held.vendor_path().join("settings.json").exists());
        drop(held);
        let listed = jail_binary(&fixture, &["state", "list", "--json"]);
        assert!(listed.status.success(), "{listed:?}");
        let value: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
        let removing: Vec<&serde_json::Value> = value
            .as_array()
            .unwrap()
            .iter()
            .filter(|state| state["removing"] == true)
            .collect();
        assert_eq!(removing.len(), 1, "{value:#}");
        assert_eq!(removing[0]["launch"], "keeper");
        let text = jail_binary(&fixture, &["state", "list"]);
        let text = String::from_utf8_lossy(&text.stdout);
        assert!(text.contains("run ukai-jail gc"), "{text}");
        // The obstruction moved with the tombstone.
        drop(undo);
        if cfg!(target_os = "macos") {
            let pinned = fixture
                .data
                .join("state/keeper")
                .join(&tombstones(&fixture)[0])
                .join("vendor/pinned");
            assert!(
                std::process::Command::new("chflags")
                    .arg("nouchg")
                    .arg(&pinned)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let dry = fixture.gc(true).unwrap();
        assert_eq!(tombstones(&fixture).len(), 1, "a dry run removes nothing");
        assert!(
            dry.state_removals
                .iter()
                .any(|line| line.ends_with("would_remove")),
            "{:?}",
            dry.state_removals
        );
        for _ in 0..3 {
            let _ = fixture.gc(false).unwrap();
            if tombstones(&fixture).is_empty() {
                break;
            }
        }
        assert_eq!(tombstones(&fixture), Vec::<String>::new());
        assert!(key.join("state.json").exists(), "the new state is kept");
    }

    /// K71: `gc` reports a state root it cannot read, among what stayed
    /// incomplete, and still reports and reconciles the attempts.
    #[test]
    fn k71_gc_reports_a_state_root_it_cannot_read() {
        let fixture = Fixture::new();
        keeper(&fixture, "");
        assert_eq!(run_keeper(&fixture, Sim::default(), &[]).exit_code, 0);
        let root = fixture.data.join("state");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let report = fixture.gc(false).expect("gc reports");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(report.entries.len(), 1, "{report:?}");
        assert!(
            report
                .incomplete
                .iter()
                .any(|line| line.starts_with("state/ (")),
            "{:?}",
            report.incomplete
        );
    }

    /// K70 (review: quarantine files were unbounded): a quarantine names at
    /// most a bounded number of files and counts the rest, so a release that
    /// found the value in many files with long names still leaves a record
    /// the next acquisition reads, and it refuses `state_quarantined`, not
    /// `unsafe_state_path`.
    #[test]
    fn k70_a_quarantine_of_many_files_stays_readable() {
        let fixture = Fixture::new();
        let value = "vault-value-many-0123456789abcdef";
        let source = fixture.credential("token", value.as_bytes());
        keeper(
            &fixture,
            &format!(
                "\n[credentials.token]\nsource = \"{}\"\nmode = \"vault\"\n\
                 hosts = [\"https://api.example.test\"]\n\n[network]\nallow = [\"api.example.test\"]\n",
                source.display()
            ),
        );
        let copies: Activity = Arc::new(move |vendor: &Path| {
            let padding = "x".repeat(220);
            for index in 0..1500 {
                std::fs::write(
                    vendor.join(format!("f{index:05}-{padding}")),
                    format!("Bearer {value}"),
                )
                .unwrap();
            }
        });
        let report = run_keeper(
            &fixture,
            Sim {
                activity: Some(copies),
                ..Sim::default()
            },
            &[],
        );
        assert_eq!(report.exit_code, 1, "{:?}", report.error);
        let next = run_keeper(&fixture, Sim::default(), &[]);
        let error = next.error.expect("refused");
        assert_eq!(error.code, ErrorCode::StateQuarantined, "{error:?}");
        let workspace = fixture.workspace.canonicalize().unwrap();
        let shown = state::show(&fixture.data, "keeper", &workspace)
            .unwrap()
            .unwrap();
        let record = shown.record.expect("the record reads");
        let quarantine = record.quarantine.expect("quarantined");
        assert_eq!(
            quarantine.files.len() + usize::try_from(quarantine.files_omitted).unwrap(),
            1500
        );
        assert!(quarantine.files.len() <= state::QUARANTINE_FILES_MAX);
    }

    /// K71 (review: the state verbs needed the workspace to exist): `state
    /// show` and `state rm` take the absolute path of a workspace that was
    /// deleted or moved, so the state a quarantine or the workspace check
    /// names can still be shown and removed.
    #[test]
    fn k71_the_state_verbs_take_a_workspace_that_is_gone() {
        let fixture = inspection_fixture();
        keeper(&fixture, "");
        assert_eq!(run_keeper(&fixture, Sim::default(), &[]).exit_code, 0);
        let workspace = fixture.workspace.canonicalize().unwrap();
        let key = key_dir(&fixture, &workspace);
        std::fs::rename(&fixture.workspace, fixture.root.join("moved")).unwrap();
        private_dir(&fixture.root.join("cwd"));
        let gone = workspace.display().to_string();
        let run = |args: &[&str]| {
            std::process::Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
                .args(args)
                .current_dir(fixture.root.join("cwd"))
                .env("UKAI_CONFIG_DIR", &fixture.config)
                .env("UKAI_DATA_DIR", &fixture.data)
                .env("HOME", fixture.root.join("home"))
                .output()
                .unwrap()
        };
        let shown = run(&["state", "show", "keeper", "--workspace", &gone]);
        assert!(shown.status.success(), "{shown:?}");
        assert!(
            String::from_utf8_lossy(&shown.stdout).contains("generation 1"),
            "{shown:?}"
        );
        // A relative path that does not exist is still refused.
        let relative = run(&["state", "show", "keeper", "--workspace", "gone/below"]);
        assert_eq!(relative.status.code(), Some(2), "{relative:?}");
        let removed = run(&["state", "rm", "keeper", "--workspace", &gone]);
        assert!(removed.status.success(), "{removed:?}");
        assert!(!key.exists());
        // A workspace whose parent is gone too.
        let nested = fixture.root.join("nest/repo");
        private_dir(&nested);
        drop(try_acquire(&fixture, &nested).unwrap());
        let nested_key = key_dir(&fixture, &nested);
        assert!(nested_key.exists());
        std::fs::remove_dir_all(fixture.root.join("nest")).unwrap();
        let nested = nested.display().to_string();
        let removed = run(&["state", "rm", "keeper", "--workspace", &nested]);
        assert!(removed.status.success(), "{removed:?}");
        assert!(!nested_key.exists());
    }

    /// K70 (review: scan gaps): a value found before a file passed the byte
    /// bound is still a hit, and a value in an entry's name, in its path
    /// across a directory, or in a symlink's target is found too, though the
    /// pass reads nothing behind the link.
    #[test]
    fn k70_the_scan_finds_a_value_wherever_the_pass_read_it() {
        let root = common::private_tempdir();
        let vendor = root.path().join("vendor");
        std::fs::create_dir(&vendor).unwrap();
        let open = || ukai_jail::state::anchored::Dir::open_trusted(&vendor).unwrap();
        let value: &[u8] = b"needle/0123456789";
        let mut big = b"Bearer needle/0123456789 ".to_vec();
        big.resize(8192, b'x');
        std::fs::write(vendor.join("big"), &big).unwrap();
        // SAFETY: a test seam read by this process only.
        unsafe { std::env::set_var(state::SEAM_BOUNDS, "65536,4096") };
        let past = state::manifest(&open(), &[value]);
        // SAFETY: as above.
        unsafe { std::env::remove_var(state::SEAM_BOUNDS) };
        assert_eq!(past.digest, Err(state::Unavailable::TooLarge));
        assert_eq!(past.hits, [b"big".to_vec()], "a hit found is a hit");
        std::fs::remove_file(vendor.join("big")).unwrap();

        std::fs::create_dir(vendor.join("needle")).unwrap();
        std::fs::write(vendor.join("needle/0123456789.json"), b"{}").unwrap();
        std::os::unix::fs::symlink("/elsewhere/needle/0123456789", vendor.join("link")).unwrap();
        let pass = state::manifest(&open(), &[value]);
        assert!(pass.digest.is_ok(), "{pass:?}");
        let mut hits = pass.hits.clone();
        hits.sort();
        assert_eq!(
            hits,
            [b"[vault value].json".to_vec(), b"link".to_vec()],
            "{:?}",
            pass.hits
                .iter()
                .map(|hit| String::from_utf8_lossy(hit).into_owned())
                .collect::<Vec<_>>()
        );
    }

    /// K70, the same through a run: an entry named after the value
    /// quarantines the state, and neither the record nor `state show`
    /// carries the value: the name is recorded with it replaced.
    #[test]
    fn k70_a_value_in_a_file_name_quarantines_without_recording_it() {
        let fixture = Fixture::new();
        let value = "vault-value-named-0123456789abcdef";
        let source = fixture.credential("token", value.as_bytes());
        keeper(
            &fixture,
            &format!(
                "\n[credentials.token]\nsource = \"{}\"\nmode = \"vault\"\n\
                 hosts = [\"https://api.example.test\"]\n\n[network]\nallow = [\"api.example.test\"]\n",
                source.display()
            ),
        );
        let named: Activity = Arc::new(move |vendor: &Path| {
            std::fs::write(vendor.join(format!("cache-{value}")), b"{}").unwrap();
        });
        let report = run_keeper(
            &fixture,
            Sim {
                activity: Some(named),
                ..Sim::default()
            },
            &[],
        );
        assert_eq!(report.exit_code, 1, "{:?}", report.error);
        let receipt = receipt_json(&report);
        assert_eq!(vendor_state(&receipt)["secret_scan"], "found");
        let key = key_dir(&fixture, &fixture.workspace);
        assert_eq!(
            record(&key)["quarantine"]["files"],
            serde_json::json!(["cache-[vault value]"])
        );
        assert!(
            !std::fs::read_to_string(key.join("state.json"))
                .unwrap()
                .contains(value)
        );
    }

    /// Review (records): `doctor` says why the state for this workspace is
    /// unusable where `run` would refuse, never "none yet"; `state list`
    /// says when it could not tell whether the lease is held.
    #[test]
    fn doctor_and_state_list_say_what_they_could_not_read() {
        let fixture = inspection_fixture();
        keeper(&fixture, "");
        assert_eq!(run_keeper(&fixture, Sim::default(), &[]).exit_code, 0);
        let key = key_dir(&fixture, &fixture.workspace.canonicalize().unwrap());
        let lease = key.join("lease");
        std::fs::rename(&lease, key.join("lease.real")).unwrap();
        std::os::unix::fs::symlink(key.join("lease.real"), &lease).unwrap();
        let listed = jail_binary(&fixture, &["state", "list", "--json"]);
        let value: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
        assert_eq!(value[0]["held"], serde_json::Value::Null, "{value:#}");
        assert!(
            value[0]["lease_error"]
                .as_str()
                .is_some_and(|why| why.contains("symbolic link")),
            "{value:#}"
        );
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o755)).unwrap();
        let doctor = jail_binary(&fixture, &["doctor", "--launch", "keeper"]);
        let stdout = String::from_utf8_lossy(&doctor.stdout);
        let line = stdout
            .lines()
            .find(|line| line.starts_with("state persistent"))
            .unwrap_or_else(|| panic!("{doctor:?}"));
        assert!(
            line.starts_with("state persistent: unusable (unsafe_state_path"),
            "{line}"
        );
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// K67 (review: records): a lease held while the record still names an
    /// attempt that already released the state (the next holder has not
    /// written itself yet) falls back naming "another attempt", never the
    /// released one, even while that one's supervisor is still alive.
    #[test]
    fn k67_a_held_fallback_never_names_an_attempt_that_released() {
        let fixture = Fixture::new();
        let workspace = fixture.workspace.canonicalize().unwrap();
        let settling = ukai_jail::state::AttemptId::generate();
        let Acquisition::Held(mut held) = state::acquire(&Request {
            data_dir: &fixture.data,
            launch: "keeper",
            workspace: &workspace,
            attempt: settling.as_str(),
        })
        .unwrap() else {
            panic!("the state is free");
        };
        state::hold(&mut held, settling.as_str()).unwrap();
        state::release(
            *held,
            settling.as_str(),
            &[],
            &[],
            Releaser::Supervisor { every_value: true },
        )
        .unwrap();
        // Its supervisor is still settling: its jail.lock is held.
        private_dir(&fixture.data.join("attempts"));
        let attempt_root = fixture.data.join("attempts").join(settling.as_str());
        private_dir(&attempt_root);
        let lock = std::fs::File::create(attempt_root.join("jail.lock")).unwrap();
        std::fs::set_permissions(
            attempt_root.join("jail.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&lock);
        // SAFETY: flock of a descriptor this test owns.
        let locked = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(locked, 0);
        assert!(state::attempt_live(&fixture.data, settling.as_str()));
        // The next holder took the lease and has not recorded itself yet.
        let key = state::key("keeper", workspace.as_os_str().as_bytes());
        let levels = state::open_levels(&fixture.data, "keeper", &key, false)
            .unwrap()
            .unwrap();
        let next = state::take_lease(&levels.key_dir, &levels.path)
            .unwrap()
            .unwrap();
        let Ok(Acquisition::Fallback(fallback)) = try_acquire(&fixture, &workspace) else {
            panic!("the lease is held");
        };
        assert_eq!(fallback.reason, FallbackReason::Held);
        assert_eq!(fallback.held_by, None, "{fallback:?}");
        drop(next);
        drop(lock);
    }

    /// K75: the vendor file a profile discards is named only in data.
    #[test]
    fn k75_no_vendor_file_name_in_the_execution_core() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for krate in ["ukai-jail/src", "ukai-records/src", "ukai-ledger/src"] {
            let mut stack = vec![root.join(krate)];
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if let Ok(text) = std::fs::read_to_string(&path) {
                        assert!(
                            !text.contains(".credentials.json"),
                            "{} names a vendor file",
                            path.display()
                        );
                    }
                }
            }
        }
        let bundled = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/launch/claude.toml"),
        )
        .unwrap();
        assert!(bundled.contains("state = \"persistent\""));
        assert!(bundled.contains("state_discard = [\".credentials.json\"]"));
    }
}
