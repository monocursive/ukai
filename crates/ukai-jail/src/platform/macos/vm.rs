//! The VM tier (J18, jail-macos.md §6): a warm Linux guest per operator,
//! selected with `--vm` before native preparation.
//!
//! What crosses to the guest is fixed (decision D1): the profile (`tool` or
//! `agent`), the wall, the argv, the network shape (tool offline, agent
//! proxied with the canonical allow set) and vault-mode credentials. Every
//! other element of the policy snapshot is compared, before any connection
//! or boot, with the snapshot those inputs alone resolve to on the guest
//! platform; a difference refuses with `vm:not-carried:<field>`
//! ([`policy_refusal`]). The probe answers `available` only for a
//! requirement a measured guest record backs (decision D2,
//! [`GUEST_MEASUREMENTS`]), which today is none, so every `run --vm`
//! refuses at probing until the live phase re-measures the guest.
//!
//! The transport below is tested with stand-ins. Its guest reports are
//! checked for consistency and binding; they are not independent host
//! measurements of guest kernel enforcement. The host supervisor's identity
//! is macOS even though policies resolve for Linux.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Seek as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use sha2::Digest as _;

use crate::capability::{
    Capability, CapabilityScope, CapabilityStatus, REASON_VM_NOT_CARRIED, REASON_VM_NOT_MEASURED,
    REASON_VM_OWNER_LOSS_NOT_PROVIDED, Requirement,
};
use crate::lifecycle::{BoundaryKind, Integrity, VerificationScope};
use crate::platform::{
    BoundaryIdentity, ContinuousDeadline, Deadline, GuestFacts, LimitCause, PlanRequest, Platform,
    PlatformIdentity, PreparedExecution, PreparedPlan, ReleaseFailure, RunEvent, RunningExecution,
    Sinks, StopReason, Teardown, TreeObservation,
};
use crate::policy::{
    CredentialDecl, CredentialMode, EnvironmentSnapshot, FilesystemSnapshot, LaunchSnapshot,
    LimitCeiling, LimitKey, LimitsSnapshot, NetworkSnapshot, ObservationSnapshot, PolicySnapshot,
    ProfileName, Roots,
};
use crate::records::{
    AppliedLimit, ErrorCode, ErrorStage, JailError, NativeLifetime, Os, Remediation, rfc3339_utc,
};

use image::Install;

pub mod control;
pub mod image;
pub mod protocol;
pub mod record;
pub mod share;

/// How long starting `ukai-vm serve` may take before the run refuses: the
/// cold guest boot (EFI, kernel, cloud-init, controller handshake) measured
/// 30-90s on the qualified image; the warm path answers immediately.
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(180);

/// One bounded wait step inside the run loop: long enough not to spin,
/// short enough for the wall deadline to fire between frames.
const POLL_STEP: Duration = Duration::from_secs(1);

/// The file a spawned `ukai-vm serve` writes its standard error to, beneath
/// the VM runtime directory: a serve that exits before it answers is refused
/// with what it said (decision D4).
pub const SERVE_STDERR: &str = "serve.stderr";

/// The most bytes of a dead serve's standard error a refusal quotes.
const SERVE_STDERR_QUOTED: u64 = 2048;

/// Where the guest controller stages a vault credential's value for the
/// guest jail: tmpfs, one file per credential id (`guest.py` `stage_secret`).
pub const GUEST_CREDENTIAL_ROOT: &str = "/run/ukai-vm/credentials";

/// The mechanism an available VM capability names.
const GUEST_MECHANISM: &str = "linux-bwrap-in-vm";

/// The runtime directory beneath the operator's data directory.
#[must_use]
pub fn vm_runtime_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("vm")
}

/// `ukai-jail vm stop`: asks the per-operator `ukai-vm` for an orderly stop.
///
/// A missing `ukai-vm` is not an error (§6.1: the verb reports and exits 0);
/// a peer that answers but fails is.
///
/// # Errors
/// [`JailError`] when a serving `ukai-vm` refused or the exchange failed.
pub fn stop_guest(data_dir: &Path, json: bool) -> Result<String, JailError> {
    let socket = control::control_socket(data_dir);
    match control::control_round_trip(&socket, protocol::ToControl::Stop) {
        Err(control::ControlError::Absent) => Ok("no VM is running".to_owned()),
        Err(control::ControlError::Failed(error)) => Err(JailError::new(
            ErrorCode::BackendUnavailable,
            ErrorStage::Reconciling,
            Remediation::Retry,
            format!("vm stop: {error}"),
        )),
        Ok(protocol::FromControl::Stopping { .. }) => {
            let status = "stopping: the warm guest ends with its service".to_owned();
            if json {
                Ok(format!("{}", serde_json::json!({"vm": "stopping"})))
            } else {
                Ok(status)
            }
        }
        Ok(other) => Err(JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Reconciling,
            Remediation::InspectState,
            format!("vm stop: unexpected reply {other:?}"),
        )),
    }
}

fn refused(message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::UnsupportedPlatform,
        ErrorStage::Preparing,
        Remediation::Unsupported,
        message.into(),
    )
}

fn invalid(message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::InvalidConfig,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message.into(),
    )
}

fn transport(message: impl std::fmt::Display) -> JailError {
    JailError::new(
        ErrorCode::BackendUnavailable,
        ErrorStage::Preparing,
        Remediation::Retry,
        format!("--vm: {message}"),
    )
}

/// The ready frame's facts, kept for the boundary identity and the
/// transport record.
struct ReadyFrame {
    boot_id: String,
    disk_sha256: String,
    helper_sha256: String,
    custodian_sha256: String,
    seed_sha256: String,
    vsock_port: u32,
}

/// The `--vm` platform. It discovers the installed preview (the same paths
/// `install.sh.in` writes, or `UKAI_VM_HOME`), verifies the image against
/// its recorded hashes, and reuses the preview's custodian and VZ client
/// binaries unmodified.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VmPlatform {
    data_dir: PathBuf,
    install: Install,
}

impl VmPlatform {
    /// Discovers and verifies the installation for this operator.
    ///
    /// # Errors
    /// The discovery or verification refusal: a `--vm` run never boots an
    /// image whose bytes do not match `image.json`.
    pub fn new(data_dir: &Path) -> Result<Self, JailError> {
        let install = Install::discover().map_err(|error| invalid(format!("--vm: {error}")))?;
        install
            .verify()
            .map_err(|error| invalid(format!("--vm: {error}")))?;
        Ok(VmPlatform {
            data_dir: data_dir.to_path_buf(),
            install,
        })
    }

    /// The control socket this platform drives.
    #[must_use]
    pub fn control_socket(&self) -> PathBuf {
        control::control_socket(&self.data_dir)
    }

    /// Starts `ukai-vm serve` when no instance answers, waits for the
    /// control socket (§6: "starts the guest on first use"), and checks the
    /// serving instance's status either way (decision D4): it shares exactly
    /// this workspace live, and has its NAT adapter when the policy is
    /// proxied. A listener alone proves nothing: another run may have started
    /// a serve for another tree a moment earlier.
    ///
    /// The binary is this package's `ukai-vm`, found beside this executable
    /// or on `PATH`. The child is detached: its own process group, standard
    /// input and output closed, standard error to [`SERVE_STDERR`] beneath
    /// the VM runtime directory, so an operator interrupt of the run is not
    /// its exit and a serve that dies first is refused with what it said.
    /// Every wait is bounded by [`SERVE_TIMEOUT`] and by `deadline`, the
    /// attempt's preparation budget.
    ///
    /// # Errors
    /// The refusal when no serve answers in time, the spawned one exited, or
    /// the serving instance shares another workspace or lacks the NAT
    /// adapter a proxied policy needs.
    pub fn ensure_serving(
        &self,
        workspace: &Path,
        guest_nat: bool,
        deadline: ContinuousDeadline,
    ) -> Result<(), JailError> {
        self.serve_with(workspace, guest_nat, deadline, || self.serve_binary())
    }

    /// [`VmPlatform::ensure_serving`] with the program to spawn found by
    /// `program`, which runs only when no serve answers yet.
    fn serve_with(
        &self,
        workspace: &Path,
        guest_nat: bool,
        deadline: ContinuousDeadline,
        program: impl FnOnce() -> Result<PathBuf, JailError>,
    ) -> Result<(), JailError> {
        let socket = self.control_socket();
        if !control::is_listening(&socket) {
            self.spawn_serve(&program()?, workspace, guest_nat, deadline)?;
        }
        check_serving(&socket, workspace, guest_nat)
    }

    /// Spawns `program serve` for `workspace` and waits until its control
    /// socket answers, its child exits, or the budget ends.
    fn spawn_serve(
        &self,
        program: &Path,
        workspace: &Path,
        guest_nat: bool,
        deadline: ContinuousDeadline,
    ) -> Result<(), JailError> {
        let runtime = vm_runtime_dir(&self.data_dir);
        std::fs::create_dir_all(&runtime).map_err(|error| {
            refused(format!(
                "--vm: {} cannot be created: {error}",
                runtime.display()
            ))
        })?;
        let stderr_path = runtime.join(SERVE_STDERR);
        let stderr = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&stderr_path)
            .map_err(|error| {
                refused(format!(
                    "--vm: {} cannot be opened: {error}",
                    stderr_path.display()
                ))
            })?;
        let mut command = std::process::Command::new(program);
        command.arg("serve").arg("--live-workspace").arg(workspace);
        if guest_nat {
            command.arg("--guest-nat");
        }
        let mut child = command
            .env("UKAI_VM_HOME", &self.install.root)
            .env("UKAI_DATA_DIR", &self.data_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr.try_clone().map_err(transport)?)
            .process_group(0)
            .spawn()
            .map_err(|error| {
                refused(format!("--vm: {} cannot start: {error}", program.display()))
            })?;
        wait_serving(
            &self.control_socket(),
            &mut child,
            stderr,
            SERVE_TIMEOUT.min(deadline.remaining()),
        )
    }

    fn serve_binary(&self) -> Result<PathBuf, JailError> {
        if let Ok(exe) = std::env::current_exe()
            && let Some(sibling) = exe.parent().map(|parent| parent.join("ukai-vm"))
            && sibling.is_file()
        {
            return Ok(sibling);
        }
        if let Ok(output) = std::process::Command::new("/usr/bin/which")
            .arg("ukai-vm")
            .output()
        {
            let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
            if path.is_file() {
                return Ok(path);
            }
        }
        Err(refused(
            "--vm: no ukai-vm program found beside ukai-jail or on PATH",
        ))
    }
}

/// The capability scope a requirement is measured at, as the native
/// platform spells it.
fn scope_for(requirement: Requirement) -> CapabilityScope {
    match requirement {
        Requirement::SyscallFilter => CapabilityScope::Process,
        _ => CapabilityScope::Tree,
    }
}

/// The serving instance's status must be this run's (decision D4): a live
/// share of exactly `workspace`, and the NAT adapter when the policy is
/// proxied. The same checks for a reused serve and a freshly spawned one.
fn check_serving(socket: &Path, workspace: &Path, guest_nat: bool) -> Result<(), JailError> {
    let status =
        control::control_round_trip(socket, protocol::ToControl::Status).map_err(transport)?;
    let protocol::FromControl::Status {
        live_workspace,
        guest_nat: nat,
        ..
    } = &status
    else {
        return Err(refused(format!(
            "--vm: the serving ukai-vm answered `status` with {status:?}"
        )));
    };
    if guest_nat && !nat {
        return Err(refused(
            "--vm: the running guest was booted without its NAT adapter, so a proxied \
             policy cannot reach the network; stop it with `ukai-vm stop` and rerun",
        ));
    }
    let live = live_workspace.as_deref().ok_or_else(|| {
        refused(
            "--vm: the running guest serves staged attempts, not a live workspace; stop \
             it with `ukai-vm stop` before a --vm run",
        )
    })?;
    let running = std::fs::canonicalize(live)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| live.to_owned());
    let wanted = std::fs::canonicalize(workspace)
        .map(|path| path.display().to_string())
        .map_err(|error| {
            invalid(format!(
                "--vm: {} cannot be resolved: {error}",
                workspace.display()
            ))
        })?;
    if running != wanted {
        return Err(refused(format!(
            "--vm: the running guest shares {running}, not {wanted}; stop it with \
             `ukai-vm stop` or run against that workspace"
        )));
    }
    Ok(())
}

/// Waits, within `budget`, until `socket` has a listener. A child that
/// exits first is refused with the head of what it wrote to `stderr`.
fn wait_serving(
    socket: &Path,
    child: &mut std::process::Child,
    mut stderr: std::fs::File,
    budget: Duration,
) -> Result<(), JailError> {
    let started = Instant::now();
    loop {
        if control::is_listening(socket) {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            let mut said = String::new();
            let _ = stderr.rewind();
            let _ = (&mut stderr)
                .take(SERVE_STDERR_QUOTED)
                .read_to_string(&mut said);
            let said = said.trim();
            return Err(refused(format!(
                "--vm: ukai-vm serve exited ({status}) before it answered on {}{}",
                socket.display(),
                if said.is_empty() {
                    " and wrote nothing to standard error".to_owned()
                } else {
                    format!(": {}", crate::records::escape_control(said))
                }
            )));
        }
        let left = budget.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(refused(format!(
                "--vm: no ukai-vm answered on {} within {}s (the attempt's preparation \
                 budget bounds the wait)",
                socket.display(),
                budget.as_secs()
            )));
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
}

impl Platform for VmPlatform {
    fn state_identity(&self) -> PlatformIdentity {
        // State and the supervisor birth identity belong to the Mac host;
        // policy and receipts retain the guest identity returned below.
        crate::platform::macos::MacosPlatform.identity()
    }

    fn owner_identity(&self) -> Option<crate::platform::OwnerIdentity> {
        crate::platform::macos::owner_identity()
    }

    fn identity(&self) -> PlatformIdentity {
        // The policy resolves for the guest: the profile's baselines, the
        // workspace grants and the limits are the guest jail's, and the
        // receipt this platform stores is a Linux receipt. The kernel string
        // is the guest's only once it has reported one; before that it is a
        // stated unknown, never the Mac host's.
        PlatformIdentity {
            os: Os::Linux,
            arch: "aarch64".to_owned(),
            kernel: "unknown: the guest reports its kernel at prepare".to_owned(),
        }
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        probe_rows(
            &plan.requirements,
            policy_refusal(&plan.snapshot).map(|(reason, _)| reason),
            GUEST_MEASUREMENTS,
        )
    }

    fn prepare(
        &self,
        plan: PreparedPlan,
        sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        VmExecution::prepare(self, plan, sinks).map(|execution| Box::new(execution) as _)
    }
}

// ---------------------------------------------------------------------------
// Decision D2: what the probe may call available
// ---------------------------------------------------------------------------

/// One guest measurement backing an `available` capability row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMeasurement {
    /// The requirement's wire name (`limit:wall`, `network_none`, ...).
    pub requirement: &'static str,
    /// The record that measured it in the guest: a repository path with a
    /// JSON pointer to the verdict.
    pub record: &'static str,
    /// When the measurement ran, RFC 3339 UTC, as the record itself states
    /// it. A record that states no time cannot be listed.
    pub measured_at: &'static str,
}

/// The one table of guest measurements (decision D2): a requirement answers
/// `available` only when a record here measured it inside the guest, through
/// the guest jail command `--vm` issues. Every other requirement answers
/// `unavailable` with `vm:not-measured:<requirement>`. The live phase
/// re-measures the guest and updates this table, and nothing else.
///
/// It is empty. The 2026-11-02 records (`macos-vm-warm-2026-11-02/`) state no
/// time of measurement, and none of their verdicts measured its requirement
/// alone: `wall` cannot tell the guest jail's deadline from the controller's
/// own `wall + 10 s` backstop, `pids` passes whatever the limit, `mem`
/// passes on any OOM kill, `containment` measured writes but not reads, and
/// `network_none`'s TCP half was vacuous (`/dev/tcp` under dash).
pub const GUEST_MEASUREMENTS: &[GuestMeasurement] = &[];

/// The capability rows for `requirements`: the owner-loss row always refuses
/// (K112), a policy `--vm` cannot carry refuses every other row with its
/// reason, and otherwise a row is available exactly when `measured` backs it.
fn probe_rows(
    requirements: &[Requirement],
    refusal: Option<String>,
    measured: &[GuestMeasurement],
) -> Vec<Capability> {
    requirements
        .iter()
        .map(|&requirement| {
            let name = requirement.to_string();
            let unavailable = |reason: String| Capability {
                name: name.clone(),
                status: CapabilityStatus::Unavailable,
                scope: scope_for(requirement),
                mechanism: None,
                reason_code: Some(reason),
                measured_at: None,
                evidence_ref: None,
            };
            // No kernel-bound lifetime exists inside this VM either: the
            // guest's wall is a deadline, not an owner-loss bound. K112: a
            // qualified VM backend must provide one before accepting the
            // key, so it refuses here, before any boot.
            if requirement == Requirement::OwnerLossTermination {
                return unavailable(REASON_VM_OWNER_LOSS_NOT_PROVIDED.to_owned());
            }
            if let Some(reason) = &refusal {
                return unavailable(reason.clone());
            }
            match measured.iter().find(|row| row.requirement == name) {
                Some(row) => Capability {
                    name: name.clone(),
                    status: CapabilityStatus::Available,
                    scope: scope_for(requirement),
                    mechanism: Some(GUEST_MECHANISM.to_owned()),
                    reason_code: Some("ok".to_owned()),
                    measured_at: Some(row.measured_at.to_owned()),
                    evidence_ref: Some(row.record.to_owned()),
                },
                None => unavailable(format!("{REASON_VM_NOT_MEASURED}{name}")),
            }
        })
        .collect()
}

/// One `--vm` attempt between claim and release: the guest has accepted the
/// staging and holds; the jail has not started.
struct VmExecution {
    attempt_dir: PathBuf,
    attempt_id: String,
    connection: control::AttemptConnection,
    sockets: (PathBuf, PathBuf),
    boot_id: String,
    guest_kernel: String,
    image: record::ImageDigests,
    vsock_port: u32,
    started: Instant,
    started_wall: String,
    profile: String,
    argv_digest: String,
    limits: LimitsSnapshot,
    network: image::GuestNetwork,
    stdout: std::fs::File,
    stderr: std::fs::File,
}

impl VmExecution {
    fn prepare(
        platform: &VmPlatform,
        plan: PreparedPlan,
        _sinks: Sinks,
    ) -> Result<Self, JailError> {
        // Everything that can refuse without the guest refuses first, before
        // any connection or boot (decisions D1, D3): the carry rule, the
        // vault hand-off, then the share's containment preflight, which is
        // a host-side fact (measured 2026-11-02: symlinks stay guest-side,
        // but a pre-existing hardlink writes through and a case-folding
        // volume bypasses every guest denial).
        let snapshot = &plan.request.snapshot;
        validate_policy(snapshot)?;
        let wall = guest_wall(snapshot)?;
        let profile = snapshot.profile.as_str().to_owned();
        let (launch, vault_secrets) = vault_launch(&plan)?;
        let allow_hosts = guest_allow_hosts(&snapshot.network);
        let network = image::GuestNetwork::requested(
            snapshot.network.mode.as_str(),
            snapshot.network.allow.iter().cloned(),
            snapshot.network.tls_only.iter().cloned(),
        );
        let share_facts = share::preflight(&plan.workspace).map_err(refused)?;
        let proxied = snapshot.network.mode == crate::network::NetworkMode::Proxy;
        platform.ensure_serving(&plan.workspace, proxied, plan.prepare_deadline)?;
        let socket = control::attempt_socket(&platform.data_dir);
        let mut connection = control::AttemptConnection::connect(&socket).map_err(transport)?;
        let ready = expect_ready(&mut connection, plan.prepare_deadline)?;
        verify_ready(&ready, &platform.install.manifest)?;
        let staged = protocol::ToVm::Prepare {
            attempt_id: plan.attempt_id.clone(),
            profile: profile.clone(),
            wall_seconds: wall,
            argv: plan
                .argv
                .iter()
                .map(|argument| protocol::encode_data(argument))
                .collect(),
            secrets: vault_secrets,
            allow_hosts,
            launch,
        };
        connection.send(&staged).map_err(transport)?;
        let guest_kernel = expect_prepared(&mut connection, plan.prepare_deadline)?;
        // Live share: the workspace crosses as the virtio-fs device the
        // service attached; staging puts are refused by both ends, so none
        // are sent. The share's facts travel in the transport record below.
        debug_assert!(!share_facts.case_fold);
        for group in ["workspace", "evidence"] {
            std::fs::create_dir(plan.attempt_dir.join(group)).map_err(transport)?;
        }
        let stdout = duplicate_output(libc::STDOUT_FILENO)?;
        let stderr = duplicate_output(libc::STDERR_FILENO)?;
        Ok(VmExecution {
            attempt_dir: plan.attempt_dir,
            attempt_id: plan.attempt_id,
            connection,
            sockets: (
                control::control_socket(&platform.data_dir),
                control::attempt_socket(&platform.data_dir),
            ),
            boot_id: ready.boot_id,
            guest_kernel,
            image: record::ImageDigests {
                disk_sha256: platform.install.manifest.disk_sha256.clone(),
                helper_sha256: platform.install.manifest.helper_sha256.clone(),
                custodian_sha256: platform.install.manifest.custodian_sha256.clone(),
                seed_sha256: platform.install.manifest.seed_sha256.clone(),
            },
            vsock_port: ready.vsock_port,
            started: Instant::now(),
            started_wall: rfc3339_utc(SystemTime::now()),
            profile,
            argv_digest: crate::canonical::argv_digest(&plan.argv),
            limits: snapshot.limits.clone(),
            network,
            stdout,
            stderr,
        })
    }
}

// ---------------------------------------------------------------------------
// Decision D1: what `--vm` carries
// ---------------------------------------------------------------------------

/// The ceilings the guest controller adds to every guest jail run
/// (`guest.py` `run_command`: `--limit mem=512MiB --limit swap=0 --limit
/// pids=64`), in the snapshot's units.
pub const GUEST_FIXED_LIMITS: [(LimitKey, u64); 3] = [
    (LimitKey::Pids, 64),
    (LimitKey::Mem, 512 * 1024 * 1024),
    (LimitKey::Swap, 0),
];

/// The values the guest jail's environment gives the contained baseline's
/// admitted names (`guest.py` `attempt_environment`): `LANG=C.UTF-8`, and
/// neither `TERM` nor `TZ`.
pub const GUEST_ADMITTED_ENVIRONMENT: [(&str, &str); 1] = [("LANG", "C.UTF-8")];

/// One snapshot element `--vm` does not carry: its key path, and what the
/// guest jail would do instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotCarried {
    /// The key path, as the snapshot spells it (`filesystem.deny_read`).
    pub field: String,
    /// Why, for the prepare-time refusal.
    pub detail: String,
}

impl NotCarried {
    fn new(field: impl Into<String>, detail: impl Into<String>) -> Self {
        NotCarried {
            field: field.into(),
            detail: detail.into(),
        }
    }

    /// `vm:not-carried:<field>`, in the reason-code alphabet: lower case,
    /// anything else as `-`.
    #[must_use]
    pub fn reason(&self) -> String {
        let mut reason = REASON_VM_NOT_CARRIED.to_owned();
        reason.extend(self.field.chars().map(|character| {
            let lower = character.to_ascii_lowercase();
            if lower.is_ascii_lowercase() || lower.is_ascii_digit() || "_.:-".contains(lower) {
                lower
            } else {
                '-'
            }
        }));
        reason
    }

    fn message(&self) -> String {
        format!(
            "--vm does not carry `{}` to the guest jail: {}; nothing was staged and no guest \
             was contacted ({})",
            self.field,
            self.detail,
            self.reason()
        )
    }
}

/// `Err` naming `field` unless `same`.
fn carried(
    field: impl Into<String>,
    same: bool,
    detail: impl Into<String>,
) -> Result<(), NotCarried> {
    if same {
        Ok(())
    } else {
        Err(NotCarried::new(field, detail))
    }
}

/// A short remedy for a `vm:not-carried:<field>` refusal, for the probing
/// message, which carries only the reason code.
#[must_use]
pub fn not_carried_hint(field: &str) -> Option<&'static str> {
    Some(match field {
        "limits.wall" => {
            "the guest takes an explicit whole-second wall of 1 to 300 seconds \
             (`--limit wall=<seconds>s`)"
        }
        "limits.pids" | "limits.mem" | "limits.swap" => {
            "the guest applies pids=64, mem=512MiB and swap=0: a required ceiling must equal \
             that value, and a preferred one may not be stricter"
        }
        "limits.storage" | "limits.inodes" | "limits.cpu" => {
            "the guest jail applies no such ceiling"
        }
        "environment.bindings" => {
            "the guest jail's environment admits LANG=C.UTF-8 only (unset TERM and TZ, set \
             LANG=C.UTF-8) and carries no launch-profile environment"
        }
        "terminal" => "run with `--terminal detach`",
        _ if field.starts_with("filesystem.") => {
            "the guest jail applies the profile's baseline filesystem rules only"
        }
        _ if field.starts_with("launch.") => {
            "only vault credentials cross to the guest, without executable bindings or refresh"
        }
        _ => return None,
    })
}

/// Why `--vm` refuses `snapshot` before any connection or boot, as the
/// probe's reason code and the prepare-time message, or `None` when the
/// guest jail would apply exactly this snapshot (decision D1).
fn policy_refusal(snapshot: &PolicySnapshot) -> Option<(String, String)> {
    match snapshot.profile {
        ProfileName::Tool | ProfileName::Agent => {}
        ProfileName::Build => {
            return Some((
                "vm:build-profile-refuses-the-live-share".to_owned(),
                "--vm: the build profile treats the workspace as a disposable copy with no \
                 protected segments, and a live share is the operator's real directory \
                 (measured: the operator's .git was writable through it); use --profile tool"
                    .to_owned(),
            ));
        }
        ProfileName::None => {
            return Some((
                "vm:profile-unsupported:tool-and-agent-only".to_owned(),
                "--vm: profile none is unsupported; the guest jail takes `tool` or `agent`"
                    .to_owned(),
            ));
        }
    }
    not_carried(snapshot).map(|refusal| (refusal.reason(), refusal.message()))
}

/// The first element of `snapshot` the guest jail would not apply as the
/// snapshot says, or `None` (decision D1): the launch group's own rule, then
/// a comparison with the snapshot the carried inputs alone resolve to.
#[must_use]
pub fn not_carried(snapshot: &PolicySnapshot) -> Option<NotCarried> {
    // A staged mode is the most specific refusal, and the carried shape
    // below takes only what the guest declaration can carry.
    if let Err(refusal) = carried_launch(snapshot.launch.as_ref()) {
        return Some(refusal);
    }
    match carried_shape(snapshot) {
        Ok(expected) => compare_carried(snapshot, &expected).err(),
        Err(error) => Some(NotCarried::new(
            "policy",
            format!("the carried inputs alone do not resolve: {error}"),
        )),
    }
}

/// The snapshot the guest jail resolves from what `--vm` carries and
/// nothing else: the profile's baseline on the guest platform with the
/// guest's environment, the workspace the share mounts, the allow set as it
/// is spelled on the wire, and the generated declaration of the vault
/// credentials. Limits are compared separately ([`carried_limits`]), with
/// the guest's fixed shape.
fn carried_shape(snapshot: &PolicySnapshot) -> Result<PolicySnapshot, String> {
    use crate::policy::{Layer, LayerOrigin, PolicyDelta, ResolveInputs, ScratchRoot};
    let lookup = |name: &str| {
        GUEST_ADMITTED_ENVIRONMENT
            .iter()
            .find(|(admitted, _)| *admitted == name)
            .map(|(_, value)| value.as_bytes().to_vec())
    };
    let baseline = crate::profiles::baseline(snapshot.profile, snapshot.platform, &lookup);
    let allow = guest_allow_hosts(&snapshot.network);
    let layers = if allow.is_empty() {
        Vec::new()
    } else {
        vec![Layer {
            origin: LayerOrigin::CommandLine,
            base_dir: None,
            delta: PolicyDelta {
                network_allow: allow,
                ..PolicyDelta::default()
            },
        }]
    };
    let inputs = ResolveInputs {
        platform: snapshot.platform,
        base_profile: snapshot.profile,
        policy_name: snapshot.profile.as_str().to_owned(),
        baseline,
        workspace: snapshot.roots.workspace.as_bytes().to_vec(),
        scratch: ScratchRoot::Managed,
        vendor_state: None,
        operator_home: None,
        translation_prefixes: Vec::new(),
        layers,
    };
    let mut resolved = crate::policy::resolve(&inputs).map_err(|error| error.message)?;
    if let Some(launch) = guest_launch_profile(snapshot) {
        resolved =
            crate::launch_profile::apply(resolved, &launch).map_err(|error| error.message)?;
    }
    Ok(resolved.snapshot)
}

/// The launch profile the guest's generated declaration
/// ([`guest_launch_toml`]) parses to, with the host's credential sources:
/// the vault credentials and nothing else. `None` without credentials: no
/// declaration crosses then.
fn guest_launch_profile(snapshot: &PolicySnapshot) -> Option<crate::launch_profile::LaunchProfile> {
    let launch = snapshot
        .launch
        .as_ref()
        .filter(|launch| !launch.credentials.is_empty())?;
    Some(crate::launch_profile::LaunchProfile {
        name: "vm".to_owned(),
        source: crate::launch_profile::LaunchSource::Bundled,
        bundles: Vec::new(),
        filesystem: crate::config::FilesystemSection::default(),
        jail: snapshot.profile,
        state_var: None,
        home_is_state: false,
        state_subdirs: Vec::new(),
        state: crate::launch_profile::StateKind::Attempt,
        state_discard: Vec::new(),
        environment: Vec::new(),
        credentials: launch
            .credentials
            .iter()
            .filter(|credential| credential.mode == CredentialMode::Vault)
            .cloned()
            .collect(),
        network_allow: Vec::new(),
        program_root: crate::launch_profile::PROGRAM_ROOT_DEFAULT,
        credentials_one_of: Vec::new(),
        hints: BTreeMap::new(),
    })
}

/// The launch group's rule: only vault credentials cross, without
/// executable bindings or refresh, and no vendor-state shape of its own.
fn carried_launch(launch: Option<&LaunchSnapshot>) -> Result<(), NotCarried> {
    let Some(LaunchSnapshot {
        state_var,
        home_is_state,
        state_subdirs,
        credentials,
        state_discard,
    }) = launch
    else {
        return Ok(());
    };
    let declaration = "the guest's generated launch declaration carries vault credentials only";
    carried(
        "launch.state_discard",
        state_discard.is_none(),
        "persistent vendor state stays on the host; the guest's is attempt-private",
    )?;
    carried("launch.state_var", state_var.is_none(), declaration)?;
    carried("launch.home_is_state", !*home_is_state, declaration)?;
    carried(
        "launch.state_subdirs",
        state_subdirs.is_empty(),
        declaration,
    )?;
    for credential in credentials {
        let CredentialDecl {
            vault,
            id,
            source: _,
            dest: _,
            mode,
        } = credential;
        let key = format!("launch.credentials.{id}");
        if *mode != CredentialMode::Vault {
            return Err(NotCarried::new(
                format!("{key}.mode"),
                format!(
                    "credential `{id}` uses staged mode `{}`, which would write the value into \
                     the guest's vendor state; only vault mode crosses (the guest proxy \
                     injects the value, and nothing is staged)",
                    mode.as_str()
                ),
            ));
        }
        let Some(policy) = vault else {
            return Err(NotCarried::new(
                format!("{key}.vault"),
                "a vault credential without its policy",
            ));
        };
        let crate::vault::Policy {
            hosts: _,
            allow_plaintext: _,
            header: _,
            paths: _,
            binaries,
            refresh,
            env: _,
        } = policy;
        carried(
            format!("{key}.vault.binaries"),
            binaries.is_empty(),
            "executable bindings pin host files the guest does not have",
        )?;
        carried(
            format!("{key}.vault.refresh"),
            refresh.is_none(),
            "a refresh would rotate the token inside the guest, and the rotated token would \
             never reach the host's source",
        )?;
    }
    Ok(())
}

/// Compares `host` with its carried shape `expected`. Every field is named,
/// so a new snapshot field does not compile until this says whether `--vm`
/// carries it; the first difference is the refusal.
fn compare_carried(host: &PolicySnapshot, expected: &PolicySnapshot) -> Result<(), NotCarried> {
    let PolicySnapshot {
        commands,
        schema,
        profile,
        profile_version,
        platform,
        roots,
        filesystem,
        network,
        limits,
        observation,
        environment,
        launch,
        terminal,
        lifetime_boundary,
    } = host;
    carried(
        "terminal",
        terminal.is_none(),
        "an attached terminal is not relayed into the guest",
    )?;
    carried(
        "lifetime_boundary",
        lifetime_boundary.is_none(),
        "the guest's wall is a deadline, not an owner-loss bound",
    )?;
    carried(
        "commands",
        commands.is_empty(),
        "the guest jail checks no command rules",
    )?;
    let Roots {
        workspace,
        scratch,
        vendor_state,
        cwd,
    } = roots;
    carried(
        "roots.workspace",
        *workspace == expected.roots.workspace,
        "the share mounts the workspace root",
    )?;
    carried(
        "roots.scratch",
        *scratch == expected.roots.scratch,
        "the guest jail uses its own managed scratch",
    )?;
    carried(
        "roots.vendor_state",
        *vendor_state == expected.roots.vendor_state,
        "the guest's vendor state is attempt-private; persistent state stays on the host",
    )?;
    carried(
        "roots.cwd",
        *cwd == expected.roots.cwd,
        "the guest jail starts in the workspace root",
    )?;
    let FilesystemSnapshot {
        read_write,
        read_only,
        deny_read,
        protected_segments,
        protected_coverage,
    } = filesystem;
    let baseline_only = "the guest jail applies the profile's baseline only";
    carried(
        "filesystem.deny_read",
        *deny_read == expected.filesystem.deny_read,
        "the guest jail denies no read its baseline does not, so the denial would be dropped",
    )?;
    carried(
        "filesystem.read_write",
        *read_write == expected.filesystem.read_write,
        baseline_only,
    )?;
    carried(
        "filesystem.read_only",
        *read_only == expected.filesystem.read_only,
        baseline_only,
    )?;
    carried(
        "filesystem.protected_segments",
        *protected_segments == expected.filesystem.protected_segments,
        baseline_only,
    )?;
    carried(
        "filesystem.protected_coverage",
        *protected_coverage == expected.filesystem.protected_coverage,
        baseline_only,
    )?;
    let NetworkSnapshot {
        mode,
        allow,
        tls_only,
        ruleset,
        translation_prefixes,
    } = network;
    carried(
        "network.mode",
        *mode == expected.network.mode,
        "tool runs offline and agent runs its own proxy in the guest",
    )?;
    let respelled = "the allow set does not re-parse to the same rules in the guest";
    carried("network.allow", *allow == expected.network.allow, respelled)?;
    carried(
        "network.tls_only",
        *tls_only == expected.network.tls_only,
        respelled,
    )?;
    carried(
        "network.ruleset",
        *ruleset == expected.network.ruleset,
        respelled,
    )?;
    carried(
        "network.translation_prefixes",
        *translation_prefixes == expected.network.translation_prefixes,
        "the guest's host manifest configures no NAT64 prefixes",
    )?;
    carried_limits(limits)?;
    let ObservationSnapshot {
        learning,
        mode: observe,
        evidence,
    } = observation;
    let observed = "the guest jail observes with its profile's baseline";
    carried(
        "observation.learning",
        *learning == expected.observation.learning,
        observed,
    )?;
    carried(
        "observation.mode",
        *observe == expected.observation.mode,
        observed,
    )?;
    carried(
        "observation.evidence",
        *evidence == expected.observation.evidence,
        observed,
    )?;
    let EnvironmentSnapshot {
        inherit_host,
        bindings,
    } = environment;
    carried(
        "environment.inherit_host",
        *inherit_host == expected.environment.inherit_host,
        "the guest jail's environment is contained",
    )?;
    if *bindings != expected.environment.bindings {
        let theirs: BTreeSet<_> = expected.environment.bindings.iter().collect();
        let names: BTreeSet<&str> = bindings
            .iter()
            .collect::<BTreeSet<_>>()
            .symmetric_difference(&theirs)
            .map(|binding| binding.name.as_str())
            .collect();
        return Err(NotCarried::new(
            "environment.bindings",
            format!(
                "the guest jail's environment differs at {}: it admits LANG=C.UTF-8 only and \
                 carries no launch-profile environment",
                names.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    carried(
        "launch",
        *launch == expected.launch,
        "the guest's generated launch declaration resolves differently",
    )?;
    let fixed = "fixed by the carried inputs";
    carried("schema", *schema == expected.schema, fixed)?;
    carried("profile", *profile == expected.profile, fixed)?;
    carried(
        "profile_version",
        *profile_version == expected.profile_version,
        fixed,
    )?;
    carried("platform", *platform == expected.platform, fixed)?;
    Ok(())
}

/// The ceiling the guest controller adds for `key`, if it adds one.
fn guest_fixed_limit(key: LimitKey) -> Option<u64> {
    GUEST_FIXED_LIMITS
        .iter()
        .find(|(fixed, _)| *fixed == key)
        .map(|(_, value)| *value)
}

/// The limits rule of decision D1: the wall crosses, the guest adds its
/// fixed pids, mem and swap ceilings (honouring a ceiling that equals one,
/// or a preferred ceiling it is stricter than), and applies nothing else.
fn carried_limits(limits: &LimitsSnapshot) -> Result<(), NotCarried> {
    let LimitsSnapshot {
        wall,
        pids,
        mem,
        swap,
        storage,
        inodes,
        cpu,
    } = limits;
    wall_seconds(wall.as_ref()).map_err(|detail| NotCarried::new("limits.wall", detail))?;
    for (key, ceiling) in [
        (LimitKey::Pids, pids),
        (LimitKey::Mem, mem),
        (LimitKey::Swap, swap),
    ] {
        let Some(ceiling) = ceiling else { continue };
        let field = format!("limits.{}", key.as_str());
        let guest = guest_fixed_limit(key).unwrap_or_default();
        let Some(requested) = parse_size(&ceiling.value) else {
            return Err(NotCarried::new(
                field,
                format!("`{}` is not a number", ceiling.value),
            ));
        };
        if ceiling.required && requested != guest {
            return Err(NotCarried::new(
                field,
                format!(
                    "the guest applies {}={guest}, so the required {requested} would not be \
                     applied as asked",
                    key.as_str()
                ),
            ));
        }
        if guest > requested {
            return Err(NotCarried::new(
                field,
                format!(
                    "the guest applies {}={guest}, looser than the {requested} the policy asks for",
                    key.as_str()
                ),
            ));
        }
    }
    for (key, ceiling) in [
        (LimitKey::Storage, storage),
        (LimitKey::Inodes, inodes),
        (LimitKey::Cpu, cpu),
    ] {
        carried(
            format!("limits.{}", key.as_str()),
            ceiling.is_none(),
            format!("the guest jail applies no {} ceiling", key.as_str()),
        )?;
    }
    Ok(())
}

/// The guest wall in whole seconds, 1..=[`protocol::WALL_MAX`], from the
/// policy's ceiling (milliseconds): the guest grammar takes nothing else.
fn wall_seconds(wall: Option<&LimitCeiling>) -> Result<u32, String> {
    let wall_ms: u64 = wall
        .and_then(|wall| wall.value.parse().ok())
        .ok_or_else(|| {
            "the policy sets no wall ceiling; the guest grammar needs one \
             (`--limit wall=<seconds>s`)"
                .to_owned()
        })?;
    let seconds = wall_ms / 1000;
    if !wall_ms.is_multiple_of(1000) || seconds == 0 || seconds > u64::from(protocol::WALL_MAX) {
        return Err(format!(
            "the guest grammar takes a wall of 1..={} whole seconds, the policy asks for \
             {wall_ms}ms; set an explicit whole-second ceiling (`--limit wall=<seconds>s`)",
            protocol::WALL_MAX
        ));
    }
    u32::try_from(seconds).map_err(|_| format!("{seconds}s is not a guest wall"))
}

/// [`wall_seconds`] of the snapshot, as the prepare-time refusal.
fn guest_wall(snapshot: &PolicySnapshot) -> Result<u32, JailError> {
    wall_seconds(snapshot.limits.wall.as_ref()).map_err(|detail| refused(format!("--vm: {detail}")))
}

/// The allow rules as they cross to the guest, one `--allow-host` each, in
/// the snapshot's order: the canonical rule, or for a TLS-only rule (every
/// grant of it omitted its port, so `tls_only` lists it) the rule without its
/// `:443`, so the guest's grammar records it TLS-only too. The canonical
/// spelling alone would admit plaintext HTTP in the guest (network-rules.md,
/// audit 2026-10-08 L21). [`not_carried`] re-resolves exactly these
/// spellings, so one that parses differently refuses before anything
/// crosses.
fn guest_allow_hosts(network: &NetworkSnapshot) -> Vec<String> {
    network
        .allow
        .iter()
        .map(|rule| {
            if network.tls_only.contains(rule) {
                rule.strip_suffix(":443").unwrap_or(rule).to_owned()
            } else {
                rule.clone()
            }
        })
        .collect()
}

/// The prepare-time form of [`policy_refusal`]: the same rule, refused with
/// its full message, before any connection or boot.
fn validate_policy(snapshot: &PolicySnapshot) -> Result<(), JailError> {
    match policy_refusal(snapshot) {
        Some((_, message)) => Err(refused(message)),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Decision D3: the vault hand-off
// ---------------------------------------------------------------------------

/// The vaulted launch of one `--vm` attempt (decision D3): the guest's launch
/// declaration, generated from the snapshot's `launch` group
/// ([`guest_launch_toml`]), and each value from the secret the supervisor
/// staged and validated for it (`PreparedPlan::launch`: a private,
/// no-follow source outside every child-writable grant). Nothing is read
/// from disk here, and every refusal comes before any connection or boot.
fn vault_launch(
    plan: &PreparedPlan,
) -> Result<
    (
        Option<protocol::LaunchDeclaration>,
        Vec<protocol::SecretEntry>,
    ),
    JailError,
> {
    let staged: &[std::sync::Arc<crate::vault::Secret>] = plan
        .launch
        .as_ref()
        .map_or(&[], |handoff| handoff.vault.as_slice());
    if plan
        .launch
        .as_ref()
        .is_some_and(|handoff| !handoff.binds.is_empty())
    {
        return Err(refused(
            "--vm: the supervisor staged read-only credential binds, which never cross to \
             the guest",
        ));
    }
    let Some(launch) = plan
        .request
        .snapshot
        .launch
        .as_ref()
        .filter(|launch| !launch.credentials.is_empty())
    else {
        if let Some(secret) = staged.first() {
            return Err(invalid(format!(
                "--vm: vault secret `{}` was staged for a policy that declares no credentials",
                secret.id
            )));
        }
        return Ok((None, Vec::new()));
    };
    let name = plan
        .launch_name
        .as_deref()
        .filter(|name| crate::launch_profile::valid_name(name))
        .ok_or_else(|| {
            invalid("--vm: the policy declares credentials without a valid launch profile name")
        })?;
    let toml = guest_launch_toml(name, plan.request.snapshot.profile, launch)?;
    let mut secrets = Vec::with_capacity(launch.credentials.len());
    for credential in &launch.credentials {
        let secret = staged
            .iter()
            .find(|secret| secret.id == credential.id)
            .ok_or_else(|| {
                refused(format!(
                    "--vm: vault credential `{}` has no value the supervisor staged; the VM \
                     tier reads no credential source itself",
                    credential.id
                ))
            })?;
        let (values, complete) = secret.loaded_values();
        let ([value], true) = (values.as_slice(), complete) else {
            return Err(refused(format!(
                "--vm: vault credential `{}` holds {} loaded values; exactly the one staged \
                 value crosses",
                credential.id,
                values.len()
            )));
        };
        secrets.push(protocol::SecretEntry {
            id: credential.id.clone(),
            data: protocol::encode_data(value),
        });
    }
    if let Some(extra) = staged.iter().find(|secret| {
        !launch
            .credentials
            .iter()
            .any(|credential| credential.id == secret.id)
    }) {
        return Err(invalid(format!(
            "--vm: vault secret `{}` was staged but the policy does not declare it",
            extra.id
        )));
    }
    Ok((
        Some(protocol::LaunchDeclaration {
            name: name.to_owned(),
            toml,
        }),
        secrets,
    ))
}

/// The guest's launch declaration for `launch` (decision D3): `name`, the
/// guest profile, and each vault credential with its policy and its source
/// at the guest's tmpfs staging path ([`GUEST_CREDENTIAL_ROOT`]), in the
/// grammar the guest jail's loader parses. The text is parsed back with that
/// same loader before it is sent and must reproduce the snapshot's credential
/// declarations exactly, but for the source.
fn guest_launch_toml(
    name: &str,
    profile: ProfileName,
    launch: &LaunchSnapshot,
) -> Result<String, JailError> {
    #[derive(serde::Serialize)]
    struct File<'a> {
        name: &'a str,
        jail: &'a str,
        credentials: BTreeMap<&'a str, Credential<'a>>,
    }
    #[derive(serde::Serialize)]
    struct Credential<'a> {
        mode: &'static str,
        source: String,
        hosts: &'a [String],
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        allow_plaintext: bool,
        #[serde(skip_serializing_if = "no_paths")]
        paths: &'a [String],
        #[serde(skip_serializing_if = "Option::is_none")]
        env: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        header: Option<Header<'a>>,
    }
    #[derive(serde::Serialize)]
    struct Header<'a> {
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<&'a str>,
    }
    fn no_paths(paths: &&[String]) -> bool {
        paths.is_empty()
    }
    let refuse = |what: String| {
        refused(format!(
            "--vm: the guest launch declaration cannot carry {what}"
        ))
    };
    let staged_source = |id: &str| format!("{GUEST_CREDENTIAL_ROOT}/{id}");
    let mut credentials = BTreeMap::new();
    for credential in &launch.credentials {
        let Some(policy) = credential
            .vault
            .as_ref()
            .filter(|_| credential.mode == CredentialMode::Vault)
        else {
            return Err(refuse(format!(
                "the {} credential `{}`",
                credential.mode.as_str(),
                credential.id
            )));
        };
        let crate::vault::Policy {
            hosts,
            allow_plaintext,
            header,
            paths,
            binaries,
            refresh,
            env,
        } = policy;
        if !binaries.is_empty() || refresh.is_some() {
            return Err(refuse(format!(
                "the executable bindings or refresh of `{}`",
                credential.id
            )));
        }
        credentials.insert(
            credential.id.as_str(),
            Credential {
                mode: CredentialMode::Vault.as_str(),
                source: staged_source(&credential.id),
                hosts,
                allow_plaintext: *allow_plaintext,
                paths,
                env: env.as_deref(),
                header: header.as_ref().map(|header| Header {
                    name: &header.name,
                    prefix: header.prefix.as_deref(),
                }),
            },
        );
    }
    let text = toml::to_string(&File {
        name,
        jail: profile.as_str(),
        credentials,
    })
    .map_err(|error| refuse(format!("its credentials ({error})")))?;
    // The guest jail's loader is this one: what it reads back must be what
    // the snapshot declares, but for the staged source.
    let parsed = crate::launch_profile::parse(
        &text,
        name,
        crate::launch_profile::LaunchSource::Bundled,
        None,
    )
    .map_err(|error| refuse(format!("a declaration its loader accepts ({error})")))?;
    let declared: Vec<CredentialDecl> = launch
        .credentials
        .iter()
        .map(|credential| CredentialDecl {
            source: crate::records::NativeString::Text(staged_source(&credential.id)),
            ..credential.clone()
        })
        .collect();
    if parsed.credentials != declared
        || parsed.jail != profile
        || parsed.state_var.is_some()
        || parsed.home_is_state
        || !parsed.state_subdirs.is_empty()
        || !parsed.environment.is_empty()
        || !parsed.network_allow.is_empty()
    {
        return Err(refuse(
            "the snapshot's credentials exactly: its loader reads the generated text back \
             differently"
                .to_owned(),
        ));
    }
    Ok(text)
}

/// Parses a size or count ceiling ("64", "256", "512MiB", "1g", "0") to its
/// plain number; `None` when the spelling is not one.
fn parse_size(value: &str) -> Option<u64> {
    let text = value.trim();
    let split = text
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number.trim().parse().ok()?;
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => return None,
    };
    number.checked_mul(multiplier)
}

fn duplicate_output(fd: libc::c_int) -> Result<std::fs::File, JailError> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: fcntl duplicates the caller's output before the supervisor redirects it.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(transport(std::io::Error::last_os_error()));
    }
    // SAFETY: the duplicate is newly owned.
    Ok(unsafe { std::fs::File::from_raw_fd(copy) })
}

fn verify_ready(ready: &ReadyFrame, manifest: &image::ImageManifest) -> Result<(), JailError> {
    if ready.boot_id.is_empty()
        || ready.disk_sha256 != manifest.disk_sha256
        || ready.helper_sha256 != manifest.helper_sha256
        || ready.custodian_sha256 != manifest.custodian_sha256
        || ready.seed_sha256 != manifest.seed_sha256
        || ready.vsock_port != 1024
    {
        return Err(refused(
            "--vm: ready does not match the host-verified installation",
        ));
    }
    Ok(())
}

fn verify_applied_limits(
    receipt: &Value,
    expected: &crate::policy::LimitsSnapshot,
) -> Result<(), String> {
    let rows: Vec<AppliedLimit> = serde_json::from_value(
        receipt
            .pointer("/applied/limits")
            .cloned()
            .ok_or("missing applied limits")?,
    )
    .map_err(|e| e.to_string())?;
    let expected = serde_json::to_value(expected).map_err(|e| e.to_string())?;
    let expected = expected.as_object().ok_or("invalid expected limits")?;
    if rows.is_empty() {
        return Err("the guest receipt reports no applied limits".to_owned());
    }
    // Subset with preferred semantics: a REQUIRED ceiling must be applied
    // with the requested value (wall). A PREFERRED ceiling is satisfied by
    // a guest row at least as strict (the tool baseline's pids=256 against
    // the guest's applied 64), matching how macOS records a preferred
    // ceiling the platform cannot apply exactly. The guest's additional
    // fixed limits are more enforcement, never less.
    for (key, ceiling) in expected.iter().filter(|(_, v)| !v.is_null()) {
        let required = ceiling["required"].as_bool().unwrap_or(false);
        let value = ceiling["value"].as_str().unwrap_or_default();
        let matching: Vec<_> = rows.iter().filter(|row| &row.key == key).collect();
        if matching.len() != 1 || !matching[0].applied {
            return Err(format!("guest did not apply the requested {key} ceiling"));
        }
        let row = &matching[0];
        if required {
            let same = row.requested == value
                || parse_size(&row.requested)
                    .zip(parse_size(value))
                    .is_some_and(|(a, b)| a == b);
            if !same {
                return Err(format!(
                    "guest applied {key}={}; the required ceiling is {value}",
                    row.requested
                ));
            }
        } else {
            let stricter = parse_size(&row.requested)
                .zip(parse_size(value))
                .is_some_and(|(applied, requested)| applied <= requested);
            if !stricter {
                return Err(format!(
                    "guest applied {key}={}, looser than the preferred {value}",
                    row.requested
                ));
            }
        }
    }
    Ok(())
}

/// The facts the verified guest receipt reports the guest jail applied, in
/// the host receipt's own types (decision D5), with the native details that
/// name the guest receipt they came from. A receipt whose groups do not read
/// as those types is refused like any other unverifiable one.
fn guest_facts(receipt: &Value, sha256: &str) -> Result<GuestFacts, String> {
    fn group<T: serde::de::DeserializeOwned>(receipt: &Value, pointer: &str) -> Result<T, String> {
        let value = receipt
            .pointer(pointer)
            .cloned()
            .ok_or_else(|| format!("the guest receipt has no {pointer}"))?;
        serde_json::from_value(value)
            .map_err(|error| format!("the guest receipt's {pointer} does not read: {error}"))
    }
    let mut details = serde_json::Map::new();
    details.insert(
        "guest_receipt".to_owned(),
        Value::String("evidence/jail.json".to_owned()),
    );
    details.insert(
        "guest_receipt_sha256".to_owned(),
        Value::String(format!("sha256:{sha256}")),
    );
    details.insert(
        "guest_carried".to_owned(),
        Value::from(GuestFacts::CARRIED.to_vec()),
    );
    Ok(GuestFacts {
        kernel: group(receipt, "/platform/kernel")?,
        arch: group(receipt, "/platform/arch")?,
        exec_observed: group(receipt, "/exec_observed")?,
        applied: group(receipt, "/applied")?,
        observer: group(receipt, "/observer")?,
        coverage: group(receipt, "/coverage")?,
        details,
    })
}

fn expect_ready(
    connection: &mut control::AttemptConnection,
    deadline: ContinuousDeadline,
) -> Result<ReadyFrame, JailError> {
    // The service binds its sockets before the guest finishes booting, so
    // the first frame can legally wait out a cold boot (measured 30-90s on
    // the qualified image); every later exchange stays on the short
    // handshake budget. Both are bounded by what is left of the attempt's
    // preparation budget (decision D4).
    match connection
        .next_frame_within(SERVE_TIMEOUT.min(deadline.remaining()))
        .map_err(transport)?
    {
        control::Within::Frame(protocol::FromVm::Ready {
            schema,
            boot_id,
            disk_sha256,
            helper_sha256,
            custodian_sha256,
            seed_sha256,
            vsock_port,
        }) => {
            if schema != protocol::SCHEMA_ATTEMPT {
                return Err(refused(format!(
                    "--vm: the attempt socket speaks {schema}, not {}",
                    protocol::SCHEMA_ATTEMPT
                )));
            }
            Ok(ReadyFrame {
                boot_id,
                disk_sha256,
                helper_sha256,
                custodian_sha256,
                seed_sha256,
                vsock_port,
            })
        }
        control::Within::Frame(protocol::FromVm::Error { message }) => {
            Err(refused(format!("--vm: {message}")))
        }
        control::Within::Frame(other) => Err(refused(format!(
            "--vm: the attempt socket opened with {other:?}, not `ready`"
        ))),
        control::Within::Idle => Err(refused(
            "--vm: the guest did not finish booting before the budget; try again",
        )),
        control::Within::End => Err(refused("--vm: the attempt socket closed before `ready`")),
    }
}

fn expect_prepared(
    connection: &mut control::AttemptConnection,
    deadline: ContinuousDeadline,
) -> Result<String, JailError> {
    match connection
        .next_frame_within(control::HANDSHAKE_TIMEOUT.min(deadline.remaining()))
        .map_err(transport)?
    {
        control::Within::Frame(protocol::FromVm::Prepared { kernel, .. }) => Ok(kernel),
        control::Within::Frame(protocol::FromVm::Error { message }) => {
            Err(refused(format!("--vm: {message}")))
        }
        control::Within::Frame(other) => Err(refused(format!(
            "--vm: the guest answered staging with {other:?}, not `prepared`"
        ))),
        control::Within::Idle => Err(refused(
            "--vm: the guest did not accept the staging within the preparation budget",
        )),
        control::Within::End => Err(refused(
            "--vm: the attempt connection ended before the guest accepted the staging",
        )),
    }
}

impl PreparedExecution for VmExecution {
    fn boundary(&self) -> BoundaryIdentity {
        // Requested guest mechanism, not a host-kernel observation: the
        // receipt below is the guest's own Linux receipt, digest- and
        // binding-verified on the host, and the boundary says what it is:
        // guest-reported, host-verified consistency.
        BoundaryIdentity {
            boundary: BoundaryKind::PidNamespace,
            verification_scope: VerificationScope::AttemptTree,
            native: Some(NativeLifetime {
                os: Os::Linux,
                details: {
                    let mut details = serde_json::Map::new();
                    details.insert(
                        "evidence_origin".to_owned(),
                        Value::String("guest_reported; host verifies consistency only".to_owned()),
                    );
                    details.insert("vm_boot_id".to_owned(), Value::String(self.boot_id.clone()));
                    details.insert(
                        "disk_sha256".to_owned(),
                        Value::String(self.image.disk_sha256.clone()),
                    );
                    details.insert("vsock_port".to_owned(), Value::from(self.vsock_port));
                    details.insert(
                        "transport".to_owned(),
                        Value::String(record::SCHEMA_TRANSPORT.to_owned()),
                    );
                    details.insert(
                        "workspace_share".to_owned(),
                        Value::String("live-virtio-fs".to_owned()),
                    );
                    details.insert(
                        "share_measurements".to_owned(),
                        Value::String(
                            "docs/benchmarks/jail/results/macos-vm-share-2026-11-02/README.md"
                                .to_owned(),
                        ),
                    );
                    details
                },
            }),
            process: None,
            backend: Some("ukai-vm".to_owned()),
            backend_version: None,
        }
    }

    fn release(self: Box<Self>) -> Result<Box<dyn RunningExecution>, Box<ReleaseFailure>> {
        let mut execution = *self;
        let fail = |error: JailError| {
            // The lease is end-of-file (§6): dropping the connection is the
            // cancellation. No tree fact is claimed without the guest's own
            // verification, so a refused run records `tree_unknown`.
            Box::new(ReleaseFailure {
                error,
                teardown: Some(Teardown { tree: None }),
            })
        };
        if let Err(error) = execution.connection.send(&protocol::ToVm::Run) {
            return Err(fail(transport(error)));
        }
        match execution
            .connection
            .next_frame_within(control::HANDSHAKE_TIMEOUT)
        {
            Ok(control::Within::Frame(protocol::FromVm::Released { .. })) => {}
            Ok(control::Within::Frame(protocol::FromVm::Error { message })) => {
                return Err(fail(refused(format!("--vm: {message}"))));
            }
            Ok(control::Within::Frame(other)) => {
                return Err(fail(refused(format!(
                    "--vm: the guest answered the release with {other:?}, not `released`"
                ))));
            }
            Ok(_) => {
                return Err(fail(refused("--vm: the connection ended at the release")));
            }
            Err(error) => {
                return Err(fail(transport(error)));
            }
        }
        Ok(Box::new(VmRunning {
            inner: execution,
            receipt: None,
            guest: None,
            finished: false,
            failed: false,
        }))
    }

    fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
        drop(self.connection);
        Ok(Teardown { tree: None })
    }
}

/// The released attempt: the guest jail runs, and this side relays.
struct VmRunning {
    inner: VmExecution,
    receipt: Option<Value>,
    /// What the verified guest receipt reports the guest jail applied, for
    /// the host receipt to mirror (decision D5).
    guest: Option<GuestFacts>,
    finished: bool,
    failed: bool,
}

impl VmRunning {
    /// Writes one exported file beneath the attempt directory, never
    /// following a link: the guest names the path, so every component is
    /// descended through directory descriptors (`openat`, `O_NOFOLLOW`), the
    /// way the preview's launcher did.
    fn export(
        &self,
        group: &str,
        relative: &str,
        executable: bool,
        payload: &[u8],
    ) -> Result<(), JailError> {
        use std::ffi::CString;
        use std::os::fd::FromRawFd as _;
        if group != "workspace" && group != "evidence" {
            return Err(refused(format!(
                "--vm: the guest exported unknown group `{group}`"
            )));
        }
        if relative.is_empty()
            || relative.starts_with('/')
            || relative
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(refused(format!(
                "--vm: the guest exported an invalid path `{relative}`"
            )));
        }
        let name =
            |part: &str| CString::new(part).map_err(|_| refused("--vm: an export path held a NUL"));
        let root = self.inner.attempt_dir.join(group);
        let open_dir = |path: &Path| {
            let text = CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(|_| refused("--vm: the attempt directory path held a NUL"))?;
            // SAFETY: `open` with a NUL-terminated path; the flags ask for a
            // directory that is not a link, and the descriptor is owned from
            // here on.
            let fd = unsafe {
                libc::open(
                    text.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(refused(format!(
                    "--vm: {} is unreadable: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: `fd` is a freshly opened, owned descriptor.
            Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
        };
        let mut directory = open_dir(&root)?;
        let parts: Vec<&str> = relative.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            let part = name(part)?;
            // SAFETY: `mkdirat` reads the NUL-terminated name and writes
            // nothing the caller does not own.
            let created = unsafe { libc::mkdirat(directory.as_raw_fd(), part.as_ptr(), 0o700) };
            if created != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(refused(format!(
                    "--vm: `{relative}` cannot be created: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: `openat` with a NUL-terminated name on the owned
            // descriptor; `O_NOFOLLOW` refuses a planted link.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    part.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(refused(format!(
                    "--vm: `{relative}` cannot be descended: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: `fd` is a freshly opened, owned descriptor.
            directory = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        }
        let last = name(parts[parts.len() - 1])?;
        // SAFETY: `openat` with a NUL-terminated name; the flags create the
        // file exclusively, refuse a link, and keep it private.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                last.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(refused(format!(
                "--vm: `{relative}` cannot be written: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `fd` is a freshly created, owned descriptor.
        let file = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let mut written = 0_usize;
        while written < payload.len() {
            // SAFETY: `write` reads the caller's buffer for `count` bytes.
            let count = unsafe {
                libc::write(
                    file.as_raw_fd(),
                    payload[written..].as_ptr().cast(),
                    payload.len() - written,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(refused(format!(
                    "--vm: `{relative}` cannot be written: {error}"
                )));
            }
            written += count as usize;
        }
        let mode = if executable { 0o700 } else { 0o600 };
        // SAFETY: `fchmod` on the owned descriptor.
        let done = unsafe { libc::fchmod(file.as_raw_fd(), mode) };
        if done != 0 {
            return Err(refused(format!(
                "--vm: `{relative}` mode failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Verifies and stores the guest receipt; the one path to a completed
    /// attempt runs through this check (§6: the receipt is the guest's Linux
    /// receipt, verified on the host).
    fn store_receipt(
        &mut self,
        sha256: &str,
        data: &str,
        binding: &protocol::ReceiptBinding,
    ) -> Result<(), String> {
        if self.receipt.is_some() {
            return Err("duplicate guest receipt".to_owned());
        }
        let bytes = protocol::decode_data(data).map_err(|error| error.to_string())?;
        let digest = image::hex(&sha2::Sha256::digest(&bytes));
        if digest != sha256 {
            return Err(
                "the guest receipt's digest does not match its bytes; the attempt never \
                 claims a receipt it cannot verify"
                    .to_owned(),
            );
        }
        let receipt: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("the guest receipt is not JSON: {error}"))?;
        image::verify_bound_guest_receipt(
            &receipt,
            binding,
            &image::BoundExpectation {
                attempt_id: &self.inner.attempt_id,
                boot_id: &self.inner.boot_id,
                profile: &self.inner.profile,
                argv_digest: &self.inner.argv_digest,
                network: &self.inner.network,
            },
        )
        .map_err(|e| e.to_string())?;
        verify_applied_limits(&receipt, &self.inner.limits)?;
        let guest = guest_facts(&receipt, &digest)?;
        self.export("evidence", "jail.json", false, &bytes)
            .map_err(|e| e.message)?;
        let binding = serde_json::to_vec(binding).map_err(|e| e.to_string())?;
        self.export("evidence", "vm-binding.json", false, &binding)
            .map_err(|e| e.message)?;
        self.receipt = Some(receipt);
        self.guest = Some(guest);
        Ok(())
    }

    /// Whether the attempt ended with a verified guest receipt, its `done`
    /// and the transport record: the one state whose guest facts the host
    /// receipt mirrors.
    fn verified(&self) -> bool {
        self.finished && !self.failed && self.receipt.is_some()
    }

    /// Writes the transport record once the verified receipt and the guest's
    /// `done` have both landed (§6, row K111).
    fn settle_record(&self) -> Result<(), String> {
        if self.failed || self.receipt.is_none() {
            return Err("no verified guest receipt".to_owned());
        }
        let bytes = std::fs::read(self.inner.attempt_dir.join("evidence/jail.json"))
            .map_err(|e| format!("guest evidence read failed: {e}"))?;
        let record = record::TransportRecord::new(
            self.inner.attempt_id.clone(),
            self.inner.boot_id.clone(),
            self.inner.guest_kernel.clone(),
            self.inner.image.clone(),
            self.inner.vsock_port,
            self.inner.sockets.0.display().to_string(),
            self.inner.sockets.1.display().to_string(),
            self.inner.started_wall.clone(),
            self.inner.started.elapsed().as_secs_f64(),
            image::hex(&sha2::Sha256::digest(&bytes)),
        );
        record
            .write_in(&self.inner.attempt_dir)
            .map_err(|e| format!("transport record write failed: {e}"))
    }
}

impl VmRunning {
    fn wait_frames(&mut self, deadline: Deadline) -> RunEvent {
        loop {
            let budget = deadline
                .at
                .map(|at| at.saturating_duration_since(Instant::now()))
                .unwrap_or(POLL_STEP);
            if budget.is_zero() {
                return RunEvent::WallExpired;
            }
            let frame = match self
                .inner
                .connection
                .next_frame_within(budget.min(POLL_STEP))
            {
                Ok(control::Within::Frame(frame)) => frame,
                Ok(control::Within::Idle) => continue,
                Ok(control::Within::End) => {
                    return RunEvent::Unknown {
                        reason: "the attempt connection ended before the guest reported its \
                                 outcome"
                            .to_owned(),
                    };
                }
                Err(error) => {
                    return RunEvent::Unknown {
                        reason: format!("the attempt transport failed: {error}"),
                    };
                }
            };
            match frame {
                protocol::FromVm::Stdout { data } => {
                    let payload = match protocol::decode_data(&data) {
                        Ok(data) => data,
                        Err(error) => {
                            self.failed = true;
                            return RunEvent::Unknown {
                                reason: error.to_string(),
                            };
                        }
                    };
                    // Choose by frame before moving its payload (handled below).
                    if let Err(error) = self.inner.stdout.write_all(&payload) {
                        self.failed = true;
                        return RunEvent::Unknown {
                            reason: format!("guest stdout delivery failed: {error}"),
                        };
                    }
                }
                protocol::FromVm::Stderr { data } => {
                    let result = protocol::decode_data(&data)
                        .map_err(|e| e.to_string())
                        .and_then(|data| {
                            self.inner
                                .stderr
                                .write_all(&data)
                                .map_err(|e| e.to_string())
                        });
                    if let Err(reason) = result {
                        self.failed = true;
                        return RunEvent::Unknown { reason };
                    }
                }
                protocol::FromVm::File {
                    group,
                    path,
                    executable,
                    data,
                } => {
                    let payload = match protocol::decode_data(&data) {
                        Ok(payload) => payload,
                        Err(error) => {
                            return RunEvent::Unknown {
                                reason: format!("an export frame was malformed: {error}"),
                            };
                        }
                    };
                    if let Err(error) = self.export(&group, &path, executable, &payload) {
                        return RunEvent::Unknown {
                            reason: error.message,
                        };
                    }
                }
                protocol::FromVm::BoundReceipt {
                    sha256,
                    data,
                    binding,
                } => {
                    if let Err(reason) = self.store_receipt(&sha256, &data, &binding) {
                        self.failed = true;
                        return RunEvent::Unknown { reason };
                    }
                }
                protocol::FromVm::Receipt { .. } => {
                    self.failed = true;
                    return RunEvent::Unknown {
                        reason: "unbound guest receipt refused".to_owned(),
                    };
                }
                protocol::FromVm::Released { .. } => {}
                protocol::FromVm::Ready { .. } | protocol::FromVm::Prepared { .. } => {
                    return RunEvent::Unknown {
                        reason: "the guest repeated a staging frame mid-attempt".to_owned(),
                    };
                }
                protocol::FromVm::Error { message } => {
                    return RunEvent::Unknown { reason: message };
                }
                protocol::FromVm::Done { exit_code } => {
                    self.finished = true;
                    if let Err(reason) = self.settle_record() {
                        self.failed = true;
                        return RunEvent::Unknown { reason };
                    }
                    let code = u8::try_from(exit_code).unwrap_or(125);
                    return RunEvent::TargetExited { code };
                }
            }
        }
    }
}

impl RunningExecution for VmRunning {
    fn final_limits(&self) -> Vec<AppliedLimit> {
        self.receipt
            .as_ref()
            .and_then(|receipt| receipt.pointer("/applied/limits"))
            .and_then(|limits| serde_json::from_value::<Vec<AppliedLimit>>(limits.clone()).ok())
            .unwrap_or_default()
    }

    fn limit_cause(&self) -> Option<LimitCause> {
        None
    }

    fn integrity_lost(&self) -> bool {
        self.failed
            || self
                .receipt
                .as_ref()
                .and_then(|receipt| receipt.pointer("/lifetime/integrity"))
                .and_then(Value::as_str)
                == Some("lost")
    }

    fn final_native_details(&self) -> serde_json::Map<String, Value> {
        let mut details = serde_json::Map::new();
        details.insert(
            "transport".to_owned(),
            Value::String(record::SCHEMA_TRANSPORT.to_owned()),
        );
        details.insert(
            "evidence_origin".to_owned(),
            Value::String("guest_reported; host verifies consistency only".to_owned()),
        );
        details
    }

    fn guest_facts(&self) -> Option<GuestFacts> {
        self.guest.clone().filter(|_| self.verified())
    }

    fn wait(&mut self, deadline: Deadline) -> RunEvent {
        let event = self.wait_frames(deadline);
        if matches!(
            event,
            RunEvent::Unknown { .. } | RunEvent::StdioFailed { .. }
        ) {
            self.failed = true;
        }
        event
    }

    fn request_stop(&mut self, _reason: StopReason) {
        // The lease is end-of-file: half-closing the write side cancels the
        // guest attempt, and the frames that remain are still read for the
        // outcome the guest reports on its way down.
        let _ = self.inner.connection.shutdown_write();
    }

    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        if !self.finished && !self.failed {
            let event = self.wait(Deadline {
                at: Some(Instant::now() + budget),
            });
            if !matches!(event, RunEvent::TargetExited { .. }) {
                self.failed = true;
            }
        }
        let verified = self.verified() && self.settle_record().is_ok();
        TreeObservation {
            tree_empty: verified.then_some(true),
            verified_at: None,
            verification_scope: VerificationScope::AttemptTree,
            integrity: if verified {
                Integrity::Verified
            } else {
                Integrity::Lost
            },
        }
    }

    fn observer_summary(&mut self) -> Option<crate::observer::CoverageSummary> {
        None
    }
}

#[cfg(test)]
#[path = "vm/tests.rs"]
mod tests;

#[cfg(test)]
#[test]
fn p2_vm_state_identity_is_the_mac_host_while_policy_identity_is_linux() {
    let platform = VmPlatform {
        data_dir: PathBuf::from("unused-data"),
        install: Install {
            root: PathBuf::from("unused-install"),
            manifest: image::ImageManifest {
                status: "prepared".into(),
                disk_sha256: "d".repeat(64),
                helper_sha256: "h".repeat(64),
                custodian_sha256: "c".repeat(64),
                seed_sha256: "s".repeat(64),
            },
        },
    };
    assert_eq!(platform.identity().os, Os::Linux);
    assert_eq!(
        platform.state_identity(),
        crate::platform::macos::MacosPlatform.identity()
    );
    assert_eq!(
        platform.owner_identity(),
        crate::platform::macos::owner_identity()
    );
}
