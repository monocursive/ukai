//! The VM tier (J18, jail-macos.md §6): a warm Linux guest per operator,
//! selected with `--vm` before native preparation.
//!
//! [`VmPlatform`] currently refuses every CLI policy before connection or
//! staging: the live workspace share and pre-release guest measurements are
//! not implemented. The transport implementation below is tested with stand-ins.
//! Its guest reports are checked for consistency and binding; they are not
//! independent host measurements of guest kernel enforcement.
//! The host supervisor's identity is macOS even though policies resolve for Linux.

use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use sha2::Digest as _;

use crate::capability::{Capability, CapabilityScope, CapabilityStatus, Requirement};
use crate::lifecycle::{BoundaryKind, Integrity, VerificationScope};
use crate::platform::{
    BoundaryIdentity, Deadline, LimitCause, PlanRequest, Platform, PlatformIdentity,
    PreparedExecution, PreparedPlan, ReleaseFailure, RunEvent, RunningExecution, Sinks, StopReason,
    Teardown, TreeObservation,
};
use crate::records::{
    AppliedLimit, ErrorCode, ErrorStage, JailError, NativeLifetime, Os, Remediation, rfc3339_utc,
};

use image::Install;

pub mod control;
pub mod image;
pub mod protocol;
pub mod record;

/// How long starting `ukai-vm serve` may take before the run refuses.
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(20);

/// One bounded wait step inside the run loop: long enough not to spin,
/// short enough for the wall deadline to fire between frames.
const POLL_STEP: Duration = Duration::from_secs(1);

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

    /// Starts `ukai-vm serve` when no instance answers, and waits for the
    /// control socket (§6: "starts the guest on first use").
    ///
    /// The binary is this package's `ukai-vm`, found beside this executable
    /// or on `PATH`. The child is detached: its own process group, its
    /// standard streams closed, so an operator interrupt of the run is not
    /// its exit.
    ///
    /// # Errors
    /// The refusal when no server answers after [`SERVE_TIMEOUT`].
    pub fn ensure_serving(&self) -> Result<(), JailError> {
        let socket = self.control_socket();
        if control::is_listening(&socket) {
            return Ok(());
        }
        let program = self.serve_binary()?;
        let runtime = vm_runtime_dir(&self.data_dir);
        std::fs::create_dir_all(&runtime).map_err(|error| {
            refused(format!(
                "--vm: {} cannot be created: {error}",
                runtime.display()
            ))
        })?;
        std::process::Command::new(&program)
            .arg("serve")
            .env("UKAI_VM_HOME", &self.install.root)
            .env("UKAI_DATA_DIR", &self.data_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|error| {
                refused(format!("--vm: {} cannot start: {error}", program.display()))
            })?;
        let deadline = Instant::now() + SERVE_TIMEOUT;
        while Instant::now() < deadline {
            if control::is_listening(&socket) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(refused(format!(
            "--vm: no ukai-vm answered on {} within {}s",
            socket.display(),
            SERVE_TIMEOUT.as_secs()
        )))
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

    /// The capability scope a requirement is measured at, as the native
    /// platform spells it.
    fn scope_for(requirement: Requirement) -> CapabilityScope {
        match requirement {
            Requirement::SyscallFilter => CapabilityScope::Process,
            _ => CapabilityScope::Tree,
        }
    }
}

impl Platform for VmPlatform {
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
        let reason = policy_refusal(&plan.snapshot).0;
        plan.requirements
            .iter()
            .map(|&requirement| Capability {
                name: requirement.to_string(),
                status: CapabilityStatus::Unavailable,
                scope: Self::scope_for(requirement),
                mechanism: None,
                reason_code: Some(reason.to_owned()),
                measured_at: None,
                evidence_ref: None,
            })
            .collect()
    }

    fn prepare(
        &self,
        plan: PreparedPlan,
        sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        VmExecution::prepare(self, plan, sinks).map(|execution| Box::new(execution) as _)
    }
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
    limits: crate::policy::LimitsSnapshot,
    stdout: std::fs::File,
    stderr: std::fs::File,
}

impl VmExecution {
    fn prepare(
        platform: &VmPlatform,
        plan: PreparedPlan,
        _sinks: Sinks,
    ) -> Result<Self, JailError> {
        // The missing share/measurement applies to every current VM policy.
        // Refuse before connecting, staging files, or moving any credentials.
        validate_policy(&plan.request.snapshot)?;
        platform.ensure_serving()?;
        let socket = control::attempt_socket(&platform.data_dir);
        let mut connection = control::AttemptConnection::connect(&socket).map_err(transport)?;
        let ready = expect_ready(&mut connection)?;
        verify_ready(&ready, &platform.install.manifest)?;
        let snapshot = &plan.request.snapshot;
        let wall = guest_wall(snapshot)?;
        let profile = snapshot.profile.as_str().to_owned();
        if !protocol::GUEST_PROFILES.contains(&profile.as_str()) {
            return Err(invalid(format!(
                "--vm: the guest jail takes one of {}, not `{profile}`",
                protocol::GUEST_PROFILES.join(", ")
            )));
        }
        let entries = image::snapshot_workspace(&plan.workspace)
            .map_err(|error| invalid(format!("--vm: {}", error.0)))?;
        let staged = protocol::ToVm::Prepare {
            attempt_id: plan.attempt_id.clone(),
            profile: profile.clone(),
            wall_seconds: wall,
            argv: plan
                .argv
                .iter()
                .map(|argument| protocol::encode_data(argument))
                .collect(),
            secrets: Vec::new(),
        };
        connection.send(&staged).map_err(transport)?;
        let guest_kernel = expect_prepared(&mut connection)?;
        for entry in &entries {
            connection
                .send(&protocol::ToVm::Put(protocol::Put {
                    path: entry.path.clone(),
                    executable: entry.executable,
                    data: protocol::encode_data(&entry.data),
                }))
                .map_err(transport)?;
        }
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
            stdout,
            stderr,
        })
    }
}

/// The guest wall, in whole seconds, from the policy's ceiling. The guest
/// grammar takes 1..=300 seconds; the preview's jail enforces the same
/// shape, so a policy outside it refuses here rather than mid-guest.
fn guest_wall(snapshot: &crate::policy::PolicySnapshot) -> Result<u32, JailError> {
    let wall_ms: u64 = snapshot
        .limits
        .wall
        .as_ref()
        .and_then(|wall| wall.value.parse().ok())
        .ok_or_else(|| {
            invalid(
                "--vm: the policy sets no wall ceiling; the guest grammar needs one \
                 (`--limit wall=<seconds>s`)",
            )
        })?;
    let seconds = wall_ms / 1000;
    if !wall_ms.is_multiple_of(1000) || seconds == 0 || seconds > u64::from(protocol::WALL_MAX) {
        return Err(invalid(format!(
            "--vm: the guest grammar takes a wall of 1..={} whole seconds, the policy asks \
             for {wall_ms}ms",
            protocol::WALL_MAX
        )));
    }
    Ok(u32::try_from(seconds).unwrap_or(protocol::WALL_MAX))
}

fn policy_refusal(snapshot: &crate::policy::PolicySnapshot) -> (&'static str, String) {
    use crate::policy::ProfileName;
    if !matches!(snapshot.profile, ProfileName::Tool | ProfileName::Build) {
        return (
            "vm:profile-unsupported:offline-tool-and-build-only",
            format!(
                "--vm: profile {} is unsupported; only offline tool/build previews exist",
                snapshot.profile.as_str()
            ),
        );
    }
    if snapshot.launch.is_some() {
        return (
            "vm:launch-and-vault-credentials-not-implemented",
            "--vm: launch profiles and vault credentials are not wired into the guest jail"
                .to_owned(),
        );
    }
    if snapshot.network.mode != crate::network::NetworkMode::None {
        return (
            "vm:network-unavailable:no-guest-nat-or-proxy",
            "--vm: network and proxy policy are unavailable; the guest has no run-mode NAT"
                .to_owned(),
        );
    }
    if !snapshot.filesystem.deny_read.is_empty() {
        return (
            "vm:deny-read-not-supported-by-workspace-copy",
            "--vm: deny-read policy cannot be honored by workspace copying; no files were staged"
                .to_owned(),
        );
    }
    ("vm:policy-unavailable:live-workspace-share-and-guest-measurements-not-implemented",
        "--vm: policy enforcement is unavailable: a live workspace share and pre-release guest capability measurements are not implemented; no workload was started".to_owned())
}

fn validate_policy(snapshot: &crate::policy::PolicySnapshot) -> Result<(), JailError> {
    Err(refused(policy_refusal(snapshot).1))
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
    let count = expected.values().filter(|v| !v.is_null()).count();
    if rows.len() != count {
        return Err("guest applied limits differ from requested limits".to_owned());
    }
    for (key, ceiling) in expected.iter().filter(|(_, v)| !v.is_null()) {
        let matching: Vec<_> = rows.iter().filter(|row| &row.key == key).collect();
        if matching.len() != 1
            || !matching[0].applied
            || Some(matching[0].requested.as_str()) != ceiling["value"].as_str()
            || Some(matching[0].required) != ceiling["required"].as_bool()
        {
            return Err(format!("guest did not apply requested {key} ceiling"));
        }
    }
    Ok(())
}

fn expect_ready(connection: &mut control::AttemptConnection) -> Result<ReadyFrame, JailError> {
    match connection.next_frame().map_err(transport)? {
        Some(protocol::FromVm::Ready {
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
        Some(protocol::FromVm::Error { message }) => Err(refused(format!("--vm: {message}"))),
        Some(other) => Err(refused(format!(
            "--vm: the attempt socket opened with {other:?}, not `ready`"
        ))),
        None => Err(refused("--vm: the attempt socket closed before `ready`")),
    }
}

fn expect_prepared(connection: &mut control::AttemptConnection) -> Result<String, JailError> {
    match connection.next_frame().map_err(transport)? {
        Some(protocol::FromVm::Prepared { kernel }) => Ok(kernel),
        Some(protocol::FromVm::Error { message }) => Err(refused(format!("--vm: {message}"))),
        Some(other) => Err(refused(format!(
            "--vm: the guest answered staging with {other:?}, not `prepared`"
        ))),
        None => Err(refused(
            "--vm: the attempt connection ended before the guest accepted the staging",
        )),
    }
}

impl PreparedExecution for VmExecution {
    fn boundary(&self) -> BoundaryIdentity {
        // Requested guest mechanism, not a host-kernel observation. The
        // current capability/policy gate prevents any CLI run from reaching
        // this provisional boundary. Enabling it requires a measured guest
        // preflight; a post-run consistency check is not a substitute.
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
            &self.inner.attempt_id,
            &self.inner.boot_id,
            &self.inner.profile,
            &self.inner.argv_digest,
        )
        .map_err(|e| e.to_string())?;
        verify_applied_limits(&receipt, &self.inner.limits)?;
        self.export("evidence", "jail.json", false, &bytes)
            .map_err(|e| e.message)?;
        let binding = serde_json::to_vec(binding).map_err(|e| e.to_string())?;
        self.export("evidence", "vm-binding.json", false, &binding)
            .map_err(|e| e.message)?;
        self.receipt = Some(receipt);
        Ok(())
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
        let verified =
            self.finished && !self.failed && self.receipt.is_some() && self.settle_record().is_ok();
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
