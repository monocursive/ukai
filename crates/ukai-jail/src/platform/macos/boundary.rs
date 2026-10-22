//! The supervisor side of the native tier: the boundary of §4.3–§4.6 and
//! §4.8 (jail-macos.md), built by [`prepare`] behind
//! `MacosPlatform::prepare`.
//!
//! # Order of a start (§4.3)
//!
//! 1. Client **S**: a descendants custody client, unmuted and checked, the
//!    three custody events subscribed. `ERR_NOT_ENTITLED` refuses with
//!    remediation `unsupported`; `ERR_TOO_MANY_CLIENTS` with `retry`.
//! 2. The guardian record (an empty file in the attempt directory), pipes
//!    **A** (supervisor → guardian) and **B** (guardian → supervisor), the
//!    launcher's release pipe **R** and error pipe **E** — every descriptor
//!    close-on-exec. The launcher's ends of R and E, the pty slave and the
//!    launch block cross the guardian's spawn by explicit `addinherit_np`,
//!    with `POSIX_SPAWN_CLOEXEC_DEFAULT`: the inheritance
//!    contract `guardian::spawn` continues with `addinherit_np` for
//!    `sandbox-exec`'s child.
//! 3. The guardian, this binary as `ukai-jail __guardian …`, spawned with
//!    `POSIX_SPAWN_SETPGID` (its own group, §4.2) and the supervisor's
//!    signal mask. The supervisor does **not** lower `RLIMIT_NPROC`: the
//!    guardian lowers its own (§4.1 rule 6).
//! 4. Handshake: `ready` on B within the preparation budget; the first fork
//!    on S whose pid is not the guardian's names the launcher; the
//!    launcher's `blocked` report on E (the 8-byte `errno = 0, detail = 0`
//!    sentinel of `macos::launcher`) then lets the supervisor send
//!    `launcher-token` on A and wait for `token-seen` on B (§4.3 step 5).
//!    S then registers both custodians and its expected root, and replays
//!    every retained handshake event once, in delivery order.
//! 5. Release (§4.3 step 6): `release-deadline` on A (continuous-clock
//!    nanoseconds), then one release byte on R.
//! 6. Exec (step 7): the launcher's `NOTIFY_EXEC` on S confirms it and its
//!    token is the target's identity; the target's outcome is its
//!    `NOTIFY_EXIT` wait status (`wait4` semantics, per `ESMessage.h`) —
//!    there is no second source.
//!
//! # Stopping (§4.5) and loss (§4.6)
//!
//! `request_stop` runs jail-v1 §9.3's cooperative grace (`SIGTERM` to the
//! target by audit token, initial 2 s), then closes A — whose end-of-file is
//! the guardian's stop — and runs the supervisor's own stop from client S.
//! The two custodians signal the same identities, which is harmless. The
//! supervisor settles from its own drain, or from the guardian's `record`
//! frame on B within the budget; `tree_empty = true` needs one custodian
//! that drained (root observed, empty table, contiguous stream, no user
//! change). A guardian
//! that dies before the stop is recorded and the run continues from S alone
//! (`tree_empty` stays possible from S); a guardian that stalls at the stop
//! is ended only while its direct-child PID is still owned, then reaped.
//!
//! # Live custody rows
//!
//! The K87–K97 rows need the Endpoint Security entitlement (the dev VM,
//! docs/benchmarks/jail/macos-development.md). On this Mac client creation
//! refuses (`ERR_NOT_ENTITLED`), which the conformance tests turn into the
//! K98 end-to-end refusal; the pipe discipline, the B-frame codec and the
//! RunEvent mapping are unit-tested here without a client.

use std::ffi::{CString, OsString};
use std::io::Read;
use std::os::fd::{AsFd as _, IntoRawFd as _, RawFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::lifecycle::Integrity;
use crate::platform::macos::bridge::{self, BridgeConfig};
use crate::platform::macos::custody::{
    AUDIT_TOKEN_PID, AUDIT_TOKEN_PIDVERSION, Custodian, Signaller, StopResult,
};
use crate::platform::macos::custody_io::{self, EsNewResult, EsSignaller, Token};
use crate::platform::macos::es::{self, CustodyClient, EsEvent};
use crate::platform::macos::guardian::frames::{
    MAX_FRAME_BYTES, NO_DEADLINE, encode_launcher_token, encode_release_deadline,
    encode_release_without_deadline,
};
use crate::platform::macos::guardian::launch_block::{self, FdAction, LaunchBlock};
use crate::platform::macos::guardian::record;
use crate::platform::macos::guardian::rlimit::NPROC_HEADROOM;
use crate::platform::macos::relay::TerminalRelay;
use crate::platform::macos::sandbox::{self as seatbelt, ProfileParams};
use crate::platform::{
    BoundaryIdentity, BoundaryKind, ContinuousDeadline, Deadline, PreparedExecution, PreparedPlan,
    ReleaseFailure, RunEvent, Sinks, StopReason, Teardown, TreeObservation, VerificationScope,
};
use crate::records::{
    Applied, AppliedFilesystem, AppliedLimit, AppliedMount, AppliedNetwork, AppliedTerminal,
    ErrorCode, ErrorStage, JailError, NativeLifetime, NativeString, Os, ProcessIdentity,
    ProcessRecord, Remediation,
};

/// The stop budget, initial 5 s from the stop's start, as Linux's §9.3.
const STOP_BUDGET_NS: u64 = 5_000_000_000;
/// The freeze sweep interval (§4.5 step 2, initial 20 ms).
const SETTLE_NS: u64 = 20_000_000;
/// The cooperative grace: `SIGTERM` to the target, initial 2 s (§4.5).
const STOP_GRACE_NS: u64 = 2_000_000_000;
/// How long a stalled guardian may keep working past the settlement budget
/// before the supervisor ends it (§4.5: the guardian's own tail).
const GUARDIAN_TAIL: Duration = Duration::from_secs(60);
/// One bounded-wait slice, in milliseconds.
const TICK_MS: u32 = 20;

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

fn refusal(
    code: ErrorCode,
    stage: ErrorStage,
    remediation: Remediation,
    message: impl Into<String>,
) -> JailError {
    JailError::new(code, stage, remediation, message)
}

/// Client S's creation and check (§4.3 step 1), with the refusal codes the
/// section fixes.
fn create_client_s() -> Result<CustodyClient, JailError> {
    let client = match custody_io::create_custody_client() {
        Ok(client) => client,
        Err(result) => {
            let name = custody_io::es_new_result_name(result);
            let (code, remediation, hint) = match result {
                EsNewResult::NotEntitled => (
                    ErrorCode::UnsupportedPlatform,
                    Remediation::Unsupported,
                    "the executable lacks com.apple.developer.endpoint-security.client; run \
                     inside the development VM or install the entitled app bundle",
                ),
                EsNewResult::TooManyClients => (
                    ErrorCode::UnsupportedPlatform,
                    Remediation::Retry,
                    "another Endpoint Security client holds the system's client slot",
                ),
                _ => (
                    ErrorCode::UnsupportedPlatform,
                    Remediation::Unsupported,
                    "the system refused the custody client",
                ),
            };
            return Err(refusal(
                code,
                ErrorStage::Probing,
                remediation,
                format!("es_new_descendants_client answered {name}: {hint}"),
            ));
        }
    };
    custody_io::setup_custody(&client).map_err(|message| {
        refusal(
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Probing,
            Remediation::Unsupported,
            format!("the custody client is unusable: {message}"),
        )
    })?;
    Ok(client)
}

// ---------------------------------------------------------------------------
// Descriptors and the guardian's spawn
// ---------------------------------------------------------------------------

/// The thread-local errno.
fn errno() -> i32 {
    // SAFETY: `__error` is libSystem's thread-local errno location.
    unsafe { *libc::__error() }
}

/// One pipe, both ends close-on-exec.
struct Pipe {
    read: RawFd,
    write: RawFd,
}

impl Pipe {
    fn new() -> Result<Self, JailError> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a valid out array for `pipe`.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(refusal(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("pipe: {}", std::io::Error::last_os_error()),
            ));
        }
        let pipe = Pipe {
            read: fds[0],
            write: fds[1],
        };
        // Darwin has no pipe2. All native spawns use CLOEXEC_DEFAULT and an
        // explicit inheritance list, independent of this fcntl window; Rust
        // Command on Darwin also uses CLOEXEC_DEFAULT. Never fork/exec here.
        for fd in fds {
            // SAFETY: F_SETFD takes scalars and dereferences nothing.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(refusal(
                    ErrorCode::InvalidFd,
                    ErrorStage::Preparing,
                    Remediation::InspectState,
                    format!("fcntl FD_CLOEXEC: {}", std::io::Error::last_os_error()),
                ));
            }
        }
        Ok(pipe)
    }
    fn take_read(&mut self) -> RawFd {
        std::mem::replace(&mut self.read, -1)
    }
    fn take_write(&mut self) -> RawFd {
        std::mem::replace(&mut self.write, -1)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        for fd in [self.read, self.write] {
            if fd >= 0 {
                // SAFETY: each end is owned here until taken.
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// A raw descriptor this module owns, closed on drop, read nonblockingly.
struct Fd(RawFd);

impl Fd {
    /// Takes ownership of a descriptor and sets `O_NONBLOCK`: every read of
    /// B and E is one bounded poll slice, never a block without a deadline.
    fn take_fd(&mut self) -> RawFd {
        std::mem::replace(&mut self.0, -1)
    }

    fn close(&mut self) {
        drop(Fd(self.take_fd()));
    }

    fn nonblocking(fd: RawFd) -> Result<Self, JailError> {
        let owned = Fd(fd);
        // SAFETY: F_GETFL takes a descriptor number and dereferences nothing.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: F_SETFL takes scalars and dereferences nothing.
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(refusal(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("fcntl O_NONBLOCK: {}", std::io::Error::last_os_error()),
            ));
        }
        Ok(owned)
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: a plain close of a descriptor this process owns.
            unsafe { libc::close(self.0) };
        }
    }
}

impl Read for Fd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: the buffer is caller-provided and live for the call.
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// The C runtime's `environ`.
fn environ() -> *const *const libc::c_char {
    unsafe extern "C" {
        static environ: *const *const libc::c_char;
    }
    // SAFETY: `environ` is the C runtime's own pointer, valid for the life
    // of the process.
    unsafe { environ }
}

/// `POSIX_SPAWN_SETPGID` (sys/spawn.h): the child runs in a process group of
/// its own (§4.2).
const POSIX_SPAWN_SETPGID: libc::c_int = 0x0008;

/// Spawns `exe args…` with `posix_spawn`, inheriting exactly the standard
/// descriptors plus `fds` (`addinherit_np` explicitly admits each one),
/// with all other descriptors closed, in its own process group, with this
/// process's signal mask.
fn spawn_self(exe: &Path, args: &[String], fds: &[RawFd]) -> Result<libc::pid_t, JailError> {
    let text = |what: &'static str, bytes: &[u8]| -> Result<CString, JailError> {
        CString::new(bytes).map_err(|_| {
            refusal(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("{what} contains NUL; the guardian argv is text"),
            )
        })
    };
    let path = text("the executable's path", exe.as_os_str().as_encoded_bytes())?;
    let mut argv: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv.push(path.clone());
    for argument in args {
        argv.push(text("a guardian argument", argument.as_bytes())?);
    }
    let mut argv_raw: Vec<*mut libc::c_char> =
        argv.iter().map(|part| part.as_ptr().cast_mut()).collect();
    argv_raw.push(std::ptr::null_mut());

    // Custody never needs the operator's tokens, proxy credentials, or loader
    // environment. The launch block separately carries the workload's env.
    let environment = [c"PATH=/usr/bin:/bin:/usr/sbin:/sbin", c"LANG=C"];
    let mut envp_raw: Vec<*const libc::c_char> = environment.iter().map(|v| v.as_ptr()).collect();
    envp_raw.push(std::ptr::null());

    let mut actions = libc::posix_spawn_file_actions_t::default();
    // SAFETY: each call initializes or extends `actions`, which lives across
    // the spawn and is destroyed below; no pointers are retained into them.
    unsafe {
        if libc::posix_spawn_file_actions_init(&mut actions) != 0 {
            return Err(spawn_error("posix_spawn_file_actions_init"));
        }
    }
    // SAFETY: documented pairing with the init above; runs before every
    // early return past this point.
    struct Actions(libc::posix_spawn_file_actions_t);
    impl Drop for Actions {
        fn drop(&mut self) {
            // SAFETY: `self.0` was initialized and is destroyed once.
            unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
        }
    }
    let mut actions = Actions(actions);
    unsafe extern "C" {
        fn posix_spawn_file_actions_addinherit_np(
            actions: *mut libc::posix_spawn_file_actions_t,
            fd: libc::c_int,
        ) -> libc::c_int;
    }
    let mut inherited = vec![0, 1, 2];
    inherited.extend_from_slice(fds);
    inherited.sort_unstable();
    inherited.dedup();
    for fd in inherited {
        // SAFETY: actions is initialized; addinherit clears CLOEXEC on the
        // child's copy. Self-dup2 does not do that on Darwin.
        let result = unsafe { posix_spawn_file_actions_addinherit_np(&mut actions.0, fd) };
        if result != 0 {
            return Err(spawn_error("posix_spawn_file_actions_addinherit_np"));
        }
    }

    let mut attributes = libc::posix_spawnattr_t::default();
    // SAFETY: init before use, destroy on scope exit below.
    unsafe {
        if libc::posix_spawnattr_init(&mut attributes) != 0 {
            return Err(spawn_error("posix_spawnattr_init"));
        }
    }
    struct Attributes(libc::posix_spawnattr_t);
    impl Drop for Attributes {
        fn drop(&mut self) {
            // SAFETY: `self.0` was initialized and is destroyed once.
            unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
        }
    }
    let mut attributes = Attributes(attributes);
    // SAFETY: `attributes.0` is initialized; the flags and the mask are the
    // spawn attributes of §4.2.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut mask) != 0
            || libc::pthread_sigmask(0, std::ptr::null(), &mut mask) != 0
        {
            return Err(spawn_error("pthread_sigmask"));
        }
        if libc::posix_spawnattr_setsigmask(&mut attributes.0, &mask) != 0 {
            return Err(spawn_error("posix_spawnattr_setsigmask"));
        }
        if libc::posix_spawnattr_setflags(
            &mut attributes.0,
            (POSIX_SPAWN_SETPGID | libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_CLOEXEC_DEFAULT)
                as libc::c_short,
        ) != 0
        {
            return Err(spawn_error("posix_spawnattr_setflags"));
        }
    }
    let mut pid: libc::pid_t = 0;
    // SAFETY: argv/envp are NUL-terminated arrays with null sentinels; the
    // actions and attributes records above are live for this call.
    let result = unsafe {
        libc::posix_spawn(
            &mut pid,
            path.as_ptr(),
            &actions.0,
            &attributes.0,
            argv_raw.as_ptr(),
            // The child's environment is read-only for this process; the
            // historical signature wants mutable pointers.
            envp_raw.as_ptr() as *mut *const libc::c_char as *mut *mut libc::c_char,
        )
    };
    if result != 0 {
        return Err(refusal(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("posix_spawn of the guardian failed: errno {result}"),
        ));
    }
    Ok(pid)
}

fn spawn_error(step: &str) -> JailError {
    refusal(
        ErrorCode::BackendUnavailable,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!("{step}: {}", std::io::Error::last_os_error()),
    )
}

// ---------------------------------------------------------------------------
// The launch block's inputs
// ---------------------------------------------------------------------------

/// The `ukai-jail __launch-macos` argv the launch block carries.
fn launcher_argv(
    exe: &Path,
    release_fd: i32,
    error_fd: i32,
    terminal_slave: Option<i32>,
    sigmask: u64,
    argv: &[Vec<u8>],
) -> Result<Vec<String>, JailError> {
    let exe = exe.to_str().ok_or_else(|| {
        refusal(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            "the executable's path is not UTF-8; the macOS launch block is text",
        )
    })?;
    let mut out = vec![
        exe.to_owned(),
        "__launch-macos".to_owned(),
        "--release-fd".to_owned(),
        release_fd.to_string(),
        "--error-fd".to_owned(),
        error_fd.to_string(),
    ];
    if let Some(slave) = terminal_slave {
        out.push("--terminal-slave".to_owned());
        out.push(slave.to_string());
    }
    out.push("--sigmask".to_owned());
    out.push(format!("{sigmask:x}"));
    out.push("--".to_owned());
    for part in argv {
        let text = std::str::from_utf8(part).map_err(|_| {
            refusal(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                "the command line is not UTF-8; the macOS launch block is text",
            )
        })?;
        out.push(text.to_owned());
    }
    Ok(out)
}

/// The child's environment: the snapshot's effective bindings, plus the
/// bridge's proxy variables when a bridge exists (§4.10).
fn child_envp(plan: &PreparedPlan, bridge: Option<&BridgeConfig>) -> Vec<String> {
    let mut out = Vec::new();
    let environment = &plan.request.snapshot.environment;
    if environment.inherit_host {
        // SAFETY: walking the C runtime's own NULL-terminated array.
        unsafe {
            let mut env = environ();
            while !(*env).is_null() {
                if let Ok(text) = std::ffi::CStr::from_ptr(*env).to_str() {
                    out.push(text.to_owned());
                }
                env = env.add(1);
            }
        }
    }
    for binding in &environment.bindings {
        if let Some(value) = binding_text(plan, &binding.value) {
            out.retain(|line: &String| !line.starts_with(&format!("{}=", binding.name)));
            out.push(format!("{}={value}", binding.name));
        }
    }
    if let Some(bridge) = bridge {
        for (name, value) in bridge.environment() {
            out.retain(|line: &String| !line.starts_with(&format!("{name}=")));
            out.push(format!("{name}={value}"));
        }
    }
    out
}

/// One binding's value, as the child receives it: a literal, or a managed
/// root resolved to its host path.
fn binding_text(plan: &PreparedPlan, value: &crate::policy::EnvValue) -> Option<String> {
    match value {
        crate::policy::EnvValue::Native(native) => {
            Some(String::from_utf8_lossy(native.as_bytes()).into_owned())
        }
        crate::policy::EnvValue::Path(reference) => {
            let root = match reference.root {
                crate::policy::RootToken::Host => PathBuf::new(),
                crate::policy::RootToken::Workspace => plan.workspace.clone(),
                crate::policy::RootToken::Scratch => plan.attempt_dir.join("scratch"),
                crate::policy::RootToken::VendorState => plan.attempt_dir.join("vendor-state"),
            };
            Some(
                root.join(OsString::from_vec(reference.path.as_bytes().to_vec()))
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
}

/// `kern.maxprocperuid`: the table capacity's input (§4.1 rule 6). A kernel
/// that does not answer leaves the table at its clamp.
fn maxprocperuid() -> usize {
    const NAME: &[u8] = b"kern.maxprocperuid\0";
    let mut value: i32 = 0;
    let mut size = std::mem::size_of::<i32>();
    // SAFETY: plain sysctlbyname with a fixed, kernel-known name.
    unsafe {
        if libc::sysctlbyname(
            NAME.as_ptr().cast(),
            std::ptr::from_mut(&mut value).cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return 1;
        }
    }
    value.max(1) as usize
}

/// The SBPL parameters (§4.7, §4.10): the snapshot's resolved roots, the
/// `--from-path` pins and the bridge's ports. The setuid scan covers the
/// readable roots (§4.7 class 3: scanned at preparation).
fn profile_params(
    plan: &PreparedPlan,
    bridge: Option<&BridgeConfig>,
) -> Result<ProfileParams, JailError> {
    let snapshot = &plan.request.snapshot;
    if snapshot.filesystem.protected_coverage == crate::policy::ProtectedCoverage::AllDescendants {
        return Err(refusal(
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Preparing,
            Remediation::Unsupported,
            "native protected segments currently cover existing directories and their roots; all_descendants is unavailable",
        ));
    }
    let scratch = match &snapshot.roots.scratch {
        crate::policy::ScratchRoot::Managed => plan.attempt_dir.join("scratch"),
        crate::policy::ScratchRoot::Host { path } => native_path(path),
    };
    if matches!(snapshot.roots.scratch, crate::policy::ScratchRoot::Managed) {
        std::fs::create_dir_all(&scratch)
            .map_err(|error| spawn_error(&format!("create scratch: {error}")))?;
    }
    std::fs::create_dir_all(plan.attempt_dir.join("vendor-state"))
        .map_err(|e| profile_error(format!("create empty vendor root: {e}")))?;
    let resolve = |reference: &crate::policy::PathRef| -> Result<PathBuf, JailError> {
        use crate::policy::RootToken;
        let suffix = native_path(&reference.path);
        let path = match reference.root {
            RootToken::Host => suffix,
            RootToken::Workspace => plan.workspace.join(suffix),
            RootToken::Scratch => scratch.join(suffix),
            RootToken::VendorState => plan.attempt_dir.join("vendor-state").join(suffix),
        };
        Ok(path)
    };
    let mut params = ProfileParams {
        read_write: snapshot
            .filesystem
            .read_write
            .iter()
            .map(resolve)
            .collect::<Result<_, _>>()?,
        read_only: snapshot
            .filesystem
            .read_only
            .iter()
            .map(resolve)
            .collect::<Result<_, _>>()?,
        deny_read: snapshot
            .filesystem
            .deny_read
            .iter()
            .map(resolve)
            .collect::<Result<_, _>>()?,
        ..ProfileParams::default()
    };
    params.read_only.extend(seatbelt::runtime_roots());
    // The launcher must execute inside the boundary before it can release
    // the target. This admits this binary only, never its parent directory.
    params
        .read_only
        .push(std::env::current_exe().map_err(|_| spawn_error("current_exe"))?);
    params
        .read_only
        .extend(plan.pinned_roots.iter().map(|pin| pin.path.clone()));
    for root in &params.read_write {
        params.protected_segments.extend(protected_paths(
            root,
            &snapshot.filesystem.protected_segments,
        )?);
    }
    params.read_only.sort();
    params.read_only.dedup();
    params.protected_segments.sort();
    params.protected_segments.dedup();
    // Validate before walking paths: byte paths must never become lossy grants.
    seatbelt::try_generate(&params).map_err(profile_error)?;
    let roots: Vec<_> = params
        .read_only
        .iter()
        .chain(&params.read_write)
        .cloned()
        .collect();
    let scan = crate::platform::macos::setuid::scan_readable_roots_report(&roots);
    params.setuid_exec_denied = crate::platform::macos::setuid::deny_paths(&scan.entries);
    params.setuid_scan_holes = scan.holes;
    if let Some(bridge) = bridge {
        params.bridge_http_port = Some(bridge.http_port);
        params.bridge_socks_port = Some(bridge.socks_port);
    }
    seatbelt::try_generate(&params).map_err(profile_error)?;
    Ok(params)
}

fn native_path(native: &NativeString) -> PathBuf {
    PathBuf::from(OsString::from_vec(native.as_bytes().to_vec()))
}

fn profile_error(message: String) -> JailError {
    refusal(
        ErrorCode::InvalidConfig,
        ErrorStage::Preparing,
        Remediation::Configuration,
        message,
    )
}

/// Existing-and-root coverage: deny each suffix at the root and at every
/// existing directory, without following directory symlinks. Future deep
/// directories are not claimed (all_descendants refuses above).
fn protected_paths(root: &Path, segments: &[String]) -> Result<Vec<PathBuf>, JailError> {
    if segments.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<_> = segments.iter().map(|segment| root.join(segment)).collect();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| profile_error(format!("protected scan {dir:?}: {e}")))?
        {
            let entry = entry.map_err(|e| profile_error(format!("protected scan: {e}")))?;
            let path = entry.path();
            if segments
                .iter()
                .any(|segment| path.ends_with(Path::new(segment)))
            {
                out.push(path);
            } else if entry
                .file_type()
                .map_err(|e| profile_error(format!("protected scan: {e}")))?
                .is_dir()
            {
                pending.push(path);
            }
        }
    }
    Ok(out)
}

fn working_dir(plan: &PreparedPlan) -> Result<String, JailError> {
    let utf8 = |what: &'static str, native: &NativeString| -> Result<String, JailError> {
        std::str::from_utf8(native.as_bytes())
            .map(str::to_owned)
            .map_err(|_| {
                refusal(
                    ErrorCode::InvalidConfig,
                    ErrorStage::Preparing,
                    Remediation::Configuration,
                    format!("{what} is not UTF-8; the macOS launch block is text"),
                )
            })
    };
    let workspace = utf8("the workspace path", &plan.request.snapshot.roots.workspace)?;
    let cwd = utf8("the working directory", &plan.request.snapshot.roots.cwd)?;
    if cwd.is_empty() {
        Ok(workspace)
    } else {
        Ok(Path::new(&workspace)
            .join(cwd)
            .to_string_lossy()
            .into_owned())
    }
}

/// The receipt's `applied` group (§4.8): the seatbelt profile, the bridge's
/// ports, the terminal relay when attached. The profile's digest and the
/// generated parameters ride in the native lifetime details.
fn build_applied(
    plan: &PreparedPlan,
    params: &ProfileParams,
    bridge: Option<&BridgeConfig>,
    terminal: bool,
) -> Applied {
    let snapshot = &plan.request.snapshot;
    let mut mounts = Vec::new();
    let mut push = |bytes: &[u8], mode: &str| {
        if let Ok(native) = NativeString::from_bytes(bytes.to_vec()) {
            mounts.push(AppliedMount {
                path: native,
                mode: mode.to_owned(),
            });
        }
    };
    for (paths, mode) in [
        (&params.read_write, "rw"),
        (&params.read_only, "ro"),
        (&params.deny_read, "deny"),
    ] {
        for path in paths {
            push(path.as_os_str().as_encoded_bytes(), mode);
        }
    }
    let mut environment_names: Vec<String> = snapshot
        .environment
        .bindings
        .iter()
        .map(|binding| binding.name.clone())
        .collect();
    if let Some(bridge) = bridge {
        for (name, _) in bridge.environment() {
            environment_names.push(name.to_owned());
        }
    }
    environment_names.sort();
    environment_names.dedup();
    Applied {
        filesystem: Some(AppliedFilesystem {
            mechanism: "seatbelt_profile".to_owned(),
            protected_coverage: snapshot.filesystem.protected_coverage.as_str().to_owned(),
            mounts,
        }),
        network: AppliedNetwork {
            mode: snapshot.network.mode.as_str().to_owned(),
            mechanism: Some(if bridge.is_some() {
                "loopback_bridge".to_owned()
            } else {
                "seatbelt-deny-network".to_owned()
            }),
            allowed_hosts: snapshot.network.allow.clone(),
            tls_only: snapshot.network.tls_only.clone(),
        },
        syscalls: None,
        limits: limit_rows(&snapshot.limits),
        environment_names,
        removed_environment_names: Vec::new(),
        terminal: terminal.then(|| AppliedTerminal {
            device: "pty".to_owned(),
            session: crate::platform::macos::relay::RELAY_SESSION.to_owned(),
            process_group: "own".to_owned(),
            stops: 0,
            restored: None,
        }),
    }
}

/// Preserve every requested ceiling, including preferred limits this tier
/// cannot enforce. Only the wall is applied; headroom rlimits are not policy
/// tree ceilings and must never be reported as such.
fn limit_rows(limits: &crate::policy::LimitsSnapshot) -> Vec<AppliedLimit> {
    crate::policy::LimitKey::ALL
        .into_iter()
        .filter_map(|key| {
            let ceiling = limits.get(key)?;
            let applied = key == crate::policy::LimitKey::Wall;
            Some(AppliedLimit {
                key: key.as_str().to_owned(),
                requested: ceiling.value.clone(),
                required: ceiling.required,
                applied,
                mechanism: applied.then(|| "both-custodians-continuous-clock".to_owned()),
                scope: applied.then(|| "tree".to_owned()),
                hit: applied.then_some(false),
            })
        })
        .collect()
}

/// The audit-token identity's fields (§4.8): the pid and pid version ride in
/// the token's last two words (`audit_token_t`), the boot session is the
/// kernel's.
fn audit_token_value(token: Token) -> serde_json::Map<String, serde_json::Value> {
    let mut value = serde_json::Map::new();
    value.insert(
        "pid".to_owned(),
        serde_json::Value::from(token[AUDIT_TOKEN_PID]),
    );
    value.insert(
        "pidversion".to_owned(),
        serde_json::Value::from(token[AUDIT_TOKEN_PIDVERSION]),
    );
    value.insert(
        "boot_session".to_owned(),
        serde_json::Value::from(record::boot_session_uuid()),
    );
    value.insert(
        "token".to_owned(),
        serde_json::Value::from(
            token
                .iter()
                .map(|word| format!("{word:08x}"))
                .collect::<String>(),
        ),
    );
    value
}

// ---------------------------------------------------------------------------
// The B-pipe frames: what the guardian writes (§4.3)
// ---------------------------------------------------------------------------

/// One frame from B. `decode_frame` reads A's grammar, so B has its own
/// reader: `ready` (step 3), `token-seen` (step 5) and the final
/// `record ` + JSON (§4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BFrame {
    Ready,
    TokenSeen,
    Record(Vec<u8>),
}

/// The length-prefixed reader over B.
#[derive(Default)]
struct BReader {
    buffer: Vec<u8>,
}

impl BReader {
    /// Push one read's bytes; returns every complete frame. The grammar is
    /// fixed by `guardian::frames`; a malformed prefix stops the run rather
    /// than guessing.
    fn feed(&mut self, bytes: &[u8]) -> Result<Vec<BFrame>, JailError> {
        self.buffer.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                return Ok(out);
            }
            let length = u32::from_le_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err(spawn_error("invalid guardian frame length"));
            }
            if self.buffer.len() < 4 + length {
                return Ok(out);
            }
            let payload: Vec<u8> = self.buffer.drain(..4 + length).collect();
            let frame = match &payload[4..] {
                b"ready" => BFrame::Ready,
                b"token-seen" => BFrame::TokenSeen,
                json if json.starts_with(b"record ") => BFrame::Record(json[7..].to_vec()),
                _ => {
                    return Err(refusal(
                        ErrorCode::BackendUnavailable,
                        ErrorStage::Preparing,
                        Remediation::InspectState,
                        "the guardian sent a frame the B grammar does not define",
                    ));
                }
            };
            out.push(frame);
        }
    }
}

// ---------------------------------------------------------------------------
// prepare: §4.3 steps 1–5
// ---------------------------------------------------------------------------

/// The one prepared macOS boundary.
pub struct MacosPrepared {
    client: Option<CustodyClient>,
    engine: Custodian,
    a_write: RawFd,
    r_write: Fd,
    b_read: Fd,
    e_read: Fd,
    guardian: GuardianProcess,
    launcher_token: Token,
    process: ProcessRecord,
    applied: Applied,
    wall_ms: Option<u64>,
    relay: Option<TerminalRelay>,
    headroom: u64,
    profile_params: ProfileParams,
    handshake_events: Vec<es::EsPoll>,
    /// The outside proxy, the sink that tallies its results, and the
    /// loopback relay to it (§4.10); `None` without a proxy-mode network.
    proxy: Option<crate::proxy::ProxyHandle>,
    proxy_sink: Option<std::sync::Arc<crate::proxy::coverage::TraceSink>>,
    serving: Option<bridge::Serving>,
}

/// Staging is unavailable until the native copy/trust/placeholder pipeline
/// is implemented. Refuse even callers that bypass capability derivation.
fn require_supported_staging(plan: &PreparedPlan) -> Result<(), JailError> {
    if plan
        .request
        .requirements
        .contains(&crate::capability::Requirement::CredentialStaging)
        || plan.request.snapshot.roots.vendor_state.is_some()
        || plan.launch.as_ref().is_some_and(|launch| {
            !launch.binds.is_empty() || !launch.vault.is_empty() || launch.vendor_state.is_some()
        })
    {
        return Err(refusal(
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Preparing,
            Remediation::Unsupported,
            "native credential and vendor-state staging is unavailable",
        ));
    }
    Ok(())
}

/// The supervisor's side of `Platform::prepare` (§4.3 steps 1–5).
///
/// # Errors
/// The refusal of the step that failed; an error return leaves no boundary
/// behind (the handshake paths close their own pipes and reap their own
/// guardian).
pub fn prepare(plan: PreparedPlan, sinks: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
    // J18: a kernel-bound lifetime is the VM tier's (§6). `--vm` never
    // reaches the native prepare through the run's own selection; if a
    // kernel-bound requirement still arrives here, the flag named it.
    if plan.request.snapshot.lifetime_boundary.is_some() {
        return Err(refusal(
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Preparing,
            Remediation::Unsupported,
            "--vm is required for a kernel-bound lifetime; the native custody tier does not \
             provide one",
        ));
    }
    super::require_native_enabled()?;
    require_supported_staging(&plan)?;
    let budget = plan.prepare_deadline;
    if budget.remaining().is_zero() {
        return Err(refusal(
            ErrorCode::PrepareTimeout,
            ErrorStage::Preparing,
            Remediation::Retry,
            "preparation did not complete within its budget: it was spent before the boundary \
             was built",
        ));
    }
    // Step 1: client S, before any other process of the attempt exists.
    let client = create_client_s()?;

    // Step 2: the applied resources, then the record, the pipes and the
    // launch block. A failure past this point tears the client down.
    let wants_terminal =
        plan.request.snapshot.terminal == Some(crate::policy::TerminalMode::Attached);
    let mut relay = if wants_terminal {
        match TerminalRelay::allocate(0) {
            Ok(relay) => Some(relay),
            Err(error) => {
                let _ = client.delete();
                return Err(refusal(
                    ErrorCode::InvalidFd,
                    ErrorStage::Preparing,
                    Remediation::Configuration,
                    format!("the terminal relay could not allocate a pty: {error}"),
                ));
            }
        }
    } else {
        None
    };
    let (bridge_bound, bridge_config) =
        if plan.request.snapshot.network.mode == crate::network::NetworkMode::Proxy {
            match bridge::bind(crate::proxy::ProxyAuth::generate()) {
                Ok(bound) => {
                    let config = bound.config.clone();
                    (Some(bound), Some(config))
                }
                Err(error) => {
                    let _ = client.delete();
                    return Err(refusal(
                        ErrorCode::InvalidFd,
                        ErrorStage::Preparing,
                        Remediation::InspectState,
                        format!("the loopback bridge could not bind: {error}"),
                    ));
                }
            }
        } else {
            (None, None)
        };

    let built = build_and_spawn(&plan, relay.as_mut(), bridge_config.as_ref());
    if let Err(error) = built {
        let _ = client.delete();
        return Err(error);
    }
    let mut built = built.expect("checked above");

    // Steps 3–5: the handshake, within the preparation budget.
    let mut handshake = match handshake(
        &client,
        &mut built.b_read,
        &mut built.e_read,
        built.pipe_a_write.0,
        &mut built.guardian,
        &budget,
    ) {
        Ok(handshake) => handshake,
        Err(error) => {
            built.pipe_r_write.close();
            abort_guardian(&mut built.guardian, built.pipe_a_write.take_fd());
            let _ = client.delete();
            return Err(error);
        }
    };

    let capacity = crate::platform::macos::custody::table_capacity(maxprocperuid());
    let engine = (|| {
        let supervisor =
            es::self_token().ok_or_else(|| spawn_error("cannot read supervisor audit token"))?;
        let engine = supervisor_custody(
            capacity,
            handshake.launcher_token,
            supervisor,
            built
                .guardian
                .pid
                .expect("handshake retained the guardian child"),
            &mut handshake.events,
            client.ring_overflowed(),
        )?;
        if engine.gapped()
            || engine.integrity_loss()
            || !engine.contains_token(&handshake.launcher_token)
        {
            return Err(spawn_error(
                "the supervisor could not verify the launcher's custody stream",
            ));
        }
        Ok(engine)
    })();
    let engine = match engine {
        Ok(engine) => engine,
        Err(error) => {
            built.pipe_r_write.close();
            abort_guardian(&mut built.guardian, built.pipe_a_write.take_fd());
            let _ = client.delete();
            return Err(error);
        }
    };
    let process = ProcessRecord {
        pid: handshake.launcher_token[AUDIT_TOKEN_PID],
        identity: ProcessIdentity {
            kind: "macos_audit_token".to_owned(),
            value: audit_token_value(handshake.launcher_token),
        },
    };
    // The outside proxy on the attempt's private socket, and the loopback
    // relay to it (§4.10): policy and secret are enforced at the proxy.
    // Vault requests refuse before reaching this raw transport.
    let (proxy, proxy_sink, serving) = match bridge_bound {
        Some(bound) => {
            let started = start_proxy(&plan, &sinks, &bound);
            match started {
                Ok(started) => (Some(started.0), Some(started.1), Some(started.2)),
                Err(error) => {
                    built.pipe_r_write.close();
                    abort_guardian(&mut built.guardian, built.pipe_a_write.take_fd());
                    let _ = client.delete();
                    return Err(error);
                }
            }
        }
        None => (None, None, None),
    };
    Ok(Box::new(MacosPrepared {
        client: Some(client),
        engine,
        a_write: built.pipe_a_write.take_fd(),
        r_write: built.pipe_r_write,
        b_read: built.b_read,
        e_read: built.e_read,
        guardian: built.guardian,
        launcher_token: handshake.launcher_token,
        process,
        applied: build_applied(
            &plan,
            &built.profile_params,
            bridge_config.as_ref(),
            relay.is_some(),
        ),
        profile_params: built.profile_params,
        wall_ms: plan
            .request
            .snapshot
            .limits
            .wall
            .as_ref()
            .and_then(|wall| wall.value.parse::<u64>().ok()),
        relay,
        headroom: u64::from(NPROC_HEADROOM),
        handshake_events: handshake.events,
        proxy,
        proxy_sink,
        serving,
    }))
}

/// Starts the outside proxy on the attempt's private socket and the
/// loopback relay to it (§4.10): the child's proxy URLs name the two
/// loopback ports, the relay carries them to the proxy, and the proxy holds
/// the policy and the per-attempt secret. Vault staging is unavailable.
fn start_proxy(
    plan: &PreparedPlan,
    sinks: &Sinks,
    bound: &bridge::Bound,
) -> Result<
    (
        crate::proxy::ProxyHandle,
        std::sync::Arc<crate::proxy::coverage::TraceSink>,
        bridge::Serving,
    ),
    JailError,
> {
    let Some(handoff) = &plan.proxy else {
        return Err(refusal(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            "a proxy-mode network without a registered proxy directory",
        ));
    };
    let socket_path = handoff
        .host_path
        .join(crate::state::proxy_dir::PROXY_SOCKET_NAME);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).map_err(|error| {
        refusal(
            ErrorCode::InvalidFd,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the proxy socket could not be bound: {error}"),
        )
    })?;
    // For the supervisor to record, so `gc` can recognise this node after a
    // crash, as on Linux (§10).
    if let Ok(stat) = crate::state::anchored::fstat(listener.as_fd()) {
        let _ = handoff
            .socket
            .set(crate::state::ProxySocketIdentity::of(&stat));
    }
    let rules = plan
        .request
        .snapshot
        .network
        .proxy_rules()
        .map_err(|error| {
            refusal(
                ErrorCode::InvalidConfig,
                ErrorStage::Preparing,
                Remediation::Configuration,
                format!("the proxy rules do not parse: {error}"),
            )
        })?;
    // The vault's process binding is the attempt's here (§4.11 decision 4):
    // every member that holds the proxy secret may use the credential.
    let secrets = plan
        .launch
        .as_ref()
        .map_or_else(Vec::new, |launch| launch.vault.clone());
    let vault = (!secrets.is_empty())
        .then(|| {
            crate::vault::Vault::new(&plan.attempt_id, secrets).map_err(|error| {
                refusal(
                    ErrorCode::CredentialUnavailable,
                    ErrorStage::Preparing,
                    Remediation::Configuration,
                    format!("the vault could not be built: {error}"),
                )
            })
        })
        .transpose()?
        .map(std::sync::Arc::new);
    let sink = std::sync::Arc::new(crate::proxy::coverage::TraceSink::new(
        &plan.attempt_id,
        sinks.trace.clone(),
    ));
    // The resolver's in-flight bound, as the Linux bridge's (§10).
    const RESOLVER_IN_FLIGHT: usize = 16;
    let config = crate::proxy::ProxyConfig {
        listener,
        rules,
        budgets: crate::proxy::Budgets::default(),
        resolver: std::sync::Arc::new(crate::proxy::SystemResolver::new(RESOLVER_IN_FLIGHT)),
        auth: Some(bound.config.auth.clone()),
    };
    let proxy = crate::proxy::start_with_vault(config, sink.clone(), vault).map_err(|error| {
        refusal(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the outside proxy could not be started: {error}"),
        )
    })?;
    let serving = bridge::serve(
        bridge::Bound {
            http: bound.http.try_clone().map_err(|error| {
                refusal(
                    ErrorCode::InvalidFd,
                    ErrorStage::Preparing,
                    Remediation::InspectState,
                    format!("the HTTP listener could not be shared: {error}"),
                )
            })?,
            socks: bound.socks.try_clone().map_err(|error| {
                refusal(
                    ErrorCode::InvalidFd,
                    ErrorStage::Preparing,
                    Remediation::InspectState,
                    format!("the SOCKS listener could not be shared: {error}"),
                )
            })?,
            config: bound.config.clone(),
        },
        &socket_path,
    )
    .map_err(|error| {
        refusal(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the loopback relay could not be started: {error}"),
        )
    })?;
    Ok((proxy, sink, serving))
}

/// Everything the spawn created, for the handshake.
struct Spawned {
    b_read: Fd,
    e_read: Fd,
    pipe_a_write: Fd,
    pipe_r_write: Fd,
    profile_params: ProfileParams,
    guardian: GuardianProcess,
}

fn build_and_spawn(
    plan: &PreparedPlan,
    mut relay: Option<&mut TerminalRelay>,
    bridge: Option<&BridgeConfig>,
) -> Result<Spawned, JailError> {
    let record_path = plan.attempt_dir.join("guardian-record.json");
    std::fs::write(&record_path, b"").map_err(|error| {
        refusal(
            ErrorCode::StateWriteFailed,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the guardian record could not be created: {error}"),
        )
    })?;
    let mut pipe_a = Pipe::new()?;
    let mut pipe_b = Pipe::new()?;
    let mut pipe_r = Pipe::new()?;
    let mut pipe_e = Pipe::new()?;
    let b_read = Fd::nonblocking(pipe_b.take_read())?;
    let e_read = Fd::nonblocking(pipe_e.take_read())?;

    let exe = std::env::current_exe().map_err(|error| {
        refusal(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the executable's path could not be read: {error}"),
        )
    })?;
    let slave_fd = relay.as_deref().and_then(TerminalRelay::slave_fd);
    let sigmask = capture_mask();
    let launcher = launcher_argv(
        &exe,
        pipe_r.read,
        pipe_e.write,
        slave_fd,
        sigmask,
        &plan.argv,
    )?;
    let mut profile_params = profile_params(plan, bridge)?;
    profile_params.terminal_slave = relay.as_deref().map(|r| PathBuf::from(r.device()));
    let profile_source = seatbelt::try_generate(&profile_params).map_err(profile_error)?;
    let block = LaunchBlock {
        sandbox_exec_path: "/usr/bin/sandbox-exec".to_owned(),
        sbpl_profile_source: profile_source,
        child_argv: launcher,
        child_envp: child_envp(plan, bridge),
        working_dir: working_dir(plan)?,
        stdio: match slave_fd {
            // In terminal mode the relay's pty slave is the child's standard
            // descriptors (§4.11); the launcher takes it as controlling
            // terminal with TIOCSCTTY.
            Some(slave) => [
                FdAction::Fd(slave),
                FdAction::Fd(slave),
                FdAction::Fd(slave),
            ],
            None => [FdAction::Fd(0), FdAction::Fd(1), FdAction::Fd(2)],
        },
        // §4.2: the terminal signals the guardian ignores come back to their
        // default disposition, and the mask is the supervisor's inherited
        // one.
        sigdef: vec![
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGTSTP,
            libc::SIGTTIN,
            libc::SIGTTOU,
        ],
        sigmask,
        setsid: true,
        launcher_read_fd: pipe_r.read,
        launcher_error_fd: pipe_e.write,
        terminal: slave_fd.is_some(),
        grace_ms: u32::try_from(STOP_GRACE_NS / 1_000_000).unwrap_or(u32::MAX),
    };
    let block_path = plan.attempt_dir.join("launch-block");
    std::fs::write(&block_path, launch_block::encode(&block)).map_err(|error| {
        refusal(
            ErrorCode::StateWriteFailed,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the launch block could not be written: {error}"),
        )
    })?;
    // File::open handles the native path and sets CLOEXEC atomically.
    let block_fd = Fd(std::fs::File::open(&block_path)
        .map_err(|error| {
            refusal(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("the launch block could not be reopened: {error}"),
            )
        })?
        .into_raw_fd());

    let record_arg = record_path.to_str().ok_or_else(|| {
        refusal(
            ErrorCode::InvalidConfig,
            ErrorStage::Preparing,
            Remediation::Configuration,
            "the attempt directory's path is not UTF-8; the guardian argv is text",
        )
    })?;
    let args = vec![
        "__guardian".to_owned(),
        record_arg.to_owned(),
        pipe_a.read.to_string(),
        pipe_b.write.to_string(),
        pipe_r.read.to_string(),
        pipe_e.write.to_string(),
        block_fd.0.to_string(),
    ];
    let mut inherited = vec![
        pipe_a.read,
        pipe_b.write,
        pipe_r.read,
        pipe_e.write,
        block_fd.0,
    ];
    inherited.extend(slave_fd);
    let guardian_pid = spawn_self(&exe, &args, &inherited)?;
    // Pipe drops close EVERY child end. Only these four ends remain owned
    // by the supervisor; B/E EOF and R cancellation now have meaning.
    if let Some(relay) = relay.as_mut() {
        relay.close_slave();
    }
    Ok(Spawned {
        b_read,
        e_read,
        pipe_a_write: Fd(pipe_a.take_write()),
        pipe_r_write: Fd(pipe_r.take_write()),
        profile_params,
        guardian: GuardianProcess::new(guardian_pid),
    })
}

// ---------------------------------------------------------------------------
// The handshake (§4.3 steps 3–5)
// ---------------------------------------------------------------------------

/// What the handshake leaves behind.
struct Handshake {
    launcher_token: Token,
    // Retained in delivery order, consumed by replay after custodian registration.
    events: Vec<es::EsPoll>,
}

/// Register both custodians before replay, using G's first observed token so
/// its subsequent exec transitions remain part of the same sequenced stream.
fn supervisor_custody(
    capacity: usize,
    launcher: Token,
    supervisor: Token,
    guardian_pid: libc::pid_t,
    retained: &mut Vec<es::EsPoll>,
    overflowed: bool,
) -> Result<Custodian, JailError> {
    let guardian = retained
        .iter()
        .map(|poll| *poll.event.token())
        .find(|token| token[AUDIT_TOKEN_PID] as libc::pid_t == guardian_pid)
        .ok_or_else(|| spawn_error("the supervisor never observed the guardian's identity"))?;
    let mut engine = Custodian::new(capacity).with_stop(SETTLE_NS, STOP_BUDGET_NS);
    engine.expect_root(launcher[AUDIT_TOKEN_PID] as libc::pid_t);
    for token in [supervisor, guardian] {
        engine
            .register_custodian(token)
            .map_err(|_| spawn_error("cannot register custody identities"))?;
    }
    replay_retained(&mut engine, retained);
    if overflowed {
        engine.note_stream_gap();
    }
    Ok(engine)
}

fn replay_retained(engine: &mut Custodian, retained: &mut Vec<es::EsPoll>) {
    let events = std::mem::take(retained);
    engine.replay_handshake(&events);
}

fn apply_supervisor_event(
    engine: &mut Custodian,
    poll: &es::EsPoll,
    signaller: &mut dyn Signaller,
) {
    if engine.stop().begun() {
        engine.apply_polled_during_stop(poll, signaller);
    } else {
        engine.apply_polled(poll);
    }
}

fn handshake_timeout() -> JailError {
    refusal(
        ErrorCode::PrepareTimeout,
        ErrorStage::Preparing,
        Remediation::Retry,
        "the guardian did not complete the launch handshake within the preparation budget",
    )
}

/// Reaps an aborted preparation. Once reaped, the child handle cannot wait
/// for or signal a subsequently reused numeric PID.
fn abort_guardian(guardian: &mut GuardianProcess, pipe_a_write: RawFd) {
    // SAFETY: a plain close of a descriptor this process owns.
    unsafe { libc::close(pipe_a_write) };
    let deadline = Instant::now() + Duration::from_secs(1);
    while !guardian.poll() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    guardian.end();
}

/// The handshake of §4.3 steps 3–5, within the preparation budget.
fn handshake(
    client: &CustodyClient,
    b_read: &mut Fd,
    e_read: &mut Fd,
    pipe_a_write: RawFd,
    guardian: &mut GuardianProcess,
    budget: &ContinuousDeadline,
) -> Result<Handshake, JailError> {
    let deadline = Instant::now() + budget.remaining();
    let guardian_pid = guardian.pid.expect("the spawned guardian is still owned");
    let mut reader = BReader::default();
    // `ready` (step 3). A guardian that dies names its failing step on
    // stderr and its exit status here.
    let mut ready = false;
    let mut events = Vec::new();
    loop {
        for frame in read_b(&mut reader, b_read, guardian)? {
            match frame {
                BFrame::Ready => ready = true,
                other => {
                    return Err(refusal(
                        ErrorCode::BackendUnavailable,
                        ErrorStage::Preparing,
                        Remediation::InspectState,
                        format!("the guardian answered {other:?} before `ready`"),
                    ));
                }
            }
        }
        if ready {
            break;
        }
        if Instant::now() >= deadline {
            return Err(handshake_timeout());
        }
        client.drain(TICK_MS);
    }
    // The launcher's fork: the first event on S whose pid is not the
    // guardian's own (§4.2). The launcher's `blocked` on E rides alongside.
    let mut launcher_token: Option<Token> = None;
    let mut blocked_seen = false;
    let mut synced_after_block = false;
    loop {
        while let Some(poll) = client.poll_full() {
            track_launcher(&mut launcher_token, guardian_pid, &poll.event);
            events.push(poll);
        }
        if let Some(report) = read_e(e_read) {
            if report.is_empty() {
                // End-of-file on E before `blocked`: the launcher never ran.
                return Err(exec_report_refusal(&[]));
            }
            if crate::platform::macos::launcher::is_blocked_report(&report) {
                blocked_seen = true;
            } else if launcher_token.is_some() {
                // An exec report before `blocked` cannot happen in the
                // grammar; treat it as what it is, a failed launch.
                return Err(exec_report_refusal(&report));
            }
        }
        // A blocked launcher cannot exec again before R. Synchronize S
        // AFTER observing blocked, then consume the queued exec transitions,
        // so the token sent on A cannot still be sandbox-exec's/fork's token.
        if blocked_seen && !synced_after_block && client.drain(TICK_MS) {
            while let Some(poll) = client.poll_full() {
                track_launcher(&mut launcher_token, guardian_pid, &poll.event);
                events.push(poll);
            }
            if client.ring_overflowed() {
                return Err(spawn_error("custody overflow during the launch handshake"));
            }
            synced_after_block = true;
        }
        if let (Some(token), true) = (launcher_token, blocked_seen && synced_after_block) {
            // Step 5: the launcher's current token goes on A.
            write_frame(pipe_a_write, &encode_launcher_token(&token))?;
            loop {
                for frame in read_b(&mut reader, b_read, guardian)? {
                    if matches!(frame, BFrame::TokenSeen) {
                        return Ok(Handshake {
                            launcher_token: token,
                            events,
                        });
                    }
                }
                if Instant::now() >= deadline {
                    return Err(handshake_timeout());
                }
                client.drain(TICK_MS);
                while let Some(poll) = client.poll_full() {
                    events.push(poll);
                }
            }
        }
        // Continue decoding whole frames; never consume a byte just to
        // probe EOF (that would corrupt the next length prefix).
        if !read_b(&mut reader, b_read, guardian)?.is_empty() {
            return Err(spawn_error(
                "unexpected guardian frame before launcher token",
            ));
        }
        if Instant::now() >= deadline {
            return Err(handshake_timeout());
        }
        client.drain(TICK_MS);
    }
}

/// One bounded poll slice of B. Returns the frames that completed.
fn read_b(
    reader: &mut BReader,
    b_read: &mut Fd,
    guardian: &mut GuardianProcess,
) -> Result<Vec<BFrame>, JailError> {
    let mut buffer = [0u8; MAX_FRAME_BYTES + 4];
    match b_read.read(&mut buffer) {
        Ok(0) => {
            let code = guardian.exit_code();
            Err(refusal(
                ErrorCode::BackendUnavailable,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("the guardian exited during the handshake (exit {code})"),
            ))
        }
        Ok(n) => reader.feed(&buffer[..n]),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
        Err(error) => Err(refusal(
            ErrorCode::InvalidFd,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("read from B failed: {error}"),
        )),
    }
}

/// Select the first non-guardian child, then follow that pid's exec tokens.
fn track_launcher(current: &mut Option<Token>, guardian_pid: libc::pid_t, event: &EsEvent) {
    match *event {
        EsEvent::Fork { token }
            if current.is_none() && token[AUDIT_TOKEN_PID] as libc::pid_t != guardian_pid =>
        {
            *current = Some(token)
        }
        EsEvent::Exec { token }
            if current.is_some_and(|old| old[AUDIT_TOKEN_PID] == token[AUDIT_TOKEN_PID]) =>
        {
            *current = Some(token)
        }
        _ => {}
    }
}

/// One nonblocking read of E; `None` when nothing waits.
fn read_e(e_read: &mut Fd) -> Option<Vec<u8>> {
    let mut buffer = [0u8; 16];
    match e_read.read(&mut buffer) {
        Ok(0) => Some(Vec::new()),
        Ok(n) => Some(buffer[..n].to_vec()),
        Err(_) => None,
    }
}

/// A failed exec report on E (§4.3 step 7): the attempt is refused with the
/// Linux error pipe's distinctions (X04, review F5, J14).
fn exec_report_refusal(report: &[u8]) -> JailError {
    let (errno_name, detail) = crate::platform::macos::launcher::exec_failure_parts(report);
    let (code, message) = match detail {
        Some(detail) => (
            detail.error_code(),
            format!(
                "the target's exec failed ({errno_name}): {}",
                detail.explanation()
            ),
        ),
        None => (
            ErrorCode::ExecFailed,
            format!("the target's exec failed: {errno_name}"),
        ),
    };
    refusal(
        code,
        ErrorStage::Released,
        Remediation::Configuration,
        message,
    )
}

/// Writes one frame to A in full.
fn write_frame(fd: RawFd, payload: &[u8]) -> Result<(), JailError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(spawn_error("invalid supervisor frame length"));
    }
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload);
    write_bytes(fd, &frame)
}

fn write_bytes(fd: RawFd, frame: &[u8]) -> Result<(), JailError> {
    let mut written = 0usize;
    while written < frame.len() {
        // SAFETY: the buffer is live and only `written` past its start.
        let n = unsafe { libc::write(fd, frame[written..].as_ptr().cast(), frame.len() - written) };
        if n <= 0 {
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            return Err(refusal(
                ErrorCode::InvalidFd,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("write to A failed: {}", std::io::Error::last_os_error()),
            ));
        }
        written += n as usize;
    }
    Ok(())
}

/// A remains the guardian's liveness channel. R alone carries release.
fn release_launcher(
    a_write: RawFd,
    r_write: &mut Fd,
    deadline_ns: Option<u64>,
) -> Result<(), JailError> {
    let release = deadline_ns.map_or_else(encode_release_without_deadline, encode_release_deadline);
    write_frame(a_write, &release)?;
    write_bytes(r_write.0, b"L")?;
    r_write.close();
    Ok(())
}

/// The PID is a child ownership capability only until waitpid reaps it.
/// Keep the cached status separately; every later cleanup becomes a no-op.
struct GuardianProcess {
    pid: Option<libc::pid_t>,
    status: Option<i32>,
}

impl GuardianProcess {
    fn new(pid: libc::pid_t) -> Self {
        assert!(pid > 0);
        Self {
            pid: Some(pid),
            status: None,
        }
    }

    fn poll(&mut self) -> bool {
        self.poll_with(&mut wait_guardian)
    }

    fn poll_with(
        &mut self,
        wait: &mut impl FnMut(libc::pid_t, bool) -> std::io::Result<Option<i32>>,
    ) -> bool {
        let Some(pid) = self.pid else {
            return true;
        };
        match wait(pid, true) {
            Ok(None) => false,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => false,
            Ok(status) => {
                self.status = status;
                self.pid = None;
                true
            }
            Err(_) => {
                self.pid = None;
                true
            }
        }
    }

    fn exit_code(&mut self) -> i32 {
        self.poll();
        self.status
            .filter(|status| libc::WIFEXITED(*status))
            .map_or(-1, |status| libc::WEXITSTATUS(status))
    }

    fn end(&mut self) -> bool {
        self.end_with(&mut wait_guardian, &mut |pid| {
            // SAFETY: only an owned, unreaped direct child reaches this call.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }

    fn end_with(
        &mut self,
        wait: &mut impl FnMut(libc::pid_t, bool) -> std::io::Result<Option<i32>>,
        kill: &mut impl FnMut(libc::pid_t) -> std::io::Result<()>,
    ) -> bool {
        if self.poll_with(wait) {
            return false;
        }
        let pid = self.pid.expect("poll kept ownership of the live child");
        if kill(pid).is_err() {
            return false;
        }
        loop {
            match wait(pid, false) {
                Ok(None) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(status) => {
                    self.status = status;
                    break;
                }
                Err(_) => break,
            }
        }
        self.pid = None;
        true
    }
}

fn wait_guardian(pid: libc::pid_t, nonblocking: bool) -> std::io::Result<Option<i32>> {
    let mut status = 0;
    // SAFETY: wait only for the positive PID of this owned direct child.
    let reaped = unsafe {
        libc::waitpid(
            pid,
            &mut status,
            if nonblocking { libc::WNOHANG } else { 0 },
        )
    };
    if reaped < 0 {
        Err(std::io::Error::last_os_error())
    } else if reaped == 0 {
        Ok(None)
    } else {
        Ok(Some(status))
    }
}

// ---------------------------------------------------------------------------
// PreparedExecution
// ---------------------------------------------------------------------------

impl PreparedExecution for MacosPrepared {
    fn boundary(&self) -> BoundaryIdentity {
        let mut details = serde_json::Map::new();
        details.insert(
            "custody".to_owned(),
            serde_json::Value::from("es_descendants"),
        );
        details.insert("defense".to_owned(), serde_json::Value::from("seatbelt"));
        details.insert("native_execution".to_owned(), serde_json::json!("dev"));
        details.insert(
            "profile_digest".to_owned(),
            serde_json::json!(seatbelt::template_digest()),
        );
        details.insert(
            "profile_parameters".to_owned(),
            self.profile_params.receipt(),
        );
        details.insert(
            "handshake_events_pending".to_owned(),
            serde_json::Value::from(self.handshake_events.len()),
        );
        details.insert(
            "process_headroom".to_owned(),
            serde_json::Value::from(self.headroom),
        );
        BoundaryIdentity {
            boundary: BoundaryKind::NativeTree,
            verification_scope: VerificationScope::AttemptTree,
            native: Some(NativeLifetime {
                os: Os::Macos,
                details,
            }),
            process: Some(self.process.clone()),
            // The backend is this binary's native tier; the version is the
            // crate's own, as `bubblewrap` names the Linux backend's program
            // and this names the binary that is both custodian.
            backend: Some("ukai-jail-macos".to_owned()),
            backend_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        }
    }

    fn applied(&self) -> Option<Applied> {
        Some(self.applied.clone())
    }

    fn release(
        self: Box<Self>,
    ) -> Result<Box<dyn crate::platform::RunningExecution>, Box<ReleaseFailure>> {
        self.release_inner()
            .map(|running| Box::new(running) as Box<dyn crate::platform::RunningExecution>)
    }

    fn abort(mut self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(self.abort_inner())
    }
}

impl MacosPrepared {
    fn release_inner(mut self) -> Result<MacosRunning, Box<ReleaseFailure>> {
        // §4.3 step 6: the release deadline on A, then the release byte on
        // R. The deadline is continuous-clock nanoseconds; both custodians
        // arm their wall from release, and it counts sleep.
        let release_ns = es::continuous_time_ns();
        let deadline_ns = self.wall_ms.map(|ms| {
            release_ns
                .saturating_add(ms.saturating_mul(1_000_000))
                .min(NO_DEADLINE - 1)
        });
        let fail = |error: JailError, teardown: Teardown| {
            Box::new(ReleaseFailure {
                error,
                teardown: Some(teardown),
            })
        };
        if let Err(error) = release_launcher(self.a_write, &mut self.r_write, deadline_ns) {
            return Err(fail(
                error.in_stage(ErrorStage::Released),
                self.abort_inner(),
            ));
        }
        Ok(MacosRunning::from_prepared(self, release_ns))
    }

    /// Tears the prepared boundary down without running the target: A's
    /// end-of-file is the guardian's stop, and the blocked launcher — the
    /// only member — is killed by token like any other (§4.5, §4.3).
    fn abort_inner(&mut self) -> Teardown {
        self.r_write.close();
        if self.a_write >= 0 {
            // SAFETY: a plain close of a descriptor this process owns.
            unsafe { libc::close(self.a_write) };
            self.a_write = -1;
        }
        self.engine.begin_stop(es::continuous_time_ns());
        let _ = es::signal_by_token(&self.launcher_token, libc::SIGKILL);
        let tree = self.settle_guardian(GUARDIAN_TAIL);
        if let Some(client) = self.client.take() {
            let _ = client.delete();
        }
        Teardown { tree }
    }

    /// The live client, until [`MacosPrepared::abort_inner`] deletes it.
    fn custody(&self) -> &CustodyClient {
        self.client
            .as_ref()
            .expect("the client is deleted only at teardown")
    }

    fn settle_guardian(&mut self, tail: Duration) -> Option<TreeObservation> {
        let deadline = Instant::now() + tail;
        let mut reader = BReader::default();
        let mut record = None;
        let mut own = None;
        loop {
            if !self.custody().drain(TICK_MS) {
                self.engine.note_stream_gap();
            }
            while let Some(poll) = self.custody().poll_full() {
                apply_supervisor_event(&mut self.engine, &poll, &mut EsSignaller);
            }
            if self.custody().ring_overflowed() {
                self.engine.note_stream_gap();
            }
            if own.is_none() {
                own = self.engine.tick(es::continuous_time_ns(), &mut EsSignaller);
            }
            let mut buffer = [0u8; MAX_FRAME_BYTES + 4];
            match self.b_read.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if receive_guardian_record(&mut reader, &buffer[..n], &mut record).is_err() {
                        break;
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
            if record.is_some()
                || own.is_some_and(|result| result.drained())
                || self.guardian.poll()
                || Instant::now() >= deadline
            {
                break;
            }
        }
        self.guardian.end();
        let guardian_integrity = record
            .as_ref()
            .and_then(|r| r.get("reason"))
            .and_then(serde_json::Value::as_str)
            == Some("integrity");
        let integrity = self.engine.integrity_loss() || guardian_integrity;
        let guardian_drained = record
            .as_ref()
            .and_then(|r| r.get("drained"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        let drained = own.is_some_and(|result| result.drained()) || guardian_drained;
        let tree_empty = (!integrity && drained).then_some(true);
        Some(TreeObservation {
            tree_empty,
            verified_at: tree_empty.map(|_| SystemTime::now()),
            verification_scope: VerificationScope::AttemptTree,
            integrity: if tree_empty == Some(true) {
                Integrity::Verified
            } else if integrity {
                Integrity::Lost
            } else {
                Integrity::Pending
            },
        })
    }
}

// ---------------------------------------------------------------------------
// The running execution: §4.4–§4.6
// ---------------------------------------------------------------------------

/// The supervisor's custodian state while the target runs.
struct MacosRunning {
    client: Option<CustodyClient>,
    engine: Custodian,
    a_write: RawFd,
    b_read: Fd,
    e_read: Fd,
    b_reader: BReader,
    guardian: GuardianProcess,
    guardian_record: Option<serde_json::Value>,
    guardian_lost: bool,
    guardian_stalled: bool,
    /// J16 §4.6: custodian errors found during the stop, drained into the
    /// settled receipt's `errors[]`.
    custodian_errors: Vec<crate::records::JailError>,
    /// Whether the guardian's loss already reached the run loop as an event,
    /// so the settlement drain does not name it twice.
    loss_reported: bool,
    launcher_token: Token,
    target_token: Option<Token>,
    exec_confirmed: bool,
    release_ns: u64,
    wall_ns: u64,
    wall_expired: bool,
    settled_at_ns: Option<u64>,
    limits: Vec<AppliedLimit>,
    stop: Option<StopDrive>,
    stop_result: Option<StopResult>,
    integrity_lost: bool,
    events: u64,
    peak_members: usize,
    relay: Option<TerminalRelay>,
    target_was_stopped: bool,
    headroom: u64,
    profile_params: ProfileParams,
    handshake_events: Vec<es::EsPoll>,
    /// The outside proxy, its tally, and the loopback relay (§4.10).
    proxy: Option<crate::proxy::ProxyHandle>,
    proxy_sink: Option<std::sync::Arc<crate::proxy::coverage::TraceSink>>,
    serving: Option<bridge::Serving>,
}

/// The cooperative grace, then the stop (§4.5).
struct StopDrive {
    reason: StopReason,
    grace_ends_ns: u64,
    begun: bool,
}

impl MacosRunning {
    fn from_prepared(prepared: MacosPrepared, release_ns: u64) -> Self {
        let events = prepared.engine.seq().counts().into_iter().sum();
        let peak_members = prepared.engine.live_count();
        Self {
            client: prepared.client,
            engine: prepared.engine,
            a_write: prepared.a_write,
            b_read: prepared.b_read,
            e_read: prepared.e_read,
            b_reader: BReader::default(),
            guardian: prepared.guardian,
            guardian_record: None,
            guardian_lost: false,
            guardian_stalled: false,
            custodian_errors: Vec::new(),
            loss_reported: false,
            launcher_token: prepared.launcher_token,
            target_token: None,
            exec_confirmed: false,
            release_ns,
            wall_ns: prepared
                .wall_ms
                .map_or(0, |ms| ms.saturating_mul(1_000_000)),
            wall_expired: false,
            settled_at_ns: None,
            limits: prepared.applied.limits,
            stop: None,
            stop_result: None,
            integrity_lost: false,
            events,
            peak_members,
            relay: prepared.relay,
            target_was_stopped: false,
            headroom: prepared.headroom,
            profile_params: prepared.profile_params,
            handshake_events: prepared.handshake_events,
            proxy: prepared.proxy,
            proxy_sink: prepared.proxy_sink,
            serving: prepared.serving,
        }
    }

    /// The live client, until [`MacosRunning::drop`] deletes it.
    fn custody(&self) -> &CustodyClient {
        self.client
            .as_ref()
            .expect("the client is deleted only at the end")
    }

    /// Whether the target's exit has been observed on S.
    fn target_ended(&self) -> bool {
        self.target_token
            .is_some_and(|token| !self.engine.contains_token(&token))
    }

    /// Applies one drained event to the engine; returns the run event it
    /// carries (the §4.3 step 7 and §4.4 mapping).
    fn apply_event(&mut self, poll: &es::EsPoll) -> Option<RunEvent> {
        let gapped = self.engine.gapped();
        self.events = self.events.saturating_add(1);
        apply_supervisor_event(&mut self.engine, poll, &mut EsSignaller);
        self.peak_members = self.peak_members.max(self.engine.live_count());
        let event = track_target(
            &poll.event,
            &self.launcher_token,
            &mut self.target_token,
            &mut self.exec_confirmed,
        );
        if let (Some(relay), Some(token)) = (&mut self.relay, self.target_token) {
            let _ = relay.set_workload_group(token[AUDIT_TOKEN_PID] as libc::pid_t);
        }
        if self.engine.integrity_loss() && !self.integrity_lost {
            self.integrity_lost = true;
            return Some(RunEvent::EvidenceLost {
                reason: "membership integrity lost (a member changed user or the membership \
                         table filled)"
                    .to_owned(),
                after_target_end: self.target_ended(),
            });
        }
        if self.engine.gapped() && !gapped {
            return Some(RunEvent::EvidenceLost {
                reason: "the custody stream lost sequence continuity".into(),
                after_target_end: self.target_ended(),
            });
        }
        event
    }

    /// Drains everything available on S, returning the first run event.
    fn drain_events(&mut self) -> Option<RunEvent> {
        let stopping = self.engine.stop().begun();
        let overflowed = self.custody().ring_overflowed();
        let sync_failed = stopping && !self.custody().drain(TICK_MS);
        let mut first = None;
        if overflowed || sync_failed {
            let was_gapped = self.engine.gapped();
            self.engine.note_stream_gap();
            if !was_gapped {
                first = Some(RunEvent::EvidenceLost {
                    reason: "the custody stream dropped messages or could not synchronize".into(),
                    after_target_end: self.target_ended(),
                });
            }
        }
        while let Some(poll) = self.custody().poll_full() {
            let event = self.apply_event(&poll);
            if first.is_none() {
                first = event;
            }
            if !stopping && first.is_some() {
                return first;
            }
        }
        if self.custody().ring_overflowed() {
            let was_gapped = self.engine.gapped();
            self.engine.note_stream_gap();
            if !was_gapped && first.is_none() {
                first = Some(RunEvent::EvidenceLost {
                    reason: "the custody stream dropped messages (ring overflow)".into(),
                    after_target_end: self.target_ended(),
                });
            }
        }
        first
    }

    /// One nonblocking read of E: a byte-carrying report is an exec failure;
    /// the success EOF and the late `blocked` sentinel report nothing.
    fn read_exec_report(&mut self) -> Option<RunEvent> {
        let mut buffer = [0u8; 16];
        match self.e_read.read(&mut buffer) {
            Ok(0) | Err(_) => None,
            Ok(n) => {
                let report = &buffer[..n];
                if crate::platform::macos::launcher::is_blocked_report(report) {
                    return None;
                }
                let (errno, detail) = crate::platform::macos::launcher::exec_failure_parts(report);
                Some(RunEvent::ExecError { errno, detail })
            }
        }
    }

    /// Reads frames from B, keeping the guardian's record and noticing a
    /// lost guardian (§4.6).
    fn poll_guardian(&mut self) {
        let mut buffer = [0u8; MAX_FRAME_BYTES + 4];
        match self.b_read.read(&mut buffer) {
            Ok(0) => {
                self.guardian_lost |=
                    self.guardian_record.is_none() || !self.b_reader.buffer.is_empty();
            }
            Ok(n) if !self.guardian_lost => {
                if let Err(()) = receive_guardian_record(
                    &mut self.b_reader,
                    &buffer[..n],
                    &mut self.guardian_record,
                ) {
                    self.guardian_lost = true;
                }
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => self.guardian_lost = true,
        }
        if self.guardian_lost {
            self.guardian_record = None;
        }
    }

    /// The wall on the continuous clock, which counts sleep (§4.3 step 6).
    fn wall_check(&mut self) -> Option<RunEvent> {
        if self.wall_expired || self.wall_ns == 0 {
            return None;
        }
        if es::continuous_time_ns() >= self.release_ns.saturating_add(self.wall_ns) {
            self.wall_expired = true;
            return Some(RunEvent::WallExpired);
        }
        None
    }

    /// Begins the supervisor's own stop: A closes (end-of-file is the
    /// guardian's stop, §4.3) and the engine's stop machine starts.
    fn begin_stop(&mut self) {
        if self.a_write >= 0 {
            // SAFETY: a plain close of a descriptor this process owns.
            unsafe { libc::close(self.a_write) };
            self.a_write = -1;
        }
        self.engine.begin_stop(es::continuous_time_ns());
    }

    /// Advances the stop one tick; `true` when it has ended (§4.5).
    fn tick_stop(&mut self) -> bool {
        if let Some(result) = self.engine.tick(es::continuous_time_ns(), &mut EsSignaller) {
            self.stop_result = Some(result);
            return true;
        }
        false
    }

    /// Ends an unreaped direct child that stalled at the stop. An exited,
    /// unreaped child keeps its pid reserved; never signal after reaping.
    fn end_stalled_guardian(&mut self) {
        if !self.guardian.end() {
            return;
        }
        self.guardian_stalled = true;
        // §4.6: the stall reaches the settled receipt's `errors[]`.
        self.custodian_errors.push(crate::records::JailError::new(
            crate::records::ErrorCode::CustodianStalled,
            crate::records::ErrorStage::Stopping,
            crate::records::Remediation::InspectState,
            "the guardian custodian stalled at the stop and was ended".to_owned(),
        ));
    }

    /// Settles the tree: the supervisor's drain, or the guardian's `record`
    /// result within the budget (§4.5 budget rules).
    fn settle(&mut self, budget: Duration) -> TreeObservation {
        let deadline = Instant::now() + budget;
        let already_begun = self.stop.as_ref().is_some_and(|stop| stop.begun);
        if !already_begun {
            self.begin_stop();
        }
        loop {
            let _ = self.drain_events();
            self.poll_guardian();
            if self.tick_stop() {
                break;
            }
            // The guardian's record is its stop's end (§4.4): settled from
            // it when the supervisor's own machine is still running.
            if self.guardian_record.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                self.end_stalled_guardian();
                break;
            }
            self.custody().drain(TICK_MS);
        }
        self.settled_tree()
    }

    /// Combine the completed custody results into the receipt's tree fact.
    fn settled_tree(&mut self) -> TreeObservation {
        self.settled_at_ns = Some(es::continuous_time_ns());
        // The tree is ended, so no member can connect again: the loopback
        // relay stops before the proxy is drained (§4.10).
        self.serving.take();
        // §4.6: a guardian lost during the stop, without the mid-run event,
        // still names itself in the settled receipt.
        if self.guardian_lost && !self.loss_reported {
            self.loss_reported = true;
            self.custodian_errors.push(crate::records::JailError::new(
                crate::records::ErrorCode::CustodianLost,
                crate::records::ErrorStage::Stopping,
                crate::records::Remediation::InspectState,
                "the guardian custodian was lost at the stop".to_owned(),
            ));
        }
        let own = self.stop_result;
        let guardian_drained = self
            .guardian_record
            .as_ref()
            .and_then(|record| record.get("drained"))
            .and_then(serde_json::Value::as_bool);
        let guardian_integrity = self
            .guardian_record
            .as_ref()
            .and_then(|record| record.get("reason"))
            .and_then(serde_json::Value::as_str)
            == Some("integrity");
        let integrity = self.engine.integrity_loss() || guardian_integrity;
        if integrity {
            self.integrity_lost = true;
        }
        let drained = own.is_some_and(|result| result.drained()) || guardian_drained == Some(true);
        // tree_empty=true needs one custodian that drained; anything else is
        // tree_unknown (§4.5). Failed verification loses integrity and
        // retains state, as on Linux.
        let tree_empty = (!integrity && drained).then_some(true);
        let verified_at = tree_empty.filter(|empty| *empty).map(|_| SystemTime::now());
        if let Some(relay) = self.relay.as_mut() {
            relay.settle(tree_empty == Some(true));
        }
        TreeObservation {
            tree_empty,
            verified_at,
            verification_scope: VerificationScope::AttemptTree,
            integrity: if tree_empty == Some(true) && !integrity {
                Integrity::Verified
            } else if self.integrity_lost {
                Integrity::Lost
            } else {
                Integrity::Pending
            },
        }
    }

    /// The native details (§4.8), complete once the stop has ended.
    fn native_details(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut details = serde_json::Map::new();
        details.insert(
            "custody".to_owned(),
            serde_json::Value::from("es_descendants"),
        );
        details.insert("defense".to_owned(), serde_json::Value::from("seatbelt"));
        details.insert("native_execution".to_owned(), serde_json::json!("dev"));
        details.insert(
            "profile_digest".to_owned(),
            serde_json::json!(seatbelt::template_digest()),
        );
        details.insert(
            "profile_parameters".to_owned(),
            self.profile_params.receipt(),
        );
        details.insert(
            "handshake_events_pending".to_owned(),
            serde_json::Value::from(self.handshake_events.len()),
        );
        details.insert(
            "process_headroom".to_owned(),
            serde_json::Value::from(self.headroom),
        );
        let mut custodians = serde_json::Map::new();
        custodians.insert("supervisor".to_owned(), self.custodian_facts());
        custodians.insert("guardian".to_owned(), self.guardian_facts());
        details.insert("custodians".to_owned(), serde_json::Value::from(custodians));
        let mut stop = serde_json::Map::new();
        stop.insert(
            "members".to_owned(),
            serde_json::Value::from(self.peak_members),
        );
        stop.insert(
            "budget_ns".to_owned(),
            serde_json::Value::from(STOP_BUDGET_NS),
        );
        stop.insert(
            "elapsed_ns".to_owned(),
            serde_json::Value::from(self.stop_result.map_or(0, |result| result.elapsed_ns())),
        );
        details.insert("stop".to_owned(), serde_json::Value::from(stop));
        if let Some(relay) = &self.relay {
            details.insert(
                "relay_terminal".into(),
                serde_json::json!(AppliedTerminal {
                    device: relay.device().to_owned(),
                    session: super::relay::RELAY_SESSION.into(),
                    process_group: "own".into(),
                    stops: relay.stops,
                    restored: relay.restored,
                }),
            );
        }
        if let Some(token) = self.target_token {
            details.insert(
                "target_process".into(),
                serde_json::json!(ProcessRecord {
                    pid: token[AUDIT_TOKEN_PID],
                    identity: ProcessIdentity {
                        kind: "macos_audit_token".into(),
                        value: audit_token_value(token)
                    },
                }),
            );
        }
        details
    }

    fn custodian_facts(&self) -> serde_json::Value {
        serde_json::json!({
            "result": match self.stop_result {
                Some(result) if result.drained() => "drained",
                _ => "not_drained",
            },
            "stream": if self.engine.gapped() { "gapped" } else { "contiguous" },
            "events": self.events,
        })
    }

    fn guardian_facts(&self) -> serde_json::Value {
        guardian_facts(
            self.guardian_record.as_ref(),
            self.guardian_lost,
            self.guardian_stalled,
        )
    }
}

/// Exec replaces pidversion. Track every exec of the target pid, while only
/// the first confirms release; only the current identity can end the target.
fn track_target(
    event: &EsEvent,
    launcher: &Token,
    target: &mut Option<Token>,
    confirmed: &mut bool,
) -> Option<RunEvent> {
    match *event {
        EsEvent::Exec { token } if token[AUDIT_TOKEN_PID] == launcher[AUDIT_TOKEN_PID] => {
            *target = Some(token);
            let first = !*confirmed;
            *confirmed = true;
            first.then_some(RunEvent::ExecConfirmed)
        }
        EsEvent::Exit { token, status } if *target == Some(token) => exit_status_event(status),
        _ => None,
    }
}

/// After token-seen, B carries exactly one well-formed final record. A bad
/// frame invalidates this channel's evidence; EOF cannot later clear loss.
fn receive_guardian_record(
    reader: &mut BReader,
    bytes: &[u8],
    record: &mut Option<serde_json::Value>,
) -> Result<(), ()> {
    let accepted = (|| {
        for frame in reader.feed(bytes).map_err(|_| ())? {
            let BFrame::Record(json) = frame else {
                return Err(());
            };
            if record.is_some() {
                return Err(());
            }
            let value: serde_json::Value = serde_json::from_slice(&json).map_err(|_| ())?;
            if value.get("schema").and_then(serde_json::Value::as_str) != Some(record::SCHEMA)
                || value
                    .get("drained")
                    .and_then(serde_json::Value::as_bool)
                    .is_none()
            {
                return Err(());
            }
            *record = Some(value);
        }
        Ok(())
    })();
    if accepted.is_err() {
        *record = None;
    }
    accepted
}

fn guardian_facts(
    record: Option<&serde_json::Value>,
    lost: bool,
    stalled: bool,
) -> serde_json::Value {
    let result = if lost && record.is_none() {
        "lost"
    } else if stalled {
        "stalled"
    } else {
        match record
            .and_then(|record| record.get("drained"))
            .and_then(serde_json::Value::as_bool)
        {
            Some(true) => "drained",
            _ => "not_drained",
        }
    };
    let stream = match record
        .and_then(|record| record.get("reason"))
        .and_then(serde_json::Value::as_str)
    {
        Some("gap") => "gapped",
        _ if record
            .and_then(|r| r.get("drained"))
            .and_then(serde_json::Value::as_bool)
            .is_some() =>
        {
            "contiguous"
        }
        _ => "unknown",
    };
    let events = record.map(|record| {
        ["forks", "execs", "exits"]
            .iter()
            .filter_map(|key| record.get(*key).and_then(serde_json::Value::as_u64))
            .sum::<u64>()
    });
    serde_json::json!({
        "result": result,
        "stream": stream,
        "events": events,
    })
}

/// The target's outcome from its `NOTIFY_EXIT` wait status: the raw `stat`
/// field follows `wait4` (per `ESMessage.h`), so `WIFEXITED` and
/// `WIFSIGNALED` decode it. Any other shape is an `Unknown`, never a
/// fabricated code.
fn exit_status_event(status: i32) -> Option<RunEvent> {
    if libc::WIFEXITED(status) {
        Some(RunEvent::TargetExited {
            code: u8::try_from(libc::WEXITSTATUS(status)).unwrap_or(0),
        })
    } else if libc::WIFSIGNALED(status) {
        Some(RunEvent::TargetSignaled {
            signal: u32::try_from(libc::WTERMSIG(status)).unwrap_or(0),
        })
    } else {
        Some(RunEvent::Unknown {
            reason: "the target's exit status is neither exited nor signaled".to_owned(),
        })
    }
}

impl crate::platform::RunningExecution for MacosRunning {
    fn final_limits(&self) -> Vec<AppliedLimit> {
        let mut limits = self.limits.clone();
        for limit in &mut limits {
            if limit.key == "wall" && limit.applied {
                limit.hit = self.wall_hit();
            }
        }
        limits
    }

    fn integrity_lost(&self) -> bool {
        self.integrity_lost
    }

    fn final_native_details(&self) -> serde_json::Map<String, serde_json::Value> {
        self.native_details()
    }

    fn custodian_errors(&mut self) -> Vec<crate::records::JailError> {
        std::mem::take(&mut self.custodian_errors)
    }

    fn wait(&mut self, deadline: Deadline) -> RunEvent {
        let bounded = Instant::now() + Duration::from_millis(100);
        let step_end = deadline.at.map_or(bounded, |at| at.min(bounded));
        loop {
            // The relay first (§4.11): the operator's bytes and window sizes
            // move whether or not the target has reported, and the
            // workload never holds the operator's terminal.
            if let Some(event) = self.pump_relay() {
                return event;
            }
            if let Some(event) = self.drain_events() {
                return event;
            }
            if let Some(event) = self.read_exec_report() {
                return event;
            }
            self.poll_guardian();
            if self.guardian_lost && self.guardian_record.is_none() && !self.loss_reported {
                // §4.6: a guardian that dies mid-run is recorded, and the
                // run continues from S alone; the stop it never ran is the
                // supervisor's, and the loss is that stop's cause.
                self.begin_stop();
                self.loss_reported = true;
                return RunEvent::CustodianLost;
            }
            if let Some(event) = self.wall_check() {
                return event;
            }
            // The cooperative grace, then the stop (§4.5).
            if let Some(stop) = self.stop.as_mut()
                && !stop.begun
                && es::continuous_time_ns() >= stop.grace_ends_ns
            {
                stop.begun = true;
                self.begin_stop();
            }
            if self.stop.as_ref().is_some_and(|stop| stop.begun) && self.tick_stop() {
                return RunEvent::Poll;
            }
            if Instant::now() >= step_end {
                return RunEvent::Poll;
            }
            self.custody().drain(TICK_MS);
        }
    }

    fn request_stop(&mut self, reason: StopReason) {
        self.request_stop_with(reason, &mut EsSignaller);
    }

    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        self.settle(budget)
    }

    fn observer_summary(&mut self) -> Option<crate::observer::CoverageSummary> {
        // §4.10/§5: `proxy.net` comes from the bridge, as on Linux. Every
        // other class is the observer's (J17) or unobserved.
        // As on Linux with observation off, audit classes are unsupported;
        // the wrapper can still count its confirmed wall hits.
        let mut coverage = crate::observer::CoverageSummary::unobserved();
        let hit = self.wall_hit();
        let gaps = if hit.is_none() {
            // G's record does not carry its wall trigger. A deadline that
            // passed while S was paused leaves the hit count unknown.
            vec![crate::records::Gap {
                classes: vec!["limits".into()],
                source: "wrapper".into(),
                start_ns: "0".into(),
                end_ns: Some(crate::platform::elapsed_since_start_ns().to_string()),
                reason: "wall_hit_unobserved".into(),
                lost_count: None,
            }]
        } else {
            Vec::new()
        };
        if !gaps.is_empty() {
            coverage.sources.wrapper = crate::records::SourceStatus::Degraded;
            coverage.gaps = gaps.clone();
        }
        coverage.classes.insert(
            crate::observer::CoverageClass::Limits,
            crate::observer::ClassSummary {
                status: if hit.is_some() {
                    crate::records::SourceStatus::Active
                } else {
                    crate::records::SourceStatus::Degraded
                },
                observed_count: hit.map(u64::from),
                gaps,
                resolver_refused: 0,
            },
        );
        let Some(proxy) = self.proxy.take() else {
            return Some(coverage);
        };
        let stopped_at = (!proxy.serving()).then(crate::platform::elapsed_since_start_ns);
        let summary = proxy.stop(crate::proxy::MAX_DEADLINE);
        let (delivered, lost, resolver_refused) = self
            .proxy_sink
            .as_ref()
            .map_or((0, 0, 0), |sink| sink.account());
        crate::proxy::coverage::apply_coverage(
            &mut coverage,
            &crate::proxy::coverage::Account {
                delivered,
                lost,
                resolver_refused,
                missing: Some(summary.results_missing),
                stopped_at,
                now: crate::platform::elapsed_since_start_ns(),
            },
        );
        Some(coverage)
    }
}

impl MacosRunning {
    fn wall_hit(&self) -> Option<bool> {
        // A later expiry during another stop's grace is still a hit, while
        // the first stop remains the cause. Never infer a hit from elapsed
        // settlement time or the target's signal/exit code.
        if self.wall_expired
            || self
                .stop
                .as_ref()
                .is_some_and(|stop| stop.reason == StopReason::WallExpiry)
        {
            return Some(true);
        }
        let observed_at = self.settled_at_ns.unwrap_or_else(es::continuous_time_ns);
        if self.wall_ns == 0 || observed_at < self.release_ns.saturating_add(self.wall_ns) {
            Some(false)
        } else {
            // S never observed expiry and G does not report its trigger:
            // after the deadline, neither a hit nor an unhit wall is proved.
            None
        }
    }

    fn request_stop_with(&mut self, reason: StopReason, signaller: &mut dyn Signaller) {
        match self.stop.as_mut() {
            Some(stop) => {
                // The grace is running; an explicit second ask ends it now:
                // the caller owns the lifecycle and has asked again.
                stop.grace_ends_ns = es::continuous_time_ns();
            }
            None => {
                // §4.5: `SIGTERM` to the target by audit token, initial 2 s.
                if let Some(token) = self.target_token {
                    let _ = signaller.signal(&token, libc::SIGTERM);
                }
                // A termination request is not a terminal stop event.

                self.stop = Some(StopDrive {
                    reason,
                    grace_ends_ns: es::continuous_time_ns() + STOP_GRACE_NS,
                    begun: false,
                });
            }
        }
    }

    /// One relay slice; `Some` is a stdio failure the supervisor records.
    fn pump_relay(&mut self) -> Option<RunEvent> {
        let relay = self.relay.as_mut()?;
        if let Err(error) = relay.propagate_window() {
            return Some(RunEvent::StdioFailed {
                reason: format!("terminal window relay failed: {error}"),
                after_target_end: self.target_ended(),
            });
        }
        if let Some(token) = self.target_token {
            let stopped =
                super::relay::target_stopped(token[AUDIT_TOKEN_PID] as libc::pid_t).is_some();
            if stopped && !self.target_was_stopped {
                relay.stops += 1;
            }
            self.target_was_stopped = stopped;
        }
        match relay.pump(0) {
            Ok(crate::platform::macos::relay::RelayEvent::Relayed { .. })
            | Ok(crate::platform::macos::relay::RelayEvent::Idle) => None,
            Ok(_) => Some(RunEvent::StdioFailed {
                reason: "the terminal relay lost the operator's end".to_owned(),
                after_target_end: self.target_ended(),
            }),
            Err(error) => Some(RunEvent::StdioFailed {
                reason: format!("the terminal relay failed: {error}"),
                after_target_end: self.target_ended(),
            }),
        }
    }
}

impl Drop for MacosRunning {
    fn drop(&mut self) {
        // Whatever path leaves the run: A closes (the guardian's stop), the
        // guardian is reaped or ended, the client deleted.
        if self.a_write >= 0 {
            // SAFETY: a plain close of a descriptor this process owns.
            unsafe { libc::close(self.a_write) };
            self.a_write = -1;
        }
        let deadline = Instant::now() + GUARDIAN_TAIL;
        while self.guardian_record.is_none() && Instant::now() < deadline {
            self.poll_guardian();
            if self.guardian.poll() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.guardian.end();
        if let Some(client) = self.client.take() {
            let _ = client.delete();
        }
    }
}

// ---------------------------------------------------------------------------
// Pure mappings, for the conformance tests
// ---------------------------------------------------------------------------

/// The RunEvent mapping of [`MacosRunning::apply_event`], on plain values:
/// exec confirmed, target exited, target signaled.
#[must_use]
pub fn map_sequence(events: &[es::EsPoll], launcher: &Token) -> Vec<RunEvent> {
    let mut engine = Custodian::new(crate::platform::macos::custody::table_capacity(
        maxprocperuid(),
    ));
    let mut out = Vec::new();
    let mut confirmed = false;
    for poll in events {
        engine.apply_polled(poll);
        match poll.event {
            EsEvent::Exec { token }
                if !confirmed && token[AUDIT_TOKEN_PID] == launcher[AUDIT_TOKEN_PID] =>
            {
                confirmed = true;
                out.push(RunEvent::ExecConfirmed);
            }
            EsEvent::Exit { token, status }
                if confirmed && token[AUDIT_TOKEN_PID] == launcher[AUDIT_TOKEN_PID] =>
            {
                if let Some(event) = exit_status_event(status) {
                    out.push(event);
                }
            }
            _ => {}
        }
    }
    out
}

/// The stop budget a record reports.
#[must_use]
pub fn stop_budget_ns() -> u64 {
    STOP_BUDGET_NS
}

/// The cooperative grace, exposed for the tests.
#[must_use]
pub fn stop_grace() -> Duration {
    Duration::from_nanos(STOP_GRACE_NS)
}

/// The B-frame codec, exposed for the conformance tests: the frames the
/// guardian writes decode, and nothing else does.
pub fn decode_b_frames(chunks: &[&[u8]]) -> Result<Vec<BFrame>, String> {
    let mut reader = BReader::default();
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend(reader.feed(chunk).map_err(|error| error.message)?);
    }
    Ok(out)
}

/// The calling thread's blocked signals as a bitmask (bit `n - 1` for signal
/// `n`, 1..=64) — the mask the target gets, the same capture the Linux
/// launcher performs at the supervisor's start.
fn capture_mask() -> u64 {
    // SAFETY: `set` is plain stack data pthread_sigmask fills; a null
    // new-mask pointer only reads the current one.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &raw mut set) != 0 {
            return 0;
        }
        (1..=32).fold(0u64, |mask, signal| {
            if libc::sigismember(&raw const set, signal) == 1 {
                mask | (1u64 << (signal - 1))
            } else {
                mask
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(pid: u32) -> Token {
        let mut token = [0u32; 8];
        token[AUDIT_TOKEN_PID] = pid;
        token[AUDIT_TOKEN_PIDVERSION] = 1;
        token
    }

    fn pipe_read_bounded(fd: &mut Fd, bytes: &mut [u8]) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match fd.read(bytes) {
                Ok(n) => return n,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("pipe did not become readable within the bound: {error}"),
            }
        }
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn poll(event: EsEvent, global: u64, seq: u64, kind: u32) -> es::EsPoll {
        es::EsPoll {
            event,
            kind,
            global_seq: global,
            seq,
        }
    }

    #[derive(Default)]
    struct RecordedSignals(Vec<(Token, i32)>);

    impl Signaller for RecordedSignals {
        fn signal(&mut self, token: &Token, signal: i32) -> i32 {
            self.0.push((*token, signal));
            0
        }
    }

    fn retained_handshake() -> (Vec<es::EsPoll>, Token, Token) {
        let guardian_fork = token(1001);
        let mut guardian = guardian_fork;
        guardian[AUDIT_TOKEN_PIDVERSION] = 2;
        let launcher_fork = token(2001);
        let mut launcher = launcher_fork;
        launcher[AUDIT_TOKEN_PIDVERSION] = 2;
        (
            vec![
                poll(
                    EsEvent::Fork {
                        token: guardian_fork,
                    },
                    1,
                    1,
                    es::EVENT_FORK,
                ),
                poll(EsEvent::Exec { token: guardian }, 2, 1, es::EVENT_EXEC),
                poll(
                    EsEvent::Fork {
                        token: launcher_fork,
                    },
                    3,
                    2,
                    es::EVENT_FORK,
                ),
                poll(EsEvent::Exec { token: launcher }, 4, 2, es::EVENT_EXEC),
            ],
            launcher,
            guardian,
        )
    }

    #[test]
    fn supervisor_replays_the_handshake_once_in_delivery_order() {
        let (mut retained, launcher, guardian) = retained_handshake();
        let mut engine =
            supervisor_custody(8, launcher, token(42), 1001, &mut retained, false).unwrap();
        assert!(retained.is_empty(), "replay must consume the queue");
        assert_eq!(engine.seq().counts(), [2, 2, 0]);
        assert!(engine.contains_token(&launcher));
        assert!(
            !engine.contains_token(&token(2001)),
            "exec replaced the fork token"
        );
        assert!(!engine.contains_token(&guardian));
        assert_eq!(engine.live_count(), 1);
        assert!(engine.table().root_entered());
        replay_retained(&mut engine, &mut retained);
        assert_eq!(engine.seq().counts(), [2, 2, 0]);
        let child = token(3001);
        apply_supervisor_event(
            &mut engine,
            &poll(EsEvent::Fork { token: child }, 5, 3, es::EVENT_FORK),
            &mut RecordedSignals::default(),
        );
        assert_eq!(engine.seq().counts(), [3, 2, 0]);
        assert!(engine.contains_token(&child));
        assert!(
            !engine.gapped(),
            "replay and later polls share one sequence"
        );
    }

    #[test]
    fn a_registered_guardian_exit_does_not_gap_the_supervisors_drain() {
        let (mut retained, launcher, guardian) = retained_handshake();
        let mut engine =
            supervisor_custody(8, launcher, token(42), 1001, &mut retained, false).unwrap();
        assert!(
            !engine.contains_token(&guardian),
            "custodians must be excluded before any stop"
        );
        assert_eq!(engine.live_count(), 1);
        let mut signaller = RecordedSignals::default();
        apply_supervisor_event(
            &mut engine,
            &poll(
                EsEvent::Exit {
                    token: guardian,
                    status: 0,
                },
                5,
                1,
                es::EVENT_EXIT,
            ),
            &mut signaller,
        );
        assert!(!engine.gapped());
        assert_eq!(engine.live_count(), 1, "only the launcher is a member");
        engine.begin_stop(0);
        assert!(engine.tick(0, &mut signaller).is_none());
        assert_eq!(signaller.0, [(launcher, libc::SIGSTOP)]);
        apply_supervisor_event(
            &mut engine,
            &poll(
                EsEvent::Exit {
                    token: launcher,
                    status: 0,
                },
                6,
                2,
                es::EVENT_EXIT,
            ),
            &mut signaller,
        );
        assert!(engine.tick(1, &mut signaller).unwrap().drained());
        assert!(!engine.gapped());
        assert_eq!(engine.seq().counts(), [2, 2, 2]);
    }

    #[test]
    fn a_supervisor_stop_before_root_entry_cannot_answer_drained() {
        let (mut retained, launcher, _) = retained_handshake();
        retained.truncate(2); // G entered and execed; the launcher never entered S.
        let mut engine =
            supervisor_custody(8, launcher, token(42), 1001, &mut retained, false).unwrap();
        assert_eq!(engine.live_count(), 0);
        assert!(!engine.table().root_entered());
        engine.begin_stop(0);
        assert!(matches!(
            engine.tick(0, &mut RecordedSignals::default()),
            Some(StopResult::NotDrained {
                reason: crate::platform::macos::custody::StopNotDrainedReason::Gap,
                ..
            })
        ));
        assert!(engine.gapped());
    }

    #[test]
    fn handshake_overflow_vetoes_the_supervisors_drain() {
        let (mut retained, launcher, _) = retained_handshake();
        let mut engine =
            supervisor_custody(8, launcher, token(42), 1001, &mut retained, true).unwrap();
        assert!(engine.gapped());
        apply_supervisor_event(
            &mut engine,
            &poll(
                EsEvent::Exit {
                    token: launcher,
                    status: 0,
                },
                5,
                1,
                es::EVENT_EXIT,
            ),
            &mut RecordedSignals::default(),
        );
        assert_eq!(engine.live_count(), 0);
        engine.begin_stop(0);
        assert!(
            !engine
                .tick(0, &mut RecordedSignals::default())
                .unwrap()
                .drained()
        );
    }

    #[test]
    fn supervisor_signals_stop_arrivals_before_the_next_tick() {
        let (mut retained, launcher, _) = retained_handshake();
        let mut engine =
            supervisor_custody(8, launcher, token(42), 1001, &mut retained, false).unwrap();
        let mut signaller = RecordedSignals::default();
        engine.begin_stop(0);
        let child = token(3001);
        apply_supervisor_event(
            &mut engine,
            &poll(EsEvent::Fork { token: child }, 5, 3, es::EVENT_FORK),
            &mut signaller,
        );
        assert_eq!(signaller.0, [(child, libc::SIGSTOP)]);
    }

    #[test]
    fn supervisor_does_not_skip_a_malformed_polled_event() {
        let (mut retained, launcher, _) = retained_handshake();
        let mut engine =
            supervisor_custody(8, launcher, token(42), 1001, &mut retained, false).unwrap();
        apply_supervisor_event(
            &mut engine,
            &poll(
                EsEvent::Exit {
                    token: launcher,
                    status: 0,
                },
                5,
                1,
                u32::MAX,
            ),
            &mut RecordedSignals::default(),
        );
        assert!(engine.gapped());
        assert_eq!(engine.live_count(), 0);
    }

    #[test]
    fn missing_guardian_identity_refuses_supervisor_custody() {
        let (_, launcher, _) = retained_handshake();
        assert!(supervisor_custody(8, launcher, token(42), 1001, &mut Vec::new(), false).is_err());
    }

    #[test]
    fn reaping_the_guardian_retires_its_pid_before_any_later_cleanup() {
        let mut guardian = GuardianProcess::new(123);
        let mut waits = 0;
        let mut wait = |pid: libc::pid_t, nonblocking: bool| {
            assert_eq!(pid, 123);
            assert!(nonblocking);
            waits += 1;
            // A second wait represents an unrelated process reusing PID 123.
            Ok(if waits == 1 { Some(7 << 8) } else { None })
        };
        assert!(guardian.poll_with(&mut wait));
        let mut kills = Vec::new();
        assert!(!guardian.end_with(&mut wait, &mut |pid| {
            kills.push(pid);
            Ok(())
        }));
        assert!(guardian.poll_with(&mut wait));
        assert_eq!(guardian.exit_code(), 7, "status is cached, never re-waited");
        assert_eq!(waits, 1);
        assert!(kills.is_empty());
    }

    #[test]
    fn guardian_cleanup_never_signals_after_echild() {
        let mut guardian = GuardianProcess::new(123);
        let mut waits = 0;
        let mut wait = |_, _| {
            waits += 1;
            Err(std::io::Error::from_raw_os_error(libc::ECHILD))
        };
        let mut kills = 0;
        let mut kill = |_| {
            kills += 1;
            Ok(())
        };
        assert!(!guardian.end_with(&mut wait, &mut kill));
        assert!(!guardian.end_with(&mut wait, &mut kill));
        assert_eq!(waits, 1);
        assert_eq!(kills, 0);
        assert!(guardian.pid.is_none());
    }

    #[test]
    fn ending_a_live_guardian_signals_once_then_reaps_once() {
        let mut guardian = GuardianProcess::new(123);
        let mut waits = Vec::new();
        let mut wait = |pid: libc::pid_t, nonblocking: bool| {
            waits.push((pid, nonblocking));
            Ok(if nonblocking {
                None
            } else {
                Some(libc::SIGKILL)
            })
        };
        let mut kills = Vec::new();
        let mut kill = |pid| {
            kills.push(pid);
            Ok(())
        };
        assert!(guardian.end_with(&mut wait, &mut kill));
        assert!(!guardian.end_with(&mut wait, &mut kill));
        assert_eq!(waits, [(123, true), (123, false)]);
        assert_eq!(kills, [123]);
        assert_eq!(guardian.status, Some(libc::SIGKILL));
        assert!(guardian.pid.is_none());
    }

    #[test]
    fn an_exited_spawned_guardian_is_reaped_without_later_signalling() {
        let pid = spawn_self(Path::new("/usr/bin/true"), &[], &[]).unwrap();
        let mut guardian = GuardianProcess::new(pid);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !guardian.poll() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if guardian.pid.is_some() {
            guardian.end();
            panic!("child did not exit within the bounded wait");
        }
        assert_eq!(guardian.exit_code(), 0);
        assert!(!guardian.end());
        assert!(guardian.poll());
    }

    #[test]
    fn no_wall_release_uses_the_guardians_explicit_no_deadline_frame() {
        use crate::platform::macos::guardian::frames::{Feed, Frame, FrameReader, wall_deadline};
        let mut a = Pipe::new().unwrap();
        let mut r = Pipe::new().unwrap();
        let mut a_read = Fd::nonblocking(a.take_read()).unwrap();
        let mut r_read = Fd::nonblocking(r.take_read()).unwrap();
        let mut release = Fd(r.take_write());
        release_launcher(a.write, &mut release, None).unwrap();
        let mut bytes = [0u8; 128];
        let n = a_read.read(&mut bytes).unwrap();
        assert_eq!(
            FrameReader::default().read(&bytes[..n], false),
            Feed::Frames(vec![Ok(Frame::ReleaseDeadline(NO_DEADLINE))])
        );
        assert_eq!(wall_deadline(NO_DEADLINE), None);
        assert_eq!(
            a_read.read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(r_read.read(&mut bytes).unwrap(), 1);
        assert_eq!(bytes[0], b'L');
        assert_eq!(pipe_read_bounded(&mut r_read, &mut bytes), 0);
    }

    #[test]
    fn the_b_grammar_decodes_ready_token_seen_and_record() {
        let record = br#"{"schema":"ukai.jail.guardian-record/1","drained":true}"#;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&frame(b"ready"));
        bytes.extend_from_slice(&frame(b"token-seen"));
        let mut record_payload = b"record ".to_vec();
        record_payload.extend_from_slice(record);
        let record_frame = frame(&record_payload);
        bytes.extend_from_slice(&record_frame);
        assert_eq!(
            decode_b_frames(&[&bytes]).expect("decodes"),
            vec![
                BFrame::Ready,
                BFrame::TokenSeen,
                BFrame::Record(record.to_vec()),
            ]
        );
    }

    #[test]
    fn the_b_grammar_survives_fragmented_reads_and_refuses_unknown_frames() {
        let bytes = frame(b"ready");
        let split: Vec<&[u8]> = (0..bytes.len()).map(|at| &bytes[at..at + 1]).collect();
        assert_eq!(
            decode_b_frames(&split).expect("decodes"),
            vec![BFrame::Ready]
        );
        let unknown = frame(b"surprise");
        assert!(decode_b_frames(&[&unknown]).is_err());
    }

    #[test]
    fn the_exit_status_mapping_follows_wait4() {
        assert_eq!(
            exit_status_event(0),
            Some(RunEvent::TargetExited { code: 0 })
        );
        assert_eq!(
            exit_status_event(3 << 8),
            Some(RunEvent::TargetExited { code: 3 })
        );
        assert_eq!(
            exit_status_event(15),
            Some(RunEvent::TargetSignaled { signal: 15 })
        );
        assert_eq!(
            exit_status_event(9),
            Some(RunEvent::TargetSignaled { signal: 9 })
        );
    }

    #[test]
    fn a_sequence_maps_exec_then_exit() {
        let launcher = token(4242);
        // The target is the launcher's process after its exec: same pid,
        // new audit token.
        let mut target = token(4242);
        target[AUDIT_TOKEN_PIDVERSION] = 2;
        let events = vec![
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
            map_sequence(&events, &launcher),
            vec![RunEvent::ExecConfirmed, RunEvent::TargetExited { code: 0 }]
        );
    }

    #[test]
    fn a_signal_death_maps_to_target_signaled() {
        let launcher = token(10);
        let mut target = token(10);
        target[AUDIT_TOKEN_PIDVERSION] = 2;
        let events = vec![
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
            map_sequence(&events, &launcher),
            vec![
                RunEvent::ExecConfirmed,
                RunEvent::TargetSignaled { signal: 9 }
            ]
        );
    }

    #[test]
    fn an_exec_that_never_happens_maps_to_nothing() {
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
        assert!(map_sequence(&events, &launcher).is_empty());
    }

    #[test]
    fn the_blocked_sentinel_is_not_an_errno() {
        assert!(crate::platform::macos::launcher::is_blocked_report(
            &[0u8; 8]
        ));
        assert!(!crate::platform::macos::launcher::is_blocked_report(
            &libc::EACCES.to_le_bytes()
        ));
    }

    /// The default-off development gate refuses before attempting any ES client.
    #[test]
    fn prepare_refuses_when_the_native_development_gate_is_off() {
        use crate::platform::{PlanRequest, Sinks};
        use crate::policy::{ProfileName, ResolveInputs, ScratchRoot};

        fn plan_for(profile: ProfileName) -> PlanRequest {
            let baseline = crate::profiles::baseline(profile, Os::Macos, &|_| None);
            let inputs = ResolveInputs {
                platform: Os::Macos,
                base_profile: profile,
                policy_name: profile.as_str().to_owned(),
                baseline,
                workspace: b"/work".to_vec(),
                scratch: ScratchRoot::Managed,
                vendor_state: None,
                operator_home: None,
                translation_prefixes: Vec::new(),
                layers: Vec::new(),
            };
            let resolved = crate::policy::resolve(&inputs).expect("resolves");
            PlanRequest {
                snapshot: resolved.snapshot,
                requirements: resolved.requirements,
            }
        }

        let dir = tempfile::tempdir().expect("temp dir");
        let plan = PreparedPlan {
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            attempt_dir: dir.path().to_path_buf(),
            request: plan_for(ProfileName::None),
            argv: vec![b"/usr/bin/true".to_vec()],
            prepare_deadline: ContinuousDeadline::after(Duration::from_secs(30)),
            workspace: std::path::PathBuf::from("/work"),
            config_dir: dir.path().to_path_buf(),
            launch: None,
            proxy: None,
            pinned_roots: Vec::new(),
            exec_pins: Vec::new(),
        };
        let prepared = prepare(plan, Sinks { trace: None });
        let error = match prepared {
            Ok(_) => panic!("the custody client cannot exist without the entitlement"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::UnsupportedPlatform);
        assert_eq!(error.remediation, Remediation::Unsupported);
        assert!(
            error.message.contains("UKAI_JAIL_MACOS_NATIVE=dev"),
            "{}",
            error.message
        );
        assert_eq!(error.exit_code(), 125);
    }

    #[test]
    fn the_grace_is_two_seconds_and_the_budget_five() {
        assert_eq!(stop_grace(), Duration::from_secs(2));
        assert_eq!(stop_budget_ns(), 5_000_000_000);
    }
    #[test]
    fn supervisor_frames_reach_the_guardian_reader() {
        use crate::platform::macos::guardian::frames::{Feed, Frame, FrameReader};
        let mut pipe = Pipe::new().unwrap();
        write_frame(pipe.write, &encode_launcher_token(&token(42))).unwrap();
        write_frame(pipe.write, &encode_release_deadline(123)).unwrap();
        let mut read = Fd::nonblocking(pipe.take_read()).unwrap();
        let mut bytes = [0u8; 256];
        let n = read.read(&mut bytes).unwrap();
        let mut reader = FrameReader::default();
        assert_eq!(
            reader.read(&bytes[..n], false),
            Feed::Frames(vec![
                Ok(Frame::LauncherToken(token(42))),
                Ok(Frame::ReleaseDeadline(123)),
            ])
        );
    }

    #[test]
    fn guardian_spawn_inherits_exactly_requested_descriptors() {
        let mut pipe = Pipe::new().unwrap();
        // A deliberately inheritable extra descriptor must still be absent.
        // SAFETY: dup returns an owned fd; fcntl changes that fd only.
        let extra = Fd(unsafe { libc::dup(pipe.read) });
        assert!(extra.0 >= 0);
        let script = format!(
            r#"import os, fcntl
fds = []
for fd in range(3, {}):
    try: fcntl.fcntl(fd, fcntl.F_GETFD); fds.append(fd)
    except OSError: pass
os.write({}, (','.join(map(str, fds))).encode())
"#,
            extra.0.max(pipe.write) + 10,
            pipe.write
        );
        let pid = spawn_self(
            Path::new("/usr/bin/python3"),
            &["-c".into(), script],
            &[pipe.write],
        )
        .unwrap();
        let mut status = 0;
        // SAFETY: reaps only the child this test spawned.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0, "fixture failed before reporting descriptors");
        let mut read = Fd::nonblocking(pipe.take_read()).unwrap();
        let mut bytes = [0u8; 1024];
        let n = read.read(&mut bytes).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes[..n]).unwrap(),
            pipe.write.to_string()
        );
    }

    #[test]
    fn b_rejects_oversize_and_zero_lengths_immediately() {
        for length in [0u32, (MAX_FRAME_BYTES + 1) as u32, u32::MAX] {
            assert!(
                decode_b_frames(&[&length.to_le_bytes()]).is_err(),
                "{length}"
            );
        }
    }

    fn policy_plan(profile: crate::policy::ProfileName) -> (tempfile::TempDir, PreparedPlan) {
        use crate::policy::{ResolveInputs, ScratchRoot};
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("work");
        let attempt = dir.path().join("attempt");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&attempt).unwrap();
        let resolved = crate::policy::resolve(&ResolveInputs {
            platform: Os::Macos,
            base_profile: profile,
            policy_name: profile.as_str().into(),
            baseline: crate::profiles::baseline(profile, Os::Macos, &|_| None),
            workspace: workspace.as_os_str().as_encoded_bytes().to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        })
        .unwrap();
        (
            dir,
            PreparedPlan {
                attempt_id: "att_00000000-0000-4000-8000-000000000001".into(),
                attempt_dir: attempt,
                request: crate::platform::PlanRequest {
                    snapshot: resolved.snapshot,
                    requirements: resolved.requirements,
                },
                argv: vec![b"/usr/bin/true".to_vec()],
                prepare_deadline: ContinuousDeadline::after(Duration::from_secs(30)),
                workspace,
                config_dir: PathBuf::from("/unused"),
                launch: None,
                proxy: None,
                pinned_roots: Vec::new(),
                exec_pins: Vec::new(),
            },
        )
    }

    /// No ES client or workload process is created. The production native
    /// prepared/released objects still produce every receipt field; this
    /// adapter replaces only the event source, signalling and host probes.
    struct ReceiptPlatform {
        wall_hit: Option<bool>,
        prepared_receipt: std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>>,
    }

    struct ReceiptPrepared {
        inner: MacosPrepared,
        peers: [Fd; 2],
        wall_hit: Option<bool>,
        receipt_path: PathBuf,
        prepared_receipt: std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>>,
    }

    struct ReceiptRun {
        inner: MacosRunning,
        _peers: [Fd; 2],
        wall_hit: Option<bool>,
        next_event: u8,
    }

    fn receipt_prepared(plan: &PreparedPlan) -> (MacosPrepared, [Fd; 2]) {
        let params = profile_params(plan, None).unwrap();
        let (mut events, launcher, _) = retained_handshake();
        let engine = supervisor_custody(8, launcher, token(42), 1001, &mut events, false).unwrap();
        let mut a = Pipe::new().unwrap();
        let mut r = Pipe::new().unwrap();
        let peers = [Fd(a.take_read()), Fd(r.take_read())];
        (
            MacosPrepared {
                client: None,
                engine,
                a_write: a.take_write(),
                r_write: Fd(r.take_write()),
                b_read: Fd(-1),
                e_read: Fd(-1),
                guardian: GuardianProcess {
                    pid: None,
                    status: Some(0),
                },
                launcher_token: launcher,
                process: ProcessRecord {
                    pid: launcher[AUDIT_TOKEN_PID],
                    identity: ProcessIdentity {
                        kind: "macos_audit_token".to_owned(),
                        value: audit_token_value(launcher),
                    },
                },
                applied: build_applied(plan, &params, None, false),
                wall_ms: plan
                    .request
                    .snapshot
                    .limits
                    .wall
                    .as_ref()
                    .map(|wall| wall.value.parse().unwrap()),
                relay: None,
                headroom: u64::from(NPROC_HEADROOM),
                profile_params: params,
                handshake_events: events,
                proxy: None,
                proxy_sink: None,
                serving: None,
            },
            peers,
        )
    }

    impl crate::platform::Platform for ReceiptPlatform {
        fn identity(&self) -> crate::platform::PlatformIdentity {
            crate::platform::macos::MacosPlatform.identity()
        }

        fn owner_identity(&self) -> Option<crate::platform::OwnerIdentity> {
            crate::platform::macos::owner_identity()
        }

        fn probe(&self, plan: &crate::platform::PlanRequest) -> Vec<crate::capability::Capability> {
            plan.requirements
                .iter()
                .map(|requirement| crate::capability::Capability {
                    name: requirement.to_string(),
                    status: crate::capability::CapabilityStatus::Available,
                    scope: crate::capability::CapabilityScope::Tree,
                    mechanism: Some("receipt-test-fake-probe".into()),
                    reason_code: Some("ok".into()),
                    measured_at: Some(crate::records::rfc3339_utc(SystemTime::now())),
                    evidence_ref: Some("receipt-test".into()),
                })
                .collect()
        }

        fn prepare(
            &self,
            plan: PreparedPlan,
            _: Sinks,
        ) -> Result<Box<dyn PreparedExecution>, JailError> {
            let (inner, peers) = receipt_prepared(&plan);
            Ok(Box::new(ReceiptPrepared {
                inner,
                peers,
                wall_hit: self.wall_hit,
                receipt_path: plan.attempt_dir.join(crate::state::RECEIPT_NAME),
                prepared_receipt: self.prepared_receipt.clone(),
            }))
        }
    }

    impl PreparedExecution for ReceiptPrepared {
        fn boundary(&self) -> BoundaryIdentity {
            self.inner.boundary()
        }
        fn applied(&self) -> Option<Applied> {
            self.inner.applied()
        }
        fn release(
            self: Box<Self>,
        ) -> Result<Box<dyn crate::platform::RunningExecution>, Box<ReleaseFailure>> {
            *self.prepared_receipt.lock().unwrap() =
                Some(serde_json::from_slice(&std::fs::read(&self.receipt_path).unwrap()).unwrap());
            let inner = self.inner.release_inner()?;
            Ok(Box::new(ReceiptRun {
                inner,
                _peers: self.peers,
                wall_hit: self.wall_hit,
                next_event: 0,
            }))
        }
        fn abort(self: Box<Self>) -> Result<Teardown, JailError> {
            // The fixture owns this pipe; there is no real guardian or ES
            // client to stop. Reaching this path is a test failure below.
            let _a = Fd(self.inner.a_write);
            Ok(Teardown { tree: None })
        }
    }

    impl crate::platform::RunningExecution for ReceiptRun {
        fn wait(&mut self, _: Deadline) -> RunEvent {
            let event = self.next_event;
            self.next_event += 1;
            match event {
                0 => {
                    let mut target = self.inner.launcher_token;
                    target[AUDIT_TOKEN_PIDVERSION] += 1;
                    self.inner
                        .apply_event(&poll(EsEvent::Exec { token: target }, 5, 3, es::EVENT_EXEC))
                        .unwrap()
                }
                1 if self.wall_hit == Some(true) => {
                    self.inner.release_ns = 0;
                    self.inner.wall_ns = 1;
                    self.inner.wall_check().unwrap()
                }
                1 | 2 => {
                    if self.wall_hit.is_none() {
                        self.inner.release_ns = 0;
                        self.inner.wall_ns = 1; // No S wall check; G's cause is unknown.
                    }
                    let target = self.inner.target_token.unwrap();
                    self.inner
                        .apply_event(&poll(
                            EsEvent::Exit {
                                token: target,
                                status: if self.wall_hit == Some(false) {
                                    0
                                } else {
                                    libc::SIGKILL
                                },
                            },
                            6,
                            1,
                            es::EVENT_EXIT,
                        ))
                        .unwrap()
                }
                _ => RunEvent::Poll,
            }
        }
        fn request_stop(&mut self, reason: StopReason) {
            self.inner
                .request_stop_with(reason, &mut RecordedSignals::default());
        }
        fn wait_tree(&mut self, _: Duration) -> TreeObservation {
            self.inner.begin_stop();
            assert!(self.inner.tick_stop()); // The fake source already delivered the exit.
            self.inner.settled_tree()
        }
        fn final_limits(&self) -> Vec<AppliedLimit> {
            self.inner.final_limits()
        }
        fn observer_summary(&mut self) -> Option<crate::observer::CoverageSummary> {
            self.inner.observer_summary()
        }
        fn final_native_details(&self) -> serde_json::Map<String, serde_json::Value> {
            self.inner.final_native_details()
        }
    }

    fn receipt_validator() -> jsonschema::Validator {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1");
        let schemas: Vec<serde_json::Value> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .ends_with(".schema.json")
            })
            .map(|path| serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
            .collect();
        let resources: Vec<_> = schemas
            .iter()
            .map(|schema| {
                (
                    schema["$id"].as_str().unwrap().to_owned(),
                    jsonschema::Resource::from_contents(schema.clone()),
                )
            })
            .collect();
        let registry = Box::leak(Box::new(
            jsonschema::Registry::new()
                .extend(resources)
                .unwrap()
                .prepare()
                .unwrap(),
        ));
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.join("jail-receipt.schema.json")).unwrap(),
        )
        .unwrap();
        jsonschema::options()
            .with_registry(&*registry)
            .should_validate_formats(true)
            .build(&schema)
            .unwrap()
    }

    #[test]
    fn native_prepared_and_settled_producer_receipts_validate_with_and_without_a_wall_hit() {
        use clap::Parser as _;
        use std::os::unix::fs::PermissionsExt as _;
        // Keep the explicit development opt-in local to a subprocess, so
        // parallel gate-refusal tests continue to test the default-off state.
        const CHILD: &str = "UKAI_CONTAINMENT_RECEIPT_TEST";
        if std::env::var_os(CHILD).is_none() {
            let test_name = format!(
                "{}::native_prepared_and_settled_producer_receipts_validate_with_and_without_a_wall_hit",
                module_path!().split_once("::").unwrap().1
            );
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--nocapture"])
                .env(CHILD, "1")
                .env("UKAI_JAIL_MACOS_NATIVE", "dev")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
                "the subprocess must execute the schema fixture: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        let validator = receipt_validator();
        for wall_hit in [Some(false), Some(true), None] {
            let temp = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let root = temp.path().canonicalize().unwrap();
            let workspace = root.join("work");
            std::fs::create_dir(&workspace).unwrap();
            let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
            let ctx = crate::supervisor::Context {
                platform: Box::new(ReceiptPlatform {
                    wall_hit,
                    prepared_receipt: captured.clone(),
                }),
                env_settings: crate::config::EnvSettings {
                    config_dir: Some(root.join("config")),
                    data_dir: Some(root.join("data")),
                    ..Default::default()
                },
                cwd: workspace.clone(),
                home: Some(root.join("home")),
                env_lookup: Box::new(|_| None),
            };
            let crate::cli::Command::Run(args) = crate::cli::Cli::parse_from([
                "ukai-jail",
                "run",
                "--profile",
                "tool",
                "--workspace",
                workspace.to_str().unwrap(),
                "--",
                "/usr/bin/true",
            ])
            .command
            else {
                unreachable!()
            };
            let report = crate::supervisor::run(&ctx, &args);
            let settled = serde_json::to_value(report.receipt.as_ref().unwrap()).unwrap();
            assert_eq!(
                settled["phase"], "settled",
                "{:?}\n{settled:#}",
                report.error
            );
            let prepared = captured
                .lock()
                .unwrap()
                .take()
                .expect("the prepared receipt was persisted before release");
            assert_eq!(prepared["phase"], "prepared");
            for (receipt, hit) in [(&prepared, Some(false)), (&settled, wall_hit)] {
                let errors: Vec<_> = validator
                    .iter_errors(receipt)
                    .map(|error| format!("{error} at {}", error.instance_path()))
                    .collect();
                assert!(errors.is_empty(), "{errors:?}\n{receipt:#}");
                let rows = receipt["applied"]["limits"].as_array().unwrap();
                let wall = rows
                    .iter()
                    .find(|row| row["key"] == "wall")
                    .expect("native wall row");
                assert_eq!(wall["mechanism"], "both-custodians-continuous-clock");
                assert_eq!(wall["scope"], "tree");
                assert_eq!(wall["required"], true);
                assert_eq!(wall["applied"], true);
                assert_eq!(wall["hit"], serde_json::json!(hit));
            }
            assert_eq!(settled["lifetime"]["tree_empty"], true);
            assert_eq!(
                settled["lifetime"]["native"]["details"]["custodians"]["supervisor"]["result"],
                "drained"
            );
            assert_eq!(settled["observer"]["backend"], serde_json::Value::Null);
            assert_eq!(settled["observer"]["attached"], false);
            for class in ["exec", "fs.write", "fs.deny", "net", "proxy.net"] {
                assert_eq!(settled["coverage"][class]["status"], "unsupported");
                assert!(settled["coverage"][class]["observed_count"].is_null());
            }
            assert_eq!(
                settled["coverage"]["limits"]["status"],
                if wall_hit.is_some() {
                    "active"
                } else {
                    "degraded"
                }
            );
            assert_eq!(
                settled["coverage"]["limits"]["observed_count"],
                serde_json::json!(wall_hit.map(u64::from))
            );
            assert_eq!(
                settled["outcome"]["cause"],
                if wall_hit == Some(true) {
                    serde_json::json!("wall_expiry")
                } else {
                    serde_json::Value::Null
                }
            );
        }
    }

    #[test]
    fn native_limit_rows_preserve_all_requested_unapplied_ceilings() {
        let mut limits = crate::policy::LimitsSnapshot::default();
        for key in crate::policy::LimitKey::ALL {
            *limits.get_mut(key) = Some(crate::policy::LimitCeiling {
                value: "123".into(),
                required: key == crate::policy::LimitKey::Wall,
            });
        }
        let rows = limit_rows(&limits);
        assert_eq!(rows.len(), crate::policy::LimitKey::ALL.len());
        for row in rows {
            assert_eq!(row.requested, "123");
            if row.key != "wall" {
                assert!(!row.applied);
                assert!(!row.required);
                assert_eq!((row.mechanism, row.scope, row.hit), (None, None, None));
            }
        }
    }

    #[test]
    fn custodian_loss_errors_do_not_claim_an_unproved_drain() {
        let (_dir, plan) = policy_plan(crate::policy::ProfileName::Tool);
        let (prepared, _peers) = receipt_prepared(&plan);
        let mut running = prepared.release_inner().unwrap();
        running.guardian_lost = true;
        running.engine.note_stream_gap();
        running.begin_stop();
        assert!(running.tick_stop());
        assert_eq!(running.settled_tree().tree_empty, None);
        assert_eq!(running.custodian_facts()["result"], "not_drained");
        assert_eq!(running.custodian_errors.len(), 1);
        assert!(!running.custodian_errors[0].message.contains("drained"));
    }

    #[test]
    fn an_unobserved_late_wall_is_not_reported_as_an_unhit_ceiling() {
        use crate::platform::RunningExecution as _;
        let (_dir, plan) = policy_plan(crate::policy::ProfileName::Tool);
        let (prepared, _peers) = receipt_prepared(&plan);
        let mut running = prepared.release_inner().unwrap();
        running.release_ns = 0;
        running.wall_ns = 1; // S resumed after the deadline; no wall check ran.
        let mut target = running.launcher_token;
        target[AUDIT_TOKEN_PIDVERSION] += 1;
        running.apply_event(&poll(EsEvent::Exec { token: target }, 5, 3, es::EVENT_EXEC));
        running.apply_event(&poll(
            EsEvent::Exit {
                token: target,
                status: libc::SIGKILL,
            },
            6,
            1,
            es::EVENT_EXIT,
        ));
        running.begin_stop();
        assert!(running.tick_stop());
        assert_eq!(running.settled_tree().tree_empty, Some(true));
        let wall = running
            .final_limits()
            .into_iter()
            .find(|row| row.key == "wall")
            .unwrap();
        assert_eq!(
            wall.hit, None,
            "SIGKILL and elapsed time cannot establish which custodian hit the wall"
        );
        let summary = running.observer_summary().unwrap();
        let limits = &summary.classes[&crate::observer::CoverageClass::Limits];
        assert_eq!(limits.status, crate::records::SourceStatus::Degraded);
        assert_eq!(limits.observed_count, None);
        assert!(
            limits
                .gaps
                .iter()
                .any(|gap| gap.reason == "wall_hit_unobserved")
        );
    }

    #[test]
    fn native_wall_hit_does_not_replace_an_earlier_stop_cause() {
        use crate::platform::RunningExecution as _;
        let (_dir, plan) = policy_plan(crate::policy::ProfileName::Tool);
        let (prepared, _peers) = receipt_prepared(&plan);
        let mut running = prepared.release_inner().unwrap();
        running.request_stop_with(StopReason::OperatorSignal, &mut RecordedSignals::default());
        running.wall_expired = true;
        running.request_stop_with(StopReason::WallExpiry, &mut RecordedSignals::default());
        assert_eq!(
            running.stop.as_ref().unwrap().reason,
            StopReason::OperatorSignal
        );
        let wall = running
            .final_limits()
            .into_iter()
            .find(|row| row.key == "wall")
            .unwrap();
        assert_eq!(wall.hit, Some(true));
        assert_eq!(
            running.observer_summary().unwrap().classes[&crate::observer::CoverageClass::Limits]
                .observed_count,
            Some(1)
        );
    }

    #[test]
    fn production_profiles_compile_and_execute_true() {
        use crate::policy::ProfileName;
        for profile in [ProfileName::Tool, ProfileName::Build, ProfileName::Agent] {
            let (_dir, plan) = policy_plan(profile);
            let params = profile_params(&plan, None).unwrap();
            let output = std::process::Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &seatbelt::generate(&params), "/usr/bin/true"])
                .current_dir("/")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{profile:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn production_protected_segments_are_applied() {
        use crate::policy::ProfileName;
        for profile in [ProfileName::Tool, ProfileName::Agent] {
            let (_dir, plan) = policy_plan(profile);
            std::fs::create_dir_all(plan.workspace.join(".git")).unwrap();
            let config = plan.workspace.join(".git/config");
            std::fs::write(&config, "original").unwrap();
            let params = profile_params(&plan, None).unwrap();
            assert!(!params.protected_segments.is_empty());
            let output = std::process::Command::new("/usr/bin/sandbox-exec")
                .args([
                    "-p",
                    &seatbelt::generate(&params),
                    "/bin/sh",
                    "-c",
                    "echo overwrite > \"$1\"",
                    "sh",
                ])
                .arg(&config)
                .current_dir("/")
                .output()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
                "{output:?}"
            );
            assert_eq!(std::fs::read_to_string(config).unwrap(), "original");
        }
    }

    #[test]
    fn build_grants_scratch_without_writable_workspace() {
        let (_dir, plan) = policy_plan(crate::policy::ProfileName::Build);
        let params = profile_params(&plan, None).unwrap();
        assert_eq!(params.read_write, vec![plan.attempt_dir.join("scratch")]);
    }

    #[test]
    fn filesystem_read_only_deny_read_and_extra_grants_are_enforced() {
        use crate::policy::{PathRef, ProfileName};
        let (_dir, mut plan) = policy_plan(ProfileName::Tool);
        let readonly = plan.workspace.join("readonly");
        let hidden = plan.workspace.join("hidden");
        let extra = plan.attempt_dir.join("extra");
        for path in [&readonly, &hidden, &extra] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::write(hidden.join("secret"), "private").unwrap();
        let reference = |path: &Path| {
            PathRef::host(
                NativeString::from_bytes(path.as_os_str().as_encoded_bytes().to_vec()).unwrap(),
            )
        };
        plan.request
            .snapshot
            .filesystem
            .read_only
            .push(reference(&readonly));
        plan.request
            .snapshot
            .filesystem
            .deny_read
            .push(reference(&hidden));
        plan.request
            .snapshot
            .filesystem
            .read_write
            .push(reference(&extra));
        let params = profile_params(&plan, None).unwrap();
        let profile = seatbelt::generate(&params);
        let run = |script: &str, path: &Path| {
            std::process::Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &profile, "/bin/sh", "-c", script, "sh"])
                .arg(path)
                .current_dir("/")
                .output()
                .unwrap()
        };
        assert!(run("echo allowed > \"$1/new\"", &extra).status.success());
        let readonly_denial = run("echo denied > \"$1/new\"", &readonly);
        assert!(!readonly_denial.status.success());
        assert!(!readonly.join("new").exists());
        let hidden_denial = run("cat \"$1/secret\"", &hidden);
        assert!(!hidden_denial.status.success());
        assert!(!String::from_utf8_lossy(&hidden_denial.stdout).contains("private"));
    }

    #[test]
    fn production_profile_denies_other_process_arguments_and_environment() {
        let (_dir, plan) = policy_plan(crate::policy::ProfileName::Tool);
        let source = plan.attempt_dir.join("procargs.c");
        let binary = plan.attempt_dir.join("procargs");
        std::fs::write(&source, r#"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "hold") == 0) { sleep(30); return 0; }
    char bytes[65536]; size_t n = sizeof(bytes);
    int pid = atoi(argv[1]);
    int args[] = {CTL_KERN, KERN_PROCARGS2, pid};
    int info[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    if (argc == 3) n = sizeof(struct kinfo_proc);
    int rc = argc == 3 ? sysctl(info, 4, bytes, &n, NULL, 0) : sysctl(args, 3, bytes, &n, NULL, 0);
    if (rc < 0) { printf("errno=%d\n", errno); return 1; }
    if (argc == 3) return n > 0 ? 0 : 2;
    const char *secret = "UKAI_REVIEW_SECRET=containment-sentinel";
    for (size_t i = 0; i + strlen(secret) <= n; i++) if (memcmp(bytes+i, secret, strlen(secret)) == 0) return 0;
    return 2;
}
"#).unwrap();
        let compile = std::process::Command::new("/usr/bin/cc")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(compile.status.success(), "{compile:?}");
        let mut params = profile_params(&plan, None).unwrap();
        params.read_only.push(binary.clone());
        let profile = seatbelt::generate(&params);
        let mut victim = std::process::Command::new(&binary)
            .arg("hold")
            .env("UKAI_REVIEW_SECRET", "containment-sentinel")
            .spawn()
            .unwrap();
        for info in [false, true] {
            let mut outside = std::process::Command::new(&binary);
            outside.arg(victim.id().to_string());
            if info {
                outside.arg("info");
            }
            let outside = outside.output().unwrap();
            let mut inside = std::process::Command::new("/usr/bin/sandbox-exec");
            inside
                .args(["-p", &profile])
                .arg(&binary)
                .arg(victim.id().to_string())
                .current_dir("/");
            if info {
                inside.arg("info");
            }
            let inside = inside.output().unwrap();
            if !outside.status.success() || inside.status.code() != Some(1) {
                let _ = victim.kill();
                let _ = victim.wait();
                panic!("positive control {outside:?}, sandbox {inside:?}");
            }
            assert_eq!(String::from_utf8_lossy(&inside.stdout).trim(), "errno=1");
        }
        let _ = victim.kill();
        let _ = victim.wait();
    }

    #[test]
    fn guardian_spawn_does_not_inherit_operator_environment() {
        let script = "test -z \"${RUSTUP_TOOLCHAIN+x}\" && test -z \"${HOME+x}\" && test \"$PATH\" = /usr/bin:/bin:/usr/sbin:/sbin";
        let pid = spawn_self(Path::new("/bin/sh"), &["-c".into(), script.into()], &[]).unwrap();
        let mut status = 0;
        // SAFETY: wait only for the child this test owns.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
    }

    #[test]
    fn a_kernel_bound_lifetime_never_enters_native_preparation() {
        let (_dir, mut plan) = policy_plan(crate::policy::ProfileName::Tool);
        plan.request.snapshot.lifetime_boundary =
            Some(crate::policy::LifetimeBoundary::KernelBound);
        let error = prepare(plan, Sinks { trace: None })
            .err()
            .expect("native must refuse --vm guarantee");
        assert_eq!(error.code, ErrorCode::UnsupportedPlatform);
        assert_eq!(error.remediation, Remediation::Unsupported);
        assert!(error.message.contains("--vm is required"));
    }

    #[test]
    fn launcher_tracking_selects_first_child_and_follows_exec_tokens() {
        let mut current = None;
        track_launcher(&mut current, 10, &EsEvent::Fork { token: token(10) });
        assert_eq!(current, None);
        let fork = token(11);
        track_launcher(&mut current, 10, &EsEvent::Fork { token: fork });
        track_launcher(&mut current, 10, &EsEvent::Fork { token: token(12) });
        assert_eq!(current, Some(fork));
        let mut exec = fork;
        exec[AUDIT_TOKEN_PIDVERSION] += 1;
        track_launcher(&mut current, 10, &EsEvent::Exec { token: exec });
        assert_eq!(current, Some(exec));
    }

    #[test]
    fn profile_evidence_records_paths_setuid_list_and_scan_holes() {
        let (_dir, plan) = policy_plan(crate::policy::ProfileName::Tool);
        let params = profile_params(&plan, None).unwrap();
        let receipt = params.receipt();
        assert!(receipt["read_write"].as_array().unwrap().iter().any(|p| {
            p.as_str().is_some_and(|path| {
                std::fs::canonicalize(path).ok() == std::fs::canonicalize(&plan.workspace).ok()
            })
        }));
        assert!(
            receipt["setuid_exec_denied"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == "/usr/bin/sudo")
        );
        assert!(
            receipt["protected_segments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p
                    .as_str()
                    .is_some_and(|path| Path::new(path).ends_with("work/.git")))
        );
        assert!(receipt["setuid_scan_holes"].is_array());
        let applied = build_applied(&plan, &params, None, false);
        assert!(
            applied.syscalls.is_none(),
            "Seatbelt operation rules are recorded under native profile_parameters"
        );
    }
    #[test]
    fn release_writes_r_and_keeps_a_open_until_stop() {
        use crate::platform::macos::guardian::frames::{Feed, Frame, FrameReader};
        let mut a = Pipe::new().unwrap();
        let mut r = Pipe::new().unwrap();
        let mut a_read = Fd::nonblocking(a.take_read()).unwrap();
        let mut r_read = Fd::nonblocking(r.take_read()).unwrap();
        let mut release = Fd(r.take_write());
        release_launcher(a.write, &mut release, Some(123)).unwrap();
        let mut bytes = [0u8; 128];
        let n = a_read.read(&mut bytes).unwrap();
        assert_eq!(
            FrameReader::default().read(&bytes[..n], false),
            Feed::Frames(vec![Ok(Frame::ReleaseDeadline(123))])
        );
        assert_eq!(
            a_read.read(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(r_read.read(&mut bytes).unwrap(), 1);
        assert_eq!(bytes[0], b'L');
        assert_eq!(
            pipe_read_bounded(&mut r_read, &mut bytes),
            0,
            "R closes after release"
        );
        drop(a);
        assert_eq!(
            pipe_read_bounded(&mut a_read, &mut bytes),
            0,
            "A EOF is the later stop"
        );
    }

    #[test]
    fn every_supervisor_pipe_end_is_close_on_exec() {
        let pipe = Pipe::new().unwrap();
        for fd in [pipe.read, pipe.write] {
            // SAFETY: queries this pipe's owned descriptors.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn absent_guardian_evidence_cannot_be_a_contiguous_stream() {
        let facts = guardian_facts(None, true, false);
        assert_eq!(facts["result"], "lost");
        assert_eq!(facts["stream"], "unknown");
        assert!(facts["events"].is_null());
        let drained = serde_json::json!({"drained": true, "reason": null, "forks": 1, "execs": 2, "exits": 1});
        let facts = guardian_facts(Some(&drained), false, false);
        assert_eq!(facts["stream"], "contiguous");
        assert_eq!(facts["events"], 4);
    }

    #[test]
    fn target_identity_tracks_every_exec_and_rejects_stale_exit() {
        let launcher = token(42);
        let mut first = launcher;
        first[AUDIT_TOKEN_PIDVERSION] += 1;
        let mut second = first;
        second[AUDIT_TOKEN_PIDVERSION] += 1;
        let mut current = None;
        let mut confirmed = false;
        assert_eq!(
            track_target(
                &EsEvent::Exec { token: first },
                &launcher,
                &mut current,
                &mut confirmed
            ),
            Some(RunEvent::ExecConfirmed)
        );
        assert_eq!(current, Some(first));
        assert_eq!(
            track_target(
                &EsEvent::Exec { token: second },
                &launcher,
                &mut current,
                &mut confirmed
            ),
            None
        );
        assert_eq!(current, Some(second));
        assert_eq!(
            track_target(
                &EsEvent::Exit {
                    token: first,
                    status: 0
                },
                &launcher,
                &mut current,
                &mut confirmed
            ),
            None
        );
        assert_eq!(
            track_target(
                &EsEvent::Exit {
                    token: second,
                    status: 0
                },
                &launcher,
                &mut current,
                &mut confirmed
            ),
            Some(RunEvent::TargetExited { code: 0 })
        );
    }

    #[test]
    fn required_staging_refuses_even_without_capability_derivation() {
        let (_dir, mut plan) = policy_plan(crate::policy::ProfileName::Tool);
        require_supported_staging(&plan).unwrap();
        plan.request
            .requirements
            .push(crate::capability::Requirement::CredentialStaging);
        let error = require_supported_staging(&plan).unwrap_err();
        assert_eq!(error.code, crate::records::ErrorCode::UnsupportedPlatform);
    }
    #[test]
    fn invalid_guardian_frames_invalidate_previous_evidence() {
        let mut reader = BReader::default();
        let mut record = None;
        receive_guardian_record(
            &mut reader,
            &frame(br#"record {"schema":"ukai.jail.guardian-record/1","drained":true}"#),
            &mut record,
        )
        .unwrap();
        assert_eq!(record.as_ref().unwrap()["drained"], true);
        assert!(receive_guardian_record(&mut reader, &0u32.to_le_bytes(), &mut record).is_err());
        assert!(record.is_none());
        for bytes in [
            frame(b"record {invalid}"),
            frame(b"ready"),
            frame(b"record {}"),
            frame(b"record null"),
        ] {
            assert!(receive_guardian_record(&mut BReader::default(), &bytes, &mut None).is_err());
        }
    }
}
