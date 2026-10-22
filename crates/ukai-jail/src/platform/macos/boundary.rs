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
//!    launch block cross the guardian's spawn by explicit `dup2(fd, fd)`,
//!    which clears close-on-exec on the child's copy: the inheritance
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
//! that drained (empty table, contiguous stream, no user change). A guardian
//! that dies before the stop is recorded and the run continues from S alone
//! (`tree_empty` stays possible from S); a guardian that stalls at the stop
//! is ended by process group after the drain and recorded as stalled.
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
use std::os::fd::{AsFd as _, RawFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::lifecycle::Integrity;
use crate::platform::macos::bridge::{self, BridgeConfig};
use crate::platform::macos::custody::{
    AUDIT_TOKEN_PID, AUDIT_TOKEN_PIDVERSION, Custodian, StopResult,
};
use crate::platform::macos::custody_io::{self, EsNewResult, EsSignaller, Token};
use crate::platform::macos::es::{self, CustodyClient, EsEvent};
use crate::platform::macos::guardian::frames::{encode_launcher_token, encode_release_deadline};
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
    Applied, AppliedFilesystem, AppliedMount, AppliedNetwork, AppliedTerminal, ErrorCode,
    ErrorStage, JailError, NativeLifetime, NativeString, Os, ProcessIdentity, ProcessRecord,
    Remediation,
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
        Ok(Pipe {
            read: fds[0],
            write: fds[1],
        })
    }
}

/// A raw descriptor this module owns, closed on drop, read nonblockingly.
struct Fd(RawFd);

impl Fd {
    /// Takes ownership of a descriptor and sets `O_NONBLOCK`: every read of
    /// B and E is one bounded poll slice, never a block without a deadline.
    fn nonblocking(fd: RawFd) -> Result<Self, JailError> {
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
        Ok(Fd(fd))
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
/// descriptors plus `fds` (a `dup2(fd, fd)` in the child clears
/// close-on-exec on that number), in its own process group, with this
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

    let mut envp_raw: Vec<*const libc::c_char> = Vec::new();
    // SAFETY: walking the C runtime's own NULL-terminated array, copying the
    // pointers for one spawn call.
    unsafe {
        let mut env = environ();
        while !(*env).is_null() {
            envp_raw.push(*env);
            env = env.add(1);
        }
    }
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
    for fd in fds {
        // SAFETY: `actions.0` is an initialized record; `dup2(fd, fd)` keeps
        // the number and clears close-on-exec on the child's copy — the
        // documented inheritance contract of §4.3 step 2.
        unsafe {
            if libc::posix_spawn_file_actions_adddup2(&mut actions.0, *fd, *fd) != 0 {
                return Err(spawn_error("posix_spawn_file_actions_adddup2"));
            }
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
            (POSIX_SPAWN_SETPGID | libc::POSIX_SPAWN_SETSIGMASK) as libc::c_short,
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
    let path_of =
        |native: &NativeString| PathBuf::from(OsString::from_vec(native.as_bytes().to_vec()));
    let mut params = ProfileParams {
        read_write: vec![path_of(&snapshot.roots.workspace)],
        ..ProfileParams::default()
    };
    match &snapshot.roots.scratch {
        crate::policy::ScratchRoot::Managed => {
            // The managed scratch lives in the attempt directory; the
            // profile admits exactly that directory.
            let scratch = plan.attempt_dir.join("scratch");
            let _ = std::fs::create_dir_all(&scratch);
            params.read_write.push(scratch);
        }
        crate::policy::ScratchRoot::Host { path } => params.read_write.push(path_of(path)),
    }
    if snapshot.roots.vendor_state.is_some() {
        // The vendor-state root is attempt-local (§4.11); the profile admits
        // exactly that directory.
        params
            .read_write
            .push(plan.attempt_dir.join("vendor-state"));
    }
    for pin in &plan.pinned_roots {
        params.read_only.push(pin.path.clone());
    }
    let roots: Vec<PathBuf> = params
        .read_write
        .iter()
        .chain(params.read_only.iter())
        .cloned()
        .collect();
    params.setuid_exec_denied = crate::platform::macos::setuid::scan_readable_roots(&roots)
        .map(|entries| crate::platform::macos::setuid::deny_paths(&entries))
        .map_err(|error| {
            refusal(
                ErrorCode::InternalError,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("the setuid scan failed: {error}"),
            )
        })?;
    if let Some(bridge) = bridge {
        params.bridge_http_port = Some(bridge.http_port);
        params.bridge_socks_port = Some(bridge.socks_port);
    }
    Ok(params)
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
fn build_applied(plan: &PreparedPlan, bridge: Option<&BridgeConfig>, terminal: bool) -> Applied {
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
    push(snapshot.roots.workspace.as_bytes(), "rw");
    if let crate::policy::ScratchRoot::Host { path } = &snapshot.roots.scratch {
        push(path.as_bytes(), "rw");
    }
    if snapshot.roots.vendor_state.is_some() {
        push(
            plan.attempt_dir
                .join("vendor-state")
                .as_os_str()
                .as_encoded_bytes(),
            "rw",
        );
    }
    for pin in &plan.pinned_roots {
        push(pin.path.as_os_str().as_encoded_bytes(), "ro");
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
            mechanism: bridge.map(|_| "loopback_bridge".to_owned()),
            allowed_hosts: snapshot.network.allow.clone(),
            tls_only: snapshot.network.tls_only.clone(),
        },
        syscalls: None,
        limits: Vec::new(),
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
    b_read: Fd,
    e_read: Fd,
    guardian_pid: libc::pid_t,
    launcher_token: Token,
    process: ProcessRecord,
    applied: Applied,
    wall_ms: Option<u64>,
    relay: Option<TerminalRelay>,
    headroom: u64,
    /// The outside proxy, the sink that tallies its results, and the
    /// loopback relay to it (§4.10); `None` without a proxy-mode network.
    proxy: Option<crate::proxy::ProxyHandle>,
    proxy_sink: Option<std::sync::Arc<crate::proxy::coverage::TraceSink>>,
    serving: Option<bridge::Serving>,
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
    let handshake = match handshake(
        &client,
        &mut built.b_read,
        &mut built.e_read,
        built.pipe_a_write,
        built.guardian_pid,
        &budget,
    ) {
        Ok(handshake) => handshake,
        Err(error) => {
            let _ = client.delete();
            return Err(error);
        }
    };

    let capacity = crate::platform::macos::custody::table_capacity(maxprocperuid());
    let process = ProcessRecord {
        pid: handshake.launcher_token[AUDIT_TOKEN_PID],
        identity: ProcessIdentity {
            kind: "macos_audit_token".to_owned(),
            value: audit_token_value(handshake.launcher_token),
        },
    };
    // The outside proxy on the attempt's private socket, and the loopback
    // relay to it (§4.10): the policy, the vault and the secret are the
    // proxy's, and the relay interprets nothing.
    let (proxy, proxy_sink, serving) = match bridge_bound {
        Some(bound) => {
            let started = start_proxy(&plan, &sinks, &bound);
            match started {
                Ok(started) => (Some(started.0), Some(started.1), Some(started.2)),
                Err(error) => {
                    let _ = client.delete();
                    return Err(error);
                }
            }
        }
        None => (None, None, None),
    };
    Ok(Box::new(MacosPrepared {
        client: Some(client),
        engine: Custodian::new(capacity).with_stop(SETTLE_NS, STOP_BUDGET_NS),
        a_write: handshake.a_write,
        b_read: built.b_read,
        e_read: built.e_read,
        guardian_pid: built.guardian_pid,
        launcher_token: handshake.launcher_token,
        process,
        applied: build_applied(&plan, bridge_config.as_ref(), relay.is_some()),
        wall_ms: plan
            .request
            .snapshot
            .limits
            .wall
            .as_ref()
            .and_then(|wall| wall.value.parse::<u64>().ok()),
        relay,
        headroom: u64::from(NPROC_HEADROOM),
        proxy,
        proxy_sink,
        serving,
    }))
}

/// Starts the outside proxy on the attempt's private socket and the
/// loopback relay to it (§4.10): the child's proxy URLs name the two
/// loopback ports, the relay carries them to the proxy, and the proxy holds
/// the policy, the vault and the per-attempt secret.
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
    pipe_a_write: RawFd,
    guardian_pid: libc::pid_t,
}

fn build_and_spawn(
    plan: &PreparedPlan,
    relay: Option<&mut TerminalRelay>,
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
    let pipe_a = Pipe::new()?;
    let pipe_b = Pipe::new()?;
    let pipe_r = Pipe::new()?;
    let pipe_e = Pipe::new()?;

    let exe = std::env::current_exe().map_err(|error| {
        refusal(
            ErrorCode::BackendUnavailable,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the executable's path could not be read: {error}"),
        )
    })?;
    let slave_fd = relay.and_then(|relay| relay.slave_fd());
    let sigmask = capture_mask();
    let launcher = launcher_argv(
        &exe,
        pipe_r.read,
        pipe_e.write,
        slave_fd,
        sigmask,
        &plan.argv,
    )?;
    let block = LaunchBlock {
        sandbox_exec_path: "/usr/bin/sandbox-exec".to_owned(),
        sbpl_profile_source: seatbelt::generate(&profile_params(plan, bridge)?),
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
    // SAFETY: a plain open of a path this supervisor created; close-on-exec.
    let block_fd = unsafe {
        libc::open(
            block_path.as_os_str().as_encoded_bytes().as_ptr().cast(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if block_fd < 0 {
        return Err(refusal(
            ErrorCode::InvalidFd,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!(
                "the launch block could not be reopened: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    let block_fd = Fd(block_fd);

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
    let guardian_pid = spawn_self(
        &exe,
        &args,
        &[
            pipe_a.read,
            pipe_b.write,
            pipe_r.read,
            pipe_e.write,
            block_fd.0,
        ],
    )?;
    // The child ends close: the parent keeps only its own pipe halves, the
    // launch block closes, and the relay's slave has crossed the spawn chain
    // (a Darwin pty master reports EOF only once every slave is closed).
    drop(block_fd);
    Ok(Spawned {
        b_read: Fd::nonblocking(pipe_b.read)?,
        e_read: Fd::nonblocking(pipe_e.read)?,
        pipe_a_write: pipe_a.write,
        guardian_pid,
    })
}

// ---------------------------------------------------------------------------
// The handshake (§4.3 steps 3–5)
// ---------------------------------------------------------------------------

/// What the handshake leaves behind.
struct Handshake {
    a_write: RawFd,
    launcher_token: Token,
}

fn handshake_timeout(guardian_pid: libc::pid_t, pipe_a_write: RawFd) -> JailError {
    abort_guardian(guardian_pid, pipe_a_write);
    refusal(
        ErrorCode::PrepareTimeout,
        ErrorStage::Preparing,
        Remediation::Retry,
        "the guardian did not complete the launch handshake within the preparation budget",
    )
}

/// Reaps an aborted preparation: closes A (whose end-of-file is the
/// guardian's stop), then ends and reaps the guardian.
fn abort_guardian(guardian_pid: libc::pid_t, pipe_a_write: RawFd) {
    // SAFETY: a plain close of a descriptor this process owns.
    unsafe { libc::close(pipe_a_write) };
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        // SAFETY: WNOHANG waitpid on a pid this process spawned.
        let status = unsafe { libc::waitpid(guardian_pid, std::ptr::null_mut(), libc::WNOHANG) };
        if status == guardian_pid || status < 0 {
            return;
        }
        if Instant::now() >= deadline {
            // SAFETY: scalar signal and reaping wait for the guardian.
            unsafe {
                libc::kill(guardian_pid, libc::SIGKILL);
                libc::waitpid(guardian_pid, std::ptr::null_mut(), 0);
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The handshake of §4.3 steps 3–5, within the preparation budget.
fn handshake(
    client: &CustodyClient,
    b_read: &mut Fd,
    e_read: &mut Fd,
    pipe_a_write: RawFd,
    guardian_pid: libc::pid_t,
    budget: &ContinuousDeadline,
) -> Result<Handshake, JailError> {
    let deadline = Instant::now() + budget.remaining();
    let mut reader = BReader::default();
    // `ready` (step 3). A guardian that dies names its failing step on
    // stderr and its exit status here.
    let mut ready = false;
    loop {
        for frame in read_b(&mut reader, b_read, guardian_pid)? {
            match frame {
                BFrame::Ready => ready = true,
                other => {
                    abort_guardian(guardian_pid, pipe_a_write);
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
            return Err(handshake_timeout(guardian_pid, pipe_a_write));
        }
        client.drain(TICK_MS);
    }
    // The launcher's fork: the first event on S whose pid is not the
    // guardian's own (§4.2). The launcher's `blocked` on E rides alongside.
    let mut launcher_token: Option<Token> = None;
    let mut blocked_seen = false;
    loop {
        if launcher_token.is_none() {
            launcher_token = drain_until_launcher_fork(client, guardian_pid, launcher_token);
        }
        if let Some(report) = read_e(e_read) {
            if report.is_empty() {
                // End-of-file on E before `blocked`: the launcher never ran.
                abort_guardian(guardian_pid, pipe_a_write);
                return Err(exec_report_refusal(&[]));
            }
            if crate::platform::macos::launcher::is_blocked_report(&report) {
                blocked_seen = true;
            } else if launcher_token.is_some() {
                // An exec report before `blocked` cannot happen in the
                // grammar; treat it as what it is, a failed launch.
                abort_guardian(guardian_pid, pipe_a_write);
                return Err(exec_report_refusal(&report));
            }
        }
        if let (Some(token), true) = (launcher_token, blocked_seen) {
            // Step 5: the launcher's current token goes on A.
            write_frame(pipe_a_write, &encode_launcher_token(&token))?;
            loop {
                for frame in read_b(&mut reader, b_read, guardian_pid)? {
                    if matches!(frame, BFrame::TokenSeen) {
                        return Ok(Handshake {
                            a_write: pipe_a_write,
                            launcher_token: token,
                        });
                    }
                }
                if Instant::now() >= deadline {
                    return Err(handshake_timeout(guardian_pid, pipe_a_write));
                }
                client.drain(TICK_MS);
            }
        }
        if b_eof(b_read)? {
            abort_guardian(guardian_pid, pipe_a_write);
            let code = guardian_exit_code(guardian_pid);
            return Err(refusal(
                ErrorCode::BackendUnavailable,
                ErrorStage::Preparing,
                Remediation::InspectState,
                format!("the guardian exited during the launch handshake (exit {code})"),
            ));
        }
        if Instant::now() >= deadline {
            return Err(handshake_timeout(guardian_pid, pipe_a_write));
        }
        client.drain(TICK_MS);
    }
}

/// One bounded poll slice of B. Returns the frames that completed.
fn read_b(
    reader: &mut BReader,
    b_read: &mut Fd,
    guardian_pid: libc::pid_t,
) -> Result<Vec<BFrame>, JailError> {
    let mut buffer = [0u8; 4096];
    match b_read.read(&mut buffer) {
        Ok(0) => {
            let code = guardian_exit_code(guardian_pid);
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

/// Whether B has reached end-of-file: the guardian is gone (§4.6).
fn b_eof(b_read: &mut Fd) -> Result<bool, JailError> {
    let mut byte = [0u8; 1];
    Ok(matches!(b_read.read(&mut byte), Ok(0)))
}

/// Drains S until the launcher's fork appears; returns its token. The
/// guardian's own fork (its pid) is not a member (§4.2).
fn drain_until_launcher_fork(
    client: &CustodyClient,
    guardian_pid: libc::pid_t,
    _previous: Option<Token>,
) -> Option<Token> {
    let mut found = None;
    while let Some(poll) = client.poll_full() {
        if let EsEvent::Fork { token } = poll.event
            && token[AUDIT_TOKEN_PID] as libc::pid_t != guardian_pid
        {
            found = Some(token);
        }
    }
    found
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
fn write_frame(fd: RawFd, frame: &[u8]) -> Result<(), JailError> {
    let mut written = 0usize;
    while written < frame.len() {
        // SAFETY: the buffer is live and only `written` past its start.
        let n = unsafe { libc::write(fd, frame[written..].as_ptr().cast(), frame.len() - written) };
        if n < 0 {
            if errno() == libc::EINTR {
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

/// The reaping wait for a guardian that already exited; the exit code, or
/// -1 when it did not exit cleanly.
fn guardian_exit_code(guardian_pid: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: a blocking reaping wait for a pid this process spawned.
    let reaped = unsafe { libc::waitpid(guardian_pid, &mut status, 0) };
    if reaped == guardian_pid && libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
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
        details.insert(
            "process_headroom".to_owned(),
            serde_json::Value::from(self.headroom),
        );
        details.insert(
            "profile_digest".to_owned(),
            serde_json::Value::from(seatbelt::template_digest()),
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
        mut self: Box<Self>,
    ) -> Result<Box<dyn crate::platform::RunningExecution>, Box<ReleaseFailure>> {
        // §4.3 step 6: the release deadline on A, then the release byte on
        // R. The deadline is continuous-clock nanoseconds; both custodians
        // arm their wall from release, and it counts sleep.
        let release_ns = es::continuous_time_ns();
        let wall_ns = self.wall_ms.map_or(0, |ms| ms.saturating_mul(1_000_000));
        let fail = |error: JailError, teardown: Teardown| {
            Box::new(ReleaseFailure {
                error,
                teardown: Some(teardown),
            })
        };
        if let Err(error) = write_frame(
            self.a_write,
            &encode_release_deadline(release_ns.saturating_add(wall_ns)),
        ) {
            let error = refusal(
                ErrorCode::InvalidFd,
                ErrorStage::Released,
                Remediation::InspectState,
                format!("the release deadline could not be sent: {}", error.message),
            );
            return Err(fail(error, self.abort_inner()));
        }
        if let Err(error) = write_frame(self.a_write, b"L") {
            let error = refusal(
                ErrorCode::InvalidFd,
                ErrorStage::Released,
                Remediation::InspectState,
                format!("the release byte could not be sent: {}", error.message),
            );
            return Err(fail(error, self.abort_inner()));
        }
        // The supervisor holds no other end of R: end-of-file on R is the
        // launcher's, exactly as on Linux (jail-v1 §8.3).
        // SAFETY: a plain close of the descriptor this process owns.
        unsafe { libc::close(self.a_write) };
        self.a_write = -1;
        Ok(Box::new(MacosRunning::from_prepared(*self, release_ns)))
    }

    fn abort(mut self: Box<Self>) -> Result<Teardown, JailError> {
        Ok(self.abort_inner())
    }
}

impl MacosPrepared {
    /// Tears the prepared boundary down without running the target: A's
    /// end-of-file is the guardian's stop, and the blocked launcher — the
    /// only member — is killed by token like any other (§4.5, §4.3).
    fn abort_inner(&mut self) -> Teardown {
        if self.a_write >= 0 {
            // SAFETY: a plain close of a descriptor this process owns.
            unsafe { libc::close(self.a_write) };
            self.a_write = -1;
        }
        let _ = es::signal_by_token(&self.launcher_token, libc::SIGKILL);
        let tree = self.settle_guardian(GUARDIAN_TAIL);
        if let Some(client) = self.client.take() {
            let _ = client.delete();
        }
        Teardown { tree }
    }

    /// Waits for the guardian's record on B, then reaps it; ends a stalled
    /// guardian by process group. The tree facts come from the record and
    /// from S's own view.
    /// The live client, until [`MacosPrepared::abort_inner`] deletes it.
    fn custody(&self) -> &CustodyClient {
        self.client
            .as_ref()
            .expect("the client is deleted only at teardown")
    }

    fn settle_guardian(&mut self, tail: Duration) -> Option<TreeObservation> {
        let deadline = Instant::now() + tail;
        let mut reader = BReader::default();
        let mut record_json: Option<Vec<u8>> = None;
        while Instant::now() < deadline {
            let mut buffer = [0u8; 4096];
            match self.b_read.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(frames) = reader.feed(&buffer[..n]) {
                        for frame in frames {
                            if let BFrame::Record(json) = frame {
                                record_json = Some(json);
                            }
                        }
                    }
                }
                Err(_) => {}
            }
            if record_json.is_some() {
                break;
            }
            // The supervisor's table keeps moving while the guardian works,
            // so its own view stays current for the observation.
            while let Some(poll) = self.custody().poll_full() {
                if let Some(kind) = custody_io::custody_kind(poll.kind) {
                    let _ =
                        self.engine
                            .apply_sequenced(kind, poll.global_seq, poll.seq, &poll.event);
                }
            }
            // SAFETY: WNOHANG waitpid on a pid this process spawned.
            if unsafe { libc::waitpid(self.guardian_pid, std::ptr::null_mut(), libc::WNOHANG) }
                == self.guardian_pid
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: the final reaping wait; the guardian exits after its
        // record (§4.4), and a stalled one has been killed by its group.
        if unsafe { libc::waitpid(self.guardian_pid, std::ptr::null_mut(), libc::WNOHANG) }
            != self.guardian_pid
        {
            // SAFETY: ending a guardian that did not finish in its tail.
            unsafe {
                libc::kill(self.guardian_pid, libc::SIGKILL);
                libc::waitpid(self.guardian_pid, std::ptr::null_mut(), 0);
            }
        }
        let record = record_json
            .as_deref()
            .map(serde_json::from_slice::<serde_json::Value>)
            .and_then(Result::ok);
        let integrity = self.engine.integrity_loss();
        let guardian_drained = record
            .as_ref()
            .and_then(|record| record.get("drained"))
            .and_then(serde_json::Value::as_bool);
        let tree_empty = if integrity { None } else { guardian_drained };
        let verified_at = tree_empty.filter(|empty| *empty).map(|_| SystemTime::now());
        Some(TreeObservation {
            tree_empty,
            verified_at,
            verification_scope: VerificationScope::AttemptTree,
            integrity: if tree_empty == Some(true) && !integrity {
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
    guardian_pid: libc::pid_t,
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
    stop: Option<StopDrive>,
    stop_result: Option<StopResult>,
    integrity_lost: bool,
    events: u64,
    peak_members: usize,
    relay: Option<TerminalRelay>,
    target_stop_signal: Option<i32>,
    headroom: u64,
    /// The outside proxy, its tally, and the loopback relay (§4.10).
    proxy: Option<crate::proxy::ProxyHandle>,
    proxy_sink: Option<std::sync::Arc<crate::proxy::coverage::TraceSink>>,
    serving: Option<bridge::Serving>,
}

/// The cooperative grace, then the stop (§4.5).
struct StopDrive {
    #[allow(dead_code)]
    reason: StopReason,
    grace_ends_ns: u64,
    begun: bool,
}

impl MacosRunning {
    fn from_prepared(prepared: MacosPrepared, release_ns: u64) -> Self {
        Self {
            client: prepared.client,
            engine: prepared.engine,
            a_write: prepared.a_write,
            b_read: prepared.b_read,
            e_read: prepared.e_read,
            b_reader: BReader::default(),
            guardian_pid: prepared.guardian_pid,
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
            stop: None,
            stop_result: None,
            integrity_lost: false,
            events: 0,
            peak_members: 0,
            relay: prepared.relay,
            target_stop_signal: None,
            headroom: prepared.headroom,
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
        let kind = custody_io::custody_kind(poll.kind)?;
        self.events += 1;
        self.engine
            .apply_sequenced(kind, poll.global_seq, poll.seq, &poll.event);
        self.peak_members = self.peak_members.max(self.engine.live_count());
        if self.engine.integrity_loss() && !self.integrity_lost {
            self.integrity_lost = true;
            return Some(RunEvent::EvidenceLost {
                reason: "membership integrity lost (a member changed user or the membership \
                         table filled)"
                    .to_owned(),
                after_target_end: self.target_ended(),
            });
        }
        match poll.event {
            // §4.3 step 7: the launcher's NOTIFY_EXEC confirms the exec. The
            // exec event carries the new token; the launcher's process is
            // known by its pid (the table's key), and its new token is the
            // target's identity.
            EsEvent::Exec { token }
                if !self.exec_confirmed
                    && token[AUDIT_TOKEN_PID] == self.launcher_token[AUDIT_TOKEN_PID] =>
            {
                self.exec_confirmed = true;
                self.target_token = Some(token);
                Some(RunEvent::ExecConfirmed)
            }
            EsEvent::Exit { token, status } if self.target_token == Some(token) => {
                exit_status_event(status)
            }
            _ => None,
        }
    }

    /// Drains everything available on S, returning the first run event.
    fn drain_events(&mut self) -> Option<RunEvent> {
        while let Some(poll) = self.custody().poll_full() {
            if let Some(event) = self.apply_event(&poll) {
                return Some(event);
            }
        }
        if self.custody().ring_overflowed() && !self.engine.gapped() {
            // §4.4: a gap marks the stream for the rest of the attempt.
            self.engine.note_stream_gap();
            return Some(RunEvent::EvidenceLost {
                reason: "the custody stream dropped messages (ring overflow)".to_owned(),
                after_target_end: self.target_ended(),
            });
        }
        None
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
        let mut buffer = [0u8; 4096];
        match self.b_read.read(&mut buffer) {
            Ok(0) => self.guardian_lost = true,
            Ok(n) => {
                if let Ok(frames) = self.b_reader.feed(&buffer[..n]) {
                    for frame in frames
                        .into_iter()
                        .filter_map(|frame| match frame {
                            BFrame::Record(json) => Some(json),
                            _ => None,
                        })
                        .filter_map(|json| serde_json::from_slice(&json).ok())
                    {
                        self.guardian_record = Some(frame);
                    }
                }
            }
            Err(_) => {}
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

    /// Ends a guardian that stalled at the stop, by process group (§4.5:
    /// "the supervisor reaps it, and ends it by audit token first if it is
    /// stalled"; the group is the pid here, the guardian being its own
    /// group leader).
    fn end_stalled_guardian(&mut self) {
        // SAFETY: scalar signal and reaping wait for the guardian's group.
        unsafe {
            libc::kill(self.guardian_pid, libc::SIGKILL);
            libc::waitpid(self.guardian_pid, std::ptr::null_mut(), 0);
        }
        self.guardian_stalled = true;
        // §4.6: the stall reaches the settled receipt's `errors[]`.
        self.custodian_errors.push(crate::records::JailError::new(
            crate::records::ErrorCode::CustodianStalled,
            crate::records::ErrorStage::Stopping,
            crate::records::Remediation::InspectState,
            "the guardian custodian stalled at the stop and was ended; the supervisor drained \
             the tree alone"
                .to_owned(),
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
                "the guardian custodian was lost at the stop; the supervisor drained the tree \
                 alone"
                    .to_owned(),
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
        let observed = own.is_some() || guardian_drained.is_some();
        // tree_empty=true needs one custodian that drained; anything else is
        // tree_unknown (§4.5). Failed verification loses integrity and
        // retains state, as on Linux.
        let tree_empty = if !observed || integrity {
            None
        } else {
            Some(drained)
        };
        let verified_at = tree_empty.filter(|empty| *empty).map(|_| SystemTime::now());
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
        let record = self.guardian_record.as_ref();
        let result = if self.guardian_lost && record.is_none() {
            "lost"
        } else if self.guardian_stalled {
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
            _ => "contiguous",
        };
        let events = record
            .map(|record| {
                ["forks", "execs", "exits"]
                    .iter()
                    .filter_map(|key| record.get(*key).and_then(serde_json::Value::as_u64))
                    .sum::<u64>()
            })
            .unwrap_or(0);
        serde_json::json!({
            "result": result,
            "stream": stream,
            "events": events,
        })
    }
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
            if self.guardian_lost && self.guardian_record.is_none() && self.a_write >= 0 {
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
        match self.stop.as_mut() {
            Some(stop) => {
                // The grace is running; an explicit second ask ends it now:
                // the caller owns the lifecycle and has asked again.
                stop.grace_ends_ns = es::continuous_time_ns();
            }
            None => {
                // §4.5: `SIGTERM` to the target by audit token, initial 2 s.
                if let Some(token) = self.target_token
                    && es::signal_by_token(&token, libc::SIGTERM) == 0
                {
                    self.target_stop_signal = Some(libc::SIGTERM);
                    if let Some(relay) = self.relay.as_mut() {
                        let _ = relay.relayed_stop(libc::SIGTERM);
                    }
                }
                self.stop = Some(StopDrive {
                    reason,
                    grace_ends_ns: es::continuous_time_ns() + STOP_GRACE_NS,
                    begun: false,
                });
            }
        }
    }

    fn wait_tree(&mut self, budget: Duration) -> TreeObservation {
        self.settle(budget)
    }

    fn observer_summary(&mut self) -> Option<crate::observer::CoverageSummary> {
        // §4.10/§5: `proxy.net` comes from the bridge, as on Linux. Every
        // other class is the observer's (J17) or unobserved.
        let proxy = self.proxy.take()?;
        let stopped_at = (!proxy.serving()).then(crate::platform::elapsed_since_start_ns);
        let summary = proxy.stop(crate::proxy::MAX_DEADLINE);
        let (delivered, lost, resolver_refused) = self
            .proxy_sink
            .as_ref()
            .map_or((0, 0, 0), |sink| sink.account());
        let mut coverage = crate::observer::CoverageSummary::unobserved();
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

    fn target_stop(&mut self) -> Option<i32> {
        self.target_stop_signal.take()
    }
}

impl MacosRunning {
    /// One relay slice; `Some` is a stdio failure the supervisor records.
    fn pump_relay(&mut self) -> Option<RunEvent> {
        let relay = self.relay.as_mut()?;
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
            // SAFETY: WNOHANG waitpid on a pid this process spawned.
            if unsafe { libc::waitpid(self.guardian_pid, std::ptr::null_mut(), libc::WNOHANG) }
                == self.guardian_pid
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: the final reaping wait, after ending a stalled guardian.
        unsafe {
            if libc::waitpid(self.guardian_pid, std::ptr::null_mut(), libc::WNOHANG)
                != self.guardian_pid
            {
                libc::kill(self.guardian_pid, libc::SIGKILL);
                libc::waitpid(self.guardian_pid, std::ptr::null_mut(), 0);
            }
        }
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
        let Some(kind) = custody_io::custody_kind(poll.kind) else {
            continue;
        };
        engine.apply_sequenced(kind, poll.global_seq, poll.seq, &poll.event);
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

    /// The §4.3 step 1 refusal, through the real platform seam: on this Mac
    /// (no entitlement) client creation answers `ERR_NOT_ENTITLED` and
    /// `prepare` refuses with remediation `unsupported`, naming the code.
    #[test]
    fn prepare_refuses_naming_err_not_entitled_and_unsupported() {
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
            error.message.contains("ERR_NOT_ENTITLED"),
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
}
