//! `ukai-vm` (J18, jail-macos.md §6): the per-operator host program for the
//! warm Linux guest.
//!
//! One subcommand runs the service: `ukai-vm serve` discovers and verifies
//! the installed preview image (the same paths `install.sh.in` writes, or
//! `UKAI_VM_HOME`), reuses the preview's custodian and VZ client binaries
//! unmodified, boots the guest once, and serves attempts on two Unix
//! sockets beneath the operator's data directory:
//!
//! * `vm/control.sock` — `status` and `stop` (`ukai-jail vm stop`).
//! * `vm/attempt.sock` — one connection per attempt, the lease by
//!   end-of-file (§6: "The lease is end-of-file, not a timer").
//!
//! The service stays a foreground process that operator tooling starts and
//! stops: no launchd job, no detached double fork, no root. After
//! [`IDLE_SECONDS`] with no live attempt, on the continuous clock, it stops
//! the guest and exits. A boot that fails or is refused keeps its
//! directory (console, copied image, nvram) under `vm/<boot id>` as
//! evidence; the newest [`KEPT_BOOT_DIRS`] are kept, older ones removed.
//! The wire frames are [`protocol`]; the guest
//! controller's own vsock frames are this file's `guest` module, the warm
//! successors of the preview's (`session`, `reset`, `secret`, `run2`,
//! `cancel2` join `ready`, `put` and `run`, which keep their meaning).

#![allow(clippy::too_many_lines)]

use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::process::CommandExt as _;

#[path = "../platform/macos/vm/control.rs"]
// Both ends include the wire modules by path; the bin drives the subset it
// serves, and the rest is the host's surface (the same shape tests/common
// takes).
#[allow(dead_code)]
mod control;
#[path = "../platform/macos/vm/image.rs"]
// Both ends include the wire modules by path; the bin drives the subset it
// serves, and the rest is the host's surface (the same shape tests/common
// takes).
#[allow(dead_code)]
mod image;
#[path = "../platform/macos/vm/protocol.rs"]
// Both ends include the wire modules by path; the bin drives the subset it
// serves, and the rest is the host's surface (the same shape tests/common
// takes).
#[allow(dead_code)]
mod protocol;
#[path = "../platform/macos/vm/record.rs"]
// Both ends include the wire modules by path; the bin drives the subset it
// serves, and the rest is the host's surface (the same shape tests/common
// takes).
#[allow(dead_code)]
mod record;
#[path = "../platform/macos/vm/share.rs"]
// The live-workspace preflight, shared with the supervisor's vm module.
mod share;

/// The idle budget: no live attempt for this long ends the warm guest
/// (jail-macos.md §6: "initial 10 min").
pub const IDLE_SECONDS: u64 = 600;

/// The custody lease, exactly the preview's: the custodian kills the VZ
/// client after this long without a refresh, and a refresh must be
/// acknowledged within [`LEASE_ACK`].
const LEASE_REFRESH: Duration = Duration::from_millis(250);
const LEASE_ACK: Duration = Duration::from_millis(1500);

/// The guest controller's vsock port, the preview's.
const GUEST_PORT: u32 = 1024;

/// The package version this build reports (D8): the packager sets
/// `UKAI_VM_PACKAGE_VERSION` from release.json's `vm.candidate_version` when
/// it builds `ukai-vm`; any other build says it is a development build of
/// the crate version.
const PACKAGE_VERSION: &str = match option_env!("UKAI_VM_PACKAGE_VERSION") {
    Some(version) => version,
    None => concat!(env!("CARGO_PKG_VERSION"), "-dev"),
};

/// How many boot directories (guest console, copied image, nvram) of
/// failed or refused boots the service keeps as evidence. Older ones are
/// removed when a service starts and whenever it keeps a new one: each
/// holds a clone of the guest disk, so an unbounded history is unbounded
/// disk.
const KEPT_BOOT_DIRS: usize = 3;

// ---------------------------------------------------------------------------
// The helper (custodian → VZ client) and guest protocols
// ---------------------------------------------------------------------------

/// Host → helper, over the custodian's stdin: write bytes to the guest, or
/// stop. The preview's frames, unchanged.
#[derive(Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum HelperWrite {
    /// `data` is the base64 of whole NDJSON lines for the guest.
    Write { data: String },
    /// An orderly VM stop; the helper acknowledges with `stopped`.
    Stop,
}

/// Helper → host, over the custodian's stdout. Fields the service does not
/// read are not constrained (the preview's rule); `data` is read strictly.
#[derive(Clone, Deserialize)]
struct HelperEvent {
    event: String,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Host → guest, over vsock. `ready`, `put`, `ping`, `run` and `cancel`
/// keep the preview's meaning; the warm session adds the rest (jail-macos.md
/// §6).
#[derive(Clone, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum GuestOp {
    /// Enter the warm multi-run session.
    Session,
    /// Empty the attempt directories for the next attempt.
    Reset,
    /// Stage one ephemeral credential in the guest's tmpfs (J18 §6): the
    /// value crosses once per attempt and is never on the guest disk; the
    /// launch profile's sources name these paths, the guest jail's vault
    /// reads them, and the guest removes them when the attempt ends.
    Secret { id: String, data: String },
    /// Receive the vaulted launch profile's TOML for this attempt (the
    /// guest controller writes it under its config dir and runs the jail
    /// with `--launch NAME`).
    LaunchToml { toml: String },
    /// One workspace file, the preview's frame.
    Put {
        path: String,
        executable: bool,
        data: String,
    },
    /// Run the jail, warm: no poweroff at completion.
    Run2 {
        attempt_id: String,
        boot_id: String,
        profile: String,
        wall_seconds: u32,
        argv: Vec<String>,
        allow_hosts: Vec<String>,
        /// The vaulted launch profile (J18 §6): the name for the guest
        /// jail's `--launch` grammar. The guest synthesizes the TOML with
        /// credential sources at the tmpfs staging root.
        launch: Option<String>,
    },
    /// Cancel one attempt; the session stays up.
    Cancel2,
    /// The preview's lease ping; a warm session ignores the timer, and no
    /// warm code path constructs this: it exists so the parser and the
    /// guest's grammar agree on every name.
    #[allow(dead_code)]
    Ping { sequence: i64 },
}

/// Guest → host, over vsock. Typed where the service reads; the fields a
/// warm session does not read stay named, so the parser and the guest's
/// grammar agree on every name.
#[derive(Clone, Deserialize)]
#[allow(dead_code)]
struct GuestEvent {
    event: String,
    #[serde(default)]
    kernel: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    executable: Option<bool>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    supervisor_pid: Option<u32>,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    sequence: Option<i64>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    binding: Option<protocol::ReceiptBinding>,
    /// D6: the guest controller's stop of a warm attempt, carried by `done`;
    /// relayed as the guest reported it, and judged by the client.
    #[serde(default)]
    stop: Option<protocol::GuestStop>,
    /// D7: whether the guest mounted the live workspace share (`ready` and
    /// `session` state it).
    #[serde(default)]
    live_share: Option<bool>,
}

// ---------------------------------------------------------------------------
// Shared service state
// ---------------------------------------------------------------------------

/// What the control socket's `status` reports, kept current by the threads.
#[derive(Default)]
struct Shared {
    stopping: AtomicBool,
    attempt_live: AtomicBool,
    helper_alive: AtomicBool,
    failed: AtomicBool,
}

impl Shared {
    fn stop_requested(&self) -> bool {
        // The signal handler can only set STOP. Every thread must observe
        // that request before interpreting teardown as a custody failure.
        STOP.load(AtomicOrdering::SeqCst) || self.stopping.load(AtomicOrdering::SeqCst)
    }
}

// SAFETY: a plain system call; the symbol is linked only on macOS, where
// the call site compiles in.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_continuous_time() -> u64;
}

// `libc` marks the Mach time functions deprecated in favour of the `mach2`
// crate, which this crate does not carry; the calls are the standard port.
#[allow(deprecated)]
fn continuous_ns() -> u128 {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `mach_continuous_time` and `mach_timebase_info` are plain
        // system calls reading fixed-size memory the caller owns.
        unsafe {
            let mut scale = std::mem::MaybeUninit::<libc::mach_timebase_info_data_t>::uninit();
            if libc::mach_timebase_info(scale.as_mut_ptr()) != 0 {
                return 0;
            }
            let scale = scale.assume_init();
            u128::from(mach_continuous_time()) * u128::from(scale.numer) / u128::from(scale.denom)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::time::Instant;
        static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        BASE.get_or_init(Instant::now).elapsed().as_nanos()
    }
}

static STOP: AtomicBool = AtomicBool::new(false);

/// The guest kernel, once the session handshake reported it; the control
/// thread's `status` reads it.
static SHARED_GUEST_KERNEL: Mutex<Option<String>> = Mutex::new(None);

extern "C" fn on_signal(_signal: libc::c_int) {
    STOP.store(true, AtomicOrdering::SeqCst);
}

fn install_signal_handlers() {
    // SAFETY: the handler only stores to an atomic, which is
    // async-signal-safe; the signals it replaces have no Rust handlers.
    unsafe {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            #[allow(deprecated)]
            let handler: unsafe extern "C" fn(libc::c_int) = on_signal;
            #[allow(deprecated)]
            libc::signal(signal, handler as libc::sighandler_t);
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

struct Service {
    helper_stdin: Arc<Mutex<std::process::ChildStdin>>,
    shared: Arc<Shared>,
    boot_id: String,
    install: image::Install,
    sockets: (PathBuf, PathBuf),
    /// The live workspace share (J18 §6): the host directory crossing as
    /// one writable virtio-fs device, with its preflight facts. `None` is
    /// the preview's staged mode.
    live_share: Option<(PathBuf, share::ShareFacts)>,
    /// Whether this guest booted with its NAT adapter.
    guest_nat: bool,
}

/// One guest frame as the reader thread delivered it, or the transport's end.
enum GuestLine {
    Frame(Box<GuestEvent>),
    HelperEnded(String),
}

fn write_helper(service: &Service, frame: &HelperWrite) -> Result<(), String> {
    let line = protocol::encode(frame).map_err(|error| error.to_string())?;
    let mut stdin = service
        .helper_stdin
        .lock()
        .map_err(|error| error.to_string())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut pending = line.as_slice();
    while !pending.is_empty() {
        match stdin.write(pending) {
            Ok(0) => return Err("the VZ client stopped reading".to_owned()),
            Ok(n) => pending = &pending[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err("the VZ client write timed out".to_owned());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("the VZ client stopped reading: {error}")),
        }
    }
    Ok(())
}

fn guest_line(service: &Service, frame: &GuestOp) -> Result<(), String> {
    let mut line = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
    line.push(b'\n');
    write_helper(
        service,
        &HelperWrite::Write {
            data: base64::engine::general_purpose::STANDARD.encode(line),
        },
    )
}

/// The runtime's `flock`, held for the service's life. Its Drop unlocks
/// before the descriptor closes: a lock belongs to the open file
/// description, and a child that any thread forks holds a duplicate of
/// every descriptor until it execs (close-on-exec acts only then), so a
/// close alone leaves the runtime locked for as long as that child sits
/// between fork and exec (measured 2026-11-04 on macOS and Linux; the
/// test below holds such a child). `LOCK_UN` releases the description for
/// every duplicate.
struct RuntimeLock(std::fs::File);

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        // SAFETY: flock only operates on the owned open file description.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// The lock precedes every unlink and remains owned until all children end.
fn lock_runtime(runtime: &Path) -> Result<RuntimeLock, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(runtime.join("serve.lock"))
        .map_err(|e| e.to_string())?;
    // SAFETY: flock only operates on the owned open file description.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("a ukai-vm service already owns this runtime".to_owned());
    }
    Ok(RuntimeLock(lock))
}

fn nonblocking(fd: &impl std::os::fd::AsRawFd) -> Result<(), String> {
    // SAFETY: both fcntl calls operate on a live owned descriptor.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

fn read_helper(
    mut stdout: std::process::ChildStdout,
    sender: &std::sync::mpsc::Sender<GuestLine>,
    shared: &Shared,
) -> Result<(), String> {
    let mut helper = protocol::LineSplitter::default();
    let mut guest = protocol::LineSplitter::default();
    let mut chunk = [0u8; 16384];
    while !shared.stop_requested() {
        let n = match stdout.read(&mut chunk) {
            Ok(0) => return Err("helper EOF".to_owned()),
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        };
        for line in helper.push(&chunk[..n]).map_err(|e| e.to_string())? {
            let event: HelperEvent = protocol::decode(&line).map_err(|e| e.to_string())?;
            match event.event.as_str() {
                "data" => {
                    let bytes =
                        protocol::decode_data(event.data.as_deref().ok_or("missing helper data")?)
                            .map_err(|e| e.to_string())?;
                    for line in guest.push(&bytes).map_err(|e| e.to_string())? {
                        let frame =
                            protocol::decode::<GuestEvent>(&line).map_err(|e| e.to_string())?;
                        sender
                            .send(GuestLine::Frame(Box::new(frame)))
                            .map_err(|e| e.to_string())?;
                    }
                }
                "error" => return Err(event.error.unwrap_or_else(|| "helper error".to_owned())),
                "stopped" | "guest_stopped" => return Err("helper stopped".to_owned()),
                "owner" | "booted" | "connected" | "stopping" => {}
                other => return Err(format!("unknown helper event: {other}")),
            }
        }
    }
    Ok(())
}

fn maintain_lease(
    lease_write: std::os::fd::OwnedFd,
    ack_read: std::os::fd::OwnedFd,
    shared: &Shared,
) -> Result<(), String> {
    nonblocking(&lease_write)?;
    nonblocking(&ack_read)?;
    let mut acknowledged = continuous_ns();
    let mut last_wake = continuous_ns();
    let mut sent = 0;
    while !shared.stop_requested() {
        let now = continuous_ns();
        // A suspension (Ctrl-Z of the foreground group) freezes this thread
        // while the continuous clock keeps counting; an expiry can only be
        // decided by code that is running, so an unexplained wake gap resets
        // the acknowledgement baseline instead of failing the lease
        // (jail-macos §6/K110: suspending the operator's job must not end
        // the attempt; measured 2026-11-02: the 1.5s budget saw the 2s stop
        // as a lost acknowledgement). The custodian applies the same rule
        // on its side (custodian.c), so a stop of the whole group longer
        // than its three-second lease no longer ends the VM either; a
        // service that stays stopped still loses the VM three seconds
        // after the custodian runs again.
        if now.saturating_sub(last_wake) > 500_000_000 {
            acknowledged = now;
        }
        last_wake = now;
        if sent == 0 || now.saturating_sub(sent) >= LEASE_REFRESH.as_nanos() {
            // SAFETY: one byte from a live buffer to our lease descriptor.
            if unsafe { libc::write(lease_write.as_raw_fd(), b".".as_ptr().cast(), 1) } != 1 {
                return Err("the custody lease closed".to_owned());
            }
            sent = now;
        }
        let mut bytes = [0u8; 64];
        match read_nonblocking(&ack_read, &mut bytes) {
            Ok(0) => return Err("the custody acknowledgement closed".to_owned()),
            Ok(n) => {
                if bytes[..n].iter().any(|b| *b != b'.') {
                    return Err("invalid custody acknowledgement".to_owned());
                }
                acknowledged = now;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
        if now.saturating_sub(acknowledged) > LEASE_ACK.as_nanos() {
            return Err("the custody lease stopped being acknowledged".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Publish an orderly stop before dropping the lease lets the custodian
    // terminate the helper and close its output pipe.
    shared.stopping.store(true, AtomicOrdering::SeqCst);
    Ok(())
}

/// Own and reap only the custodian this service spawned, including on early errors.
struct Custodian(std::process::Child);
impl Drop for Custodian {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve(args: ServeArgs) -> Result<(), String> {
    install_signal_handlers();
    let install = image::Install::discover().map_err(|e| e.0)?;
    install.verify().map_err(|e| e.0)?;
    // The live share's containment preflight runs before anything boots:
    // its refusals (symlinks, multi-link files, case-folding volumes) are
    // host-side facts no guest policy can enforce (§6, measured 2026-11-02).
    let live_share = match &args.live_workspace {
        Some(path) => {
            let facts = share::preflight(path)?;
            Some((path.canonicalize().map_err(|e| e.to_string())?, facts))
        }
        None => None,
    };
    let runtime = data_dir()?.join("vm");
    std::fs::create_dir_all(&runtime).map_err(|e| e.to_string())?;
    private_dir(&runtime)?;
    let _lock = lock_runtime(&runtime)?;
    for stale in ["control.sock", "attempt.sock"] {
        let _ = std::fs::remove_file(runtime.join(stale));
    }
    // Every boot directory here is an earlier service's (the lock is ours).
    if let Err(error) = prune_boot_dirs(&runtime, KEPT_BOOT_DIRS, None) {
        eprintln!("ukai-vm: earlier boot evidence could not be pruned: {error}");
    }
    let boot_id = format!("vm-{}", uuid::Uuid::new_v4());
    // Copy first, then hash the private copies that are actually executed.
    let boot = runtime.join(&boot_id);
    std::fs::create_dir(&boot).map_err(|e| e.to_string())?;
    private_dir(&boot)?;
    let install = install.verified_copy(&boot).map_err(|e| e.0)?;
    let disk = install.base_disk();
    let nvram = boot.join("guest.nvram");
    let console = boot.join("console.log");
    let control_listener = bind_socket(&runtime.join("control.sock"))?;
    let attempt_listener = bind_socket(&runtime.join("attempt.sock"))?;
    control_listener
        .set_nonblocking(true)
        .map_err(|e| e.to_string())?;
    let (lease_read, lease_write) = fd_pipe()?;
    let (ack_read, ack_write) = fd_pipe()?;
    let mut custodian = Custodian(spawn_custodian(
        &install,
        &disk,
        &install.seed(),
        &nvram,
        &console,
        &lease_read,
        &ack_write,
        live_share.as_ref().map(|(path, _)| path.as_path()),
        args.guest_nat,
    )?);
    drop(lease_read);
    drop(ack_write);
    let helper_stdin = custodian.0.stdin.take().ok_or("no helper stdin")?;
    let helper_stdout = custodian.0.stdout.take().ok_or("no helper stdout")?;
    nonblocking(&helper_stdin)?;
    nonblocking(&helper_stdout)?;
    let (guest_sender, guest_frames) = std::sync::mpsc::channel();
    let shared = Arc::new(Shared::default());
    shared.helper_alive.store(true, AtomicOrdering::SeqCst);
    let reader_shared = Arc::clone(&shared);
    let reader = std::thread::spawn(move || {
        let result = read_helper(helper_stdout, &guest_sender, &reader_shared);
        if !reader_shared.stop_requested() {
            reader_shared.failed.store(true, AtomicOrdering::SeqCst);
            STOP.store(true, AtomicOrdering::SeqCst);
        }
        reader_shared
            .helper_alive
            .store(false, AtomicOrdering::SeqCst);
        reader_shared.stopping.store(true, AtomicOrdering::SeqCst);
        let _ = guest_sender.send(GuestLine::HelperEnded(
            result.err().unwrap_or_else(|| "stopped".to_owned()),
        ));
    });
    let lease_shared = Arc::clone(&shared);
    let lease = std::thread::spawn(move || {
        if let Err(error) = maintain_lease(lease_write, ack_read, &lease_shared) {
            if !lease_shared.stop_requested() {
                eprintln!("ukai-vm: {error}");
                lease_shared.failed.store(true, AtomicOrdering::SeqCst);
            }
            STOP.store(true, AtomicOrdering::SeqCst);
            lease_shared.stopping.store(true, AtomicOrdering::SeqCst);
        }
    });
    let service = Arc::new(Service {
        helper_stdin: Arc::new(Mutex::new(helper_stdin)),
        shared,
        boot_id,
        install,
        sockets: (runtime.join("control.sock"), runtime.join("attempt.sock")),
        live_share,
        guest_nat: args.guest_nat,
    });
    let control_service = Arc::clone(&service);
    let control_thread = std::thread::spawn(move || {
        serve_control(&control_service, &control_listener, args.idle_seconds);
    });
    // Exactly one session handshake per boot, including the first kernel reply.
    let result = (|| {
        expect_guest_within(&guest_frames, "ready", Duration::from_secs(150))?;
        guest_line(&service, &GuestOp::Session)?;
        let session = expect_guest(&guest_frames, "session")?;
        let kernel = session.kernel.ok_or("session omitted kernel")?;
        check_live_share(service.live_share.is_some(), session.live_share)?;
        *SHARED_GUEST_KERNEL.lock().map_err(|e| e.to_string())? = Some(kernel);
        drive_attempts(
            &service,
            &guest_frames,
            &attempt_listener,
            args.idle_seconds,
        )
    })();
    // A signal or control stop can interrupt the initial guest handshake.
    // Capture the request before our own teardown sets `stopping`; actual
    // custody/transport failures remain latched and take precedence below.
    let stop_requested = service.shared.stop_requested();
    service.shared.stopping.store(true, AtomicOrdering::SeqCst);
    let _ = write_helper(&service, &HelperWrite::Stop);
    let _ = lease.join(); // closes the lease: the custodian has a three-second backstop
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while custodian.0.try_wait().map_err(|e| e.to_string())?.is_none()
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(custodian);
    let _ = reader.join();
    let _ = control_thread.join();
    for socket in [&service.sockets.0, &service.sockets.1] {
        let _ = std::fs::remove_file(socket);
    }
    let failed = service.shared.failed.load(AtomicOrdering::SeqCst);
    // A guest that ended itself names why on its console (a share that did
    // not mount, an attempt stop it could not verify).
    let powered_off = guest_poweroff_reason(&console);
    if failed || (!stop_requested && result.is_err()) {
        // Keep the boot directory (guest console, copied image, nvram) as
        // evidence under its boot id; deleting it is exactly how a custody
        // failure becomes undiagnosable (measured 2026-11-02). The newest
        // [`KEPT_BOOT_DIRS`] are kept.
        eprintln!("ukai-vm: evidence retained at {}", boot.display());
        if let Err(error) = prune_boot_dirs(&runtime, KEPT_BOOT_DIRS.saturating_sub(1), Some(&boot))
        {
            eprintln!("ukai-vm: earlier boot evidence could not be pruned: {error}");
        }
        if let Some(reason) = &powered_off {
            eprintln!("ukai-vm: the guest powered itself off: {reason}");
        }
    } else {
        std::fs::remove_dir_all(&boot).map_err(|e| e.to_string())?;
    }
    if failed {
        return Err(match powered_off {
            Some(reason) => format!("VM custody or transport failed (guest poweroff: {reason})"),
            None => "VM custody or transport failed".to_owned(),
        });
    }
    if stop_requested { Ok(()) } else { result }
}

fn serve_control(service: &Service, listener: &UnixListener, idle_seconds: u64) {
    while !service.shared.stopping.load(AtomicOrdering::SeqCst)
        && !STOP.load(AtomicOrdering::SeqCst)
    {
        let (mut stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(_) => break,
        };
        let Ok(line) = read_line(&mut stream, Duration::from_secs(1)) else {
            continue;
        };
        let Ok(request) = protocol::decode::<protocol::ToControl>(&line) else {
            continue;
        };
        let manifest = &service.install.manifest;
        let reply = match request {
            protocol::ToControl::Status => {
                let warm = service.shared.helper_alive.load(AtomicOrdering::SeqCst)
                    && !service.shared.stopping.load(AtomicOrdering::SeqCst);
                // The kernel is set once the session handshake completed: the
                // guest booted, its controller answered, and the next attempt
                // runs without waiting for a boot (`warm` holds from the start).
                let kernel = SHARED_GUEST_KERNEL.lock().ok().and_then(|g| g.clone());
                protocol::FromControl::Status {
                    schema: protocol::SCHEMA_CONTROL.to_owned(),
                    boot_id: service.boot_id.clone(),
                    warm,
                    ready: warm && kernel.is_some(),
                    attempt_live: service.shared.attempt_live.load(AtomicOrdering::SeqCst),
                    kernel,
                    disk_sha256: manifest.disk_sha256.clone(),
                    helper_sha256: manifest.helper_sha256.clone(),
                    custodian_sha256: manifest.custodian_sha256.clone(),
                    seed_sha256: manifest.seed_sha256.clone(),
                    vsock_port: GUEST_PORT,
                    idle_seconds,
                    live_workspace: service
                        .live_share
                        .as_ref()
                        .map(|(path, _)| path.display().to_string()),
                    live_workspace_facts: service.live_share.as_ref().map(|(_, facts)| {
                        protocol::LiveShareFacts {
                            case_fold: facts.case_fold,
                            normalization_fold: facts.normalization_fold,
                        }
                    }),
                    guest_nat: service.guest_nat,
                }
            }
            protocol::ToControl::Stop => {
                service.shared.stopping.store(true, AtomicOrdering::SeqCst);
                STOP.store(true, AtomicOrdering::SeqCst);
                protocol::FromControl::Stopping {
                    schema: protocol::SCHEMA_CONTROL.to_owned(),
                }
            }
        };
        if let Ok(frame) = protocol::encode(&reply) {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = stream.write_all(&frame);
        }
    }
}

/// Accepts attempt connections until stopped, or until the guest has been
/// idle for `idle_seconds` on the continuous clock.
fn drive_attempts(
    service: &Service,
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    listener: &UnixListener,
    idle_seconds: u64,
) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let mut idle_since = continuous_ns();
    loop {
        if STOP.load(AtomicOrdering::SeqCst) || service.shared.stopping.load(AtomicOrdering::SeqCst)
        {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let outcome = run_attempt(service, frames, stream);
                service
                    .shared
                    .attempt_live
                    .store(false, AtomicOrdering::SeqCst);
                if service.shared.stop_requested() {
                    // Whole-service teardown ends the guest. Do not start
                    // an attempt-cancellation handshake after that stop.
                    return Ok(());
                }
                if let Err(error) = outcome {
                    eprintln!("ukai-vm: attempt failed: {error}");
                    // Cancel and drain this attempt before accepting another one. If
                    // cleanup cannot be acknowledged the entire guest must stop.
                    guest_line(service, &GuestOp::Cancel2)?;
                    expect_guest(frames, "cancelled")?;
                }
                idle_since = continuous_ns();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.to_string()),
        }
        if idle_seconds != 0
            && !service.shared.attempt_live.load(AtomicOrdering::SeqCst)
            && continuous_ns().saturating_sub(idle_since) > u128::from(idle_seconds) * 1_000_000_000
        {
            eprintln!("ukai-vm: the guest has been idle for {idle_seconds}s");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One attempt session: stage, release, relay, verdict. The connection is
/// the lease; its end cancels the attempt (§6).
fn run_attempt(
    service: &Service,
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    stream: UnixStream,
) -> Result<(), String> {
    service
        .shared
        .attempt_live
        .store(true, AtomicOrdering::SeqCst);
    let mut stream = stream;
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let send = |stream: &mut UnixStream, frame: &protocol::FromVm| -> Result<(), String> {
        let mut line = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
        line.push(b'\n');
        stream
            .write_all(&line)
            .map_err(|error| format!("the attempt connection failed: {error}"))
    };
    let manifest = &service.install.manifest;
    send(
        &mut stream,
        &protocol::FromVm::Ready {
            schema: protocol::SCHEMA_ATTEMPT.to_owned(),
            boot_id: service.boot_id.clone(),
            disk_sha256: manifest.disk_sha256.clone(),
            helper_sha256: manifest.helper_sha256.clone(),
            custodian_sha256: manifest.custodian_sha256.clone(),
            seed_sha256: manifest.seed_sha256.clone(),
            vsock_port: GUEST_PORT,
        },
    )?;
    let prepared = match read_request(&mut stream)? {
        protocol::ToVm::Prepare {
            attempt_id,
            profile,
            wall_seconds,
            argv,
            secrets,
            allow_hosts,
            launch,
        } => {
            if !protocol::GUEST_PROFILES.contains(&profile.as_str()) {
                return Err(format!(
                    "the attempt names profile `{profile}`, not one of {}",
                    protocol::GUEST_PROFILES.join(", ")
                ));
            }
            if service.live_share.is_some() && profile == "build" {
                // The build profile's disposable-copy grant has no protected
                // segments; on a live share it would expose the operator's
                // real .git (measured, run 2 of the 2026-11-02 K109
                // evidence). The guest refuses it too.
                return Err(
                    "the build profile treats the workspace as a disposable copy with no \
                     protected segments; a live share is the operator's real directory, so \
                     run it with profile `tool`"
                        .to_owned(),
                );
            }
            if !(1..=protocol::WALL_MAX).contains(&wall_seconds) {
                return Err(format!(
                    "the attempt names a wall of {wall_seconds}s, past the guest grammar"
                ));
            }
            if argv.is_empty() {
                return Err("empty argv".to_owned());
            }
            for (index, argument) in argv.iter().enumerate() {
                if (index == 0
                    && protocol::decode_data(argument)
                        .map_err(|error| error.to_string())?
                        .is_empty())
                    || protocol::decode_data(argument)
                        .map_err(|error| error.to_string())?
                        .contains(&0)
                {
                    return Err(
                        "the attempt's argv holds an empty or NUL-bearing element".to_owned()
                    );
                }
            }
            Ok((
                attempt_id,
                profile,
                wall_seconds,
                argv,
                secrets,
                allow_hosts,
                launch,
            ))
        }
        protocol::ToVm::Put(_) | protocol::ToVm::Run => {
            Err("the attempt opened with staging frames instead of `prepare`".to_owned())
        }
    }?;
    let (attempt_id, profile, wall_seconds, argv, secrets, allow_hosts, launch) = prepared;
    check_secret_ids(secrets.iter().map(|s| s.id.as_str()))?;
    guest_line(service, &GuestOp::Reset)?;
    expect_guest(frames, "reset")?;
    if let Some(launch) = &launch {
        // The launch TOML crossed in Prepare as part of the declaration;
        // the guest controller keeps it for `--launch` (it holds no value:
        // sources point at the tmpfs staging root).
        guest_line(
            service,
            &GuestOp::LaunchToml {
                toml: launch.toml.clone(),
            },
        )?;
        expect_guest(frames, "launch_toml")?;
    }
    let mut staged_secrets: Vec<(String, String)> = Vec::new();
    for secret in &secrets {
        // The transport stages each value in the guest's tmpfs for this
        // attempt, where the launch profile's sources name it; the guest
        // removes every value when the attempt ends, and a value it refuses
        // is this attempt's error (the caller cancels it).
        guest_line(
            service,
            &GuestOp::Secret {
                id: secret.id.clone(),
                data: secret.data.clone(),
            },
        )?;
        let staged = expect_guest(frames, "secret")?;
        if staged.id.as_deref() != Some(secret.id.as_str()) {
            return Err(format!(
                "the guest acknowledged the wrong secret: {:?}",
                staged.id
            ));
        }
        staged_secrets.push((secret.id.clone(), staged.path.clone().unwrap_or_default()));
    }
    let kernel = SHARED_GUEST_KERNEL
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or("session did not establish a guest kernel")?;
    send(
        &mut stream,
        &protocol::FromVm::Prepared {
            kernel: kernel.clone(),
            staged_secrets,
        },
    )?;

    // The release loop ends only by sending `run`; from there the attempt
    // is released.
    loop {
        match read_request(&mut stream)? {
            protocol::ToVm::Put(put) => {
                if service.live_share.is_some() {
                    // A live share's staging is the host's side of the mount;
                    // forwarding the put would write through to the host
                    // workspace, and the guest ends its VM on one. The files
                    // are already in place through the share.
                    return Err(format!(
                        "a live-workspace service does not stage files; `{}` is already \
                         shared from the host",
                        put.path
                    ));
                }
                guest_line(
                    service,
                    &GuestOp::Put {
                        path: put.path.clone(),
                        executable: put.executable,
                        data: put.data,
                    },
                )?;
                expect_guest_put(frames, &put.path)?;
            }
            protocol::ToVm::Run => break,
            protocol::ToVm::Prepare { .. } => {
                return Err("the attempt repeated `prepare`".to_owned());
            }
        }
    }
    guest_line(
        service,
        &GuestOp::Run2 {
            attempt_id,
            boot_id: service.boot_id.clone(),
            profile,
            wall_seconds,
            argv,
            allow_hosts: allow_hosts.clone(),
            launch: launch.as_ref().map(|decl| decl.name.clone()),
        },
    )?;
    let running = expect_guest(frames, "running")?;
    send(
        &mut stream,
        &protocol::FromVm::Released {
            supervisor_pid: running
                .supervisor_pid
                .ok_or("running omitted supervisor_pid")?,
        },
    )?;
    relay_attempt(service, frames, &mut stream)
}

fn relay_attempt(
    service: &Service,
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    stream: &mut UnixStream,
) -> Result<(), String> {
    let deadline = continuous_ns() + u128::from(protocol::WALL_MAX + 90) * 1_000_000_000;
    let mut receipt: Option<(String, Vec<u8>)> = None;
    let send = |stream: &mut UnixStream, frame: &protocol::FromVm| -> Result<(), String> {
        let mut line = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
        line.push(b'\n');
        stream
            .write_all(&line)
            .map_err(|error| format!("the attempt connection failed: {error}"))
    };
    loop {
        if STOP.load(AtomicOrdering::SeqCst) || service.shared.stopping.load(AtomicOrdering::SeqCst)
        {
            return Err("service stopping".to_owned());
        }
        let mut byte = [0u8; 1];
        // SAFETY: recv peeks into caller-owned memory without consuming protocol data.
        let peer = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if peer == 0 {
            return Err("the attempt lease ended".to_owned());
        }
        if peer > 0 {
            return Err("unexpected data after release".to_owned());
        }
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Err(error.to_string());
        }
        if continuous_ns() > deadline {
            return Err("the attempt ran past its host deadline".to_owned());
        }
        let frame = match frames.recv_timeout(Duration::from_millis(100)) {
            Ok(GuestLine::Frame(frame)) => frame,
            Ok(GuestLine::HelperEnded(reason)) => {
                return Err(format!("the VM service ended: {reason}"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("the guest reader stopped".to_owned());
            }
        };
        match frame.event.as_str() {
            "stdout" | "stderr" => {
                let data = frame.data.clone().unwrap_or_default();
                let line = if frame.event == "stdout" {
                    protocol::FromVm::Stdout { data }
                } else {
                    protocol::FromVm::Stderr { data }
                };
                send(stream, &line)?;
            }
            "file" => {
                let group = frame.group.clone().unwrap_or_default();
                let path = frame.path.clone().unwrap_or_default();
                let data = frame.data.clone().unwrap_or_default();
                if group == "evidence" && path == "jail.json" {
                    receipt = Some((
                        protocol::encode_data(
                            &protocol::decode_data(&data).map_err(|error| error.to_string())?,
                        ),
                        protocol::decode_data(&data).map_err(|error| error.to_string())?,
                    ));
                }
                if group == "evidence" && path == "jail.json" {
                    continue;
                }
                send(
                    stream,
                    &protocol::FromVm::File {
                        group,
                        path,
                        executable: frame.executable.unwrap_or(false),
                        data,
                    },
                )?;
            }
            "done" => {
                let exit_code = frame.exit_code.unwrap_or(125);
                let (sha256, bytes) = receipt
                    .take()
                    .ok_or("the guest completed without carrying its receipt")?;
                let digest = image::hex(&sha2::Sha256::digest(&bytes));
                send(
                    stream,
                    &protocol::FromVm::BoundReceipt {
                        sha256: digest,
                        data: sha256,
                        binding: frame.binding.ok_or("guest omitted receipt binding")?,
                    },
                )?;
                send(
                    stream,
                    &protocol::FromVm::Done {
                        exit_code,
                        stop: frame.stop.clone(),
                    },
                )?;
                return Ok(());
            }
            "error" => {
                let message = frame
                    .message
                    .clone()
                    .unwrap_or_else(|| "guest error".to_owned());
                let _ = send(stream, &protocol::FromVm::Error { message });
                return Err("the guest reported an error".to_owned());
            }
            _ => {}
        }
    }
}

fn read_line(stream: &mut UnixStream, timeout: Duration) -> Result<Vec<u8>, String> {
    // macOS accepted sockets inherit O_NONBLOCK from the listener.
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + timeout;
    let mut line = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        if STOP.load(AtomicOrdering::SeqCst) || std::time::Instant::now() >= deadline {
            return Err("request timed out or service stopping".to_owned());
        }
        if !control::wait_readable(stream, Duration::from_millis(100)).map_err(|e| e.to_string())? {
            continue;
        }
        // Peek to consume only this line; the next request stays in the socket.
        // SAFETY: recv writes into the caller-owned chunk, and the stream is live.
        let peeked = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                chunk.len(),
                libc::MSG_PEEK,
            )
        };
        if peeked == 0 {
            return Err("the connection closed".to_owned());
        }
        if peeked < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(e.to_string());
        }
        let available = peeked as usize;
        let end = chunk[..available].iter().position(|b| *b == b'\n');
        let count = end.map_or(available, |n| n + 1);
        stream
            .read_exact(&mut chunk[..count])
            .map_err(|e| e.to_string())?;
        line.extend_from_slice(&chunk[..end.unwrap_or(count)]);
        if line.len() > protocol::MAX_FRAME {
            return Err("oversized request".to_owned());
        }
        if end.is_some() {
            return Ok(line);
        }
    }
}

fn read_request(stream: &mut UnixStream) -> Result<protocol::ToVm, String> {
    let line = read_line(stream, control::HANDSHAKE_TIMEOUT)?;
    protocol::decode(&line).map_err(|e| e.to_string())
}

fn expect_guest(
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    event: &str,
) -> Result<GuestEvent, String> {
    expect_guest_within(frames, event, Duration::from_secs(30))
}

fn expect_guest_within(
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    event: &str,
    budget: Duration,
) -> Result<GuestEvent, String> {
    // The guest's own boot (EFI, kernel, cloud-init, controller) takes up
    // to a minute on the measured image; every later exchange is warm and
    // stays on the short deadline.
    let deadline = continuous_ns() + budget.as_nanos();
    loop {
        if STOP.load(AtomicOrdering::SeqCst) || continuous_ns() > deadline {
            return Err(format!("the guest did not answer `{event}`"));
        }
        match frames.recv_timeout(Duration::from_millis(100)) {
            Ok(GuestLine::Frame(frame)) if frame.event == event => return Ok(*frame),
            Ok(GuestLine::Frame(frame)) if frame.event == "error" => {
                return Err(frame.message.unwrap_or_else(|| "guest error".to_owned()));
            }
            Ok(GuestLine::Frame(_)) => continue,
            Ok(GuestLine::HelperEnded(reason)) => {
                return Err(format!("the VM service ended: {reason}"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("the guest reader stopped".to_owned());
            }
        }
    }
}

fn expect_guest_put(
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    path: &str,
) -> Result<(), String> {
    let frame = expect_guest(frames, "put")?;
    if frame.path.as_deref() != Some(path) {
        return Err(format!(
            "the guest acknowledged `{}` for `{path}`",
            frame.path.unwrap_or_default()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

fn data_dir() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("UKAI_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or("no UKAI_DATA_DIR and no HOME")?;
    Ok(PathBuf::from(home).join(".local/share/ukai"))
}

fn private_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("{} cannot be made private: {error}", path.display()))
}

fn bind_socket(path: &Path) -> Result<UnixListener, String> {
    UnixListener::bind(path).map_err(|error| format!("{} cannot bind: {error}", path.display()))
}

fn fd_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), String> {
    // SAFETY: the array is plain writable storage `pipe` fills.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe` writes exactly two descriptor numbers into the array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe failed: {}", std::io::Error::last_os_error()));
    }
    for fd in fds {
        // SAFETY: these descriptors were just created by pipe.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            // SAFETY: close both fresh descriptors on the error path.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    // SAFETY: both descriptors are freshly created and owned.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

// One argument per object the custodian inherits; a struct would only
// rename them.
#[allow(clippy::too_many_arguments)]
fn spawn_custodian(
    install: &image::Install,
    disk: &Path,
    seed: &Path,
    nvram: &Path,
    console: &Path,
    lease_read: &std::os::fd::OwnedFd,
    ack_write: &std::os::fd::OwnedFd,
    share_dir: Option<&Path>,
    guest_nat: bool,
) -> Result<std::process::Child, String> {
    use std::os::fd::AsRawFd as _;
    use std::process::Stdio;
    let mut command = custodian_command(
        &install.custodian(),
        &install.helper(),
        disk,
        seed,
        nvram,
        console,
        share_dir,
        guest_nat,
    );
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // The closure must own its descriptors ('static); the clones die
    // with the child's exec or with the command.
    let duplicate = |fd: &std::os::fd::OwnedFd| {
        // SAFETY: duplicate a live descriptor above the dup2 destinations.
        let n = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if n < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: fcntl returned a fresh owned descriptor.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(n) })
    };
    let lease_child = duplicate(lease_read)?;
    let ack_child = duplicate(ack_write)?;
    // SAFETY: `pre_exec` runs the closure in the child, before exec. It
    // moves the lease and acknowledgement descriptors to the numbers the
    // custodian's grammar names — the duplicates lose the close-on-exec
    // flag by `dup2`'s rule, which is what the custodian requires — and
    // exits the child on failure.
    unsafe {
        let _ = command.pre_exec(move || {
            if libc::dup2(lease_child.as_raw_fd(), 3) < 0
                || libc::dup2(ack_child.as_raw_fd(), 4) < 0
            {
                libc::_exit(125);
            }
            Ok(())
        });
    }
    command
        .spawn()
        .map_err(|error| format!("{} cannot start: {error}", install.custodian().display()))
}

/// The custodian's command line and environment, before its descriptors.
/// The optional trailing argument is the live workspace share (J18 §6):
/// the custodian forwards it to the VZ client, which attaches one writable
/// virtio-fs device; the guest controller mounts it as the attempt
/// workspace. The NAT adapter is the `--guest-nat` flag's alone: an
/// inherited `UKAI_VM_GUEST_NAT` is removed, so `status` (which reports the
/// flag) can never say `false` for a guest that has the adapter.
#[allow(clippy::too_many_arguments)]
fn custodian_command(
    custodian: &Path,
    helper: &Path,
    disk: &Path,
    seed: &Path,
    nvram: &Path,
    console: &Path,
    share_dir: Option<&Path>,
    guest_nat: bool,
) -> std::process::Command {
    let mut command = std::process::Command::new(custodian);
    command
        .args(["3", "4"])
        .arg(helper)
        .arg(disk)
        .arg(seed)
        .arg(nvram)
        .arg(console)
        .arg("run");
    if let Some(share) = share_dir {
        command.arg(share);
    }
    command.env_remove("UKAI_VM_GUEST_NAT");
    if guest_nat {
        command.env("UKAI_VM_GUEST_NAT", "1");
    }
    command
}

/// D7: the guest's own statement of whether it mounted the live share must
/// be what this service attached. A guest that fell back to its staged
/// workspace would run every attempt outside the operator's directory
/// while the host records a live share; a guest that predates the
/// statement is refused rather than trusted.
fn check_live_share(attached: bool, stated: Option<bool>) -> Result<(), String> {
    match stated {
        Some(stated) if stated == attached => Ok(()),
        Some(true) => {
            Err("the guest reports a live workspace share this service did not attach".to_owned())
        }
        Some(false) => Err(
            "the guest did not mount the live workspace share this service attached; it never \
             falls back to the staged workspace"
                .to_owned(),
        ),
        None => Err(
            "the guest's session does not state whether it mounted a live share; its \
             controller predates this service"
                .to_owned(),
        ),
    }
}

/// Refuses credential ids that would collide in the guest's staging tree,
/// before any guest traffic: the same id twice, or one id that is a
/// directory of another (`a` and `a/b`). The guest refuses both too.
fn check_secret_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let mut ids: Vec<&str> = ids.collect();
    ids.sort_unstable();
    for (index, id) in ids.iter().enumerate() {
        for other in &ids[index + 1..] {
            if other == id {
                return Err(
                    "the attempt stages the same credential id twice; ids must be unique"
                        .to_owned(),
                );
            }
            if other
                .strip_prefix(id)
                .is_some_and(|rest| rest.starts_with('/'))
            {
                return Err(format!(
                    "credential id `{id}` is a directory of `{other}` in the staging tree; ids \
                     must not nest inside each other"
                ));
            }
        }
    }
    Ok(())
}

/// Removes boot directories (`vm-*`) of earlier boots beyond the newest
/// `keep`, by modification time; `current` is never counted or removed.
/// Only directories are touched; a link is never followed out of the
/// runtime directory.
fn prune_boot_dirs(
    runtime: &Path,
    keep: usize,
    current: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let mut boots = Vec::new();
    for entry in std::fs::read_dir(runtime).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if !entry.file_name().to_string_lossy().starts_with("vm-")
            || current.is_some_and(|current| current == path)
        {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
        boots.push((modified, path));
    }
    boots.sort();
    let excess = boots.len().saturating_sub(keep);
    let removed: Vec<PathBuf> = boots.into_iter().take(excess).map(|(_, p)| p).collect();
    for path in &removed {
        std::fs::remove_dir_all(path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(removed)
}

/// The reason of the guest controller's last `poweroff` audit on its
/// console (`UKAI_VM {"event": "poweroff", "reason": ...}`), when the guest
/// ended itself. Reads at most the console's last MiB.
fn guest_poweroff_reason(console: &Path) -> Option<String> {
    let bytes = std::fs::read(console).ok()?;
    let tail = &bytes[bytes.len().saturating_sub(1 << 20)..];
    String::from_utf8_lossy(tail)
        .lines()
        .rev()
        .find_map(|line| {
            let start = line.find("UKAI_VM {")?;
            let value: Value =
                serde_json::from_str(line[start + "UKAI_VM ".len()..].trim()).ok()?;
            if value.get("event")?.as_str()? != "poweroff" {
                return None;
            }
            value.get("reason")?.as_str().map(str::to_owned)
        })
}

fn read_nonblocking(fd: &std::os::fd::OwnedFd, buffer: &mut [u8]) -> std::io::Result<usize> {
    // SAFETY: `read` on an owned descriptor with a valid buffer.
    let count = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if count < 0 {
        let error = std::io::Error::last_os_error();
        return Err(error);
    }
    Ok(count as usize)
}

// ---------------------------------------------------------------------------
// The operator verbs
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "ukai-vm",
    about = "Serve, inspect or stop the per-operator warm Linux guest (J18)."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Boot the guest once and serve attempts until idle or stopped.
    Serve(ServeArgs),
    /// Ask the running ukai-vm for an orderly stop.
    Stop,
    /// Report the warm guest's state.
    Status,
    /// Report the installed image's package and host prerequisites.
    Doctor,
    /// Print the version and the schema identifiers this build announces.
    Version,
}

#[derive(Debug, clap::Args)]
struct ServeArgs {
    /// The idle budget in seconds; 0 never idles out.
    #[arg(long, default_value_t = IDLE_SECONDS)]
    idle_seconds: u64,
    /// Share this workspace live over virtio-fs instead of staging per
    /// attempt (J18 §6). Refused for workspaces with symlinks or
    /// multi-link files, or on case-folding volumes. A guest that does not
    /// mount the share is refused; it never falls back to a staged copy.
    #[arg(long, value_name = "DIR")]
    live_workspace: Option<PathBuf>,
    /// Attach the guest's NAT adapter during attempts too (J18 §6). The
    /// guest jail's network policy, not the adapter, decides what the
    /// workload can reach. Only this flag attaches it.
    #[arg(long)]
    guest_nat: bool,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let outcome = match args.command {
        Command::Version => {
            println!(
                "{}",
                serde_json::json!({
                    "component": "ukai-vm",
                    "version": PACKAGE_VERSION,
                    "execution": "linux-vm-warm",
                    "native_macos_execution": false,
                    "attempt": protocol::SCHEMA_ATTEMPT,
                    "control": protocol::SCHEMA_CONTROL,
                    "transport": record::SCHEMA_TRANSPORT,
                })
            );
            Ok(())
        }
        Command::Doctor => doctor(),
        Command::Status => control_round_trip(protocol::ToControl::Status).and_then(|reply| {
            if let Some(reply) = reply {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&reply).map_err(|e| e.to_string())?
                );
            } else {
                println!("ukai-vm: no VM is running");
            }
            Ok(())
        }),
        Command::Stop => control_round_trip(protocol::ToControl::Stop).map(|reply| {
            if reply.is_some() {
                println!("ukai-vm: stopping: the warm guest ends with its service");
            } else {
                println!("ukai-vm: no VM is running");
            }
        }),
        Command::Serve(args) => qualified().and_then(|()| serve(args)),
    };
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ukai-vm: {error}");
            std::process::ExitCode::from(125)
        }
    }
}

fn control_round_trip(
    request: protocol::ToControl,
) -> Result<Option<protocol::FromControl>, String> {
    let socket = control_socket();
    match control::control_round_trip(&socket, request) {
        Ok(reply) => Ok(Some(reply)),
        Err(control::ControlError::Absent) => Ok(None),
        Err(control::ControlError::Failed(error)) => Err(error.to_string()),
    }
}

fn control_socket() -> PathBuf {
    data_dir()
        .map(|dir| dir.join("vm").join("control.sock"))
        .unwrap_or_else(|_| PathBuf::from("/nonexistent/vm/control.sock"))
}

/// The installer's readiness report, in the preview's schema: the image
/// directory beside this executable (the staged installer runs the check
/// before the install reaches its final location), otherwise the
/// discovered installation. A real run still verifies the guest jail.
fn doctor() -> Result<(), String> {
    let image_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .and_then(|bin| bin.parent())
                .map(|root| root.join("image"))
        })
        .filter(|dir| dir.join("image.json").is_file())
        .or_else(|| {
            image::Install::discover()
                .ok()
                .map(|install| install.root.join("image"))
        })
        .ok_or_else(|| "no installed ukai-vm image found".to_owned())?;
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(image_dir.join("image.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut checks = serde_json::Map::new();
    let virtualization_supported = std::process::Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg("kern.hv_support")
        .output()
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "1")
        .unwrap_or(false);
    checks.insert(
        "virtualization_supported".to_owned(),
        serde_json::Value::Bool(virtualization_supported),
    );
    for (name, key) in [
        ("base.raw", "disk_sha256"),
        ("seed.iso", "seed_sha256"),
        ("vz", "helper_sha256"),
        ("custodian", "custodian_sha256"),
    ] {
        let recorded = manifest.get(key).and_then(Value::as_str).unwrap_or("");
        let matches = image::digest(&image_dir.join(name))
            .map(|actual| actual == recorded)
            .unwrap_or(false);
        checks.insert(name.to_owned(), serde_json::Value::Bool(matches));
    }
    let ready = checks.values().all(|value| value.as_bool() == Some(true));
    let report = serde_json::json!({
        "schema": "ukai.vm.install-check/1",
        "version": PACKAGE_VERSION,
        "ready": ready,
        "checks": serde_json::Value::Object(checks),
        "scope": "package and host prerequisites; a real run still verifies the guest jail",
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    if ready {
        Ok(())
    } else {
        Err("install check is not ready".to_owned())
    }
}

/// The host the preview is qualified for: Apple Silicon, macOS 27 or later.
fn qualified() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let ok = std::env::consts::ARCH == "aarch64" && {
            // SAFETY: an all-zero `utsname` is a valid value `uname`
            // overwrites; `uname` writes the fixed-size struct itself.
            let mut version: libc::utsname = unsafe { std::mem::zeroed() };
            // SAFETY: `uname` fills the caller-provided fixed-size struct
            // and returns 0 on success.
            if unsafe { libc::uname(&mut version) } != 0 {
                false
            } else {
                // The release field reads like `27.0.0` on this platform.
                let bytes: Vec<u8> = version
                    .release
                    .iter()
                    .take_while(|byte| **byte != 0)
                    .map(|byte| *byte as u8)
                    .collect();
                let release = String::from_utf8_lossy(&bytes);
                release
                    .split('.')
                    .next()
                    .and_then(|major| major.parse::<u32>().ok())
                    .is_some_and(|major| major >= 27)
            }
        };
        if ok {
            Ok(())
        } else {
            Err("this service is qualified for Apple Silicon and macOS 27 or later".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("ukai-vm serves on macOS hosts; there is no VM service here".to_owned())
    }
}

#[cfg(test)]
mod service_regressions {
    use super::*;

    #[test]
    fn request_bound_is_reached_before_json_decode_or_timeout() {
        let (mut reader, mut peer) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = peer.write_all(&vec![b' '; protocol::MAX_FRAME + 1]);
        });
        let error = read_request(&mut reader).unwrap_err();
        assert!(error.contains("oversized request"), "{error}");
        drop(reader);
        writer.join().unwrap();
    }

    #[test]
    fn nonblocking_accepted_request_waits_for_a_delayed_frame() {
        let (mut reader, mut peer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            peer.write_all(b"{\"op\":\"run\"}\n").unwrap();
        });
        assert_eq!(read_request(&mut reader).unwrap(), protocol::ToVm::Run);
        writer.join().unwrap();
    }

    #[test]
    fn silent_and_trickled_requests_have_an_absolute_deadline() {
        let (mut reader, mut peer) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..40 {
                if peer.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let start = std::time::Instant::now();
        assert!(
            read_line(&mut reader, Duration::from_millis(40))
                .unwrap_err()
                .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_millis(150));
        drop(reader);
        writer.join().unwrap();
    }

    #[test]
    fn the_package_version_is_the_packagers_or_says_dev() {
        match option_env!("UKAI_VM_PACKAGE_VERSION") {
            Some(version) => assert_eq!(PACKAGE_VERSION, version),
            None => assert_eq!(
                PACKAGE_VERSION,
                format!("{}-dev", env!("CARGO_PKG_VERSION"))
            ),
        }
    }

    #[test]
    fn the_session_must_state_the_share_this_service_attached() {
        assert!(check_live_share(true, Some(true)).is_ok());
        assert!(check_live_share(false, Some(false)).is_ok());
        let missing = check_live_share(true, Some(false)).unwrap_err();
        assert!(missing.contains("did not mount"), "{missing}");
        assert!(check_live_share(false, Some(true)).is_err());
        assert!(check_live_share(false, None).is_err());
        assert!(check_live_share(true, None).is_err());
    }

    #[test]
    fn credential_ids_may_neither_repeat_nor_nest() {
        for ids in [
            &["a", "a"][..],
            &["a", "a/b"],
            &["x", "a/b", "a"],
            &["a/b", "a/b/c"],
        ] {
            assert!(check_secret_ids(ids.iter().copied()).is_err(), "{ids:?}");
        }
        for ids in [
            &["a", "ab"][..],
            &["a/b", "ab"],
            &["a/b", "a/bc"],
            &["api/token", "api/key"],
            &[],
        ] {
            assert!(check_secret_ids(ids.iter().copied()).is_ok(), "{ids:?}");
        }
    }

    #[test]
    fn boot_evidence_keeps_the_newest_and_touches_only_boot_directories() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path();
        let base = std::time::SystemTime::now() - Duration::from_secs(3600);
        let mut boots = Vec::new();
        for index in 0..5u64 {
            let boot = runtime.join(format!("vm-{index}"));
            std::fs::create_dir(&boot).unwrap();
            std::fs::write(boot.join("console.log"), b"x").unwrap();
            std::fs::File::open(&boot)
                .unwrap()
                .set_modified(base + Duration::from_secs(index * 60))
                .unwrap();
            boots.push(boot);
        }
        std::fs::write(runtime.join("vm-file"), b"not a boot").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), runtime.join("vm-link")).unwrap();
        std::fs::write(runtime.join("serve.lock"), b"").unwrap();
        // The current boot is the oldest here, and still never removed.
        std::fs::File::open(&boots[0])
            .unwrap()
            .set_modified(base - Duration::from_secs(60))
            .unwrap();
        let removed = prune_boot_dirs(runtime, 2, Some(&boots[0])).unwrap();
        assert_eq!(removed, vec![boots[1].clone(), boots[2].clone()]);
        for kept in [&boots[0], &boots[3], &boots[4]] {
            assert!(kept.is_dir(), "{}", kept.display());
        }
        assert!(runtime.join("vm-file").is_file());
        assert!(runtime.join("vm-link").is_symlink());
        assert!(runtime.join("serve.lock").exists());
        assert!(outside.path().is_dir());
        assert_eq!(prune_boot_dirs(runtime, 3, None).unwrap().len(), 0);
        assert_eq!(prune_boot_dirs(runtime, 1, None).unwrap().len(), 2);
    }

    #[test]
    fn the_guests_last_poweroff_reason_is_read_from_its_console() {
        let dir = tempfile::tempdir().unwrap();
        let console = dir.path().join("console.log");
        assert_eq!(guest_poweroff_reason(&console), None);
        std::fs::write(
            &console,
            "[    1.0] boot noise\r\nUKAI_VM {\"event\": \"ready\", \"kernel\": \"7.0\"}\n\
             [    2.0] UKAI_VM {\"event\": \"poweroff\", \"reason\": \"first\"}\r\n\
             UKAI_VM {\"event\": \"poweroff\", \"reason\": \"live_share_mount_failed\"}\r\n\
             UKAI_VM {not json\n",
        )
        .unwrap();
        assert_eq!(
            guest_poweroff_reason(&console).as_deref(),
            Some("live_share_mount_failed")
        );
        std::fs::write(
            &console,
            "UKAI_VM {\"event\": \"done\", \"exit_code\": 0}\n",
        )
        .unwrap();
        assert_eq!(guest_poweroff_reason(&console), None);
        // Other audits carry a `reason` too; only a poweroff's is the
        // guest's own ending, however late the other line comes.
        std::fs::write(
            &console,
            "UKAI_VM {\"event\": \"poweroff\", \"reason\": \"attempt_tree_unverified\"}\n\
             UKAI_VM {\"event\": \"attempt_stop_failed\", \"reason\": \"not_a_poweroff\"}\n",
        )
        .unwrap();
        assert_eq!(
            guest_poweroff_reason(&console).as_deref(),
            Some("attempt_tree_unverified")
        );
        std::fs::write(
            &console,
            "UKAI_VM {\"event\": \"infrastructure_unknown\", \"reason\": \"not_a_poweroff\"}\n",
        )
        .unwrap();
        assert_eq!(guest_poweroff_reason(&console), None);
    }

    #[test]
    fn the_nat_adapter_is_the_flags_alone() {
        let path = Path::new("/x");
        for (flag, expected) in [(false, None), (true, Some(std::ffi::OsStr::new("1")))] {
            let command = custodian_command(path, path, path, path, path, path, None, flag);
            let nat: Vec<_> = command
                .get_envs()
                .filter(|(key, _)| *key == "UKAI_VM_GUEST_NAT")
                .collect();
            // `env_remove` is recorded as an explicit unset, so an inherited
            // value cannot reach the custodian.
            assert_eq!(nat.len(), 1, "{nat:?}");
            assert_eq!(nat[0].1, expected);
        }
        let share = Path::new("/workspace");
        let command = custodian_command(path, path, path, path, path, path, Some(share), false);
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args.last(), Some(&share.as_os_str()));
        assert_eq!(
            args[..2],
            [std::ffi::OsStr::new("3"), std::ffi::OsStr::new("4")]
        );
    }

    #[test]
    fn runtime_lock_is_exclusive_and_released_with_its_owner() {
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_runtime(dir.path()).unwrap();
        assert!(lock_runtime(dir.path()).is_err());
        drop(lock);
        lock_runtime(dir.path()).unwrap();
    }

    #[test]
    fn runtime_lock_is_released_while_a_forked_child_still_holds_its_descriptor() {
        // Another test's spawn forks the whole descriptor table, the lock's
        // descriptor included; the child keeps it until it execs (the
        // close-on-exec flag acts only then). This child is held in
        // pre_exec, between the fork and the exec, while the owner drops
        // the lock and the runtime is locked again.
        use std::io::{Read as _, Write as _};
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_runtime(dir.path()).unwrap();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let (gate_read, mut gate_write) = std::io::pipe().unwrap();
        let (ready_fd, gate_fd) = (ready_write.as_raw_fd(), gate_read.as_raw_fd());
        let spawner = std::thread::spawn(move || {
            let mut command = std::process::Command::new("/usr/bin/true");
            // SAFETY: the closure runs in the forked child and calls only
            // async-signal-safe functions (write, read, _exit).
            unsafe {
                command.pre_exec(move || {
                    let mut byte = 0u8;
                    if libc::write(ready_fd, b"r".as_ptr().cast(), 1) != 1
                        || libc::read(gate_fd, (&raw mut byte).cast(), 1) != 1
                    {
                        libc::_exit(125);
                    }
                    Ok(())
                });
            }
            let status = command.status();
            drop((ready_write, gate_read));
            status
        });
        let mut byte = [0u8];
        ready_read.read_exact(&mut byte).unwrap();
        drop(lock);
        let again = lock_runtime(dir.path());
        gate_write.write_all(b"g").unwrap();
        assert!(spawner.join().unwrap().unwrap().success());
        again.expect("the runtime lock outlived its owner in a forked child");
    }
}
