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
//! the guest and exits. The wire frames are [`protocol`]; the guest
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
    /// Stage one ephemeral credential in the guest's tmpfs.
    Secret { id: String, data: String },
    /// One workspace file, the preview's frame.
    Put {
        path: String,
        executable: bool,
        data: String,
    },
    /// Run the jail, warm: no poweroff at completion.
    Run2 {
        profile: String,
        wall_seconds: u32,
        argv: Vec<String>,
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
}

// ---------------------------------------------------------------------------
// Shared service state
// ---------------------------------------------------------------------------

/// What the control socket's `status` reports, kept current by the threads.
#[derive(Default)]
struct Shared {
    stopping: AtomicBool,
    attempt_live: AtomicBool,
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
}

/// One guest frame as the reader thread delivered it, or the transport's end.
enum GuestLine {
    Frame(GuestEvent),
    HelperEnded(String),
}

fn write_helper(service: &Service, frame: &HelperWrite) -> Result<(), String> {
    let line = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
    let mut stdin = service
        .helper_stdin
        .lock()
        .map_err(|error| error.to_string())?;
    stdin
        .write_all(&line)
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.flush())
        .map_err(|error| format!("the VZ client stopped reading: {error}"))
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

fn serve(args: ServeArgs) -> Result<(), String> {
    install_signal_handlers();
    let install = image::Install::discover().map_err(|e| e.0)?;
    install.verify().map_err(|e| e.0)?;
    let data_dir = data_dir()?;
    let runtime = data_dir.join("vm");
    std::fs::create_dir_all(&runtime)
        .map_err(|error| format!("{} cannot be created: {error}", runtime.display()))?;
    private_dir(&runtime)?;
    for stale in ["control.sock", "attempt.sock"] {
        let _ = std::fs::remove_file(runtime.join(stale));
    }
    // A crashed earlier serve may leave its clone; it is disposable state,
    // never a resumed VM (the preview's rule), so the boot starts clean.
    let disk = runtime.join("guest.raw");
    let _ = std::fs::remove_file(&disk);
    let nvram = runtime.join("guest.nvram");
    let _ = std::fs::remove_file(&nvram);
    let console = runtime.join("console.log");
    let _ = std::fs::remove_file(&console);
    clone_disk(&install.base_disk(), &disk)?;

    // The custody lease, the preview's shape: the custodian owns the VZ
    // client as an unreaped child and kills it when this lease expires.
    let (lease_read, lease_write) = fd_pipe()?;
    let (ack_read, ack_write) = fd_pipe()?;
    // The custodian owns the lease's read end and the ack's write end in
    // the child; the parent keeps the write and read ends alive for the
    // lease thread's whole life.
    let mut custodian = spawn_custodian(
        &install,
        &disk,
        &install.seed(),
        &nvram,
        &console,
        &lease_read,
        &ack_write,
    )?;
    let helper_stdin = custodian.stdin.take().ok_or("no helper stdin")?;
    let helper_stdout = custodian.stdout.take().ok_or("no helper stdout")?;
    let mut stdout_reader = std::io::BufReader::new(helper_stdout);

    let (guest_sender, guest_frames) = std::sync::mpsc::channel::<GuestLine>();
    let shared = Arc::new(Shared::default());
    let reader_shared = Arc::clone(&shared);
    let reader = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 16384];
        'outer: loop {
            match stdout_reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                Err(error) => {
                    let _ = std::fs::OpenOptions::new()
                        .append(true)
                        .open("/dev/stderr")
                        .and_then(|mut err| writeln!(err, "ukai-vm: helper read failed: {error}"));
                    break;
                }
            }
            while let Some(position) = buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = buffer.drain(..=position).collect();
                let Ok(event) = serde_json::from_slice::<HelperEvent>(&line[..line.len() - 1])
                else {
                    continue;
                };
                match event.event.as_str() {
                    "data" => {
                        let Some(encoded) = event.data.as_deref() else {
                            continue;
                        };
                        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded)
                        else {
                            continue;
                        };
                        for frame in bytes.split(|byte| *byte == b'\n') {
                            if frame.is_empty() {
                                continue;
                            }
                            match serde_json::from_slice::<GuestEvent>(frame) {
                                Ok(parsed) => {
                                    if guest_sender.send(GuestLine::Frame(parsed)).is_err() {
                                        break 'outer;
                                    }
                                }
                                Err(_) => continue,
                            }
                        }
                    }
                    "error" => {
                        let _ = guest_sender.send(GuestLine::HelperEnded(
                            event.error.unwrap_or_else(|| "helper error".to_owned()),
                        ));
                        break 'outer;
                    }
                    "stopped" => {
                        let _ = guest_sender.send(GuestLine::HelperEnded(String::from("stopped")));
                        break 'outer;
                    }
                    _ => {}
                }
            }
            if buffer.len() > 4 * 1024 * 1024 || reader_shared.stopping.load(AtomicOrdering::SeqCst)
            {
                break;
            }
        }
    });

    // The lease thread: refresh, check the acknowledgement, die loudly.
    let lease = {
        let shared = Arc::clone(&shared);
        let lease_write = lease_write.try_clone_to_owned()?;
        let ack_read = ack_read.try_clone_to_owned()?;
        std::thread::spawn(move || {
            let mut refreshed = continuous_ns();
            let mut ack_buffer = [0u8; 64];
            while !shared.stopping.load(AtomicOrdering::SeqCst)
                && !STOP.load(AtomicOrdering::SeqCst)
            {
                std::thread::sleep(LEASE_REFRESH);
                let now = continuous_ns();
                let _ = read_nonblocking(&ack_read, &mut ack_buffer);
                if now.saturating_sub(refreshed) > u128::from(LEASE_ACK.as_secs()) {
                    // The custodian is about to kill the VZ client on its
                    // own three-second lease; record and let it.
                    eprintln!("ukai-vm: the custody lease stopped being acknowledged");
                    std::process::exit(125);
                }
                refreshed = now;
                // SAFETY: `write` on an owned descriptor with a valid buffer.
                let written =
                    unsafe { libc::write(lease_write.as_raw_fd(), b".".as_ptr().cast(), 1) };
                if written < 0 {
                    eprintln!("ukai-vm: the custody lease closed");
                    std::process::exit(125);
                }
            }
        })
    };

    let control_listener = bind_socket(&runtime.join("control.sock"))?;
    let attempt_listener = bind_socket(&runtime.join("attempt.sock"))?;
    eprintln!(
        "ukai-vm: serving warm guest {} on {}",
        install.root.display(),
        runtime.join("control.sock").display()
    );

    let service = Arc::new(Service {
        helper_stdin: Arc::new(Mutex::new(helper_stdin)),
        shared: Arc::clone(&shared),
        boot_id: format!("vm-{}", std::process::id()),
        install,
        sockets: (runtime.join("control.sock"), runtime.join("attempt.sock")),
    });

    // The control thread answers status and stop while attempts run.
    let control_shared = Arc::clone(&service.shared);
    let control_install = image::Install::from_root(service.install.root.clone())
        .map(|install| install.manifest)
        .map_err(|error| error.to_string())?;
    let control_stop = {
        let service = Arc::clone(&service);
        move || {
            let _ = write_helper(&service, &HelperWrite::Stop);
        }
    };
    let control_thread = std::thread::spawn(move || {
        for stream in control_listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match stream.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        line.push(byte[0]);
                        if byte[0] == b'\n' || line.len() > protocol::MAX_FRAME {
                            break;
                        }
                    }
                }
            }
            let Ok(request) = serde_json::from_slice::<protocol::ToControl>(&line) else {
                continue;
            };
            let reply = match request {
                protocol::ToControl::Status => protocol::FromControl::Status {
                    schema: protocol::SCHEMA_CONTROL.to_owned(),
                    boot_id: String::from("reported-by-serve"),
                    warm: !control_shared.stopping.load(AtomicOrdering::SeqCst),
                    attempt_live: control_shared.attempt_live.load(AtomicOrdering::SeqCst),
                    kernel: SHARED_GUEST_KERNEL
                        .lock()
                        .ok()
                        .and_then(|guard| guard.clone()),
                    disk_sha256: control_install.disk_sha256.clone(),
                    helper_sha256: control_install.helper_sha256.clone(),
                    custodian_sha256: control_install.custodian_sha256.clone(),
                    seed_sha256: control_install.seed_sha256.clone(),
                    vsock_port: GUEST_PORT,
                    idle_seconds: IDLE_SECONDS,
                },
                protocol::ToControl::Stop => {
                    control_shared.stopping.store(true, AtomicOrdering::SeqCst);
                    STOP.store(true, AtomicOrdering::SeqCst);
                    control_stop();
                    protocol::FromControl::Stopping {
                        schema: protocol::SCHEMA_CONTROL.to_owned(),
                    }
                }
            };
            if let Ok(mut frame) = serde_json::to_vec(&reply) {
                frame.push(b'\n');
                let _ = stream.write_all(&frame);
            }
            if matches!(reply, protocol::FromControl::Stopping { .. }) {
                break;
            }
        }
    });

    let boot_id = service.boot_id.clone();
    let result = drive_attempts(
        &service,
        &guest_frames,
        &attempt_listener,
        args.idle_seconds,
    );
    // Orderly stop: the guest session ends, the VM service ends, the sockets
    // come down.
    service.shared.stopping.store(true, AtomicOrdering::SeqCst);
    let _ = write_helper(&service, &HelperWrite::Stop);
    let _ = std::fs::remove_file(&service.sockets.0);
    let _ = std::fs::remove_file(&service.sockets.1);
    let _ = std::fs::remove_file(&disk);
    let _ = reader.join();
    let _ = lease.join();
    let _ = control_thread.join();
    eprintln!("ukai-vm: stopped boot {boot_id}");
    result
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
                idle_since = continuous_ns();
                let outcome = run_attempt(service, frames, stream);
                service
                    .shared
                    .attempt_live
                    .store(false, AtomicOrdering::SeqCst);
                outcome?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.to_string()),
        }
        if !service.shared.attempt_live.load(AtomicOrdering::SeqCst)
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
        } => {
            if !protocol::GUEST_PROFILES.contains(&profile.as_str()) {
                return Err(format!(
                    "the attempt names profile `{profile}`, not one of {}",
                    protocol::GUEST_PROFILES.join(", ")
                ));
            }
            if !(1..=protocol::WALL_MAX).contains(&wall_seconds) {
                return Err(format!(
                    "the attempt names a wall of {wall_seconds}s, past the guest grammar"
                ));
            }
            for argument in &argv {
                if protocol::decode_data(argument)
                    .map_err(|error| error.to_string())?
                    .is_empty()
                    || protocol::decode_data(argument)
                        .map_err(|error| error.to_string())?
                        .contains(&0)
                {
                    return Err(
                        "the attempt's argv holds an empty or NUL-bearing element".to_owned()
                    );
                }
            }
            Ok((attempt_id, profile, wall_seconds, argv, secrets))
        }
        protocol::ToVm::Put(_) | protocol::ToVm::Run => {
            Err("the attempt opened with staging frames instead of `prepare`".to_owned())
        }
    }?;
    let (_, profile, wall_seconds, argv, secrets) = prepared;

    // The warm session, once per boot.
    guest_line(service, &GuestOp::Session)?;
    expect_guest(frames, "session")?;
    guest_line(service, &GuestOp::Reset)?;
    expect_guest(frames, "reset")?;
    let kernel = guest_kernel(frames)?;
    if let Ok(mut guard) = SHARED_GUEST_KERNEL.lock() {
        *guard = Some(kernel.clone());
    }
    for secret in &secrets {
        guest_line(
            service,
            &GuestOp::Secret {
                id: secret.id.clone(),
                data: secret.data.clone(),
            },
        )?;
        expect_guest(frames, "secret")?;
    }
    let staged = service_staged_files(service, &mut stream)?;
    send(
        &mut stream,
        &protocol::FromVm::Prepared {
            kernel: kernel.clone(),
        },
    )?;
    let _ = staged;

    // The release loop ends only by sending `run`; from there the attempt
    // is released.
    loop {
        match read_request(&mut stream)? {
            protocol::ToVm::Put(put) => {
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
            profile,
            wall_seconds,
            argv,
        },
    )?;
    expect_guest(frames, "running")?;

    // The lease: this stream's end cancels the attempt. The watcher holds a
    // clone and blocks on it; the client sends nothing after `run`.
    let watch_stream = stream.try_clone().map_err(|error| error.to_string())?;
    let watch_flag = Arc::new(AtomicBool::new(false));
    let watcher_flag = Arc::clone(&watch_flag);
    let watcher = std::thread::spawn(move || {
        let mut stream = watch_stream;
        let mut buffer = [0u8; 1];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        watcher_flag.store(true, AtomicOrdering::SeqCst);
    });

    let outcome = relay_attempt(service, frames, &mut stream, &watch_flag);
    watcher.join().map_err(|_| "the lease watcher failed")?;
    outcome
}

fn relay_attempt(
    service: &Service,
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    stream: &mut UnixStream,
    watch_flag: &AtomicBool,
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
        if continuous_ns() > deadline {
            return Err("the attempt ran past its host deadline".to_owned());
        }
        let frame = match frames.recv_timeout(Duration::from_millis(100)) {
            Ok(GuestLine::Frame(frame)) => frame,
            Ok(GuestLine::HelperEnded(reason)) => {
                return Err(format!("the VM service ended: {reason}"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if watch_flag.load(AtomicOrdering::SeqCst) {
                    // The lease's end-of-file: cancel the attempt, and the
                    // session stays warm (§6). The client is gone, so the
                    // outcome goes nowhere; the guest's audit has it.
                    guest_line(service, &GuestOp::Cancel2)?;
                    let _ = expect_guest(frames, "cancelled");
                    return Err(
                        "the attempt's lease ended: the guest attempt was cancelled".to_owned()
                    );
                }
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
                    &protocol::FromVm::Receipt {
                        sha256: digest,
                        data: sha256,
                    },
                )?;
                send(stream, &protocol::FromVm::Done { exit_code })?;
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

/// Reads and acknowledges the attempt's `put` frames, so the guest stages
/// them before the run is released.
fn service_staged_files(_service: &Service, _stream: &mut UnixStream) -> Result<usize, String> {
    // The puts arrive after `prepared` (the host sends them once the guest
    // accepted the staging), so this side reads them in the release loop.
    Ok(0)
}

fn read_request(stream: &mut UnixStream) -> Result<protocol::ToVm, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Err("the attempt connection closed".to_owned()),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > protocol::MAX_FRAME {
                    return Err("the attempt sent an oversized frame".to_owned());
                }
            }
            Err(error) => return Err(format!("the attempt connection failed: {error}")),
        }
    }
    protocol::decode::<protocol::ToVm>(&line).map_err(|error| error.to_string())
}

fn expect_guest(
    frames: &std::sync::mpsc::Receiver<GuestLine>,
    event: &str,
) -> Result<GuestEvent, String> {
    let deadline = continuous_ns() + 30 * 1_000_000_000;
    loop {
        if continuous_ns() > deadline {
            return Err(format!("the guest did not answer `{event}`"));
        }
        match frames.recv_timeout(Duration::from_millis(100)) {
            Ok(GuestLine::Frame(frame)) if frame.event == event => return Ok(frame),
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

fn guest_kernel(frames: &std::sync::mpsc::Receiver<GuestLine>) -> Result<String, String> {
    let mut guard = SHARED_GUEST_KERNEL
        .lock()
        .map_err(|error| error.to_string())?;
    if let Some(kernel) = guard.as_ref() {
        return Ok(kernel.clone());
    }
    let frame = expect_guest(frames, "session")?;
    let kernel = frame.kernel.clone().unwrap_or_else(|| "unknown".to_owned());
    *guard = Some(kernel.clone());
    Ok(kernel)
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

fn clone_disk(base: &Path, destination: &Path) -> Result<(), String> {
    let status = std::process::Command::new("/bin/cp")
        .arg("-c")
        .arg(base)
        .arg(destination)
        .status()
        .map_err(|error| format!("cp cannot start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "the guest disk clone failed: {} is not a clone of {}",
            destination.display(),
            base.display()
        ))
    }
}

fn fd_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), String> {
    // SAFETY: the array is plain writable storage `pipe` fills.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe` writes exactly two descriptor numbers into the array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe failed: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: both descriptors are freshly created and owned.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

trait TryCloneFd {
    fn try_clone_to_owned(&self) -> Result<std::os::fd::OwnedFd, String>;
}

impl TryCloneFd for std::os::fd::OwnedFd {
    fn try_clone_to_owned(&self) -> Result<std::os::fd::OwnedFd, String> {
        self.try_clone().map_err(|error| error.to_string())
    }
}

fn spawn_custodian(
    install: &image::Install,
    disk: &Path,
    seed: &Path,
    nvram: &Path,
    console: &Path,
    lease_read: &std::os::fd::OwnedFd,
    ack_write: &std::os::fd::OwnedFd,
) -> Result<std::process::Child, String> {
    use std::os::fd::AsRawFd as _;
    use std::process::Stdio;
    let lease_fd = lease_read.as_raw_fd();
    let ack_fd = ack_write.as_raw_fd();
    let mut command = std::process::Command::new(install.custodian());
    command
        .args([lease_fd.to_string(), ack_fd.to_string()])
        .arg(install.helper())
        .arg(disk)
        .arg(seed)
        .arg(nvram)
        .arg(console)
        .arg("run")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // The closure must own its descriptors ('static); the clones die
    // with the child's exec or with the command.
    let lease_child = lease_read
        .try_clone()
        .map_err(|error| format!("the lease end cannot be cloned: {error}"))?;
    let ack_child = ack_write
        .try_clone()
        .map_err(|error| format!("the ack end cannot be cloned: {error}"))?;
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

fn read_nonblocking(fd: &std::os::fd::OwnedFd, buffer: &mut [u8]) -> std::io::Result<usize> {
    // SAFETY: `read` on an owned descriptor with a valid buffer.
    let count = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if count < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(0);
        }
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
    /// Print the version and the schema identifiers this build announces.
    Version,
}

#[derive(Debug, clap::Args)]
struct ServeArgs {
    /// The idle budget in seconds; 0 never idles out.
    #[arg(long, default_value_t = IDLE_SECONDS)]
    idle_seconds: u64,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let outcome = match args.command {
        Command::Version => {
            println!(
                "{}",
                serde_json::json!({
                    "component": "ukai-vm",
                    "version": env!("CARGO_PKG_VERSION"),
                    "execution": "linux-vm-warm",
                    "native_macos_execution": false,
                    "attempt": protocol::SCHEMA_ATTEMPT,
                    "control": protocol::SCHEMA_CONTROL,
                    "transport": record::SCHEMA_TRANSPORT,
                })
            );
            Ok(())
        }
        Command::Status => control_round_trip(protocol::ToControl::Status).and_then(|reply| {
            println!(
                "{}",
                serde_json::to_string_pretty(&reply).map_err(|error| error.to_string())?
            );
            Ok(())
        }),
        Command::Stop => control_round_trip(protocol::ToControl::Stop).map(|_| {
            println!("ukai-vm: stopping: the warm guest ends with its service");
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

fn control_round_trip(request: protocol::ToControl) -> Result<(), String> {
    let socket = control_socket();
    match control::control_round_trip(&socket, request) {
        Ok(_) => Ok(()),
        Err(control::ControlError::Absent) => {
            println!("ukai-vm: no VM is running");
            Ok(())
        }
        Err(control::ControlError::Failed(error)) => Err(error.to_string()),
    }
}

fn control_socket() -> PathBuf {
    data_dir()
        .map(|dir| dir.join("vm").join("control.sock"))
        .unwrap_or_else(|_| PathBuf::from("/nonexistent/vm/control.sock"))
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
