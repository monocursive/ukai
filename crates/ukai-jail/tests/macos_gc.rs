//! J16 (jail-macos.md §4.9) on the real macOS host: the boot session read,
//! custodian liveness against real processes, `gc --abandon` through the
//! binary against fabricated attempt roots, the audit-token kill's errno
//! paths, and the `run`/`doctor` orphan scan. Gated to macOS; the pure
//! custody decisions are covered portably in `portable_gc.rs` and in the
//! `decide` unit tests.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

use ukai_jail::capability::Capability;
use ukai_jail::config::EnvSettings;
use ukai_jail::gc::{self, Host as _};
use ukai_jail::platform::{
    PlanRequest, Platform, PlatformIdentity, PreparedExecution, PreparedPlan, Sinks,
};
use ukai_jail::records::{JailError, Os};
use ukai_jail::state::{self, AttemptDir, AttemptId};
use ukai_jail::supervisor;

/// The real macOS platform for `NativeHost`: only its identity is asked.
struct RealPlatform;

impl Platform for RealPlatform {
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Macos,
            arch: std::env::consts::ARCH.to_owned(),
            kernel: "darwin".to_owned(),
        }
    }
    fn probe(&self, _: &PlanRequest) -> Vec<Capability> {
        Vec::new()
    }
    fn prepare(&self, _: PreparedPlan, _: Sinks) -> Result<Box<dyn PreparedExecution>, JailError> {
        Err(ukai_jail::platform::macos::MacosPlatform::unsupported_error())
    }
}

fn context(data: PathBuf, root: &std::path::Path) -> supervisor::Context {
    supervisor::Context {
        platform: Box::new(RealPlatform),
        env_settings: EnvSettings {
            config_dir: Some(root.join("config")),
            data_dir: Some(data),
            ..Default::default()
        },
        cwd: root.join("workspace"),
        home: Some(root.join("home")),
        env_lookup: Box::new(|_| None),
    }
}

fn private_dir(path: &std::path::Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn json_file(path: &std::path::Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn read_json(path: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// The kernel's `proc_bsdinfo`, as far as this test reads it.
#[repr(C)]
struct BsdInfo {
    _head: [u32; 12],
    _comm: [u8; 16],
    _name: [u8; 32],
    _tail: [u32; 6],
    start_tvsec: u64,
    _start_tvusec: u64,
}

fn start_tvsec(pid: u32) -> Option<u64> {
    #[repr(C)]
    struct Info(BsdInfo);
    let mut info = Info(BsdInfo {
        _head: [0; 12],
        _comm: [0; 16],
        _name: [0; 32],
        _tail: [0; 6],
        start_tvsec: 0,
        _start_tvusec: 0,
    });
    // SAFETY: `info` is a `proc_bsdinfo`-shaped buffer outliving the call.
    let got = unsafe {
        proc_pidinfo(
            pid as libc::c_int,
            3,
            0,
            std::ptr::addr_of_mut!(info).cast(),
            std::mem::size_of::<Info>() as libc::c_int,
        )
    };
    (got != 0).then_some(info.0.start_tvsec)
}

unsafe extern "C" {
    // SAFETY: matches libproc's `proc_pidinfo` (libproc.h).
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

/// A child that is alive but stopped: a custodian that is unambiguously not
/// the test process, with a birth time the test reads back from the kernel.
struct StoppedChild(std::process::Child);

impl StoppedChild {
    fn spawn() -> StoppedChild {
        let child = Command::new("/bin/sleep").arg("300").spawn().unwrap();
        let pid = child.id() as i32;
        // SAFETY: `pid` names the child this process just spawned.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
        StoppedChild(child)
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for StoppedChild {
    fn drop(&mut self) {
        // SAFETY: `pid` names the child this process spawned.
        unsafe { libc::kill(self.0.id() as i32, libc::SIGKILL) };
        self.0.wait().unwrap();
    }
}

/// A child this test started, killed and reaped: its pid names nothing.
fn reaped_pid() -> u32 {
    let mut child = Command::new("/usr/bin/true").spawn().unwrap();
    let pid = child.id();
    // SAFETY: `pid` names the child this process spawned.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    child.wait().unwrap();
    pid
}

struct Fixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = common::private_tempdir();
        let root = dir.path().canonicalize().unwrap();
        let data = root.join("data");
        private_dir(&data);
        private_dir(&data.join("attempts"));
        private_dir(&root.join("config"));
        private_dir(&root.join("workspace"));
        Fixture {
            data,
            root,
            _root: dir,
        }
    }
    fn ctx(&self) -> supervisor::Context {
        context(self.data.clone(), &self.root)
    }
    /// The real binary over this fixture's state root.
    fn binary(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
            .args(args)
            .current_dir(self.root.join("workspace").as_path())
            .env("UKAI_CONFIG_DIR", self.root.join("config"))
            .env("UKAI_DATA_DIR", &self.data)
            .env("HOME", self.root.join("home"))
            .output()
            .unwrap()
    }
}

/// The claim a macOS supervisor writes (§7): boot session and an
/// epoch-second birth time.
fn claim(dir: &AttemptDir, owner: (u32, String, u64)) {
    let id = dir.root().file_name().unwrap().to_str().unwrap();
    json_file(
        &dir.state_path(),
        &json!({
            "schema": "ukai.jail.state/1",
            "attempt_id": id,
            "os": "macos",
            "arch": std::env::consts::ARCH,
            "kernel": "darwin",
            "component_version": "0.0.0",
            "claimed_at": "2026-10-22T00:00:00Z",
            "owner": {"pid": owner.0, "boot_id": owner.1, "start_time_ticks": owner.2},
            "boundary": Value::Null,
            "vendor_state": Value::Null,
            "state_cleanup": "not_needed",
        }),
    );
    let bytes = std::fs::read(dir.state_path()).unwrap();
    if let Err(error) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        panic!("the fabricated claim is not JSON: {error}");
    }
}

/// A `jail.lock` whose lease nobody holds.
fn free_lock(dir: &AttemptDir) {
    drop(
        state::Lease::acquire(&dir.lock_path())
            .unwrap()
            .expect("a fresh lease is free"),
    );
}

/// A macOS receipt: `macos_audit_token` identity, unverified end. Built on
/// the shipped example, which carries the full typed shape the cleanup's
/// receipt reader needs.
fn receipt(dir: &AttemptDir, target: (u32, u32), boot: &str) {
    let mut receipt: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/specs/jail-v1/examples/receipt-none-prepared.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let id = dir.root().file_name().unwrap().to_str().unwrap();
    receipt["attempt_id"] = json!(id);
    receipt["phase"] = json!("enforced");
    receipt["exec_observed"] = json!(true);
    receipt["process"]["identity"] = json!({
        "kind": "macos_audit_token",
        "value": {"pid": target.0, "pidversion": target.1, "boot_session": boot},
    });
    receipt["lifetime"]["integrity"] = json!("verified");
    receipt["lifetime"]["boundary"] = json!("native_tree");
    receipt["lifetime"]["tree_empty"] = Value::Null;
    receipt["lifetime"]["native"] = json!({
        "os": "macos", "details": {
            "custody": "es_descendants", "defense": "seatbelt",
            "custodians": {"supervisor": {"result": "lost"},
                           "guardian": {"result": "lost"}},
        },
    });
    json_file(&dir.receipt_path(), &receipt);
}

/// The guardian's record as the guardian writes it.
fn guardian_record(dir: &AttemptDir, drained: bool) {
    let token: Vec<u32> = (0..8)
        .map(|word| if word == 5 { 88 } else { word + 1 })
        .collect();
    json_file(
        &dir.root().join("guardian.json"),
        &json!({
            "schema": "ukai.jail.guardian-record/1",
            "drained": drained,
            "own_token": token,
            "boot_session": gc::boot_session(),
        }),
    );
}

fn actions(dir: &AttemptDir) -> Vec<String> {
    read_json(&dir.state_path())["gc_actions"]
        .as_array()
        .map(|actions| {
            actions
                .iter()
                .map(|action| action["action"].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn fresh(fixture: &Fixture) -> (String, AttemptDir) {
    let id = AttemptId::generate().as_str().to_owned();
    let dir = AttemptDir::new(&fixture.data, &AttemptId::parse(&id).unwrap());
    dir.create(&fixture.data).unwrap();
    free_lock(&dir);
    (id, dir)
}

/// The boot session this host reports matches what the kernel says.
#[test]
fn the_boot_session_is_the_kernel_s() {
    let output = Command::new("/usr/sbin/sysctl")
        .arg("-n")
        .arg("kern.bootsessionuuid")
        .output()
        .unwrap();
    let kernel = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let read = gc::boot_session();
    if kernel.is_empty() {
        assert!(read.is_none(), "{read:?}");
    } else {
        assert_eq!(read.as_deref(), Some(kernel.as_str()));
    }
}

/// Custodian liveness: a stopped child is alive at its recorded birth
/// time; a wrong birth time is a reused pid; a reaped pid is gone.
#[test]
fn custodian_liveness_reads_the_host() {
    let session = gc::boot_session().expect("a boot session on macOS");
    let stopped = StoppedChild::spawn();
    let start = start_tvsec(stopped.pid()).expect("the child's start time");
    let ctx = context(PathBuf::from("/nonexistent"), &std::env::temp_dir());
    let host = gc::native_host(&ctx);
    let owner = ukai_jail::gc::OwnerRecord {
        pid: stopped.pid(),
        boot_id: session.clone(),
        start_time_ticks: start,
    };
    assert!(matches!(host.owner(&owner), ukai_jail::gc::Liveness::Alive));
    let reused = ukai_jail::gc::OwnerRecord {
        start_time_ticks: start.wrapping_sub(1),
        ..owner.clone()
    };
    assert!(matches!(
        host.owner(&reused),
        ukai_jail::gc::Liveness::Reused
    ));
    drop(stopped);
    let gone = ukai_jail::gc::OwnerRecord {
        pid: reaped_pid(),
        ..owner
    };
    assert!(matches!(host.owner(&gone), ukai_jail::gc::Liveness::Gone));
}

/// The audit-token kill tolerates `ESRCH`: a token whose pid is gone (and
/// a pid version that is not the kernel's) is a no-op, recorded
/// `gc_killed_target`, and the vendor lease stays held.
#[test]
fn the_kill_of_a_gone_target_is_recorded_and_holds_the_lease() {
    let fixture = Fixture::new();
    let (_id, dir) = fresh(&fixture);
    claim(&dir, (reaped_pid(), gc::boot_session().unwrap(), 1));
    receipt(
        &dir,
        (reaped_pid(), 0),
        gc::boot_session().unwrap().as_str(),
    );
    guardian_record(&dir, false);
    let vendor = dir.vendor_state_path();
    private_dir(&vendor);
    std::fs::write(vendor.join("precious"), b"vendor state").unwrap();
    let mut state = read_json(&dir.state_path());
    state["state_cleanup"] = json!("pending");
    json_file(&dir.state_path(), &state);

    let output = fixture.binary(&["gc"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(stdout.contains("killed_target"), "{stdout}\n{stderr}");
    assert!(
        output.status.success(),
        "exit {:?}: {stdout}\n{stderr}",
        output.status.code()
    );
    assert!(actions(&dir).contains(&"gc_killed_target".to_owned()));
    assert!(vendor.exists(), "the vendor lease stays held");
}

/// `gc --abandon` releases the lease: vendor state goes, `gc_abandoned` is
/// recorded, the receipt and the attempt stay on disk.
#[test]
fn abandon_releases_the_lease_and_keeps_the_attempt() {
    let fixture = Fixture::new();
    let (id, dir) = fresh(&fixture);
    claim(&dir, (reaped_pid(), gc::boot_session().unwrap(), 1));
    receipt(
        &dir,
        (reaped_pid(), 0),
        gc::boot_session().unwrap().as_str(),
    );
    guardian_record(&dir, true);
    let vendor = dir.vendor_state_path();
    private_dir(&vendor);
    std::fs::write(vendor.join("precious"), b"vendor state").unwrap();
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(&vendor).unwrap();
        let mut state = read_json(&dir.state_path());
        state["vendor_state"] = json!({
            "name": "vendor-state",
            "registered_at": "2026-10-22T00:00:00Z",
            "dev": meta.dev().to_string(),
            "ino": meta.ino().to_string(),
            "credentials": [],
        });
        state["state_cleanup"] = json!("pending");
        json_file(&dir.state_path(), &state);
    }

    let output = fixture.binary(&["gc", "--abandon", &id]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(actions(&dir).contains(&"gc_abandoned".to_owned()));
    assert!(!vendor.exists());
    assert!(
        dir.receipt_path().exists(),
        "the receipt is left as written"
    );
    assert!(dir.state_path().exists(), "the attempt is retained on disk");

    // A later pass finds nothing further, and the dry run reports it.
    let dry = fixture.binary(&["gc", "--dry-run", "--json"]);
    let stdout = String::from_utf8_lossy(&dry.stdout).into_owned();
    assert!(
        stdout.contains("custody_verified") || stdout.contains("finished"),
        "{stdout}"
    );
}

/// An abandon of an unknown attempt is refused naming it.
#[test]
fn an_unknown_abandon_is_refused_naming_it() {
    let fixture = Fixture::new();
    let missing = "att_00000000-0000-4000-8000-00000000000f";
    let output = fixture.binary(&["gc", "--abandon", missing]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(missing), "{stderr}");
}

/// §4.9, last paragraph: `doctor` names the attempts whose custodians are
/// both dead and whose end is not verified, and never touches them. A
/// released or settled attempt is not named.
#[test]
fn doctor_names_unverified_ends_and_nothing_else() {
    let fixture = Fixture::new();
    let (unverified, dir) = fresh(&fixture);
    claim(&dir, (reaped_pid(), gc::boot_session().unwrap(), 1));
    receipt(
        &dir,
        (reaped_pid(), 0),
        gc::boot_session().unwrap().as_str(),
    );
    let (settled, settled_dir) = fresh(&fixture);
    claim(&settled_dir, (reaped_pid(), gc::boot_session().unwrap(), 1));
    // A released custody: gc_abandoned in jail state.
    let mut state = read_json(&settled_dir.state_path());
    state["gc_actions"] = json!([{"action": "gc_abandoned", "at": "t"}]);
    json_file(&settled_dir.state_path(), &state);

    let output = fixture.binary(&["doctor"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        stderr.contains(&format!("attempt {unverified} ended unverified")),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("gc --abandon {unverified}")),
        "{stderr}"
    );
    assert!(!stderr.contains(&format!("attempt {settled} ")), "{stderr}");
    // The scan killed nothing and wrote nothing: the named attempt's state
    // and receipt are exactly as they were fabricated.
    assert!(actions(&dir).is_empty());
}

/// The orphan scan on a real host through the library entry point: a dead
/// attempt with a drained guardian record is named too.
#[test]
fn the_scan_names_a_drained_but_unrecorded_end_once() {
    let fixture = Fixture::new();
    let (id, dir) = fresh(&fixture);
    claim(&dir, (reaped_pid(), gc::boot_session().unwrap(), 1));
    guardian_record(&dir, true);
    // No receipt at all: the end is not verified by anything.
    let printed = gc::orphans::announce(&fixture.ctx());
    assert_eq!(printed, 1, "the scan names {id} once");
    assert!(actions(&dir).is_empty(), "the scan never writes");
}
