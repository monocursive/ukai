//! J14 persistent vendor state, live (`docs/specs/jail-interactive-sessions.md`
//! §6.2, rows K66, K67, K69, K70, K73 and K74).
//!
//! Every run here is the real `ukai-jail run --launch` with a fixture launch
//! profile, `keeper`, whose state is persistent. The runs of one test share
//! one data and config directory (`UKAI_DATA_DIR`, `UKAI_CONFIG_DIR`), so they
//! see the same state, the way one operator's successive sessions do. The
//! contained side is a Python script; the host side is the test, standing in
//! for the operator between runs. Every receipt read is held to the
//! re-blessed schemas.
#![cfg(target_os = "linux")]

mod common;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;
use ukai_fixture::harness::{self, Jail, Run};
use ukai_jail::persistent;

/// The launch profile every test here writes.
const LAUNCH: &str = "keeper";

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn fixture_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// One operator's data and config directories, the `keeper` profile and the
/// workspaces its runs use.
struct Keeper {
    root: tempfile::TempDir,
}

impl Keeper {
    /// `keeper` under `jail`, persistent, discarding `.login.json` and
    /// `drop-me`, plus `extra` profile lines.
    fn new(jail: &str, extra: &str) -> Keeper {
        let keeper = Keeper {
            root: common::private_tempdir(),
        };
        private_dir(&keeper.data());
        private_dir(&keeper.config().join("launch"));
        fixture_file(
            &keeper
                .config()
                .join("launch")
                .join(format!("{LAUNCH}.toml")),
            format!(
                "name = \"{LAUNCH}\"\njail = \"{jail}\"\nstate_var = \"KEEP_HOME\"\n\
                 state = \"persistent\"\nstate_discard = [\".login.json\", \"drop-me\"]\n{extra}"
            )
            .as_bytes(),
        );
        keeper
    }

    fn data(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn config(&self) -> PathBuf {
        self.root.path().join("config")
    }

    /// A fresh private workspace directory under this operator's root.
    fn workspace(&self, name: &str) -> PathBuf {
        let path = self.root.path().join(name);
        private_dir(&path);
        path
    }

    /// `ukai-jail run --launch keeper` in `workspace`, sharing this
    /// operator's directories.
    fn jail(&self, workspace: &Path) -> Jail {
        Jail::new()
            .unwrap()
            .env("UKAI_DATA_DIR", self.data())
            .env("UKAI_CONFIG_DIR", self.config())
            .arg("run")
            .arg("--workspace")
            .arg(workspace)
            .arg("--launch")
            .arg(LAUNCH)
    }

    /// Another `ukai-jail` verb with this operator's directories.
    fn verb(&self, args: &[&str]) -> std::process::Output {
        Command::new(harness::jail_path())
            .args(args)
            .env("UKAI_DATA_DIR", self.data())
            .env("UKAI_CONFIG_DIR", self.config())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn attempts(&self) -> BTreeSet<PathBuf> {
        std::fs::read_dir(self.data().join("attempts"))
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default()
    }

    /// The one attempt made since `before`.
    fn new_attempt(&self, before: &BTreeSet<PathBuf>) -> PathBuf {
        let made: Vec<PathBuf> = self.attempts().difference(before).cloned().collect();
        assert_eq!(made.len(), 1, "one new attempt: {made:?}");
        made.into_iter().next().unwrap()
    }

    fn key_dir(&self, workspace: &Path) -> PathBuf {
        persistent::key_path(
            &self.data(),
            LAUNCH,
            &persistent::key(LAUNCH, workspace.as_os_str().as_bytes()),
        )
    }

    fn record(&self, workspace: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(self.key_dir(workspace).join("state.json")).unwrap())
            .unwrap()
    }

    fn vendor(&self, workspace: &Path) -> PathBuf {
        self.key_dir(workspace).join("vendor")
    }
}

/// An attempt's receipt, held to the schemas.
fn receipt(attempt: &Path) -> Value {
    common::read_receipt(&attempt.join("jail.json"))
}

fn attempt_id(attempt: &Path) -> String {
    attempt.file_name().unwrap().to_str().unwrap().to_owned()
}

/// The summary's `state` line for an attempt, as `tail --summary` computes it.
fn state_line(attempt: &Path) -> Option<String> {
    ukai_jail::summary::summarize_attempt(attempt)
        .unwrap()
        .lines
        .into_iter()
        .find(|line| line.line == "state")
        .map(|line| line.text)
}

/// The last JSON line a run's target printed.
fn out(run: &Run) -> Value {
    let text = run.stdout_text();
    let line = text
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON: stdout {text:?}, stderr {}", run.stderr_text()));
    serde_json::from_str(line).unwrap()
}

fn python(script: &str, args: &[&OsString]) -> Vec<OsString> {
    let mut argv = vec![
        OsString::from(common::PYTHON),
        OsString::from("-c"),
        OsString::from(script),
    ];
    argv.extend(args.iter().map(|arg| (*arg).clone()));
    argv
}

/// What a run with standard error a terminal printed there, and its exit
/// code. Standard input is `/dev/null`, so the run is detached: only the
/// lines a terminal on standard error earns are under test.
fn run_with_terminal_stderr(keeper: &Keeper, args: &[OsString]) -> (Option<i32>, String) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: two live integers for the descriptors; the name, termios and
    // window-size arguments may be null.
    let rc = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: openpty returned two fresh descriptors this test now owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let mut child = Command::new(harness::jail_path())
        .args(args)
        .env("UKAI_DATA_DIR", keeper.data())
        .env("UKAI_CONFIG_DIR", keeper.config())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let mut text = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        // SAFETY: a read into a live buffer from a descriptor this test owns.
        let n = unsafe {
            libc::read(
                master.as_raw_fd(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if n <= 0 {
            // EIO once the last holder of the slave is gone.
            break;
        }
        text.extend_from_slice(&buffer[..usize::try_from(n).unwrap()]);
    }
    let status = child.wait().unwrap();
    let _ = reader.join();
    (status.code(), String::from_utf8_lossy(&text).into_owned())
}

/// The words of a `run --launch keeper` in `workspace`, then `argv`.
fn run_words(workspace: &Path, flags: &[&str], argv: &[OsString]) -> Vec<OsString> {
    let mut words: Vec<OsString> = vec![
        "run".into(),
        "--workspace".into(),
        workspace.as_os_str().to_owned(),
        "--launch".into(),
        LAUNCH.into(),
    ];
    words.extend(flags.iter().map(OsString::from));
    words.push("--".into());
    words.extend(argv.iter().cloned());
    words
}

// ===========================================================================
// K66 and K69: protection, privacy between workspaces, and the chain
// ===========================================================================

/// The first run's child: writes a kept file, the discard list's entries, a
/// link out of the state, a FIFO and a socket; tries a hard link each way
/// between the state and the workspace; lists its descriptors.
const WRITER: &str = r#"
import json, os, socket, sys
home = os.environ["KEEP_HOME"]; ws, outside, content = sys.argv[1:4]
out = {"saw": sorted(os.listdir(home))}
open(home + "/kept-k66.txt", "w").write(content)
open(home + "/.login.json", "w").write("a login made inside")
os.makedirs(home + "/drop-me/deep", exist_ok=True)
open(home + "/drop-me/deep/x", "w").write("x")
if not os.path.lexists(home + "/out"):
    os.symlink(outside, home + "/out")
if not os.path.lexists(home + "/fifo"):
    os.mkfifo(home + "/fifo")
try:
    if not os.path.lexists(home + "/sock"):
        socket.socket(socket.AF_UNIX).bind(home + "/sock")
    out["socket"] = True
except OSError as error:
    out["socket"] = error.errno
open(ws + "/w.txt", "w").write("w")
def link(a, b):
    try:
        os.link(a, b)
        return 0
    except OSError as error:
        return error.errno
out["link_state_to_workspace"] = link(home + "/kept-k66.txt", ws + "/alias")
out["link_workspace_to_state"] = link(ws + "/w.txt", home + "/alias")
print(json.dumps(out))
"#;

/// A later run's child: what the state holds.
const READER: &str = r#"
import json, os
home = os.environ["KEEP_HOME"]
out = {"saw": sorted(os.listdir(home))}
try:
    out["kept"] = open(home + "/kept-k66.txt").read()
except OSError as error:
    out["kept"] = error.errno
print(json.dumps(out))
"#;

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

#[test]
fn k66_k69_a_state_is_private_to_its_workspace_and_chains_its_releases() {
    if !common::live() || !common::python() {
        return;
    }
    let keeper = Keeper::new("tool", "");
    let a = keeper.workspace("repo-a");
    let outside = keeper.root.path().join("outside");
    private_dir(&outside);
    fixture_file(&outside.join("precious"), b"precious");

    // Run 1: a new state.
    let before = keeper.attempts();
    let run = keeper
        .jail(&a)
        .target(python(
            WRITER,
            &[
                &a.clone().into_os_string(),
                &outside.join("precious").into_os_string(),
                &OsString::from("one"),
            ],
        ))
        .run()
        .unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let first = keeper.new_attempt(&before);
    let written = out(&run);
    assert_eq!(
        written["saw"],
        serde_json::json!([]),
        "a new state is empty"
    );
    // EXDEV both ways: two bind mounts, so neither side aliases the other.
    assert_eq!(written["link_state_to_workspace"], libc::EXDEV, "{written}");
    assert_eq!(written["link_workspace_to_state"], libc::EXDEV, "{written}");
    let receipt1 = receipt(&first);
    assert_eq!(receipt1["phase"], "settled");
    assert_eq!(receipt1["state_cleanup"], "released", "{receipt1:#}");
    let state1 = &receipt1["vendor_state"];
    assert_eq!(state1["kind"], "persistent", "{receipt1:#}");
    assert_eq!(state1["generation_start"], 0);
    assert_eq!(state1["generation_end"], 1);
    assert_eq!(state1["inherited_from"], Value::Null);
    assert_eq!(state1["matches_release"], Value::Null);
    assert_eq!(state1["matches_release_reason"], "new_state");
    assert_eq!(state1["discarded"], 2, "{state1}");
    assert_eq!(state1["secret_scan"], "clean");
    assert_eq!(
        state_line(&first).as_deref(),
        Some("state: kept, generation 1 · new for this workspace")
    );

    // On the host: every level private and the operator's, the discards gone
    // as links, the link out of the state never followed.
    let key = keeper.key_dir(&a);
    let uid = std::fs::metadata(keeper.data()).unwrap().uid();
    for (path, expected) in [
        (keeper.data().join("state"), 0o700),
        (keeper.data().join("state").join(LAUNCH), 0o700),
        (key.clone(), 0o700),
        (key.join("vendor"), 0o700),
        (key.join("state.json"), 0o600),
        (key.join("lease"), 0o600),
    ] {
        assert_eq!(mode(&path), expected, "{}", path.display());
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().uid(),
            uid,
            "{}",
            path.display()
        );
    }
    let vendor = keeper.vendor(&a);
    assert!(!vendor.join(".login.json").exists());
    assert!(!vendor.join("drop-me").exists());
    assert!(
        std::fs::symlink_metadata(vendor.join("out"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read(outside.join("precious")).unwrap(),
        b"precious"
    );
    let record = keeper.record(&a);
    assert_eq!(record["generation"], 1, "{record:#}");
    assert_eq!(record["holder"]["released"], true, "{record:#}");

    // Run 2: the chain, unchanged.
    let before = keeper.attempts();
    let run = keeper.jail(&a).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let second = keeper.new_attempt(&before);
    assert_eq!(out(&run)["kept"], "one");
    let state2 = receipt(&second)["vendor_state"].clone();
    assert_eq!(state2["generation_start"], 1, "{state2}");
    assert_eq!(state2["generation_end"], 2, "{state2}");
    assert_eq!(state2["inherited_from"], attempt_id(&first), "{state2}");
    assert_eq!(state2["matches_release"], true, "{state2}");
    assert_eq!(
        state_line(&second),
        Some(format!(
            "state: kept, generation 2 · started from what {} released, unchanged",
            attempt_id(&first)
        ))
    );

    // The operator edits the state between runs: run 3 says so.
    std::fs::write(vendor.join("kept-k66.txt"), b"edited").unwrap();
    let before = keeper.attempts();
    let run = keeper.jail(&a).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let third = keeper.new_attempt(&before);
    assert_eq!(out(&run)["kept"], "edited");
    let state3 = receipt(&third)["vendor_state"].clone();
    assert_eq!(state3["matches_release"], false, "{state3}");
    assert_eq!(state3["inherited_from"], attempt_id(&second), "{state3}");
    assert_eq!(
        state_line(&third),
        Some(format!(
            "state: kept, generation 3 · CHANGED outside the jail since {} released it",
            attempt_id(&second)
        ))
    );

    // Another workspace: its own state, which never sees this one.
    let b = keeper.workspace("repo-b");
    let before = keeper.attempts();
    let run = keeper.jail(&b).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let other = keeper.new_attempt(&before);
    assert_eq!(out(&run)["saw"], serde_json::json!([]));
    assert_eq!(out(&run)["kept"], libc::ENOENT);
    assert_ne!(keeper.key_dir(&b), keeper.key_dir(&a));
    assert_eq!(
        receipt(&other)["vendor_state"]["matches_release_reason"],
        "new_state"
    );

    // K69: no receipt or journal names anything below the state or carries
    // its private digest.
    let digest = keeper.record(&a)["last_release"]["digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let hex = digest.trim_start_matches("sha256:");
    for attempt in keeper.attempts() {
        for file in ["jail.json", "trace.ndjson"] {
            let bytes = std::fs::read(attempt.join(file)).unwrap_or_default();
            for needle in ["kept-k66.txt", "precious", "drop-me", ".login.json", hex] {
                assert!(
                    !contains(&bytes, needle.as_bytes()),
                    "{} {file} names {needle}",
                    attempt.display()
                );
            }
        }
    }

    // `state rm` removes the links as links, and the state with them.
    let removed = keeper.verb(&["state", "rm", LAUNCH, "--workspace", a.to_str().unwrap()]);
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(!key.exists());
    assert_eq!(
        std::fs::read(outside.join("precious")).unwrap(),
        b"precious"
    );
}

// ===========================================================================
// K67: the lease and the fallback
// ===========================================================================

/// A holder's child: writes into the state, lists its descriptors, says it
/// is ready, then waits for `go` in the workspace.
const HOLDER: &str = r#"
import json, os, sys, time
home = os.environ["KEEP_HOME"]; ws = sys.argv[1]
open(home + "/held.txt", "w").write("held")
fds = {}
for fd in os.listdir("/proc/self/fd"):
    try:
        fds[fd] = os.readlink("/proc/self/fd/" + fd)
    except OSError:
        pass
print(json.dumps({"fds": fds}), flush=True)
open(ws + "/ready", "w").write("")
deadline = time.time() + 120
while not os.path.exists(ws + "/go") and time.time() < deadline:
    time.sleep(0.05)
"#;

/// A fallback's child: what it sees, and a file it leaves.
const PEEK: &str = r#"
import json, os
home = os.environ["KEEP_HOME"]
print(json.dumps({"saw": sorted(os.listdir(home))}))
open(home + "/throwaway.txt", "w").write("x")
"#;

fn wait_ready(workspace: &Path) {
    common::eventually(
        "the holder's child is ready",
        Duration::from_secs(60),
        || workspace.join("ready").exists(),
    );
    std::fs::remove_file(workspace.join("ready")).unwrap();
}

#[test]
fn k67_a_held_state_falls_back_visibly_or_refuses_and_an_unreleased_one_waits_for_gc() {
    if !common::live() || !common::python() {
        return;
    }
    let keeper = Keeper::new("tool", "");
    let ws = keeper.workspace("repo");
    let peek = python(PEEK, &[]);

    // The holder.
    let before = keeper.attempts();
    let holder = keeper
        .jail(&ws)
        .target(python(HOLDER, &[&ws.clone().into_os_string()]))
        .timeout(Duration::from_secs(180))
        .spawn()
        .unwrap();
    wait_ready(&ws);
    let held_by = attempt_id(&keeper.new_attempt(&before));

    // Standard error not a terminal: the fallback could not be shown, so the
    // attempt refuses before exec, naming the holder.
    let before = keeper.attempts();
    let busy = keeper.jail(&ws).target(peek.clone()).run().unwrap();
    assert_eq!(busy.code(), Some(125), "{}", busy.stderr_text());
    assert!(
        busy.stderr_text().contains("state_busy"),
        "{}",
        busy.stderr_text()
    );
    assert!(
        busy.stderr_text().contains(&held_by),
        "{}",
        busy.stderr_text()
    );
    assert!(busy.stdout_text().is_empty(), "the target never ran");
    let refused = receipt(&keeper.new_attempt(&before));
    assert_eq!(refused["phase"], "refused", "{refused:#}");

    // Standard error a terminal: throwaway state, said before exec, also
    // under --quiet.
    for quiet in [false, true] {
        let before = keeper.attempts();
        let flags: &[&str] = if quiet { &["--quiet"] } else { &[] };
        let (code, text) = run_with_terminal_stderr(&keeper, &run_words(&ws, flags, &peek));
        assert_eq!(code, Some(0), "{text}");
        assert!(
            text.contains(&format!(
                "ukai-jail: state: {LAUNCH} for this workspace is held by {held_by} · this \
                 session uses throwaway state and will not be kept"
            )),
            "quiet {quiet}: {text}"
        );
        let fallback = keeper.new_attempt(&before);
        let receipt = receipt(&fallback);
        assert_eq!(receipt["state_cleanup"], "complete", "{receipt:#}");
        assert_eq!(
            receipt["vendor_state"],
            serde_json::json!({
                "kind": "attempt_fallback",
                "state_id": keeper.record(&ws)["state_id"],
                "reason": "held",
                "held_by": held_by,
            }),
            "{receipt:#}"
        );
        assert_eq!(
            state_line(&fallback),
            Some(format!(
                "state: NOT kept · this session used throwaway state because {held_by} held \
                 the persistent state for this workspace"
            ))
        );
        assert!(
            !fallback.join("vendor-state").exists(),
            "removed at settlement"
        );
    }

    // The holder ends: its release is the only generation, and nothing the
    // fallbacks wrote is in the state.
    std::fs::write(ws.join("go"), b"").unwrap();
    let run = holder.wait().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    std::fs::remove_file(ws.join("go")).unwrap();
    let record = keeper.record(&ws);
    assert_eq!(record["generation"], 1, "{record:#}");
    assert_eq!(record["holder"]["released"], true);
    assert!(keeper.vendor(&ws).join("held.txt").exists());
    assert!(!keeper.vendor(&ws).join("throwaway.txt").exists());
    // X06: the lease, the record and the key directory never reach the child.
    let fds = out(&run)["fds"].clone();
    let key = keeper.key_dir(&ws);
    for (fd, target) in fds.as_object().unwrap() {
        let target = target.as_str().unwrap();
        assert!(
            !target.contains("lease")
                && !target.contains("state.json")
                && !target.contains(key.file_name().unwrap().to_str().unwrap()),
            "descriptor {fd} reached the child: {target}"
        );
    }

    // A supervisor killed mid-run never releases: the next attempt falls
    // back naming it and `gc`.
    let before = keeper.attempts();
    let mut holder = keeper
        .jail(&ws)
        .target(python(HOLDER, &[&ws.clone().into_os_string()]))
        .timeout(Duration::from_secs(180))
        .spawn()
        .unwrap();
    wait_ready(&ws);
    let killed = attempt_id(&keeper.new_attempt(&before));
    holder.kill().unwrap();
    let _ = holder.wait();
    let record = keeper.record(&ws);
    assert_eq!(record["holder"]["attempt"], killed, "{record:#}");
    assert_eq!(record["holder"]["released"], false, "{record:#}");
    let before = keeper.attempts();
    let (code, text) = run_with_terminal_stderr(&keeper, &run_words(&ws, &[], &peek));
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains(&format!(
            "ukai-jail: state: {LAUNCH} for this workspace was not released by {killed} (run \
             ukai-jail gc) · this session uses throwaway state and will not be kept"
        )),
        "{text}"
    );
    let fallback = receipt(&keeper.new_attempt(&before));
    assert_eq!(fallback["vendor_state"]["reason"], "unreleased");
    assert_eq!(fallback["vendor_state"]["held_by"], killed.as_str());

    // `gc` finishes the release, unscanned; the next attempt acquires.
    let gc = keeper.verb(&["gc"]);
    assert!(
        gc.status.success(),
        "{}{}",
        String::from_utf8_lossy(&gc.stdout),
        String::from_utf8_lossy(&gc.stderr)
    );
    let record = keeper.record(&ws);
    assert_eq!(record["holder"]["released"], true, "{record:#}");
    assert_eq!(record["generation"], 2, "{record:#}");
    let before = keeper.attempts();
    let run = keeper.jail(&ws).target(peek).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert_eq!(
        out(&run)["saw"],
        serde_json::json!(["held.txt"]),
        "the released state, with nothing a fallback wrote"
    );
    let acquired = receipt(&keeper.new_attempt(&before))["vendor_state"].clone();
    assert_eq!(acquired["kind"], "persistent", "{acquired}");
    assert_eq!(acquired["generation_start"], 2, "{acquired}");
    assert_eq!(acquired["inherited_from"], killed.as_str(), "{acquired}");
}

// ===========================================================================
// K70: a reflected vault value quarantines the state
// ===========================================================================

/// A loopback origin that answers every request with the `Authorization`
/// value it received: the server that reflects the secret.
struct Reflector {
    addr: SocketAddr,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Reflector {
    fn start() -> Reflector {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let thread = {
            let stopping = Arc::clone(&stopping);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(stream) = stream {
                        reflect(stream);
                    }
                }
            })
        };
        Reflector {
            addr,
            stopping,
            thread: Some(thread),
        }
    }
}

impl Drop for Reflector {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stopping.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr);
            let _ = thread.join();
        }
    }
}

fn reflect(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while !contains(&head, b"\r\n\r\n") && head.len() < 64 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let echo = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_default();
    let body = format!("{{\"echo\":\"{echo}\"}}\n");
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
}

/// Sends the placeholder to the origin and keeps the answer in the state,
/// as an agent keeps a transcript.
const TRANSCRIBER: &str = r#"
import os, sys, urllib.request
home = os.environ["KEEP_HOME"]
request = urllib.request.Request(sys.argv[1] + "/turn",
    headers={"Authorization": os.environ["KEEP_TOKEN"]})
with urllib.request.urlopen(request, timeout=20) as response:
    body = response.read()
os.makedirs(home + "/projects/x", exist_ok=True)
open(home + "/projects/x/session.jsonl", "wb").write(body)
print('{"kept": true}')
"#;

/// A vault credential `token`, sent to `origin`, under `jail = "agent"`.
fn vault_profile(source: &Path, origin: &str, destination: &str) -> String {
    let quoted = serde_json::to_string(source.to_str().unwrap()).unwrap();
    format!(
        "\n[credentials.token]\nmode = \"vault\"\nsource = {quoted}\nenv = \"KEEP_TOKEN\"\n\
         hosts = [\"{origin}\"]\nallow_plaintext = true\n\n[network]\nallow = [\"{destination}\"]\n"
    )
}

#[test]
fn k70_a_reflected_vault_value_quarantines_the_state() {
    if !common::live() || !common::python() {
        return;
    }
    let secret = "k70-vault-value-0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    let origin = Reflector::start();
    let url = format!("http://{}", origin.addr);
    let probe = Keeper::new("agent", "");
    let source = probe.root.path().join("vault-token");
    fixture_file(&source, secret.as_bytes());
    let keeper = Keeper::new(
        "agent",
        &vault_profile(&source, &url, &origin.addr.to_string()),
    );
    let ws = keeper.workspace("repo");

    let before = keeper.attempts();
    let run = keeper
        .jail(&ws)
        .target(python(TRANSCRIBER, &[&OsString::from(&url)]))
        .run()
        .unwrap();
    let attempt = keeper.new_attempt(&before);
    assert_eq!(out(&run)["kept"], true, "{}", run.stderr_text());
    assert_eq!(run.code(), Some(1), "{}", run.stderr_text());
    let found = receipt(&attempt);
    assert_eq!(found["vendor_state"]["secret_scan"], "found", "{found:#}");
    assert!(
        found["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error["code"] == "credential_persisted"),
        "{found:#}"
    );
    assert_eq!(
        state_line(&attempt).as_deref(),
        Some("state: quarantined: a vault credential's value was found in it")
    );
    let record = keeper.record(&ws);
    assert_eq!(record["quarantine"]["reason"], "credential_persisted");
    // The value is nowhere the jail writes or prints, and the file is named
    // only in the private record.
    assert!(!run.stderr_text().contains(secret));
    for file in [
        "jail.json",
        "trace.ndjson",
        "jail-state.json",
        "policy.json",
    ] {
        let bytes = std::fs::read(attempt.join(file)).unwrap_or_default();
        assert!(!contains(&bytes, secret.as_bytes()), "{file}");
        assert!(!contains(&bytes, b"session.jsonl"), "{file}");
    }
    assert!(!contains(
        &std::fs::read(keeper.key_dir(&ws).join("state.json")).unwrap(),
        secret.as_bytes()
    ));

    // The next acquisition refuses until the operator removes the state.
    let run = keeper.jail(&ws).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(
        run.stderr_text().contains("state_quarantined"),
        "{}",
        run.stderr_text()
    );
    let shown = keeper.verb(&["state", "show", LAUNCH, "--workspace", ws.to_str().unwrap()]);
    let shown = String::from_utf8_lossy(&shown.stdout).into_owned();
    assert!(shown.contains("projects/x/session.jsonl"), "{shown}");
    assert!(!shown.contains(secret), "{shown}");
    let removed = keeper.verb(&["state", "rm", LAUNCH, "--workspace", ws.to_str().unwrap()]);
    assert!(removed.status.success());
    let before = keeper.attempts();
    let run = keeper.jail(&ws).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    assert_eq!(
        receipt(&keeper.new_attempt(&before))["vendor_state"]["matches_release_reason"],
        "new_state"
    );
}

// ===========================================================================
// K73: what acquisition and release cost on this host
// ===========================================================================

/// Fills `vendor` with `files` files of `size` bytes each, spread over
/// directories of at most 255 entries.
fn fill(vendor: &Path, files: usize, size: usize) {
    let block: Vec<u8> = (0..size).map(|i| (i * 7 + 13) as u8).collect();
    for i in 0..files {
        let dir = vendor.join(format!("d{:03}", i / 255));
        if i % 255 == 0 {
            std::fs::create_dir_all(&dir).unwrap();
        }
        std::fs::write(dir.join(format!("f{:03}", i % 255)), &block).unwrap();
    }
}

fn empty(vendor: &Path) {
    for entry in std::fs::read_dir(vendor).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            std::fs::remove_dir_all(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
    }
}

/// K73: one run per state shape, timed from the jail's start to its exit,
/// against an empty state. Each run pays two passes, the acquisition's
/// digest and the release's digest and scan, so a pass costs half the
/// difference. Prints one JSON line per shape (`--nocapture` records them).
#[test]
fn k73_acquisition_and_release_cost_on_this_host() {
    if !common::live() {
        return;
    }
    let probe = Keeper::new("tool", "");
    let source = probe.root.path().join("vault-token");
    fixture_file(&source, b"k73-vault-value-never-sent-0123456789abcdef");
    // The credential is never used: it is loaded, so the release scans.
    let keeper = Keeper::new(
        "agent",
        &vault_profile(&source, "https://k73.invalid", "k73.invalid"),
    );
    let ws = keeper.workspace("repo");
    let timed = |label: &str| {
        let before = keeper.attempts();
        let started = Instant::now();
        let run = keeper
            .jail(&ws)
            .target(["/usr/bin/true"])
            .timeout(Duration::from_secs(300))
            .run()
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(run.code(), Some(0), "{label}: {}", run.stderr_text());
        let receipt = receipt(&keeper.new_attempt(&before));
        let state = receipt["vendor_state"].clone();
        println!(
            "{}",
            serde_json::json!({
                "row": "K73", "shape": label, "ms": elapsed.as_millis(),
                "matches_release": state["matches_release"],
                "reason": state["matches_release_reason"],
                "secret_scan": state["secret_scan"],
            })
        );
        (elapsed, state)
    };
    timed("first, new");
    let (baseline, _) = timed("empty");
    let vendor = keeper.vendor(&ws);
    const MIB: usize = 1024 * 1024;
    for (label, files, size) in [
        ("1 MiB", 16, MIB / 16),
        ("64 MiB", 64, MIB),
        ("256 MiB", 256, MIB),
        ("65,536 entries", 65_536 - 65_536 / 256, 16),
    ] {
        empty(&vendor);
        fill(&vendor, files, size);
        // The operator's writes: the first run after them reports a change,
        // the second one runs on a state unchanged since its release.
        let (_, changed) = timed(label);
        assert_eq!(changed["matches_release"], false, "{label}: {changed}");
        let (elapsed, state) = timed(label);
        assert_eq!(state["matches_release"], true, "{label}: {state}");
        assert_eq!(state["secret_scan"], "clean", "{label}: {state}");
        // The preparation budget is 30 s; the whole run stays under it.
        assert!(
            elapsed < Duration::from_secs(30),
            "{label}: {elapsed:?} against {baseline:?}"
        );
    }
    // Past either bound the digest is unavailable and nothing claims a match.
    for (label, files, size) in [
        ("past 256 MiB", 257, MIB),
        ("past 65,536 entries", 65_536, 16),
    ] {
        empty(&vendor);
        fill(&vendor, files, size);
        timed(label);
        let (_, state) = timed(label);
        assert_eq!(state["matches_release"], Value::Null, "{label}: {state}");
        assert_eq!(
            state["matches_release_reason"], "state_too_large",
            "{label}: {state}"
        );
        assert_eq!(state["secret_scan"], "not_scanned", "{label}: {state}");
    }
}

// ===========================================================================
// K74: a workspace made again at the same path
// ===========================================================================

/// The workspace lives on the home directory's filesystem (ext4 on the
/// reference host), where an inode number freed by a removal is reused at
/// once; `/tmp` may be a tmpfs, which does not reuse it.
#[test]
fn k74_a_workspace_made_again_refuses_unless_its_inode_was_reused() {
    if !common::live() || !common::python() {
        return;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        harness::skip_or_fail("HOME is unset");
        return;
    };
    let keeper = Keeper::new("tool", "");
    let parent = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(&home)
        .unwrap();
    let ws = parent.path().join("repo");
    private_dir(&ws);
    let inode = |path: &Path| std::fs::metadata(path).unwrap().ino();
    let run = keeper.jail(&ws).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());

    // Made again with a different inode: refused, naming `state rm`.
    let first = inode(&ws);
    std::fs::remove_dir(&ws).unwrap();
    private_dir(&parent.path().join("filler"));
    private_dir(&ws);
    assert_ne!(inode(&ws), first, "the filler took the old inode");
    let run = keeper.jail(&ws).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    assert!(
        run.stderr_text().contains("state_workspace_changed"),
        "{}",
        run.stderr_text()
    );
    assert!(
        run.stderr_text().contains("ukai-jail state rm"),
        "{}",
        run.stderr_text()
    );
    assert!(run.stdout_text().is_empty(), "the target never ran");

    // Made again at once: the named limit. When the filesystem reused the
    // inode, the check cannot tell and the run acquires; otherwise it
    // refuses. Either way the result is printed for the record.
    let removed = keeper.verb(&["state", "rm", LAUNCH, "--workspace", ws.to_str().unwrap()]);
    assert!(removed.status.success());
    let run = keeper.jail(&ws).target(python(READER, &[])).run().unwrap();
    assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    let before = inode(&ws);
    std::fs::remove_dir(&ws).unwrap();
    private_dir(&ws);
    let reused = inode(&ws) == before;
    let run = keeper.jail(&ws).target(python(READER, &[])).run().unwrap();
    println!(
        "{}",
        serde_json::json!({"row": "K74", "inode_reused": reused, "code": run.code()})
    );
    if reused {
        assert_eq!(run.code(), Some(0), "{}", run.stderr_text());
    } else {
        assert_eq!(run.code(), Some(125), "{}", run.stderr_text());
    }
}
