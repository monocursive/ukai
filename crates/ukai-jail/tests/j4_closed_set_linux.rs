#![cfg(target_os = "linux")]
//! J4 slice O, end to end: the observer's closed set and its attribution
//! (jail-v1 §15 O01, O02, O04, O06 and the §16 "closed set" exit).
//!
//! Every test drives the real `ukai-jail run` over the conformance fixture
//! and compares what the fixture says the kernel returned with the audit
//! events the jail wrote to its trace and the counts its receipt claims. The
//! fixture performs one named raw syscall per operation, so the comparison is
//! result by result: operation, `fields.syscall`, raw return, errno name and
//! `attempted_operation`.
//!
//! Which rows apply where. `tool`, `build` and `none` observe all 22 x86_64
//! rows through the ptrace observer; `connect` is an AF_INET connect there,
//! because `tool` and `build` refuse AF_UNIX sockets outright (§9.2) and a
//! connect needs a socket first. `agent` observes the same 21 filesystem and
//! exec rows through the ptrace observer and every `connect` through the
//! unix-peer mediator (`fields.observation = seccomp_user_notification`,
//! §11.4). No baseline refuses any of the variants used here, so none of
//! them is compared as a refusal; the variants a baseline does refuse
//! (`clone(CLONE_UNTRACED)`, S4) have their own tests below.
//!
//! Every process these tests start is their own; nothing on the host is
//! changed. Live: `UKAI_CONFORMANCE=1` on the reference host.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use serde_json::Value;
use ukai_fixture::harness::{self, Jail, Run};
use ukai_jail::policy::ProfileName;

mod common;

// ---------------------------------------------------------------------------
// Schemas, cases, runs
// ---------------------------------------------------------------------------

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/specs/jail-v1")
        .canonicalize()
        .expect("the checked-in specification directory exists")
}

/// A run of `ukai-jail run --profile <profile>` over a private workspace
/// holding the fixture at `<workspace>/ukai-fixture`, trace and control on.
struct Case {
    jail: Jail,
    workspace: PathBuf,
    fixture: PathBuf,
    /// `build` exposes no workspace (§3.1: a package build reads declared
    /// inputs and writes scratch), so the fixture and its script are
    /// declared read-only inputs and the operations run under `/tmp`.
    build: bool,
}

fn case(profile: ProfileName, evidence: &str) -> Case {
    let jail = Jail::new().expect("a private harness");
    let workspace = jail.root().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = workspace.join("ukai-fixture");
    std::fs::copy(harness::fixture_path(), &fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut jail = jail
        .arg("run")
        .arg("--profile")
        .arg(profile.as_str())
        .arg("--evidence")
        .arg(evidence)
        .arg("--workspace")
        .arg(&workspace);
    if profile == ProfileName::Build {
        // `build` requires an explicit memory ceiling (§6.4).
        jail = jail.args(["--limit", "mem=512MiB"]);
    }
    Case {
        jail: jail.trace().control(),
        workspace,
        fixture,
        build: profile == ProfileName::Build,
    }
}

impl Case {
    fn ws(&self, name: &str) -> String {
        self.workspace.join(name).to_str().unwrap().to_owned()
    }

    fn fixture_s(&self) -> String {
        self.fixture.to_str().unwrap().to_owned()
    }

    /// Run a fixture `script` of `steps` written into the workspace.
    fn script(self, name: &str, steps: &Value) -> Run {
        let path = self.workspace.join(format!("{name}.json"));
        std::fs::write(&path, serde_json::to_vec(steps).unwrap()).unwrap();
        let argv = vec![
            self.fixture.clone().into_os_string(),
            OsString::from("script"),
            path.clone().into_os_string(),
        ];
        self.run_with_inputs(argv, &[path])
    }

    /// Run `argv`; under `build` the fixture and `inputs` are declared.
    fn run_with_inputs(self, argv: Vec<OsString>, inputs: &[PathBuf]) -> Run {
        let mut jail = self.jail;
        if self.build {
            jail = jail.arg("--ro").arg(&self.fixture);
            for input in inputs {
                jail = jail.arg("--ro").arg(input);
            }
        }
        jail.target(argv).run().expect("the jail runs")
    }

    /// The directory the operations run in, and the roots §11.3 reports
    /// paths below it against: `(base, workspace root, scratch root)`.
    fn base(&self) -> String {
        if self.build {
            "/tmp/o01".to_owned()
        } else {
            self.workspace.to_str().unwrap().to_owned()
        }
    }
}

/// The receipt's own name for the target: pid and `linux_boot_start` ticks.
fn target_identity(receipt: &Value) -> (i64, u64) {
    let process = &receipt["process"];
    assert_eq!(
        process["identity"]["kind"], "linux_boot_start",
        "{process:#}"
    );
    let ticks = &process["identity"]["value"]["start_time_ticks"];
    let ticks = ticks
        .as_u64()
        .or_else(|| ticks.as_str().and_then(|t| t.parse().ok()))
        .unwrap_or_else(|| panic!("no start_time_ticks: {process:#}"));
    (process["pid"].as_i64().unwrap(), ticks)
}

/// The audit source's results, in trace order.
fn audit_results(run: &Run) -> Vec<&Value> {
    run.trace_events()
        .iter()
        .filter(|event| event["source"] == "audit" && event["stage"] == "result")
        .collect()
}

fn gap_reasons(receipt: &Value) -> Vec<String> {
    receipt["coverage"]
        .as_object()
        .into_iter()
        .flat_map(|classes| classes.values())
        .flat_map(|class| class["gaps"].as_array().cloned().unwrap_or_default())
        .filter_map(|gap| gap["reason"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn dump(run: &Run) -> String {
    let mut out = String::new();
    out.push_str("fixture lines:\n");
    for line in run.fixture_lines() {
        out.push_str(&format!("  {line}\n"));
    }
    out.push_str("audit results:\n");
    for event in audit_results(run) {
        out.push_str(&format!(
            "  {} {} ret={} errno={} fields={}\n",
            event["operation"],
            event["outcome"]["completion"],
            event["outcome"]["return_value"],
            event["outcome"]["errno"],
            event["fields"]
        ));
    }
    out.push_str(&format!("stderr: {}\n", run.stderr_text()));
    out
}

// ---------------------------------------------------------------------------
// The closed set, as the fixture reports it
// ---------------------------------------------------------------------------

/// The 22 x86_64 rows of `linux-closed-v1` (§11.2).
const ROWS: &[&str] = &[
    "execve",
    "execveat",
    #[cfg(not(target_arch = "aarch64"))]
    "open",
    "openat",
    "openat2",
    #[cfg(not(target_arch = "aarch64"))]
    "creat",
    "truncate",
    #[cfg(not(target_arch = "aarch64"))]
    "rename",
    "renameat",
    "renameat2",
    #[cfg(not(target_arch = "aarch64"))]
    "unlink",
    "unlinkat",
    #[cfg(not(target_arch = "aarch64"))]
    "rmdir",
    #[cfg(not(target_arch = "aarch64"))]
    "mkdir",
    "mkdirat",
    #[cfg(not(target_arch = "aarch64"))]
    "mknod",
    "mknodat",
    #[cfg(not(target_arch = "aarch64"))]
    "link",
    "linkat",
    #[cfg(not(target_arch = "aarch64"))]
    "symlink",
    "symlinkat",
    "connect",
];

const O_ACCMODE: i64 = 0o3;
const O_CREAT: i64 = 0o100;
const O_TRUNC: i64 = 0o1000;

/// The §11.2 operation a fixture line's call is reported as when it
/// succeeds, or `None` when the call is outside the set (a read-only open).
fn base_operation(line: &Value) -> Option<&'static str> {
    let op = line["op"].as_str()?;
    Some(match op {
        "execve" | "execveat" => "proc.exec",
        "creat" => "fs.create",
        "open" | "openat" | "openat2" => {
            let flags = line["args"]["flags"].as_i64()?;
            if flags & O_CREAT != 0 {
                "fs.create"
            } else if flags & O_ACCMODE == 0 && flags & O_TRUNC == 0 {
                return None;
            } else {
                "fs.write"
            }
        }
        "truncate" => "fs.write",
        "rename" | "renameat" | "renameat2" => "fs.rename",
        "unlink" | "unlinkat" | "rmdir" => "fs.unlink",
        "mkdir" | "mkdirat" | "mknod" | "mknodat" | "link" | "linkat" | "symlink" | "symlinkat" => {
            "fs.create"
        }
        "connect" => "net.connect",
        _ => return None,
    })
}

/// The class an audit operation is counted under (§11.4).
fn class_of(operation: &str) -> &'static str {
    match operation {
        "proc.exec" | "proc.exit" => "exec",
        "fs.deny" => "fs.deny",
        "net.connect" => "net",
        _ => "fs.write",
    }
}

/// Which fixture argument each event path stands for.
fn path_keys(op: &str) -> (Option<&'static str>, Option<&'static str>) {
    match op {
        "rename" | "renameat" | "renameat2" | "link" | "linkat" => (Some("from"), Some("to")),
        "symlink" | "symlinkat" => (Some("linkpath"), Some("target")),
        "connect" => (None, None),
        _ => (Some("path"), None),
    }
}

/// What §11.3 lets an event say about a pathname the fixture passed with
/// `AT_FDCWD`: relative to the workspace or scratch, using the real entry-time
/// cwd for these fixtures' relative arguments; a digest elsewhere. Not a
/// symlink's target, which is no pathname ([`expected_arg`]).
fn expected_path(arg: &str, roots: &Roots) -> Value {
    for (root, kind) in [
        (Some(roots.workspace.as_str()), "workspace_relative"),
        (roots.scratch.as_deref(), "scratch_relative"),
    ] {
        if let Some(root) = root
            && let Some(rest) = arg.strip_prefix(root)
            && (rest.is_empty() || rest.starts_with('/'))
        {
            return serde_json::json!({
                "kind": kind,
                "value": rest.trim_start_matches('/'),
            });
        }
    }
    if !arg.starts_with('/') {
        // These fixed fixtures start in the workspace; the tracer snapshots
        // the actual cwd at entry instead of reusing an earlier chdir event.
        return serde_json::json!({"kind": "workspace_relative", "value": arg});
    }
    serde_json::json!({"kind": "digest"})
}

/// The two roots a contained attempt reports paths against.
struct Roots {
    workspace: String,
    /// `/tmp` inside a contained profile; `none` uses only the workspace here.
    scratch: Option<String>,
}

/// What §11.3 lets an event say about the fixture argument `arg` that `op`
/// passed in `field`: a symlink's target (`path2`) is a string the call
/// stores, resolved against nothing, so it is the digest of exactly its
/// bytes whether it is relative or absolute, never a path. Every other
/// argument is a path ([`expected_path`]).
fn expected_arg(op: &str, field: &str, arg: &str, roots: &Roots) -> Value {
    if field == "path2" && matches!(op, "symlink" | "symlinkat") {
        return serde_json::json!({
            "kind": "digest",
            "digest": ukai_jail::canonical::sha256_prefixed(arg.as_bytes()),
            "reason": "symlink_target",
        });
    }
    expected_path(arg, roots)
}

/// `{"kind": "digest"}` alone stands for any digest; anything else is
/// compared exactly.
fn path_matches(event_path: &Value, expected: &Value) -> bool {
    if *expected == serde_json::json!({"kind": "digest"}) {
        return event_path["kind"] == "digest";
    }
    event_path == expected
}

/// Whether `event` is the one audit result `line` stands for.
fn matches(line: &Value, event: &Value, roots: &Roots) -> bool {
    let Some(base) = base_operation(line) else {
        return false;
    };
    let op = line["op"].as_str().unwrap_or_default();
    let errno = line["errno"].as_str();
    let denied = (matches!(errno, Some("EACCES" | "EPERM"))
        || (base.starts_with("fs.") && matches!(errno, Some("EROFS" | "EBUSY"))))
        && event["fields"]["observation"] != "seccomp_user_notification";
    let operation = if denied { "fs.deny" } else { base };
    if event["operation"] != operation || event["fields"]["syscall"] != op {
        return false;
    }
    if denied && event["fields"]["attempted_operation"] != base {
        return false;
    }
    if !denied && event["fields"].get("attempted_operation").is_some() {
        return false;
    }
    let exec_success = base == "proc.exec" && errno.is_none();
    if exec_success {
        // A successful exec never returns to its caller: its evidence is the
        // confirmed transition, with no return value (§11.2).
        if event["outcome"]["completion"] != "exec_transition"
            || !event["outcome"]["return_value"].is_null()
        {
            return false;
        }
    } else if event["outcome"]["completion"] != "syscall_return"
        || event["outcome"]["return_value"].as_i64()
            != line["ret"].as_i64().map(|ret| {
                // The fixture reports -1 and the errno, as libc does; the event
                // carries the raw kernel return, -errno.
                if ret < 0 {
                    -i64::from(errno_value(errno.unwrap_or_default()))
                } else {
                    ret
                }
            })
        || event["outcome"]["errno"].as_str() != errno
    {
        return false;
    }
    let (first, second) = path_keys(op);
    for (key, field) in [(first, "path"), (second, "path2")] {
        if let Some(key) = key {
            let Some(arg) = line["args"][key].as_str() else {
                return false;
            };
            if !path_matches(
                &event["fields"][field],
                &expected_arg(op, field, arg, roots),
            ) {
                return false;
            }
        }
    }
    true
}

fn errno_value(name: &str) -> i32 {
    match name {
        "EPERM" => libc::EPERM,
        "ENOENT" => libc::ENOENT,
        "EACCES" => libc::EACCES,
        "EEXIST" => libc::EEXIST,
        "EXDEV" => libc::EXDEV,
        "ENOSYS" => libc::ENOSYS,
        "ECONNREFUSED" => libc::ECONNREFUSED,
        "ENETUNREACH" => libc::ENETUNREACH,
        "EROFS" => libc::EROFS,
        other => panic!("errno {other} is not in this test's table"),
    }
}

/// The O01 steps: every one of the 22 rows at least once, a success and a
/// failure where both are cheap, one denial per operation family that has
/// an easy one, a read-only open that must produce nothing, and two
/// successful execs whose children exit.
fn o01_steps(c: &Case) -> Value {
    let base = c.base();
    let w = |name: &str| format!("{base}/{name}");
    let fixture = c.fixture_s();
    let steps = serde_json::json!([
        ["mkdir", base.clone(), "--expect", "any"],
        [
            "open",
            w("denied.txt"),
            "--create",
            "--write",
            "--mode",
            "000"
        ],
        ["open", w("o-openat.txt"), "--create", "--write"],
        [
            "open",
            w("o-open.txt"),
            "--via",
            "open",
            "--create",
            "--write"
        ],
        ["open", w("o-creat.txt"), "--via", "creat"],
        [
            "open",
            w("o-openat2.txt"),
            "--via",
            "openat2",
            "--create",
            "--write"
        ],
        ["open", w("o-openat.txt"), "--write"],
        ["open", w("o-openat.txt"), "--via", "open", "--rdwr"],
        ["open", w("o-openat.txt")],
        ["open", w("denied.txt"), "--write", "--expect", "EACCES"],
        [
            "open",
            w("absent/x"),
            "--create",
            "--write",
            "--expect",
            "ENOENT"
        ],
        ["truncate", w("o-openat.txt"), "0"],
        ["truncate", w("absent/y"), "0", "--expect", "ENOENT"],
        ["mkdir", w("d-mkdir"), "--via", "mkdir"],
        ["mkdir", w("d-mkdirat"), "--via", "mkdirat"],
        [
            "mkdir",
            w("d-mkdir"),
            "--via",
            "mkdir",
            "--expect",
            "EEXIST"
        ],
        [
            "rename",
            w("o-open.txt"),
            w("r-rename.txt"),
            "--via",
            "rename"
        ],
        [
            "rename",
            w("r-rename.txt"),
            w("r-renameat.txt"),
            "--via",
            "renameat"
        ],
        [
            "rename",
            w("r-renameat.txt"),
            w("r-renameat2.txt"),
            "--via",
            "renameat2"
        ],
        [
            "rename",
            w("absent-a"),
            w("absent-b"),
            "--via",
            "renameat",
            "--expect",
            "ENOENT"
        ],
        [
            "link",
            w("r-renameat2.txt"),
            w("l-link.txt"),
            "--via",
            "link"
        ],
        [
            "link",
            w("r-renameat2.txt"),
            w("l-linkat.txt"),
            "--via",
            "linkat"
        ],
        ["symlink", "target", w("s-symlink"), "--via", "symlink"],
        [
            "symlink",
            w("target"),
            w("s-symlinkat"),
            "--via",
            "symlinkat"
        ],
        ["mknod", w("n-mknod"), "--via", "mknod"],
        ["mknod", w("n-mknodat"), "--via", "mknodat"],
        ["unlink", w("l-link.txt"), "--via", "unlink"],
        ["unlink", w("l-linkat.txt"), "--via", "unlinkat"],
        [
            "unlink",
            w("l-link.txt"),
            "--via",
            "unlink",
            "--expect",
            "ENOENT"
        ],
        ["rmdir", w("d-mkdir"), "--via", "rmdir"],
        ["rmdir", w("d-mkdirat"), "--via", "unlinkat"],
        ["connect", "127.0.0.1:9", "--udp"],
        ["connect", "127.0.0.1:1", "--expect", "ECONNREFUSED"],
        [
            "exec",
            "--via",
            "execve",
            "--expect",
            "ENOENT",
            "--",
            "/nonexistent-ukai-j4"
        ],
        [
            "exec",
            "--via",
            "execveat",
            "--expect",
            "ENOENT",
            "--",
            "/nonexistent-ukai-j4"
        ],
        [
            "exec",
            "--via",
            "execve",
            "--expect",
            "EACCES",
            "--",
            w("denied.txt")
        ],
        ["exec", "--via", "execve", "--", fixture, "exit", "0"],
        ["exec", "--via", "execveat", "--", fixture, "exit", "0"]
    ]);
    let mut steps = steps;
    // Preserve every operation and dependency in the matrix while using only
    // the variants this architecture has. The observer must name the actual
    // syscall, which the fixture and strace independently verify.
    for step in steps.as_array_mut().unwrap() {
        let args = step.as_array_mut().unwrap();
        if let Some(via) = args.iter().position(|arg| arg == "--via") {
            let asked = args[via + 1].as_str().unwrap().to_owned();
            let native = native_via(&asked);
            if native != asked {
                if asked == "creat" {
                    args.extend(["--create".into(), "--write".into(), "--trunc".into()]);
                }
                args[via + 1] = native.into();
            }
        }
    }
    steps
}

/// The spelling of a path call this architecture has. x86_64, where the
/// closed-set evidence was taken, keeps the legacy calls; Linux aarch64 has
/// only their `*at` forms, which resolve the same names against `AT_FDCWD`
/// (`creat` is `openat` with create, write and truncate). A test asks for,
/// and expects the observer to name, the call the kernel can actually see.
fn native_via(via: &str) -> &str {
    if ukai_fixture::raw::has_legacy_syscalls() {
        return via;
    }
    match via {
        "open" | "creat" => "openat",
        "mkdir" => "mkdirat",
        "rename" => "renameat",
        "link" => "linkat",
        "symlink" => "symlinkat",
        "mknod" => "mknodat",
        "unlink" | "rmdir" => "unlinkat",
        other => other,
    }
}

/// O01 for one profile: every fixture line of a closed-set call matches
/// exactly one audit result on operation, `fields.syscall`, raw return,
/// errno and `attempted_operation` (and on both path classifications); the
/// only audit results left over are the target's own exec and one exit per
/// process that execed; every class count equals the results in that class,
/// including a class with none; every `fs.write` names its action; no audit
/// outcome carries a byte count.
fn o01_matrix(profile: ProfileName) {
    if !common::profile_live(profile) {
        return;
    }
    let c = case(profile, "strict");
    let roots = Roots {
        workspace: c.workspace.to_str().unwrap().to_owned(),
        scratch: (profile != ProfileName::None).then(|| "/tmp".to_owned()),
    };
    let steps = o01_steps(&c);
    let run = c.script("o01", &steps);
    let receipt = common::settled(&run);
    let lines = run.fixture_lines();
    let events = audit_results(&run);
    let context = dump(&run);

    // Every row was exercised, by the fixture's own account.
    let exercised: BTreeSet<&str> = lines.iter().filter_map(|l| l["op"].as_str()).collect();
    for row in ROWS {
        assert!(
            exercised.contains(row),
            "{profile:?}: row {row} never ran\n{context}"
        );
    }
    // The script's own verdict: every expectation held.
    assert_eq!(
        run.code(),
        Some(0),
        "{profile:?}: the fixture exited non-zero\n{context}"
    );

    let mut used = vec![false; events.len()];
    // The target's own exec is not a fixture line: the launcher made it. It
    // looks exactly like the fixture's own `execve` of the same binary, so
    // it is set aside first, by the pid the receipt names the target with.
    let target = target_identity(&receipt).0;
    let own = events
        .iter()
        .position(|e| {
            e["operation"] == "proc.exec"
                && e["outcome"]["completion"] == "exec_transition"
                && e["fields"]["pid"].as_i64() == Some(target)
        })
        .unwrap_or_else(|| panic!("{profile:?}: the target's own exec is missing\n{context}"));
    used[own] = true;
    let mut matched_lines = 0usize;
    let mut excluded = 0usize;
    for line in &lines {
        let Some(op) = line["op"].as_str() else {
            continue;
        };
        if !ROWS.contains(&op) {
            continue;
        }
        if base_operation(line).is_none() {
            // A read-only open: outside the set, so no event at all.
            excluded += 1;
            continue;
        }
        let found: Vec<usize> = (0..events.len())
            .filter(|i| !used[*i] && matches(line, events[*i], &roots))
            .collect();
        let Some(first) = found.first() else {
            panic!("{profile:?}: no audit result for {line}\n{context}");
        };
        used[*first] = true;
        matched_lines += 1;
    }
    assert!(excluded >= 1, "{profile:?}: the read-only open was not run");

    // What is left is the exits of the processes that execed: the target and
    // the two children that ran `exit 0`.
    let leftover: Vec<&Value> = events
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|(event, _)| *event)
        .collect();
    let leftover_ops: Vec<&str> = leftover
        .iter()
        .map(|e| e["operation"].as_str().unwrap_or_default())
        .collect();
    let execs = leftover_ops.iter().filter(|op| **op == "proc.exec").count();
    let exits = leftover_ops.iter().filter(|op| **op == "proc.exit").count();
    assert_eq!(
        (execs, exits, leftover.len()),
        (0, 3, 3),
        "{profile:?}: audit results no fixture line accounts for: {leftover_ops:?}\n{context}"
    );
    for event in &leftover {
        assert_eq!(event["outcome"]["ok"], true, "{profile:?}: {event}");
    }
    assert!(
        leftover
            .iter()
            .any(|e| e["fields"]["pid"].as_i64() == Some(target)),
        "{profile:?}: the target's own exit is missing\n{context}"
    );

    // Class counts are the results per class, and every audit class is
    // active with a number.
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for event in &events {
        *counts
            .entry(class_of(event["operation"].as_str().unwrap_or_default()))
            .or_default() += 1;
    }
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "active", "{profile:?} {class}: {entry:#}");
        assert_eq!(
            entry["observed_count"].as_u64(),
            Some(counts.get(class).copied().unwrap_or(0)),
            "{profile:?} {class}: the count is not the number of results\n{context}"
        );
    }
    assert_eq!(gap_reasons(&receipt), Vec::<String>::new(), "{profile:?}");

    for event in &events {
        // No outcome asserts a byte count (O01).
        let outcome = event["outcome"].as_object().unwrap();
        assert!(
            !outcome.keys().any(|key| key.starts_with("bytes_")),
            "{profile:?}: {event}"
        );
        // A field named fs.write names its action (§11.2).
        if event["operation"] == "fs.write" {
            let action = event["fields"]["action"].as_str();
            assert!(
                matches!(action, Some("opened_for_mutation" | "truncated")),
                "{profile:?}: an fs.write without its action: {event}"
            );
        }
        // Only a mediated connect says it was one, and in `agent` every
        // connect result is one.
        let connect = event["fields"]["syscall"] == "connect";
        let mediated = event["fields"]["observation"] == "seccomp_user_notification";
        if profile == ProfileName::Agent {
            assert_eq!(connect, mediated, "{profile:?}: {event}");
        } else {
            assert!(!mediated, "{profile:?}: {event}");
        }
    }
    eprintln!(
        "{profile:?}: {matched_lines} fixture results matched one-to-one, {excluded} read-only \
         open(s) produced nothing, counts {counts:?}"
    );

    // Zero counts are zero, not absent: a target that only exits.
    let c = case(profile, "strict");
    let fixture = c.fixture.clone().into_os_string();
    let run = c.run_with_inputs(vec![fixture, "exit".into(), "0".into()], &[]);
    let receipt = common::settled(&run);
    let events = audit_results(&run);
    let ops: Vec<&str> = events
        .iter()
        .map(|e| e["operation"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        ops,
        ["proc.exec", "proc.exit"],
        "{profile:?}\n{}",
        dump(&run)
    );
    for (class, count) in [("exec", 2), ("fs.write", 0), ("fs.deny", 0), ("net", 0)] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "active", "{profile:?} {class}: {entry:#}");
        assert_eq!(
            entry["observed_count"],
            Value::from(count),
            "{profile:?} {class}: {entry:#}"
        );
    }
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_tool() {
    o01_matrix(ProfileName::Tool);
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_build() {
    o01_matrix(ProfileName::Build);
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_none() {
    o01_matrix(ProfileName::None);
}

#[test]
fn j4_o01_every_variant_is_one_event_per_result_agent() {
    o01_matrix(ProfileName::Agent);
}

// ---------------------------------------------------------------------------
// O02: attribution by birth identity
// ---------------------------------------------------------------------------

/// Every audit result names its process by host pid and birth: the start
/// time of that process (field 22 of `/proc/<pid>/stat`, clock ticks since
/// boot) as `fields.pid_start_ticks`. With the receipt's `boot_id` that is a
/// name no later process given the same number can share (§11.3).
fn assert_births(run: &Run, receipt: &Value, profile: ProfileName) -> BTreeMap<i64, u64> {
    let context = dump(run);
    let mut births: BTreeMap<i64, u64> = BTreeMap::new();
    for event in audit_results(run) {
        let pid = event["fields"]["pid"]
            .as_i64()
            .unwrap_or_else(|| panic!("{profile:?}: an audit result without its pid: {event}"));
        let ticks = event["fields"]["pid_start_ticks"]
            .as_u64()
            .unwrap_or_else(|| {
                panic!(
                    "{profile:?}: an audit result without its process's birth: {event}\n{context}"
                )
            });
        let seen = *births.entry(pid).or_insert(ticks);
        assert_eq!(
            seen, ticks,
            "{profile:?}: pid {pid} named with two births\n{context}"
        );
    }
    // The target's birth is the one the receipt records for it.
    let (target, ticks) = target_identity(receipt);
    assert_eq!(
        births.get(&target).copied(),
        Some(ticks),
        "{profile:?}: the target's audit birth is not the receipt's\n{context}"
    );
    births
}

#[test]
fn j4_o02_every_audit_event_names_the_birth_of_its_process() {
    for profile in [ProfileName::Tool, ProfileName::Agent] {
        if !common::profile_live(profile) {
            return;
        }
        let c = case(profile, "strict");
        let fixture = c.fixture_s();
        let child = c.workspace.join("child.json");
        std::fs::write(
            &child,
            serde_json::to_vec(&serde_json::json!([
                ["identity"],
                ["mkdir", c.ws("by-child")],
                ["connect", "127.0.0.1:9", "--udp"]
            ]))
            .unwrap(),
        )
        .unwrap();
        let steps = serde_json::json!([
            ["identity"],
            ["mkdir", c.ws("by-target")],
            ["connect", "127.0.0.1:9", "--udp"],
            ["thread"],
            ["exec", "--expect", "ENOENT", "--", "/nonexistent-ukai-j4"],
            ["exec", "--", fixture, "script", child.to_str().unwrap()]
        ]);
        let run = c.script("births", &steps);
        let receipt = common::settled(&run);
        let context = dump(&run);
        let births = assert_births(&run, &receipt, profile);
        let lines = run.fixture_lines();
        let identities: Vec<&Value> = lines.iter().filter(|l| l["op"] == "identity").collect();
        assert_eq!(identities.len(), 2, "{profile:?}\n{context}");
        // Each process names itself with the birth the audit gives it: the
        // target and the exec'd child, which in the contained profiles see
        // themselves under a namespace pid the events never use. Births are
        // clock ticks (10 ms here), so two processes may share one; the name
        // is the pair, and each pair is checked against its own process.
        let target = target_identity(&receipt).0;
        let events = audit_results(&run);
        let by_path = |value: &str| -> i64 {
            events
                .iter()
                .find(|e| e["fields"]["path"]["value"] == value)
                .and_then(|e| e["fields"]["pid"].as_i64())
                .unwrap_or_else(|| panic!("{profile:?}: no result for {value}\n{context}"))
        };
        let child = by_path("by-child");
        assert_eq!(by_path("by-target"), target, "{profile:?}");
        assert_ne!(child, target, "{profile:?}");
        for (identity, pid) in identities.iter().zip([target, child]) {
            assert_eq!(
                births.get(&pid).copied(),
                identity["args"]["start_ticks"].as_u64(),
                "{profile:?}: pid {pid} is named with another birth than {identity}\n{context}"
            );
        }
        // The failed-exec child never execs: its one result still names it,
        // with a pid of its own and a birth no earlier than the target's.
        // (The fixture reports that child's pid as it sees it, which in a
        // contained profile is a namespace pid; the event carries the host
        // one, so the two are tied by the call, not by the number.)
        let failed: Vec<&&Value> = events
            .iter()
            .filter(|e| e["fields"]["syscall"] == "execve" && e["outcome"]["errno"] == "ENOENT")
            .collect();
        assert_eq!(failed.len(), 1, "{profile:?}\n{context}");
        let failed_pid = failed[0]["fields"]["pid"].as_i64().unwrap();
        assert!(failed_pid != target && failed_pid != child, "{profile:?}");
        assert!(births[&failed_pid] >= births[&target], "{profile:?}");
        assert!(births[&child] >= births[&failed_pid], "{profile:?}");
        // Threads are not processes: every pid named is a thread group this
        // run created (target, the failed-exec child, the exec'd child).
        assert_eq!(births.len(), 3, "{profile:?}: {births:?}\n{context}");
    }
}

/// O02 with a nested pid namespace, as far as the stock host allows (S10):
/// `none` runs the host's bubblewrap as its target, which puts the fixture
/// in a new user and pid namespace one layer down, traced through it. The
/// fixture sees itself under its namespace pid; every audit result names
/// the host pid, and its birth is the one the fixture reads for itself.
#[test]
fn j4_o02_a_nested_pid_namespace_under_none_keeps_host_attribution() {
    if !common::profile_live(ProfileName::None) {
        return;
    }
    let c = case(ProfileName::None, "strict");
    let workspace = c.workspace.to_str().unwrap().to_owned();
    let script = c.workspace.join("nested.json");
    std::fs::write(
        &script,
        serde_json::to_vec(&serde_json::json!([
            ["identity"],
            ["mkdir", c.ws("nested-dir")],
            ["open", c.ws("nested-file"), "--create", "--write"]
        ]))
        .unwrap(),
    )
    .unwrap();
    let mut argv: Vec<OsString> = vec![
        common::bwrap_path().into_os_string(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--die-with-parent".into(),
    ];
    for root in ukai_jail::platform::linux::bwrap::RUNTIME_ROOTS
        .iter()
        .filter_map(|path| ukai_jail::platform::linux::fs::resolve_runtime_root(Path::new(path)))
    {
        match root {
            ukai_jail::platform::linux::fs::RootSpec::RoBind(path) => {
                argv.extend(["--ro-bind".into(), path.clone().into(), path.into()]);
            }
            ukai_jail::platform::linux::fs::RootSpec::Symlink { path, target } => {
                argv.extend(["--symlink".into(), target.into(), path.into()]);
            }
        }
    }
    argv.extend([
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--bind".into(),
        workspace.clone().into(),
        workspace.clone().into(),
        "--chdir".into(),
        workspace.clone().into(),
        "--".into(),
        c.fixture.clone().into_os_string(),
        "script".into(),
        script.into_os_string(),
    ]);
    let run = c.jail.target(argv).run().expect("the jail runs");
    let receipt = common::settled(&run);
    let context = dump(&run);
    let lines = run.fixture_lines();
    let identity = lines
        .iter()
        .find(|l| l["op"] == "identity")
        .unwrap_or_else(|| panic!("the fixture never ran inside bwrap\n{context}"));
    let inner_pid = identity["args"]["pid"].as_i64().unwrap();
    let inner_ticks = identity["args"]["start_ticks"].as_u64().unwrap();
    let nspid = identity["args"]["nspid"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let events = audit_results(&run);
    let mkdir = events
        .iter()
        .find(|e| {
            e["fields"]["syscall"] == "mkdirat" && e["fields"]["path"]["value"] == "nested-dir"
        })
        .unwrap_or_else(|| panic!("no audit result for the nested mkdir\n{context}"));
    let host_pid = mkdir["fields"]["pid"].as_i64().unwrap();
    assert_ne!(
        host_pid, inner_pid,
        "the event must carry the host pid, not the namespace pid {inner_pid} ({nspid})\n{context}"
    );
    assert_eq!(
        mkdir["fields"]["pid_start_ticks"].as_u64(),
        Some(inner_ticks),
        "the host-attributed result names the birth the process reads for itself\n{context}"
    );
    // The same process, the same name, for every one of its results.
    let mine: Vec<&&Value> = events
        .iter()
        .filter(|e| e["fields"]["pid"].as_i64() == Some(host_pid))
        .collect();
    let ops: BTreeSet<&str> = mine
        .iter()
        .filter_map(|e| e["operation"].as_str())
        .collect();
    assert!(
        ops.contains("proc.exec") && ops.contains("proc.exit") && ops.contains("fs.create"),
        "{ops:?}\n{context}"
    );
    for event in mine {
        assert_eq!(
            event["fields"]["pid_start_ticks"].as_u64(),
            Some(inner_ticks),
            "{event}"
        );
    }
    assert_eq!(receipt["outcome"]["kind"], "exited", "{context}");
    assert_eq!(gap_reasons(&receipt), Vec::<String>::new(), "{context}");
}

// ---------------------------------------------------------------------------
// O04: unrelated host processes
// ---------------------------------------------------------------------------

/// A process on the host that is not part of the attempt keeps making
/// closed-set calls for the whole run. `none` shares the host's view, which
/// makes it the profile where such a process is most visible; none of its
/// calls may appear, by pid or by path.
#[test]
fn j4_o04_an_unrelated_host_process_is_never_observed() {
    if !common::profile_live(ProfileName::None) {
        return;
    }
    let c = case(ProfileName::None, "strict");
    let outside = c.jail.root().join("unrelated");
    std::fs::create_dir_all(&outside).unwrap();
    let a = outside.join("race-a");
    let b = outside.join("race-b");
    let mut unrelated = std::process::Command::new(harness::fixture_path())
        .args(["--no-report", "race-mkdir"])
        .arg(&a)
        .arg(&b)
        .arg("100000000")
        .spawn()
        .expect("the unrelated process starts");
    // Synchronised on the process's own first effect, not on a sleep.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !a.exists() && !b.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the unrelated process never ran"
        );
        std::thread::yield_now();
    }
    let steps = serde_json::json!([
        ["mkdir", c.ws("mine")],
        ["open", c.ws("mine/file"), "--create", "--write"],
        ["rmdir", c.ws("absent"), "--expect", "ENOENT"]
    ]);
    let run = c.script("o04", &steps);
    let still_running = unrelated.try_wait().expect("try_wait").is_none();
    let _ = unrelated.kill();
    let _ = unrelated.wait();
    assert!(still_running, "the unrelated process must outlive the run");
    let receipt = common::settled(&run);
    let context = dump(&run);
    let target = target_identity(&receipt).0;
    let digests: Vec<String> = [&a, &b]
        .iter()
        .map(|p| ukai_jail::canonical::sha256_prefixed(p.as_os_str().as_bytes()))
        .collect();
    let events = audit_results(&run);
    for event in &events {
        assert_eq!(
            event["fields"]["pid"].as_i64(),
            Some(target),
            "only the target made calls in this run: {event}\n{context}"
        );
        assert_ne!(
            event["fields"]["pid"].as_i64(),
            Some(i64::from(unrelated.id())),
            "{event}"
        );
        let text = event.to_string();
        for digest in &digests {
            assert!(!text.contains(digest.as_str()), "{event}");
        }
        assert!(
            !text.contains("race-a") && !text.contains("race-b"),
            "{event}"
        );
    }
    let fs: Vec<&&Value> = events
        .iter()
        .filter(|e| class_of(e["operation"].as_str().unwrap_or_default()) == "fs.write")
        .collect();
    assert_eq!(fs.len(), 3, "exactly the target's three calls\n{context}");
    assert_eq!(receipt["coverage"]["fs.write"]["observed_count"], 3);
}

// ---------------------------------------------------------------------------
// O06: paths never falsely resolved
// ---------------------------------------------------------------------------

fn event_for<'a>(events: &[&'a Value], syscall: &str, n: usize) -> &'a Value {
    events
        .iter()
        .filter(|e| e["fields"]["syscall"] == syscall)
        .nth(n)
        .copied()
        .unwrap_or_else(|| panic!("no {n}th {syscall} result"))
}

/// A renamed cwd is read at the syscall entry. Joining to the earlier
/// `chdir` spelling would name a directory that no longer exists.
#[test]
fn j4_o06_renamed_cwd() {
    if !common::profile_live(ProfileName::Tool) {
        return;
    }
    let c = case(ProfileName::Tool, "strict");
    let workspace = c.workspace.clone();
    let steps = serde_json::json!([
        ["mkdir", c.ws("cwd-a")],
        ["chdir", c.ws("cwd-a")],
        [
            "rename",
            c.ws("cwd-a"),
            c.ws("cwd-b"),
            "--via",
            native_via("rename")
        ],
        ["mkdir", "made", "--via", native_via("mkdir")],
        ["open", "file.txt", "--create", "--write"]
    ]);
    let run = c.script("cwd", &steps);
    let _ = common::settled(&run);
    let context = dump(&run);
    assert!(workspace.join("cwd-b/made").is_dir(), "{context}");
    assert!(!workspace.join("cwd-a").exists(), "{context}");
    let events = audit_results(&run);
    let rename = event_for(&events, native_via("rename"), 0);
    assert_eq!(rename["fields"]["path"]["value"], "cwd-a", "{context}");
    assert_eq!(rename["fields"]["path2"]["value"], "cwd-b", "{context}");
    // Entry-time /proc cwd snapshots reflect the renamed directory, rather
    // than the obsolete name from the earlier chdir.
    // The `made` call is the first of its spelling after the rename: on
    // aarch64 the earlier `cwd-a` step is spelled `mkdirat` too.
    let made = *events
        .iter()
        .skip_while(|e| e["fields"]["syscall"] != native_via("rename"))
        .find(|e| e["fields"]["syscall"] == native_via("mkdir"))
        .unwrap_or_else(|| panic!("no mkdir after the rename\n{context}"));
    assert_eq!(
        made["fields"]["path"],
        serde_json::json!({"kind":"workspace_relative", "value":"cwd-b/made"}),
        "{context}"
    );
    let file = events
        .iter()
        .find(|e| e["fields"]["syscall"] == "openat" && e["operation"] == "fs.create")
        .unwrap();
    assert_eq!(
        file["fields"]["path"],
        serde_json::json!({"kind":"workspace_relative", "value":"cwd-b/file.txt"}),
        "{context}"
    );
    for event in &events {
        let text = event["fields"].to_string();
        for guess in ["cwd-a/made", "cwd-a/file.txt"] {
            assert!(!text.contains(guess), "a resolved guess {guess}: {event}");
        }
    }
    assert_eq!(made["fields"]["path_basis"], "argument_snapshot");
}

/// A relative name resolved against a directory descriptor: the event
/// records the descriptor and names the path below that descriptor's own
/// link, read at the entry and exit stops (§11.3 `directory_link`) — never
/// against the cwd, which is the workspace here and would name `made`. An
/// absolute name ignores the descriptor, and is reported as what it is.
#[test]
fn j4_o06_foreign_dirfd() {
    if !common::profile_live(ProfileName::Tool) {
        return;
    }
    let c = case(ProfileName::Tool, "strict");
    std::fs::create_dir_all(c.workspace.join("sub")).unwrap();
    let workspace = c.workspace.clone();
    let steps = serde_json::json!([
        ["mkdir", "made", "--via", "mkdirat", "--dirfd", c.ws("sub")],
        [
            "mkdir",
            c.ws("abs-made"),
            "--via",
            "mkdirat",
            "--dirfd",
            c.ws("sub")
        ]
    ]);
    let run = c.script("dirfd", &steps);
    let _ = common::settled(&run);
    let context = dump(&run);
    assert!(workspace.join("sub/made").is_dir(), "{context}");
    let lines = run.fixture_lines();
    let mkdirs: Vec<&Value> = lines.iter().filter(|l| l["op"] == "mkdirat").collect();
    let fd = mkdirs[0]["args"]["dirfd"].as_i64().unwrap();
    let events = audit_results(&run);
    let relative = event_for(&events, "mkdirat", 0);
    assert_eq!(
        relative["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "sub/made"}),
        "{context}"
    );
    assert_eq!(relative["fields"]["path_basis"], "directory_link");
    assert_eq!(
        relative["fields"]["path_dirfd"].as_i64(),
        Some(fd),
        "{context}"
    );
    assert_eq!(relative["fields"]["path_complete"], true);
    assert_eq!(relative["outcome"]["return_value"], 0);
    let absolute = event_for(&events, "mkdirat", 1);
    assert_eq!(
        absolute["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "abs-made"}),
        "{context}"
    );
    assert_eq!(absolute["fields"]["path_basis"], "argument_snapshot");
    for event in &events {
        assert_ne!(
            event["fields"]["path"],
            serde_json::json!({"kind": "workspace_relative", "value": "made"}),
            "resolved against the cwd: {event}"
        );
    }
    // The directory's own open is read-only: outside the set.
    assert!(
        events.iter().all(|e| e["fields"]["syscall"] != "openat"),
        "{context}"
    );
}

/// Claude Code 2.1.302 (Bun) writes a workspace file as
/// `openat(AT_FDCWD, "/proc/self/fd/<N>/<name>.tmp…", O_CREAT|O_EXCL…)` and
/// `rename` through the same descriptor (measured on the reference host,
/// 2026-10-17). §11.3: such a name is resolved through descriptor N, as
/// `openat(N, name)` is. A successful open is named by the returned
/// descriptor's own link when the directory descriptor's link joined with the
/// name is exactly it (`path_basis: descriptor_link`), for both spellings;
/// the rename is named below the descriptor's link read at both stops
/// (`directory_link`); a name the descriptor does not corroborate (a symlink
/// below the directory) is still downgraded, and that is the run's only gap.
/// `/dev/null` opened for writing is a `standard_device` digest; the same
/// descriptor spelled `/dev/fd/<N>/<name>` is not one (it reaches a
/// workspace file through a symlink, so it is downgraded), and neither is a
/// file below `/dev/shm`, whatever its open returned.
#[test]
fn j4_o06_a_name_through_a_descriptor_is_named_by_the_kernels_resolution() {
    for profile in [ProfileName::Tool, ProfileName::Agent] {
        if !common::profile_live(profile) {
            return;
        }
        let c = case(profile, "strict");
        std::fs::create_dir_all(c.workspace.join("sub")).unwrap();
        std::os::unix::fs::symlink("sub", c.workspace.join("link")).unwrap();
        let workspace = c.workspace.clone();
        let ws = c.ws("");
        let ws = ws.trim_end_matches('/');
        let steps = serde_json::json!([
            [
                "open",
                "g.tmp",
                "--dirfd",
                ws,
                "--proc-fd",
                "--write",
                "--create"
            ],
            [
                "rename",
                "g.tmp",
                "greeting.txt",
                "--via",
                "rename",
                "--dirfd",
                ws,
                "--proc-fd"
            ],
            ["open", "slug.py", "--dirfd", ws, "--write", "--create"],
            [
                "open",
                "link/x",
                "--dirfd",
                ws,
                "--proc-fd",
                "--write",
                "--create"
            ],
            ["open", "/dev/null", "--write"],
            [
                "open",
                "devfd.txt",
                "--dirfd",
                ws,
                "--dev-fd",
                "--write",
                "--create"
            ],
            [
                "open",
                "/dev/shm/ukai-shm-probe",
                "--write",
                "--create",
                "--expect",
                "any"
            ]
        ]);
        let run = c.script("through", &steps);
        let receipt = common::settled(&run);
        let context = format!("{profile:?}\n{}", dump(&run));
        assert!(workspace.join("greeting.txt").is_file(), "{context}");
        assert!(workspace.join("sub/x").is_file(), "{context}");
        let lines = run.fixture_lines();
        let descriptors: Vec<i64> = lines
            .iter()
            .filter(|l| l["args"]["purpose"] == "dirfd")
            .map(|l| l["ret"].as_i64().expect("the directory opened"))
            .collect();
        assert_eq!(descriptors.len(), 5, "{context}");
        let events = audit_results(&run);

        let created = event_for(&events, "openat", 0);
        assert_eq!(
            created["fields"]["path"],
            serde_json::json!({"kind": "workspace_relative", "value": "g.tmp"}),
            "{context}"
        );
        assert_eq!(
            created["fields"]["path_basis"], "descriptor_link",
            "{context}"
        );
        assert_eq!(
            created["fields"]["path_dirfd"].as_i64(),
            Some(descriptors[0])
        );
        assert_eq!(created["fields"]["path_complete"], true);

        let renamed = event_for(&events, "rename", 0);
        for (key, name) in [("path", "g.tmp"), ("path2", "greeting.txt")] {
            assert_eq!(
                renamed["fields"][key],
                serde_json::json!({"kind": "workspace_relative", "value": name}),
                "{key}: {context}"
            );
            assert_eq!(
                renamed["fields"][format!("{key}_dirfd")].as_i64(),
                Some(descriptors[1]),
                "{key}: {context}"
            );
        }
        assert_eq!(renamed["fields"]["path_basis"], "directory_link");

        let true_dirfd = event_for(&events, "openat", 1);
        assert_eq!(
            true_dirfd["fields"]["path"],
            serde_json::json!({"kind": "workspace_relative", "value": "slug.py"}),
            "{context}"
        );
        assert_eq!(true_dirfd["fields"]["path_basis"], "descriptor_link");
        assert_eq!(
            true_dirfd["fields"]["path_dirfd"].as_i64(),
            Some(descriptors[2])
        );

        let symlinked = event_for(&events, "openat", 2);
        assert_eq!(
            symlinked["fields"]["path"],
            serde_json::json!({"kind": "unavailable", "reason": "path_truncated"}),
            "{context}"
        );
        assert_eq!(symlinked["fields"]["path_complete"], false);
        assert_eq!(symlinked["fields"]["path_basis"], "argument_snapshot");

        let null = event_for(&events, "openat", 3);
        assert_eq!(null["operation"], "fs.write", "{context}");
        assert_eq!(null["fields"]["path"]["kind"], "digest", "{context}");
        assert_eq!(
            null["fields"]["path"]["reason"], "standard_device",
            "{context}"
        );
        // `/dev/fd` is the jail's symlink to `/proc/self/fd`: the open lands
        // in the workspace, which the snapshot does not name, so it is
        // downgraded like any symlinked name.
        assert!(workspace.join("devfd.txt").is_file(), "{context}");
        let devfd = event_for(&events, "openat", 4);
        assert_eq!(
            devfd["fields"]["path"],
            serde_json::json!({"kind": "unavailable", "reason": "path_truncated"}),
            "{context}"
        );
        // Whatever `/dev/shm` allowed, a file there is no standard device.
        let shm = event_for(&events, "openat", 5);
        assert_ne!(
            shm["fields"]["path"]["reason"], "standard_device",
            "{context}"
        );
        // A bookkeeping gap of no class: in the observer's account, under no
        // coverage class.
        assert!(gap_reasons(&receipt).is_empty(), "{context}");
        let observer_gaps: BTreeSet<&str> = receipt["observer"]["gaps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|gap| gap["reason"].as_str())
            .collect();
        assert_eq!(
            observer_gaps,
            BTreeSet::from(["path_claim_unverified"]),
            "only the symlinked names: {context}"
        );
        assert_eq!(
            receipt["lifetime"]["native"]["details"]["path_claims_unverified"], 2,
            "the symlink below the directory, and /dev/fd: {context}"
        );
        assert_eq!(
            receipt["lifetime"]["native"]["details"]["path_anchors_unverified"], 0,
            "{context}"
        );
        // The directory descriptors are read-only opens, outside the set.
        assert_eq!(
            events
                .iter()
                .filter(|e| e["fields"]["syscall"] == "openat")
                .count(),
            6,
            "{context}"
        );
    }
}

/// §11.3: "Two-path operations treat both paths independently." Each side
/// is classified on its own evidence: one by its absolute spelling, the
/// other below its directory descriptor's link (`directory_link`), in both
/// orders; and a scratch path beside a workspace path.
#[test]
fn j4_o06_two_paths_independent() {
    if !common::profile_live(ProfileName::Tool) {
        return;
    }
    let c = case(ProfileName::Tool, "strict");
    std::fs::create_dir_all(c.workspace.join("sub")).unwrap();
    std::fs::write(c.workspace.join("two-a"), b"a").unwrap();
    let steps = serde_json::json!([
        [
            "rename",
            c.ws("two-a"),
            "two-b",
            "--via",
            "renameat",
            "--dirfd2",
            c.ws("sub")
        ],
        [
            "rename",
            "two-b",
            c.ws("two-c"),
            "--via",
            "renameat2",
            "--dirfd",
            c.ws("sub")
        ],
        [
            "link",
            c.ws("two-c"),
            "/tmp/two-d",
            "--via",
            "linkat",
            "--expect",
            "any"
        ]
    ]);
    let run = c.script("two", &steps);
    let _ = common::settled(&run);
    let context = dump(&run);
    let events = audit_results(&run);
    let lines = run.fixture_lines();
    let renames: Vec<&Value> = lines
        .iter()
        .filter(|l| l["op"] == "renameat" || l["op"] == "renameat2")
        .collect();
    let first = event_for(&events, "renameat", 0);
    assert_eq!(
        first["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "two-a"}),
        "{context}"
    );
    assert_eq!(
        first["fields"]["path2"],
        serde_json::json!({"kind": "workspace_relative", "value": "sub/two-b"}),
        "{context}"
    );
    assert_eq!(first["fields"]["path_basis"], "directory_link");
    assert_eq!(
        first["fields"]["path2_dirfd"].as_i64(),
        renames[0]["args"]["dirfd2"].as_i64()
    );
    assert!(first["fields"].get("path_dirfd").is_none(), "{first}");
    let second = event_for(&events, "renameat2", 0);
    assert_eq!(
        second["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "sub/two-b"}),
        "{context}"
    );
    assert_eq!(
        second["fields"]["path_dirfd"].as_i64(),
        renames[1]["args"]["dirfd"].as_i64()
    );
    assert_eq!(
        second["fields"]["path2"],
        serde_json::json!({"kind": "workspace_relative", "value": "two-c"}),
        "{context}"
    );
    let link = event_for(&events, "linkat", 0);
    assert_eq!(
        link["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "two-c"}),
        "{context}"
    );
    assert_eq!(
        link["fields"]["path2"],
        serde_json::json!({"kind": "scratch_relative", "value": "two-d"}),
        "{context}"
    );
}

/// A symlink's target is a string the call stores, resolved against
/// nothing: relative or absolute, it is the digest of its bytes
/// (`symlink_target`), never joined to the cwd, never a workspace path. A
/// hard link names both its paths, and the end-of-run summary counts only
/// the entry each call created: the links, never the file they point at or
/// give a name to (jail-launch-and-summary §4.2, K46).
#[test]
fn j4_o06_a_link_names_only_the_entry_it_creates() {
    if !common::profile_live(ProfileName::Tool) {
        return;
    }
    let c = case(ProfileName::Tool, "strict");
    std::fs::write(c.workspace.join("README.md"), b"r").unwrap();
    let readme = c.ws("README.md");
    let steps = serde_json::json!([
        [
            "symlink",
            "README.md",
            "l-rel",
            "--via",
            native_via("symlink")
        ],
        [
            "symlink",
            c.ws("README.md"),
            c.ws("l-abs"),
            "--via",
            "symlinkat"
        ],
        [
            "link",
            c.ws("README.md"),
            c.ws("hard"),
            "--via",
            native_via("link")
        ]
    ]);
    let run = c.script("links", &steps);
    let receipt = common::settled(&run);
    let context = dump(&run);
    let events = audit_results(&run);
    let target = |bytes: &str| {
        serde_json::json!({
            "kind": "digest",
            "digest": ukai_jail::canonical::sha256_prefixed(bytes.as_bytes()),
            "reason": "symlink_target",
        })
    };
    let relative = event_for(&events, native_via("symlink"), 0);
    assert_eq!(
        relative["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "l-rel"}),
        "the link is resolved against the cwd: {context}"
    );
    assert_eq!(
        relative["fields"]["path2"],
        target("README.md"),
        "the target is not: {context}"
    );
    let absolute = event_for(
        &events,
        "symlinkat",
        usize::from(native_via("symlink") == "symlinkat"),
    );
    assert_eq!(
        absolute["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "l-abs"}),
        "{context}"
    );
    assert_eq!(
        absolute["fields"]["path2"],
        target(&readme),
        "an absolute target is no workspace path either: {context}"
    );
    for event in [relative, absolute] {
        assert_eq!(event["fields"]["path_basis"], "argument_snapshot");
        assert!(
            event["fields"].get("path2_dirfd").is_none(),
            "{event}: {context}"
        );
    }
    let hard = event_for(&events, native_via("link"), 0);
    assert_eq!(
        hard["fields"]["path"],
        serde_json::json!({"kind": "workspace_relative", "value": "README.md"}),
        "{context}"
    );
    assert_eq!(
        hard["fields"]["path2"],
        serde_json::json!({"kind": "workspace_relative", "value": "hard"}),
        "{context}"
    );
    assert_eq!(
        receipt["lifetime"]["native"]["details"]["path_anchors_unverified"], 0,
        "{context}"
    );

    let last: Value =
        serde_json::from_slice(run.final_receipt().expect("a final receipt")).unwrap();
    let mut journal = Vec::new();
    for event in run.trace_events() {
        journal.extend(serde_json::to_vec(event).unwrap());
        journal.push(b'\n');
    }
    let summary = ukai_jail::summary::summary(&last, ukai_jail::summary::Journal::Bytes(&journal));
    let workspace = summary
        .lines
        .iter()
        .find(|line| line.line == "workspace")
        .expect("a workspace line");
    assert_eq!(
        workspace.facts["paths"],
        serde_json::json!([
            {"kind": "workspace_relative", "value": "hard"},
            {"kind": "workspace_relative", "value": "l-abs"},
            {"kind": "workspace_relative", "value": "l-rel"},
        ]),
        "README.md was given names, never opened for writing: {}\n{context}",
        workspace.text
    );
    assert_eq!(
        workspace.facts["opened_for_writing"], 3,
        "{}",
        workspace.text
    );
    assert_eq!(workspace.facts["unnamed"], 0, "{}", workspace.text);
}

/// A name that is not UTF-8 is carried as its bytes (the base64 form of the
/// native-string codec) and decodes to exactly what the fixture passed.
#[test]
fn j4_o06_non_utf8_round_trip() {
    if !common::profile_live(ProfileName::Tool) {
        return;
    }
    let c = case(ProfileName::Tool, "strict");
    let name: &[u8] = b"caf\xe9-\xff\xfe";
    let mut path = c.workspace.as_os_str().as_bytes().to_vec();
    path.push(b'/');
    path.extend_from_slice(name);
    let path = OsString::from_vec(path);
    let run = c
        .jail
        .target([
            c.fixture.clone().into_os_string(),
            OsString::from("mkdir"),
            path.clone(),
        ])
        .run()
        .expect("the jail runs");
    let _ = common::settled(&run);
    let context = dump(&run);
    assert!(Path::new(&path).is_dir(), "{context}");
    let events = audit_results(&run);
    let mkdir = event_for(&events, "mkdirat", 0);
    assert_eq!(
        mkdir["fields"]["path"]["kind"], "workspace_relative",
        "{context}"
    );
    let value = &mkdir["fields"]["path"]["value"];
    assert_eq!(value["encoding"], "base64", "{context}");
    let decoded: ukai_jail::records::NativeString =
        serde_json::from_value(value.clone()).expect("a native string");
    assert_eq!(decoded.as_bytes(), name, "{context}");
    assert_eq!(mkdir["fields"]["path_complete"], true);
    let _ = OsStr::from_bytes(name);
}

/// A pathname another thread keeps rewriting while the call runs. The
/// observer snapshots the argument at the entry; the kernel reads it again
/// after the stop. Since the security audit of 2026-09-25 (F1) the exit
/// re-reads what the event asserts: a snapshot that still reads the same is
/// delivered as one of the two literal names the buffer ever held, labelled
/// `argument_snapshot` — never a resolved or blended path — and a snapshot
/// that changed is dropped and counted as one `argument_snapshot_unstable`
/// gap of `fs.write`, so a falsified name can never be presented as an
/// observed fact. Calls and gap counts together account for every call.
#[test]
fn j4_o06_racing_pathname_is_only_a_literal_snapshot() {
    if !common::profile_live(ProfileName::Tool) {
        return;
    }
    let c = case(ProfileName::Tool, "best-effort");
    const CALLS: usize = 300;
    let steps = serde_json::json!([[
        "race-mkdir",
        c.ws("race-a"),
        c.ws("race-b"),
        CALLS.to_string()
    ]]);
    let workspace = c.workspace.clone();
    let run = c.script("race", &steps);
    let receipt = common::settled(&run);
    let context = dump(&run);
    let lines: Vec<Value> = run
        .fixture_lines()
        .into_iter()
        .filter(|l| l["op"] == native_via("mkdir"))
        .collect();
    assert_eq!(lines.len(), CALLS, "{context}");
    let events: Vec<&Value> = audit_results(&run)
        .into_iter()
        .filter(|e| e["fields"]["syscall"] == native_via("mkdir"))
        .collect();
    let unstable: u64 = receipt["coverage"]["fs.write"]["gaps"]
        .as_array()
        .into_iter()
        .flat_map(|gaps| gaps.iter())
        .filter(|g| g["reason"] == "argument_snapshot_unstable")
        .map(|g| g["lost_count"].as_u64().unwrap_or(0))
        .sum();
    let observed = events.len() as u64;
    assert_eq!(
        observed + unstable,
        CALLS as u64,
        "every call is either a stable event or an unstable-snapshot gap \
         (events {observed}, gaps {unstable})\n{context}"
    );
    // The race was actually observed, not merely tolerated: the flipper
    // thread runs for all 300 calls, so at least one snapshot must have been
    // caught mid-flip and recorded as an argument_snapshot_unstable gap.
    assert!(
        unstable > 0,
        "no unstable snapshot in {CALLS} racing mkdirs — the race did not \
         happen and this test proves nothing\n{context}"
    );
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut created = 0;
    for line in &lines {
        if line["ret"].as_i64() == Some(0) {
            created += 1;
        }
    }
    for event in &events {
        assert_eq!(
            event["fields"]["path_basis"], "argument_snapshot",
            "{event}"
        );
        let value = event["fields"]["path"]["value"]
            .as_str()
            .unwrap_or_default();
        assert!(
            event["fields"]["path"]["kind"] == "workspace_relative"
                && (value == "race-a" || value == "race-b"),
            "a snapshot that is neither literal name: {event}"
        );
        *seen.entry(value.to_owned()).or_default() += 1;
    }
    assert!(created <= 2, "each name can be created once");
    let on_disk = ["race-a", "race-b"]
        .iter()
        .filter(|n| workspace.join(n).is_dir())
        .count();
    assert_eq!(on_disk, created, "{context}");
    assert!(
        receipt["coverage"]["fs.write"]["status"] == "active"
            || receipt["coverage"]["fs.write"]["status"] == "degraded",
        "gaps degrade, never silently weaken\n{:#}",
        receipt["coverage"]["fs.write"]
    );
    eprintln!(
        "racing snapshots: {seen:?}, unstable gaps: {unstable}, directories created: {created}, \
         all fs.write gaps: {:#?}",
        receipt["coverage"]["fs.write"]["gaps"]
    );
}

/// A directory descriptor another thread keeps swapping (`dup2` of two
/// directories onto it) while `mkdirat` names a new entry through it, as a
/// true `dirfd` and spelled `/proc/self/fd/<N>/<name>`, and the working
/// directory swapped the same way (`fchdir`) under a relative name. §11.3:
/// the anchor is read at the entry stop and again at the exit stop; a name
/// is resolved against it only when both reads agree, and a disagreement
/// leaves the call `relative_to_dirfd` (`relative_to_unresolved_cwd`) with
/// one bookkeeping `path_anchor_unverified` gap, which degrades no class and
/// never stops a strict run. Every call is one event, every name is one of
/// the two directories (never a blend), and the race was caught. Each call
/// creates its own name, so the disk says which directory the kernel used:
/// a name the two reads agreed on but the kernel did not use is the stated
/// residual (a swap and a swap back between the reads), counted and
/// printed, not asserted away.
#[test]
fn j4_o06_a_descriptor_moved_between_the_stops_is_not_resolved() {
    for profile in [ProfileName::Tool, ProfileName::Agent] {
        if !common::profile_live(profile) {
            return;
        }
        let c = case(profile, "strict");
        const CALLS: usize = 200;
        for dir in ["ra", "rb"] {
            std::fs::create_dir_all(c.workspace.join(dir)).unwrap();
        }
        let steps = serde_json::json!([
            ["race-dirfd", c.ws("ra"), c.ws("rb"), "t", CALLS.to_string()],
            [
                "race-dirfd",
                c.ws("ra"),
                c.ws("rb"),
                "p",
                CALLS.to_string(),
                "--proc-fd"
            ],
            [
                "race-dirfd",
                c.ws("ra"),
                c.ws("rb"),
                "c",
                CALLS.to_string(),
                "--cwd"
            ]
        ]);
        let workspace = c.workspace.clone();
        let run = c.script("race-dirfd", &steps);
        let receipt = common::settled(&run);
        let context = format!("{profile:?}\n{}", dump(&run));
        let lines: Vec<Value> = run
            .fixture_lines()
            .into_iter()
            .filter(|l| l["op"] == "mkdirat" && l["args"]["racing"] == true)
            .collect();
        assert_eq!(lines.len(), 3 * CALLS, "{context}");
        assert!(
            lines.iter().all(|l| l["ret"] == 0),
            "every name is new: {context}"
        );
        let events: Vec<&Value> = audit_results(&run)
            .into_iter()
            .filter(|e| e["fields"]["syscall"] == "mkdirat")
            .collect();
        assert_eq!(events.len(), 3 * CALLS, "no result is lost: {context}");
        // Per anchor: named, named below the directory the kernel did not
        // use, unresolved.
        let mut tally: BTreeMap<&str, (u64, u64, u64)> = BTreeMap::new();
        for (line, event) in lines.iter().zip(&events) {
            let name = line["args"]["name"].as_str().unwrap();
            let cwd = name.starts_with('c');
            let anchor = match name.as_bytes()[0] {
                b't' => "dirfd",
                b'p' => "proc-fd",
                _ => "cwd",
            };
            let entry = tally.entry(anchor).or_default();
            let path = &event["fields"]["path"];
            if cwd {
                assert!(event["fields"].get("path_dirfd").is_none(), "{event}");
            } else {
                assert_eq!(
                    event["fields"]["path_dirfd"], line["args"]["descriptor"],
                    "{event}"
                );
            }
            assert_eq!(event["fields"]["path_complete"], true, "{event}");
            if path["kind"] == "unavailable" {
                let reason = if cwd {
                    "relative_to_unresolved_cwd"
                } else {
                    "relative_to_dirfd"
                };
                assert_eq!(path["reason"], reason, "{event}");
                assert_eq!(event["fields"]["path_basis"], "argument_snapshot");
                entry.2 += 1;
                continue;
            }
            let value = path["value"].as_str().unwrap_or_default();
            assert!(
                path["kind"] == "workspace_relative"
                    && (value == format!("ra/{name}") || value == format!("rb/{name}")),
                "a name below neither directory: {event}"
            );
            assert_eq!(
                event["fields"]["path_basis"],
                if cwd {
                    "argument_snapshot"
                } else {
                    "directory_link"
                },
                "{event}"
            );
            entry.0 += 1;
            if !workspace.join(value).is_dir() {
                entry.1 += 1;
            }
        }
        let unresolved: u64 = tally.values().map(|(_, _, unresolved)| unresolved).sum();
        // The race happened, for every anchor, and the two reads caught it.
        for (anchor, (_, _, caught)) in &tally {
            assert!(
                *caught > 0,
                "no moved {anchor} in {CALLS} racing calls: the race did not happen \
                 and this test proves nothing\n{context}"
            );
        }
        let details = &receipt["lifetime"]["native"]["details"];
        assert_eq!(
            details["path_anchors_unverified"].as_u64(),
            Some(unresolved),
            "one gap per unresolved call: {context}"
        );
        assert!(
            receipt["observer"]["gaps"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|gap| gap["reason"] == "path_anchor_unverified"),
            "{context}"
        );
        assert_eq!(
            receipt["coverage"]["fs.write"]["status"], "active",
            "{context}"
        );
        assert!(
            !gap_reasons(&receipt).contains(&"path_anchor_unverified".to_owned()),
            "bookkeeping, under no class: {context}"
        );
        for (anchor, (named, wrong, caught)) in &tally {
            eprintln!(
                "{profile:?} racing {anchor}: {named} named ({wrong} below the directory the \
                 kernel did not use), {caught} unresolved, of {CALLS}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// S4: CLONE_UNTRACED
// ---------------------------------------------------------------------------

/// `clone(CLONE_UNTRACED)` would create a descendant the observer never
/// attaches to. Every contained baseline refuses it with EPERM, and the
/// ordinary ways of creating tasks keep working.
#[test]
fn j4_clone_untraced_refused_in_contained() {
    for profile in [ProfileName::Tool, ProfileName::Build, ProfileName::Agent] {
        if !common::profile_live(profile) {
            return;
        }
        let c = case(profile, "strict");
        let untraced = c.workspace.join("untraced");
        let fixture = c.fixture_s();
        let steps = serde_json::json!([
            [
                "clone-untraced",
                untraced.to_str().unwrap(),
                "--expect",
                "EPERM"
            ],
            ["thread"],
            ["exec", "--", fixture, "exit", "0"]
        ]);
        let run = c.script("untraced", &steps);
        let receipt = common::settled(&run);
        let context = dump(&run);
        let lines = run.fixture_lines();
        let clone = lines.iter().find(|l| l["op"] == "clone").unwrap();
        assert_eq!(clone["errno"], "EPERM", "{profile:?}\n{context}");
        assert!(
            lines.iter().all(|l| l["op"] != "untraced-mkdir"),
            "{profile:?}: a child ran\n{context}"
        );
        assert!(!untraced.exists(), "{profile:?}");
        assert_eq!(
            run.code(),
            Some(0),
            "{profile:?}: threads and fork still work\n{context}"
        );
        assert_eq!(gap_reasons(&receipt), Vec::<String>::new(), "{profile:?}");
    }
}

/// In `none` nothing refuses the flag. The observer stops on it, and a
/// descendant it can never attach to is a gap in every class: coverage
/// cannot be `active`, strict evidence stops the attempt. The descendant's
/// own closed-set calls fail closed (ENOSYS: a trace stop with no tracer).
/// `clone3`, whose flags seccomp cannot read, is refused with ENOSYS so that
/// glibc falls back to `clone`, and threads keep working.
#[test]
fn j4_clone_untraced_is_a_gap_in_none() {
    if !common::profile_live(ProfileName::None) {
        return;
    }
    let c = case(ProfileName::None, "best-effort");
    let untraced = c.workspace.join("untraced");
    let steps = serde_json::json!([
        ["clone3", "--expect", "ENOSYS"],
        ["thread"],
        ["clone-untraced", untraced.to_str().unwrap()]
    ]);
    let run = c.script("untraced-none", &steps);
    let receipt = common::settled(&run);
    let context = dump(&run);
    let lines = run.fixture_lines();
    let clone3 = lines.iter().find(|l| l["op"] == "clone3").unwrap();
    assert_eq!(clone3["errno"], "ENOSYS", "{context}");
    let thread = lines.iter().find(|l| l["op"] == "thread").unwrap();
    assert_eq!(thread["args"]["joined"], true, "{context}");
    let clone = lines.iter().find(|l| l["op"] == "clone").unwrap();
    assert!(clone["ret"].as_i64().unwrap() > 0, "{context}");
    let child = lines.iter().find(|l| l["op"] == "untraced-mkdir").unwrap();
    assert_eq!(
        child["errno"], "ENOSYS",
        "the untraced child fails closed\n{context}"
    );
    assert!(!untraced.exists());
    assert!(
        gap_reasons(&receipt)
            .iter()
            .any(|r| r == "untraced_descendant"),
        "{:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
        assert_eq!(entry["observed_count"], Value::Null, "{class}");
        let gap = entry["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["reason"] == "untraced_descendant")
            .unwrap_or_else(|| panic!("{class}: {entry:#}"));
        assert_eq!(
            gap["end_ns"],
            Value::Null,
            "{class}: its lifetime is not observed"
        );
    }
    assert_eq!(
        receipt["outcome"]["kind"], "exited",
        "{:#}",
        receipt["outcome"]
    );

    // Strict: the same gap stops the attempt.
    let c = case(ProfileName::None, "strict");
    let untraced = c.workspace.join("untraced");
    let steps = serde_json::json!([
        ["clone-untraced", untraced.to_str().unwrap()],
        ["sleep", "10000"]
    ]);
    let run = c.script("untraced-strict", &steps);
    let receipt = common::settled(&run);
    assert_eq!(
        receipt["outcome"]["cause"], "evidence_loss",
        "{:#}",
        receipt["outcome"]
    );
}

// ---------------------------------------------------------------------------
// §16 closed set: the published table
// ---------------------------------------------------------------------------

fn published_table_path() -> PathBuf {
    specs_dir().join(format!(
        "evidence/closed-set-{}.txt",
        ukai_jail::platform::linux::abi::TABLE_ARCH
    ))
}

/// §11.2: "The implementation must publish its exact hook/syscall table."
/// The table is generated from the observer's own rows and by running the
/// installed program; the checked-in evidence must be exactly it, and the
/// narrowing-filter digest it publishes must be the one a live receipt of
/// this build reads back — for a contained profile and for `none`, which
/// install the same program.
#[test]
fn j4_closed_set_the_published_table_is_the_one_this_build_traces() {
    let generated = ukai_jail::platform::linux::tracer::closed_set_table();
    let checked_in = std::fs::read_to_string(published_table_path())
        .unwrap_or_else(|e| panic!("{}: {e}", published_table_path().display()));
    assert_eq!(
        generated, checked_in,
        "the published closed-set table has drifted from what this build traces; \
         regenerate it with the ignored `bless_the_published_closed_set_table` and UKAI_BLESS=1"
    );
    let published = checked_in
        .lines()
        .find_map(|line| line.strip_prefix("narrowing filter digest: "))
        .expect("the table publishes the filter digest")
        .to_owned();
    for profile in [ProfileName::Tool, ProfileName::None] {
        if !common::profile_live(profile) {
            return;
        }
        let c = case(profile, "strict");
        let fixture = c.fixture.clone().into_os_string();
        let run = c.run_with_inputs(vec![fixture, "exit".into(), "0".into()], &[]);
        let receipt = common::settled(&run);
        assert_eq!(
            receipt["lifetime"]["native"]["details"]["narrowing_filter_digest"].as_str(),
            Some(published.as_str()),
            "{profile:?}: the receipt reads back another filter"
        );
        eprintln!("{profile:?}: receipt narrowing_filter_digest = {published}");
    }
}

/// Writes the published table from this build. Run by hand, on Linux,
/// after a deliberate change to the closed set or the narrowing filter:
/// `UKAI_BLESS=1 cargo test --test j4_closed_set_linux -- --ignored
/// bless_the_published_closed_set_table`. Without `UKAI_BLESS=1` it writes
/// nothing, so `--include-ignored` never rewrites checked-in evidence.
#[test]
#[ignore = "writes the evidence file with UKAI_BLESS=1; run deliberately"]
fn bless_the_published_closed_set_table() {
    if std::env::var_os("UKAI_BLESS").is_none_or(|value| value != "1") {
        eprintln!(
            "not blessing {}: set UKAI_BLESS=1 to rewrite it",
            published_table_path().display()
        );
        return;
    }
    std::fs::write(
        published_table_path(),
        ukai_jail::platform::linux::tracer::closed_set_table(),
    )
    .unwrap();
}
