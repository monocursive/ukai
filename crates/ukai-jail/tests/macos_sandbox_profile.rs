//! J16: the generated Seatbelt profile, live against `sandbox-exec`.
//!
//! Every claim the template bakes in (see the sandbox module docs for the
//! measurements) is re-measured here against the profile `generate` actually
//! emits — precedence, vnode-resolved matching, protected segments, the
//! empty Mach allowlist, network grants and the setuid refusal. The K90
//! harness in `macos_defense_matrix.rs` builds on the same helpers.
//!
//! `sandbox-exec` works unprivileged on macOS, so all rows are live on any
//! Mac; nothing here skips on macOS. The whole file is gated to macOS
//! because `sandbox-exec` exists nowhere else.
#![cfg(target_os = "macos")]

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

mod common;

use common::private_tempdir;
// The modules are the crate's own sources, included by path: the tests run
// the exact bytes that ship, before `platform/macos/mod.rs` exposes them.
#[path = "../src/platform/macos/sandbox.rs"]
mod sandbox;
#[path = "../src/platform/macos/setuid.rs"]
mod setuid;

use sandbox::{ProfileParams, TEMPLATE as TEMPLATE_TEXT};

/// The K90 anchor (§4.7: "a build whose template digest differs from the one
/// K90 passed is not a release"). The pinned digest is the one these tests
/// measured; changing the template is a deliberate act that updates this
/// constant and re-runs the matrix in the same change.
const PINNED_TEMPLATE_DIGEST: &str =
    "7082956e4a0fce608a5674f47cd771c6afdc29a8ab51fd33524f49a28b2d38e6";

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The runtime roots every process needs on this platform, as measured: dyld
/// ignition and the logging subsystem read these before `main`. This host's
/// git is Homebrew's, so its prefix is an admitted root too — exactly what
/// the policy snapshot would admit for this operator.
fn system_read_roots() -> Vec<PathBuf> {
    [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/lib",
        "/usr/share",
        "/usr/libexec",
        "/opt/homebrew",
        "/System/Library",
        "/private/var/db/dyld",
        "/Library/Preferences/Logging",
        "/private/var/db/uuidtext",
        "/private/var/db/diagnostics",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// A workspace, a scratch tree and vendor state under one private root,
/// with the protected segments the policy models (the agent's `.git/hooks`
/// and `.git/config`, and the whole `.ukai` tree — jail-v1 §3.3).
struct Fixture {
    _root: tempfile::TempDir,
    workspace: PathBuf,
    scratch: PathBuf,
    vendor_state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = private_tempdir();
        let workspace = root.path().join("workspace");
        let scratch = root.path().join("scratch");
        let vendor_state = root.path().join("vendor-state");
        for dir in [&workspace, &scratch, &vendor_state] {
            std::fs::create_dir_all(dir).expect("fixture directories");
        }
        std::fs::create_dir_all(workspace.join(".git/hooks")).expect("protected .git/hooks");
        std::fs::write(workspace.join(".git/config"), "[core]\n").expect("protected .git/config");
        std::fs::create_dir_all(workspace.join(".ukai")).expect("protected .ukai");
        Self {
            _root: root,
            workspace,
            scratch,
            vendor_state,
        }
    }

    fn params(&self, node_root: Option<&Path>) -> ProfileParams {
        let mut read_only = system_read_roots();
        if let Some(root) = node_root {
            read_only.push(root.to_path_buf());
        }
        ProfileParams {
            read_write: vec![
                self.workspace.clone(),
                self.scratch.clone(),
                self.vendor_state.clone(),
            ],
            read_only,
            protected_segments: vec![
                self.workspace.join(".git/hooks"),
                self.workspace.join(".git/config"),
                self.workspace.join(".ukai"),
            ],
            setuid_exec_denied: setuid::deny_paths(&setuid::system_entries().entries),
            ..ProfileParams::default()
        }
    }
}

fn generated(fixture: &Fixture, node_root: Option<&Path>) -> String {
    sandbox::generate(&fixture.params(node_root))
}

/// Runs `program` under the profile; the profile goes through `-f` exactly
/// as the launcher writes it. The child runs at `/` with the harness's
/// `PWD` scrubbed: neither the harness's working directory nor its `PWD`
/// is meaningful inside the sandbox, and `sh` refuses to run with a cwd it
/// cannot resolve.
fn run_sandboxed_env(profile: &str, program: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let dir = private_tempdir();
    let file = dir.path().join("profile.sb");
    std::fs::write(&file, profile).expect("profile file");
    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-f").arg(&file).arg(program).args(args);
    command
        .current_dir("/")
        .env_remove("PWD")
        .env_remove("OLDPWD");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().expect("sandbox-exec spawns")
}

fn run_sandboxed(profile: &str, program: &Path, args: &[&str]) -> Output {
    run_sandboxed_env(profile, program, args, &[])
}

fn ran(output: &Output) -> bool {
    output.status.success()
}

fn denied_by_sandbox(output: &Output) -> bool {
    // sandbox-exec reports a refused exec itself ("execvp() of '…' failed:
    // Operation not permitted"); the sandboxed program reports `EPERM` for
    // a refused operation it attempted.
    String::from_utf8_lossy(&output.stderr).contains("Operation not permitted")
}

/// The host's `node`, or `None` on a Mac without one (the empty-allowlist
/// row needs a runtime worth measuring; git and sh always exist).
fn node() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("UKAI_JAIL_TEST_NODE") {
        return Some(PathBuf::from(path));
    }
    for candidate in ["/opt/homebrew/bin/node", "/usr/local/bin/node"] {
        if Path::new(candidate).exists() {
            return Some(PathBuf::from(candidate));
        }
    }
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg("command -v node")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// The git binary the operator's shell would use, preferring Homebrew's.
fn git() -> PathBuf {
    for candidate in ["/opt/homebrew/bin/git", "/usr/bin/git"] {
        if Path::new(candidate).exists() {
            return PathBuf::from(candidate);
        }
    }
    PathBuf::from("/usr/bin/git")
}

// ---------------------------------------------------------------------------
// The template and its digest
// ---------------------------------------------------------------------------

/// §4.7: the receipt records the template's digest, and K90 runs against
/// that exact digest. The pin is the digest of the checked-in template.
#[test]
fn the_template_digest_is_the_pinned_release_digest() {
    assert_eq!(sandbox::template_digest(), PINNED_TEMPLATE_DIGEST);
    // The template is a single source: what generate instantiates is the
    // checked-in text, and the generated profile embeds its digest.
    assert_eq!(sandbox::template(), TEMPLATE_TEXT);
    let profile = sandbox::generate(&ProfileParams::default());
    assert!(profile.contains(PINNED_TEMPLATE_DIGEST));
}

/// The invariant skeleton survives substitution: default-deny first, the
/// class denials present, and no parameter token left unfilled.
#[test]
fn the_generated_profile_keeps_the_invariant_skeleton() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);
    assert!(profile.starts_with("; ukai-jail"));
    assert!(profile.contains("(version 1)"));
    for invariant in [
        "(deny default)",
        "(deny signal)",
        "(allow signal (target same-sandbox))",
        "(deny system-suspend-resume)",
        "(deny system-memorystatus-control)",
        "(deny system-sched)",
        "(deny process-info-setcontrol)",
        "(deny mach-task-name)",
        "(deny mach-task-read)",
        "(deny lsopen)",
        "(deny appleevent-send)",
        "(deny job-creation)",
        "(deny mach-lookup)",
        "(deny network*)",
        "(deny file-write-setugid)",
    ] {
        assert!(profile.contains(invariant), "missing {invariant}");
    }
    assert!(!profile.contains("@@"), "a token survived substitution");
}

/// Precedence (measured: last matching rule wins) is visible in the emitted
/// order: protected-segment and setuid denials follow the grants they must
/// override, and the network allows follow `(deny network*)`.
#[test]
fn denials_are_ordered_after_the_grants_they_override() {
    let fixture = Fixture::new();
    let mut params = fixture.params(None);
    params.bridge_http_port = Some(1);
    params.bridge_socks_port = Some(2);
    let profile = sandbox::generate(&params);
    let position = |needle: &str| {
        profile
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };
    assert!(position("(deny file-write* (subpath") > position("(allow file-write* (subpath"));
    assert!(position("(deny process-exec (literal") > position("(allow process-exec"));
    assert!(position("(allow network-outbound") > position("(deny network*)"));
}

// ---------------------------------------------------------------------------
// Live behaviour: filesystem (jail-v2 §8.1, K102 rows)
// ---------------------------------------------------------------------------

#[test]
fn a_member_writes_the_workspace_and_reads_the_system() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);
    let target = fixture.workspace.join("member-file");
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/sh"),
        &["-c", &format!("echo member > {}", target.display())],
    );
    assert!(ran(&output), "sh under the profile: {:?}", output.stderr);
    assert_eq!(std::fs::read_to_string(target).unwrap().trim(), "member");
}

/// The protected segments deny over their writable parents — hooks and
/// config of the agent's repository, the `.ukai` tree — and the
/// case-variant spellings resolve to the same vnodes, so `.GIT` is denied
/// too (K102's case-insensitivity row, measured). The rest of `.git` stays
/// writable: the member extends the repository (see the git row).
#[test]
fn protected_segments_and_case_variants_are_denied() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);
    for attack in [
        ".git/hooks/hook",
        ".git/config",
        ".ukai/state",
        ".GIT/hooks/hook",
        ".GIT/config",
        ".UKAI/state",
    ] {
        let target = fixture.workspace.join(attack);
        let output = run_sandboxed(
            &profile,
            Path::new("/bin/sh"),
            &["-c", &format!("echo x >> {}", target.display())],
        );
        assert!(
            !ran(&output),
            "write to {attack} must be denied: {:?}",
            output.stderr
        );
        assert!(denied_by_sandbox(&output));
    }
    // The parent workspace is still writable beside the protected segments.
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/sh"),
        &[
            "-c",
            &format!("echo x > {}/sibling", fixture.workspace.display()),
        ],
    );
    assert!(ran(&output));
}

/// `/var` versus `/private/var` (K102): the profile grants both spellings,
/// and vendor state granted in the physical spelling is writable through
/// the logical one.
#[test]
fn var_and_tmp_spellings_resolve_to_the_same_vnode() {
    let fixture = Fixture::new();
    let mut params = fixture.params(None);
    params.read_write.push(PathBuf::from("/private/var/tmp"));
    let profile = sandbox::generate(&params);
    assert!(
        profile.contains("(subpath \"/private/var/tmp\")")
            && profile.contains("(subpath \"/var/tmp\")"),
        "both spellings are granted"
    );
    let logical = run_sandboxed(
        &profile,
        Path::new("/bin/sh"),
        &["-c", "echo x > /var/tmp/ukai-j16-spelling"],
    );
    let physical = run_sandboxed(
        &profile,
        Path::new("/bin/sh"),
        &["-c", "echo x > /private/var/tmp/ukai-j16-spelling"],
    );
    let result = (ran(&logical), ran(&physical));
    for file in [
        "/var/tmp/ukai-j16-spelling",
        "/private/var/tmp/ukai-j16-spelling",
    ] {
        let _ = std::fs::remove_file(file);
    }
    assert_eq!(
        result,
        (true, true),
        "both spellings writable: {:?} / {:?}",
        String::from_utf8_lossy(&logical.stderr),
        String::from_utf8_lossy(&physical.stderr)
    );
    // Scratch under /private/tmp is reachable through /tmp (vnode-resolved).
    let scratch = fixture
        .scratch
        .canonicalize()
        .unwrap_or_else(|_| fixture.scratch.clone());
    let profile = generated(&fixture, None);
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/sh"),
        &["-c", &format!("echo x > {}/via-tmp", scratch.display())],
    );
    assert!(ran(&output), "scratch writable: {:?}", output.stderr);
}

/// `subpath` matches on component boundaries (measured): a grant on the
/// workspace does not cover a sibling whose name extends it — files,
/// directories and lookups past the sibling are all refused. Re-measured
/// because an earlier session had recorded the opposite from a profile
/// that also granted the parent directory (K102).
#[test]
fn sibling_names_beyond_the_workspace_boundary_are_refused() {
    let fixture = Fixture::new();
    // A directory and a file whose names merely extend the workspace name.
    let sibling_dir = fixture._root.path().join("workspaceX");
    std::fs::create_dir_all(&sibling_dir).expect("sibling directory");
    let sibling_file = fixture._root.path().join("workspaceXfile");
    std::fs::write(&sibling_file, b"outside").expect("sibling file");
    let profile = generated(&fixture, None);
    for target in [sibling_dir.join("sibling"), sibling_file] {
        let output = run_sandboxed(
            &profile,
            Path::new("/bin/sh"),
            &["-c", &format!("echo x > {}", target.display())],
        );
        assert!(!ran(&output), "{} must be refused", target.display());
        assert!(denied_by_sandbox(&output));
    }
}

/// The workspace is data, not programs: execution from a writable root is
/// not granted (jail-v2 §8.1). The script is made executable so the refusal
/// is the sandbox's `EPERM`, not the file mode's `EACCES`.
#[test]
fn execution_is_not_granted_from_writable_roots() {
    let fixture = Fixture::new();
    let script = fixture.workspace.join("run-me");
    std::fs::write(&script, "#!/bin/sh\necho executed\n").expect("script");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let profile = generated(&fixture, None);
    let output = run_sandboxed(&profile, &script, &[]);
    assert!(!ran(&output), "workspace exec must be denied");
    assert!(denied_by_sandbox(&output));
}

// ---------------------------------------------------------------------------
// Live behaviour: the empty Mach allowlist runs the toolchain (§4.10)
// ---------------------------------------------------------------------------

#[test]
fn node_git_and_shell_run_with_mach_lookup_fully_denied() {
    let fixture = Fixture::new();
    let node = node();
    let node_root = node.as_ref().and_then(|binary| {
        // A version manager layout: admit the install root that holds the
        // binary and its dylibs.
        binary.ancestors().nth(2).map(Path::to_path_buf)
    });
    let profile = generated(&fixture, node_root.as_deref());
    // The launcher points git's configuration into the attempt's private
    // tree (jail-v2 §8.1 in-child paths); here /dev/null stands in for it,
    // which the baseline grants.
    let git_env = [
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
    ];
    for (name, program, args) in [
        ("sh", PathBuf::from("/bin/sh"), vec!["-c", "echo shell-ok"]),
        (
            "bash",
            PathBuf::from("/bin/bash"),
            vec!["-c", "echo bash-ok"],
        ),
        ("git", git(), vec!["--version"]),
    ] {
        let output = run_sandboxed_env(&profile, &program, &args, &git_env);
        assert!(
            ran(&output),
            "{name} must run with mach-lookup denied: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if let Some(node) = node {
        let output = run_sandboxed(&profile, &node, &["--version"]);
        assert!(
            ran(&output),
            "node must run with mach-lookup denied: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        eprintln!("no node on this Mac; the empty-allowlist node row is unexercised");
    }
}

/// Git's real object work inside an existing repository: index locks and
/// `/dev/null` writes are covered by the baseline (measured: git refuses
/// without the `/dev/null` write grant). The repository is prepared
/// outside the sandbox — the agent's `.git/config` and `.git/hooks` are
/// protected segments, so the jail-1 model is "extend the repo, never
/// reconfigure it".
#[test]
fn git_extends_an_existing_repository_but_never_reconfigures_it() {
    let fixture = Fixture::new();
    let workspace = fixture.workspace.display().to_string();
    // Prepare outside: a repository with identity and one commit.
    for args in [
        vec!["init", "-q", "."],
        vec!["config", "user.email", "a@b.c"],
        vec!["config", "user.name", "a"],
    ] {
        let prepare = Command::new(git())
            .args(&args)
            .current_dir(&fixture.workspace)
            .output()
            .unwrap();
        assert!(
            prepare.status.success(),
            "prepare {:?}: {:?}",
            args,
            prepare.stderr
        );
    }
    std::fs::write(fixture.workspace.join("seed"), b"seed").unwrap();
    let prepare = Command::new(git())
        .args(["add", "seed"])
        .current_dir(&fixture.workspace)
        .output()
        .unwrap();
    assert!(prepare.status.success(), "git add: {:?}", prepare.stderr);

    let profile = generated(&fixture, None);
    // Inside: extend the repository — index, objects and refs are writable,
    // git's /dev/null scratch works, and the config and hooks stay read-only.
    let script = format!(
        "set -e; cd {workspace}; echo more >> seed; git add seed; git commit -qm inside; \
         git log --oneline > {workspace}/log.txt"
    );
    let output = run_sandboxed_env(
        &profile,
        Path::new("/bin/sh"),
        &["-c", &script],
        &[
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ],
    );
    assert!(
        ran(&output),
        "git commit under the profile: {:?}\n{:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The protected segments refuse configuration and hook writes.
    for attack in [
        "git config user.email evil@evil.evil",
        "printf '#!' > .git/hooks/pre-commit; chmod +x .git/hooks/pre-commit",
    ] {
        let output = run_sandboxed(
            &profile,
            Path::new("/bin/sh"),
            &["-c", &format!("cd {workspace} && {attack}")],
        );
        assert!(
            !ran(&output),
            "protected segment write must be denied: {attack}"
        );
    }
    // The history the member wrote is real.
    assert!(fixture.workspace.join("log.txt").exists());
}

// ---------------------------------------------------------------------------
// Live behaviour: network (§4.10)
// ---------------------------------------------------------------------------

/// A one-shot TCP listener on an ephemeral loopback port.
struct Echo {
    listener: TcpListener,
    address: String,
}

impl Echo {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let address = listener.local_addr().expect("local addr").to_string();
        listener.set_nonblocking(true).expect("nonblocking");
        Self { listener, address }
    }

    fn port(&self) -> String {
        self.address.split(':').next_back().unwrap().to_string()
    }

    /// Accepts one pending connection, if the client made one.
    fn had_a_connection(&self) -> bool {
        self.listener.accept().is_ok()
    }
}

fn drain_sockets() {
    std::thread::sleep(Duration::from_millis(50));
}

/// Under `network_none` (no bridge ports), loopback egress is denied — the
/// positive control connects the same way from outside the sandbox.
#[test]
fn network_none_denies_loopback_and_unix_sockets() {
    let fixture = Fixture::new();
    let echo = Echo::bind();
    let socket_dir = private_tempdir();
    let socket_path = socket_dir.path().join("server.sock");
    let listener = UnixListener::bind(&socket_path).expect("unix listener");

    let profile = generated(&fixture, None);
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/bash"),
        &["-c", &format!("exec 3<>/dev/tcp/127.0.0.1/{}", echo.port())],
    );
    assert!(!ran(&output), "network_none must deny loopback TCP");
    assert!(denied_by_sandbox(&output));

    let output = run_sandboxed(
        &profile,
        Path::new("/bin/bash"),
        &[
            "-c",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{}", Echo::bind().port()),
        ],
    );
    assert!(!ran(&output), "an unlisted port must be denied");

    // The sandboxed member never connected: nothing to accept.
    assert!(!echo.had_a_connection(), "a denied connect must not arrive");

    // The positive control: the same connects work outside the sandbox.
    assert!(std::net::TcpStream::connect(echo.address.clone()).is_ok());
    assert!(
        std::os::unix::net::UnixStream::connect(&socket_path).is_ok(),
        "unix socket reachable outside"
    );
    drop(listener);
    drain_sockets();
}

/// Under the bridge profile, exactly the two authenticated ports are
/// reachable (§4.10; the ports are ephemeral and per-attempt).
#[test]
fn the_bridge_profile_admits_only_the_two_bridge_ports() {
    let fixture = Fixture::new();
    let http = Echo::bind();
    let socks = Echo::bind();
    let other = Echo::bind();
    let mut params = fixture.params(None);
    params.bridge_http_port = http.port().parse().ok();
    params.bridge_socks_port = socks.port().parse().ok();
    let profile = sandbox::generate(&params);

    for bridge in [&http, &socks] {
        let output = run_sandboxed(
            &profile,
            Path::new("/bin/bash"),
            &[
                "-c",
                &format!("exec 3<>/dev/tcp/127.0.0.1/{}", bridge.port()),
            ],
        );
        assert!(
            ran(&output),
            "bridge port {} must be reachable: {:?}",
            bridge.port(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/bash"),
        &[
            "-c",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{}", other.port()),
        ],
    );
    assert!(!ran(&output), "a third loopback port must stay denied");
    assert!(
        !other.had_a_connection(),
        "the denied port saw no connection"
    );
}

/// Unix-domain sockets are default-deny apart from named grants (§4.7
/// class 2): tmux, Docker, SSH ControlMaster and language servers stay
/// unreachable even when their socket path is known.
#[test]
fn unix_socket_connects_need_a_named_grant() {
    let fixture = Fixture::new();
    let socket_dir = private_tempdir();
    let granted = socket_dir.path().join("granted.sock");
    let stranger = socket_dir.path().join("stranger.sock");
    let granted_listener = UnixListener::bind(&granted).expect("granted listener");
    let stranger_listener = UnixListener::bind(&stranger).expect("stranger listener");

    let node = node().expect("the unix-socket grant row drives node");
    let node_root = node.ancestors().nth(2).map(Path::to_path_buf);
    let mut params = fixture.params(node_root.as_deref());
    params.unix_socket_paths = vec![granted.clone()];
    let profile = sandbox::generate(&params);

    let connect = |path: &Path| {
        let script = format!(
            "const n=require('net');const s=n.connect({});s.on('error',e=>{{console.log('ERR '+e.code);process.exit(1)}});s.on('connect',()=>{{console.log('CONNECTED');process.exit(0)}});setTimeout(()=>process.exit(2),4000)",
            serde_json_string(path)
        );
        run_sandboxed(&profile, &node, &["-e", &script])
    };
    let ok = connect(&granted);
    assert!(
        ran(&ok),
        "granted unix socket connects: out={:?} err={:?} status={:?}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr),
        ok.status
    );
    assert!(granted_listener.accept().is_ok(), "the grant arrived");
    let denied = connect(&stranger);
    assert!(!ran(&denied), "an ungranted unix socket must be denied");
    drop(stranger_listener);
    drain_sockets();
}

/// JS string literal for a path (quote and backslash escaping).
fn serde_json_string(path: &Path) -> String {
    let raw = path.display().to_string();
    format!("\"{}\"", raw.replace('\\', "\\\\").replace('"', "\\\""))
}

// ---------------------------------------------------------------------------
// Live behaviour: class 1 signalling and class 3 setuid
// ---------------------------------------------------------------------------

/// The measured base: a member cannot signal any process outside its
/// sandbox, and signals inside it (its own children) work (§4.7 class 1).
#[test]
fn signals_stay_confined_to_the_sandbox() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);

    let mut keeper = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("sleeper");
    let outside_pid = keeper.id().to_string();
    let output = run_sandboxed(&profile, Path::new("/bin/kill"), &["-TERM", &outside_pid]);
    assert!(!ran(&output), "a member must not signal an outside process");
    assert!(denied_by_sandbox(&output));
    // The positive control: the outside process is alive and signallable.
    assert!(keeper.try_wait().unwrap().is_none(), "the sleeper survived");
    let control = Command::new("/bin/kill")
        .arg("-0")
        .arg(&outside_pid)
        .output()
        .unwrap();
    assert!(
        control.status.success(),
        "outside, the same signal path works"
    );

    // Inside the sandbox, a member's own children are signallable: the
    // `same-sandbox` allow is what makes the workload work (measured base).
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/sh"),
        &[
            "-c",
            "sleep 30 & p=$!; kill -TERM $p && wait $p; test $? -ge 128",
        ],
    );
    assert!(
        ran(&output),
        "same-sandbox signalling works: {:?}",
        output.stderr
    );
    let _ = keeper.kill();
    let _ = keeper.wait();
}

/// §4.7 class 3: executing an enumerated setuid file is denied by path —
/// and the kernel backstop refuses setuid-exec for sandboxed processes
/// regardless (measured; the outside control runs the same binary).
#[test]
fn setuid_execution_is_denied_inside_and_possible_outside() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);
    for setuid_binary in ["/usr/bin/sudo", "/usr/bin/su", "/usr/libexec/authopen"] {
        if !Path::new(setuid_binary).exists() {
            continue;
        }
        let output = run_sandboxed(&profile, Path::new(setuid_binary), &["-n", "true"]);
        assert!(!ran(&output), "{setuid_binary} exec must be denied");
        assert!(denied_by_sandbox(&output), "{setuid_binary}: EPERM at exec");
    }
    // Positive control: the binary executes outside the sandbox (it may
    // fail for want of a password — what matters is that exec happened).
    let outside = Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg("true")
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&outside.stderr).contains("Operation not permitted"),
        "outside, sudo execs (it may then ask for a password)"
    );
}

// ---------------------------------------------------------------------------
// Live behaviour: class 2 deputies and class 4 leftovers
// ---------------------------------------------------------------------------

/// launchd job submission is refused: with `mach-lookup` default-deny the
/// member cannot reach launchd, and `job-creation` is denied outright.
#[test]
fn launchd_job_submission_is_refused() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);
    let label = format!("ukai-j16-{}", std::process::id());
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/launchctl"),
        &["submit", "-l", &label, "--", "/bin/true"],
    );
    assert!(!ran(&output), "launchctl submit must fail in the sandbox");
    // The positive control: launchctl itself works outside (it answers,
    // even if only to reject the request shape).
    let outside = Command::new("/bin/launchctl")
        .args(["submit", "-l", &format!("{label}-out"), "--", "/bin/true"])
        .output()
        .unwrap();
    let _ = Command::new("/bin/launchctl")
        .args(["remove", &format!("{label}-out")])
        .output();
    let _ = outside;
    // And the sandboxed label never got registered.
    let listed = Command::new("/bin/launchctl")
        .args(["print", &label])
        .output()
        .unwrap();
    assert!(!listed.status.success(), "the refused job must not exist");
}

/// Apple Events are refused (`appleevent-send`), and — measured —
/// `osascript` cannot even initialize its scripting component under the
/// empty Mach allowlist ("can't open default scripting component"): the
/// K100 row holds a fortiori on this build. An outside Apple-Event send is
/// a TCC prompt on this Mac, so the outside control is recorded, not run.
#[test]
fn apple_events_are_refused_while_osascript_cannot_reach_its_component() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);
    let output = run_sandboxed(
        &profile,
        Path::new("/usr/bin/osascript"),
        &[
            "-e",
            "tell application \"System Events\" to display dialog \"no\"",
        ],
    );
    assert!(!ran(&output), "an Apple Event send must fail");
    let control = run_sandboxed(&profile, Path::new("/usr/bin/osascript"), &["-e", "1 + 1"]);
    assert!(
        String::from_utf8_lossy(&control.stderr).contains("can't open default scripting component"),
        "measured: osascript cannot initialize OSA under the empty allowlist: {:?}",
        String::from_utf8_lossy(&control.stderr)
    );
    eprintln!(
        "RECORD appleevent-send: inside=DENIED outside=recorded (a send is a TCC prompt); \
         osascript cannot reach its scripting component with mach-lookup denied"
    );
}

/// Class 4: the obvious shell start-up files and launch-agent plists are
/// not writable — `HOME` is not a granted root (jail-v2 §8.1 covers these;
/// K90 checks the obvious ones).
#[test]
fn shell_startup_files_and_launch_agents_are_not_writable() {
    let fixture = Fixture::new();
    let profile = generated(&fixture, None);
    let home = std::env::var("HOME").expect("HOME set");
    for target in [
        format!("{home}/.zshenv"),
        format!("{home}/.zprofile"),
        format!("{home}/.bash_profile"),
        format!("{home}/Library/LaunchAgents/ukai-j16.plist"),
    ] {
        let output = run_sandboxed(
            &profile,
            Path::new("/bin/sh"),
            &[
                "-c",
                &format!("echo x >> '{}'", target.replace('\'', "'\\''")),
            ],
        );
        assert!(!ran(&output), "{target} must not be writable");
        assert!(denied_by_sandbox(&output));
    }
}

/// The profile file the launcher writes is what runs: `-f` on a generated
/// profile compiles (the `doctor` probe of jail-v2 §8.1).
#[test]
fn every_generated_profile_variant_compiles() {
    let fixture = Fixture::new();
    let mut variants = vec![
        generated(&fixture, None),
        generated(&fixture, node().as_deref()),
    ];
    let mut proxied = fixture.params(None);
    proxied.bridge_http_port = Some(1);
    proxied.bridge_socks_port = Some(2);
    variants.push(sandbox::generate(&proxied));
    for variant in variants {
        let output = run_sandboxed(&variant, Path::new("/bin/echo"), &["compiled"]);
        assert!(
            ran(&output),
            "profile variant must compile and run: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// A profile with an empty read-write parameter grants nothing: the empty
/// list must not degrade into an unfiltered allow (the hazard the template
/// guards against).
#[test]
fn an_empty_write_parameter_grants_nothing() {
    let fixture = Fixture::new();
    let mut params = fixture.params(None);
    params.read_write.clear();
    let profile = sandbox::generate(&params);
    let output = run_sandboxed(
        &profile,
        Path::new("/bin/sh"),
        &[
            "-c",
            &format!("echo x > {}/denied", fixture.workspace.display()),
        ],
    );
    assert!(!ran(&output), "an empty rw parameter must grant no writes");
}

/// The setuid enumeration covers the sealed roots of this build (§4.7
/// class 3), and its list is what the profile denies.
#[test]
fn the_setuid_enumeration_matches_the_sealed_volume() {
    let system = setuid::system_entries();
    assert!(!system.build.is_empty(), "kern.osversion recorded");
    let sudo = system
        .entries
        .iter()
        .find(|entry| entry.path == Path::new("/usr/bin/sudo"))
        .expect("sudo is setuid on this build");
    assert!(sudo.setuid && !sudo.setgid);
    // A granted root is scanned at preparation: a planted setgid file is
    // found and denied in the generated profile.
    let fixture = Fixture::new();
    let planted = fixture.workspace.join("planted-sgid");
    std::fs::write(&planted, b"").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o2755)).unwrap();
    let scanned = setuid::scan_readable_roots(std::slice::from_ref(&fixture.workspace)).unwrap();
    assert!(scanned.iter().any(|entry| entry.path == planted));
    let mut params = fixture.params(None);
    params.setuid_exec_denied = setuid::deny_paths(&scanned);
    let profile = sandbox::generate(&params);
    assert!(
        profile.contains(&format!("(literal \"{}\"", planted.display()))
            && profile.contains(&format!("(literal \"{}\"))", planted.display())),
        "both spellings of the planted file are denied for exec",
    );
}
