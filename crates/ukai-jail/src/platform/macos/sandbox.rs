//! The macOS native tier's Seatbelt profile: one checked-in SBPL template,
//! instantiated from the resolved policy snapshot (jail-v2 §8.1, jail-macos
//! §4.7, §4.10).
//!
//! The template is a single Rust `const` ([`TEMPLATE`]); the receipt records
//! its SHA-256 digest ([`template_digest`]), and K90 (jail-v2 §9.1) runs
//! against that exact digest — a build whose digest differs from the one K90
//! passed is not a release (§4.7). [`generate`] substitutes the
//! snapshot-informed parameters into the template; the substitution never
//! reorders or removes an invariant rule, so a generated profile closes
//! exactly the classes the template closes.
//!
//! # Measured vocabulary and semantics (macOS 27.0.1, build 26A434)
//!
//! Every claim below was measured on this build with `sandbox-exec -p`
//! compile and behaviour probes; the K90 harness re-measures the load-bearing
//! ones against every shipped template (macos_defense_matrix.rs).
//!
//! **Version line.** `(version 1)` is required — `sandbox-exec` refuses a
//! profile without it ("no version specified"). `(version 3)` compiles but
//! `execvp` of any binary fails `EPERM` even with broad allows (measured with
//! and without `file-map-executable`), because Apple's own v3 profiles depend
//! on the `system.sb` import scaffolding (`mach-bootstrap`, `syscall*`). The
//! template pins `(version 1)`, which is also the spec's baseline.
//!
//! **Precedence: the LAST matching rule wins.** Measured both directions:
//! `(allow file-write* (subpath P))` followed by
//! `(deny file-write* (subpath P/.git))` denies `P/.git` writes;
//! the same two rules in the opposite order allow them. Therefore every
//! parametric deny rule is emitted after the allows it must override, and the
//! protected-segment denies follow the read-write grants.
//!
//! **Matching is vnode-resolved.** Seatbelt matches the resolved vnode, not
//! the requested spelling: a grant on `/private/tmp/x` allows a write issued
//! as `/tmp/x`, and a deny on `/bin/ps` denies an exec issued as `/BIN/PS`
//! (case-insensitive APFS: `.GIT` is caught by a `.git` deny — the K102 case
//! row needs no extra case coverage on this build). The `/var` versus
//! `/private/var` dual spelling of every grant is still emitted per §4.10;
//! it is belt and braces, and K90 re-measures the deny side.
//!
//! **`subpath` matches on component boundaries.** Measured with blanket and
//! scoped read grants alike: a grant on `…/workspace` does not cover a
//! sibling whose name extends it (`…/workspaceX`, file or directory —
//! writes, stats and lookups past the sibling are all refused), and a
//! protected `…/workspace/.git` does not accidentally deny
//! `…/workspace/.gitconfig`. An earlier session had recorded a raw-prefix
//! quirk; re-measurement showed that profile had also granted the parent
//! directory, and this record corrects it (K102).
//!
//! **The denied-operation vocabulary this build accepts** (compile-probed;
//! names absent from the kernel table fail with "unbound variable"):
//! `signal` (+ `target same-sandbox`), `system-suspend-resume`
//! (pid_suspend/pid_resume), `system-memorystatus-control`,
//! `system-sched` (priority), `process-info-setcontrol`
//! (proc_rlimit_control), `process-info-dirtycontrol`,
//! `process-info-ledger`, `mach-task-name` (task_for_pid /
//! task_name_for_pid), `mach-task-read`, `lsopen`, `appleevent-send`,
//! `job-creation`, `file-write-setugid`, `mach-lookup`, `network*`,
//! `network-outbound`, `system-socket`, `process-exec`,
//! `process-exec-interpreter`, `file-map-executable`, `pseudo-tty`.
//! There is **no** `ptrace`, `task_for_pid`, `pid_suspend`, or
//! `proc_terminate` operation on this build: task ports are governed by
//! `mach-task-name`/`mach-task-read`, and the exec-of-setuid backstop is
//! kernel-side (below). `send-signal` is a *filter* of `signal`, not an
//! operation. The measured base for §4.7 class 1 signalling is
//! `(deny signal)` + `(allow signal (target same-sandbox))`, under which the
//! spec reports 800/800 workload attempts returned `EPERM`.
//!
//! **Exec of setuid/setgid binaries is denied kernel-side for sandboxed
//! processes.** Measured: with `(allow process-exec (subpath "/usr/bin"))`,
//! exec of `/usr/bin/sudo` fails `EPERM` inside the sandbox while the same
//! command outside runs. The template still emits the per-path
//! `(deny process-exec (literal …))` rules for every enumerated setuid/setgid
//! file (§4.7 class 3 requires the path denial); the kernel behaviour is the
//! vnode-true backstop that also covers hardlinks to a setuid binary under a
//! granted path.
//!
//! **An empty Mach allowlist runs Node, Git and a shell.** Measured on this
//! Mac: `sh`, `bash`, `node --version` and `git --version` all complete with
//! `mach-lookup` fully denied. The allowlist parameter therefore starts
//! empty; the backend evaluation admits and justifies every later entry
//! (§4.10), and K90 probes each admitted service.
//!
//! **The one surprising startup read:** dyld ignition enumerates the root
//! directory — a `file-read-data` on `/` — while locating the shared cache;
//! without it every binary dies in `dyld4::CacheFinder` with SIGABRT
//! (measured via crash reports). The template grants exactly
//! `(allow file-read-data (literal "/"))`; the top-level directory *names*
//! of the boot volume are the only thing this exposes.
//!
//! **`file-map-executable` is inert under `(version 1)`** (no
//! `file-map-executable` allow is needed to map dylibs — measured). The
//! rules are carried anyway so the read-only roots stay correct if the
//! version line is ever revisited; a version bump re-runs K90.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The checked-in SBPL template: the single source whose digest the receipt
/// records and against which K90 runs (§4.7).
///
/// `@@NAME@@` tokens mark the points where [`generate`] substitutes the
/// parametric rule blocks; every other line is invariant. Order is
/// load-bearing: last matching rule wins (measured — see the module docs),
/// so parametric denies sit after the grants they must override.
pub const TEMPLATE: &str = r#"; ukai-jail native tier (macOS): defense profile.
; Template digest (SHA-256): @@TEMPLATE_DIGEST@@
; jail-macos §4.7 classes 1-4, jail-v2 §8.1 containment, jail-macos §4.10.
; SBPL semantics measured on this build: the LAST matching rule wins, and
; filters match the resolved vnode (case- and spelling-insensitive).
(version 1)
(deny default)

; --- §4.7 class 1: direct control of another process -----------------------
; Signals by every route the vocabulary exposes, confined to the sandbox
; (the measured base). pid_suspend/pid_resume, memorystatus_control,
; priority changes and proc_rlimit_control have no same-sandbox filter on
; this build and are denied outright; task ports via mach-task-name and
; mach-task-read close ptrace/task_for_pid/task_name_for_pid for every
; target, members included. An explicit process-info denial is necessary
; alongside the sysctl allowlist: default-deny alone still permits
; KERN_PROCARGS2 on this build, exposing another process's environment.
(deny signal)
(allow signal (target same-sandbox))
(deny system-suspend-resume)
(deny system-memorystatus-control)
(deny system-sched)
(deny process-info*)
(allow process-info* (target self))
(deny process-info-setcontrol)
(deny process-info-dirtycontrol)
(deny process-info-ledger)
(deny mach-task-name)
(deny mach-task-read)

; --- Runtime baseline -------------------------------------------------------
; dyld ignition enumerates the root directory while locating the shared
; cache; without this every exec dies in dyld4::CacheFinder (measured).
(allow file-read-data (literal "/"))
; No kern.proc* grant: it would expose other processes' argv/environment.
; Hardware facts include libSystem's hw.pagesize_compat and Rust's
; hw.optional.* feature probes. Kernel facts remain explicitly enumerated.
(allow sysctl-read
    (sysctl-name-prefix "hw.")
    (sysctl-name "kern.osrelease") (sysctl-name "kern.osversion")
    (sysctl-name "kern.ostype") (sysctl-name "kern.version")
    (sysctl-name "kern.argmax") (sysctl-name "kern.boottime")
    (sysctl-name "kern.maxfilesperproc") (sysctl-name "kern.maxprocperuid")
    (sysctl-name "machdep.cpu.brand_string") (sysctl-name "vm.loadavg"))
(allow file-ioctl (literal "/dev/dtracehelper"))
; Git opens /dev/null read-write and fails hard without the read half
; (measured with Homebrew's git).
(allow file-read* (literal "/dev/null"))
(allow file-write* (literal "/dev/null"))
(allow system-socket)
; Creating a file needs file-read-metadata on the parent directory (measured:
; open(O_CREAT) stats the parent), which the read grants below carry for the
; granted trees. Reaching a granted tree through the root symlinks adds one
; more lookup: the symlink itself (K102's /var versus /private/var row), and
; runtimes that realpath every path (Node's module loader) lstat each
; ancestor component, so the chain above every granted root is readable as
; metadata only — names on the chain, never listings, never data. getcwd
; reads the cwd vnode, so a member whose working directory is a granted
; root (the launcher sets it to the workspace) resolves its own position.
(allow file-read-metadata (literal "/tmp") (literal "/var") (literal "/private") (literal "/"))
@@ANCESTOR_METADATA@@
; The workload forks and spawns pipelines; the child inherits the sandbox,
; so a fork starts no process outside it (§4.7 closes exec, not fork).
(allow process-fork)

; --- Filesystem: read-only admitted roots (jail-v2 §8.1) -------------------
@@ACCESS_RULES@@
; --- Execution: admitted at the read-only roots only -----------------------
@@EXEC_RULES@@
; --- Protected segments, AFTER the grants they override --------------------
@@PROTECTED_RULES@@
; Literal ancestor denials pin guarded paths while their other children stay writable.
@@PATH_ANCHOR_RULES@@
; Explicit read denials override every grant, including ancestor metadata.
@@DENY_READ_RULES@@
; Terminal control is confined to this attempt's own slave vnode.
@@TERMINAL_RULES@@
; --- §4.7 class 3: no gaining another user ---------------------------------
; Executing every enumerated setuid/setgid file is denied by path; the
; kernel additionally refuses setuid-exec for any sandboxed process
; (measured), and file-write-setugid refuses creating new ones.
(deny file-write-setugid)
@@SETUID_RULES@@
; --- §4.7 class 2: asking another process to run something -----------------
; launchd job operations, LaunchServices and Apple Events are denied.
; mach-lookup is default-deny: only explicitly admitted services may be
; looked up, each justified by the backend evaluation (§4.10). Unix-domain
; sockets are default-deny apart from named grants, and network egress is
; denied except loopback to the attempt's two authenticated bridge ports.
(deny lsopen)
(deny appleevent-send)
(deny job-creation)
(deny mach-lookup)
@@MACH_ALLOW_RULE@@
(deny network*)
@@UNIX_ALLOW_RULE@@
@@BRIDGE_ALLOW_RULE@@
"#;

/// The parameters [`generate`] substitutes into [`TEMPLATE`].
///
/// Paths must be absolute; the policy snapshot resolves them before the
/// profile is composed. Path order is preserved (the receipt's parameter
/// record mirrors it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileParams {
    /// Read-write roots: the workspace, scratch and vendor-state directories.
    pub read_write: Vec<PathBuf>,
    /// Read-only roots: the admitted system roots and `--from-path` pins.
    pub read_only: Vec<PathBuf>,
    /// Explicit read denials, applied after all grants.
    pub deny_read: Vec<PathBuf>,
    /// The attempt's pty slave, never a wildcard over /dev/ttys*.
    pub terminal_slave: Option<PathBuf>,
    /// Protected segments denied for writing over the writable parents
    /// (`.git`, `.ukai`, an agent's `.git/hooks` and `.git/config`).
    pub protected_segments: Vec<PathBuf>,
    /// Every setuid/setgid file found in the readable roots (§4.7 class 3),
    /// from `crate::platform::macos::setuid` — denied for exec by path.
    pub setuid_exec_denied: Vec<PathBuf>,
    /// Enumeration holes; the kernel setuid-exec backstop still applies.
    pub setuid_scan_holes: Vec<PathBuf>,
    /// Admitted `mach-lookup` service names. Starts empty: measured on this
    /// build, Node, Git and a shell run with lookup fully denied. The
    /// backend evaluation pins the final list; K90 probes every entry.
    pub mach_services: Vec<String>,
    /// Unix-domain socket paths a member may connect to (named grants;
    /// default-deny otherwise — tmux, Docker, SSH ControlMaster and language
    /// servers stay unreachable).
    pub unix_socket_paths: Vec<PathBuf>,
    /// The attempt bridge's HTTP port on loopback (`None` under
    /// `network_none`).
    pub bridge_http_port: Option<u16>,
    /// The attempt bridge's SOCKS5 port on loopback (`None` under
    /// `network_none`).
    pub bridge_socks_port: Option<u16>,
}

impl ProfileParams {
    /// Public parameters only: never proxy secrets or environment values.
    #[must_use]
    pub fn receipt(&self) -> serde_json::Value {
        serde_json::json!({
            "read_write": self.read_write, "read_only": self.read_only, "deny_read": self.deny_read,
            "protected_segments": self.protected_segments, "path_anchors": path_anchors(self),
            "setuid_exec_denied": self.setuid_exec_denied,
            "setuid_scan_holes": self.setuid_scan_holes.iter().map(|p| p.as_os_str().as_encoded_bytes()).collect::<Vec<_>>(),
            "setuid_backstop": "kernel_sandbox_exec_denial",
            "mach_services": self.mach_services, "unix_socket_paths": self.unix_socket_paths,
            "terminal_slave": self.terminal_slave, "bridge_http_port": self.bridge_http_port,
            "bridge_socks_port": self.bridge_socks_port,
        })
    }
}

/// The SBPL template, for readers and the receipt tooling.
#[must_use]
pub fn template() -> &'static str {
    TEMPLATE
}

/// The SHA-256 digest of [`TEMPLATE`], hex-encoded. The receipt records this
/// (§4.7); K90 runs against this exact digest.
#[must_use]
pub fn template_digest() -> String {
    digest(TEMPLATE)
}

/// The SHA-256 digest of `text`, hex-encoded.
#[must_use]
pub fn digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Instantiates [`TEMPLATE`] with the snapshot-informed parameters.
///
/// The substitution only ever fills the parametric rule blocks; invariant
/// rules and their order come from the template, so a generated profile
/// closes exactly the classes the template closes (§4.7).
#[must_use]
pub fn generate(params: &ProfileParams) -> String {
    // Compatibility entry point. Invalid input grants nothing; production
    // calls try_generate and reports a typed refusal before spawning.
    try_generate(params).unwrap_or_else(|_| "(version 1)(deny default)".to_owned())
}

/// Validate and generate a profile, refusing byte paths and template markers.
/// Literal SBPL strings are escaped once, and replacement text is NEVER
/// parsed for template tokens. The launch-block interface currently carries
/// source only; these constants have the same evaluation semantics as -D
/// string parameters. Moving the transport to -D requires the guardian API.
pub fn try_generate(params: &ProfileParams) -> Result<String, String> {
    for path in params
        .read_only
        .iter()
        .chain(&params.read_write)
        .chain(&params.deny_read)
        .chain(&params.protected_segments)
        .chain(&params.setuid_exec_denied)
        .chain(&params.unix_socket_paths)
        .chain(params.terminal_slave.iter())
    {
        let Some(text) = path.to_str() else {
            return Err("profile path is not UTF-8".into());
        };
        if !path.is_absolute() || text.contains("@@") || text.contains('\0') {
            return Err(format!("invalid profile path: {path:?}"));
        }
    }
    if params
        .mach_services
        .iter()
        .any(|s| s.contains("@@") || s.contains('\0'))
    {
        return Err("invalid Mach service name".into());
    }
    let mut output = String::new();
    // Scan only TEMPLATE. User data can never become a subsequent token.
    let mut pieces = TEMPLATE.split("@@");
    output.push_str(pieces.next().unwrap_or_default());
    while let Some(token) = pieces.next() {
        let value = match token {
            "TEMPLATE_DIGEST" => template_digest(),
            "ACCESS_RULES" => access_rules(params),
            "ANCESTOR_METADATA" => ancestor_metadata(&params.read_only, &params.read_write),
            "EXEC_RULES" => exec_rules(&params.read_only),
            "PROTECTED_RULES" => protected_rules(&params.protected_segments),
            "PATH_ANCHOR_RULES" => file_rules("deny file-write*", &path_anchors(params), &|p| {
                format!("(literal {})", sbpl_string(p))
            }),
            // Read denials also pin the denied vnode/subtree: otherwise a
            // writable sibling name bypasses a pathname-only read denial.
            "DENY_READ_RULES" => {
                file_rules("deny file-read* file-write*", &params.deny_read, &|p| {
                    format!("(subpath {})", sbpl_string(p))
                })
            }
            "TERMINAL_RULES" => file_rules(
                "allow file-ioctl",
                &params.terminal_slave.iter().cloned().collect::<Vec<_>>(),
                &|p| format!("(literal {})", sbpl_string(p)),
            ),
            "SETUID_RULES" => setuid_rules(&params.setuid_exec_denied),
            "MACH_ALLOW_RULE" => mach_allow_rule(&params.mach_services),
            "UNIX_ALLOW_RULE" => unix_allow_rule(&params.unix_socket_paths),
            "BRIDGE_ALLOW_RULE" => {
                bridge_allow_rule(params.bridge_http_port, params.bridge_socks_port)
            }
            _ => return Err(format!("unknown profile token {token}")),
        };
        output.push_str(&value);
        output.push_str(pieces.next().ok_or("unterminated template token")?);
    }
    Ok(output)
}

/// Baseline reads/execution needed by system binaries and their loader.
/// Operator-installed tools still require explicit policy or --from-path grants.
#[must_use]
pub fn runtime_roots() -> Vec<PathBuf> {
    [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/libexec",
        "/usr/share",
        "/System/Library",
        "/private/var/db/dyld",
        "/Library/Preferences/Logging",
        "/private/var/db/uuidtext",
        "/private/var/db/diagnostics",
    ]
    .into_iter()
    .map(PathBuf::from)
    .filter(|path| path.exists())
    .collect()
}

/// More specific filesystem grants override parents, as in the policy
/// resolver. Read-only children revoke writes granted by an ancestor.
fn access_rules(params: &ProfileParams) -> String {
    let mut paths: Vec<_> = params
        .read_only
        .iter()
        .map(|p| (p, false))
        .chain(params.read_write.iter().map(|p| (p, true)))
        .collect();
    paths.sort_by_key(|(path, write)| (path.components().count(), *path, *write));
    paths
        .into_iter()
        .map(|(path, write)| {
            let one = std::slice::from_ref(path);
            if write {
                write_rules(one)
            } else {
                format!(
                    "{}{}",
                    read_rules(one),
                    file_rules("deny file-write*", one, &|p| format!(
                        "(subpath {})",
                        sbpl_string(p)
                    ))
                )
            }
        })
        .collect()
}

/// `file-read-metadata` on every ancestor component above the granted
/// roots, in both spellings: resolving a granted path (the `/var` symlink,
/// Node's `realpath`, `getcwd`, `stat`, `cd`) walks the *resolved* chain —
/// `/private/var/…` — and each component is lstat'd on the way, so a
/// missing link fails the whole path. Metadata only: the chain's component
/// names are visible, their contents are not. Components that are
/// themselves granted roots are skipped (their subpath grant covers them).
fn ancestor_metadata(read_only: &[PathBuf], read_write: &[PathBuf]) -> String {
    let granted: std::collections::BTreeSet<String> = read_only
        .iter()
        .chain(read_write)
        .flat_map(|path| spellings(path))
        .collect();
    let mut ancestors = std::collections::BTreeSet::new();
    for path in read_only.iter().chain(read_write) {
        let mut current = path.as_path();
        while let Some(parent) = current.parent() {
            for spelling in spellings(parent) {
                if spelling != "/" && !granted.contains(&spelling) {
                    ancestors.insert(spelling);
                }
            }
            current = parent;
        }
    }
    if ancestors.is_empty() {
        return String::new();
    }
    let mut rule = String::from("(allow file-read-metadata");
    for ancestor in ancestors {
        rule.push_str(" (literal ");
        rule.push_str(&sbpl_string(&ancestor));
        rule.push(')');
    }
    rule.push_str(")\n");
    rule
}

/// An SBPL string literal: the only characters needing escapes inside a
/// profile string are the backslash and the double quote.
fn sbpl_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Both spellings of a path across the system's root symlinks (§4.10: grant
/// `/var` and `/private/var` alike; matching is vnode-resolved, so this is
/// belt and braces — K102 re-measures it).
fn spellings(path: &Path) -> Vec<String> {
    let raw = require_absolute(path);
    let mut all = vec![raw.clone()];
    for (logical, physical) in [("/tmp", "/private/tmp"), ("/var", "/private/var")] {
        if raw == *physical {
            all.push(logical.to_string());
        } else if let Some(rest) = raw.strip_prefix(&format!("{physical}/")) {
            all.push(format!("{logical}/{rest}"));
        } else if raw == *logical {
            all.push(physical.to_string());
        } else if let Some(rest) = raw.strip_prefix(&format!("{logical}/")) {
            all.push(format!("{physical}/{rest}"));
        }
    }
    all.sort();
    all.dedup();
    all
}

fn require_absolute(path: &Path) -> String {
    let raw = path.to_str().expect("validated UTF-8 path").to_owned();
    assert!(
        path.is_absolute(),
        "profile parameters must be absolute paths, got {raw:?}"
    );
    raw
}

/// A file-op rule over the granted roots, or, for an empty parameter, a rule
/// whose filter rejects every path (an unfiltered `allow` would allow the
/// operation unconditionally — the empty list must mean "grant nothing").
fn file_rules(allow: &str, paths: &[PathBuf], filter: &dyn Fn(&str) -> String) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let mut rules = String::new();
    rules.push('(');
    rules.push_str(allow);
    for path in paths {
        for spelling in spellings(path) {
            rules.push(' ');
            rules.push_str(&filter(&spelling));
        }
    }
    rules.push_str(")\n");
    rules
}

/// Read-only grants: `file-read*`, `file-test-existence` and
/// `file-map-executable` over the admitted roots.
fn read_rules(paths: &[PathBuf]) -> String {
    let subpath = |spelling: &str| format!("(subpath {})", sbpl_string(spelling));
    format!(
        "{}{}{}",
        file_rules("allow file-read*", paths, &subpath),
        file_rules("allow file-test-existence", paths, &subpath),
        file_rules("allow file-map-executable", paths, &subpath)
    )
}

/// Read-write grants: read, existence, write and ioctl (Git's index locks
/// take `fcntl` locks) over the workspace, scratch and vendor-state roots.
fn write_rules(paths: &[PathBuf]) -> String {
    let subpath = |spelling: &str| format!("(subpath {})", sbpl_string(spelling));
    format!(
        "{}{}{}{}",
        file_rules("allow file-read*", paths, &subpath),
        file_rules("allow file-test-existence", paths, &subpath),
        file_rules("allow file-write*", paths, &subpath),
        file_rules("allow file-ioctl", paths, &subpath)
    )
}

/// Execution stays at the admitted (read-only) roots: the workspace is
/// data, not programs (jail-v2 §8.1). Interpreters get their own operation
/// so shebang scripts at granted roots run.
fn exec_rules(paths: &[PathBuf]) -> String {
    let subpath = |spelling: &str| format!("(subpath {})", sbpl_string(spelling));
    format!(
        "{}{}",
        file_rules("allow process-exec", paths, &subpath),
        file_rules("allow process-exec-interpreter", paths, &subpath)
    )
}

/// A pathname deny is stable only while the workload cannot rename/delete
/// its ancestors. Deny writes on each ancestor vnode *literally*, excluding
/// a writable root unless another writable root also contains it. Descendant
/// creation (for example .git/objects) remains permitted. Source-side
/// file-write denials also prevent hard links out of the guarded subtree.
fn path_anchors(params: &ProfileParams) -> Vec<PathBuf> {
    params
        .protected_segments
        .iter()
        .chain(&params.deny_read)
        .flat_map(|path| path.ancestors().skip(1))
        .filter(|ancestor| {
            params
                .read_write
                .iter()
                .any(|root| *ancestor != root && ancestor.starts_with(root))
        })
        .map(Path::to_path_buf)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Protected segments: write-denials over the writable parents, emitted
/// after the grants so the last matching rule is the deny (measured).
fn protected_rules(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let subpath = |spelling: &str| format!("(subpath {})", sbpl_string(spelling));
    file_rules("deny file-write*", paths, &subpath)
}

/// Per-path exec denials for the enumerated setuid/setgid files (§4.7
/// class 3). `literal` matches exactly; vnode-resolved matching handles the
/// case-variant spellings (measured), and the kernel-side setuid-exec
/// refusal backstops every path not in the enumeration.
fn setuid_rules(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let literal = |spelling: &str| format!("(literal {})", sbpl_string(spelling));
    file_rules("deny process-exec", paths, &literal)
}

/// The `mach-lookup` allowlist rule, only when non-empty: absent, the
/// template's `(deny mach-lookup)` leaves the default-deny in force.
fn mach_allow_rule(services: &[String]) -> String {
    if services.is_empty() {
        return String::new();
    }
    let mut rule = String::from("(allow mach-lookup");
    for service in services {
        rule.push_str(" (global-name ");
        rule.push_str(&sbpl_string(service));
        rule.push(')');
    }
    rule.push_str(")\n");
    rule
}

/// Unix-domain socket connect grants (§4.7 class 2): only the named paths,
/// in both spellings — clients resolve the path before connecting (Node's
/// `net.connect` realpaths it), and the filter matches the resolved string.
fn unix_allow_rule(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let mut rule = String::from("(allow network-outbound");
    for path in paths {
        for spelling in spellings(path) {
            rule.push_str(" (remote unix-socket (path ");
            rule.push_str(&sbpl_string(&spelling));
            rule.push_str("))");
        }
    }
    rule.push_str(")\n");
    rule
}

/// Loopback egress to the attempt bridge's two authenticated ports only
/// (§4.10). `localhost` is the accepted loopback host token in SBPL `remote
/// ip` filters; a numeric literal fails to compile ("host must be * or
/// localhost"). Under `network_none` neither port exists and no allow is
/// emitted.
fn bridge_allow_rule(http: Option<u16>, socks: Option<u16>) -> String {
    let ports: Vec<u16> = [http, socks].into_iter().flatten().collect();
    if ports.is_empty() {
        return String::new();
    }
    let mut rule = String::from("(allow network-outbound");
    for port in ports {
        rule.push_str(&format!(" (remote ip \"localhost:{port}\")"));
    }
    rule.push_str(")\n");
    rule
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ProfileParams {
        ProfileParams {
            read_write: vec![PathBuf::from("/ws"), PathBuf::from("/private/tmp/scratch")],
            read_only: vec![PathBuf::from("/usr/lib"), PathBuf::from("/bin")],
            deny_read: Vec::new(),
            terminal_slave: None,
            protected_segments: vec![PathBuf::from("/ws/.git"), PathBuf::from("/ws/.ukai")],
            setuid_exec_denied: vec![PathBuf::from("/usr/bin/sudo")],
            setuid_scan_holes: Vec::new(),
            mach_services: Vec::new(),
            unix_socket_paths: Vec::new(),
            bridge_http_port: Some(8080),
            bridge_socks_port: Some(8081),
        }
    }

    #[test]
    fn template_declares_version_and_default_deny_first() {
        let body = TEMPLATE.trim_start();
        let after_comment = body
            .lines()
            .find(|line| !line.starts_with(';'))
            .expect("a non-comment line");
        assert_eq!(after_comment, "(version 1)");
        assert!(TEMPLATE.contains("(deny default)"));
        let default_deny = TEMPLATE.find("(deny default)").expect("deny default");
        let first_class = TEMPLATE.find("(deny signal)").expect("class 1");
        assert!(default_deny < first_class);
    }

    #[test]
    fn generate_keeps_the_invariant_skeleton_and_fills_parameters() {
        let profile = generate(&params());
        assert_eq!(params().receipt()["read_write"][0], "/ws");
        assert!(profile.contains("(allow file-write* (subpath \"/ws\")"));
        assert!(profile.contains("(subpath \"/tmp/scratch\")"));
        assert!(profile.contains("(deny file-write* (subpath \"/ws/.git\")"));
        assert!(profile.contains("(deny process-exec (literal \"/usr/bin/sudo\")"));
        assert!(profile.contains("(remote ip \"localhost:8080\")"));
        assert!(profile.contains(&format!(
            "; Template digest (SHA-256): {}",
            template_digest()
        )));
        // No token survives substitution.
        assert!(!profile.contains("@@"));
    }

    #[test]
    fn denials_are_ordered_after_the_grants_they_override() {
        let profile = generate(&params());
        let write_grant = profile
            .find("(allow file-write* (subpath \"/ws\")")
            .expect("rw grant");
        let protected_deny = profile
            .find("(deny file-write* (subpath \"/ws/.git\")")
            .expect("protected deny");
        let exec_grant = profile.find("(allow process-exec").expect("exec grant");
        let setuid_deny = profile
            .find("(deny process-exec (literal \"/usr/bin/sudo\")")
            .expect("setuid deny");
        let network_deny = profile.find("(deny network*)").expect("network deny");
        let bridge_allow = profile
            .find("(allow network-outbound (remote ip")
            .expect("bridge allow");
        assert!(
            protected_deny > write_grant,
            "protected denies follow rw grants"
        );
        assert!(setuid_deny > exec_grant, "setuid denies follow exec grants");
        assert!(
            bridge_allow > network_deny,
            "bridge allow follows network deny"
        );
    }

    #[test]
    fn empty_parameters_grant_nothing() {
        let profile = generate(&ProfileParams::default());
        // The unfiltered-allow hazard: an empty read-write parameter must
        // produce a rule that rejects every path, not an unconditional allow.
        assert!(!profile.contains("require-none"));
        assert!(!profile.contains("(allow network-outbound"));
        assert!(!profile.contains("(allow mach-lookup"));
        assert!(!profile.contains("(allow file-write* )"));
        assert!(!profile.contains("@@"));
    }

    #[test]
    fn var_and_tmp_spellings_are_both_granted() {
        let p = ProfileParams {
            read_write: vec![
                PathBuf::from("/private/var/vendor-state"),
                PathBuf::from("/tmp/scratch"),
            ],
            ..ProfileParams::default()
        };
        let profile = generate(&p);
        assert!(profile.contains("(subpath \"/private/var/vendor-state\")"));
        assert!(profile.contains("(subpath \"/var/vendor-state\")"));
        assert!(profile.contains("(subpath \"/tmp/scratch\")"));
        assert!(profile.contains("(subpath \"/private/tmp/scratch\")"));
    }

    #[test]
    fn the_template_digest_is_sha256_of_the_template() {
        // Independent recomputation via the public helper.
        assert_eq!(template_digest(), digest(TEMPLATE));
        assert_eq!(template_digest().len(), 64);
    }

    #[test]
    fn sbpl_strings_escape_quotes_and_backslashes() {
        assert_eq!(sbpl_string("/a\"b\\c"), "\"/a\\\"b\\\\c\"");
    }
}
