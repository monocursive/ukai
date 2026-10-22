//! J12: zero-config launch (jail-launch-and-summary.md §3.2 to §3.4).
//!
//! - [`discover_workspace`]: with `--from-path` and no `--workspace`, the
//!   nearest git top level, found by a no-follow walk; `git` itself is
//!   never run (a repository's own configuration can make it execute
//!   commands, `core.fsmonitor` for one, with the operator's authority).
//! - [`home_workspace`]: on every contained run, a workspace that is `/`,
//!   the operator's home or an ancestor of it refuses (§7, decision 2);
//!   `doctor` reports it instead (§8 item 5).
//! - [`program_layer`] and [`check_program_placement`]: the read-only
//!   install roots of the resolved program, as an operator layer before the
//!   project file (which can still deny-read them), and the refusals of
//!   §3.3 step 4.
//! - [`select_credentials`] and [`bind_program_token`]: the launch-profile
//!   keys `credentials_one_of` and `binaries = ["@program"]` (§3.4).
//! - [`child_cwd`]: the child starts where the operator stood, when that is
//!   beneath the workspace (§3.2 step 4).

use std::ffi::OsStr;
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::{Context, canonical_existing_prefix, child_writable_roots, overlaps, usage};
use crate::launch_profile::LaunchProfile;
use crate::policy::{Layer, LayerOrigin, PolicyDelta, ProvenanceEntry, Resolved, RootToken};
use crate::program::Program;
use crate::records::{ErrorCode, ErrorStage, JailError, NativeString, Remediation};
use crate::state::anchored::{self, Dir, Kind, Name};

/// The largest `.git` file read: git's own gitfile is one short line.
const GITFILE_MAX: u64 = 4096;

/// The provenance origin of everything `--from-path` derived (§3.3 step 6).
pub(super) const ORIGIN: &str = "program-resolution";

fn widening(key: &str, message: String) -> JailError {
    JailError::new(
        ErrorCode::PolicyWidening,
        ErrorStage::Resolving,
        Remediation::Configuration,
        message,
    )
    .with_key_path(key)
}

// ---------------------------------------------------------------------------
// The group-writable rule (jail-macos.md §4.11)
// ---------------------------------------------------------------------------

/// jail-macos.md §4.11: J12 refuses a group-writable install directory, and
/// Homebrew's `/opt/homebrew/bin` is group-writable by `admin`, which on the
/// reference Mac holds exactly `root` and the operator. A group-writable
/// directory is therefore accepted only when its group's member list, read
/// at preparation, resolves to exactly `root` and the operator: no third
/// member, no unresolvable member (which is what a nested group's name in
/// `gr_mem` would be — nested groups are refused by not resolving), and no
/// empty list (an empty `gr_mem` may hide membership the directory database
/// does not enumerate, so it refuses).
///
/// `resolve` maps a member name to its uid; `None` is an unresolvable
/// member. The rule is pure so a test can state the database.
pub(crate) fn group_writable_ok(
    _group_name: &str,
    members: &[&str],
    root_uid: u32,
    operator_uid: u32,
    resolve: &dyn Fn(&str) -> Option<u32>,
) -> bool {
    if members.is_empty() {
        return false;
    }
    let mut uids: Vec<u32> = Vec::with_capacity(members.len());
    for member in members {
        match resolve(member) {
            Some(uid) => uids.push(uid),
            // A name the user database does not answer (a nested group, or
            // a deleted account still listed) refuses.
            None => return false,
        }
    }
    uids.sort_unstable();
    uids.dedup();
    uids.len() == 2 && uids.contains(&root_uid) && uids.contains(&operator_uid)
}

/// The macOS wrapper: the group `gid`'s own member list from the group
/// database, resolved through the user database, against root and this
/// operator. `false` when the group cannot be read at all.
#[cfg(target_os = "macos")]
pub(crate) fn group_writable_install_dir(gid: u32) -> bool {
    let operator_uid = crate::state::effective_uid();
    let Ok(Some(group)) = crate::state::accounts::group(gid) else {
        return false;
    };
    let members: Vec<&str> = group
        .members
        .iter()
        .map(|member| std::str::from_utf8(member.as_slice()).unwrap_or(""))
        .collect();
    let name = String::from_utf8_lossy(&group.name).into_owned();
    group_writable_ok(&name, &members, 0, operator_uid, &uid_of_name)
}

/// The non-macos stub: the rule is a macOS amendment (§4.11); Linux keeps
/// J12's unconditional refusal.
#[cfg(not(target_os = "macos"))]
pub(crate) fn group_writable_install_dir(_gid: u32) -> bool {
    false
}

/// The uid a member name resolves to, or `None` when the user database has
/// no such account.
#[cfg(target_os = "macos")]
fn uid_of_name(name: &str) -> Option<u32> {
    use std::ffi::CString;

    let Ok(name) = CString::new(name) else {
        return None;
    };
    // SAFETY: `passwd` is a plain C struct; all-zero is a valid value that
    // getpwnam_r overwrites before it is read.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    // SAFETY: every pointer is to a live local, the length is the buffer's
    // own, and getpwnam_r writes only within them.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &raw mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(entry.pw_uid)
}

// ---------------------------------------------------------------------------
// The workspace (§3.2)
// ---------------------------------------------------------------------------

/// The nearest directory at or above `cwd` holding a `.git` entry that is
/// either a directory containing `HEAD` or a regular file of at most 4 KiB
/// whose first line begins `gitdir: ` (§3.2 step 1). The walk opens every
/// directory from `/` with no symlink followed and stops, as git does by
/// default, where the device changes. Nothing outside a repository is
/// guessed (step 2).
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `--workspace` outside a repository, or
/// when the invocation directory cannot be walked.
pub(super) fn discover_workspace(cwd: &Path) -> Result<PathBuf, JailError> {
    let unreadable = |error: std::io::Error| {
        usage(
            "--workspace",
            format!(
                "the invocation directory {} cannot be walked to find its repository: {error}",
                cwd.display()
            ),
        )
    };
    let cwd = std::fs::canonicalize(cwd).map_err(unreadable)?;
    let components = anchored::split_absolute(cwd.as_os_str().as_bytes()).map_err(unreadable)?;
    let mut levels: Vec<(PathBuf, Dir, anchored::Stat)> = Vec::with_capacity(components.len() + 1);
    let root = Dir::open_root_for_walk().map_err(unreadable)?;
    let root_stat = root.stat().map_err(unreadable)?;
    levels.push((PathBuf::from("/"), root, root_stat));
    for component in &components {
        let (parent_path, parent, _) = levels.last().expect("the root is first");
        let path = parent_path.join(OsStr::from_bytes(component.as_bytes()));
        let stat = parent.stat_at(component).map_err(unreadable)?;
        if stat.kind != Kind::Directory {
            return Err(unreadable(std::io::Error::other(format!(
                "{} is {}",
                path.display(),
                stat.kind.describe()
            ))));
        }
        let dir = parent
            .open_walk_at(component, Some(&stat))
            .map_err(unreadable)?;
        levels.push((path, dir, stat));
    }
    let found = nearest_top(
        levels
            .iter()
            .map(|(path, dir, stat)| (path.as_path(), stat.dev, || is_repository_top(dir))),
    );
    if let Some(top) = found {
        return Ok(top.to_path_buf());
    }
    Err(usage(
        "--workspace",
        format!(
            "{} is not inside a git repository; pass --workspace PATH",
            cwd.display()
        ),
    ))
}

/// The deepest level, walking up from the last, that is a repository's top
/// level, never crossing to another device than the last level's
/// (GIT_DISCOVERY_ACROSS_FILESYSTEM is off by default). `levels` run from
/// `/` down; each is its path, its device and how to ask whether it is a top
/// level, asked only for levels on the starting device.
fn nearest_top<'a, F: Fn() -> bool>(
    levels: impl DoubleEndedIterator<Item = (&'a Path, u64, F)>,
) -> Option<&'a Path> {
    let mut device = None;
    for (path, dev, is_top) in levels.rev() {
        if *device.get_or_insert(dev) != dev {
            return None;
        }
        if is_top() {
            return Some(path);
        }
    }
    None
}

/// Review F7: the repository a discovered workspace is nested in, if any:
/// discovery stops at the nearest top level, so from inside a vendored
/// repository the outer repository's `ukai.toml` does not apply. `doctor`
/// and `explain` say so.
#[must_use]
pub fn outer_repository(workspace: &Path) -> Option<PathBuf> {
    discover_workspace(workspace.parent()?).ok()
}

/// Whether `dir` holds a `.git` that marks a repository's top level.
fn is_repository_top(dir: &Dir) -> bool {
    let Ok(git) = Name::new(b".git") else {
        return false;
    };
    let Ok(stat) = dir.stat_at(&git) else {
        return false;
    };
    match stat.kind {
        Kind::Directory => {
            let Ok(head) = Name::new(b"HEAD") else {
                return false;
            };
            dir.open_walk_at(&git, Some(&stat))
                .and_then(|inner| inner.stat_at(&head))
                .is_ok()
        }
        Kind::Regular if stat.size <= GITFILE_MAX => {
            let Ok(file) = dir.open_read_at(&git, Some(&stat)) else {
                return false;
            };
            let mut bytes = Vec::new();
            if file.take(GITFILE_MAX + 1).read_to_end(&mut bytes).is_err() {
                return false;
            }
            bytes.starts_with(b"gitdir: ")
        }
        _ => false,
    }
}

/// The operator's home directories: `HOME`, and the user database's entry
/// for this uid, each canonical where it exists. A workspace or an install
/// root at or above either refuses: `HOME` is what the operator's tools
/// write to, and the database entry is where their shell start-up files,
/// SSH keys and agent credentials live whatever `HOME` says.
pub(super) fn operator_homes(ctx: &Context) -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    let database = crate::state::accounts::user(crate::state::effective_uid())
        .ok()
        .flatten()
        .and_then(|user| user.home)
        .map(|home| PathBuf::from(OsStr::from_bytes(&home)));
    for home in ctx.home.iter().cloned().chain(database) {
        if !home.is_absolute() {
            continue;
        }
        let home = std::fs::canonicalize(&home).unwrap_or(home);
        if !homes.contains(&home) {
            homes.push(home);
        }
    }
    homes
}

/// What a directory no contained run grants is: `/`, one of the
/// operator's homes, or an ancestor of one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HomeKind {
    /// `/`, by its name or another path.
    FilesystemRoot,
    /// The operator's home, by its name or another path.
    Home,
    /// A directory above the operator's home, other than `/`.
    HomeAncestor,
}

impl HomeKind {
    /// The reason code `doctor --json` records for a workspace of this
    /// kind (`workspace.reason_code`).
    #[must_use]
    pub fn reason_code(self) -> &'static str {
        match self {
            HomeKind::FilesystemRoot => "filesystem_root",
            HomeKind::Home => "home_directory",
            HomeKind::HomeAncestor => "home_ancestor",
        }
    }
}

/// Why a directory may not be granted ([`home_or_above`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HomeOrAbove {
    /// What the directory is.
    pub kind: HomeKind,
    /// The home it is or lies above; `None` for `/` by its name.
    pub home: Option<PathBuf>,
    /// Whether it was matched by identity, through another path (review
    /// F4).
    pub by_another_path: bool,
    /// The refusals' wording: "the operator's home /home/u", "an ancestor
    /// of the operator's home /home/u", ...
    what: String,
}

impl std::fmt::Display for HomeOrAbove {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.what)
    }
}

/// Why `path` (canonical) may not be granted: it is `/`, a home, or an
/// ancestor of one. `None` when it is none of those.
pub(super) fn home_or_above(path: &Path, homes: &[PathBuf]) -> Option<HomeOrAbove> {
    if path == Path::new("/") {
        return Some(HomeOrAbove {
            kind: HomeKind::FilesystemRoot,
            home: None,
            by_another_path: false,
            what: "the filesystem root".to_owned(),
        });
    }
    let by_name = homes.iter().find_map(|home| {
        let (kind, what) = if home == path {
            (
                HomeKind::Home,
                format!("the operator's home {}", home.display()),
            )
        } else if home.starts_with(path) {
            (
                HomeKind::HomeAncestor,
                format!("an ancestor of the operator's home {}", home.display()),
            )
        } else {
            return None;
        };
        Some(HomeOrAbove {
            kind,
            home: Some(home.clone()),
            by_another_path: false,
            what,
        })
    });
    by_name.or_else(|| home_or_above_by_identity(path, homes))
}

/// Review F4: [`home_or_above`] by `(dev, ino)`, so a bind mount or another
/// spelling of the home, of `/` or of a directory above the home is the
/// directory it is.
fn home_or_above_by_identity(path: &Path, homes: &[PathBuf]) -> Option<HomeOrAbove> {
    use std::os::unix::fs::MetadataExt as _;
    let identity = |path: &Path| std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
    let target = identity(path)?;
    for home in homes {
        let mut ancestor = Some(home.as_path());
        while let Some(directory) = ancestor {
            if identity(directory) == Some(target) {
                let (kind, what) = if directory == home.as_path() {
                    (
                        HomeKind::Home,
                        format!("the operator's home {}, by another path", home.display()),
                    )
                } else {
                    (
                        if directory == Path::new("/") {
                            HomeKind::FilesystemRoot
                        } else {
                            HomeKind::HomeAncestor
                        },
                        format!(
                            "{} (an ancestor of the operator's home {}), by another path",
                            directory.display(),
                            home.display()
                        ),
                    )
                };
                return Some(HomeOrAbove {
                    kind,
                    home: Some(home.clone()),
                    by_another_path: true,
                    what,
                });
            }
            ancestor = directory.parent();
        }
    }
    None
}

/// A workspace that is `/`, the operator's home or an ancestor of it
/// (§3.2 step 3): every contained run refuses it ([`Self::refusal`]), and
/// `doctor` without `--from-path` reports it instead (§8 item 5).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HomeWorkspace {
    /// The workspace, canonical.
    pub path: PathBuf,
    /// What it is.
    pub why: HomeOrAbove,
    /// Whether `--workspace` named it; otherwise it is the invocation
    /// directory.
    pub explicit: bool,
}

impl HomeWorkspace {
    /// §3.2 step 3: a contained run never grants it, however it was
    /// chosen. There is no flag to bypass it; `--profile none` grants no
    /// workspace.
    pub(super) fn refusal(&self) -> JailError {
        widening(
            "--workspace",
            format!(
                "the workspace {} is {}; a contained run never grants it (its shell \
                 start-up files, SSH keys and agent credentials). Run from a project \
                 directory or pass --workspace PATH",
                self.path.display(),
                self.why
            ),
        )
    }

    /// `doctor`'s line for it (§8 item 5), in the operator's terms, with
    /// its paths escaped (audit M1). With `--launch`, `--from-path` from
    /// inside a repository is one more way to name a workspace.
    #[must_use]
    pub fn doctor_line(&self, launch: bool) -> String {
        let shown = |path: &Path| crate::records::escape_control(&path.to_string_lossy());
        let of_home = self
            .why
            .home
            .as_deref()
            .map(|home| format!(" {}", shown(home)))
            .unwrap_or_default();
        let mut what = match self.why.kind {
            HomeKind::FilesystemRoot => "the filesystem root".to_owned(),
            HomeKind::Home if self.why.home.as_deref() == Some(self.path.as_path()) => {
                "your home directory".to_owned()
            }
            HomeKind::Home => format!("your home directory{of_home}"),
            HomeKind::HomeAncestor => format!("an ancestor of your home directory{of_home}"),
        };
        if self.why.by_another_path {
            what.push_str(", by another path");
        }
        let subject = if self.explicit {
            "the workspace"
        } else {
            "the current directory"
        };
        let remedy = if launch {
            "run doctor from your project directory, pass --workspace PATH, or pass \
             --from-path from inside a repository"
        } else {
            "run doctor from your project directory or pass --workspace PATH"
        };
        format!(
            "workspace unusable reason={}: {subject} {} is {what}, which is never a workspace \
             (a contained run refuses it); {remedy}",
            self.why.kind.reason_code(),
            shown(&self.path)
        )
    }
}

/// The workspace a contained run refuses, when `workspace` is one; `explicit`
/// when `--workspace` named it.
pub(super) fn home_workspace(
    ctx: &Context,
    workspace: &Path,
    explicit: bool,
) -> Option<HomeWorkspace> {
    let path = canonical_existing_prefix(workspace);
    home_or_above(&path, &operator_homes(ctx)).map(|why| HomeWorkspace {
        path,
        why,
        explicit,
    })
}

/// §3.2 step 4: the child's working directory, relative to the workspace:
/// the invocation directory when it lies strictly beneath the workspace,
/// `None` (the root) otherwise.
pub(super) fn child_cwd(cwd: &Path, workspace: &Path) -> Option<NativeString> {
    let cwd = std::fs::canonicalize(cwd).ok()?;
    let relative = cwd.strip_prefix(workspace).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    NativeString::from_bytes(relative.as_os_str().as_bytes().to_vec()).ok()
}

// ---------------------------------------------------------------------------
// The program (§3.3)
// ---------------------------------------------------------------------------

/// The layer of the derived read-only install roots: an operator layer,
/// applied after the command line and before the project file, so a project
/// `ukai.toml` can still deny-read a root (the agent then fails visibly) but
/// never add one.
pub(super) fn program_layer(program: &Program) -> Layer {
    Layer {
        origin: LayerOrigin::ProgramResolution,
        base_dir: None,
        delta: PolicyDelta {
            read_only: program
                .roots()
                .iter()
                .map(|root| root.path.as_os_str().as_bytes().to_vec())
                .collect(),
            ..PolicyDelta::default()
        },
    }
}

/// One derived install root, as `explain`, the pre-exec line and `doctor`
/// disclose it (§3.3 step 6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DerivedRoot {
    /// The directory.
    pub path: PathBuf,
    /// Whether it is a new read-only grant (`by: program_resolution` in the
    /// receipt), or already readable through a root before it.
    pub granted: bool,
    /// The root that already makes it readable, when it is not granted.
    pub covered_by: Option<String>,
    /// Review F6: a `deny_read` (a project file's, say) that covers it, so
    /// the grant or cover gives the child nothing and the program cannot be
    /// read inside.
    pub denied_by: Option<String>,
}

/// What the resolution made of each install root: granted, or covered by a
/// root that already grants it (an npm install's root lies under `/usr`,
/// which is a runtime root already).
#[must_use]
pub fn derived_roots(program: &Program, resolved: &Resolved) -> Vec<DerivedRoot> {
    program
        .roots()
        .into_iter()
        .map(|root| {
            let value = root.path.as_os_str().as_bytes();
            let granted = resolved.grants.iter().any(|grant| {
                grant.by == "program_resolution"
                    && grant.kind == "read_only"
                    && grant.value.as_bytes() == value
            });
            let covered_by = (!granted)
                .then(|| {
                    resolved
                        .snapshot
                        .filesystem
                        .read_only
                        .iter()
                        .chain(&resolved.snapshot.filesystem.read_write)
                        .filter(|reference| reference.root == RootToken::Host)
                        .filter(|reference| {
                            Path::new(OsStr::from_bytes(value))
                                .starts_with(OsStr::from_bytes(reference.path.as_bytes()))
                        })
                        .max_by_key(|reference| reference.path.as_bytes().len())
                        .map(|reference| reference.path.to_display())
                })
                .flatten();
            let denied_by = resolved
                .snapshot
                .filesystem
                .deny_read
                .iter()
                .filter(|reference| reference.root == RootToken::Host)
                .find(|reference| {
                    Path::new(OsStr::from_bytes(value))
                        .starts_with(OsStr::from_bytes(reference.path.as_bytes()))
                })
                .map(|reference| reference.path.to_display());
            DerivedRoot {
                path: root.path.clone(),
                granted,
                covered_by,
                denied_by,
            }
        })
        .collect()
}

/// The line printed before exec when stderr is a terminal (§3.3 step 6):
/// the name, the argv it became and every derived root.
#[must_use]
pub fn program_line(program: &Program, resolved: &Resolved) -> String {
    let argv: Vec<String> = program
        .argv_prefix()
        .iter()
        .map(|word| crate::records::escape_control(&String::from_utf8_lossy(word)))
        .collect();
    let roots: Vec<String> = derived_roots(program, resolved)
        .iter()
        .map(|root| {
            let path = crate::records::escape_control(&root.path.display().to_string());
            let shown = match (&root.covered_by, root.granted) {
                (_, true) => format!("read-only: {path}"),
                (Some(by), false) => format!(
                    "already readable: {path} under {}",
                    crate::records::escape_control(by)
                ),
                (None, false) => format!("not granted: {path}"),
            };
            match &root.denied_by {
                Some(by) => format!(
                    "{shown}, but denied by deny_read {}: the program cannot be read inside",
                    crate::records::escape_control(by)
                ),
                None => shown,
            }
        })
        .collect();
    format!(
        "ukai-jail: {} = {} ({})",
        crate::records::escape_control(&program.name),
        argv.join(" "),
        roots.join("; ")
    )
}

/// The provenance of the resolution itself: the program and, after an
/// `env` expansion, its interpreter.
pub(super) fn program_provenance(program: &Program) -> Vec<ProvenanceEntry> {
    let mut why = vec![ProvenanceEntry {
        origin: ORIGIN.to_owned(),
        key: "program".to_owned(),
        detail: Some(format!(
            "{} = {} ({})",
            program.name,
            program.program.path.display(),
            program.format.as_str()
        )),
    }];
    if let Some(interpreter) = &program.interpreter {
        why.push(ProvenanceEntry {
            origin: ORIGIN.to_owned(),
            key: "program.interpreter".to_owned(),
            detail: Some(interpreter.path.display().to_string()),
        });
    }
    why
}

/// What §3.3 step 4 compares an install root and an executable against.
pub(super) struct Placement<'a> {
    pub(super) resolved: &'a Resolved,
    pub(super) workspace: &'a Path,
    pub(super) config_dir: &'a Path,
    pub(super) data_dir: &'a Path,
    /// Every credential source the launch profile declares, staged or not.
    pub(super) sources: Vec<PathBuf>,
    pub(super) homes: Vec<PathBuf>,
}

/// §3.3 step 4: each install root (granted or covered) and each executable
/// refuses when it is `/`, a home or an ancestor of one; contains the
/// config directory, the data directory or a credential source of this
/// launch; lies inside or contains the workspace, the scratch, vendor state
/// (beneath the data directory) or any writable grant, or is reached from
/// one through a bind alias; or is, contains or lies beneath `/proc` or
/// `/sys` (the cgroup filesystem is beneath `/sys`). A contained agent that
/// could rewrite its own executable would run that code with the
/// operator's authority on the next host launch.
///
/// # Errors
/// [`ErrorCode::PolicyWidening`] at `--from-path` naming the root.
pub(super) fn check_program_placement(
    program: &Program,
    placement: &Placement<'_>,
) -> Result<(), JailError> {
    let refuse = |root: &Path, why: String| {
        widening(
            crate::program::KEY,
            format!(
                "the program {} would be granted through {}, which {why}",
                program.program.path.display(),
                root.display()
            ),
        )
    };
    let writable: Vec<PathBuf> =
        child_writable_roots(placement.resolved, Some(placement.workspace))
            .iter()
            .map(|root| canonical_existing_prefix(root))
            .collect();
    let guarded: Vec<(PathBuf, &str)> = [
        (placement.config_dir, "the config directory"),
        (placement.data_dir, "the data directory"),
    ]
    .into_iter()
    .map(|(path, what)| (canonical_existing_prefix(path), what))
    .collect();
    let mut checked: Vec<&Path> = program
        .roots()
        .into_iter()
        .map(|root| root.path.as_path())
        .collect();
    checked.extend(
        program
            .executables()
            .into_iter()
            .map(|executable| executable.path.as_path()),
    );
    // Review F1: a lookup a child-writable root steered. A symbolic link the
    // repository ships in a `PATH` entry inside the workspace (direnv,
    // `node_modules/.bin`, a `.venv`) would otherwise choose the program, and
    // `@program` would bind the credential to whatever trusted file it names.
    for executable in program.executables() {
        for link in &executable.found_through {
            let refuse_link = |why: String| {
                widening(
                    crate::program::KEY,
                    format!(
                        "`{}` was found on PATH through the symbolic link {}, which {why}; the \
                         program it names would be chosen by whoever can write there",
                        program.name,
                        link.display()
                    ),
                )
            };
            if let Some(grant) = writable.iter().find(|grant| link.starts_with(grant)) {
                return Err(refuse_link(format!(
                    "lies inside the child-writable root {}",
                    grant.display()
                )));
            }
            // Where the link lives: its directory, never followed (the
            // link itself would be followed to its target, which the root
            // and executable checks below judge).
            let holder = link.parent().unwrap_or(Path::new("/"));
            if let Some(alias) = super::alias_conflict(&writable, holder, crate::program::KEY)? {
                return Err(refuse_link(format!(
                    "is reached from a child-writable root through the bind alias {}",
                    alias.display()
                )));
            }
            if let Some(why) = link.parent().and_then(untrusted_directory) {
                return Err(refuse_link(why));
            }
        }
    }
    for root in checked {
        if let Some(what) = home_or_above(root, &placement.homes) {
            return Err(refuse(root, format!("is {what}")));
        }
        for (path, what) in &guarded {
            if overlaps(root, path) {
                return Err(refuse(root, format!("overlaps {what} {}", path.display())));
            }
        }
        for source in &placement.sources {
            if canonical_existing_prefix(source).starts_with(root) {
                return Err(refuse(
                    root,
                    "contains a credential source of this launch".to_owned(),
                ));
            }
        }
        if let Some(grant) = writable.iter().find(|grant| overlaps(root, grant)) {
            return Err(refuse(
                root,
                format!("overlaps the child-writable root {}", grant.display()),
            ));
        }
        for pseudo in ["/proc", "/sys"] {
            if overlaps(root, Path::new(pseudo)) {
                return Err(refuse(root, format!("overlaps {pseudo}")));
            }
        }
        if let Some(alias) = super::alias_conflict(&writable, root, crate::program::KEY)? {
            return Err(refuse(
                root,
                format!(
                    "is reached from a child-writable root through the bind alias {}",
                    alias.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Why a directory holding a link the `PATH` lookup followed cannot be
/// trusted to keep naming what it named: owned by someone other than root
/// or this operator, or writable by others without the sticky bit (the walk
/// rule of the pin). `None` when it can.
fn untrusted_directory(directory: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) => return Some(format!("lies in {} ({error})", directory.display())),
    };
    untrusted_owner_or_mode(
        directory,
        metadata.uid(),
        metadata.mode() & 0o7777,
        metadata.gid(),
    )
}

/// [`untrusted_directory`]'s rule over a directory's owner, mode and group.
fn untrusted_owner_or_mode(directory: &Path, uid: u32, mode: u32, gid: u32) -> Option<String> {
    if uid != 0 && uid != crate::state::effective_uid() {
        return Some(format!(
            "lies in {}, owned by uid {uid}, neither root nor this operator",
            directory.display()
        ));
    }
    if crate::state::writable_by_others(mode, uid, gid) && mode & 0o1000 == 0 {
        return Some(format!(
            "lies in {}, mode {mode:04o}: writable by others without the sticky bit",
            directory.display()
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// The launch-profile keys (§3.4)
// ---------------------------------------------------------------------------

/// `credentials_one_of`: keeps the first listed credential whose source
/// exists and drops every other listed one; the rest of the profile's
/// credentials are untouched. Only absence counts as absent (the source, or
/// a directory on its path, does not exist): a source that exists and is
/// unsafe (a wrong mode, owner, link count, a symlink) is kept and refused
/// by staging, as today, never skipped in favour of the next one. None
/// present refuses before anything is prepared, listing each id with its
/// hint. Returns the provenance of each id skipped.
///
/// # Errors
/// [`ErrorCode::CredentialUnavailable`] at `launch.credentials_one_of` when
/// no listed source exists.
pub(super) fn select_credentials(
    launch: &mut LaunchProfile,
) -> Result<Vec<ProvenanceEntry>, JailError> {
    if launch.credentials_one_of.is_empty() {
        return Ok(Vec::new());
    }
    let origin = format!("launch-profile:{}", launch.name);
    let mut why = Vec::new();
    let mut chosen: Option<String> = None;
    for id in &launch.credentials_one_of {
        let Some(credential) = launch.credentials.iter().find(|c| &c.id == id) else {
            continue;
        };
        if crate::credentials::source_absent(credential.source.as_bytes()) {
            why.push(ProvenanceEntry {
                origin: origin.clone(),
                key: format!("launch.credentials.{id}"),
                detail: Some("skipped: absent".to_owned()),
            });
            continue;
        }
        chosen = Some(id.clone());
        break;
    }
    let Some(chosen) = chosen else {
        let listed: Vec<String> = launch
            .credentials_one_of
            .iter()
            .map(|id| match launch.hints.get(id) {
                Some(hint) => format!("`{id}` ({hint})"),
                None => format!("`{id}`"),
            })
            .collect();
        return Err(JailError::new(
            ErrorCode::CredentialUnavailable,
            ErrorStage::Resolving,
            Remediation::Configuration,
            format!(
                "launch profile `{}` needs one of its credentials, and none is present: {}",
                launch.name,
                listed.join("; ")
            ),
        )
        .with_key_path("launch.credentials_one_of"));
    };
    let dropped: Vec<String> = launch
        .credentials_one_of
        .iter()
        .filter(|id| **id != chosen)
        .cloned()
        .collect();
    for id in &dropped {
        if !why
            .iter()
            .any(|entry| entry.key == format!("launch.credentials.{id}"))
        {
            why.push(ProvenanceEntry {
                origin: origin.clone(),
                key: format!("launch.credentials.{id}"),
                detail: Some(format!("skipped: `{chosen}` comes first")),
            });
        }
    }
    launch
        .credentials
        .retain(|credential| !dropped.contains(&credential.id));
    Ok(why)
}

/// `binaries = ["@program"]`: binds the credential to the resolved program
/// (`X'` after an `env` expansion) under `--from-path`, and otherwise to
/// `PROGRAM` when it is an absolute path (canonical, so the binding names
/// the file the kernel reports as the connecting process's executable). A
/// run whose `PROGRAM` is not absolute refuses naming the key; `explain`
/// and `doctor` without `--from-path` have no program and keep the token.
///
/// # Errors
/// [`ErrorCode::InvalidConfig`] at `launch.credentials.<id>.binaries`.
pub(super) fn bind_program_token(
    launch: &mut LaunchProfile,
    program: Option<&Program>,
    argv0: Option<&[u8]>,
    executing: bool,
) -> Result<(), JailError> {
    for credential in &mut launch.credentials {
        let id = credential.id.clone();
        let Some(vault) = credential.vault.as_mut() else {
            continue;
        };
        if !vault
            .binaries
            .iter()
            .any(|binary| binary == crate::vault::PROGRAM_TOKEN)
        {
            continue;
        }
        let key = format!("launch.credentials.{id}.binaries");
        let path: Option<PathBuf> = match (program, argv0) {
            // A `#!` script run by a system interpreter never makes a
            // connection itself: the kernel reports the interpreter as the
            // connecting executable, so a binding to the script would refuse
            // every request, and one to the interpreter would admit every
            // script it runs. Neither is what `@program` says.
            (Some(program), _)
                if matches!(program.format, crate::program::Format::Script { .. }) =>
            {
                return Err(usage(
                    &key,
                    format!(
                        "`@program` binds a credential to the executable that makes its \
                         connections, and {} is a `#!` script whose connections come from its \
                         interpreter; name the executable in `binaries` instead",
                        program.program.path.display()
                    ),
                ));
            }
            (Some(program), _) => Some(program.bound().path.clone()),
            (None, Some(argv0)) if argv0.first() == Some(&b'/') => Some(
                std::fs::canonicalize(OsStr::from_bytes(argv0)).map_err(|error| {
                    usage(
                        &key,
                        format!(
                            "`@program` names PROGRAM {}, which cannot be resolved: {error}",
                            String::from_utf8_lossy(argv0)
                        ),
                    )
                })?,
            ),
            (None, Some(_)) if executing => {
                return Err(usage(
                    &key,
                    "`@program` needs --from-path or an absolute PROGRAM after `--`",
                ));
            }
            (None, _) => None,
        };
        let Some(path) = path else { continue };
        let Some(text) = path.to_str() else {
            return Err(usage(
                &key,
                format!(
                    "`@program` resolved to {}, which is not UTF-8",
                    path.display()
                ),
            ));
        };
        for binary in &mut vault.binaries {
            if binary == crate::vault::PROGRAM_TOKEN {
                text.clone_into(binary);
            }
        }
        vault.binaries.sort();
        vault.binaries.dedup();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// jail-macos.md §4.11: the pure group-writable rule. The stated
    /// database resolves `root` to 0 and `operator` to 501; every other
    /// name is unresolvable (as a nested group's name would be).
    #[test]
    fn the_group_writable_rule_accepts_exactly_root_and_the_operator() {
        let resolve = |name: &str| match name {
            "root" => Some(0),
            "operator" => Some(501),
            _ => None,
        };
        // admin's member list on the reference Mac: root + the operator.
        assert!(group_writable_ok(
            "admin",
            &["root", "operator"],
            0,
            501,
            &resolve
        ));
        assert!(group_writable_ok(
            "admin",
            &["operator", "root"],
            0,
            501,
            &resolve
        ));
        // A third member refuses.
        assert!(!group_writable_ok(
            "admin",
            &["root", "operator", "intern"],
            0,
            501,
            &resolve
        ));
        // An empty member list refuses: nested membership cannot be seen,
        // so it is not accepted on faith.
        assert!(!group_writable_ok("admin", &[], 0, 501, &resolve));
        // A member the database does not resolve (a nested group's name, a
        // deleted account) refuses.
        assert!(!group_writable_ok(
            "admin",
            &["root", "operator", "developers"],
            0,
            501,
            &resolve
        ));
        assert!(!group_writable_ok(
            "admin",
            &["root", "ghost"],
            0,
            501,
            &resolve
        ));
        // A different operator, or root missing, refuses.
        assert!(!group_writable_ok(
            "staff",
            &["root", "someone"],
            0,
            501,
            &resolve
        ));
        assert!(!group_writable_ok("admin", &["operator"], 0, 501, &resolve));
        // A lone operator entry that duplicates resolves to one member.
        assert!(!group_writable_ok(
            "admin",
            &["operator", "operator"],
            0,
            501,
            &resolve
        ));
    }

    /// K34: discovery stops at a mount boundary, as git does by default,
    /// whether or not a repository lies beyond it.
    #[test]
    fn discovery_never_crosses_a_device_boundary() {
        let levels = |marks: &[(&'static str, u64, bool)]| -> Option<&'static str> {
            nearest_top(
                marks
                    .iter()
                    .map(|(path, dev, top)| (Path::new(*path), *dev, move || *top)),
            )
            .map(|path| path.to_str().unwrap())
        };
        // The same device all the way: the nearest top level wins.
        assert_eq!(
            levels(&[
                ("/", 1, false),
                ("/r", 1, true),
                ("/r/a", 1, false),
                ("/r/a/b", 1, false)
            ]),
            Some("/r")
        );
        assert_eq!(
            levels(&[
                ("/", 1, false),
                ("/r", 1, true),
                ("/r/a", 1, true),
                ("/r/a/b", 1, false)
            ]),
            Some("/r/a")
        );
        // A repository beyond a mount boundary is not found.
        assert_eq!(
            levels(&[
                ("/", 1, false),
                ("/r", 1, true),
                ("/r/m", 2, false),
                ("/r/m/b", 2, false)
            ]),
            None
        );
        // One on the starting device, beneath the boundary, is.
        assert_eq!(
            levels(&[("/", 1, true), ("/m", 2, true), ("/m/b", 2, false)]),
            Some("/m")
        );
        // A level beyond the boundary is never even asked.
        let asked = std::cell::Cell::new(false);
        let ask_root = || {
            asked.set(true);
            true
        };
        let never = || false;
        let checks: [(&Path, u64, &dyn Fn() -> bool); 2] =
            [(Path::new("/"), 1, &ask_root), (Path::new("/m"), 2, &never)];
        let found = nearest_top(checks.into_iter());
        assert_eq!(found, None);
        assert!(!asked.get());
    }

    /// Review F4: another path to the home or an ancestor (a bind mount; a
    /// symlink stands in for one here) is the same directory by identity.
    #[test]
    fn home_or_above_matches_the_directory_not_only_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home/u");
        std::fs::create_dir_all(home.join("repo")).unwrap();
        std::os::unix::fs::symlink(&home, root.join("alias-of-home")).unwrap();
        std::os::unix::fs::symlink(root.join("home"), root.join("alias-of-parent")).unwrap();
        let homes = [home.clone()];
        let why = home_or_above(&root.join("alias-of-home"), &homes).expect("the home");
        assert!(why.to_string().contains("by another path"), "{why}");
        assert_eq!((why.kind, why.by_another_path), (HomeKind::Home, true));
        let why = home_or_above(&root.join("alias-of-parent"), &homes).expect("an ancestor");
        assert!(why.to_string().contains("ancestor"), "{why}");
        assert_eq!(why.kind, HomeKind::HomeAncestor);
        assert!(home_or_above(&home.join("repo"), &homes).is_none());
        assert!(home_or_above(&root.join("alias-of-home/repo"), &homes).is_none());
    }

    /// The owner rule of a directory holding a link the lookup followed,
    /// which needs a second local user end to end.
    #[test]
    fn a_link_in_a_foreign_owned_directory_is_untrusted() {
        let me = crate::state::effective_uid();
        let other = if me == 4242 { 4243 } else { 4242 };
        let path = Path::new("/x");
        assert!(untrusted_owner_or_mode(path, other, 0o755, u32::MAX - 1).is_some());
        assert!(untrusted_owner_or_mode(path, me, 0o755, u32::MAX - 1).is_none());
        assert!(untrusted_owner_or_mode(path, 0, 0o755, u32::MAX - 1).is_none());
        assert!(untrusted_owner_or_mode(path, 0, 0o777, u32::MAX - 1).is_some());
        assert!(untrusted_owner_or_mode(path, 0, 0o1777, u32::MAX - 1).is_none());
    }

    #[test]
    fn home_or_above_names_root_home_and_ancestors_only() {
        let homes = [PathBuf::from("/home/u")];
        let kind = |path: &str| home_or_above(Path::new(path), &homes).map(|why| why.kind);
        assert_eq!(kind("/"), Some(HomeKind::FilesystemRoot));
        assert_eq!(kind("/home"), Some(HomeKind::HomeAncestor));
        assert_eq!(kind("/home/u"), Some(HomeKind::Home));
        assert!(home_or_above(Path::new("/home/u/repo"), &homes).is_none());
        assert!(home_or_above(Path::new("/home/uu"), &homes).is_none());
        assert!(home_or_above(Path::new("/srv"), &homes).is_none());
    }

    fn home_workspace_at(path: &str, explicit: bool) -> HomeWorkspace {
        let homes = [PathBuf::from("/home/u")];
        HomeWorkspace {
            path: PathBuf::from(path),
            why: home_or_above(Path::new(path), &homes).expect("refused"),
            explicit,
        }
    }

    /// The run refusal keeps its words now that `doctor` reports the same
    /// workspace (§8 item 5): code, key and message.
    #[test]
    fn the_run_refusal_of_a_home_workspace_is_unchanged() {
        let error = home_workspace_at("/home/u", false).refusal();
        assert_eq!(error.code, ErrorCode::PolicyWidening);
        assert_eq!(error.key_path.as_deref(), Some("--workspace"));
        assert_eq!(
            error.message,
            "the workspace /home/u is the operator's home /home/u; a contained run never \
             grants it (its shell start-up files, SSH keys and agent credentials). Run from \
             a project directory or pass --workspace PATH"
        );
        assert!(
            home_workspace_at("/", true)
                .refusal()
                .message
                .starts_with("the workspace / is the filesystem root; ")
        );
        assert!(
            home_workspace_at("/home", true)
                .refusal()
                .message
                .starts_with("the workspace /home is an ancestor of the operator's home /home/u; ")
        );
    }

    /// `doctor`'s line names the workspace as what it is, says where it
    /// came from, and offers `--from-path` only with `--launch`.
    #[test]
    fn the_doctor_line_says_why_the_workspace_is_never_one() {
        assert_eq!(
            home_workspace_at("/home/u", false).doctor_line(true),
            "workspace unusable reason=home_directory: the current directory /home/u is your \
             home directory, which is never a workspace (a contained run refuses it); run \
             doctor from your project directory, pass --workspace PATH, or pass --from-path \
             from inside a repository"
        );
        assert_eq!(
            home_workspace_at("/home/u", false).doctor_line(false),
            "workspace unusable reason=home_directory: the current directory /home/u is your \
             home directory, which is never a workspace (a contained run refuses it); run \
             doctor from your project directory or pass --workspace PATH"
        );
        assert_eq!(
            home_workspace_at("/", true).doctor_line(false),
            "workspace unusable reason=filesystem_root: the workspace / is the filesystem \
             root, which is never a workspace (a contained run refuses it); run doctor from \
             your project directory or pass --workspace PATH"
        );
        assert!(
            home_workspace_at("/home", false)
                .doctor_line(false)
                .starts_with(
                    "workspace unusable reason=home_ancestor: the current directory /home is \
                     an ancestor of your home directory /home/u, which is never a workspace"
                )
        );
        // Another path to the home names the home it reaches.
        let mut alias = home_workspace_at("/home/u", true);
        alias.path = PathBuf::from("/mnt/alias");
        alias.why.by_another_path = true;
        assert!(
            alias.doctor_line(false).starts_with(
                "workspace unusable reason=home_directory: the workspace /mnt/alias is your \
                 home directory /home/u, by another path, which is never a workspace"
            ),
            "{}",
            alias.doctor_line(false)
        );
        // Audit M1: a path is escaped, never printed raw.
        let mut hostile = home_workspace_at("/home/u", false);
        hostile.path = PathBuf::from("/home/\u{1b}]52;c;x\u{7}u");
        let line = hostile.doctor_line(false);
        assert!(
            !line.contains('\u{1b}') && !line.contains('\u{7}'),
            "{line}"
        );
        assert!(line.contains("/home/<U+001B>]52;c;x<U+0007>u"), "{line}");
    }
}
