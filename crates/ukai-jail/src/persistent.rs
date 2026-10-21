//! J14: persistent vendor state (`docs/specs/jail-interactive-sessions.md`
//! §4).
//!
//! An operator-owned state directory per launch profile and workspace, which
//! survives attempts:
//!
//! ```text
//! <data>/state/                 0700
//!   <launch-name>/              0700
//!     <key>/                    0700; key = first 32 hex digits of
//!                               SHA-256("ukai.jail.state/1\0" ‖ name ‖ "\0" ‖ workspace)
//!       state.json              private metadata, never mounted
//!       lease                   flock of the supervisor that holds the state
//!       vendor/                 the directory bound at /run/ukai/state
//! ```
//!
//! Every level is created and opened through anchored, no-follow handles,
//! and an existing level with another owner, wider modes, a symlink or a
//! special node refuses (`unsafe_state_path`). One attempt holds a state at
//! a time (the lease); [`acquire`] gives a second one a [`Fallback`]
//! instead, which the supervisor turns into throwaway attempt-private state
//! or a `state_busy` refusal (§4.6, decision 6).
//!
//! The supervisor reads state a possibly compromised agent wrote, so every
//! host-side walk here ([`manifest`], [`discard`], [`remove`]) is anchored
//! and no-follow, never crosses a device or a mount, opens only regular
//! files (`O_NOFOLLOW | O_NONBLOCK`), records every other type without
//! opening it, and is bounded in entries, depth and bytes read (§4.4).
//!
//! Nothing here names an agent (I02): the launch profile's name is data.

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::records::{ErrorCode, ErrorStage, JailError, NativeString, Remediation};
use crate::state::anchored::{Dir, Kind, Name, Stat};

/// `<data>/state`.
pub const STATE_DIR_NAME: &str = "state";
/// The private metadata file in a state's key directory.
pub const RECORD_NAME: &str = "state.json";
/// The lease file in a state's key directory.
pub const LEASE_NAME: &str = "lease";
/// The directory bound at `/run/ukai/state`.
pub const VENDOR_NAME: &str = "vendor";
/// The identifier of `state.json`.
pub const SCHEMA_RECORD: &str = "ukai.jail.persistent-state/1";
/// The domain separator of the key derivation (§4.3).
pub const KEY_DOMAIN: &[u8] = b"ukai.jail.state/1\0";
/// The largest `state.json` read.
pub const RECORD_MAX: u64 = 256 * 1024;
/// The generations `state.json` keeps in its log.
pub const LOG_MAX: usize = 64;
/// The files a quarantine names; the rest are counted, so the record stays
/// within [`RECORD_MAX`] however many files held a value.
pub const QUARANTINE_FILES_MAX: usize = 64;
/// The bytes of file names a quarantine keeps, under the same rule.
pub const QUARANTINE_NAME_BYTES_MAX: usize = 16 * 1024;
/// Initial bound of one manifest pass on content read (§4.6).
pub const MANIFEST_BYTES_MAX: u64 = 256 * 1024 * 1024;
/// Initial bound of one manifest pass on entries (§4.6).
pub const MANIFEST_ENTRIES_MAX: usize = 65_536;
/// Directory depth a walk descends.
pub const DEPTH_MAX: usize = 128;
/// The test seam that shrinks [`MANIFEST_ENTRIES_MAX`] and
/// [`MANIFEST_BYTES_MAX`] (`ENTRIES,BYTES`), so a bound is reached without
/// writing 256 MiB.
pub const SEAM_BOUNDS: &str = "UKAI_JAIL_TEST_STATE_BOUNDS";
/// The `matches_release_reason` of a state that was never released.
pub const REASON_NEW_STATE: &str = "new_state";
/// The `matches_release_reason` of a pass past its bound.
pub const REASON_TOO_LARGE: &str = "state_too_large";
/// The `matches_release_reason` of a pass that could not read an entry.
pub const REASON_UNREADABLE: &str = "unreadable";

/// The key of the state for `launch` and the canonical `workspace` (§4.3).
#[must_use]
pub fn key(launch: &str, workspace: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(KEY_DOMAIN);
    hash.update(launch.as_bytes());
    hash.update(b"\0");
    hash.update(workspace);
    let digest = hash.finalize();
    digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `<data>/state/<launch>/<key>`, for diagnostics and `state show`.
#[must_use]
pub fn key_path(data_dir: &Path, launch: &str, key: &str) -> PathBuf {
    data_dir.join(STATE_DIR_NAME).join(launch).join(key)
}

fn unsafe_state(path: &Path, message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::UnsafeStatePath,
        ErrorStage::Preparing,
        Remediation::HostSetup,
        format!("{}: {}", path.display(), message.into()),
    )
}

fn write_failed(path: &Path, error: &std::io::Error) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!("{}: {error}", path.display()),
    )
}

fn name(text: &str) -> Name {
    Name::new(text.as_bytes()).expect("a fixed component is a valid name")
}

// ---------------------------------------------------------------------------
// state.json
// ---------------------------------------------------------------------------

/// A device and inode, as decimal strings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identity(pub (u64, u64));

impl Serialize for Identity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("dev", &self.0.0.to_string())?;
        map.serialize_entry("ino", &self.0.1.to_string())?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            dev: String,
            ino: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let parse = |text: &str| text.parse::<u64>().map_err(serde::de::Error::custom);
        Ok(Identity((parse(&raw.dev)?, parse(&raw.ino)?)))
    }
}

/// The attempt that holds, or last held, the state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holder {
    /// `att_…`.
    pub attempt: String,
    /// Its release is durable.
    pub released: bool,
}

/// The last release: who, what it left, when.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastRelease {
    /// The releasing attempt.
    pub attempt: String,
    /// The private digest of what it left, or null.
    pub digest: Option<String>,
    /// Why there is no digest (`state_too_large`, `unreadable`).
    pub digest_unavailable: Option<String>,
    /// RFC 3339 UTC.
    pub at: String,
}

/// A quarantine: a vault credential's value was found in the state, or the
/// releasing tree's integrity was lost.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// `credential_persisted` or `integrity_lost`.
    pub reason: String,
    /// The attempt whose release found it.
    pub attempt: String,
    /// RFC 3339 UTC.
    pub at: String,
    /// The files that held a value, relative to `vendor/`, for `state show`
    /// on the operator's host; never in a receipt. At most
    /// [`QUARANTINE_FILES_MAX`] names and [`QUARANTINE_NAME_BYTES_MAX`]
    /// bytes of them.
    pub files: Vec<NativeString>,
    /// The files that held a value beyond those named.
    #[serde(default)]
    pub files_omitted: u64,
}

/// One generation in the log.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    /// The generation this release produced.
    pub generation: u64,
    /// The attempt released.
    pub attempt: String,
    /// `supervisor` or `gc`.
    pub by: String,
    /// RFC 3339 UTC.
    pub at: String,
    /// The private digest, or null.
    pub digest: Option<String>,
    /// Whether the attempt started from what the release before it left.
    pub matches_release: Option<bool>,
    /// Discard-list entries removed.
    pub discarded: u64,
    /// `clean`, `found` or `not_scanned`.
    pub secret_scan: String,
}

/// `state.json` (`ukai.jail.persistent-state/1`): private, never mounted,
/// never in a receipt.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// [`SCHEMA_RECORD`].
    pub schema: String,
    /// `st_<uuid>`.
    pub state_id: String,
    /// The launch profile name.
    pub launch: String,
    /// The canonical workspace path.
    pub workspace: NativeString,
    /// The workspace root's `(dev, ino)` at creation (§4.3).
    pub workspace_identity: Identity,
    /// RFC 3339 UTC.
    pub created_at: String,
    /// Releases so far.
    pub generation: u64,
    /// The last release, or null for a new state.
    pub last_release: Option<LastRelease>,
    /// The holding attempt, or null before the first acquisition.
    pub holder: Option<Holder>,
    /// Set once a quarantine is found; cleared only by `state rm`.
    pub quarantine: Option<Quarantine>,
    /// The last [`LOG_MAX`] generations.
    pub log: Vec<Generation>,
}

impl Record {
    fn new(launch: &str, workspace: &Path, identity: (u64, u64)) -> Result<Record, JailError> {
        Ok(Record {
            schema: SCHEMA_RECORD.to_owned(),
            state_id: format!("st_{}", uuid::Uuid::new_v4()),
            launch: launch.to_owned(),
            workspace: NativeString::from_bytes(workspace.as_os_str().as_bytes().to_vec())
                .map_err(|error| unsafe_state(workspace, error.to_string()))?,
            workspace_identity: Identity(identity),
            created_at: now(),
            generation: 0,
            last_release: None,
            holder: None,
            quarantine: None,
            log: Vec::new(),
        })
    }

    /// Whether the record names this attempt as its unreleased holder.
    #[must_use]
    pub fn held_unreleased_by(&self, attempt: &str) -> bool {
        self.holder
            .as_ref()
            .is_some_and(|holder| holder.attempt == attempt && !holder.released)
    }
}

fn now() -> String {
    crate::records::rfc3339_utc(SystemTime::now())
}

/// Reads `state.json` of a key directory, `None` when there is none.
///
/// # Errors
/// [`ErrorCode::UnsafeStatePath`] for a file that is not this operator's
/// private regular file, [`ErrorCode::StateWriteFailed`] for one that cannot
/// be read or parsed.
pub fn read_record(key_dir: &Dir, path: &Path) -> Result<Option<Record>, JailError> {
    let record_name = name(RECORD_NAME);
    let stat = match key_dir.stat_at(&record_name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(write_failed(path, &error)),
    };
    let at = path.join(RECORD_NAME);
    check_private(&at, &stat, Kind::Regular, crate::state::FILE_MODE)?;
    if stat.size > RECORD_MAX {
        return Err(unsafe_state(&at, "is larger than a state record can be"));
    }
    let mut file = key_dir
        .open_read_at(&record_name, Some(&stat))
        .map_err(|error| write_failed(&at, &error))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(RECORD_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| write_failed(&at, &error))?;
    let record: Record = serde_json::from_slice(&bytes).map_err(|error| {
        JailError::new(
            ErrorCode::StateWriteFailed,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("{}: not a persistent-state record: {error}", at.display()),
        )
    })?;
    if record.schema != SCHEMA_RECORD {
        return Err(unsafe_state(&at, "is not a persistent-state record"));
    }
    Ok(Some(record))
}

/// Replaces `state.json` durably through the key directory's handle: a new
/// temporary file, written and synced, renamed over the record, then the
/// directory synced (§7's durable replacement, anchored).
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn write_record(key_dir: &Dir, path: &Path, record: &Record) -> Result<(), JailError> {
    let at = path.join(RECORD_NAME);
    let mut bytes = serde_json::to_vec_pretty(record).map_err(|error| {
        JailError::new(
            ErrorCode::InternalError,
            ErrorStage::Preparing,
            Remediation::InspectState,
            format!("the persistent-state record could not be serialized: {error}"),
        )
    })?;
    bytes.push(b'\n');
    let temp = name(&format!(
        ".{RECORD_NAME}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = key_dir
        .create_file_at(&temp, crate::state::FILE_MODE)
        .map_err(|error| write_failed(&at, &error))?;
    let written = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| key_dir.rename_at(&temp, key_dir, &name(RECORD_NAME)))
        .and_then(|()| key_dir.sync());
    if let Err(error) = written {
        let _ = key_dir.unlink_at(&temp);
        return Err(write_failed(&at, &error));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Levels and the lease
// ---------------------------------------------------------------------------

/// Checks one object the state layout owns: its kind, this operator as
/// owner, nothing wider than `mode` but the owner's private group.
fn check_private(path: &Path, stat: &Stat, kind: Kind, mode: u32) -> Result<(), JailError> {
    if stat.kind != kind {
        return Err(unsafe_state(
            path,
            format!("is {}, not {}", stat.kind.describe(), kind.describe()),
        ));
    }
    crate::state::check_ownership(path, stat.uid, stat.mode, mode)
        .map_err(|error| error.in_stage(ErrorStage::Preparing))
}

/// One level of the layout below `parent`: opened when it exists and passes
/// [`check_private`], created mode 0700 otherwise (when `create`).
fn level(
    parent: &Dir,
    path: &Path,
    component: &str,
    create: bool,
) -> Result<Option<Dir>, JailError> {
    let entry = Name::new(component.as_bytes()).map_err(|error| {
        unsafe_state(path, format!("`{component}` is not a component: {error}"))
    })?;
    match parent.stat_at(&entry) {
        Ok(stat) => {
            check_private(path, &stat, Kind::Directory, crate::state::DIRECTORY_MODE)?;
            if stat.mount_root == Some(true) {
                return Err(unsafe_state(path, "is a mount point"));
            }
            parent
                .open_dir_at(&entry, Some(&stat))
                .map(Some)
                .map_err(|error| write_failed(path, &error))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => parent
            .mkdir_at(&entry, crate::state::DIRECTORY_MODE)
            .map(Some)
            .map_err(|error| write_failed(path, &error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(write_failed(path, &error)),
    }
}

/// A state's key directory, opened.
pub struct Levels {
    /// `<data>/state/<launch>/<key>`.
    pub path: PathBuf,
    /// Its handle.
    pub key_dir: Dir,
    /// `<data>/state/<launch>`, for `state rm`.
    pub launch_dir: Dir,
    /// The key.
    pub key: String,
}

/// Opens (and with `create`, creates) the levels of the state for `launch`
/// and `key`. `None` without `create` when a level is absent.
///
/// # Errors
/// As [`level`]; the data directory must pass the state-root checks.
pub fn open_levels(
    data_dir: &Path,
    launch: &str,
    key: &str,
    create: bool,
) -> Result<Option<Levels>, JailError> {
    if !crate::launch_profile::valid_name(launch) {
        return Err(unsafe_state(
            data_dir,
            format!("`{launch}` is not a launch profile name"),
        ));
    }
    crate::state::check_state_dir(data_dir)
        .map_err(|error| error.in_stage(ErrorStage::Preparing))?;
    let data = Dir::open_trusted(data_dir).map_err(|error| write_failed(data_dir, &error))?;
    let root_path = data_dir.join(STATE_DIR_NAME);
    let Some(root) = level(&data, &root_path, STATE_DIR_NAME, create)? else {
        return Ok(None);
    };
    let launch_path = root_path.join(launch);
    let Some(launch_dir) = level(&root, &launch_path, launch, create)? else {
        return Ok(None);
    };
    let key_path = launch_path.join(key);
    let Some(key_dir) = level(&launch_dir, &key_path, key, create)? else {
        return Ok(None);
    };
    Ok(Some(Levels {
        path: key_path,
        key_dir,
        launch_dir,
        key: key.to_owned(),
    }))
}

/// The lease on a state: an exclusive `flock` of `<key>/lease`, released
/// explicitly on drop (a forked child holds an inherited `flock` until it
/// execs), close-on-exec so it never reaches the child.
#[derive(Debug)]
pub struct Lease {
    file: std::fs::File,
}

impl Drop for Lease {
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by `self.file`; LOCK_UN releases
        // the lock this process took on it.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Takes the lease without blocking: `None` when another process holds it.
///
/// # Errors
/// [`ErrorCode::UnsafeStatePath`] for a lease that is not this operator's
/// private regular file, [`ErrorCode::StateWriteFailed`] when it cannot be
/// opened or locked.
pub fn take_lease(key_dir: &Dir, path: &Path) -> Result<Option<Lease>, JailError> {
    let at = path.join(LEASE_NAME);
    let lease = name(LEASE_NAME);
    // SAFETY: a live directory descriptor and a validated component; the
    // flags never follow a final symlink and keep the descriptor from the
    // child.
    let fd = unsafe {
        libc::openat(
            key_dir.as_fd().as_raw_fd(),
            lease.as_c().as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        // `O_NOFOLLOW` met a symlink: not this operator's private file.
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(unsafe_state(&at, "is a symbolic link"));
        }
        return Err(write_failed(&at, &error));
    }
    // SAFETY: openat returned a fresh descriptor this function now owns.
    let file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let stat =
        crate::state::anchored::fstat(file.as_fd()).map_err(|error| write_failed(&at, &error))?;
    check_private(&at, &stat, Kind::Regular, crate::state::FILE_MODE)?;
    // SAFETY: flock takes a live descriptor and an operation constant.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(Lease { file }));
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(None),
        _ => Err(write_failed(&at, &error)),
    }
}

/// How long acquisition retries a lease that is taken. `state list`, `state
/// show` and `doctor` take it for an instant to tell whether it is held
/// (review F14); an attempt holds it for its whole session, so a lease still
/// taken after this long is held.
pub const LEASE_PATIENCE: std::time::Duration = std::time::Duration::from_millis(250);

/// The prefix of the name `state rm` gives a key directory before removing
/// it: a key is hex digits, so a tombstone is never one.
pub const TOMBSTONE_PREFIX: &str = ".removing-";

/// Whether `entry` is a tombstone: `.removing-<key>-<32 hex digits>`.
#[must_use]
pub fn is_tombstone(entry: &[u8]) -> bool {
    let hex = |part: &[u8]| part.len() == 32 && part.iter().all(u8::is_ascii_hexdigit);
    entry
        .strip_prefix(TOMBSTONE_PREFIX.as_bytes())
        .filter(|rest| rest.len() == 65 && rest[32] == b'-')
        .is_some_and(|rest| hex(&rest[..32]) && hex(&rest[33..]))
}

/// Whether `levels.key_dir` is still the directory at `<launch>/<key>`.
/// `state rm` renames a state away from its path, under its lease, before
/// removing it, so a lease taken in a directory that is no longer there
/// holds nothing (review: `state rm` was not atomic).
fn linked(levels: &Levels) -> Result<bool, JailError> {
    let held = levels
        .key_dir
        .stat()
        .map_err(|error| write_failed(&levels.path, &error))?;
    match levels.launch_dir.stat_at(&name(&levels.key)) {
        Ok(now) => Ok(now.identity() == held.identity()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(write_failed(&levels.path, &error)),
    }
}

/// What [`lease_linked`] found.
enum Leasing {
    /// No state has that key (without `create`).
    Absent,
    /// The lease, taken in the directory linked at the key.
    Taken(Levels, Lease),
    /// Another process holds it.
    Busy(Levels),
}

/// How often [`lease_linked`] starts again on a directory renamed away under
/// it before it gives up.
const RELINK_TRIES: usize = 8;

/// Opens the levels (creating them with `create`) and takes the lease,
/// retried every 10 ms for `patience`, in the key directory that is linked
/// at `<launch>/<key>` once the lease is taken. A directory `state rm` renamed
/// away meanwhile is left, and the levels are opened again: a new state's,
/// with `create`.
fn lease_linked(
    data_dir: &Path,
    launch: &str,
    key: &str,
    create: bool,
    patience: std::time::Duration,
) -> Result<Leasing, JailError> {
    for _ in 0..RELINK_TRIES {
        let Some(levels) = open_levels(data_dir, launch, key, create)? else {
            return Ok(Leasing::Absent);
        };
        let started = std::time::Instant::now();
        while linked(&levels)? {
            match take_lease(&levels.key_dir, &levels.path) {
                Ok(Some(lease)) if linked(&levels)? => return Ok(Leasing::Taken(levels, lease)),
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() >= patience => return Ok(Leasing::Busy(levels)),
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
                Err(error) if linked(&levels)? => return Err(error),
                Err(_) => break,
            }
        }
    }
    Err(JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!(
            "{}: the state was removed under this lease {RELINK_TRIES} times in a row",
            key_path(data_dir, launch, key).display()
        ),
    ))
}

/// Opens `vendor/` below a key directory, creating it when absent, and puts
/// its mode back to 0700: the agent owns it inside the jail and may have
/// changed it, but no one else can reach it through the private key
/// directory.
fn open_vendor(levels: &Levels) -> Result<Dir, JailError> {
    let at = levels.path.join(VENDOR_NAME);
    let vendor = name(VENDOR_NAME);
    let dir = match levels.key_dir.stat_at(&vendor) {
        Ok(stat) => {
            if stat.kind != Kind::Directory {
                return Err(unsafe_state(&at, format!("is {}", stat.kind.describe())));
            }
            if stat.uid != crate::state::effective_uid() {
                return Err(unsafe_state(&at, "is not owned by this operator"));
            }
            if stat.mount_root == Some(true) {
                return Err(unsafe_state(&at, "is a mount point"));
            }
            match levels.key_dir.open_dir_at(&vendor, Some(&stat)) {
                Ok(dir) => dir,
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    levels
                        .key_dir
                        .chmod_at(&vendor, crate::state::DIRECTORY_MODE)
                        .map_err(|error| write_failed(&at, &error))?;
                    levels
                        .key_dir
                        .open_dir_at(&vendor, Some(&stat))
                        .map_err(|error| write_failed(&at, &error))?
                }
                Err(error) => return Err(write_failed(&at, &error)),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => levels
            .key_dir
            .mkdir_at(&vendor, crate::state::DIRECTORY_MODE)
            .map_err(|error| write_failed(&at, &error))?,
        Err(error) => return Err(write_failed(&at, &error)),
    };
    dir.chmod(crate::state::DIRECTORY_MODE)
        .map_err(|error| write_failed(&at, &error))?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// The manifest: the private digest and the secret scan (§4.5, §4.6)
// ---------------------------------------------------------------------------

/// Why a manifest has no digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unavailable {
    /// The pass reached its bound.
    TooLarge,
    /// An entry could not be read.
    Unreadable,
}

impl Unavailable {
    /// The `matches_release_reason` spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Unavailable::TooLarge => REASON_TOO_LARGE,
            Unavailable::Unreadable => REASON_UNREADABLE,
        }
    }
}

/// What one pass over `vendor/` established.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    /// `sha256:…` over the canonical manifest, or why there is none.
    pub digest: Result<String, Unavailable>,
    /// The files holding one of the searched values, relative to `vendor/`.
    pub hits: Vec<Vec<u8>>,
    /// Whether every regular file was searched whole.
    pub searched_all: bool,
    /// Entries the pass visited.
    pub entries: usize,
    /// Content bytes read.
    pub bytes: u64,
}

/// The pass's bounds, the seam's when [`SEAM_BOUNDS`] is set.
#[must_use]
pub fn bounds() -> (usize, u64) {
    std::env::var(SEAM_BOUNDS)
        .ok()
        .and_then(|value| {
            let (entries, bytes) = value.split_once(',')?;
            Some((entries.parse().ok()?, bytes.parse().ok()?))
        })
        .map_or(
            (MANIFEST_ENTRIES_MAX, MANIFEST_BYTES_MAX),
            |(entries, bytes): (usize, u64)| {
                (
                    entries.min(MANIFEST_ENTRIES_MAX),
                    bytes.min(MANIFEST_BYTES_MAX),
                )
            },
        )
}

/// A fixed-string search for several values across a stream read in
/// chunks: the tail of each chunk is kept so a value split across two reads
/// is still found.
struct Search<'a> {
    values: &'a [&'a [u8]],
    tail: Vec<u8>,
    found: bool,
}

impl<'a> Search<'a> {
    fn new(values: &'a [&'a [u8]]) -> Self {
        Search {
            values,
            tail: Vec::new(),
            found: false,
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        if self.found || self.values.is_empty() {
            return;
        }
        let longest = self
            .values
            .iter()
            .map(|value| value.len())
            .max()
            .unwrap_or(0);
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(chunk);
        if self
            .values
            .iter()
            .any(|value| !value.is_empty() && contains(&window, value))
        {
            self.found = true;
            return;
        }
        let keep = longest.saturating_sub(1).min(window.len());
        self.tail = window[window.len() - keep..].to_vec();
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

struct Pass<'a> {
    device: u64,
    entries_max: usize,
    bytes_max: u64,
    entries: usize,
    bytes: u64,
    unavailable: Option<Unavailable>,
    searched_all: bool,
    lines: Vec<Vec<u8>>,
    hits: Vec<Vec<u8>>,
    values: &'a [&'a [u8]],
}

/// One manifest pass over `vendor` (§4.6): sorted entries of relative path
/// bytes, type, permission bits, size, a regular file's content SHA-256 and
/// a symlink's target bytes, digested with SHA-256. Every regular file is
/// also searched for each of `values` (§4.5). Bounded by [`bounds`]: past
/// them, or when an entry cannot be read, there is no digest, and the
/// search did not cover every file.
#[must_use]
pub fn manifest(vendor: &Dir, values: &[&[u8]]) -> Manifest {
    let (entries_max, bytes_max) = bounds();
    let device = vendor.stat().map_or(0, |stat| stat.dev);
    let mut pass = Pass {
        device,
        entries_max,
        bytes_max,
        entries: 0,
        bytes: 0,
        unavailable: None,
        searched_all: true,
        lines: Vec::new(),
        hits: Vec::new(),
        values,
    };
    walk(&mut pass, vendor, &[], 0);
    let digest = match pass.unavailable {
        Some(reason) => Err(reason),
        None => {
            pass.lines.sort();
            let mut hash = Sha256::new();
            hash.update(b"ukai.jail.state-manifest/1\0");
            for line in &pass.lines {
                hash.update((line.len() as u64).to_be_bytes());
                hash.update(line);
            }
            Ok(format!("sha256:{}", hex(&hash.finalize())))
        }
    };
    Manifest {
        digest,
        hits: pass.hits,
        searched_all: pass.searched_all && pass.unavailable.is_none(),
        entries: pass.entries,
        bytes: pass.bytes,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn kind_code(kind: Kind) -> u8 {
    match kind {
        Kind::Regular => b'f',
        Kind::Directory => b'd',
        Kind::Symlink => b'l',
        Kind::Fifo => b'p',
        Kind::Socket => b's',
        Kind::CharDevice => b'c',
        Kind::BlockDevice => b'b',
        Kind::Other => b'?',
    }
}

fn walk(pass: &mut Pass<'_>, dir: &Dir, prefix: &[u8], depth: usize) {
    if pass.unavailable == Some(Unavailable::TooLarge) {
        return;
    }
    if depth >= DEPTH_MAX {
        pass.unavailable = Some(Unavailable::TooLarge);
        return;
    }
    let room = pass.entries_max.saturating_sub(pass.entries);
    let listing = match dir.names(room) {
        Ok(listing) => listing,
        Err(_) => {
            pass.unavailable.get_or_insert(Unavailable::Unreadable);
            pass.searched_all = false;
            return;
        }
    };
    if !listing.complete {
        pass.entries += listing.names.len();
        pass.unavailable = Some(Unavailable::TooLarge);
        pass.searched_all = false;
        return;
    }
    let mut names = listing.names;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for entry in names {
        pass.entries += 1;
        if pass.entries > pass.entries_max {
            pass.unavailable = Some(Unavailable::TooLarge);
            pass.searched_all = false;
            return;
        }
        let mut relative = prefix.to_vec();
        if !relative.is_empty() {
            relative.push(b'/');
        }
        relative.extend_from_slice(entry.as_bytes());
        let Ok(stat) = dir.stat_at(&entry) else {
            pass.unavailable.get_or_insert(Unavailable::Unreadable);
            pass.searched_all = false;
            continue;
        };
        let stat = readable(dir, &entry, stat);
        let mut line = relative.clone();
        line.push(0);
        line.push(kind_code(stat.kind));
        line.extend_from_slice(format!("\0{:o}\0{}\0", stat.mode & 0o7777, stat.size).as_bytes());
        // Never cross a device or a mount (§4.4): such an entry is named,
        // and the pass makes no claim about what lies behind it.
        let foreign = stat.dev != pass.device || stat.mount_root == Some(true);
        match stat.kind {
            _ if foreign => {
                pass.unavailable.get_or_insert(Unavailable::Unreadable);
                pass.searched_all = false;
            }
            Kind::Regular => match read_regular(pass, dir, &entry, &stat) {
                Ok((sha, found)) => {
                    line.extend_from_slice(sha.as_bytes());
                    if found {
                        pass.hits.push(relative.clone());
                    }
                }
                Err(reason) => {
                    pass.unavailable.get_or_insert(reason);
                    pass.searched_all = false;
                }
            },
            Kind::Symlink => match read_link(dir, &entry) {
                Ok(target) => line.extend_from_slice(&target),
                Err(_) => {
                    pass.unavailable.get_or_insert(Unavailable::Unreadable);
                }
            },
            Kind::Directory => {
                pass.lines.push(line);
                match dir.open_dir_at(&entry, Some(&stat)) {
                    Ok(child) => walk(pass, &child, &relative, depth + 1),
                    Err(_) => {
                        pass.unavailable.get_or_insert(Unavailable::Unreadable);
                        pass.searched_all = false;
                    }
                }
                if pass.unavailable == Some(Unavailable::TooLarge) {
                    return;
                }
                continue;
            }
            // FIFOs, sockets and devices (an overlayfs whiteout is a 0:0
            // character device anyone may create): recorded, never opened.
            _ => {}
        }
        pass.lines.push(line);
        if pass.unavailable == Some(Unavailable::TooLarge) {
            return;
        }
    }
}

/// A file or directory of the operator's own that its owner cannot read (or,
/// for a directory, search) gets those bits back before the pass reads it,
/// as the cleanup walker regains a directory before removing it: an agent
/// that set a file to mode 000 must not keep it out of the digest and the
/// scan (§4.5). `fchmodat` does not follow (`AT_SYMLINK_NOFOLLOW`), and the
/// entry must still be the object `stat` described; anything else, or a
/// failure, leaves `stat` as it was, and the read then fails as before.
fn readable(dir: &Dir, entry: &Name, stat: Stat) -> Stat {
    let needed = match stat.kind {
        Kind::Regular => 0o400,
        Kind::Directory => 0o500,
        _ => return stat,
    };
    if stat.mode & needed == needed || stat.uid != crate::state::effective_uid() {
        return stat;
    }
    if dir.chmod_at(entry, (stat.mode | needed) & 0o7777).is_err() {
        return stat;
    }
    match dir.stat_at(entry) {
        Ok(now) if now.kind == stat.kind && now.identity() == stat.identity() => now,
        _ => stat,
    }
}

/// Reads one regular file through a no-follow, non-blocking descriptor
/// checked against `stat`: its content SHA-256, and whether it holds one of
/// the searched values.
fn read_regular(
    pass: &mut Pass<'_>,
    dir: &Dir,
    entry: &Name,
    stat: &Stat,
) -> Result<(String, bool), Unavailable> {
    let mut file = dir
        .open_read_at(entry, Some(stat))
        .map_err(|_| Unavailable::Unreadable)?;
    let mut hash = Sha256::new();
    let mut search = Search::new(pass.values);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| Unavailable::Unreadable)?;
        if n == 0 {
            break;
        }
        pass.bytes += n as u64;
        if pass.bytes > pass.bytes_max {
            return Err(Unavailable::TooLarge);
        }
        hash.update(&buffer[..n]);
        search.feed(&buffer[..n]);
    }
    Ok((format!("{:x}", hash.finalize()), search.found))
}

/// The target bytes of a symlink entry, never followed.
fn read_link(dir: &Dir, entry: &Name) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 4096];
    // SAFETY: a live directory descriptor, a validated NUL-terminated
    // component and a buffer whose length is passed.
    let n = unsafe {
        libc::readlinkat(
            dir.as_fd().as_raw_fd(),
            entry.as_c().as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(usize::try_from(n).unwrap_or(0));
    Ok(buffer)
}

// ---------------------------------------------------------------------------
// The discard list (§4.5)
// ---------------------------------------------------------------------------

/// Removes every discard-list entry below `vendor` with the cleanup walker:
/// each relative path is walked component by component without following a
/// link, and the last entry, whatever it is, is removed itself (a symlink
/// as a link, a directory with its tree); its contents are never read.
/// Returns how many entries were removed.
///
/// # Errors
/// The safe reason a removal stopped.
pub fn discard(vendor: &Dir, list: &[NativeString]) -> Result<u64, String> {
    let mut removed = 0u64;
    for path in list {
        let components = crate::state::anchored::split_relative(path.as_bytes())
            .map_err(|error| format!("discard entry: {error}"))?;
        let Some((last, parents)) = components.split_last() else {
            continue;
        };
        let mut dir = vendor
            .try_clone_fd()
            .map(Dir::from_owned)
            .map_err(|e| e.to_string())?;
        let mut reachable = true;
        for component in parents {
            match dir.stat_at(component) {
                Ok(stat) if stat.kind == Kind::Directory && stat.mount_root != Some(true) => {
                    match dir.open_dir_at(component, Some(&stat)) {
                        Ok(next) => dir = next,
                        Err(_) => {
                            reachable = false;
                            break;
                        }
                    }
                }
                // Absent, or not a real directory (a symlink is never
                // followed): nothing lies at this path.
                _ => {
                    reachable = false;
                    break;
                }
            }
        }
        if !reachable {
            continue;
        }
        match dir.stat_at(last) {
            Ok(stat) if stat.kind == Kind::Directory => {
                let removal = crate::cleanup::remove_tree_at(
                    &dir,
                    last,
                    Some(stat.identity()),
                    crate::cleanup::Limits::DEFAULT,
                );
                if !removal.complete {
                    return Err(removal
                        .reason
                        .unwrap_or_else(|| "discard_incomplete".to_owned()));
                }
                removed += 1;
            }
            Ok(_) => {
                dir.unlink_at(last)
                    .map_err(|error| format!("discard: {error}"))?;
                removed += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("discard: {error}")),
        }
    }
    if removed > 0 {
        let _ = vendor.sync();
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Acquisition (§4.6)
// ---------------------------------------------------------------------------

/// Why an attempt did not get the persistent state it asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FallbackReason {
    /// Another attempt holds the lease.
    Held,
    /// The last holder never released it (a crashed supervisor).
    Unreleased,
}

impl FallbackReason {
    /// The receipt's `reason`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FallbackReason::Held => "held",
            FallbackReason::Unreleased => "unreleased",
        }
    }
}

/// A state the attempt could not take: it gets throwaway state instead, or
/// refuses `state_busy` when that could not be shown (§4.6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fallback {
    /// The state's id, when its record could be read.
    pub state_id: Option<String>,
    /// Held or unreleased.
    pub reason: FallbackReason,
    /// The attempt the record names: a live holder for `held`, the
    /// unreleased one for `unreleased`; `None` for "another attempt".
    pub held_by: Option<String>,
}

/// What acquisition read from the state before binding it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Start {
    /// `st_…`.
    pub state_id: String,
    /// The generation the attempt starts from.
    pub generation: u64,
    /// The attempt whose release produced it.
    pub inherited_from: Option<String>,
    /// Unchanged since that release, or `None`.
    pub matches_release: Option<bool>,
    /// Why `matches_release` is `None`.
    pub matches_release_reason: Option<&'static str>,
}

/// A held state: the lease, the levels, `vendor/` and the record as written
/// at acquisition.
pub struct Held {
    lease: Lease,
    /// The key directory.
    pub levels: Levels,
    /// `vendor/`, the directory the platform binds.
    pub vendor: Dir,
    /// The record with this attempt as its holder.
    pub record: Record,
    /// What the attempt started from.
    pub start: Start,
}

impl Held {
    /// `vendor/`'s host path, for diagnostics.
    #[must_use]
    pub fn vendor_path(&self) -> PathBuf {
        self.levels.path.join(VENDOR_NAME)
    }
}

/// What [`acquire`] decided.
pub enum Acquisition {
    /// The attempt holds the state.
    Held(Box<Held>),
    /// The state is busy.
    Fallback(Fallback),
}

/// What an attempt asks of [`acquire`].
pub struct Request<'a> {
    /// The data directory.
    pub data_dir: &'a Path,
    /// The launch profile name.
    pub launch: &'a str,
    /// The canonical workspace.
    pub workspace: &'a Path,
    /// This attempt.
    pub attempt: &'a str,
}

fn quarantined(levels: &Levels, quarantine: &Quarantine, request: &Request<'_>) -> JailError {
    let verb = |verb: &str| {
        format!(
            "`ukai-jail state {verb} {} --workspace {}`",
            request.launch,
            request.workspace.display()
        )
    };
    JailError::new(
        ErrorCode::StateQuarantined,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!(
            "the persistent state for this launch profile and workspace is quarantined ({} at \
             the release of {}); inspect it with {}, act on the credential, then remove it \
             with {} ({})",
            quarantine.reason,
            quarantine.attempt,
            verb("show"),
            verb("rm"),
            levels.path.display()
        ),
    )
}

/// Whether `attempt`'s supervisor is alive: its `jail.lock` is held.
#[must_use]
pub fn attempt_live(data_dir: &Path, attempt: &str) -> bool {
    let Ok(id) = crate::state::AttemptId::parse(attempt) else {
        return false;
    };
    let dir = crate::state::AttemptDir::new(data_dir, &id);
    matches!(
        crate::state::Lease::probe_existing(&dir.lock_path()),
        Ok(crate::state::LeaseProbe::Held)
    )
}

/// §4.6 steps 1 to 6, up to (not including) the record of this attempt as
/// holder, which [`hold`] writes once jail state registered the state.
///
/// # Errors
/// `unsafe_state_path` for a level that fails its checks,
/// `state_quarantined`, `state_workspace_changed`, and
/// `state_write_failed` for a level or record that cannot be read or made.
pub fn acquire(request: &Request<'_>) -> Result<Acquisition, JailError> {
    let workspace_bytes = request.workspace.as_os_str().as_bytes();
    let key = key(request.launch, workspace_bytes);
    // Step 2: the lease, without blocking for long.
    let (levels, lease) =
        match lease_linked(request.data_dir, request.launch, &key, true, LEASE_PATIENCE)? {
            Leasing::Taken(levels, lease) => (levels, lease),
            Leasing::Absent => {
                return Err(unsafe_state(
                    request.data_dir,
                    "the state levels could not be made",
                ));
            }
            Leasing::Busy(levels) => {
                // The record can lag the lease by an instant: it names the
                // holder only when that attempt is alive.
                let record = read_record(&levels.key_dir, &levels.path).ok().flatten();
                let held_by = record
                    .as_ref()
                    .and_then(|record| record.holder.as_ref())
                    .map(|holder| holder.attempt.clone())
                    .filter(|attempt| attempt_live(request.data_dir, attempt));
                return Ok(Acquisition::Fallback(Fallback {
                    state_id: record.map(|record| record.state_id),
                    reason: FallbackReason::Held,
                    held_by,
                }));
            }
        };
    // Step 3: the record.
    let workspace_identity = std::fs::metadata(request.workspace)
        .map(|metadata| {
            use std::os::unix::fs::MetadataExt as _;
            (metadata.dev(), metadata.ino())
        })
        .map_err(|error| write_failed(request.workspace, &error))?;
    let record = match read_record(&levels.key_dir, &levels.path)? {
        Some(record) => record,
        None => {
            // The record is written before `vendor/` is first made, so a
            // `vendor/` without one was left by something else (a removal
            // an earlier build interrupted, a hand): whose content it is
            // cannot be told, and it is never adopted as a new state.
            match levels.key_dir.stat_at(&name(VENDOR_NAME)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(write_failed(&levels.path, &error)),
                Ok(_) => {
                    return Err(unsafe_state(
                        &levels.path,
                        format!(
                            "has `vendor/` but no state.json, so who wrote what it holds \
                             cannot be told; remove it with `ukai-jail state rm {} --workspace {}`",
                            request.launch,
                            request.workspace.display()
                        ),
                    ));
                }
            }
            let record = Record::new(request.launch, request.workspace, workspace_identity)?;
            write_record(&levels.key_dir, &levels.path, &record)?;
            record
        }
    };
    if record.launch != request.launch || record.workspace.as_bytes() != workspace_bytes {
        return Err(unsafe_state(
            &levels.path,
            "records another launch profile or workspace than its key",
        ));
    }
    // A quarantine is the operator's to act on: no fallback.
    if let Some(quarantine) = &record.quarantine {
        return Err(quarantined(&levels, quarantine, request));
    }
    if let Some(holder) = record.holder.as_ref().filter(|holder| !holder.released) {
        // Its tree may still be writing; `gc` finishes the release.
        let held_by = Some(holder.attempt.clone());
        drop(lease);
        return Ok(Acquisition::Fallback(Fallback {
            state_id: Some(record.state_id),
            reason: FallbackReason::Unreleased,
            held_by,
        }));
    }
    // Step 4: the workspace check (§4.3).
    if record.workspace_identity.0 != workspace_identity {
        return Err(JailError::new(
            ErrorCode::StateWorkspaceChanged,
            ErrorStage::Preparing,
            Remediation::Configuration,
            format!(
                "the workspace {} is not the directory the persistent state was made for (it \
                 was removed and made again at the same path); remove the old state with \
                 `ukai-jail state rm {} --workspace {}`",
                request.workspace.display(),
                request.launch,
                request.workspace.display()
            ),
        ));
    }
    // Step 5: the private digest, compared with the last release's.
    let vendor = open_vendor(&levels)?;
    let current = manifest(&vendor, &[]);
    let (matches_release, matches_release_reason) = match &record.last_release {
        None => (None, Some(REASON_NEW_STATE)),
        Some(last) => match (&last.digest, &current.digest) {
            (Some(released), Ok(now)) => (Some(released == now), None),
            (None, _) => (
                None,
                Some(match last.digest_unavailable.as_deref() {
                    Some(REASON_UNREADABLE) => REASON_UNREADABLE,
                    _ => REASON_TOO_LARGE,
                }),
            ),
            (_, Err(reason)) => (None, Some(reason.as_str())),
        },
    };
    let start = Start {
        state_id: record.state_id.clone(),
        generation: record.generation,
        inherited_from: record
            .last_release
            .as_ref()
            .map(|last| last.attempt.clone()),
        matches_release,
        matches_release_reason,
    };
    Ok(Acquisition::Held(Box::new(Held {
        lease,
        levels,
        vendor,
        record,
        start,
    })))
}

/// §4.6 step 6: records this attempt as the unreleased holder, durably.
/// Only after this is the state bound.
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`].
pub fn hold(held: &mut Held, attempt: &str) -> Result<(), JailError> {
    held.record.holder = Some(Holder {
        attempt: attempt.to_owned(),
        released: false,
    });
    write_record(&held.levels.key_dir, &held.levels.path, &held.record)
}

// ---------------------------------------------------------------------------
// Release (§4.6)
// ---------------------------------------------------------------------------

/// What a release did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Released {
    /// The generation recorded.
    pub generation: u64,
    /// Discard-list entries removed.
    pub discarded: u64,
    /// `clean`, `found` or `not_scanned`.
    pub secret_scan: &'static str,
    /// The files that held a vault value (for the operator only).
    pub hits: usize,
}

/// Who releases.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Releaser {
    /// The supervisor that held the state, which holds the vault values.
    /// `every_value`: the values given are every one the attempt loaded (a
    /// secret remembers a bounded number of distinct values; past it, the
    /// scan is `not_scanned`, review F13).
    Supervisor {
        /// Whether no loaded value was forgotten.
        every_value: bool,
    },
    /// `gc`, which holds none: the scan is `not_scanned`.
    Gc,
}

/// §4.6 release, steps 1 to 4: the discard list, the digest and the scan
/// (`values` are the vault credentials' values this attempt loaded), the
/// generation and its log entry, the holder released durably, then the
/// lease dropped (with `held`). A value found quarantines the state.
///
/// # Errors
/// The safe reason the release stopped; the state stays unreleased, so the
/// next attempt takes the `unreleased` fallback until `gc` finishes it.
pub fn release(
    held: Held,
    attempt: &str,
    discard_list: &[NativeString],
    values: &[&[u8]],
    by: Releaser,
) -> Result<Released, String> {
    let Held {
        lease,
        levels,
        vendor,
        mut record,
        start,
    } = held;
    let result = release_levels(
        &levels,
        &vendor,
        &mut record,
        attempt,
        discard_list,
        values,
        by,
        start.matches_release,
    );
    drop(lease);
    result
}

/// [`release`] over opened levels and `vendor/`, for the supervisor and for
/// `gc`, which takes the lease itself.
#[allow(clippy::too_many_arguments)]
fn release_levels(
    levels: &Levels,
    vendor: &Dir,
    record: &mut Record,
    attempt: &str,
    discard_list: &[NativeString],
    values: &[&[u8]],
    by: Releaser,
    matches_release: Option<bool>,
) -> Result<Released, String> {
    if !record.held_unreleased_by(attempt) {
        return Err("state_not_held_by_this_attempt".to_owned());
    }
    let discarded = discard(vendor, discard_list)?;
    let pass = manifest(vendor, values);
    let secret_scan = if !pass.hits.is_empty() {
        "found"
    } else if !matches!(by, Releaser::Supervisor { every_value: true }) || !pass.searched_all {
        "not_scanned"
    } else {
        "clean"
    };
    let at = now();
    record.generation += 1;
    record.last_release = Some(LastRelease {
        attempt: attempt.to_owned(),
        digest: pass.digest.as_ref().ok().cloned(),
        digest_unavailable: pass
            .digest
            .as_ref()
            .err()
            .map(|reason| reason.as_str().to_owned()),
        at: at.clone(),
    });
    record.log.push(Generation {
        generation: record.generation,
        attempt: attempt.to_owned(),
        by: match by {
            Releaser::Supervisor { .. } => "supervisor",
            Releaser::Gc => "gc",
        }
        .to_owned(),
        at: at.clone(),
        digest: pass.digest.as_ref().ok().cloned(),
        matches_release,
        discarded,
        secret_scan: secret_scan.to_owned(),
    });
    if record.log.len() > LOG_MAX {
        let excess = record.log.len() - LOG_MAX;
        record.log.drain(..excess);
    }
    if !pass.hits.is_empty() {
        // Bounded, so that many hits with long names cannot make the record
        // one the next acquisition refuses to read (review: the quarantine
        // then read as `unsafe_state_path`).
        let mut files = Vec::new();
        let mut name_bytes = 0;
        for path in &pass.hits {
            name_bytes += path.len();
            if files.len() == QUARANTINE_FILES_MAX || name_bytes > QUARANTINE_NAME_BYTES_MAX {
                break;
            }
            files.extend(NativeString::from_bytes(path.clone()).ok());
        }
        record.quarantine = Some(Quarantine {
            reason: "credential_persisted".to_owned(),
            attempt: attempt.to_owned(),
            at,
            files_omitted: u64::try_from(pass.hits.len() - files.len()).unwrap_or(u64::MAX),
            files,
        });
    }
    record.holder = Some(Holder {
        attempt: attempt.to_owned(),
        released: true,
    });
    write_record(&levels.key_dir, &levels.path, record).map_err(|error| error.message)?;
    Ok(Released {
        generation: record.generation,
        discarded,
        secret_scan,
        hits: pass.hits.len(),
    })
}

/// What `gc` found for one attempt's registered persistent state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GcRelease {
    /// The record names another holder, or this one already released it:
    /// nothing of this attempt's is left in the state.
    NotHeld,
    /// Another process holds the lease now.
    LeaseHeld,
    /// A dry run: the release would run.
    WouldRelease,
    /// This pass released it.
    Released(Released),
    /// Quarantined for lost integrity, left unreleased.
    Quarantined,
}

/// `gc` finishing a pending release (§4.9): the same steps, with the scan
/// `not_scanned` (only the dead supervisor held the vault values). With
/// `integrity_lost`, the state stays held and is quarantined instead.
///
/// # Errors
/// The safe reason it stopped.
pub fn gc_release(
    data_dir: &Path,
    launch: &str,
    key: &str,
    attempt: &str,
    discard_list: &[NativeString],
    dry_run: bool,
    integrity_lost: bool,
) -> Result<GcRelease, String> {
    let holds = |levels: &Levels| -> Result<Option<Record>, String> {
        Ok(read_record(&levels.key_dir, &levels.path)
            .map_err(|error| error.message)?
            .filter(|record| record.held_unreleased_by(attempt)))
    };
    if dry_run {
        let Some(levels) =
            open_levels(data_dir, launch, key, false).map_err(|error| error.message)?
        else {
            return Ok(GcRelease::NotHeld);
        };
        return Ok(match holds(&levels)? {
            Some(_) => GcRelease::WouldRelease,
            None => GcRelease::NotHeld,
        });
    }
    #[cfg(test)]
    tests::before_gc_lease();
    // The lease first, then the record written back: a copy read before the
    // lease may be one another `gc` has released since, and writing it back
    // would undo that release and every one after it (review: two `gc`
    // runs).
    let (levels, lease) =
        match lease_linked(data_dir, launch, key, false, std::time::Duration::ZERO)
            .map_err(|error| error.message)?
        {
            Leasing::Taken(levels, lease) => (levels, lease),
            // Read without the lease only to say whether anything is left.
            Leasing::Busy(levels) => {
                return Ok(match holds(&levels)? {
                    Some(_) => GcRelease::LeaseHeld,
                    None => GcRelease::NotHeld,
                });
            }
            Leasing::Absent => return Ok(GcRelease::NotHeld),
        };
    let Some(mut record) = holds(&levels)? else {
        return Ok(GcRelease::NotHeld);
    };
    if integrity_lost {
        record.quarantine.get_or_insert_with(|| Quarantine {
            reason: "integrity_lost".to_owned(),
            attempt: attempt.to_owned(),
            at: now(),
            files: Vec::new(),
            files_omitted: 0,
        });
        write_record(&levels.key_dir, &levels.path, &record).map_err(|error| error.message)?;
        drop(lease);
        return Ok(GcRelease::Quarantined);
    }
    let vendor = open_vendor(&levels).map_err(|error| error.message)?;
    // The attempt's own comparison at acquisition is in its receipt, which
    // `gc` does not carry over: the log says nothing about it.
    let released = release_levels(
        &levels,
        &vendor,
        &mut record,
        attempt,
        discard_list,
        &[],
        Releaser::Gc,
        None,
    );
    drop(lease);
    released.map(GcRelease::Released)
}

// ---------------------------------------------------------------------------
// The `state` verbs (§4.9)
// ---------------------------------------------------------------------------

/// One state, as `state list` reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Listed {
    /// The launch profile name.
    pub launch: String,
    /// The key.
    pub key: String,
    /// The record, or why it could not be read.
    pub record: Result<Record, String>,
    /// Bytes of regular files below `vendor/`, when the bounded walk could
    /// count them.
    pub size: Option<u64>,
    /// Whether an attempt holds the lease now.
    pub leased: bool,
    /// A `state rm` of this key that stopped: its tombstone, which no
    /// acquisition takes and `gc` finishes (`record` says so).
    pub removing: bool,
}

/// Every state below `<data>/state`, bounded like a manifest pass.
///
/// # Errors
/// The state root fails its checks or cannot be listed.
pub fn list(data_dir: &Path) -> Result<Vec<Listed>, JailError> {
    crate::state::check_state_dir(data_dir)?;
    let data = Dir::open_trusted(data_dir).map_err(|error| write_failed(data_dir, &error))?;
    let root_path = data_dir.join(STATE_DIR_NAME);
    let Some(root) = level(&data, &root_path, STATE_DIR_NAME, false)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let launches = root
        .names(MANIFEST_ENTRIES_MAX)
        .map_err(|error| write_failed(&root_path, &error))?;
    let mut launches = launches.names;
    launches.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for launch in launches {
        let Ok(launch_text) = std::str::from_utf8(launch.as_bytes()) else {
            continue;
        };
        let launch_path = root_path.join(launch_text);
        let Ok(Some(launch_dir)) = level(&root, &launch_path, launch_text, false) else {
            continue;
        };
        let Ok(keys) = launch_dir.names(MANIFEST_ENTRIES_MAX) else {
            continue;
        };
        let mut keys = keys.names;
        keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for key in keys {
            let Ok(key_text) = std::str::from_utf8(key.as_bytes()) else {
                continue;
            };
            if is_tombstone(key.as_bytes()) {
                out.push(Listed {
                    launch: launch_text.to_owned(),
                    key: key_text[TOMBSTONE_PREFIX.len()..][..32].to_owned(),
                    record: Err(format!(
                        "a `state rm` stopped; what is left is at {} and `ukai-jail gc` \
                         finishes it",
                        launch_path.join(key_text).display()
                    )),
                    size: None,
                    leased: false,
                    removing: true,
                });
                continue;
            }
            let key_path = launch_path.join(key_text);
            let Ok(Some(key_dir)) = level(&launch_dir, &key_path, key_text, false) else {
                continue;
            };
            let levels = Levels {
                path: key_path,
                key_dir,
                launch_dir: launch_dir
                    .try_clone_fd()
                    .map(Dir::from_owned)
                    .map_err(|error| write_failed(&launch_path, &error))?,
                key: key_text.to_owned(),
            };
            out.push(describe(&levels, launch_text));
        }
    }
    Ok(out)
}

fn describe(levels: &Levels, launch: &str) -> Listed {
    let record = read_record(&levels.key_dir, &levels.path)
        .map_err(|error| error.message)
        .and_then(|record| record.ok_or_else(|| "no state.json".to_owned()));
    let size = levels
        .key_dir
        .stat_at(&name(VENDOR_NAME))
        .ok()
        .filter(|stat| stat.kind == Kind::Directory)
        .and_then(|stat| {
            levels
                .key_dir
                .open_dir_at(&name(VENDOR_NAME), Some(&stat))
                .ok()
        })
        .and_then(|vendor| {
            let pass = manifest(&vendor, &[]);
            pass.digest.is_ok().then_some(pass.bytes)
        });
    let leased = match take_lease(&levels.key_dir, &levels.path) {
        Ok(Some(lease)) => {
            drop(lease);
            false
        }
        Ok(None) => true,
        Err(_) => false,
    };
    Listed {
        launch: launch.to_owned(),
        key: levels.key.clone(),
        record,
        size,
        leased,
        removing: false,
    }
}

/// The state for `launch` and `workspace`, as `state show` reports it.
///
/// # Errors
/// As [`open_levels`].
pub fn show(data_dir: &Path, launch: &str, workspace: &Path) -> Result<Option<Listed>, JailError> {
    let key = key(launch, workspace.as_os_str().as_bytes());
    Ok(open_levels(data_dir, launch, &key, false)?.map(|levels| describe(&levels, launch)))
}

/// What `state rm` did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Removed {
    /// No state exists for that launch profile and workspace.
    Absent,
    /// An attempt holds it: nothing was removed.
    Leased,
    /// It is gone.
    Removed {
        /// Its key directory.
        path: PathBuf,
    },
}

/// `state rm`: refused while leased; then, under the lease, the key
/// directory is renamed to a tombstone (`.removing-<key>-<random>`) and the
/// launch directory synced, so nothing finds a partly removed state at its
/// path, and the tombstone is removed by an anchored, no-follow walk
/// (symlinks, FIFOs and sockets removed as entries). A removal that stops
/// leaves the tombstone, which `state list` reports and `gc` finishes
/// (review: `state rm` was not atomic).
///
/// # Errors
/// As [`open_levels`], and the safe reason the removal stopped.
pub fn remove(data_dir: &Path, launch: &str, workspace: &Path) -> Result<Removed, JailError> {
    let key = key(launch, workspace.as_os_str().as_bytes());
    let (levels, lease) =
        match lease_linked(data_dir, launch, &key, false, std::time::Duration::ZERO)? {
            Leasing::Absent => return Ok(Removed::Absent),
            Leasing::Busy(_) => return Ok(Removed::Leased),
            Leasing::Taken(levels, lease) => (levels, lease),
        };
    let identity = levels
        .key_dir
        .stat()
        .map_err(|error| write_failed(&levels.path, &error))?
        .identity();
    let tombstone = name(&format!(
        "{TOMBSTONE_PREFIX}{key}-{}",
        uuid::Uuid::new_v4().simple()
    ));
    let tombstone_path = levels
        .path
        .with_file_name(OsStr::from_bytes(tombstone.as_bytes()));
    levels
        .launch_dir
        .rename_at(&name(&key), &levels.launch_dir, &tombstone)
        .and_then(|()| levels.launch_dir.sync())
        .map_err(|error| write_failed(&levels.path, &error))?;
    let removal = finish_removal(&levels.launch_dir, &tombstone, Some(identity), usize::MAX);
    drop(lease);
    if !removal.complete {
        return Err(JailError::new(
            ErrorCode::StateWriteFailed,
            ErrorStage::Reconciling,
            Remediation::InspectState,
            format!(
                "{}: the removal stopped: {}; what is left is at {}, which no attempt \
                 acquires, and `ukai-jail gc` finishes it",
                levels.path.display(),
                removal.reason.unwrap_or_else(|| "unknown".to_owned()),
                tombstone_path.display()
            ),
        ));
    }
    Ok(Removed::Removed { path: levels.path })
}

/// Removes the tombstone `entry` below a launch directory, within `budget`
/// entries (and [`crate::cleanup::Limits::DEFAULT`]'s), and syncs the
/// launch directory once it is gone.
fn finish_removal(
    launch_dir: &Dir,
    entry: &Name,
    expected: Option<(u64, u64)>,
    budget: usize,
) -> crate::cleanup::Removal {
    let mut limits = crate::cleanup::Limits::DEFAULT;
    limits.max_entries = limits.max_entries.min(budget);
    let removal = crate::cleanup::remove_tree_at(launch_dir, entry, expected, limits);
    if removal.complete {
        let _ = launch_dir.sync();
    }
    removal
}

/// What `gc` did with one tombstone a stopped `state rm` left.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FinishedRemoval {
    /// `<launch>/<tombstone>`.
    pub name: String,
    /// `removed`, `would_remove` or `pending: <reason>`.
    pub outcome: String,
    /// Entries the removal charged against `gc`'s bound.
    pub charged: usize,
}

/// `gc`: finishes every `state rm` that stopped, within `budget` entries.
/// A tombstone is no state: `rm` took it from its path under its lease, so
/// finishing it removes nothing an attempt could acquire (§4.9: `gc` never
/// removes a state on its own). With `dry_run`, it only says what it would
/// do.
///
/// # Errors
/// The state root fails its checks or cannot be listed.
pub fn finish_removals(
    data_dir: &Path,
    dry_run: bool,
    budget: usize,
) -> Result<Vec<FinishedRemoval>, JailError> {
    let data = Dir::open_trusted(data_dir).map_err(|error| write_failed(data_dir, &error))?;
    let root_path = data_dir.join(STATE_DIR_NAME);
    let Some(root) = level(&data, &root_path, STATE_DIR_NAME, false)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut room = budget;
    let launches = root
        .names(MANIFEST_ENTRIES_MAX)
        .map_err(|error| write_failed(&root_path, &error))?;
    for launch in launches.names {
        let Ok(launch_text) = std::str::from_utf8(launch.as_bytes()) else {
            continue;
        };
        let launch_path = root_path.join(launch_text);
        let Ok(Some(launch_dir)) = level(&root, &launch_path, launch_text, false) else {
            continue;
        };
        let Ok(entries) = launch_dir.names(MANIFEST_ENTRIES_MAX) else {
            continue;
        };
        let mut tombstones: Vec<Name> = entries
            .names
            .into_iter()
            .filter(|entry| is_tombstone(entry.as_bytes()))
            .collect();
        tombstones.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for tombstone in tombstones {
            let shown = format!(
                "{launch_text}/{}",
                String::from_utf8_lossy(tombstone.as_bytes())
            );
            if dry_run {
                out.push(FinishedRemoval {
                    name: shown,
                    outcome: "would_remove".to_owned(),
                    charged: 0,
                });
                continue;
            }
            let removal = finish_removal(&launch_dir, &tombstone, None, room);
            let charged = if removal.complete {
                removal.visited.min(room)
            } else {
                room
            };
            room -= charged;
            out.push(FinishedRemoval {
                name: shown,
                outcome: if removal.complete {
                    "removed".to_owned()
                } else {
                    format!(
                        "pending: {}",
                        removal.reason.unwrap_or_else(|| "unknown".to_owned())
                    )
                },
                charged,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        /// What [`gc_release`] runs on this thread just before it takes the
        /// lease: another `gc`, and the attempts after it, in that gap.
        static BEFORE_GC_LEASE: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    pub(super) fn before_gc_lease() {
        if let Some(hook) = BEFORE_GC_LEASE.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    /// A private data directory and a workspace below it.
    fn data_and_workspace() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::Builder::new()
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir()
            .unwrap();
        let base = root.path().canonicalize().unwrap();
        let (data, workspace) = (base.join("data"), base.join("workspace"));
        for dir in [&data, &workspace] {
            std::fs::create_dir(dir).unwrap();
            std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
        }
        (root, data, workspace)
    }

    /// K71 (review: two `gc` runs): `gc` writes back only a record it read
    /// under the lease. A `gc` that read the record, then lost the race for
    /// the lease to another `gc` that released the state, and to an attempt
    /// that acquired and released it after, finds nothing to release; before,
    /// it wrote its stale copy back, undoing both releases.
    #[test]
    fn k71_a_gc_never_writes_back_a_record_read_before_the_lease() {
        let (_root, data, workspace) = data_and_workspace();
        let request = |attempt: &str| {
            let request = Request {
                data_dir: &data,
                launch: "keeper",
                workspace: &workspace,
                attempt,
            };
            match acquire(&request).unwrap() {
                Acquisition::Held(held) => held,
                Acquisition::Fallback(fallback) => panic!("{fallback:?}"),
            }
        };
        let key = key("keeper", workspace.as_os_str().as_bytes());
        // The holder died without releasing.
        let mut held = request("att_dead");
        hold(&mut held, "att_dead").unwrap();
        drop(held);
        let (hook_data, hook_key, hook_workspace) = (data.clone(), key.clone(), workspace.clone());
        BEFORE_GC_LEASE.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let other = gc_release(
                    &hook_data,
                    "keeper",
                    &hook_key,
                    "att_dead",
                    &[],
                    false,
                    false,
                );
                assert!(matches!(other, Ok(GcRelease::Released(_))), "{other:?}");
                let mut next = match acquire(&Request {
                    data_dir: &hook_data,
                    launch: "keeper",
                    workspace: &hook_workspace,
                    attempt: "att_next",
                })
                .unwrap()
                {
                    Acquisition::Held(held) => held,
                    Acquisition::Fallback(fallback) => panic!("{fallback:?}"),
                };
                hold(&mut next, "att_next").unwrap();
                release(*next, "att_next", &[], &[], Releaser::Gc).unwrap();
            }));
        });
        let late = gc_release(&data, "keeper", &key, "att_dead", &[], false, false);
        assert_eq!(late, Ok(GcRelease::NotHeld));
        let levels = open_levels(&data, "keeper", &key, false).unwrap().unwrap();
        let record = read_record(&levels.key_dir, &levels.path).unwrap().unwrap();
        assert_eq!(record.generation, 2, "{record:#?}");
        assert_eq!(
            record.holder,
            Some(Holder {
                attempt: "att_next".to_owned(),
                released: true
            })
        );
        assert_eq!(
            record
                .log
                .iter()
                .map(|entry| entry.attempt.as_str())
                .collect::<Vec<_>>(),
            ["att_dead", "att_next"]
        );
    }

    #[test]
    fn the_key_is_the_documented_construction() {
        let mut hash = Sha256::new();
        hash.update(b"ukai.jail.state/1\0demo\0/work/repo");
        let expected: String = hash.finalize()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(key("demo", b"/work/repo"), expected);
        assert_eq!(expected.len(), 32);
        assert_ne!(key("demo", b"/work/repo"), key("demo", b"/work/other"));
        assert_ne!(key("demo", b"/work/repo"), key("other", b"/work/repo"));
        // The separator keeps a name and a path from sliding into each other.
        assert_ne!(key("ab", b"c/x"), key("a", b"bc/x"));
    }

    #[test]
    fn a_value_split_across_reads_is_found() {
        let values: [&[u8]; 1] = [b"secret-value"];
        let mut search = Search::new(&values);
        search.feed(b"xxxx secr");
        assert!(!search.found);
        search.feed(b"et-val");
        assert!(!search.found);
        search.feed(b"ue yyyy");
        assert!(search.found);
        let mut none = Search::new(&values);
        none.feed(b"secret-valu");
        none.feed(b"E");
        assert!(!none.found);
    }
}
