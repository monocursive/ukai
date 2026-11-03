//! The live-workspace share's host-side preflight (J18 §6, K109).
//!
//! The measured 2026-11-02 probe (see
//! `docs/benchmarks/jail/results/macos-vm-share-2026-11-02/`) found two
//! escapes no guest-side policy can stop, so the host refuses them before
//! any VM boots: a pre-existing hardlink inside the workspace writes
//! through to whatever host file it names, and a case-folding volume maps
//! a guest's `.GIT/config` onto the denied `.git/config`. Symlinks are
//! safe by construction (virtio-fs resolves them client-side) but are
//! refused uniformly, as the staged mode always did. Unicode normalization
//! folding is measured even on case-sensitive APFS, but only collides
//! names that differ in decomposition — the protected segments are pure
//! ASCII — so it is a recorded disclosure, and a future policy naming a
//! decomposable protected path must refuse on it.
//!
//! Three more shapes refuse, none of them measured through the share: a
//! nested mount (an entry on another device than the workspace root), whose
//! volume the folding probes never looked at and whose contents the share
//! may expose with another volume's rules; and FIFOs, sockets and device
//! nodes, which are no workspace content and whose behaviour across
//! virtio-fs (a guest open reaching a host process or device) nobody
//! measured.

use std::ffi::CString;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// What the preflight proved about the workspace, recorded in the attempt
/// and transport records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareFacts {
    pub case_fold: bool,
    pub normalization_fold: bool,
}

/// The prefix of the private directory the folding probes run in.
const PROBE_PREFIX: &str = ".ukai-fold-probe-";

/// How many fresh names the probe directory tries before it refuses.
const PROBE_ATTEMPTS: usize = 8;

/// The probe files inside the private directory: a lower-case name and its
/// upper-case twin, then `cafe` + combining acute (NFD) and the precomposed
/// `café` (NFC).
const PROBE_LOW: &str = "case";
const PROBE_UPPER: &str = "CASE";
const PROBE_NFD: &str = "cafe\u{301}";
const PROBE_NFC: &str = "caf\u{e9}";

/// Walk the workspace refusing symlinks, regular files with more than one
/// hard link, FIFOs, sockets, device nodes, and any entry on another device
/// than the workspace root (a nested mount). Directories' own link counts
/// (their `.` and `..` entries) are not escapes.
fn scan(workspace: &Path, device: u64) -> Result<(), String> {
    let mut pending = vec![workspace.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("{} cannot be read: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!(
                    "live workspace may not contain symlinks (measured: they stay guest-side, \
                     but the preview refuses them uniformly): {}",
                    path.display()
                ));
            }
            if metadata.dev() != device {
                return Err(format!(
                    "live workspace may not contain another mount: {} is on another device \
                     than the workspace, which the share's preflight never examined",
                    path.display()
                ));
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            // Anything else that is not a regular file: a FIFO, a socket, a
            // device node.
            if !file_type.is_file() {
                return Err(format!(
                    "live workspace may contain only directories and regular files: {} is a \
                     FIFO, socket or device node, whose behaviour across the share is not \
                     measured",
                    path.display()
                ));
            }
            if metadata.nlink() > 1 {
                return Err(format!(
                    "live workspace contains files with more than one hard link (measured \
                     write-through escape to the link target): {} ({} links)",
                    path.display(),
                    metadata.nlink()
                ));
            }
        }
    }
    Ok(())
}

fn c_name(name: &str) -> Result<CString, String> {
    CString::new(name).map_err(|_| format!("a probe name held a NUL: {name:?}"))
}

fn last_error(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Opens `path` as a directory, refusing a link.
fn open_directory(path: &Path) -> Result<OwnedFd, String> {
    let text = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} holds a NUL", path.display()))?;
    // SAFETY: `open` with a NUL-terminated path; the flags ask for a
    // directory that is not a link, and the descriptor is owned from here.
    let fd = unsafe {
        libc::open(
            text.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last_error(&format!("{} cannot be opened", path.display())));
    }
    // SAFETY: `fd` is a freshly opened, owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The private probe directory, fresh beneath the workspace: created
/// exclusively (`mkdirat` never reuses a name, and a planted entry of that
/// name is a refusal, not a target), mode 0700, opened without following a
/// link. Its name is random, so a stale or planted one is skipped.
fn probe_directory(workspace: &OwnedFd) -> Result<(String, OwnedFd), String> {
    use std::hash::{BuildHasher as _, Hasher as _};
    for _ in 0..PROBE_ATTEMPTS {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        let name = format!("{PROBE_PREFIX}{:016x}", hasher.finish());
        let text = c_name(&name)?;
        // SAFETY: `mkdirat` on the owned workspace descriptor with a
        // NUL-terminated single-component name.
        if unsafe { libc::mkdirat(workspace.as_raw_fd(), text.as_ptr(), 0o700) } != 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(last_error("the folding probe directory cannot be created"));
        }
        // SAFETY: `openat` with a NUL-terminated name on the owned
        // descriptor; `O_NOFOLLOW` refuses a link swapped in since.
        let fd = unsafe {
            libc::openat(
                workspace.as_raw_fd(),
                text.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = last_error("the folding probe directory cannot be opened");
            // SAFETY: as above; removes only an empty directory.
            unsafe { libc::unlinkat(workspace.as_raw_fd(), text.as_ptr(), libc::AT_REMOVEDIR) };
            return Err(error);
        }
        // SAFETY: `fd` is a freshly opened, owned descriptor.
        return Ok((name, unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    Err(format!(
        "no fresh folding probe directory after {PROBE_ATTEMPTS} names"
    ))
}

/// Creates `name` in `directory` exclusively and without following a link:
/// `Ok(true)` when it was created, `Ok(false)` when an entry of that name
/// already exists (which, in a fresh private directory, only a folding
/// volume makes).
fn create_exclusive(directory: &OwnedFd, name: &str) -> Result<bool, String> {
    let text = c_name(name)?;
    // SAFETY: `openat` with a NUL-terminated name on the owned descriptor;
    // the flags create the file exclusively and refuse a link.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            text.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
            return Ok(false);
        }
        return Err(last_error(&format!("the folding probe `{name}` failed")));
    }
    // SAFETY: `fd` is a freshly created, owned descriptor; closing it is all.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(true)
}

/// Whether an entry `name` exists in `directory`, not following a link.
fn exists_at(directory: &OwnedFd, name: &str) -> Result<bool, String> {
    let text = c_name(name)?;
    // SAFETY: an all-zero `stat` is a valid out-buffer for `fstatat`.
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fstatat` on the owned descriptor with a NUL-terminated name
    // and a valid out-buffer.
    let found = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            text.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if found == 0 {
        return Ok(true);
    }
    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
        return Ok(false);
    }
    Err(last_error(&format!(
        "the folding probe `{name}` cannot be read"
    )))
}

/// The folding probes, in a fresh private directory beneath the workspace:
/// a lower-case file whose upper-case twin then exists folds case; an NFD
/// name after which the NFC one cannot be created exclusively folds
/// normalization. The directory and everything in it are removed whatever
/// the result.
fn fold_probes(workspace: &Path) -> Result<ShareFacts, String> {
    let root = open_directory(workspace)?;
    let (name, directory) = probe_directory(&root)?;
    let result = (|| -> Result<ShareFacts, String> {
        if !create_exclusive(&directory, PROBE_LOW)? {
            return Err("the fresh folding probe directory was not empty".to_owned());
        }
        let case_fold = exists_at(&directory, PROBE_UPPER)?;
        if !create_exclusive(&directory, PROBE_NFD)? {
            return Err("the fresh folding probe directory was not empty".to_owned());
        }
        let normalization_fold = !create_exclusive(&directory, PROBE_NFC)?;
        Ok(ShareFacts {
            case_fold,
            normalization_fold,
        })
    })();
    for probe in [PROBE_LOW, PROBE_UPPER, PROBE_NFD, PROBE_NFC] {
        if let Ok(text) = c_name(probe) {
            // SAFETY: `unlinkat` on the owned probe directory with a
            // NUL-terminated name; a missing name is fine.
            unsafe { libc::unlinkat(directory.as_raw_fd(), text.as_ptr(), 0) };
        }
    }
    drop(directory);
    let text = c_name(&name)?;
    // SAFETY: `unlinkat` on the owned workspace descriptor; removes only the
    // probe directory, and only once empty.
    if unsafe { libc::unlinkat(root.as_raw_fd(), text.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = last_error(&format!(
            "the folding probe directory `{name}` is left behind"
        ));
        return result.and(Err(error));
    }
    result
}

/// One preflight of a live workspace: the scan above, then the folding
/// probes. [`Err`] names the remedy; [`Ok`] carries the facts.
pub fn preflight(workspace: &Path) -> Result<ShareFacts, String> {
    let workspace = workspace
        .canonicalize()
        .map_err(|error| format!("{} cannot be resolved: {error}", workspace.display()))?;
    let metadata = std::fs::symlink_metadata(&workspace)
        .map_err(|error| format!("{} cannot be read: {error}", workspace.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", workspace.display()));
    }
    scan(&workspace, metadata.dev())?;
    let facts = fold_probes(&workspace)?;
    if facts.case_fold {
        return Err(
            "the workspace volume folds case in file names, which bypasses every guest-side \
             policy denial (measured: a guest write to .GIT/config lands in .git/config); move \
             the workspace to a case-sensitive volume or use the staged (non-live) mode"
                .to_owned(),
        );
    }
    Ok(facts)
}

/// The probe directories a preflight may leave behind if it was
/// interrupted; used by tests to prove cleanliness.
#[cfg(test)]
pub(crate) fn probe_leftovers(workspace: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(workspace)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .is_some_and(|name| name.as_bytes().starts_with(PROBE_PREFIX.as_bytes()))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A case-sensitive APFS volume, attached for one test beneath a private
    /// temporary directory (never a fixed `/Volumes` name) and detached when
    /// dropped. `None` where `hdiutil` cannot make one.
    #[cfg(target_os = "macos")]
    struct CaseSensitiveVolume {
        mount: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    #[cfg(target_os = "macos")]
    impl CaseSensitiveVolume {
        fn attach() -> Option<Self> {
            let dir = tempfile::tempdir().ok()?;
            let image = dir.path().join("share.sparseimage");
            let mount = dir.path().join("mount");
            std::fs::create_dir(&mount).ok()?;
            let created = std::process::Command::new("/usr/bin/hdiutil")
                .args(["create", "-quiet", "-size", "16m", "-type", "SPARSE", "-fs"])
                .arg("Case-sensitive APFS")
                .args(["-volname", "ukai-share-test"])
                .arg(&image)
                .status()
                .ok()?;
            if !created.success() {
                return None;
            }
            let attached = std::process::Command::new("/usr/bin/hdiutil")
                .args([
                    "attach",
                    "-quiet",
                    "-nobrowse",
                    "-noautoopen",
                    "-mountpoint",
                ])
                .arg(&mount)
                .arg(&image)
                .status()
                .ok()?;
            attached
                .success()
                .then_some(CaseSensitiveVolume { mount, _dir: dir })
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for CaseSensitiveVolume {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/hdiutil")
                .args(["detach", "-quiet", "-force"])
                .arg(&self.mount)
                .status();
        }
    }

    /// A workspace the folding probes accept: a directory on a fresh
    /// case-sensitive volume, or on the temporary volume when that already
    /// is one. `None` when neither is available, which the caller reports.
    fn case_sensitive_workspace() -> Option<(std::path::PathBuf, Box<dyn std::any::Any>)> {
        let temp = tempfile::tempdir().ok()?;
        if fold_probes(temp.path()).is_ok_and(|facts| !facts.case_fold) {
            let path = temp.path().join("work");
            std::fs::create_dir(&path).ok()?;
            return Some((path, Box::new(temp)));
        }
        #[cfg(target_os = "macos")]
        if let Some(volume) = CaseSensitiveVolume::attach() {
            let path = volume.mount.join("work");
            std::fs::create_dir(&path).ok()?;
            return Some((path, Box::new(volume)));
        }
        None
    }

    #[test]
    fn a_symlink_is_refused_with_its_path() {
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/hosts", root.path().join("link")).unwrap();
        let error = preflight(root.path()).unwrap_err();
        assert!(error.contains("symlinks"), "{error}");
        assert!(error.contains("link"), "{error}");
    }

    #[test]
    fn a_multi_link_file_is_refused_and_directories_are_not() {
        let root = tempfile::tempdir().unwrap();
        let inside = root.path().join("shared.txt");
        std::fs::write(&inside, "x").unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::fs::hard_link(&inside, root.path().join("second.txt")).unwrap();
        let error = preflight(root.path()).unwrap_err();
        assert!(error.contains("hard link"), "{error}");
        assert!(
            error.contains("shared.txt") || error.contains("second.txt"),
            "{error}"
        );
    }

    #[test]
    fn fifos_and_sockets_are_refused_before_any_probe() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("pipe");
        let text = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `mkfifo` with a NUL-terminated path in a private directory.
        assert_eq!(unsafe { libc::mkfifo(text.as_ptr(), 0o600) }, 0);
        let error = preflight(root.path()).unwrap_err();
        assert!(error.contains("FIFO, socket or device"), "{error}");
        assert!(probe_leftovers(root.path()).is_empty());
        std::fs::remove_file(&fifo).unwrap();
        let socket = std::os::unix::net::UnixListener::bind(root.path().join("sock")).unwrap();
        let error = preflight(root.path()).unwrap_err();
        assert!(error.contains("FIFO, socket or device"), "{error}");
        drop(socket);
    }

    /// A nested mount is refused by device, whatever its contents; the
    /// workspace root's own device is the reference.
    #[test]
    fn an_entry_on_another_device_is_a_nested_mount() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::fs::write(root.path().join("sub/file"), "x").unwrap();
        let device = std::fs::metadata(root.path()).unwrap().dev();
        scan(root.path(), device).expect("one device");
        let error = scan(root.path(), device.wrapping_add(1)).unwrap_err();
        assert!(error.contains("another mount"), "{error}");
        #[cfg(target_os = "macos")]
        {
            // A real one: a volume attached inside the workspace.
            let Some(volume) = CaseSensitiveVolume::attach() else {
                eprintln!("no hdiutil volume: the real nested mount is not exercised");
                return;
            };
            let parent = volume.mount.parent().unwrap();
            let error = preflight(parent).unwrap_err();
            assert!(error.contains("another mount"), "{error}");
        }
    }

    #[test]
    fn the_default_volume_folds_case_and_is_refused_with_the_remedy() {
        // The Mac's default volume folds case; a clean workspace there must
        // refuse. A host with a case-sensitive default volume passes.
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.txt"), "x").unwrap();
        match preflight(root.path()) {
            Err(error) => {
                assert!(error.contains("folds case"), "{error}");
                assert!(error.contains("case-sensitive"), "{error}");
            }
            Ok(facts) => assert!(!facts.case_fold),
        }
        assert!(probe_leftovers(root.path()).is_empty());
    }

    /// The pass path, on a case-sensitive volume: no case fold, the
    /// probes leave nothing behind, and the workspace's own entries are
    /// untouched (the probes never write next to them).
    #[test]
    fn a_case_sensitive_workspace_passes_and_the_probes_clean_up() {
        let Some((work, _guard)) = case_sensitive_workspace() else {
            panic!("no case-sensitive volume could be made for the pass path");
        };
        std::fs::write(work.join("CASE"), "operator").unwrap();
        std::fs::write(work.join("case"), "operator").unwrap();
        let facts = preflight(&work).expect("a case-sensitive workspace passes");
        assert!(!facts.case_fold);
        // Measured 2026-11-02: case-sensitive APFS still folds Unicode
        // normalization; the exclusive NFC create is what detects it.
        #[cfg(target_os = "macos")]
        assert!(facts.normalization_fold);
        assert!(probe_leftovers(&work).is_empty());
        assert_eq!(std::fs::read(work.join("CASE")).unwrap(), b"operator");
        assert_eq!(std::fs::read(work.join("case")).unwrap(), b"operator");
    }

    /// The probe directory is fresh: a planted entry with the prefix is
    /// neither reused nor followed, and a planted link in the workspace is
    /// refused by the scan before any probe runs.
    #[test]
    fn planted_probe_names_are_never_reused_or_followed() {
        let Some((work, _guard)) = case_sensitive_workspace() else {
            panic!("no case-sensitive volume could be made for the probe path");
        };
        let outside = tempfile::tempdir().unwrap();
        let planted = work.join(format!("{PROBE_PREFIX}planted"));
        std::fs::create_dir(&planted).unwrap();
        std::fs::write(planted.join(PROBE_LOW), "planted").unwrap();
        // The scan accepts a planted directory of regular files; the probes
        // then run in a fresh one beside it.
        let facts = preflight(&work).expect("the planted directory is not the probe's");
        assert!(!facts.case_fold);
        assert_eq!(std::fs::read(planted.join(PROBE_LOW)).unwrap(), b"planted");
        assert_eq!(probe_leftovers(&work), vec![planted]);
        std::os::unix::fs::symlink(outside.path(), work.join(format!("{PROBE_PREFIX}link")))
            .unwrap();
        let error = preflight(&work).unwrap_err();
        assert!(error.contains("symlinks"), "{error}");
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn create_exclusive_reports_an_existing_name_and_never_follows_a_link() {
        let root = tempfile::tempdir().unwrap();
        let directory = open_directory(root.path()).unwrap();
        assert!(create_exclusive(&directory, "fresh").unwrap());
        assert!(!create_exclusive(&directory, "fresh").unwrap());
        let target = root.path().join("target");
        std::os::unix::fs::symlink(&target, root.path().join("link")).unwrap();
        assert!(!create_exclusive(&directory, "link").unwrap());
        assert!(!target.exists(), "an exclusive create never follows a link");
        assert!(exists_at(&directory, "link").unwrap());
        assert!(!exists_at(&directory, "absent").unwrap());
    }
}
