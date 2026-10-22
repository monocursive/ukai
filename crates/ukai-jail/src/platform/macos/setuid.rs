//! Enumeration of setuid/setgid executables (§4.7 class 3).
//!
//! macOS has no `no_new_privs`, so the profile denies executing every
//! setuid and setgid file in the readable roots, by path. The system volume
//! is sealed, so its set is fixed per build: it is enumerated once per
//! process (keyed by `kern.osversion` and cached), while granted roots are
//! scanned at preparation. The kernel additionally refuses exec of setuid
//! binaries for any sandboxed process (measured — see the sandbox module
//! docs), which backstops paths the enumeration could miss, e.g. hardlinks.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use libc::{c_void, size_t, sysctlbyname};

/// A file carrying the set-UID or set-GID execution bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetuidEntry {
    /// The absolute path as found; never through a symlink (symlinks are
    /// not followed, so a link to a setuid file is not itself enumerated —
    /// the kernel-side backstop covers exec through it).
    pub path: PathBuf,
    /// The set-UID bit is set.
    pub setuid: bool,
    /// The set-GID bit is set.
    pub setgid: bool,
}

/// The system roots whose contents the sealed volume fixes per build.
pub const SYSTEM_ROOTS: [&str; 5] = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"];

/// The macOS build string (`kern.osversion`, e.g. `26A434`), which keys the
/// sealed-volume cache.
#[must_use]
pub fn os_build_version() -> Option<String> {
    let name = CString::new("kern.osversion").ok()?;
    let mut value = [0u8; 32];
    let mut size: size_t = value.len() as size_t;
    // SAFETY: `name` is a NUL-terminated string and `value`/`size` are live
    // locals sysctlbyname writes within; the newp argument is null (read-only
    // query).
    let status = unsafe {
        sysctlbyname(
            name.as_ptr(),
            value.as_mut_ptr() as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return None;
    }
    let end = (size as usize).min(value.len());
    Some(String::from_utf8_lossy(&value[..end.saturating_sub(1)]).into_owned())
}

/// Scans one root for setuid/setgid files, without following symlinks.
///
/// Directories that cannot be read are skipped: a granted root that is not
/// readable contributes no entries here, and the receipt records what the
/// scan saw (the caller passes the entries to
/// [`crate::platform::macos::sandbox::ProfileParams::setuid_exec_denied`]).
pub fn scan_root(root: &Path) -> io::Result<Vec<SetuidEntry>> {
    Ok(scan_root_report(root).entries)
}

/// Enumeration evidence. Holes are recorded, never described as a complete scan.
#[derive(Clone, Debug, Default)]
pub struct ScanReport {
    pub entries: Vec<SetuidEntry>,
    pub holes: Vec<PathBuf>,
}

fn scan_root_report(root: &Path) -> ScanReport {
    let mut report = ScanReport::default();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                report.holes.push(path);
                continue;
            }
        };
        if metadata.is_dir() {
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    for entry in entries {
                        match entry {
                            Ok(entry) => pending.push(entry.path()),
                            Err(_) => report.holes.push(path.clone()),
                        }
                    }
                }
                Err(_) => report.holes.push(path),
            }
        } else if metadata.is_file() {
            let mode = metadata.permissions().mode();
            if mode & 0o6000 != 0 {
                report.entries.push(SetuidEntry {
                    path,
                    setuid: mode & 0o4000 != 0,
                    setgid: mode & 0o2000 != 0,
                });
            }
        }
        // Symlinks are deliberately not followed; the kernel's setuid-exec
        // denial remains the backstop for aliases and post-scan changes.
    }
    report.entries.sort_by(|a, b| a.path.cmp(&b.path));
    report.holes.sort();
    report.holes.dedup();
    report
}

/// The sealed-volume set for this build, enumerated once per process and
/// cached (§4.7 class 3: fixed for each `kern.osversion`).
///
/// Roots that cannot be scanned are tolerated: the sealed roots of a normal
/// Mac are world-readable, and a partial set is recorded by the caller, not
/// silently treated as complete.
pub fn system_entries() -> &'static SystemSetuid {
    static SYSTEM: LazyLock<SystemSetuid> = LazyLock::new(|| {
        let mut found = BTreeMap::new();
        let mut roots: Vec<PathBuf> = SYSTEM_ROOTS.into_iter().map(PathBuf::from).collect();
        roots.extend(super::sandbox::runtime_roots());
        roots.sort();
        roots.dedup();
        let mut holes = Vec::new();
        for root in &roots {
            let scan = scan_root_report(root);
            for entry in scan.entries {
                found.insert(entry.path.clone(), entry);
            }
            holes.extend(scan.holes);
        }
        SystemSetuid {
            build: os_build_version().unwrap_or_default(),
            entries: found.into_values().collect(),
            roots,
            holes,
        }
    });
    &SYSTEM
}

/// The sealed-volume enumeration: the build it was taken on, and the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemSetuid {
    /// `kern.osversion` at enumeration time.
    pub build: String,
    /// Every setuid/setgid file under [`SYSTEM_ROOTS`], ordered by path.
    pub entries: Vec<SetuidEntry>,
    /// Roots actually scanned, including runtime libraries.
    pub roots: Vec<PathBuf>,
    /// Paths whose metadata or directory entries could not be read.
    pub holes: Vec<PathBuf>,
}

/// The absolute paths of `entries`, in order — the profile parameter and the
/// receipt's setuid list are the same sequence (§4.7: the receipt records
/// "paths and the setuid list").
pub fn deny_paths(entries: &[SetuidEntry]) -> Vec<PathBuf> {
    entries.iter().map(|entry| entry.path.clone()).collect()
}

/// Convenience used at preparation: one call enumerating the sealed roots
/// plus every granted root, ordered by path.
pub fn scan_readable_roots(granted_roots: &[PathBuf]) -> io::Result<Vec<SetuidEntry>> {
    Ok(scan_readable_roots_report(granted_roots).entries)
}

/// Preparation's evidence, including explicit holes and file grants.
pub fn scan_readable_roots_report(granted_roots: &[PathBuf]) -> ScanReport {
    let system = system_entries();
    let mut found: BTreeMap<_, _> = system
        .entries
        .iter()
        .cloned()
        .map(|e| (e.path.clone(), e))
        .collect();
    let mut holes = system.holes.clone();
    for root in granted_roots {
        if system.roots.iter().any(|system| root.starts_with(system)) {
            continue;
        }
        let scan = scan_root_report(root);
        for entry in scan.entries {
            found.insert(entry.path.clone(), entry);
        }
        holes.extend(scan.holes);
    }
    holes.sort();
    holes.dedup();
    ScanReport {
        entries: found.into_values().collect(),
        holes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_enumeration_finds_the_known_set_of_this_build() {
        let system = system_entries();
        assert!(!system.build.is_empty(), "kern.osversion readable");
        let paths: Vec<_> = system.entries.iter().map(|e| e.path.clone()).collect();
        for expected in ["/usr/bin/sudo", "/usr/bin/su", "/usr/bin/login"] {
            assert!(
                paths.iter().any(|path| path == &PathBuf::from(expected)),
                "{expected} is setuid on this build but missing from the enumeration"
            );
        }
        let sudo = system
            .entries
            .iter()
            .find(|entry| entry.path == Path::new("/usr/bin/sudo"))
            .expect("sudo enumerated");
        assert!(sudo.setuid && !sudo.setgid);
        // Ordered by path: the receipt's list is stable.
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }

    #[test]
    fn scan_root_reports_setuid_and_setgid_distinctly() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let su = dir.path().join("su-bit");
        let sg = dir.path().join("sg-bit");
        std::fs::write(&su, b"").unwrap();
        std::fs::write(&sg, b"").unwrap();
        std::fs::set_permissions(&su, std::fs::Permissions::from_mode(0o4755)).unwrap();
        std::fs::set_permissions(&sg, std::fs::Permissions::from_mode(0o2755)).unwrap();
        let found = scan_root(dir.path()).unwrap();
        assert_eq!(found.len(), 2, "exactly the two marked files: {found:?}");
        let su_entry = found.iter().find(|e| e.path == su).unwrap();
        let sg_entry = found.iter().find(|e| e.path == sg).unwrap();
        assert!(su_entry.setuid && !su_entry.setgid);
        assert!(sg_entry.setgid && !sg_entry.setuid);
        assert!(deny_paths(&found).contains(&su));
    }
    #[test]
    fn individual_file_grants_are_scanned_and_missing_roots_are_holes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("setgid");
        std::fs::write(&file, b"fixture").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o2755)).unwrap();
        let scan = scan_root_report(&file);
        assert_eq!(scan.entries.len(), 1);
        assert!(scan.entries[0].setgid);
        assert!(scan.holes.is_empty());
        let missing = dir.path().join("missing");
        let scan = scan_root_report(&missing);
        assert_eq!(scan.holes, vec![missing]);
        assert!(scan.entries.is_empty());
    }
}
