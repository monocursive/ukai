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
    let mut found = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // Unreadable directories contribute nothing; the caller decides
            // whether a partially-scanned granted root is acceptable (§4.7
            // records the scanned set, so a hole is visible in the receipt).
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(error) if dir == root => return Err(error),
            Err(_) => continue,
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let mode = metadata.permissions().mode();
            let setuid = mode & 0o4000 != 0;
            let setgid = mode & 0o2000 != 0;
            if setuid || setgid {
                found.insert(
                    path.clone(),
                    SetuidEntry {
                        path,
                        setuid,
                        setgid,
                    },
                );
            }
        }
    }
    Ok(found.into_values().collect())
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
        for root in SYSTEM_ROOTS {
            match scan_root(Path::new(root)) {
                Ok(entries) => {
                    for entry in entries {
                        found.insert(entry.path.clone(), entry);
                    }
                }
                Err(_) => continue,
            }
        }
        SystemSetuid {
            build: os_build_version().unwrap_or_default(),
            entries: found.into_values().collect(),
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
    let mut found = BTreeMap::new();
    for entry in system_entries().entries.clone() {
        found.insert(entry.path.clone(), entry);
    }
    for root in granted_roots {
        for entry in scan_root(root)? {
            found.insert(entry.path.clone(), entry);
        }
    }
    Ok(found.into_values().collect())
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
}
