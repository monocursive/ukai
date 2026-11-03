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

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

/// What the preflight proved about the workspace, recorded in the attempt
/// and transport records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareFacts {
    pub case_fold: bool,
    pub normalization_fold: bool,
}

/// Marker names for the in-place folding probes; dot-prefixed and removed
/// afterwards. The NFD/NFC pair is `cafe` + combining acute versus the
/// precomposed `café`.
fn probe_names() -> (String, String, String, String) {
    let marker = format!(".ukai-fold-probe-{:x}", std::process::id());
    let nfd: String = format!("{}-nfd-cafe\u{301}", marker);
    let nfc: String = format!("{}-nfd-cafe\u{e9}", marker);
    (
        format!("{marker}-case"),
        format!("{}-CASE", marker.to_uppercase()),
        nfd,
        nfc,
    )
}

/// Walk the workspace refusing symlinks and regular files with more than
/// one hard link. Directories' own link counts (their `.` and `..` entries)
/// are not escapes.
fn scan(workspace: &Path) -> Result<(), String> {
    let mut pending = vec![workspace.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("{} cannot be read: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let file_type = entry.file_type().map_err(|error| error.to_string())?;
            if file_type.is_symlink() {
                return Err(format!(
                    "live workspace may not contain symlinks (measured: they stay guest-side, \
                     but the preview refuses them uniformly): {}",
                    entry.path().display()
                ));
            }
            if file_type.is_dir() {
                pending.push(entry.path());
                continue;
            }
            let metadata =
                std::fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
            if metadata.is_file() && metadata.nlink() > 1 {
                return Err(format!(
                    "live workspace contains files with more than one hard link (measured \
                     write-through escape to the link target): {} ({} links)",
                    entry.path().display(),
                    metadata.nlink()
                ));
            }
        }
    }
    Ok(())
}

/// One preflight of a live workspace: the scan above, then the folding
/// probes in place. [`Err`] names the remedy; [`Ok`] carries the facts.
pub fn preflight(workspace: &Path) -> Result<ShareFacts, String> {
    let workspace = workspace
        .canonicalize()
        .map_err(|error| format!("{} cannot be resolved: {error}", workspace.display()))?;
    if !workspace.is_dir() {
        return Err(format!("{} is not a directory", workspace.display()));
    }
    scan(&workspace)?;
    let (low, upper, nfd_name, nfc_name) = probe_names();
    let low = workspace.join(low);
    let upper = workspace.join(upper);
    let nfd = workspace.join(nfd_name);
    let nfc = workspace.join(nfc_name);
    let mut facts = ShareFacts {
        case_fold: false,
        normalization_fold: false,
    };
    let result = (|| -> Result<(), String> {
        std::fs::write(&low, "low").map_err(|e| e.to_string())?;
        if upper.try_exists().map_err(|e| e.to_string())? {
            facts.case_fold = true;
        }
        std::fs::write(&nfd, "nfd").map_err(|e| e.to_string())?;
        std::fs::write(&nfc, "nfc").map_err(|e| e.to_string())?;
        if std::fs::read(&nfd).map_err(|e| e.to_string())? == b"nfc" {
            facts.normalization_fold = true;
        }
        Ok(())
    })();
    for probe in [&low, &upper, &nfd, &nfc] {
        let _ = std::fs::remove_file(probe);
    }
    result?;
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

/// The paths a folding probe may leave behind if it was interrupted; used
/// by tests to prove cleanliness.
#[cfg(test)]
pub(crate) fn probe_leftovers(workspace: &Path) -> Vec<std::path::PathBuf> {
    let (low, upper, nfd, nfc) = probe_names();
    [low, upper, nfd, nfc]
        .into_iter()
        .map(|name| workspace.join(name))
        .filter(|path| path.exists())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_default_volume_folds_case_and_is_refused_with_the_remedy() {
        // The Mac's default volume folds case; a clean workspace there must
        // refuse. The case-sensitive pass path is exercised by the Python
        // suite, which can build a case-sensitive volume.
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.txt"), "x").unwrap();
        match preflight(root.path()) {
            Err(error) => {
                assert!(error.contains("folds case"), "{error}");
                assert!(error.contains("case-sensitive"), "{error}");
            }
            Ok(facts) => {
                // A host with a case-sensitive default volume: the probes
                // must still clean up after themselves.
                assert!(!facts.case_fold);
                assert!(probe_leftovers(root.path()).is_empty());
            }
        }
    }
}
