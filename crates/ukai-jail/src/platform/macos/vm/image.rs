//! The prepared image, its verification, and what crosses with it (J18).
//!
//! Three ports of the preview's rules, so the warm host program and the
//! `--vm` execution path enforce exactly what `run.py` did:
//!
//! * [`Install::discover`] locates the installed preview artifacts the way
//!   `install.sh.in` lays them down (`<prefix>/share/ukai-vm/<version>/`),
//!   or `UKAI_VM_HOME` names them directly.
//! * [`verify_image`] is `run.py`'s `load_image`: the image is private
//!   trusted state, and a byte that does not match its recorded hash
//!   refuses the boot before anything starts.
//! * [`verify_guest_receipt`] is `run.py`'s `verify_receipt`: a transport
//!   success is never relabelled as verified jail enforcement.
//!
//! [`snapshot_workspace`] is the staging half of `run.py`'s `snapshot`, on
//! the same limits, the same exclusions and the same refusal of links.
//!
//! The module is standalone (standard library, `sha2`, `serde_json`): the
//! `ukai-vm` binary and the stand-in tests include it by path.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// The names `run.py` excludes at every level.
pub const EXCLUDED: [&str; 6] = [
    ".git",
    "target",
    "node_modules",
    ".venv",
    "__pycache__",
    ".DS_Store",
];

/// Why the image, the receipt or the workspace refused.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

fn refusal(what: impl Into<String>) -> Refusal {
    Refusal(what.into())
}

/// The SHA-256 of a file, streamed.
///
/// # Errors
/// [`Refusal`] when the file cannot be read.
pub fn digest(path: &Path) -> Result<String, Refusal> {
    let mut file = File::open(path)
        .map_err(|error| refusal(format!("{} is unreadable: {error}", path.display())))?;
    let mut context = sha2::Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| refusal(format!("{} is unreadable: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    Ok(hex(&context.finalize()))
}

/// Lowercase hex, the one spelling every digest uses.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `image.json`, the fields the warm design reads.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ImageManifest {
    /// Always `prepared`; anything else is not a bootable image.
    pub status: String,
    /// The disk, helper, custodian and seed digests.
    pub disk_sha256: String,
    /// The VZ client's digest.
    pub helper_sha256: String,
    /// The custodian's digest.
    pub custodian_sha256: String,
    /// The seed ISO's digest.
    pub seed_sha256: String,
}

/// One installed preview: the directory `install.sh.in` laid down, with the
/// image and the two binaries the warm design reuses (it never rebuilds
/// them).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Install {
    /// The version directory: `.../share/ukai-vm/<version>`.
    pub root: PathBuf,
    /// The manifest, as read and verified by [`Install::verify`].
    pub manifest: ImageManifest,
}

impl Install {
    /// Locates the installed preview: `UKAI_VM_HOME` when it names the
    /// version directory, otherwise the newest `~/.local/share/ukai-vm/<version>`
    /// whose `image/image.json` exists, the same layout `install.sh.in`
    /// writes.
    ///
    /// # Errors
    /// [`Refusal`] when no installation is found.
    pub fn discover() -> Result<Self, Refusal> {
        if let Some(home) = std::env::var_os("UKAI_VM_HOME") {
            let root = PathBuf::from(home);
            return Self::from_root(root);
        }
        let mut home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| refusal("no UKAI_VM_HOME and no HOME: where is ukai-vm installed?"))?;
        home.push(".local/share/ukai-vm");
        let mut candidates: Vec<PathBuf> = std::fs::read_dir(&home)
            .map_err(|error| refusal(format!("{} is unreadable: {error}", home.display())))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.join("image/image.json").is_file())
            .collect();
        candidates.sort_by_key(|path| version_key(path));
        let root = candidates.pop().ok_or_else(|| {
            refusal(format!(
                "no ukai-vm installation beneath {}",
                home.display()
            ))
        })?;
        Self::from_root(root)
    }

    /// An installation at `root`, with `image/image.json` read but not yet
    /// verified.
    ///
    /// # Errors
    /// [`Refusal`] when the manifest is missing or malformed.
    pub fn from_root(root: PathBuf) -> Result<Self, Refusal> {
        let manifest_path = root.join("image").join("image.json");
        let bytes = std::fs::read(&manifest_path).map_err(|error| {
            refusal(format!(
                "{} is unreadable: {error}",
                manifest_path.display()
            ))
        })?;
        let manifest: ImageManifest = serde_json::from_slice(&bytes).map_err(|error| {
            refusal(format!(
                "{} does not name a prepared image: {error}",
                manifest_path.display()
            ))
        })?;
        Ok(Install { root, manifest })
    }

    /// Verifies every artifact against the manifest, `run.py`'s
    /// `load_image`. The digests are then the facts `ready` frames carry.
    ///
    /// # Errors
    /// [`Refusal`] when any artifact is missing or its hash differs.
    pub fn verify(&self) -> Result<(), Refusal> {
        if self.manifest.status != "prepared" {
            return Err(refusal(
                "image/helper does not match prepared metadata: the manifest is not `prepared`",
            ));
        }
        let image = self.root.join("image");
        for (name, recorded) in [
            ("base.raw", &self.manifest.disk_sha256),
            ("vz", &self.manifest.helper_sha256),
            ("custodian", &self.manifest.custodian_sha256),
            ("seed.iso", &self.manifest.seed_sha256),
        ] {
            let actual = digest(&image.join(name))?;
            if &actual != recorded {
                return Err(refusal(format!(
                    "image/helper does not match prepared metadata: {name} hashes to {actual}"
                )));
            }
        }
        Ok(())
    }

    /// Copy to a private boot directory and verify those exact copies before use.
    /// This closes the hash-source-then-clone race for the disk and executables.
    ///
    /// # Errors
    /// Refuses changed artifacts, links, nonregular inputs, or a failed copy.
    pub fn verified_copy(&self, root: &Path) -> Result<Self, Refusal> {
        let image = root.join("image");
        std::fs::create_dir(&image).map_err(|e| refusal(e.to_string()))?;
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| refusal(e.to_string()))?;
        for name in ["base.raw", "vz", "custodian", "seed.iso"] {
            let source = self.root.join("image").join(name);
            let destination = image.join(name);
            let metadata =
                std::fs::symlink_metadata(&source).map_err(|e| refusal(e.to_string()))?;
            if !metadata.is_file() {
                return Err(refusal("image artifact is not a regular file"));
            }
            // APFS clone remains cheap for the disk. Verification is AFTER cp;
            // a source substitution cannot select unchecked executable bytes.
            let status = std::process::Command::new("/bin/cp")
                .args(["-c", "--"])
                .arg(&source)
                .arg(&destination)
                .status()
                .map_err(|e| refusal(e.to_string()))?;
            if !status.success() {
                return Err(refusal("image copy failed"));
            }
            let copied =
                std::fs::symlink_metadata(&destination).map_err(|e| refusal(e.to_string()))?;
            if !copied.is_file() {
                return Err(refusal("copied artifact is not a regular file"));
            }
            std::fs::set_permissions(
                &destination,
                std::fs::Permissions::from_mode(if name == "vz" || name == "custodian" {
                    0o700
                } else {
                    0o600
                }),
            )
            .map_err(|e| refusal(e.to_string()))?;
        }
        let copy = Self {
            root: root.to_path_buf(),
            manifest: self.manifest.clone(),
        };
        copy.verify()?;
        Ok(copy)
    }

    /// The custodian binary the preview installed, reused unmodified.
    #[must_use]
    pub fn custodian(&self) -> PathBuf {
        self.root.join("image").join("custodian")
    }

    /// The VZ client the preview installed, reused unmodified.
    #[must_use]
    pub fn helper(&self) -> PathBuf {
        self.root.join("image").join("vz")
    }

    /// The seed ISO.
    #[must_use]
    pub fn seed(&self) -> PathBuf {
        self.root.join("image").join("seed.iso")
    }

    /// The prepared base disk; a warm boot clones it, never boots it.
    #[must_use]
    pub fn base_disk(&self) -> PathBuf {
        self.root.join("image").join("base.raw")
    }
}

fn version_key(path: &Path) -> (Vec<u64>, bool, String) {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let (core, suffix) = name.split_once('-').unwrap_or((&name, ""));
    (
        core.split('.').map(|n| n.parse().unwrap_or(0)).collect(),
        suffix.is_empty(),
        suffix.to_owned(),
    )
}

/// Validate both the receipt and the controller's statement binding it to this run.
/// It establishes consistency of guest reports, not independent kernel attestation.
///
/// # Errors
/// Refuses a replay, wrong boundary, wrong argv, boot, profile, or unapplied limit.
pub fn verify_bound_guest_receipt(
    receipt: &serde_json::Value,
    binding: &super::protocol::ReceiptBinding,
    attempt_id: &str,
    boot_id: &str,
    profile: &str,
    argv_digest: &str,
) -> Result<(), Refusal> {
    verify_guest_receipt(receipt, profile)?;
    if binding.attempt_id != attempt_id
        || binding.boot_id != boot_id
        || binding.profile != profile
        || binding.argv_digest != argv_digest
        || binding.guest_attempt_id.is_empty()
        || binding.guest_boot_id.is_empty()
        || receipt
            .pointer("/attempt_id")
            .and_then(serde_json::Value::as_str)
            != Some(binding.guest_attempt_id.as_str())
        || receipt
            .pointer("/argv_digest")
            .and_then(serde_json::Value::as_str)
            != Some(argv_digest)
        || receipt
            .pointer("/process/identity/value/boot_id")
            .and_then(serde_json::Value::as_str)
            != Some(binding.guest_boot_id.as_str())
    {
        return Err(refusal(
            "guest receipt does not bind to this attempt, argv, profile and boot",
        ));
    }
    Ok(())
}

/// Verifies the guest's Linux receipt on the host, `run.py`'s
/// `verify_receipt`: the attempt completes only with containment, cleanup
/// and every required limit verified.
///
/// # Errors
/// [`Refusal`] naming the first fact the receipt fails to prove.
pub fn verify_guest_receipt(receipt: &serde_json::Value, profile: &str) -> Result<(), Refusal> {
    let string = |pointer: &str| {
        receipt
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| refusal(format!("missing Linux jail receipt: {pointer}")))
    };
    if string("/schema")? != "ukai.jail.receipt/1" || string("/platform/os")? != "linux" {
        return Err(refusal("missing Linux jail receipt"));
    }
    if string("/policy/name")? != profile {
        return Err(refusal("guest receipt profile mismatch"));
    }
    if string("/containment")? != "enforced"
        || string("/child_protection")? != "enforced"
        || receipt.pointer("/exec_observed") != Some(&serde_json::Value::Bool(true))
    {
        return Err(refusal("guest did not confirm contained execution"));
    }
    if string("/lifetime/boundary")? != "pid_namespace" {
        return Err(refusal("guest receipt did not establish a pid namespace"));
    }
    if receipt.pointer("/lifetime/tree_empty") != Some(&serde_json::Value::Bool(true))
        || string("/lifetime/integrity")? != "verified"
    {
        return Err(refusal("guest process-tree cleanup was not verified"));
    }
    if string("/state_cleanup")? != "complete" {
        return Err(refusal("guest evidence or cleanup failed"));
    }
    let errors_empty = matches!(
        receipt.pointer("/errors"),
        Some(serde_json::Value::Array(errors)) if errors.is_empty()
    );
    if !errors_empty {
        return Err(refusal("guest evidence or cleanup failed"));
    }
    if string("/applied/network/mode")? != "none" {
        return Err(refusal("guest receipt did not enforce offline execution"));
    }
    let limits = receipt
        .pointer("/applied/limits")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| refusal("malformed guest receipt limits"))?;
    let mut applied: Vec<(&str, bool)> = Vec::with_capacity(limits.len());
    for limit in limits {
        let key = limit
            .pointer("/key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| refusal("malformed guest receipt limits"))?;
        let applied_flag = limit
            .pointer("/applied")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        applied.push((key, applied_flag));
    }
    for key in ["wall", "pids", "mem", "swap"] {
        if !applied
            .iter()
            .any(|(name, applied)| *name == key && *applied)
        {
            return Err(refusal("guest did not apply every required limit"));
        }
    }
    Ok(())
}

/// One staged workspace file, the host's half of a `put` frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WorkspaceEntry {
    /// The path beneath the workspace, `/`-separated.
    pub path: String,
    /// Whether the file is executable.
    pub executable: bool,
    /// The bytes.
    pub data: Vec<u8>,
}

/// Reads the workspace's regular files, `run.py`'s `snapshot`: sorted,
/// links refused, excluded names skipped, the preview's limits enforced.
///
/// # Errors
/// [`Refusal`] on a link, a special file, an oversized file or an over-budget
/// workspace.
pub fn snapshot_workspace(root: &Path) -> Result<Vec<WorkspaceEntry>, Refusal> {
    let mut entries = Vec::new();
    let mut total = 0_usize;
    walk(root, root, &mut entries, &mut total)?;
    Ok(entries)
}

fn walk(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<WorkspaceEntry>,
    total: &mut usize,
) -> Result<(), Refusal> {
    let mut children: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|error| refusal(format!("{} is unreadable: {error}", directory.display())))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    children.sort();
    for path in children {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if EXCLUDED.contains(&name.as_str()) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| refusal(format!("{} is unreadable: {error}", path.display())))?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink() {
            return Err(refusal(format!(
                "workspace symlinks are not supported: {name}"
            )));
        }
        if metadata.is_dir() {
            walk(root, &path, entries, total)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(refusal(format!("only regular files are supported: {name}")));
        }
        if path.to_str().is_none() {
            return Err(refusal(format!(
                "only UTF-8 file names cross to the guest: {name}"
            )));
        }
        if metadata.len() > super::protocol::MAX_FILE as u64 {
            return Err(refusal(format!(
                "only regular files up to 512 KiB are supported: {name}"
            )));
        }
        // Re-opened through the no-follow flag, so a name swapped for a
        // link between the listing and this open is refused, not followed.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|error| refusal(format!("{} is unreadable: {error}", path.display())))?;
        let opened = file
            .metadata()
            .map_err(|error| refusal(format!("{} is unreadable: {error}", path.display())))?;
        if !opened.is_file() {
            return Err(refusal(format!("only regular files are supported: {name}")));
        }
        let mut data = Vec::with_capacity(opened.len() as usize);
        file.read_to_end(&mut data)
            .map_err(|error| refusal(format!("{} is unreadable: {error}", path.display())))?;
        if data.len() > super::protocol::MAX_FILE {
            return Err(refusal(format!(
                "only regular files up to 512 KiB are supported: {name}"
            )));
        }
        *total += data.len();
        if *total > super::protocol::MAX_STAGED as usize
            || entries.len() >= super::protocol::MAX_FILES
        {
            return Err(refusal("workspace exceeds the preview transfer limit"));
        }
        let relative = path
            .strip_prefix(root)
            .map(|relative| relative.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.push(WorkspaceEntry {
            path: relative,
            executable: mode & 0o111 != 0,
            data,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_for(root: &Path) -> ImageManifest {
        let image = root.join("image");
        ImageManifest {
            status: "prepared".to_owned(),
            disk_sha256: digest(&image.join("base.raw")).expect("digests"),
            helper_sha256: digest(&image.join("vz")).expect("digests"),
            custodian_sha256: digest(&image.join("custodian")).expect("digests"),
            seed_sha256: digest(&image.join("seed.iso")).expect("digests"),
        }
    }

    fn installed(dir: &Path) -> PathBuf {
        let root = dir.join("0.1.0-preview.1");
        let image = root.join("image");
        std::fs::create_dir_all(&image).expect("dirs");
        for name in ["base.raw", "vz", "custodian", "seed.iso"] {
            std::fs::write(image.join(name), name).expect("files");
        }
        let manifest = manifest_for(&root);
        std::fs::write(
            image.join("image.json"),
            serde_json::to_string(&manifest).expect("serializes"),
        )
        .expect("manifest");
        root
    }

    #[test]
    fn an_install_verifies_against_its_recorded_hashes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = installed(dir.path());
        let install = Install::from_root(root).expect("found");
        install.verify().expect("hashes match");
        assert_eq!(install.helper(), install.root.join("image/vz"));
    }

    #[test]
    fn a_swapped_artifact_refuses_before_any_boot() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = installed(dir.path());
        std::fs::write(root.join("image/vz"), "tampered").expect("swap");
        let install = Install::from_root(root).expect("found");
        let error = install.verify().expect_err("hashes differ");
        assert!(
            error.0.contains("does not match prepared metadata"),
            "{error}"
        );
    }

    #[test]
    fn a_manifest_that_is_not_prepared_is_not_bootable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = installed(dir.path());
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("image/image.json")).expect("reads"))
                .expect("parses");
        let mut preparing = manifest;
        preparing["status"] = serde_json::Value::String("preparing".to_owned());
        std::fs::write(
            root.join("image/image.json"),
            serde_json::to_string(&preparing).expect("serializes"),
        )
        .expect("writes");
        let install = Install::from_root(root).expect("found");
        assert!(install.verify().is_err(), "a preparing image refuses");
    }

    #[test]
    fn the_receipt_rules_are_the_preview_ones() {
        let limits = [
            ("wall", true),
            ("mem", true),
            ("pids", true),
            ("swap", true),
        ]
        .into_iter()
        .map(|(key, applied)| serde_json::json!({"key": key, "applied": applied}))
        .collect::<Vec<_>>();
        let receipt = serde_json::json!({
            "schema": "ukai.jail.receipt/1", "platform": {"os": "linux"},
            "policy": {"name": "tool"}, "containment": "enforced",
            "child_protection": "enforced", "exec_observed": true,
            "lifetime": {"boundary": "pid_namespace", "tree_empty": true, "integrity": "verified"},
            "state_cleanup": "complete", "errors": [],
            "applied": {"network": {"mode": "none"}, "limits": limits},
        });
        verify_guest_receipt(&receipt, "tool").expect("verified");
        for mutate in [
            |r: &mut serde_json::Value| r["containment"] = "refused".into(),
            |r: &mut serde_json::Value| r["platform"]["os"] = "macos".into(),
            |r: &mut serde_json::Value| {
                r["applied"]["limits"] = serde_json::Value::Array(
                    r["applied"]["limits"].as_array().expect("array")[1..].to_vec(),
                )
            },
            |r: &mut serde_json::Value| r["applied"]["network"]["mode"] = "host".into(),
            |r: &mut serde_json::Value| r["lifetime"]["tree_empty"] = false.into(),
            |r: &mut serde_json::Value| r["lifetime"]["integrity"] = "lost".into(),
            |r: &mut serde_json::Value| r["state_cleanup"] = "incomplete".into(),
            |r: &mut serde_json::Value| r["errors"] = serde_json::json!(["boom"]),
            |r: &mut serde_json::Value| r["policy"]["name"] = "build".into(),
            |r: &mut serde_json::Value| r["applied"]["limits"] = "wall".into(),
        ] {
            let mut receipt = receipt.clone();
            mutate(&mut receipt);
            assert!(verify_guest_receipt(&receipt, "tool").is_err(), "{receipt}");
        }
        for receipt in [serde_json::Value::Null, serde_json::json!(7)] {
            assert!(verify_guest_receipt(&receipt, "tool").is_err());
        }
    }

    #[test]
    fn staging_reads_regular_files_and_refuses_links_and_limits() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("workspace");
        std::fs::create_dir_all(root.join("dir")).expect("dirs");
        std::fs::write(root.join("dir/a b.txt"), b"hello\n").expect("file");
        std::fs::write(root.join("top"), b"#!/bin/sh\n").expect("file");
        std::fs::set_permissions(root.join("top"), std::fs::Permissions::from_mode(0o755))
            .expect("mode");
        std::fs::write(root.join("target"), b"excluded by name").expect("file");
        std::fs::create_dir(root.join(".git")).expect("dir");
        std::fs::write(root.join(".git/config"), b"private").expect("file");
        let entries = snapshot_workspace(&root).expect("stages");
        assert_eq!(
            entries,
            vec![
                WorkspaceEntry {
                    path: "dir/a b.txt".to_owned(),
                    executable: false,
                    data: b"hello\n".to_vec(),
                },
                WorkspaceEntry {
                    path: "top".to_owned(),
                    executable: true,
                    data: b"#!/bin/sh\n".to_vec(),
                },
            ]
        );

        let linked = dir.path().join("workspace-link");
        std::fs::create_dir_all(&linked).expect("dir");
        std::os::unix::fs::symlink(dir.path().join("workspace"), linked.join("link"))
            .expect("link");
        assert!(snapshot_workspace(&linked).is_err(), "links refuse");

        let big = dir.path().join("workspace-big");
        std::fs::create_dir_all(&big).expect("dir");
        let file = File::create(big.join("large")).expect("file");
        file.set_len(super::super::protocol::MAX_FILE as u64 + 1)
            .expect("size");
        drop(file);
        let error = snapshot_workspace(&big).expect_err("too large");
        assert!(error.0.contains("512 KiB"), "{error}");
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    #[test]
    fn versions_are_ordered_numerically() {
        assert!(version_key(Path::new("0.10.0")) > version_key(Path::new("0.9.0")));
        assert!(version_key(Path::new("0.10.0")) > version_key(Path::new("0.10.0-rc.1")));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn copy_is_verified_after_source_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("image");
        std::fs::create_dir(&image).unwrap();
        for name in ["base.raw", "vz", "seed.iso", "custodian"] {
            std::fs::write(image.join(name), name).unwrap();
        }
        let install = Install {
            root: dir.path().to_path_buf(),
            manifest: ImageManifest {
                status: "prepared".into(),
                disk_sha256: digest(&image.join("base.raw")).unwrap(),
                helper_sha256: digest(&image.join("vz")).unwrap(),
                seed_sha256: digest(&image.join("seed.iso")).unwrap(),
                custodian_sha256: digest(&image.join("custodian")).unwrap(),
            },
        };
        install.verify().unwrap();
        std::fs::write(image.join("base.raw"), "substituted after verification").unwrap();
        let boot = tempfile::tempdir().unwrap();
        assert!(install.verified_copy(boot.path()).is_err());
    }
}
