//! Source-only credentials for a guest. These never enter a local proxy and
//! never weaken a Secret's executable binding. Replacement is revocation.
use crate::{credentials, state::anchored::Stat};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

pub(crate) struct Source {
    pub(crate) id: String,
    pub(crate) policy: super::Policy,
    path: Vec<u8>,
    forbidden: Vec<(u64, u64)>,
    epoch: Stat,
    value: Zeroizing<Vec<u8>>,
    revoked: AtomicBool,
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestCredentialSource")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Source {
    pub(crate) fn load(
        id: String,
        policy: super::Policy,
        path: Vec<u8>,
        forbidden: Vec<(u64, u64)>,
        executable: &str,
    ) -> Result<Self, String> {
        policy.validate()?;
        if policy.refresh.is_some() || policy.binaries != [executable] {
            return Err(
                "guest source needs its exact catalog executable binding and no refresh".into(),
            );
        }
        let (value, epoch) =
            credentials::read_vault_source_version(&path, &forbidden, super::SOURCE_MAX)
                .map_err(str::to_owned)?;
        if !super::valid_value(&value) {
            return Err("guest credential source is not a valid bounded value".into());
        }
        Ok(Self {
            id,
            policy,
            path,
            forbidden,
            epoch,
            value,
            revoked: AtomicBool::new(false),
        })
    }

    pub(crate) fn identity(&self) -> credentials::SourceIdentity {
        credentials::SourceIdentity {
            dev: self.epoch.dev,
            ino: self.epoch.ino,
            size: self.epoch.size,
        }
    }

    pub(crate) fn check(&self) -> bool {
        if self.revoked.load(Ordering::Acquire) {
            return false;
        }
        let live =
            credentials::read_vault_source_version(&self.path, &self.forbidden, super::SOURCE_MAX)
                .is_ok_and(|(value, epoch)| {
                    self.epoch.unchanged_since(&epoch) && self.value.as_slice() == value.as_slice()
                });
        if !live {
            self.revoked.store(true, Ordering::Release);
        }
        live && !self.revoked.load(Ordering::Acquire)
    }

    pub(crate) fn value(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        if !self.check() {
            return Err("the captured guest credential source was revoked".into());
        }
        Ok(self.value.clone())
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SourceLease(pub(crate) Vec<Arc<Source>>);
impl SourceLease {
    pub(crate) fn check(&self) -> bool {
        self.0.iter().all(|source| source.check())
    }
    pub(crate) fn ids(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|source| source.id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _};

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, super::super::Policy) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("source");
        std::fs::write(&path, b"synthetic-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let policy = super::super::Policy {
            hosts: vec!["https://example.com".into()],
            binaries: vec!["/opt/ukai/programs/example/1.0/example".into()],
            ..Default::default()
        };
        (dir, path, policy)
    }

    #[test]
    fn guest_source_does_not_open_guest_executable_but_keeps_its_binding() {
        let (_dir, path, policy) = fixture();
        let source = Source::load(
            "api".into(),
            policy.clone(),
            path.as_os_str().as_bytes().to_vec(),
            vec![],
            &policy.binaries[0],
        )
        .unwrap();
        assert_eq!(source.policy, policy);
        assert_eq!(source.value().unwrap().as_slice(), b"synthetic-value");
        let lease = SourceLease(vec![Arc::new(source)]);
        assert!(lease.check());
        assert_eq!(lease.ids(), ["api"]);
    }

    #[test]
    fn same_byte_replacement_and_restoration_never_reactivate_the_source() {
        let (_dir, path, policy) = fixture();
        let source = Source::load(
            "api".into(),
            policy.clone(),
            path.as_os_str().as_bytes().to_vec(),
            vec![],
            &policy.binaries[0],
        )
        .unwrap();
        let old = path.with_extension("old");
        std::fs::rename(&path, &old).unwrap();
        std::fs::write(&path, b"synthetic-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!source.check());
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(old, path).unwrap();
        assert!(source.value().is_err());
    }

    #[test]
    fn guest_source_rejects_unbound_policy_and_exposed_or_unsafe_source() {
        let (_dir, path, policy) = fixture();
        let bytes = path.as_os_str().as_bytes().to_vec();
        let mut unbound = policy.clone();
        unbound.binaries.clear();
        assert!(
            Source::load(
                "api".into(),
                unbound,
                bytes.clone(),
                vec![],
                &policy.binaries[0]
            )
            .is_err()
        );
        let (_, stat) =
            credentials::read_vault_source_version(&bytes, &[], super::super::SOURCE_MAX).unwrap();
        assert!(
            Source::load(
                "api".into(),
                policy.clone(),
                bytes.clone(),
                vec![stat.identity()],
                &policy.binaries[0]
            )
            .is_err()
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            Source::load(
                "api".into(),
                policy.clone(),
                bytes,
                vec![],
                &policy.binaries[0]
            )
            .is_err()
        );
    }
}
