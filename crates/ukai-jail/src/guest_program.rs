//! Descriptive guest program identities. A guest path is never a host path or
//! descriptor; the guest's real resolver pins the executable before release.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const CATALOG_SCHEMA: &str = "ukai.vm.guest-program-catalog/1";
pub const CATALOG_MAX: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestPath(String);

impl GuestPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeEntry {
    pub path: String,
    pub kind: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_u64"
    )]
    pub nlink: Option<u64>,
}

fn present_u64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    u64::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub id: String,
    pub alias: String,
    pub version: String,
    pub format: String,
    pub executable: String,
    pub install_root: String,
    pub program_root: u8,
    pub argv_prefix: Vec<String>,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub profile_sha256: String,
    pub guest_jail_sha256: String,
    pub supported_states: Vec<String>,
    pub interpreter: Option<String>,
    pub tree: Vec<TreeEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: String,
    pub entries: Vec<CatalogEntry>,
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Catalog {
    pub fn parse(bytes: &[u8], expected: &str) -> Result<Self, String> {
        if bytes.len() > CATALOG_MAX || !is_sha256(expected) || sha256(bytes) != expected {
            return Err("guest program catalog digest or size differs".into());
        }
        let catalog: Self =
            serde_json::from_slice(bytes).map_err(|_| "malformed guest program catalog")?;
        if catalog.schema != CATALOG_SCHEMA
            || catalog.entries.is_empty()
            || catalog.entries.len() > 16
        {
            return Err("unsupported guest program catalog shape".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut aliases = std::collections::BTreeSet::new();
        for entry in &catalog.entries {
            entry.validate()?;
            if !ids.insert(&entry.id) || !aliases.insert(&entry.alias) {
                return Err("duplicate guest program catalog identity".into());
            }
        }
        Ok(catalog)
    }
}

impl CatalogEntry {
    pub fn validate(&self) -> Result<(), String> {
        let version = identifier(&self.version, 64);
        let root = format!("/opt/ukai/programs/{}/{}", self.alias, self.version);
        let executable = format!("{root}/{}", self.alias);
        let expected_tree = vec![
            TreeEntry {
                path: ".".into(),
                kind: "directory".into(),
                mode: 0o555,
                uid: 0,
                gid: 0,
                nlink: None,
            },
            TreeEntry {
                path: self.alias.clone(),
                kind: "file".into(),
                mode: 0o555,
                uid: 0,
                gid: 0,
                nlink: Some(1),
            },
        ];
        if !name(&self.alias)
            || !version
            || !identifier(&self.id, 128)
            || self.format != "elf64-aarch64"
            || self.install_root != root
            || self.executable != executable
            || self.argv_prefix != [executable]
            || self.program_root != 1
            || self.interpreter.as_deref() != Some("/lib/ld-linux-aarch64.so.1")
            || self.supported_states != ["attempt"]
            || self.tree != expected_tree
            || self.executable_size < 64
            || self.executable_size > 512 * 1024 * 1024
            || ![
                &self.executable_sha256,
                &self.profile_sha256,
                &self.guest_jail_sha256,
            ]
            .into_iter()
            .all(|s| is_sha256(s))
        {
            return Err("unsupported or unsafe guest program catalog entry".into());
        }
        Ok(())
    }
}

/// Bound descriptive identity, never accepted by a local executable launcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestProgram {
    pub catalog_sha256: String,
    pub disk_sha256: String,
    pub seed_sha256: String,
    pub entry: CatalogEntry,
    pub executable: GuestPath,
    pub install_root: GuestPath,
}

impl GuestProgram {
    pub fn new(
        catalog_sha256: String,
        disk_sha256: String,
        seed_sha256: String,
        entry: CatalogEntry,
    ) -> Result<Self, String> {
        entry.validate()?;
        if ![&catalog_sha256, &disk_sha256, &seed_sha256]
            .into_iter()
            .all(|s| is_sha256(s))
        {
            return Err("guest program image identity is malformed".into());
        }
        Ok(Self {
            executable: GuestPath(entry.executable.clone()),
            install_root: GuestPath(entry.install_root.clone()),
            catalog_sha256,
            disk_sha256,
            seed_sha256,
            entry,
        })
    }
    pub fn argv_prefix(&self) -> Vec<Vec<u8>> {
        vec![self.executable.as_bytes().to_vec()]
    }
}

/// Value-free request for an execution backend's program domain.
pub struct ProgramRequest {
    pub launch_name: String,
    pub bundled_profile_sha256: Option<String>,
    pub program_root: u8,
    pub attempt_state: bool,
}

/// The backend's authoritative executable path domain.
pub enum ProgramTarget {
    Local,
    Guest(Box<GuestProgram>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_catalog_contract_vectors() {
        let fixture = include_bytes!("../vm/fixtures/guest-program-catalog.json");
        let catalog = Catalog::parse(fixture, &sha256(fixture)).unwrap();
        assert_eq!(catalog.entries[0].alias, "example");
        let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../vm/fixtures/guest-program-catalog-vectors.json"
        ))
        .unwrap();
        for (key, valid) in [("valid", true), ("invalid", false)] {
            for vector in vectors[key].as_array().unwrap() {
                let bytes = vector["data"].as_str().unwrap().as_bytes();
                let result = Catalog::parse(bytes, &sha256(bytes));
                assert_eq!(result.is_ok(), valid, "{}: {result:?}", vector["name"]);
            }
        }
    }

    #[test]
    fn catalog_digest_and_bound_are_authority() {
        let bytes = include_bytes!("../vm/fixtures/guest-program-catalog.json");
        assert!(Catalog::parse(bytes, &"0".repeat(64)).is_err());
        let oversized = vec![b' '; CATALOG_MAX + 1];
        assert!(Catalog::parse(&oversized, &sha256(&oversized)).is_err());
    }
}
