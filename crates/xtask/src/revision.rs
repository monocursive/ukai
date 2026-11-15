//! The revision a tree is at, as the suite prints it and the build records it.

use std::fmt;
use std::path::Path;

/// A commit, and whether the tree had uncommitted or untracked files.
/// Written `<40 hex>` or `<40 hex>+dirty`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// The full commit id, lowercase.
    pub sha: String,
    pub dirty: bool,
}

impl Revision {
    /// Parse `<40 hex>` or `<40 hex>+dirty`; anything else is no revision.
    #[must_use]
    pub fn parse(text: &str) -> Option<Revision> {
        let (sha, dirty) = match text.strip_suffix("+dirty") {
            Some(sha) => (sha, true),
            None => (text, false),
        };
        (sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Revision {
            sha: sha.to_ascii_lowercase(),
            dirty,
        })
    }

    /// The short form a run directory is named by.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.sha[..12]
    }

    /// The revision the repository at `root` is at: `HEAD`, dirty when
    /// tracked files have uncommitted changes or non-ignored untracked files exist.
    ///
    /// # Errors
    /// git could not say.
    pub fn of_repository(root: &Path) -> Result<Revision, String> {
        let head = crate::proc::git(root, &["rev-parse", "HEAD"])?;
        let mut revision =
            Revision::parse(&head).ok_or_else(|| format!("HEAD is `{head}`, not a commit"))?;
        revision.dirty =
            !crate::proc::git(root, &["status", "--porcelain", "--untracked-files=all"])?
                .is_empty();
        Ok(revision)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sha)?;
        if self.dirty {
            f.write_str("+dirty")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn a_revision_round_trips_and_nothing_else_parses() {
        for text in [SHA.to_owned(), format!("{SHA}+dirty")] {
            assert_eq!(Revision::parse(&text).unwrap().to_string(), text);
        }
        assert!(Revision::parse(&format!("{SHA}+dirty")).unwrap().dirty);
        assert_eq!(Revision::parse(SHA).unwrap().short(), &SHA[..12]);
        for bad in [
            "",
            "main",
            &SHA[..39],
            &format!("{SHA}0"),
            &format!("{SHA}+wip"),
            "+dirty",
        ] {
            assert_eq!(Revision::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn untracked_source_cannot_be_transferred_as_a_clean_revision() {
        // Conformance copies visible untracked source files as well as tracked
        // files, without .git. Its build claim must account for both kinds.
        let root = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| crate::proc::git(root.path(), args).unwrap();
        git(&["init", "-q"]);
        std::fs::write(root.path().join(".gitignore"), "target/\n").unwrap();
        git(&["add", ".gitignore"]);
        git(&[
            "-c",
            "user.name=Ukai fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ]);
        assert!(!Revision::of_repository(root.path()).unwrap().dirty);

        std::fs::create_dir(root.path().join("target")).unwrap();
        std::fs::write(root.path().join("target/ignored"), "build output").unwrap();
        assert!(!Revision::of_repository(root.path()).unwrap().dirty);

        std::fs::create_dir(root.path().join("crates")).unwrap();
        let source = root.path().join("crates/untracked.rs");
        std::fs::write(&source, "// uncommitted build input\n").unwrap();
        assert!(Revision::of_repository(root.path()).unwrap().dirty);
        git(&["add", "crates/untracked.rs"]);
        assert!(Revision::of_repository(root.path()).unwrap().dirty);
    }
}
