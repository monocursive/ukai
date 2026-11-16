//! Recorded evidence that unit tests read back, found by its row directory.
//!
//! An evidence directory keeps the name it was recorded under, and some of
//! those name the agent that ran. jail-v1 §15 row I02 forbids that token in
//! the execution core's sources, and the scan covers `src/`, unit tests
//! included. So a test names the row (`k113-attempt`), which is what it
//! means anyway, and this module finds the one result that recorded it.
//! None, or more than one, is a test failure, never a silent pick.

use std::path::PathBuf;

/// The results tree, read at test time so evidence is no build input.
fn results() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/benchmarks/jail/results"
    ))
}

/// The one `<result>/<row>` directory in the results tree.
///
/// # Panics
/// When the tree is unreadable, or no result or more than one records `row`.
pub(crate) fn recorded(row: &str) -> PathBuf {
    let mut found: Vec<PathBuf> = std::fs::read_dir(results())
        .expect("the results tree is readable")
        .map(|entry| entry.expect("a results entry").path().join(row))
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one result records {row}: {found:?}"
    );
    found.pop().expect("one")
}

/// The K113 attempt of 2026-11-03: a proxied, observed `--vm` attempt.
pub(crate) fn k113_attempt() -> PathBuf {
    recorded("k113-attempt")
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_row_is_found_once_and_a_missing_one_fails() {
        assert!(super::k113_attempt().join("evidence/jail.json").is_file());
        let missing = std::panic::catch_unwind(|| super::recorded("no-such-row"));
        assert!(missing.is_err(), "an unrecorded row is a failure");
    }
}
