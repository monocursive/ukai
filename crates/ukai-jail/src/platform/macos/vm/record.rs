//! The transport record `ukai.jail.vm-transport/1` (J18, jail-macos.md §6
//! and row K111): the host-side facts of an attempt that ran in the guest.
//!
//! A transport record is a Mac orchestration record, the warm successor of
//! the preview's `ukai.vm.attempt/1`. It never claims native macOS
//! enforcement, and it is never a substitute for the guest's
//! `ukai.jail.receipt/1`, which it names by digest.
//!
//! The module is standalone (`serde`, `serde_json` only): the `ukai-vm`
//! binary and the stand-in tests include it by path.

use serde::{Deserialize, Serialize};

/// The record's identifier.
pub const SCHEMA_TRANSPORT: &str = "ukai.jail.vm-transport/1";

/// The name of the record file in the host attempt directory.
pub const TRANSPORT_FILE: &str = "vm-transport.json";

/// The image digests the serving `ukai-vm` verified at boot, as
/// `image.json` pins them.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ImageDigests {
    /// The guest disk's SHA-256.
    pub disk_sha256: String,
    /// The VZ client's SHA-256.
    pub helper_sha256: String,
    /// The custodian's SHA-256.
    pub custodian_sha256: String,
    /// The seed ISO's SHA-256.
    pub seed_sha256: String,
}

/// The host-side transport facts of one `--vm` attempt.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportRecord {
    /// Always [`SCHEMA_TRANSPORT`].
    pub schema: String,
    /// The host attempt's identifier.
    pub attempt_id: String,
    /// The ukai-vm boot the attempt ran in.
    pub boot_id: String,
    /// The guest kernel, as the guest reported it at staging.
    pub guest_kernel: String,
    /// The image digests verified at boot.
    pub image: ImageDigests,
    /// The vsock port the guest controller listened on.
    pub vsock_port: u32,
    /// The control socket's path.
    pub control_socket: String,
    /// The attempt socket's path.
    pub attempt_socket: String,
    /// When the host started the attempt, RFC 3339 UTC.
    pub host_wall_started: String,
    /// How long the host drove the attempt, seconds.
    pub elapsed_seconds: f64,
    /// The SHA-256 of the stored guest receipt bytes, lowercase hex: the
    /// record's only claim about the receipt, which the host verified.
    pub guest_receipt_sha256: String,
}

impl TransportRecord {
    /// A record for an attempt that finished. The arguments are the
    /// record's own fields, in its wire order; a builder would repeat them.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        attempt_id: impl Into<String>,
        boot_id: impl Into<String>,
        guest_kernel: impl Into<String>,
        image: ImageDigests,
        vsock_port: u32,
        control_socket: impl Into<String>,
        attempt_socket: impl Into<String>,
        host_wall_started: impl Into<String>,
        elapsed_seconds: f64,
        guest_receipt_sha256: impl Into<String>,
    ) -> Self {
        TransportRecord {
            schema: SCHEMA_TRANSPORT.to_owned(),
            attempt_id: attempt_id.into(),
            boot_id: boot_id.into(),
            guest_kernel: guest_kernel.into(),
            image,
            vsock_port,
            control_socket: control_socket.into(),
            attempt_socket: attempt_socket.into(),
            host_wall_started: host_wall_started.into(),
            elapsed_seconds,
            guest_receipt_sha256: guest_receipt_sha256.into(),
        }
    }

    /// Writes the record to `dir`/[`TRANSPORT_FILE`], one JSON object.
    ///
    /// # Errors
    /// The write error, verbatim: a failed record is a failed attempt, never
    /// a silent one.
    pub fn write_in(&self, dir: &std::path::Path) -> std::io::Result<()> {
        let mut text = serde_json::to_vec_pretty(self)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        text.push(b'\n');
        std::fs::write(dir.join(TRANSPORT_FILE), text)
    }

    /// Reads the record from `dir`/[`TRANSPORT_FILE`].
    ///
    /// # Errors
    /// The read or parse error: a reader that cannot trust the record says
    /// so instead of printing a summary from a guess.
    pub fn read_in(dir: &std::path::Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(dir.join(TRANSPORT_FILE))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }
}

/// The summary's transport line (§6: "the summary prints the guest summary
/// plus one transport line from that record").
///
/// The existing caller passes a host receipt. That parameter is retained for
/// compatibility and deliberately ignored: its fields cannot certify guest facts.
/// This line names the guest evidence separately and escapes transport values.
#[must_use]
pub fn transport_line(_receipt: &serde_json::Value, record: &TransportRecord) -> String {
    // The current caller passes the HOST receipt. Do not turn its fields
    // into guest facts. The separately stored guest evidence is authoritative.
    format!(
        "vm: guest-reported facts in evidence/jail.json · boot {} · image {} · vsock {} · receipt sha256:{}",
        escape_control(&record.boot_id),
        short(&record.image.disk_sha256),
        record.vsock_port,
        short(&record.guest_receipt_sha256),
    )
}

/// The first 16 hex of a digest, enough to compare two records side by side;
/// the whole digest is in the record and in the receipt file's name.
fn short(digest: &str) -> &str {
    digest.get(..16).unwrap_or(digest)
}

/// One line, whatever the bytes: control characters render as `U+XXXX`, so
/// no transport fact can forge a second summary line.
fn escape_control(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            out.push_str(&format!("U+{:04X}", character as u32));
        } else {
            out.push(character);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> TransportRecord {
        TransportRecord::new(
            "att_00000000-0000-4000-8000-000000000001",
            "vm-boot-7f3a",
            "6.14.0-1010-aws",
            ImageDigests {
                disk_sha256: "d".repeat(64),
                helper_sha256: "h".repeat(64),
                custodian_sha256: "c".repeat(64),
                seed_sha256: "s".repeat(64),
            },
            1024,
            "/data/vm/control.sock",
            "/data/vm/attempt.sock",
            "2026-10-22T12:00:00Z",
            1.25,
            "a".repeat(64),
        )
    }

    fn receipt() -> serde_json::Value {
        serde_json::json!({
            "schema": "ukai.jail.receipt/1",
            "platform": {"os": "linux"},
            "policy": {"name": "tool"},
            "lifetime": {"boundary": "pid_namespace"},
        })
    }

    #[test]
    fn the_record_round_trips_through_its_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let written = record();
        written.write_in(dir.path()).expect("writes");
        let read = TransportRecord::read_in(dir.path()).expect("reads");
        assert_eq!(read, written);
    }

    #[test]
    fn the_transport_line_names_the_recorded_facts_and_stays_one_line() {
        let mut facts = record();
        facts.boot_id = "boot-with\nnewline".to_owned();
        let line = transport_line(&receipt(), &facts);
        assert!(
            line.starts_with("vm: guest-reported facts in evidence/jail.json"),
            "{line}"
        );
        assert!(
            line.contains("U+000A"),
            "the escape is the records' rule: {line}"
        );
        assert!(line.contains("image dddddddddddddddd"), "{line}");
        assert!(line.contains("vsock 1024"), "{line}");
        assert!(line.contains("receipt sha256:aaaaaaaaaaaaaaaa"), "{line}");
        assert_eq!(line.lines().count(), 1);
    }

    #[test]
    fn a_receipt_without_the_expected_groups_never_panics_the_line() {
        for receipt in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!(7),
        ] {
            let line = transport_line(&receipt, &record());
            assert!(line.contains("guest-reported"), "{line}");
        }
    }
}
