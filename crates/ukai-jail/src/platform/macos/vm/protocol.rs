//! The VM tier's wire frames (J18, jail-macos.md §6): NDJSON over Unix
//! sockets, one UTF-8 object per line.
//!
//! Two protocols share this module. `ukai.jail.vm-control/1` runs on the
//! per-operator control socket (`<data-dir>/vm/control.sock`): `status` and
//! `stop`. `ukai.jail.vm-attempt/1` runs on the attempt socket, one
//! connection per attempt: the host stages the workspace and the ephemeral
//! credentials, releases, and reads the run back; the connection itself is
//! the lease, so its end-of-file cancels the attempt (§6: "The lease is
//! end-of-file, not a timer").
//!
//! The module is standalone (standard library, `serde`, `serde_json`,
//! `base64` only): the `ukai-vm` binary and the stand-in tests include it by
//! path, so the host and its helper cannot drift apart silently.
//!
//! Field rules follow the preview's (`run.py`): every field a reader uses is
//! typed strictly, fields it does not read are not constrained, and a frame
//! that fails to decode is a transport failure, never a guessed message.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The control protocol's identifier, as `status` reports it.
pub const SCHEMA_CONTROL: &str = "ukai.jail.vm-control/1";

/// The attempt protocol's identifier, as `ready` reports it.
pub const SCHEMA_ATTEMPT: &str = "ukai.jail.vm-attempt/1";

/// The most bytes one frame (one NDJSON line) may take. A `put` carries at
/// most [`MAX_FILE`] payload bytes, which base64 expands by a third; the
/// receipt frame carries a whole receipt, whose bound this covers four
/// times over.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

/// The most bytes one attempt may move in both directions, the preview's
/// total transport cap.
pub const MAX_TOTAL: u64 = 128 * 1024 * 1024;

/// The most bytes one staged file may take (the preview's limit, which
/// `guest.py` owns on the guest side).
pub const MAX_FILE: usize = 512 * 1024;

/// The most files one attempt stages (the preview's limit).
pub const MAX_FILES: usize = 5000;

/// The most bytes one attempt stages in total (the preview's limit).
pub const MAX_STAGED: u64 = 32 * 1024 * 1024;

/// The wall budget one guest attempt may take, in seconds: the preview's
/// grammar.
pub const WALL_MAX: u32 = 300;

/// The profiles the guest jail accepts, the preview's two.
pub const GUEST_PROFILES: [&str; 2] = ["tool", "build"];

/// Why a frame (or a stream of them) did not decode.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrameError(pub String);

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FrameError {}

fn frame_error(what: impl Into<String>) -> FrameError {
    FrameError(what.into())
}

/// Encodes one frame as its NDJSON line, newline included.
///
/// # Errors
/// [`FrameError`] when the frame cannot serialize, which is a defect of the
/// writer, never of the peer.
pub fn encode<T: Serialize>(frame: &T) -> Result<Vec<u8>, FrameError> {
    let mut line = serde_json::to_vec(frame)
        .map_err(|error| frame_error(format!("frame does not serialize: {error}")))?;
    if line.len() > MAX_FRAME {
        return Err(frame_error(format!(
            "frame is {} bytes, over the {}-byte line bound",
            line.len(),
            MAX_FRAME
        )));
    }
    line.push(b'\n');
    Ok(line)
}

/// Decodes one NDJSON line into a frame.
///
/// # Errors
/// [`FrameError`] when the line is not the frame's shape.
pub fn decode<T: for<'de> Deserialize<'de>>(line: &[u8]) -> Result<T, FrameError> {
    if line.len() > MAX_FRAME {
        return Err(frame_error(format!(
            "line is {} bytes, over the {}-byte frame bound",
            line.len(),
            MAX_FRAME
        )));
    }
    serde_json::from_slice(line).map_err(|error| frame_error(format!("malformed frame: {error}")))
}

/// Base64 (standard alphabet, padded), the one spelling every payload uses.
///
/// # Errors
/// [`FrameError`] when the text is not base64.
pub fn decode_data(text: &str) -> Result<Vec<u8>, FrameError> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|error| frame_error(format!("payload is not base64: {error}")))
}

/// [`decode_data`] for payloads a writer already encoded.
pub fn encode_data(payload: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(payload)
}

/// Splits an NDJSON stream on newlines, carrying the partial tail.
///
/// A line over [`MAX_FRAME`] fails the whole stream: the peer is not
/// speaking this protocol.
#[derive(Default)]
pub struct LineSplitter {
    buffer: Vec<u8>,
    total: u64,
}

impl LineSplitter {
    /// A stream that has moved `total` bytes so far.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Feeds one read; returns every complete line. The first over-limit
    /// line, and any stream past [`MAX_TOTAL`], is an error that ends the
    /// attempt.
    ///
    /// # Errors
    /// [`FrameError`] on an over-bound line or stream.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        self.total += chunk.len() as u64;
        if self.total > MAX_TOTAL {
            return Err(frame_error("total transport limit exceeded"));
        }
        self.buffer.extend_from_slice(chunk);
        let mut lines = Vec::new();
        while let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.buffer.drain(..=position).collect();
            line.pop();
            if line.len() > MAX_FRAME {
                return Err(frame_error("oversized frame"));
            }
            lines.push(line);
        }
        if self.buffer.len() > MAX_FRAME {
            return Err(frame_error("oversized frame"));
        }
        Ok(lines)
    }
}

/// A workspace file the host stages, one `put` frame.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Put {
    /// The path beneath the guest workspace, as `guest.py`'s `relative`
    /// spells it.
    pub path: String,
    /// Whether the file keeps its executable bit.
    pub executable: bool,
    /// The bytes, base64.
    pub data: String,
}

/// An ephemeral credential (J18 §6): the value crosses once per attempt and
/// is never written to the guest disk. The guest controller stages it in
/// tmpfs for the jail and deletes it after the attempt.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SecretEntry {
    /// The credential id the launch profile declares.
    pub id: String,
    /// The value, base64.
    pub data: String,
}

/// Host → vm, one attempt session.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ToVm {
    /// Stage the attempt: reset the guest workspace and evidence, receive
    /// the files and the ephemeral credentials, hold.
    Prepare {
        /// The host attempt's identifier, recorded in the transport record.
        attempt_id: String,
        /// The guest jail's profile.
        profile: String,
        /// The wall budget, 1..=[`WALL_MAX`] seconds.
        wall_seconds: u32,
        /// The argv, each element base64: a byte argv, never a shell string.
        argv: Vec<String>,
        /// The ephemeral credentials, if the policy declares any.
        #[serde(default)]
        secrets: Vec<SecretEntry>,
    },
    /// One workspace file.
    Put(Put),
    /// Release: run the jail. The frames before this stage; this one starts
    /// the guest attempt.
    Run,
}

/// A guest-controller statement connecting a guest jail receipt to this host run.
/// This is guest-reported provenance, not a host measurement of the Linux kernel.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBinding {
    pub attempt_id: String,
    pub boot_id: String,
    pub guest_attempt_id: String,
    pub guest_boot_id: String,
    pub profile: String,
    pub argv_digest: String,
}

/// vm → host, one attempt session.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FromVm {
    /// The first frame of a connection: who is serving, and which image.
    Ready {
        /// The protocol identifier.
        schema: String,
        /// The ukai-vm boot this connection serves.
        boot_id: String,
        /// The image digests, as `image.json` pins them.
        disk_sha256: String,
        helper_sha256: String,
        custodian_sha256: String,
        seed_sha256: String,
        /// The vsock port the guest controller listens on.
        vsock_port: u32,
    },
    /// The guest accepted the staging: workspace reset, files and ephemeral
    /// credentials held. Carries the guest kernel, which the receipt's
    /// platform record also names.
    Prepared {
        /// The guest's kernel release.
        kernel: String,
    },
    /// The guest jail started. The release acknowledgement.
    Released {
        /// The guest supervisor's pid, as the guest reported it.
        supervisor_pid: u32,
    },
    /// A chunk of the target's stdout, base64.
    Stdout {
        /// The bytes, base64.
        data: String,
    },
    /// A chunk of the target's stderr, base64.
    Stderr {
        /// The bytes, base64.
        data: String,
    },
    /// One output file: the workspace the run changed, or the guest's
    /// evidence directory.
    File {
        /// `workspace` or `evidence`.
        group: String,
        /// The path beneath the group.
        path: String,
        /// Whether the guest recorded an executable bit.
        executable: bool,
        /// The bytes, base64.
        data: String,
    },
    /// The guest's Linux receipt, whole, with the digest of the bytes. The
    /// host verifies the digest and then the receipt itself; the verified
    /// bytes are what the host attempt directory stores.
    Receipt {
        /// The SHA-256 of the receipt bytes, lowercase hex.
        sha256: String,
        /// The receipt bytes, base64.
        data: String,
    },
    /// Receipt with a per-run guest-controller binding. Unbound receipts refuse.
    BoundReceipt {
        sha256: String,
        data: String,
        binding: ReceiptBinding,
    },
    /// The attempt ended with the guest jail's own exit status.
    Done {
        /// The guest jail's exit status.
        exit_code: i32,
    },
    /// The transport failed. The attempt ends failed; the host never
    /// invents a guest outcome.
    Error {
        /// A safe reason.
        message: String,
    },
}

/// Client → vm, over the control socket.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ToControl {
    /// Ask the warm guest's state.
    Status,
    /// Ask for an orderly stop.
    Stop,
}

/// vm → client, over the control socket.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FromControl {
    /// The warm guest's state.
    Status {
        /// The protocol identifier.
        schema: String,
        /// The ukai-vm boot's identifier.
        boot_id: String,
        /// Whether the guest is running.
        warm: bool,
        /// Whether an attempt session is live.
        attempt_live: bool,
        /// The guest kernel, when the guest has reported one.
        kernel: Option<String>,
        /// The image digests, as `image.json` pins them.
        disk_sha256: String,
        helper_sha256: String,
        custodian_sha256: String,
        seed_sha256: String,
        /// The vsock port the guest controller listens on.
        vsock_port: u32,
        /// The idle budget, seconds, after which `ukai-vm` stops the guest
        /// on its own (initial 10 minutes, jail-macos.md §6).
        idle_seconds: u64,
    },
    /// An orderly stop was requested; the guest and its service end.
    Stopping {
        /// The protocol identifier.
        schema: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_through_their_line_form() {
        let frames = [
            ToVm::Prepare {
                attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
                profile: "tool".to_owned(),
                wall_seconds: 30,
                argv: vec![encode_data(b"/bin/true")],
                secrets: vec![SecretEntry {
                    id: "token".to_owned(),
                    data: encode_data(b"s3cret"),
                }],
            },
            ToVm::Put(Put {
                path: "dir/input.txt".to_owned(),
                executable: false,
                data: encode_data(b"hello\n"),
            }),
            ToVm::Run,
        ];
        for frame in &frames {
            let line = encode(frame).expect("encodes");
            assert_eq!(decode::<ToVm>(&line).as_ref(), Ok(frame), "{frame:?}");
        }
        let frames = [
            FromVm::Ready {
                schema: SCHEMA_ATTEMPT.to_owned(),
                boot_id: "boot-1".to_owned(),
                disk_sha256: "d".repeat(64),
                helper_sha256: "h".repeat(64),
                custodian_sha256: "c".repeat(64),
                seed_sha256: "s".repeat(64),
                vsock_port: 1024,
            },
            FromVm::Prepared {
                kernel: "6.14.0".to_owned(),
            },
            FromVm::Released { supervisor_pid: 42 },
            FromVm::Stdout {
                data: encode_data(b"out"),
            },
            FromVm::Stderr {
                data: encode_data(b"err"),
            },
            FromVm::File {
                group: "workspace".to_owned(),
                path: "output.txt".to_owned(),
                executable: true,
                data: encode_data(b"made in Linux"),
            },
            FromVm::Receipt {
                sha256: "a".repeat(64),
                data: encode_data(b"{}"),
            },
            FromVm::Done { exit_code: 3 },
            FromVm::Error {
                message: "guest lease lost".to_owned(),
            },
        ];
        for frame in &frames {
            let line = encode(frame).expect("encodes");
            assert_eq!(decode::<FromVm>(&line).as_ref(), Ok(frame), "{frame:?}");
        }
        for frame in [ToControl::Status, ToControl::Stop] {
            let line = encode(&frame).expect("encodes");
            assert_eq!(decode::<ToControl>(&line).as_ref(), Ok(&frame));
        }
        let status = FromControl::Status {
            schema: SCHEMA_CONTROL.to_owned(),
            boot_id: "boot-1".to_owned(),
            warm: true,
            attempt_live: false,
            kernel: Some("6.14.0".to_owned()),
            disk_sha256: "d".repeat(64),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
            vsock_port: 1024,
            idle_seconds: 600,
        };
        let line = encode(&status).expect("encodes");
        assert_eq!(decode::<FromControl>(&line).as_ref(), Ok(&status));
        let stopping = FromControl::Stopping {
            schema: SCHEMA_CONTROL.to_owned(),
        };
        let line = encode(&stopping).expect("encodes");
        assert_eq!(decode::<FromControl>(&line).as_ref(), Ok(&stopping));
    }

    #[test]
    fn a_bool_is_not_an_int_and_an_unknown_operation_is_not_a_frame() {
        let line =
            br#"{"op":"prepare","attempt_id":"a","profile":"tool","wall_seconds":true,"argv":[]}"#;
        assert!(
            decode::<ToVm>(line).is_err(),
            "booleans stay out of int fields"
        );
        assert!(decode::<ToVm>(br#"{"op":"exec","argv":[]}"#).is_err());
        assert!(decode::<FromVm>(br#"{"event":"done","exit_code":false}"#).is_err());
        assert!(decode::<FromVm>(br#"{"event":"boom"}"#).is_err());
        assert!(decode::<ToVm>(b"not json").is_err());
    }

    #[test]
    fn the_splitter_yields_lines_and_refuses_bounds() {
        let mut splitter = LineSplitter::default();
        let lines = splitter
            .push(b"{\"op\":\"run\"}\n{\"op\":\"stop\"}")
            .expect("first read");
        assert_eq!(lines, vec![b"{\"op\":\"run\"}".to_vec()]);
        assert!(splitter.push(b"\n").expect("second read").len() == 1);
        let mut splitter = LineSplitter::default();
        let mut chunk = vec![b'a'; MAX_FRAME + 1];
        chunk.push(b'\n');
        assert!(
            splitter.push(&chunk).is_err(),
            "an over-limit line fails the stream"
        );
        let mut splitter = LineSplitter::default();
        let mut total = Vec::new();
        let one = vec![b'x'; 1024];
        while (total.len() as u64) <= MAX_TOTAL {
            total.extend_from_slice(&one);
        }
        assert!(splitter.push(&total).is_err(), "an over-limit stream fails");
    }
}

#[cfg(test)]
mod bound_regressions {
    use super::*;

    #[test]
    fn decode_checks_size_even_for_valid_json() {
        let line = serde_json::to_vec(
            &serde_json::json!({"event":"error", "message":"x".repeat(MAX_FRAME)}),
        )
        .unwrap();
        assert!(
            decode::<FromVm>(&line)
                .unwrap_err()
                .0
                .contains("frame bound")
        );
    }

    #[test]
    fn splitter_tail_bound_is_independent_of_newline_bound() {
        let mut split = LineSplitter::default();
        split.push(&vec![b'x'; MAX_FRAME]).unwrap();
        assert!(split.push(b"x").unwrap_err().0.contains("oversized"));
    }

    #[test]
    fn splitter_total_bound_uses_small_valid_lines() {
        let mut split = LineSplitter::default();
        let chunk = [vec![b'x'; 1023], vec![b'\n']].concat();
        for _ in 0..(MAX_TOTAL / chunk.len() as u64) {
            split.push(&chunk).unwrap();
        }
        assert!(split.push(b"\n").unwrap_err().0.contains("total transport"));
    }

    #[test]
    fn split_hundred_kilobyte_export_is_lossless() {
        let payload = vec![b'x'; 100_000];
        let frame = FromVm::File {
            group: "workspace".into(),
            path: "large".into(),
            executable: false,
            data: encode_data(&payload),
        };
        let encoded = encode(&frame).unwrap();
        let mut split = LineSplitter::default();
        let mut lines = Vec::new();
        for chunk in encoded.chunks(65536) {
            lines.extend(split.push(chunk).unwrap());
        }
        assert_eq!(lines.len(), 1);
        assert_eq!(decode::<FromVm>(&lines[0]).unwrap(), frame);
    }
}
