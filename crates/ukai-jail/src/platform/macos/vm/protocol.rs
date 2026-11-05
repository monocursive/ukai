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
/// The guest jail's profiles, as the wire names them. `agent` runs the
/// guest's own qualified Linux proxy (J18 §6: the guest jail's proxy
/// enforces the policy, as on any Linux host); `build` stays refused by the
/// live-share surface at the host side.
pub const GUEST_PROFILES: [&str; 3] = ["tool", "agent", "build"];

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

/// One vaulted launch declaration crossing to the guest: the name the guest
/// jail's `--launch` grammar takes, and a launch-profile TOML the host
/// generates from the policy snapshot's `launch` group (decision D3): the
/// guest profile and each vault credential, its source at
/// `/run/ukai-vm/credentials/<id>` (the transport stages the values there,
/// in tmpfs). The host parses the text back with the same loader before it
/// sends it, and the guest's loader re-parses it under its strict file
/// rules, so a malformed declaration refuses before any workload starts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LaunchDeclaration {
    /// The launch profile name, `[a-z][a-z0-9_-]{0,63}`.
    pub name: String,
    /// The generated profile TOML; it holds no credential value.
    pub toml: String,
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

/// The live workspace share's preflight facts (J18 §6, K109), as the
/// service's `status` discloses them.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LiveShareFacts {
    /// Always `false`: a case-folding volume is refused before boot.
    pub case_fold: bool,
    /// Measured `true` even on case-sensitive APFS; disclosed because two
    /// workspace names that differ only in decomposition can collide.
    /// The protected segments are pure ASCII, so no policy denial is
    /// bypassed.
    pub normalization_fold: bool,
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
        /// The canonical allow-host rules of a proxy policy (the `agent`
        /// profile): the guest jail parses each with its own `--allow-host`
        /// grammar, so an invalid rule refuses inside the guest, before any
        /// workload starts.
        #[serde(default)]
        allow_hosts: Vec<String>,
        /// The launch declaration a vaulted policy runs (J18 §6:
        /// credentials cross over vsock once per attempt and are never on
        /// the guest disk): its name and the TOML generated from the
        /// snapshot, whose credential sources name the guest's tmpfs
        /// staging path; the values themselves are the secret entries.
        /// `None` runs without a launch profile.
        #[serde(default)]
        launch: Option<LaunchDeclaration>,
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
        /// The secrets this attempt staged, as the guest acked them:
        /// `(id, tmpfs path)` pairs. The transport's evidence travels with
        /// the prepared frame so the client can verify the values crossed
        /// into the guest's tmpfs root (J18 §6).
        #[serde(default)]
        staged_secrets: Vec<(String, String)>,
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
        /// The guest controller's own stop of the attempt (decision D6),
        /// which a warm session runs before `done`. `None` when the guest
        /// sent none; the host refuses such an attempt's outcome.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stop: Option<GuestStop>,
    },
    /// The transport failed. The attempt ends failed; the host never
    /// invents a guest outcome.
    Error {
        /// A safe reason.
        message: String,
    },
}

/// The guest controller's stop of one warm attempt (decision D6), taken
/// outside the guest jail after the jail exited and verified its own tree.
/// Guest-reported, like the binding: not a host measurement. Its pre-kill
/// lists check the guest jail's `tree_empty`: a boundary still populated, or
/// a live process of the workload account outside the session's learned
/// infrastructure, when the stop began survived the guest jail. Its kills
/// alone are no such check: the boundaries' `cgroup.kill` records nothing of
/// what it ends.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct GuestStop {
    /// Every cgroup the stop killed and verified empty, relative to the
    /// guest's cgroup root.
    pub boundaries: Vec<String>,
    /// Those that held a process when the stop began, before it signalled
    /// anything.
    pub populated_before_kill: Vec<String>,
    /// The workload account's live processes outside the learned
    /// infrastructure when the stop began: guest pid and cgroup.
    pub live_before_kill: Vec<(u32, Option<String>)>,
    /// Every such process the stop killed by pid: guest pid and cgroup.
    pub strays_killed: Vec<(u32, Option<String>)>,
}

impl GuestStop {
    /// What the stop found the guest jail had left behind, worded for a
    /// refusal; `None` when it found nothing.
    #[must_use]
    pub fn survivors(&self) -> Option<String> {
        if self.populated_before_kill.is_empty()
            && self.live_before_kill.is_empty()
            && self.strays_killed.is_empty()
        {
            return None;
        }
        let processes = |list: &[(u32, Option<String>)]| {
            list.iter()
                .take(4)
                .map(|(pid, cgroup)| format!("{pid} in {}", cgroup.as_deref().unwrap_or("?")))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Some(format!(
            "{} boundar{} still populated [{}], {} process{} live [{}], {} killed by pid [{}]",
            self.populated_before_kill.len(),
            if self.populated_before_kill.len() == 1 {
                "y"
            } else {
                "ies"
            },
            self.populated_before_kill
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            self.live_before_kill.len(),
            if self.live_before_kill.len() == 1 {
                ""
            } else {
                "es"
            },
            processes(&self.live_before_kill),
            self.strays_killed.len(),
            processes(&self.strays_killed),
        ))
    }
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
        /// Whether the guest is running: the helper is alive and no stop
        /// was requested. It holds from the boot's start, while the guest
        /// may still be booting; see `ready`.
        warm: bool,
        /// Whether the guest completed its session handshake and reported
        /// its kernel: an attempt that connects now runs on a booted guest
        /// instead of waiting for the boot.
        #[serde(default)]
        ready: bool,
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
        /// The live workspace share's host path when the service booted
        /// with one (J18 §6); `None` is the preview's staged mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        live_workspace: Option<String>,
        /// The share's preflight facts, when a live share is attached.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        live_workspace_facts: Option<LiveShareFacts>,
        /// Whether the guest was booted with its NAT adapter attached: a
        /// proxied policy's guest proxy needs guest egress; without the
        /// adapter every proxied connection would refuse at the dial.
        #[serde(default)]
        guest_nat: bool,
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
                allow_hosts: vec!["api.example.com:443".to_owned()],
                launch: None,
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
                staged_secrets: Vec::new(),
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
            FromVm::Done {
                exit_code: 3,
                stop: None,
            },
            FromVm::Done {
                exit_code: 0,
                stop: Some(GuestStop {
                    boundaries: vec!["ukai-attempts.slice/attempt-1".to_owned()],
                    populated_before_kill: Vec::new(),
                    live_before_kill: vec![(7, None)],
                    strays_killed: vec![(7, Some("/user.slice/x".to_owned()))],
                }),
            },
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
            ready: true,
            attempt_live: false,
            kernel: Some("6.14.0".to_owned()),
            disk_sha256: "d".repeat(64),
            helper_sha256: "h".repeat(64),
            custodian_sha256: "c".repeat(64),
            seed_sha256: "s".repeat(64),
            vsock_port: 1024,
            idle_seconds: 600,
            live_workspace: None,
            live_workspace_facts: None,
            guest_nat: false,
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
    fn a_done_from_a_guest_without_a_stop_report_reads_as_none() {
        let done = decode::<FromVm>(br#"{"event":"done","exit_code":0}"#).expect("decodes");
        assert_eq!(
            done,
            FromVm::Done {
                exit_code: 0,
                stop: None
            }
        );
        let done = decode::<FromVm>(
            br#"{"event":"done","exit_code":0,"stop":{"boundaries":["a"],"populated_before_kill":[],"live_before_kill":[[9,null]],"strays_killed":[]}}"#,
        )
        .expect("decodes");
        let FromVm::Done {
            stop: Some(stop), ..
        } = done
        else {
            panic!("no stop: {done:?}");
        };
        assert_eq!(stop.live_before_kill, vec![(9, None)]);
    }

    #[test]
    fn a_stop_names_survivors_unless_every_list_is_empty() {
        assert_eq!(GuestStop::default().survivors(), None);
        let clean = GuestStop {
            boundaries: vec!["ukai-attempts.slice/attempt-1".to_owned()],
            ..GuestStop::default()
        };
        assert_eq!(
            clean.survivors(),
            None,
            "boundaries alone are what was covered"
        );
        let cases = [
            GuestStop {
                populated_before_kill: vec!["app.slice".to_owned()],
                ..GuestStop::default()
            },
            GuestStop {
                live_before_kill: vec![(41, Some("/user.slice/s".to_owned()))],
                ..GuestStop::default()
            },
            GuestStop {
                strays_killed: vec![(42, None)],
                ..GuestStop::default()
            },
        ];
        for stop in cases {
            let named = stop.survivors().expect("a survivor is named");
            assert!(
                named.contains("app.slice")
                    || named.contains("41 in /user.slice/s")
                    || named.contains("42 in ?"),
                "{named}"
            );
        }
    }

    #[test]
    fn a_status_without_ready_is_not_ready() {
        let line = br#"{"event":"status","schema":"ukai.jail.vm-control/1","boot_id":"b","warm":true,"attempt_live":false,"kernel":null,"disk_sha256":"d","helper_sha256":"h","custodian_sha256":"c","seed_sha256":"s","vsock_port":1024,"idle_seconds":0}"#;
        let FromControl::Status { warm, ready, .. } = decode::<FromControl>(line).expect("decodes")
        else {
            panic!("not a status");
        };
        assert!(warm && !ready);
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
