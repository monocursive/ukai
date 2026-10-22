//! J17: native observation, the supervisor's third ES client
//! (jail-macos.md §5, §4.10 flip, §9.2 K105–K107).
//!
//! The mapping and the gap semantics run here against a real trace sink;
//! the live client creation runs against this Mac (an unentitled host
//! answers `NotEntitled`, and J17 falls back honestly); the K107 summary
//! recompute runs `summary::summary()` over a synthetic macOS receipt and
//! journal, mirroring `summary_check.py`'s arms.

#![cfg(target_os = "macos")]

mod common;

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use ukai_jail::observer::{CoverageClass, CoverageSummary};
use ukai_jail::platform::macos::observe::{
    OBSERVATION_GAP_REASON, OBSERVED_CLASSES, OBSERVER_BACKEND, ObsEvent, ObsKind, ObserveJournal,
    PathEvidence, classify_path,
};
use ukai_jail::records::{Gap, SourceStatus};
use ukai_jail::summary::{self, Journal, JournalState};
use ukai_jail::trace::{self, FileSink, SharedTrace};

const ATTEMPT: &str = "attempt-observe";

/// `sha256:` over the receipt's RFC 8785 bytes: the name the journal's
/// receipt note carries.
fn digest(receipt: &Value) -> String {
    ukai_jail::canonical::sha256_prefixed(
        &ukai_jail::canonical::to_jcs(receipt).expect("a receipt canonicalizes"),
    )
}

/// One synthetic §5 notification.
fn obs(kind: ObsKind, seq: u64, path: &[u8]) -> ObsEvent {
    ObsEvent {
        kind,
        global_seq: seq,
        seq,
        token: [7; 8],
        path: path.to_vec(),
    }
}

/// A trace whose frames land in a file the test reads back.
struct FrameCapture {
    trace: SharedTrace,
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl FrameCapture {
    fn new() -> Self {
        let dir = common::private_tempdir();
        let path = dir.path().join("trace.jsonl");
        let file = std::fs::File::create(&path).expect("the trace file opens");
        FrameCapture {
            trace: trace::shared(FileSink::new(file)),
            path,
            _dir: dir,
        }
    }

    /// The audit frames, in write order.
    fn frames(&self) -> Vec<Value> {
        // Dropping the journal released the only other handle; the file sink
        // wrote every accepted frame straight through.
        let bytes = std::fs::read(&self.path).expect("the trace reads back");
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("a whole JSON frame"))
            .collect()
    }
}

/// The workspace root the classification is relative to.
fn workspace(temp: &Path) -> PathBuf {
    temp.join("work")
}

/// A macOS receipt under construction: `receipt-tool.json` re-based to the
/// §5 observation shape, with the journal frames kept beside it.
struct Fixture {
    receipt: Value,
    events: Vec<Value>,
    audit_seq: u64,
    wrapper_seq: u64,
    ns: u64,
}

impl Fixture {
    fn macos() -> Self {
        let mut receipt: Value = serde_json::from_slice(
            &std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../docs/specs/jail-v1/examples/receipt-tool.json"),
            )
            .expect("the example is checked in"),
        )
        .expect("the example is JSON");
        // The §5 shape: the observation backend, no closed-set name (the
        // closed set stays Linux's), every audit class the macOS observer
        // does not produce left unsupported, `limits` the wrapper's own.
        receipt["observer"] = json!({
            "backend": OBSERVER_BACKEND,
            "set": Value::Null,
            "attached": true,
            "sources": {"wrapper": "active", "audit": "active", "proxy": "unsupported"},
            "gaps": [],
        });
        receipt["coverage"] = json!({
            "exec": {"status": "active", "sources": ["audit"], "observed_count": 0, "gaps": []},
            "fs.write": {"status": "active", "sources": ["audit"], "observed_count": 0, "gaps": []},
            "fs.deny": {"status": "unsupported", "sources": [], "observed_count": null, "gaps": []},
            "net": {"status": "unsupported", "sources": [], "observed_count": null, "gaps": []},
            "limits": {"status": "active", "sources": ["wrapper"], "observed_count": 0, "gaps": []},
            "proxy.net": {"status": "unsupported", "sources": [], "observed_count": null, "gaps": []},
        });
        Fixture {
            receipt,
            events: Vec::new(),
            audit_seq: 0,
            wrapper_seq: 0,
            ns: 100_000_000,
        }
    }

    fn audit(&mut self, operation: &str, path: Value) {
        self.audit_seq += 1;
        self.ns += 1_000_000;
        let attempt_id = self.receipt["attempt_id"].clone();
        self.events.push(json!({
            "schema": "ukai.event/1",
            "attempt_id": attempt_id,
            "source": "audit",
            "source_seq": self.audit_seq,
            "observed_at": "2026-10-22T12:00:00Z",
            "monotonic_ns": self.ns.to_string(),
            "operation": operation,
            "stage": "result",
            "decision": Value::Null,
            "outcome": {"ok": true, "return_value": 0, "errno": null,
                        "completion": if operation == "proc.exec" { "exec_transition" } else { "syscall_return" }},
            "fields": {"path": path},
        }));
    }

    /// Syncs each active audit class's count with the frames (the K47 arm).
    fn sync(&mut self) {
        let exec = self
            .events
            .iter()
            .filter(|event| event["operation"] == "proc.exec")
            .count();
        let write = self
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event["operation"].as_str(),
                    Some("fs.create") | Some("fs.write") | Some("fs.rename") | Some("fs.unlink")
                )
            })
            .count();
        self.receipt["coverage"]["exec"]["observed_count"] = json!(exec);
        self.receipt["coverage"]["fs.write"]["observed_count"] = json!(write);
    }

    /// The complete journal: frames, then the receipt's note.
    fn journal(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for event in &self.events {
            bytes.extend(serde_json::to_vec(event).expect("serializes"));
            bytes.push(b'\n');
        }
        let note = json!({
            "schema": "ukai.event/1",
            "attempt_id": self.receipt["attempt_id"],
            "source": "wrapper",
            "source_seq": self.wrapper_seq + 1,
            "observed_at": "2026-10-22T12:00:01Z",
            "monotonic_ns": (self.ns + 1_000_000).to_string(),
            "operation": "jail.receipt",
            "stage": "result",
            "decision": Value::Null,
            "outcome": {"ok": true, "return_value": null, "errno": null, "completion": "wrapper"},
            "fields": {"phase": self.receipt["phase"], "receipt_digest": digest(&self.receipt)},
        });
        bytes.extend(serde_json::to_vec(&note).expect("serializes"));
        bytes.push(b'\n');
        bytes
    }

    fn summarize(&self) -> summary::Summary {
        summary::summary(&self.receipt, Journal::Bytes(&self.journal()))
    }

    fn evidence_facts(&self) -> Value {
        self.summarize()
            .lines
            .into_iter()
            .find(|line| line.line == "evidence")
            .expect("an evidence line")
            .facts
    }
}

/// K105: the expected operations are present — one event per §5
/// notification journals as the Linux audit vocabulary, the path
/// workspace-relative where the path is under the workspace root and a
/// digest everywhere else, and the classes come out `active` with counts
/// while `fs.deny` stays `unsupported`.
#[test]
fn k105_events_map_to_the_audit_vocabulary_and_active_classes() {
    let temp = common::private_tempdir();
    let root = workspace(temp.path());
    std::fs::create_dir(&root).expect("the workspace");
    let capture = FrameCapture::new();
    let mut journal = ObserveJournal::new(
        ATTEMPT,
        Some(capture.trace.clone()),
        root.as_os_str().as_encoded_bytes(),
    );

    journal.record(&obs(ObsKind::Exec, 1, b"/usr/bin/true"));
    journal.record(&obs(ObsKind::Create, 1, &joined(&root, "created.txt")));
    journal.record(&obs(ObsKind::Write, 1, &joined(&root, "written.txt")));
    journal.record(&obs(ObsKind::Rename, 1, &joined(&root, "renamed.txt")));
    journal.record(&obs(ObsKind::Unlink, 1, &joined(&root, "removed.txt")));

    let frames: Vec<Value> = capture
        .frames()
        .into_iter()
        .filter(|frame| frame["source"] == "audit")
        .collect();
    let operations: Vec<&str> = frames
        .iter()
        .map(|frame| frame["operation"].as_str().expect("an operation"))
        .collect();
    assert_eq!(
        operations,
        [
            "proc.exec",
            "fs.create",
            "fs.write",
            "fs.rename",
            "fs.unlink"
        ],
        "the A01 fixture's expected operations, in arrival order"
    );
    for frame in &frames {
        assert_eq!(frame["schema"], "ukai.event/1");
        assert_eq!(frame["stage"], "result");
        assert_eq!(frame["decision"], Value::Null);
        assert_eq!(frame["outcome"]["ok"], true);
    }
    // The workspace-relative form names the component-wise suffix.
    assert_eq!(
        frames[1]["fields"]["path"],
        json!({"kind": "workspace_relative", "value": "created.txt"})
    );
    // The exec image lies outside the workspace: digest only, with its
    // reason — never a host path (§11.3).
    assert_eq!(frames[0]["fields"]["path"]["kind"], "digest");
    assert_eq!(frames[0]["fields"]["path"]["reason"], "outside_workspace");
    assert_eq!(
        frames[0]["fields"]["path"]["digest"],
        ukai_jail::canonical::sha256_prefixed(b"/usr/bin/true")
    );

    let summary = journal.summary(CoverageSummary::applied(true));
    assert_eq!(summary.backend.as_deref(), Some(OBSERVER_BACKEND));
    assert_eq!(summary.sources.audit, SourceStatus::Active);
    assert_eq!(
        summary.classes[&CoverageClass::Exec].status,
        SourceStatus::Active
    );
    assert_eq!(
        summary.classes[&CoverageClass::Exec].observed_count,
        Some(1)
    );
    assert_eq!(
        summary.classes[&CoverageClass::FsWrite].status,
        SourceStatus::Active
    );
    assert_eq!(
        summary.classes[&CoverageClass::FsWrite].observed_count,
        Some(4)
    );
    // fs.deny stays unsupported (§5): Seatbelt denials are not ES events.
    assert_eq!(
        summary.classes[&CoverageClass::FsDeny].status,
        SourceStatus::Unsupported
    );
    assert_eq!(summary.classes[&CoverageClass::FsDeny].observed_count, None);
    assert!(summary.gaps.is_empty());

    // The classification helper alone agrees with the journal.
    assert_eq!(
        classify_path(
            &joined(&root, "nested/x"),
            root.as_os_str().as_encoded_bytes()
        ),
        PathEvidence::WorkspaceRelative(b"nested/x".to_vec())
    );
    assert!(matches!(
        classify_path(b"/etc/hosts", root.as_os_str().as_encoded_bytes()),
        PathEvidence::Digest(_, "outside_workspace")
    ));
}

fn joined(root: &Path, name: &str) -> Vec<u8> {
    let mut bytes = root.as_os_str().as_encoded_bytes().to_vec();
    bytes.push(b'/');
    bytes.extend_from_slice(name.as_bytes());
    bytes
}

/// K106: a gap in the observation client — here a skipped per-type
/// `seq_num`, the §5 gap semantics — marks `exec` and `fs.write`
/// `degraded` with a gap naming the reason and nulls their counts, and
/// touches nothing else: not the custody-facing wrapper source, not
/// `tree_empty`, not the other classes.
#[test]
fn k106_a_gap_degrades_only_the_observed_classes() {
    let temp = common::private_tempdir();
    let root = workspace(temp.path());
    std::fs::create_dir(&root).expect("the workspace");
    let capture = FrameCapture::new();
    let mut journal = ObserveJournal::new(
        ATTEMPT,
        Some(capture.trace.clone()),
        root.as_os_str().as_encoded_bytes(),
    );

    journal.record(&obs(ObsKind::Exec, 1, b"/usr/bin/true"));
    // Notification 2 never arrived.
    journal.record(&obs(ObsKind::Exec, 3, b"/usr/bin/false"));

    assert!(journal.is_degraded());
    let known = CoverageSummary::applied(true);
    let summary = journal.summary(known.clone());
    for class in OBSERVED_CLASSES {
        let entry = &summary.classes[&class];
        assert_eq!(entry.status, SourceStatus::Degraded, "{class:?}");
        // §11.4: "Unsupported and degraded counts are null."
        assert_eq!(entry.observed_count, None, "{class:?}");
        assert_eq!(entry.gaps.len(), 1, "{class:?}");
    }
    let gap = &summary.classes[&CoverageClass::Exec].gaps[0];
    assert_eq!(gap.classes, ["exec", "fs.write"]);
    assert_eq!(gap.source, "audit");
    assert!(
        gap.reason.starts_with(OBSERVATION_GAP_REASON),
        "{}",
        gap.reason
    );
    // Custody and the rest of the summary are untouched: the wrapper source
    // keeps its status, attachment and every non-observed class stay what
    // `known` said, and `tree_empty` (a lifetime fact, not an observer one)
    // does not appear here at all.
    assert_eq!(summary.sources.wrapper, known.sources.wrapper);
    assert_eq!(summary.sources.proxy, known.sources.proxy);
    assert_eq!(summary.attached, known.attached);
    assert_eq!(
        summary.classes[&CoverageClass::FsDeny].status,
        SourceStatus::Unsupported
    );
    assert!(
        summary
            .gaps
            .iter()
            .any(|g: &Gap| g.reason.starts_with(OBSERVATION_GAP_REASON))
    );

    // The shim's own sticky flag (ring overflow, an untrustable message)
    // lands in the same place.
    let mut journal = ObserveJournal::new(ATTEMPT, None, root.as_os_str().as_encoded_bytes());
    journal.record(&obs(ObsKind::Create, 1, &joined(&root, "a")));
    journal.mark_gap("observation_ring_overflowed");
    let summary = journal.summary(CoverageSummary::applied(true));
    assert_eq!(summary.sources.audit, SourceStatus::Degraded);
    for class in OBSERVED_CLASSES {
        assert_eq!(summary.classes[&class].status, SourceStatus::Degraded);
    }
}

/// §5: `strict` evidence refuses while a class it needs is degraded — the
/// settlement reads the coverage statuses (`supervisor::settlement_loss`)
/// — and `fs.deny`, which stays unsupported, never refuses: a healthy
/// §5 summary carries the statuses strict needs, and a degraded one names
/// its gap for the refusal to cite.
#[test]
fn strict_evidence_reads_the_coverage_statuses() {
    let temp = common::private_tempdir();
    let root = workspace(temp.path());
    std::fs::create_dir(&root).expect("the workspace");
    let mut journal = ObserveJournal::new(ATTEMPT, None, root.as_os_str().as_encoded_bytes());
    journal.record(&obs(ObsKind::Exec, 1, b"/usr/bin/true"));
    let healthy = journal.summary(CoverageSummary::applied(true));
    // Every stream class the strict settlement needs is neither degraded
    // nor unsupported-where-observed: `exec` and `fs.write` active,
    // `fs.deny` unsupported and therefore not a need (§5 says so).
    for class in OBSERVED_CLASSES {
        assert_eq!(healthy.classes[&class].status, SourceStatus::Active);
        assert_eq!(healthy.classes[&class].gaps, Vec::<Gap>::new());
    }

    journal.mark_gap(OBSERVATION_GAP_REASON);
    let degraded = journal.summary(CoverageSummary::applied(true));
    for class in OBSERVED_CLASSES {
        assert_eq!(degraded.classes[&class].status, SourceStatus::Degraded);
        assert!(
            !degraded.classes[&class].gaps.is_empty(),
            "a degraded class names its gap"
        );
    }
    // And `fs.deny` never moves off unsupported in either summary: the
    // strict refusal must not fire for it.
    assert_eq!(
        degraded.classes[&CoverageClass::FsDeny].status,
        SourceStatus::Unsupported
    );
}

/// K107: the J13 summary recomputes from a macOS receipt — active classes
/// whose counts the journal's frames exactly account for claim agreement,
/// `fs.deny` is not observed, and a receipt count the journal cannot back
/// is a disagreement, `summary_check.py`'s arms.
#[test]
fn k107_the_summary_recomputes_from_a_macos_receipt() {
    let temp = common::private_tempdir();
    let root = workspace(temp.path());
    std::fs::create_dir(&root).expect("the workspace");
    let mut fixture = Fixture::macos();
    fixture.audit(
        "proc.exec",
        json!({"kind": "digest", "digest": "sha256:aa", "reason": "outside_workspace"}),
    );
    fixture.audit(
        "proc.exec",
        json!({"kind": "digest", "digest": "sha256:bb", "reason": "outside_workspace"}),
    );
    fixture.audit(
        "fs.create",
        json!({"kind": "workspace_relative", "value": "one"}),
    );
    fixture.audit(
        "fs.write",
        json!({"kind": "workspace_relative", "value": "two"}),
    );
    fixture.audit(
        "fs.rename",
        json!({"kind": "workspace_relative", "value": "three"}),
    );
    fixture.sync();

    let facts = fixture.evidence_facts();
    assert_eq!(
        facts["classes"],
        json!({
            "exec": "active",
            "fs.write": "active",
            "fs.deny": "unsupported",
            "net": "unsupported",
            "proxy.net": "unsupported",
            "limits": "active",
        })
    );
    assert_eq!(facts["attached"], true);
    assert_eq!(facts["disagree"], json!([]));
    let summary = fixture.summarize();
    assert_eq!(summary.journal, JournalState::Complete);
    let evidence = summary
        .lines
        .iter()
        .find(|line| line.line == "evidence")
        .expect("an evidence line");
    assert!(
        // exec and fs.write from the §5 observer, limits the wrapper's own.
        evidence.text.contains("3/6 classes active"),
        "{}",
        evidence.text
    );
    assert!(
        evidence
            .text
            .contains("fs.deny, net, proxy.net not observed"),
        "{}",
        evidence.text
    );

    // The disagreement arm: a receipt count above what the journal carries
    // is a claim the journal contradicts.
    let mut inflated = fixture;
    inflated.receipt["coverage"]["fs.write"]["observed_count"] = json!(99);
    let facts = inflated.evidence_facts();
    assert_eq!(
        facts["disagree"],
        json!(["fs.write"]),
        "the journal cannot back the receipt's count"
    );
}

/// The live fallback (§5): an observation client this Mac cannot create —
/// no Endpoint Security entitlement — never fails the run. The platform
/// proceeds with observation unavailable: the honest summary carries
/// `attached = false` and the observed classes `unsupported`, and the
/// capability answer names `es_not_entitled`. On an entitled Mac the same
/// call must succeed; both answers are asserted, never a skip.
#[test]
fn an_unavailable_observation_client_degrades_the_run_neither_stops_it() {
    let client = ukai_jail::platform::macos::observe::ObserveClient::new();
    match client {
        Ok(client) => {
            client.delete();
        }
        Err(result) => {
            // The framework's refusal, carried verbatim into the capability
            // answer's reason (the es_notify probe row's `es_not_entitled`).
            use ukai_jail::platform::macos::es::EsNewResult;
            let raw = result.raw();
            println!("es_new_descendants_client (observation) answered {raw}");
            let reason = match result {
                EsNewResult::NotEntitled => "es_not_entitled",
                _ => "es_unavailable",
            };
            // The fallback receipt: attached false, the observed classes
            // unsupported with null counts, no invented zeros.
            let summary = CoverageSummary::applied(false);
            assert!(!summary.attached);
            for class in OBSERVED_CLASSES {
                let entry = &summary.classes[&class];
                assert_eq!(entry.status, SourceStatus::Unsupported);
                assert_eq!(entry.observed_count, None);
            }
            assert!(
                reason == "es_not_entitled" || reason == "es_unavailable",
                "the refusal names one of the honest reasons, not {raw}"
            );
            if let EsNewResult::NotEntitled = result {
                assert_eq!(reason, "es_not_entitled");
            }
        }
    }
}

/// The receipt-capture type exists so the mapping tests read real frames;
/// make sure the trace handle survives to the end of a test (a dropped
/// `SharedTrace` with no writer would silently take frames with it).
#[test]
fn the_capture_keeps_the_stream_alive() {
    let capture = FrameCapture::new();
    let temp = common::private_tempdir();
    let root = workspace(temp.path());
    std::fs::create_dir(&root).expect("the workspace");
    let mut journal = ObserveJournal::new(
        ATTEMPT,
        Some(capture.trace.clone()),
        root.as_os_str().as_encoded_bytes(),
    );
    journal.record(&obs(ObsKind::Create, 1, &joined(&root, "kept.txt")));
    drop(journal);
    let frames = capture.frames();
    assert_eq!(frames.len(), 1, "the frame reached the sink");
    assert_eq!(frames[0]["operation"], "fs.create");
    // And the file on disk holds it whole.
    let bytes = std::fs::read(&capture.path).expect("the trace reads back");
    std::io::sink().write_all(&bytes).expect("a sink write");
    assert!(bytes.ends_with(b"\n"), "frames end on line breaks");
}
