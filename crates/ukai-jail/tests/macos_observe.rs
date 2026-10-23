//! Synthetic J17 mapping, shim, loss and frozen-contract checks. No live ES
//! conformance claim; an unsigned executable must refuse client creation.
#![cfg(target_os = "macos")]
mod common;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use ukai_jail::observer::{CoverageClass, CoverageSummary};
use ukai_jail::platform::macos::observe::{
    OBSERVATION_GAP_REASON, OBSERVATION_SET, OBSERVED_CLASSES, ObsAction, ObsEvent, ObsKind,
    ObsMessage, ObserveJournal, ObserveRun, ObserveStartError, PathEvidence, classify_path,
};
use ukai_jail::records::{Event, Phase, SourceStatus};
use ukai_jail::summary::{self, Journal, JournalState};
use ukai_jail::trace::{self, FileSink, Priority, SharedTrace};
const ATTEMPT: &str = "att_00000000-0000-4000-8000-000000000001";
fn obs(kind: ObsKind, seq: u64, path: &[u8]) -> ObsEvent {
    ObsEvent {
        kind,
        global_seq: seq,
        seq,
        token: [7; 8],
        path: path.into(),
    }
}
fn message(
    action: ObsAction,
    event_type: u32,
    seq: u64,
    global_seq: u64,
    path: &[u8],
    path2: Option<&[u8]>,
) -> ObsMessage {
    let mut event = obs(action.kind(), seq, path);
    event.global_seq = global_seq;
    ObsMessage {
        event,
        event_type,
        action,
        path2: path2.map(Vec::from),
        ignored: false,
    }
}
struct FrameCapture {
    trace: SharedTrace,
    path: PathBuf,
    _dir: tempfile::TempDir,
}
impl FrameCapture {
    fn new() -> Self {
        let dir = common::private_tempdir();
        let path = dir.path().join("trace.ndjson");
        let trace = trace::shared(FileSink::new(std::fs::File::create(&path).unwrap()));
        Self {
            trace,
            path,
            _dir: dir,
        }
    }
    fn journal(&self) -> ObserveJournal {
        ObserveJournal::new(ATTEMPT, Some(self.trace.clone()), b"/w")
    }
    fn frames(&self) -> Vec<Value> {
        std::fs::read(&self.path)
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }
    fn audit(&self) -> Vec<Value> {
        self.frames()
            .into_iter()
            .filter(|frame| frame["source"] == "audit")
            .collect()
    }
}
fn coverage(journal: &ObserveJournal) -> CoverageSummary {
    journal.summary(CoverageSummary::applied(true))
}
fn specs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/jail-v1")
}
fn cross_check(receipt: &Value, capture: &FrameCapture) -> summary::Summary {
    let dir = common::private_tempdir();
    let attempt = dir.path().join(ATTEMPT);
    std::fs::create_dir(&attempt).unwrap();
    std::fs::write(
        attempt.join("jail.json"),
        serde_json::to_vec(receipt).unwrap(),
    )
    .unwrap();
    let bytes = std::fs::read(&capture.path).unwrap();
    std::fs::write(attempt.join("trace.ndjson"), &bytes).unwrap();
    let summary = summary::summary(receipt, Journal::Bytes(&bytes));
    let output_path = dir.path().join("summary.json");
    std::fs::write(
        &output_path,
        serde_json::to_vec(&summary.to_json()).unwrap(),
    )
    .unwrap();
    let result = Command::new(common::PYTHON)
        .arg("-I")
        .arg(specs().join("summary_check.py"))
        .arg(&attempt)
        .arg(&output_path)
        .output()
        .expect("Python is required for this cross-check");
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(common::validators()["jail-summary"].is_valid(&summary.to_json()));
    summary
}
fn receipt_for(journal: &ObserveJournal) -> Value {
    let mut receipt: Value = serde_json::from_slice(
        &std::fs::read(specs().join("examples/receipt-macos-native.json")).unwrap(),
    )
    .unwrap();
    receipt["attempt_id"] = ATTEMPT.into();
    receipt["policy"]["observe"] = "on".into();
    receipt["observer"] = serde_json::to_value(coverage(journal).to_observer_record()).unwrap();
    receipt["coverage"] = serde_json::to_value(coverage(journal).to_coverage()).unwrap();
    receipt
}
fn settle(receipt: &Value, capture: &FrameCapture) {
    let digest =
        ukai_jail::canonical::sha256_prefixed(&ukai_jail::canonical::to_jcs(receipt).unwrap());
    let event = Event::receipt_note(
        ATTEMPT,
        0,
        std::time::SystemTime::now(),
        ukai_jail::platform::elapsed_since_start_ns(),
        Phase::Settled,
        &digest,
    );
    capture
        .trace
        .lock()
        .unwrap()
        .write_event(&event, Priority::Reserve)
        .unwrap();
}

#[test]
fn phase_one_observation_is_off_until_a_run_attaches_it() {
    use ukai_jail::policy::ProfileName;
    use ukai_jail::records::{ObserveMode, Os};
    assert_eq!(
        ukai_jail::profiles::baseline(ProfileName::Tool, Os::Macos, &|_| None)
            .observation
            .mode,
        ObserveMode::Off
    );
    assert_eq!(
        ukai_jail::profiles::baseline(ProfileName::Tool, Os::Linux, &|_| None)
            .observation
            .mode,
        ObserveMode::On
    );
    let dir = common::private_tempdir();
    let output = Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir.path())
        .env("UKAI_CONFIG_DIR", dir.path().join("config"))
        .env("UKAI_DATA_DIR", dir.path().join("data"))
        .current_dir(dir.path())
        .args(["explain", "--json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).expect("explain JSON");
    assert_eq!(report["policy"]["snapshot"]["observation"]["mode"], "off");
    use ukai_jail::platform::{PlanRequest, Platform};
    let plan = PlanRequest {
        snapshot: ukai_jail::policy::resolve(&ukai_jail::policy::ResolveInputs {
            platform: Os::Macos,
            base_profile: ProfileName::Tool,
            policy_name: "tool".into(),
            baseline: ukai_jail::profiles::baseline(ProfileName::Tool, Os::Macos, &|_| None),
            workspace: dir.path().as_os_str().as_encoded_bytes().to_vec(),
            scratch: ukai_jail::policy::ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        })
        .unwrap()
        .snapshot,
        requirements: vec![ukai_jail::capability::Requirement::ClosedSetObservation],
    };
    let capabilities = ukai_jail::platform::macos::MacosPlatform.probe(&plan);
    let row = capabilities
        .iter()
        .find(|row| row.name == "closed_set_observation")
        .unwrap();
    assert_eq!(
        row.status,
        ukai_jail::capability::CapabilityStatus::Unsupported
    );
}

#[test]
fn k105_events_map_to_schema_valid_audit_results_with_honest_coverage() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    for (i, action) in [
        ObsAction::Exec,
        ObsAction::Create,
        ObsAction::Modified,
        ObsAction::Rename,
        ObsAction::Unlink,
        ObsAction::Truncate,
        ObsAction::Setmode,
        ObsAction::Setattrlist,
        ObsAction::Link,
        ObsAction::CreateDenied,
    ]
    .into_iter()
    .enumerate()
    {
        journal.record_message(&message(
            action,
            i as u32,
            0,
            i as u64,
            b"/w/source",
            Some(b"/w/dest"),
        ));
    }
    let frames = capture.audit();
    assert_eq!(frames.len(), 10);
    let ops: Vec<_> = frames
        .iter()
        .map(|f| f["operation"].as_str().unwrap())
        .collect();
    assert_eq!(
        ops,
        [
            "proc.exec",
            "fs.create",
            "fs.write",
            "fs.rename",
            "fs.unlink",
            "fs.write",
            "fs.write",
            "fs.write",
            "fs.create",
            "fs.create"
        ]
    );
    assert_eq!(
        frames[0]["fields"]["path"],
        json!({"kind":"unavailable", "reason":"argument_not_read"})
    );
    assert_eq!(frames[0]["fields"]["executable"]["value"], "source");
    assert_eq!(frames[0]["fields"]["pid"], 7);
    assert_eq!(frames[0]["fields"]["pid_start_ticks"], Value::Null);
    assert_eq!(frames[3]["fields"]["path"]["value"], "source");
    assert_eq!(frames[3]["fields"]["path2"]["value"], "dest");
    assert_eq!(frames[2]["fields"]["action"], "modified");
    assert_eq!(frames[5]["fields"]["action"], "truncated");
    assert_eq!(frames[6]["fields"]["action"], "metadata_changed");
    assert_eq!(frames[8]["fields"]["action"], "hard_link_created");
    assert_eq!(frames[9]["outcome"]["ok"], false);
    common::check_trace(&capture.frames(), None).expect("real journal frames meet frozen schemas");
    let summary = coverage(&journal);
    assert_eq!(summary.set.as_deref(), Some(OBSERVATION_SET));
    assert_eq!(
        summary.classes[&CoverageClass::Exec].observed_count,
        Some(1)
    );
    assert_eq!(journal.count(CoverageClass::FsWrite), 9);
    assert_eq!(
        summary.classes[&CoverageClass::FsWrite].status,
        SourceStatus::Degraded
    );
    assert_eq!(
        summary.classes[&CoverageClass::FsDeny].status,
        SourceStatus::Unsupported
    );
}

#[test]
fn observation_frames_validate_against_the_frozen_jail_event_schema() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    for (index, kind) in [
        ObsKind::Exec,
        ObsKind::Create,
        ObsKind::Write,
        ObsKind::Rename,
        ObsKind::Unlink,
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = obs(kind, 0, b"/w/file");
        event.global_seq = index as u64;
        journal.record(&event);
    }
    common::check_trace(&capture.frames(), None).unwrap();
}

#[test]
fn r3_ring_and_sequence_loss_are_not_counted_twice() {
    for ring_first in [false, true] {
        let capture = FrameCapture::new();
        let mut journal = capture.journal();
        journal.record(&obs(ObsKind::Exec, 0, b"/bin/true"));
        if ring_first {
            journal.record_shim_loss(5, false);
        }
        journal.record(&obs(ObsKind::Exec, 6, b"/bin/true"));
        journal.record_shim_loss(5, false);
        let gaps = &coverage(&journal).classes[&CoverageClass::Exec].gaps;
        assert_eq!(gaps.iter().filter_map(|gap| gap.lost_count).sum::<u64>(), 5);
        assert_eq!(
            gaps.iter()
                .find(|gap| gap.reason.contains("sequence_discontinuity"))
                .unwrap()
                .lost_count,
            None
        );
        // Later ring-only loss remains known even without a following event.
        journal.record_shim_loss(8, false);
        let gaps = &coverage(&journal).classes[&CoverageClass::Exec].gaps;
        assert_eq!(gaps.iter().filter_map(|gap| gap.lost_count).sum::<u64>(), 8);
        common::check_trace(&capture.frames(), None).unwrap();
    }
}

#[test]
fn r3_sequences_accept_zero_or_one_and_disclose_the_start_residual() {
    for first in [0, 1] {
        let capture = FrameCapture::new();
        let mut journal = capture.journal();
        // Disclose the uncertainty even if the run delivers no audit frames.
        assert!(
            capture
                .frames()
                .iter()
                .any(|frame| frame["fields"]["sequence_start"] == "unverified")
        );
        for (action, event_type, seq, global) in [
            (ObsAction::Exec, 1, first, first),
            (ObsAction::Modified, 2, first, first + 1),
            (ObsAction::Exec, 1, first + 1, first + 2),
        ] {
            journal.record_message(&message(action, event_type, seq, global, b"/w/a", None));
        }
        assert_eq!(
            coverage(&journal).classes[&CoverageClass::Exec].status,
            SourceStatus::Active
        );
        assert!(
            capture
                .audit()
                .iter()
                .all(|frame| frame["fields"]["sequence_start"] == "unverified")
        );
        common::check_trace(&capture.frames(), None).unwrap();
    }
}

#[test]
fn r3_one_based_sequences_are_contiguous() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    journal.record_message(&message(ObsAction::Exec, 1, 1, 1, b"/bin/tool", None));
    journal.record_message(&message(ObsAction::Modified, 2, 1, 2, b"/w/a", None));
    journal.record_message(&message(ObsAction::Exec, 1, 2, 3, b"/bin/tool", None));
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Active
    );
}

#[test]
fn r3_first_sequence_above_one_has_unknown_loss() {
    for (seq, global) in [(2, 0), (0, 2), (4, 4)] {
        let capture = FrameCapture::new();
        let mut journal = capture.journal();
        journal.record_message(&message(
            ObsAction::Exec,
            1,
            seq,
            global,
            b"/bin/tool",
            None,
        ));
        let class = &coverage(&journal).classes[&CoverageClass::Exec];
        assert_eq!(class.status, SourceStatus::Degraded);
        assert_eq!(class.gaps.len(), 1);
        assert_eq!(class.gaps[0].lost_count, None);
    }
}

#[test]
fn first_and_global_sequence_loss_are_detected() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    journal.record(&obs(ObsKind::Exec, 4, b"/bin/true"));
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Degraded
    );
    assert_eq!(
        journal
            .gaps()
            .iter()
            .find(|g| g.reason.starts_with(OBSERVATION_GAP_REASON))
            .unwrap()
            .lost_count,
        None
    );
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    journal.record(&obs(ObsKind::Exec, 0, b"/bin/true"));
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Active
    );
    let mut second = obs(ObsKind::Create, 0, b"/w/a");
    second.global_seq = 2;
    journal.record(&second);
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Degraded
    );
}

#[test]
fn sequence_buckets_are_real_types_and_include_unmodified_closes() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    journal.record_message(&message(ObsAction::Modified, 10, 0, 0, b"/w/a", None));
    journal.record_message(&message(ObsAction::Setmode, 20, 0, 1, b"/w/a", None));
    journal.record_message(&message(
        ObsAction::CloseUnmodified,
        10,
        1,
        2,
        b"/w/a",
        None,
    ));
    journal.record_message(&message(ObsAction::Modified, 10, 2, 3, b"/w/a", None));
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Active
    );
    assert_eq!(journal.count(CoverageClass::FsWrite), 3);
    assert_eq!(capture.audit().len(), 3);
    // SETMODE cannot hide a skipped CLOSE, even with continuous global input.
    journal.record_message(&message(ObsAction::Setmode, 20, 1, 4, b"/w/a", None));
    journal.record_message(&message(ObsAction::Modified, 10, 4, 5, b"/w/a", None));
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Degraded
    );
}

#[test]
fn k106_a_gap_degrades_only_the_observed_classes() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    journal.record(&obs(ObsKind::Exec, 0, b"/bin/true"));
    journal.record(&obs(ObsKind::Exec, 2, b"/bin/true"));
    let known = CoverageSummary::applied(true);
    let result = journal.summary(known.clone());
    for class in OBSERVED_CLASSES {
        assert_eq!(result.classes[&class].status, SourceStatus::Degraded);
        assert_eq!(result.classes[&class].observed_count, None);
    }
    for class in [
        CoverageClass::FsDeny,
        CoverageClass::Net,
        CoverageClass::ProxyNet,
        CoverageClass::Limits,
    ] {
        assert_eq!(result.classes[&class], known.classes[&class]);
    }
    assert_eq!(result.sources.wrapper, known.sources.wrapper);
    assert_eq!(result.sources.proxy, known.sources.proxy);
    assert_eq!(result.attached, known.attached);
    common::check_trace(&capture.frames(), None).unwrap();
}

#[test]
fn gap_notes_and_loss_counts_are_coalesced() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    for seq in (0..2000).step_by(2) {
        journal.record(&obs(ObsKind::Exec, seq, b"/bin/true"));
    }
    let gaps: Vec<_> = journal
        .gaps()
        .iter()
        .filter(|gap| gap.classes.iter().any(|c| c == "exec"))
        .collect();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].lost_count, Some(999));
    let notes: Vec<_> = capture
        .frames()
        .into_iter()
        .filter(|f| {
            f["fields"]["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with(OBSERVATION_GAP_REASON))
        })
        .collect();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["fields"]["kind"], "coverage_gap");
    journal.record_shim_loss(7, false);
    journal.record_shim_loss(12, false);
    assert_eq!(
        journal
            .gaps()
            .iter()
            .find(|g| g.reason == "observation_ring_overflowed")
            .unwrap()
            .lost_count,
        Some(12)
    );
    common::check_trace(&capture.frames(), None).unwrap();
}

#[test]
fn relative_and_missing_paths_are_not_claimed_outside() {
    for path in [b"renamed.txt".as_slice(), b""] {
        assert_ne!(
            classify_path(path, b"/w").into_json()["reason"],
            "outside_workspace"
        );
    }
    assert_eq!(
        classify_path(b"", b"/w"),
        PathEvidence::Unavailable("path_not_available")
    );
    assert_eq!(
        classify_path(b"/w/../outside", b"/w").into_json()["reason"],
        "path_basis_unknown"
    );
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    journal.record(&obs(ObsKind::Write, 0, b""));
    assert_eq!(capture.audit()[0]["fields"]["path_complete"], false);
    common::check_trace(&capture.frames(), None).unwrap();
}
#[test]
fn path_prefixes_are_component_wise() {
    assert_eq!(
        classify_path(b"/w/ab", b"/w/a").into_json()["reason"],
        "outside_workspace"
    );
    assert_eq!(
        classify_path(b"/w/a/b", b"/w/a/"),
        PathEvidence::WorkspaceRelative(b"b".to_vec())
    );
    assert_eq!(
        classify_path(b"/x", b"/"),
        PathEvidence::WorkspaceRelative(b"x".to_vec())
    );
    assert_eq!(
        classify_path(b"/w/a \n/file", b"/w/a \n"),
        PathEvidence::WorkspaceRelative(b"file".to_vec())
    );
}
#[test]
fn incomplete_mutation_subscription_cannot_claim_active_fs_write() {
    let capture = FrameCapture::new();
    let journal = capture.journal();
    let summary = coverage(&journal);
    let write = &summary.classes[&CoverageClass::FsWrite];
    assert_eq!(write.status, SourceStatus::Degraded);
    assert_eq!(write.observed_count, None);
    assert!(
        write
            .gaps
            .iter()
            .any(|g| g.reason.contains("uncovered_mutations") && g.reason.contains("mmap"))
    );
    assert_eq!(
        summary.classes[&CoverageClass::Exec].status,
        SourceStatus::Active
    );
}
#[test]
fn refused_and_poisoned_trace_frames_are_not_counted() {
    let dir = common::private_tempdir();
    let file = std::fs::File::create(dir.path().join("trace")).unwrap();
    let trace = trace::shared(FileSink::with_bounds(file, 16384, 16384));
    let mut journal = ObserveJournal::new(ATTEMPT, Some(trace.clone()), b"/w");
    journal.record(&obs(ObsKind::Exec, 0, b"/bin/true"));
    assert_eq!(journal.count(CoverageClass::Exec), 0);
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Degraded
    );
    assert!(
        journal
            .gaps()
            .iter()
            .any(|g| g.reason == "observation_trace_unavailable")
    );
    let _ = std::thread::spawn(move || {
        let _held = trace.lock().unwrap();
        panic!("deliberately poison trace");
    })
    .join();
    journal.record(&obs(ObsKind::Exec, 1, b"/bin/true"));
    assert_eq!(journal.count(CoverageClass::Exec), 0);
    assert!(
        journal
            .gaps()
            .iter()
            .any(|g| g.reason == "trace_writer_poisoned")
    );
}
#[test]
fn no_trace_means_no_delivered_frames() {
    let mut journal = ObserveJournal::new(ATTEMPT, None, b"/w");
    journal.record(&obs(ObsKind::Exec, 0, b"/bin/true"));
    assert_eq!(journal.count(CoverageClass::Exec), 0);
    assert_eq!(
        coverage(&journal).classes[&CoverageClass::Exec].status,
        SourceStatus::Degraded
    );
}

#[test]
fn k107_rust_and_python_recompute_real_native_journal_frames() {
    let capture = FrameCapture::new();
    let mut journal = capture.journal();
    let cases = [
        message(ObsAction::Exec, 1, 0, 0, b"/bin/true", None),
        message(ObsAction::Modified, 2, 0, 1, b"/w/modified", None),
        message(ObsAction::Setmode, 3, 0, 2, b"/w/mode", None),
        message(
            ObsAction::Rename,
            4,
            0,
            3,
            b"/w/leaving",
            Some(b"/outside/dest"),
        ),
        message(
            ObsAction::Link,
            5,
            0,
            4,
            b"/w/existing",
            Some(b"/w/new-link"),
        ),
        message(ObsAction::CreateDenied, 6, 0, 5, b"/w/denied", None),
        message(ObsAction::Create, 7, 0, 6, b"/w/created", None),
        message(ObsAction::Setmode, 3, 1, 7, b"/w", None),
        message(ObsAction::Modified, 2, 1, 8, b"/w/modified", None),
        message(ObsAction::Truncate, 8, 0, 9, b"/w/truncated", None),
    ];
    for event in &cases {
        journal.record_message(event);
    }
    let receipt = receipt_for(&journal);
    settle(&receipt, &capture);
    common::check_trace(&capture.frames(), Some(&receipt)).unwrap();
    let summary = cross_check(&receipt, &capture);
    assert_eq!(summary.journal, JournalState::Complete);
    let workspace = summary
        .lines
        .iter()
        .find(|l| l.line == "workspace")
        .unwrap();
    assert!(
        workspace
            .text
            .contains("at least 2 modified, at least 2 created, at least 1 with metadata changes"),
        "{}",
        workspace.text
    );
    assert!(workspace.text.contains("workspace root metadata changed"));
    assert_eq!(workspace.facts["opened_for_writing"], 0);
    assert_eq!(workspace.facts["renamed"], 1);
    let paths: Vec<_> = workspace.facts["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["value"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "",
            "created",
            "leaving",
            "mode",
            "modified",
            "new-link",
            "truncated"
        ]
    );
    let mut inflated = receipt;
    inflated["coverage"]["exec"]["observed_count"] = 99.into();
    let inflated_capture = FrameCapture::new();
    let mut inflated_journal = inflated_capture.journal();
    for event in &cases {
        inflated_journal.record_message(event);
    }
    settle(&inflated, &inflated_capture);
    let summary = cross_check(&inflated, &inflated_capture);
    assert_eq!(
        summary
            .lines
            .iter()
            .find(|l| l.line == "evidence")
            .unwrap()
            .facts["disagree"],
        json!(["exec"])
    );
}

#[test]
fn r3_summary_describes_root_changes_without_counting_workspace_entries() {
    for (action, expected) in [
        (
            ObsAction::Setmode,
            "workspace: workspace root metadata changed",
        ),
        (
            ObsAction::Modified,
            "workspace: workspace root content modified",
        ),
        (ObsAction::Create, "workspace: workspace root created"),
    ] {
        let capture = FrameCapture::new();
        let mut journal = capture.journal();
        journal.record_message(&message(action, 1, 0, 0, b"/w", None));
        let receipt = receipt_for(&journal);
        settle(&receipt, &capture);
        common::check_trace(&capture.frames(), Some(&receipt)).unwrap();
        let summary = cross_check(&receipt, &capture);
        let workspace = summary
            .lines
            .iter()
            .find(|line| line.line == "workspace")
            .unwrap();
        assert_eq!(workspace.text, expected);
        assert_eq!(workspace.facts["opened_for_writing"], 0);
    }
}

#[test]
fn an_unsigned_observe_run_refuses_not_entitled() {
    if cfg!(ukai_es_sdk_absent) {
        assert_observer_sdk_absent();
        return;
    }
    let signing = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    let info = format!(
        "{}{}",
        String::from_utf8_lossy(&signing.stdout),
        String::from_utf8_lossy(&signing.stderr)
    );
    assert!(
        !info.contains("com.apple.developer.endpoint-security.client"),
        "test requires an independently verified unentitled binary"
    );
    let capture = FrameCapture::new();
    let result = ObserveRun::start(ATTEMPT, capture.trace, b"/", &[[7; 8]]);
    assert!(
        matches!(
            result,
            Err(ObserveStartError::Client(
                ukai_jail::platform::macos::es::EsNewResult::NotEntitled
            ))
        ),
        "unsigned process must refuse, not silently degrade/start"
    );
}

fn assert_observer_sdk_absent() {
    use ukai_jail::platform::macos::{es::EsNewResult, observe::ObserveClient};
    assert!(matches!(ObserveClient::new(), Err(EsNewResult::SdkAbsent)));
    let capture = FrameCapture::new();
    let result = ObserveRun::start(ATTEMPT, capture.trace.clone(), b"/", &[[7; 8]]);
    let error = result.err().expect("SDK absence prevents observer startup");
    assert!(matches!(
        error,
        ObserveStartError::Client(EsNewResult::SdkAbsent)
    ));
    assert!(error.to_string().contains("es_sdk_absent"));
    assert!(capture.frames().is_empty(), "no observation stream started");
}

fn shim_case(name: &str) {
    if cfg!(ukai_es_sdk_absent) {
        assert_observer_sdk_absent();
        return;
    }
    static BINARY: std::sync::OnceLock<(tempfile::TempDir, PathBuf)> = std::sync::OnceLock::new();
    let (_, binary) = BINARY.get_or_init(|| {
        let dir = common::private_tempdir();
        let binary = dir.path().join("shim-synthetic");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/platform/macos/observe/synthetic.c");
        let output = Command::new("xcrun")
            .arg("clang")
            .args(["-std=c11", "-fblocks", "-Wall", "-Wextra", "-Werror"])
            .arg(source)
            .args(["-lEndpointSecurity", "-framework", "CoreFoundation", "-o"])
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        (dir, binary)
    });
    let output = Command::new(binary).arg(name).output().unwrap();
    assert!(
        output.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn shim_counts_unmodified_closes() {
    shim_case("close");
}
#[test]
fn shim_retains_real_types() {
    shim_case("types");
}
#[test]
fn shim_joins_directory_names_and_keeps_both_paths() {
    shim_case("paths");
}
#[test]
fn shim_marks_missing_paths_unknown() {
    shim_case("unknown");
}
#[test]
fn shim_rejects_truncated_paths() {
    shim_case("truncated");
}
#[test]
fn shim_counts_overflow_including_final_drops() {
    shim_case("overflow");
}
#[test]
fn shim_excludes_all_helpers_but_not_the_workload_exec() {
    shim_case("helpers");
}
#[test]
fn shim_a_late_sync_cannot_complete_the_next_drain() {
    shim_case("drain");
}
#[test]
fn shim_retains_callback_memory_when_delete_fails() {
    shim_case("delete");
}
