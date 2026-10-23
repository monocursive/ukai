//! Native ES notification evidence. This module does not provide custody.
//!
//! `macos-closed-v1` covers the declared ES notification subscription, not
//! every filesystem mutation. Out-of-set operations alone do not degrade it.
//! Loss of in-set evidence does; synthetic tests do not establish live ES proof.
#![cfg(target_os = "macos")]

use std::collections::{BTreeMap, BTreeSet};

use crate::observer::{ClassSummary, ClosedOperation, CoverageClass, CoverageSummary};
use crate::records::{Completion, Event, EventOutcome, Gap, SourceStatus};
use crate::trace::{Priority, SharedTrace};

#[cfg(not(ukai_es_sdk_absent))]
mod client;
#[cfg(ukai_es_sdk_absent)]
#[path = "observe/absent.rs"]
mod client;
mod run;
pub use client::ObserveClient;
#[cfg(test)]
pub(crate) use run::Source;
pub use run::{ObserveRun, ObserveStartError};

pub const OBSERVER_BACKEND: &str = "es_notify";
/// Identifies the subscription, not a claim of complete mutation coverage.
pub const OBSERVATION_SET: &str = "macos-closed-v1";
pub const OBSERVATION_GAP_REASON: &str = "observation_client_gap";
/// Exclusions describe the set, never a standing coverage gap.
pub const OUTSIDE_SET: &str = "individual write calls (NOTIFY_WRITE); cloud materialization and File Provider updates; mmap-only writes without a modified close or other subscribed notification; mutations without an attributable descendants notification (including autonomous OS/File Provider work); mount/remount/unmount and fcntl effects without a subscribed mutation notification; Seatbelt denials (fs.deny unsupported); native network activity (net unsupported; proxy.net is separate)";

/// Generated from the very rows included by the C subscription/mute check.
#[must_use]
pub fn closed_set_table() -> String {
    let mut table = format!(
        "ukai-jail observer closed set `{OBSERVATION_SET}` (macOS, es_notify backend)\nGenerated from observe/closed_set.def; jail-macos §5, jail-v1 §11.\n\nnotification | class | audit operation | meaning\n"
    );
    for line in include_str!("observe/closed_set.def").lines() {
        if let Some(row) = line
            .strip_prefix("UKAI_OBS_EVENT(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let columns: Vec<_> = row.split(", ").map(|s| s.trim_matches('"')).collect();
            table.push_str(&format!(
                "NOTIFY_{} | {} | {} | {}\n",
                columns[0], columns[1], columns[2], columns[3]
            ));
        }
    }
    table.push_str(&format!("\nOutside the set: {OUTSIDE_SET}.\nWrites are represented by modified CLOSE, including implicit closes at process exit.\nCounts are delivered notification results, not syscalls, bytes or content diffs.\nHelper tokens and unmodified CLOSE participate in sequencing but emit no audit result.\nNo live ES performance or completeness claim.\n"));
    table
}

pub const OBSERVED_CLASSES: [CoverageClass; 2] = [CoverageClass::Exec, CoverageClass::FsWrite];

/// Compatibility vocabulary. New producers use `ObsMessage` to retain the
/// real ES event type, action, and both paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObsKind {
    Exec,
    Create,
    Write,
    Rename,
    Unlink,
}

impl ObsKind {
    #[must_use]
    pub fn operation(self) -> ClosedOperation {
        match self {
            Self::Exec => ClosedOperation::ProcExec,
            Self::Create => ClosedOperation::FsCreate,
            Self::Write => ClosedOperation::FsWrite,
            Self::Rename => ClosedOperation::FsRename,
            Self::Unlink => ClosedOperation::FsUnlink,
        }
    }
}

/// Kept source-compatible for callers of the original journal API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObsEvent {
    pub kind: ObsKind,
    pub global_seq: u64,
    pub seq: u64,
    pub token: [u32; 8],
    /// The primary path; for rename/link this is the source.
    pub path: Vec<u8>,
}

/// Shim-internal action numbers; NOT ES sequence-number buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ObsAction {
    Exec = 1,
    Create = 2,
    Modified = 3,
    Rename = 4,
    Unlink = 5,
    Truncate = 6,
    Setattrlist = 7,
    Setmode = 8,
    Link = 9,
    CloseUnmodified = 10,
    CreateDenied = 11,
    Clone = 12,
    Copyfile = 13,
    Exchangedata = 14,
    Metadata = 15,
}

impl ObsAction {
    #[cfg(not(ukai_es_sdk_absent))]
    fn from_raw(value: i32) -> Option<Self> {
        Some(match value {
            1 => Self::Exec,
            2 => Self::Create,
            3 => Self::Modified,
            4 => Self::Rename,
            5 => Self::Unlink,
            6 => Self::Truncate,
            7 => Self::Setattrlist,
            8 => Self::Setmode,
            9 => Self::Link,
            10 => Self::CloseUnmodified,
            11 => Self::CreateDenied,
            12 => Self::Clone,
            13 => Self::Copyfile,
            14 => Self::Exchangedata,
            15 => Self::Metadata,
            _ => return None,
        })
    }

    pub fn kind(self) -> ObsKind {
        match self {
            Self::Exec => ObsKind::Exec,
            Self::Create | Self::Link | Self::CreateDenied | Self::Clone => ObsKind::Create,
            Self::Rename => ObsKind::Rename,
            Self::Unlink => ObsKind::Unlink,
            _ => ObsKind::Write,
        }
    }

    pub(super) fn has_two_paths(self) -> bool {
        matches!(
            self,
            Self::Rename | Self::Link | Self::Clone | Self::Copyfile | Self::Exchangedata
        )
    }

    fn name(self) -> &'static str {
        match self {
            Self::Exec => "exec_transition",
            Self::Create => "created",
            Self::Modified => "modified",
            Self::Rename => "renamed",
            Self::Unlink => "unlinked",
            Self::Truncate => "truncated",
            Self::Setattrlist | Self::Setmode | Self::Metadata => "metadata_changed",
            Self::Clone => "cloned",
            Self::Copyfile => "copied",
            Self::Exchangedata => "exchanged",
            Self::Link => "hard_link_created",
            Self::CloseUnmodified => "unmodified",
            Self::CreateDenied => "creation_denied",
        }
    }
}

/// A full shim message. `event_type` is the real ES type, whose sequence is
/// independent even when several types map to the same `fs.write` operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObsMessage {
    pub event: ObsEvent,
    pub event_type: u32,
    pub action: ObsAction,
    pub path2: Option<Vec<u8>>,
    /// Helper events and unmodified CLOSEs still participate in sequencing.
    pub ignored: bool,
}

impl From<&ObsEvent> for ObsMessage {
    fn from(event: &ObsEvent) -> Self {
        let action = match event.kind {
            ObsKind::Exec => ObsAction::Exec,
            ObsKind::Create => ObsAction::Create,
            ObsKind::Write => ObsAction::Modified,
            ObsKind::Rename => ObsAction::Rename,
            ObsKind::Unlink => ObsAction::Unlink,
        };
        Self {
            event: event.clone(),
            // Legacy synthetic records have no ES type. Keep their buckets
            // separate; a real client always supplies `es_message_t.event_type`.
            event_type: action as u32,
            action,
            path2: None,
            ignored: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathEvidence {
    WorkspaceRelative(Vec<u8>),
    Digest(String, &'static str),
    Unavailable(&'static str),
}

impl PathEvidence {
    #[must_use]
    pub fn into_json(self) -> serde_json::Value {
        match self {
            Self::WorkspaceRelative(bytes) => serde_json::json!({
                "kind": "workspace_relative",
                "value": crate::records::NativeString::from_bytes(bytes).expect("validated path bytes"),
            }),
            Self::Digest(digest, reason) => {
                serde_json::json!({"kind": "digest", "digest": digest, "reason": reason})
            }
            Self::Unavailable(reason) => {
                serde_json::json!({"kind": "unavailable", "reason": reason})
            }
        }
    }
}

fn strip_root<'a>(path: &'a [u8], root: &[u8]) -> Option<&'a [u8]> {
    let mut root = root;
    while root.len() > 1 && root.ends_with(b"/") {
        root = &root[..root.len() - 1];
    }
    if root == b"/" {
        return path.strip_prefix(b"/");
    }
    if root.is_empty() {
        return None;
    }
    if path == root {
        return Some(b"");
    }
    path.strip_prefix(root)?.strip_prefix(b"/")
}

/// ES paths must be complete absolute paths. Relative/missing paths do not
/// establish that they are outside the workspace. Do not resolve links by
/// touching the filesystem after the event (the namespace could have changed).
#[must_use]
pub fn classify_path(path: &[u8], workspace: &[u8]) -> PathEvidence {
    if path.is_empty() || path.contains(&0) {
        return PathEvidence::Unavailable("path_not_available");
    }
    if !workspace.starts_with(b"/")
        || workspace
            .split(|b| *b == b'/')
            .any(|part| part == b".." || part == b".")
        || !path.starts_with(b"/")
        || path
            .split(|b| *b == b'/')
            .any(|part| part == b".." || part == b".")
    {
        return PathEvidence::Digest(
            crate::canonical::sha256_prefixed(path),
            "path_basis_unknown",
        );
    }
    match strip_root(path, workspace) {
        Some(rest) if workspace.starts_with(b"/") => PathEvidence::WorkspaceRelative(rest.to_vec()),
        _ => PathEvidence::Digest(crate::canonical::sha256_prefixed(path), "outside_workspace"),
    }
}

/// One trace producer with bounded, coalesced gap categories.
pub struct ObserveJournal {
    attempt_id: String,
    trace: Option<SharedTrace>,
    workspace: Vec<u8>,
    seq: u64,
    counts: BTreeMap<CoverageClass, u64>,
    degraded: BTreeSet<CoverageClass>,
    gaps: Vec<Gap>,
    gap_indices: BTreeMap<&'static str, usize>,
    last_seq: BTreeMap<u32, u64>,
    last_global: Option<u64>,
    global_lost: u64,
    type_lost: u64,
    sequence_unknown: bool,
    ring_dropped: u64,
    created_ns: u128,
}

impl ObserveJournal {
    #[must_use]
    pub fn new(attempt_id: &str, trace: Option<SharedTrace>, workspace: &[u8]) -> Self {
        let mut journal = Self {
            attempt_id: attempt_id.to_owned(),
            trace,
            workspace: workspace.to_vec(),
            seq: 0,
            counts: BTreeMap::new(),
            degraded: BTreeSet::new(),
            gaps: Vec::new(),
            gap_indices: BTreeMap::new(),
            last_seq: BTreeMap::new(),
            last_global: None,
            global_lost: 0,
            type_lost: 0,
            sequence_unknown: false,
            ring_dropped: 0,
            created_ns: crate::platform::elapsed_since_start_ns(),
        };
        // A scope disclosure, not a coverage gap: even an empty stream states
        // the sequence-start residual and the declared set's exclusions.
        let mut note = Event::lifecycle_note(
            attempt_id,
            0,
            std::time::SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            "observation_scope",
        );
        note.fields
            .insert("sequence_start".into(), "unverified".into());
        note.fields
            .insert("observer_set".into(), OBSERVATION_SET.into());
        note.fields.insert("outside_set".into(), OUTSIDE_SET.into());
        journal.emit(&note);
        journal
    }

    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !self.degraded.is_empty()
    }
    #[must_use]
    pub fn count(&self, class: CoverageClass) -> u64 {
        self.counts.get(&class).copied().unwrap_or(0)
    }
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    pub fn record(&mut self, event: &ObsEvent) {
        self.record_message(&ObsMessage::from(event));
    }

    pub fn record_message(&mut self, message: &ObsMessage) {
        self.check_sequence(message);
        if message.ignored || message.action == ObsAction::CloseUnmodified {
            return;
        }
        let event = &message.event;
        let operation = message.action.kind().operation();
        let class = operation.coverage_class();
        let path = classify_path(&event.path, &self.workspace);
        let mut fields = serde_json::Map::new();
        let complete = !matches!(
            path,
            PathEvidence::Unavailable(_) | PathEvidence::Digest(_, "path_basis_unknown")
        );
        fields.insert("observation".into(), OBSERVER_BACKEND.into());
        // ES documents increments, not the first value. Continuity begins at
        // the first delivery; neither 0 nor 1 proves loss-free client startup.
        fields.insert("sequence_start".into(), "unverified".into());
        fields.insert("es_event_type".into(), message.event_type.into());
        fields.insert(
            "pid".into(),
            if event.token[5] == 0 {
                serde_json::Value::Null
            } else {
                event.token[5].into()
            },
        );
        // Audit tokens have no Linux start ticks. Preserve the actual birth /
        // exec identity separately rather than inventing ticks from pidversion.
        fields.insert("pid_start_ticks".into(), serde_json::Value::Null);
        fields.insert("audit_token".into(), serde_json::json!(event.token));
        fields.insert("path_basis".into(), "es_notify".into());
        if message.action == ObsAction::Exec {
            // ES reports the new image, not the execve/posix_spawn argument or
            // which syscall was used. The frozen schema's unread-argument arm
            // states exactly that; retain the independently observed image.
            fields.insert("executable".into(), path.into_json());
            fields.insert("executable_complete".into(), complete.into());
            fields.insert(
                "path".into(),
                PathEvidence::Unavailable("argument_not_read").into_json(),
            );
            fields.insert("path_complete".into(), false.into());
        } else {
            fields.insert("path".into(), path.into_json());
            fields.insert("path_complete".into(), complete.into());
            fields.insert("action".into(), message.action.name().into());
            fields.insert(
                "return_value_basis".into(),
                "normalized_notification".into(),
            );
        }
        if message.action.has_two_paths() {
            let path2 = classify_path(
                message.path2.as_deref().unwrap_or_default(),
                &self.workspace,
            );
            fields.insert(
                "path2_complete".into(),
                (!matches!(
                    path2,
                    PathEvidence::Unavailable(_) | PathEvidence::Digest(_, "path_basis_unknown")
                ))
                .into(),
            );
            fields.insert("path2".into(), path2.into_json());
        }
        let denied = message.action == ObsAction::CreateDenied;
        if denied {
            // A NEW_PATH NOTIFY_CREATE means another ES client denied it.
            // ES does not expose the syscall errno; do not invent EPERM.
            fields.insert("denial_source".into(), "endpoint_security".into());
            fields.insert(
                "return_value_basis".into(),
                "normalized_notification".into(),
            );
        }
        self.seq += 1;
        let audit = Event::audit_result(
            &self.attempt_id,
            self.seq,
            std::time::SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            operation.as_str(),
            EventOutcome {
                ok: Some(!denied),
                return_value: Some(if denied { -1 } else { 0 }),
                errno: denied.then(|| "ES_DENIED_ERRNO_UNKNOWN".to_owned()),
                completion: if message.action == ObsAction::Exec {
                    Completion::ExecTransition
                } else {
                    Completion::SyscallReturn
                },
                bytes_in: None,
                bytes_out: None,
                duration_ms: None,
            },
            fields,
        );
        if self.emit(&audit) {
            *self.counts.entry(class).or_insert(0) += 1;
        }
    }

    fn check_sequence(&mut self, message: &ObsMessage) {
        fn missing(last: Option<u64>, next: u64) -> Option<u64> {
            let expected = match last {
                // Match custody: accept either starting convention. A higher
                // first value is a gap, but its exact loss is unknowable.
                None => return (next <= 1).then_some(0),
                Some(last) => last.checked_add(1)?,
            };
            next.checked_sub(expected)
        }
        let global = missing(self.last_global, message.event.global_seq);
        let per_type = missing(
            self.last_seq.get(&message.event_type).copied(),
            message.event.seq,
        );
        self.last_global = Some(message.event.global_seq);
        self.last_seq.insert(message.event_type, message.event.seq);
        self.global_lost = self.global_lost.saturating_add(global.unwrap_or(0));
        self.type_lost = self.type_lost.saturating_add(per_type.unwrap_or(0));
        self.sequence_unknown |= global.is_none() || per_type.is_none();
        if global != Some(0) || per_type != Some(0) {
            // Both counters describe the same deliveries, not two independent
            // losses. Never add them. A regression/repeat has unknown loss.
            let lost = (!self.sequence_unknown && self.ring_dropped == 0)
                .then_some(self.global_lost.max(self.type_lost));
            self.gap(
                "sequence",
                &OBSERVED_CLASSES,
                "observation_client_gap: sequence_discontinuity",
                lost,
            );
        }
    }

    /// External observation failure. Coalesced even if repeated diagnostics
    /// contain different numbers. No custody state is changed.
    pub fn mark_gap(&mut self, reason: &str) {
        let key = match reason {
            "observation_drain_timeout" => "drain",
            "observation_delete_failed" => "delete",
            "observation_worker_panicked" => "worker",
            _ => "external",
        };
        self.gap(key, &OBSERVED_CLASSES, reason, None);
    }

    pub fn record_shim_loss(&mut self, dropped: u64, invalid: bool) {
        if dropped > 0 {
            self.ring_dropped = self.ring_dropped.max(dropped);
            // Ring drops can also appear as sequence discontinuities. Without
            // dropped sequence identities their overlap is unknowable. Keep
            // the shim's exact count, and leave the sequence count unknown,
            // rather than presenting the same loss as two additive counts.
            if let Some(index) = self.gap_indices.get("sequence") {
                self.gaps[*index].lost_count = None;
            }
            self.gap(
                "ring",
                &OBSERVED_CLASSES,
                "observation_ring_overflowed",
                Some(self.ring_dropped),
            );
        }
        if invalid {
            self.gap(
                "shim",
                &OBSERVED_CLASSES,
                "observation_invalid_message",
                None,
            );
        }
    }

    fn gap(
        &mut self,
        key: &'static str,
        classes: &[CoverageClass],
        reason: &str,
        lost_count: Option<u64>,
    ) {
        self.degraded.extend(classes.iter().copied());
        if let Some(index) = self.gap_indices.get(key).copied() {
            self.gaps[index].lost_count = lost_count;
            return;
        }
        let gap = Gap {
            classes: classes
                .iter()
                .map(|class| class.as_str().to_owned())
                .collect(),
            source: "audit".to_owned(),
            start_ns: self.created_ns.to_string(),
            end_ns: None,
            reason: reason.chars().take(256).collect(),
            lost_count,
        };
        self.gap_indices.insert(key, self.gaps.len());
        self.gaps.push(gap.clone());
        // The first note opens the continuing interval. Its count is unknown
        // because further loss may occur; the final receipt carries the total.
        let mut note_gap = gap;
        note_gap.lost_count = None;
        let mut note = Event::coverage_gap_note(
            &self.attempt_id,
            0,
            std::time::SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            &note_gap,
        );
        // Sequence startup is not proof of a complete pre-subscription history.
        note.fields
            .insert("sequence_start".into(), "unverified".into());
        if let Some(trace) = &self.trace {
            let _ = trace
                .lock()
                .map(|mut trace| trace.write_event(&note, Priority::Reserve));
        }
    }

    fn emit(&mut self, event: &Event) -> bool {
        let result = self.trace.as_ref().map(|trace| match trace.lock() {
            Ok(mut sink) => (sink.write_event(event, Priority::Normal).is_ok(), false),
            Err(_) => (false, true),
        });
        match result {
            Some((true, _)) => true,
            Some((false, true)) => {
                self.gap("poison", &OBSERVED_CLASSES, "trace_writer_poisoned", None);
                false
            }
            _ => {
                self.gap(
                    "trace",
                    &OBSERVED_CLASSES,
                    "observation_trace_unavailable",
                    None,
                );
                false
            }
        }
    }

    #[must_use]
    pub fn summary(&self, mut known: CoverageSummary) -> CoverageSummary {
        known.backend = Some(OBSERVER_BACKEND.to_owned());
        known.set = Some(OBSERVATION_SET.to_owned());
        known.sources.audit = if self.is_degraded() {
            SourceStatus::Degraded
        } else {
            SourceStatus::Active
        };
        for class in OBSERVED_CLASSES {
            let status = if self.degraded.contains(&class) {
                SourceStatus::Degraded
            } else {
                SourceStatus::Active
            };
            known.classes.insert(
                class,
                ClassSummary {
                    status,
                    observed_count: (status == SourceStatus::Active).then(|| self.count(class)),
                    gaps: self
                        .gaps
                        .iter()
                        .filter(|gap| gap.classes.iter().any(|name| name == class.as_str()))
                        .cloned()
                        .collect(),
                    resolver_refused: 0,
                },
            );
        }
        known
            .classes
            .insert(CoverageClass::FsDeny, ClassSummary::unsupported());
        for gap in &self.gaps {
            if !known.gaps.contains(gap) {
                known.gaps.push(gap.clone());
            }
        }
        known
    }
}
