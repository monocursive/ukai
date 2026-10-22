//! Native observation (J17): the supervisor's third ES client.
//!
//! Implements jail-macos.md §5. A descendants ES client held by the
//! supervisor subscribes `NOTIFY_EXEC` (the `exec` class) and the mutating
//! filesystem notifications — `NOTIFY_CREATE`, `NOTIFY_RENAME`,
//! `NOTIFY_UNLINK`, `NOTIFY_LINK`, `NOTIFY_TRUNCATE`, `NOTIFY_SETATTRLIST`,
//! `NOTIFY_SETMODE` and `NOTIFY_CLOSE` with `modified` set — for
//! `fs.write`, and nothing else. It reads paths (§11.3), which the custody
//! clients never do.
//!
//! Every observed result journals as an audit-source `ukai.event/1` frame
//! (`Event::audit_result`) on the attempt's trace, exactly as the Linux
//! audit source does, so the summary's recomputation (jail-v1 §13.5) reads
//! the same vocabulary on both platforms. A gap in this client — ring
//! overflow, a message the shim cannot trust, or a skipped per-type
//! sequence — is an observation gap: the `exec` and `fs.write` classes go
//! `degraded` and name the gap, and nothing else moves. `fs.deny` stays
//! `unsupported` (Seatbelt denials are not ES events, §5), `proxy.net`
//! comes from the bridge, and custody never appears in this module.
#![cfg(target_os = "macos")]

use std::collections::{BTreeMap, BTreeSet};

use crate::observer::{ClassSummary, ClosedOperation, CoverageClass, CoverageSummary};
use crate::records::{Completion, Event, EventOutcome, Gap, SourceStatus};
use crate::trace::{Priority, SharedTrace};

/// The observer backend name recorded in the receipt: the mechanism of §5.
pub const OBSERVER_BACKEND: &str = "es_notify";

/// Why a class is degraded when the observation stream lost an interval.
pub const OBSERVATION_GAP_REASON: &str = "observation_client_gap";

mod ffi {
    // Declared in obs_shim.h; compiled by build.rs with the EndpointSecurity
    // and CoreFoundation frameworks (the same build block as the custody
    // shim).
    unsafe extern "C" {
        pub fn ukai_obs_new_descendants(out: *mut *mut UkaiObsClient) -> i32;
        pub fn ukai_obs_unmute_all(client: *mut UkaiObsClient) -> bool;
        pub fn ukai_obs_muted_paths_events(client: *mut UkaiObsClient, event_type: u32) -> bool;
        pub fn ukai_obs_subscribe(client: *mut UkaiObsClient) -> bool;
        pub fn ukai_obs_mute_self(client: *mut UkaiObsClient) -> bool;
        pub fn ukai_obs_poll(client: *mut UkaiObsClient, out: *mut UkaiObsEvent) -> bool;
        pub fn ukai_obs_gap(client: *const UkaiObsClient) -> bool;
        pub fn ukai_obs_drain(client: *mut UkaiObsClient, timeout_ms: u32) -> bool;
        pub fn ukai_obs_delete(client: *mut UkaiObsClient) -> bool;
    }

    #[repr(C)]
    pub struct UkaiObsClient {
        _private: [u8; 0],
    }

    /// The fixed observation record of `obs_shim.h`: sequence numbers, the
    /// member's audit token and one path.
    #[repr(C)]
    pub struct UkaiObsEvent {
        pub kind: i32,
        pub global_seq: u64,
        pub seq: u64,
        pub token: [u32; 8],
        pub modified: i32,
        pub path_len: u16,
        pub path: [u8; 1024],
    }
}

/// Which §5 notification the shim delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObsKind {
    /// `NOTIFY_EXEC`.
    Exec,
    /// `NOTIFY_CREATE`.
    Create,
    /// `NOTIFY_CLOSE` with `modified`, or the other mutating notifications.
    Write,
    /// `NOTIFY_RENAME`.
    Rename,
    /// `NOTIFY_UNLINK`.
    Unlink,
}

impl ObsKind {
    /// The shim-internal event numbers of `obs_shim.h`.
    fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Exec),
            2 => Some(Self::Create),
            3 => Some(Self::Write),
            4 => Some(Self::Rename),
            5 => Some(Self::Unlink),
            _ => None,
        }
    }

    /// The closed-set operation the notification is reported as (§11.2): the
    /// Linux audit vocabulary, so a consumer reads one journal shape.
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

/// One observation event, decoded to the fixed fields the journal may read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObsEvent {
    pub kind: ObsKind,
    pub global_seq: u64,
    /// The per-type `seq_num` the gap detection checks for continuity.
    pub seq: u64,
    /// The member's audit token.
    pub token: [u32; 8],
    /// The path the event names, whole (the shim gaps a path its buffer
    /// cannot carry whole rather than report a truncated one).
    pub path: Vec<u8>,
}

/// The observation client of §5: created, driven and deleted from one
/// thread; `Send` but deliberately not `Sync`, like the custody client.
pub struct ObserveClient {
    raw: std::ptr::NonNull<ffi::UkaiObsClient>,
}

// SAFETY: the shim client is independent of any Rust thread state; ES
// clients are driven from one thread at a time, which the ownership model
// here enforces by construction (no `Sync`).
unsafe impl Send for ObserveClient {}

impl ObserveClient {
    /// `es_new_descendants_client` through the observation shim. On failure
    /// nothing is kept and the mapped result names the cause; an unentitled
    /// host answers [`EsNewResult::NotEntitled`] and J17 falls back honestly
    /// — the run proceeds with observation unavailable (§5: a crash or
    /// refusal here never takes custody).
    pub fn new() -> Result<Self, super::es::EsNewResult> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: `raw` is a valid out pointer; on success the shim returns
        // a client that stays valid until `ukai_obs_delete`.
        let result =
            super::es::EsNewResult::from_raw(unsafe { ffi::ukai_obs_new_descendants(&mut raw) });
        match std::ptr::NonNull::new(raw) {
            Some(raw) if result == super::es::EsNewResult::Success => Ok(Self { raw }),
            _ => Err(if result == super::es::EsNewResult::Success {
                super::es::EsNewResult::Internal
            } else {
                result
            }),
        }
    }

    /// `es_unmute_all_paths` + `es_unmute_all_target_paths`.
    pub fn unmute_all(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_obs_new_descendants`.
        unsafe { ffi::ukai_obs_unmute_all(self.raw.as_ptr()) }
    }

    /// Whether `event_type` is still muted by the default mute set; the
    /// creation sequence refuses the client if any §5 event answers true.
    pub fn muted_paths_events(&self, event_type: u32) -> bool {
        // SAFETY: `self.raw` is a live client; the shim releases the mute
        // list the framework returns.
        unsafe { ffi::ukai_obs_muted_paths_events(self.raw.as_ptr(), event_type) }
    }

    /// The §5 subscription: nine notifications, nothing else.
    pub fn subscribe(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_obs_new_descendants`.
        unsafe { ffi::ukai_obs_subscribe(self.raw.as_ptr()) }
    }

    /// `es_mute_process` on this process (the supervisor does not observe
    /// itself).
    pub fn mute_self(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_obs_new_descendants`.
        unsafe { ffi::ukai_obs_mute_self(self.raw.as_ptr()) }
    }

    /// Drains one event from the ring, or `None` when it is empty. An event
    /// kind outside the §5 set cannot appear — the shim gaps that stream —
    /// but if one did, the sticky gap flag reports it.
    pub fn poll(&self) -> Option<ObsEvent> {
        let mut raw = ffi::UkaiObsEvent {
            kind: 0,
            global_seq: 0,
            seq: 0,
            token: [0; 8],
            modified: 0,
            path_len: 0,
            path: [0; 1024],
        };
        // SAFETY: `self.raw` is a live client and `raw` a valid out record.
        if unsafe { ffi::ukai_obs_poll(self.raw.as_ptr(), &mut raw) } {
            let kind = ObsKind::from_raw(raw.kind as u32)?;
            Some(ObsEvent {
                kind,
                global_seq: raw.global_seq,
                seq: raw.seq,
                token: raw.token,
                path: raw.path[..usize::from(raw.path_len)].to_vec(),
            })
        } else {
            None
        }
    }

    /// The sticky stream-gap flag (§5: a gap in this client is an
    /// observation gap with `degraded` status).
    pub fn gap(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_obs_new_descendants`.
        unsafe { ffi::ukai_obs_gap(self.raw.as_ptr()) }
    }

    /// `es_sync_client` bounded by `timeout_ms`.
    pub fn drain(&self, timeout_ms: u32) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_obs_new_descendants`.
        unsafe { ffi::ukai_obs_drain(self.raw.as_ptr(), timeout_ms) }
    }

    /// `es_delete_client` and the shim's own teardown. The client is
    /// consumed.
    pub fn delete(self) -> bool {
        // SAFETY: `self.raw` is a live client, deleted exactly once; the
        // shim frees the ring and the semaphore with it.
        let deleted = unsafe { ffi::ukai_obs_delete(self.raw.as_ptr()) };
        std::mem::forget(self);
        deleted
    }
}

impl Drop for ObserveClient {
    fn drop(&mut self) {
        // A client dropped without an explicit `delete` is still released,
        // so no test or early return leaks an ES client.
        // SAFETY: `self.raw` is a live client, deleted exactly once.
        unsafe { ffi::ukai_obs_delete(self.raw.as_ptr()) };
    }
}

/// What one observation event journals as: its `{kind, value}` path form
/// (examples/event-open.json's shape — a consumer reads `fields.path.kind`,
/// not a flat key it has to know about).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathEvidence {
    /// The path is inside the workspace root, at this component-wise suffix.
    WorkspaceRelative(Vec<u8>),
    /// Nothing can be said about where it sits: only a digest of the path
    /// and why it is not named (the Linux denied-path convention).
    Digest(String, &'static str),
}

impl PathEvidence {
    /// The event's nested `fields.path` value.
    #[must_use]
    pub fn into_json(self) -> serde_json::Value {
        match self {
            Self::WorkspaceRelative(bytes) => serde_json::json!({
                "kind": "workspace_relative",
                "value": native_value(&bytes),
            }),
            Self::Digest(digest, reason) => serde_json::json!({
                "kind": "digest",
                "digest": digest,
                "reason": reason,
            }),
        }
    }
}

/// [`crate::records::NativeString`] as JSON, or null for bytes that are not
/// UTF-8 (the Linux audit source's own rendering).
fn native_value(bytes: &[u8]) -> serde_json::Value {
    crate::records::NativeString::from_bytes(bytes.to_vec())
        .ok()
        .and_then(|native| serde_json::to_value(native).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// The suffix of `path` below `root`, component-wise so that `/w/ab` is not
/// inside `/w/a`. The root itself yields an empty suffix.
fn strip_root(path: &[u8], root: &[u8]) -> Option<Vec<u8>> {
    let root = root.strip_suffix(b"/").unwrap_or(root);
    if root.is_empty() {
        return None;
    }
    if path == root {
        return Some(Vec::new());
    }
    let rest = path.strip_prefix(root)?;
    if rest.first() == Some(&b'/') {
        Some(rest[1..].to_vec())
    } else {
        None
    }
}

/// Classifies one observed path (§11.3): workspace-relative where the path
/// is under the workspace root, a digest everywhere else — never a host
/// path outside the workspace, in this form or any other.
#[must_use]
pub fn classify_path(path: &[u8], workspace: &[u8]) -> PathEvidence {
    match strip_root(path, workspace) {
        Some(rest) => PathEvidence::WorkspaceRelative(rest),
        None => PathEvidence::Digest(crate::canonical::sha256_prefixed(path), "outside_workspace"),
    }
}

/// The observation journal: audit-source frames on the attempt's trace and
/// the class counts and gaps of §11.4, for the two classes §5 observes.
pub struct ObserveJournal {
    attempt_id: String,
    trace: Option<SharedTrace>,
    workspace: Vec<u8>,
    seq: u64,
    counts: BTreeMap<CoverageClass, u64>,
    degraded: BTreeSet<CoverageClass>,
    gaps: Vec<Gap>,
    /// The last per-type `seq_num` each class saw; a skipped number is an
    /// interval the framework never delivered.
    last_seq: BTreeMap<u32, u64>,
    created_ns: u128,
}

/// The classes §5 observes, in [`CoverageClass::ALL`] order.
pub const OBSERVED_CLASSES: [CoverageClass; 2] = [CoverageClass::Exec, CoverageClass::FsWrite];

impl ObserveJournal {
    #[must_use]
    pub fn new(attempt_id: &str, trace: Option<SharedTrace>, workspace: &[u8]) -> Self {
        ObserveJournal {
            attempt_id: attempt_id.to_owned(),
            trace,
            workspace: workspace.to_vec(),
            seq: 0,
            counts: BTreeMap::new(),
            degraded: BTreeSet::new(),
            gaps: Vec::new(),
            last_seq: BTreeMap::new(),
            created_ns: crate::platform::elapsed_since_start_ns(),
        }
    }

    /// Whether any gap degraded the observed classes.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !self.degraded.is_empty()
    }

    /// Events emitted for one class so far.
    #[must_use]
    pub fn count(&self, class: CoverageClass) -> u64 {
        self.counts.get(&class).copied().unwrap_or(0)
    }

    /// The gaps this journal recorded.
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    /// One observed result: an audit frame on the trace, counted under its
    /// operation's class once the trace took it (§13.2: an undelivered
    /// frame is not an observed result).
    pub fn record(&mut self, event: &ObsEvent) {
        self.check_sequence(event);
        let operation = event.kind.operation();
        let class = operation.coverage_class();
        let mut fields = serde_json::Map::new();
        fields.insert(
            "path".to_owned(),
            classify_path(&event.path, &self.workspace).into_json(),
        );
        self.seq += 1;
        let audit = Event::audit_result(
            &self.attempt_id,
            self.seq,
            std::time::SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
            operation.as_str(),
            EventOutcome {
                ok: Some(true),
                return_value: Some(0),
                errno: None,
                completion: match event.kind {
                    ObsKind::Exec => Completion::ExecTransition,
                    ObsKind::Create | ObsKind::Write | ObsKind::Rename | ObsKind::Unlink => {
                        Completion::SyscallReturn
                    }
                },
                bytes_in: None,
                bytes_out: None,
                duration_ms: None,
            },
            fields,
        );
        if self.emit(&audit, class) {
            *self.counts.entry(class).or_insert(0) += 1;
        }
    }

    /// The per-type sequence continuity of §5's gap semantics: a skipped
    /// number is a notification the framework never delivered, and the
    /// affected classes degrade with a gap naming the interval from the
    /// journal's start. Like the framework's own sticky flag, this never
    /// heals within the attempt.
    fn check_sequence(&mut self, event: &ObsEvent) {
        let key = match event.kind {
            ObsKind::Exec => 1,
            ObsKind::Create => 2,
            ObsKind::Write => 3,
            ObsKind::Rename => 4,
            ObsKind::Unlink => 5,
        };
        match self.last_seq.get(&key) {
            Some(last) if event.seq != *last + 1 => {
                let reason = format!(
                    "{OBSERVATION_GAP_REASON}: seq_num jumped from {last} to {}",
                    event.seq
                );
                self.mark_gap(&reason);
            }
            _ => {}
        }
        self.last_seq.insert(key, event.seq);
    }

    /// Marks the observed classes degraded from the named loss (§5: a gap in
    /// this client is an observation gap and never touches custody or
    /// `tree_empty`).
    pub fn mark_gap(&mut self, reason: &str) {
        let start_ns = self.created_ns.to_string();
        let gap = Gap {
            classes: OBSERVED_CLASSES
                .iter()
                .map(|class| class.as_str().to_owned())
                .collect(),
            source: "audit".to_owned(),
            start_ns,
            end_ns: None,
            reason: reason.to_owned(),
            lost_count: None,
        };
        for class in OBSERVED_CLASSES {
            self.degraded.insert(class);
        }
        // One gap per reason, extended by nothing: the interval runs to the
        // end of the attempt (the stop drains, it does not heal).
        if !self.gaps.iter().any(|existing| existing.reason == reason) {
            self.gaps.push(gap);
        }
    }

    /// Offers one frame to the trace, degrading its class on a refusal —
    /// the audit source's own rule (§13.2).
    fn emit(&mut self, event: &Event, class: CoverageClass) -> bool {
        let Some(trace) = self.trace.as_ref() else {
            // No trace configured: nothing is lost that anyone claimed to
            // collect.
            return true;
        };
        let delivered = match trace.lock() {
            Ok(mut sink) => sink.write_event(event, Priority::Normal).is_ok(),
            Err(_) => false,
        };
        if delivered {
            return true;
        }
        // A refused frame degrades its class (§13.2); a trace whose lock a
        // panicking thread held can take no frame at all, so it is a gap of
        // its class.
        if trace.is_poisoned() {
            self.mark_gap("trace_writer_poisoned");
        } else {
            self.degraded.insert(class);
        }
        false
    }

    /// The platform's observation summary (§11.4): `exec` and `fs.write`
    /// active with their counts — or degraded, with the gap that degraded
    /// them — while `fs.deny` and every other audit class stay exactly what
    /// `known` states (`unsupported` on macOS: Seatbelt denials are not ES
    /// events). Custody and `tree_empty` do not appear here.
    #[must_use]
    pub fn summary(&self, known: CoverageSummary) -> CoverageSummary {
        let mut summary = known;
        summary.backend = Some(OBSERVER_BACKEND.to_owned());
        summary.sources.audit = if self.is_degraded() {
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
            summary.classes.insert(
                class,
                ClassSummary {
                    status,
                    // §11.4: "Unsupported and degraded counts are null."
                    observed_count: if status == SourceStatus::Degraded {
                        None
                    } else {
                        Some(self.count(class))
                    },
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
        for gap in self.gaps.clone() {
            if !summary.gaps.iter().any(|existing| existing == &gap) {
                summary.gaps.push(gap);
            }
        }
        summary
    }
}
