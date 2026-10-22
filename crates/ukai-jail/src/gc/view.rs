//! What `gc` reads: jail state and the last receipt, as the views
//! [`super::decide`] decides on.

use std::path::Path;

use serde_json::Value;

use serde::Deserialize as _;

use super::host::{GuardianRecord, LeafRecord, OwnerRecord, TargetToken};
use super::leaf_name_of;
use crate::cleanup;
use crate::lifecycle::TreeEnd;
use crate::records::{Phase, SCHEMA_RECEIPT};
use crate::state;

/// What `gc` needs from `jail-state.json`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StateView {
    /// The attempt it claims (the attempt root's name; `parse_state`
    /// refuses any other).
    pub attempt_id: String,
    /// The claiming platform's OS.
    pub os: String,
    /// The claiming platform's architecture.
    pub arch: String,
    /// The supervisor's birth identity; `None` where the platform had none.
    pub owner: Option<OwnerRecord>,
    /// N7: the execution leaf the platform registered in jail state, by
    /// name before `mkdir` and by identity right after; the only source of
    /// the leaf gc acts on (`recorded_leaf`).
    pub leaf: Option<RegisteredLeaf>,
    /// Leaves an earlier pass removed (`gc_removed_cgroup`).
    pub gc_removed: Vec<LeafRecord>,
    /// Leaves an earlier pass verified empty: terminated and seen empty
    /// (`gc_terminated_orphan`), about to be removed after it was seen empty
    /// (`gc_removing_cgroup`, J4 wave 3: by its path only for a leaf
    /// registered by name only), or removed (`gc_removed_cgroup`, which gc
    /// records only after the kernel removed an empty cgroup).
    pub gc_verified: Vec<VerifiedLeaf>,
    /// Whether an earlier pass removed managed scratch (`gc_removed_scratch`).
    pub gc_removed_scratch: bool,
    /// When an earlier pass found nothing left to do (`gc_finished`).
    pub gc_finished: Option<String>,
    /// J16 (jail-macos.md §4.9): an earlier pass verified the tree's end by
    /// the guardian's custody (`gc_custody_verified`) or the operator
    /// abandoned the attempt (`gc_abandoned`), either of which releases the
    /// lease's hold on the resources for later passes too.
    pub custody_released: bool,
    /// An operator release is never evidence that the tree drained.
    pub custody_abandoned: bool,
}

// N7
/// The execution leaf as jail state registers it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RegisteredLeaf {
    /// Named before `mkdir`; the supervisor died before it recorded the
    /// identity, so the leaf may or may not exist, and nothing was ever
    /// placed in it by this attempt (placement follows the identity record).
    Named(std::path::PathBuf),
    /// Identified right after `mkdir`, before anything was placed in it.
    Identified(LeafRecord),
}

/// A leaf an earlier pass verified empty, as gc recorded it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifiedLeaf {
    /// The leaf's path.
    pub path: std::path::PathBuf,
    /// Its `(device, inode)`; `None` for a leaf registered by name only,
    /// whose identity gc never knew when it saw it empty.
    pub identity: Option<(u64, u64)>,
}

impl VerifiedLeaf {
    /// Whether this is gc's record of the identified leaf `leaf`.
    #[must_use]
    pub fn is_of(&self, leaf: &LeafRecord) -> bool {
        self.path == leaf.path && self.identity == Some((leaf.device, leaf.inode))
    }
}

impl From<LeafRecord> for VerifiedLeaf {
    fn from(leaf: LeafRecord) -> VerifiedLeaf {
        VerifiedLeaf {
            identity: Some((leaf.device, leaf.inode)),
            path: leaf.path,
        }
    }
}

impl RegisteredLeaf {
    /// The registered path.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            RegisteredLeaf::Named(path) => path,
            RegisteredLeaf::Identified(leaf) => &leaf.path,
        }
    }

    /// Whether the identified leaf `leaf` (a receipt's) is this
    /// registration's.
    #[must_use]
    pub fn is(&self, leaf: &LeafRecord) -> bool {
        match self {
            RegisteredLeaf::Named(path) => leaf.path == *path,
            RegisteredLeaf::Identified(registered) => registered == leaf,
        }
    }

    /// Whether gc's record `verified` is of this registration: by its path
    /// for a leaf registered by name only, by its identity otherwise.
    #[must_use]
    pub fn verified_by(&self, verified: &VerifiedLeaf) -> bool {
        match self {
            RegisteredLeaf::Named(path) => verified.path == *path,
            RegisteredLeaf::Identified(registered) => verified.is_of(registered),
        }
    }
}

/// Where the execution leaf is, as gc reads it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LeafSource {
    /// No leaf is registered; why.
    NotRecorded(String),
    /// The registration.
    Recorded(LeafRecord),
    // N7
    /// Registered by name only, before `mkdir` (N7).
    NamedOnly(std::path::PathBuf),
    /// A registration that does not have the shape the supervisor writes.
    Malformed(String),
}

/// What `gc` needs from the last receipt, `jail.json`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiptView {
    /// The lifecycle phase.
    pub phase: Phase,
    /// A refused receipt explicitly records no process, a pending boundary,
    /// and only resolving/probing errors. Preparation (and therefore a
    /// guardian spawn) was never entered; a missing process alone is not
    /// this proof.
    pub refused_before_prepare: bool,
    /// What `lifetime.integrity`, `boundary` and `tree_empty` say about the
    /// tree's end.
    pub tree_end: TreeEnd,
    /// The execution OS of the recorded process boot. A Linux guest boot
    /// is a separate identity domain from its macOS supervisor's boot.
    pub boot_os: Option<String>,
    /// The boot the recorded process identity names, when it names one.
    pub boot_id: Option<String>,
    /// The execution leaf from `lifetime.native.details.execution_cgroup`.
    pub leaf: LeafSource,
    /// J16 (jail-macos.md §4.8, §4.9): the target's recorded identity,
    /// `process.identity.kind = macos_audit_token`. `gc` kills the tree's
    /// target through it; `None` on Linux receipts and macOS receipts that
    /// name no identity.
    pub target: Option<TargetToken>,
}

impl ReceiptView {
    /// Whether the receipt itself proves that no tree of the attempt can
    /// still use what it left: the proof the vendor-state cleanup accepts
    /// (`cleanup::permitted_by`), a settlement or a refusal after a verified
    /// tree end, or a refusal before any boundary existed, never after lost
    /// integrity.
    #[must_use]
    pub fn proves_tree_end(&self) -> bool {
        cleanup::wait_reason(self.phase, self.tree_end).is_none()
    }
}

fn leaf_from(value: &Value) -> Option<LeafRecord> {
    Some(LeafRecord {
        path: value.get("path")?.as_str()?.into(),
        device: value.get("device")?.as_u64()?,
        inode: value.get("inode")?.as_u64()?,
    })
}

/// The jail-state entry of a leaf gc identified.
pub(super) fn leaf_entry(leaf: &LeafRecord) -> state::LeafEntry {
    state::LeafEntry::new(leaf.path.clone(), Some((leaf.device, leaf.inode)))
}

/// A leaf jail state records with its device and inode.
fn identified(entry: &state::LeafEntry) -> Option<LeafRecord> {
    let (device, inode) = entry.identity()?;
    Some(LeafRecord {
        path: entry.path.clone(),
        device,
        inode,
    })
}

/// Parses jail state for the attempt named `id`: the projection of
/// [`state::JailState`] gc decides on.
///
/// # Errors
/// Why the state is corrupt: not JSON, another schema, another attempt, or
/// a field without the shape the supervisor writes.
pub fn parse_state(bytes: &[u8], id: &str) -> Result<StateView, String> {
    let state = state::JailState::parse(bytes).map_err(|error| error.to_string())?;
    if state.schema.get().map(String::as_str) != Some(state::SCHEMA_STATE) {
        return Err(format!("the schema is not {}", state::SCHEMA_STATE));
    }
    if state.attempt_id.get().map(String::as_str) != Some(id) {
        return Err("it names another attempt".to_owned());
    }
    let text = |field: &state::Field<String>, key: &str| {
        field
            .get()
            .cloned()
            .ok_or_else(|| format!("`{key}` is missing"))
    };
    let owner = state.owner.get().map(|owner| OwnerRecord {
        pid: owner.pid,
        boot_id: owner.boot_id.clone(),
        start_time_ticks: owner.start_time_ticks,
    });
    // N7: `{path, device, inode}`, or `{path, null, null}` for a leaf named
    // before `mkdir` whose identity was never recorded.
    let leaf = match state.execution_cgroup.get() {
        None => None,
        Some(entry) if entry.is_name_only() => Some(RegisteredLeaf::Named(entry.path.clone())),
        Some(entry) => Some(
            identified(entry)
                .map(RegisteredLeaf::Identified)
                .ok_or("`execution_cgroup` is malformed")?,
        ),
    };
    let mut gc_removed = Vec::new();
    let mut gc_verified = Vec::new();
    let mut gc_removed_scratch = false;
    let mut custody_released = false;
    let mut custody_abandoned = false;
    let mut gc_finished = None;
    for action in state.gc_actions.get().into_iter().flatten() {
        let verified_empty = action.verified_empty.get() == Some(&true);
        let leaf = action.execution_cgroup.get();
        match action.action.as_str() {
            "gc_removed_cgroup" => {
                if let Some(leaf) = leaf.and_then(identified) {
                    gc_verified.push(leaf.clone().into());
                    gc_removed.push(leaf);
                }
            }
            "gc_terminated_orphan" if verified_empty => {
                gc_verified.extend(leaf.and_then(identified).map(VerifiedLeaf::from));
            }
            // J4 wave 3 (G3): the intent, recorded after the leaf was seen
            // empty and before its `rmdir`; by name only (no device and
            // inode) for a leaf registered by name only.
            "gc_removing_cgroup" if verified_empty => {
                gc_verified.extend(leaf.and_then(|leaf| {
                    identified(leaf).map(VerifiedLeaf::from).or_else(|| {
                        leaf.is_name_only().then(|| VerifiedLeaf {
                            path: leaf.path.clone(),
                            identity: None,
                        })
                    })
                }));
            }
            "gc_removed_scratch" => gc_removed_scratch = true,
            // J16 (jail-macos.md §4.9): a custody the guardian verified, or
            // an end the operator accepted, releases the hold for later
            // passes too.
            "gc_custody_verified" => custody_released = true,
            "gc_abandoned" => {
                custody_released = true;
                custody_abandoned = true;
            }
            // J4 wave 3 (G4)
            "gc_finished" => {
                gc_finished = Some(
                    action
                        .at
                        .get()
                        .cloned()
                        .unwrap_or_else(|| "an unrecorded time".to_owned()),
                );
            }
            _ => {}
        }
    }
    Ok(StateView {
        attempt_id: id.to_owned(),
        os: text(&state.os, "os")?,
        arch: text(&state.arch, "arch")?,
        owner,
        leaf,
        gc_removed,
        gc_verified,
        gc_removed_scratch,
        custody_released,
        custody_abandoned,
        gc_finished,
    })
}

/// Parses the last receipt of the attempt named `id`.
///
/// # Errors
/// Why the receipt is corrupt: not JSON, another schema, another attempt, or
/// no lifecycle phase.
pub fn parse_receipt(bytes: &[u8], id: &str) -> Result<ReceiptView, String> {
    let receipt: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if receipt.get("schema").and_then(Value::as_str) != Some(SCHEMA_RECEIPT) {
        return Err(format!("the schema is not {SCHEMA_RECEIPT}"));
    }
    if receipt.get("attempt_id").and_then(Value::as_str) != Some(id) {
        return Err("it names another attempt".to_owned());
    }
    let phase = receipt
        .get("phase")
        .and_then(|phase| Phase::deserialize(phase).ok())
        .ok_or("it has no lifecycle phase")?;
    let lifetime = receipt.get("lifetime").unwrap_or(&Value::Null);
    let native = lifetime.get("native").unwrap_or(&Value::Null);
    let native_os = native.get("os").and_then(Value::as_str);
    let target = if native_os == Some("macos") {
        parse_macos_target(&receipt)
    } else {
        None
    };
    let leaf = if native_os == Some("linux") {
        match native
            .get("details")
            .and_then(|details| details.get("execution_cgroup"))
        {
            None | Some(Value::Null) => {
                LeafSource::NotRecorded("the receipt registers no execution cgroup".to_owned())
            }
            Some(value) if value.get("unavailable").is_some() => LeafSource::NotRecorded(
                "the run had no execution cgroup (its receipt says unavailable)".to_owned(),
            ),
            Some(value) => leaf_from(value).map_or_else(
                || {
                    LeafSource::Malformed(
                        "the registered execution cgroup has no path, device and inode".to_owned(),
                    )
                },
                LeafSource::Recorded,
            ),
        }
    } else {
        LeafSource::NotRecorded("the receipt records no Linux lifetime details".to_owned())
    };
    let text = |key: &str| lifetime.get(key).and_then(Value::as_str).unwrap_or("");
    let tree_end = TreeEnd::from_text(
        text("integrity"),
        text("boundary"),
        lifetime.get("tree_empty").and_then(Value::as_bool),
    );
    let refused_before_prepare = phase == Phase::Refused
        && tree_end.no_boundary
        && !tree_end.integrity_lost
        && receipt.get("process") == Some(&Value::Null)
        && receipt.get("exec_observed").and_then(Value::as_bool) == Some(false)
        && receipt
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|errors| {
                !errors.is_empty()
                    && errors.iter().all(|error| {
                        matches!(
                            error.get("stage").and_then(Value::as_str),
                            Some("resolving" | "probing")
                        )
                    })
            });
    Ok(ReceiptView {
        phase,
        refused_before_prepare,
        tree_end,
        boot_os: native_os
            .or_else(|| receipt.pointer("/platform/os").and_then(Value::as_str))
            .map(str::to_owned),
        boot_id: receipt
            .pointer("/process/identity/value/boot_id")
            .or_else(|| receipt.pointer("/process/identity/value/boot_session"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        leaf,
        target,
    })
}

/// J16 (jail-macos.md §4.8): the target identity a macOS receipt records,
/// `process.identity.kind = macos_audit_token` with `pid` and `pidversion`
/// in its value. A receipt that names another kind, or words the identity
/// differently than the supervisor writes it, records no target, and gc
/// never guesses one.
fn parse_macos_target(receipt: &Value) -> Option<TargetToken> {
    let identity = receipt.pointer("/process/identity").unwrap_or(&Value::Null);
    if identity.get("kind").and_then(Value::as_str) != Some("macos_audit_token") {
        return None;
    }
    let value = identity.get("value").unwrap_or(&Value::Null);
    let (pid, pidversion) = match (
        value.get("pid").and_then(Value::as_u64),
        value.get("pidversion").and_then(Value::as_u64),
    ) {
        (Some(pid), Some(pidversion))
            if pid <= u32::MAX.into() && pidversion <= u32::MAX.into() =>
        {
            (pid as u32, pidversion as u32)
        }
        _ => return None,
    };
    Some(TargetToken { pid, pidversion })
}

/// J16 (jail-macos.md §4.9): the guardian's record, read tolerantly — a
/// record that is corrupt, of another schema, or missing fields is treated
/// as absent (`None`), and only the fields the reader knows are taken.
#[must_use]
pub fn parse_guardian_record(bytes: &[u8]) -> Option<GuardianRecord> {
    let record = serde_json::from_slice::<Value>(bytes).ok()?;
    if record.get("schema").and_then(Value::as_str) != Some("ukai.jail.guardian-record/1") {
        return None;
    }
    // `own_token` is the guardian's audit token as the eight words the
    // kernel defines; pid is word 5, the pid version word 7.
    let word = |index: usize| {
        record
            .get("own_token")
            .and_then(Value::as_array)
            .and_then(|words| words.get(index))
            .and_then(Value::as_u64)
            .filter(|word| *word <= u32::MAX.into())
            .map(|word| word as u32)
    };
    Some(GuardianRecord {
        pid: word(5),
        pidversion: word(7),
        boot_session: record
            .get("boot_session")
            .and_then(Value::as_str)
            .map(str::to_owned),
        drained: record.get("drained").and_then(Value::as_bool),
    })
}

/// Where the execution leaf's identity is read from.
///
/// J4 wave 2, N7: jail state, where the platform registers the leaf by name
/// before `mkdir` and by identity right after, so a supervisor that died
/// before any receipt still left its leaf findable. The receipt is not a
/// registration; when it names a leaf too, the two must agree, and records
/// that disagree are retained (§14.2).
pub(super) fn recorded_leaf(state: &StateView, receipt: Option<&ReceiptView>) -> LeafSource {
    // J4 wave 3 (G2): the leaf carries its attempt. A registration naming
    // any other leaf (another attempt's, or no execution leaf at all) is not
    // this attempt's, and gc never acts on it, whatever identity it records.
    if let Some(registered) = &state.leaf {
        let own = leaf_name_of(&state.attempt_id);
        let path = registered.path();
        if path.file_name() != Some(std::ffi::OsStr::new(&own)) {
            return LeafSource::Malformed(format!(
                "the registered leaf's name `{}` is not this attempt's (`{own}`): gc never acts \
                 on another attempt's leaf, nor on a cgroup that is no execution leaf",
                path.file_name().map_or_else(
                    || path.display().to_string(),
                    |name| name.to_string_lossy().into_owned()
                )
            ));
        }
    }
    let in_receipt = receipt.and_then(|receipt| match &receipt.leaf {
        LeafSource::Recorded(leaf) => Some(leaf),
        _ => None,
    });
    match (&state.leaf, in_receipt) {
        (None, _) => LeafSource::NotRecorded(
            "jail state registers no execution cgroup (a receipt alone is not a registration)"
                .to_owned(),
        ),
        (Some(registered), Some(named)) if !registered.is(named) => LeafSource::Malformed(
            "jail state and the receipt name different execution cgroups".to_owned(),
        ),
        (Some(RegisteredLeaf::Named(_)), Some(_)) => LeafSource::Malformed(
            "jail state registers the leaf by name only, but a receipt names its identity"
                .to_owned(),
        ),
        (Some(RegisteredLeaf::Identified(leaf)), _) => LeafSource::Recorded(leaf.clone()),
        (Some(RegisteredLeaf::Named(path)), None) => LeafSource::NamedOnly(path.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_process_alone_does_not_prove_preparation_never_started() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let good = serde_json::json!({
            "schema": SCHEMA_RECEIPT, "attempt_id": id, "phase": "refused",
            "process": null, "exec_observed": false,
            "lifetime": {"boundary": "pending", "integrity": "pending"},
            "errors": [{"stage": "probing"}]
        });
        let proof = |value: &Value| {
            parse_receipt(&serde_json::to_vec(value).unwrap(), id)
                .unwrap()
                .refused_before_prepare
        };
        assert!(proof(&good));
        for stage in [
            "preparing",
            "prepared",
            "released",
            "running",
            "stopping",
            "reconciling",
            "settled",
            "unknown",
        ] {
            let mut value = good.clone();
            value["errors"][0]["stage"] = serde_json::json!(stage);
            assert!(!proof(&value), "{stage}");
        }
        for (pointer, replacement) in [
            ("/process", serde_json::json!({})),
            ("/exec_observed", serde_json::json!(true)),
            ("/lifetime/boundary", serde_json::json!("native_tree")),
            ("/lifetime/integrity", serde_json::json!("lost")),
            ("/errors", serde_json::json!([])),
        ] {
            let mut value = good.clone();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(!proof(&value), "{pointer}");
        }
    }

    #[test]
    fn state_and_receipt_views_refuse_what_the_supervisor_does_not_write() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let good = serde_json::json!({
            "schema": "ukai.jail.state/1", "attempt_id": id, "os": "linux", "arch": "x86_64",
            "owner": {"pid": 5, "boot_id": "b", "start_time_ticks": 9},
        });
        assert!(parse_state(&serde_json::to_vec(&good).unwrap(), id).is_ok());
        for (key, value) in [
            ("schema", serde_json::json!("ukai.jail.state/2")),
            ("attempt_id", serde_json::json!("att_other")),
            ("owner", serde_json::json!({"pid": "5"})),
            (
                "owner",
                serde_json::json!({"pid": -1, "boot_id": "b", "start_time_ticks": 9}),
            ),
            ("gc_actions", serde_json::json!({})),
            ("os", Value::Null),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                parse_state(&serde_json::to_vec(&bad).unwrap(), id).is_err(),
                "{key}"
            );
        }
        let receipt = serde_json::json!({
            "schema": SCHEMA_RECEIPT, "attempt_id": id, "phase": "enforced",
            "lifetime": {"native": {"os": "linux", "details": {"execution_cgroup":
                {"path": "/p", "device": 1, "inode": 2}}}},
        });
        let view = parse_receipt(&serde_json::to_vec(&receipt).unwrap(), id).unwrap();
        assert!(matches!(view.leaf, LeafSource::Recorded(_)));
        let mut malformed = receipt.clone();
        malformed["lifetime"]["native"]["details"]["execution_cgroup"]["inode"] =
            serde_json::json!("2");
        let view = parse_receipt(&serde_json::to_vec(&malformed).unwrap(), id).unwrap();
        assert!(matches!(view.leaf, LeafSource::Malformed(_)));
        let mut phaseless = receipt;
        phaseless["phase"] = serde_json::json!("running");
        assert!(parse_receipt(&serde_json::to_vec(&phaseless).unwrap(), id).is_err());
    }

    /// The receipt's lifetime facts are parsed once, and a tree end is
    /// proved exactly where the vendor-state cleanup accepts it.
    #[test]
    fn a_receipt_proves_its_tree_end_by_the_cleanup_rule() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let view = |phase: &str, lifetime: Value| {
            let receipt = serde_json::json!({
                "schema": SCHEMA_RECEIPT, "attempt_id": id, "phase": phase,
                "lifetime": lifetime,
            });
            parse_receipt(&serde_json::to_vec(&receipt).unwrap(), id).unwrap()
        };
        let lifetime = |integrity: &str, boundary: &str, tree_empty: Value| {
            serde_json::json!({"integrity": integrity, "boundary": boundary,
                "tree_empty": tree_empty})
        };
        let refused_before_any_boundary =
            view("refused", lifetime("pending", "pending", Value::Null));
        assert_eq!(refused_before_any_boundary.phase, Phase::Refused);
        assert!(refused_before_any_boundary.tree_end.no_boundary);
        assert!(refused_before_any_boundary.proves_tree_end());
        let settled = view(
            "settled",
            lifetime("verified", "pid_namespace", Value::Bool(true)),
        );
        assert!(settled.tree_end.verified_empty && settled.proves_tree_end());
        let lost = view(
            "settled",
            lifetime("lost", "pid_namespace", Value::Bool(true)),
        );
        assert!(lost.tree_end.integrity_lost && !lost.proves_tree_end());
        let unverified = view(
            "enforced",
            lifetime("verified", "pid_namespace", Value::Null),
        );
        assert!(!unverified.proves_tree_end());
        let silent = view("refused", Value::Null);
        assert_eq!(
            silent.tree_end,
            TreeEnd::from_text("", "", None),
            "a receipt that says nothing proves nothing"
        );
        assert!(!silent.proves_tree_end());
    }

    #[test]
    fn a_name_only_registration_parses_and_half_an_identity_does_not() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let state = |leaf: Value| {
            serde_json::to_vec(&serde_json::json!({
                "schema": "ukai.jail.state/1", "attempt_id": id, "os": "linux",
                "arch": "x86_64", "execution_cgroup": leaf,
            }))
            .unwrap()
        };
        let named = parse_state(
            &state(serde_json::json!({"path": "/p", "device": null, "inode": null})),
            id,
        )
        .unwrap();
        assert_eq!(named.leaf, Some(RegisteredLeaf::Named("/p".into())));
        let identified = parse_state(
            &state(serde_json::json!({"path": "/p", "device": 1, "inode": 2})),
            id,
        )
        .unwrap();
        assert!(matches!(
            identified.leaf,
            Some(RegisteredLeaf::Identified(_))
        ));
        for bad in [
            serde_json::json!({"path": "/p", "device": 1, "inode": null}),
            serde_json::json!({"path": "/p", "device": null}),
            serde_json::json!({"path": null, "device": null, "inode": null}),
        ] {
            assert!(parse_state(&state(bad.clone()), id).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_intent_record_is_a_verification_and_finished_is_read() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let parsed = parse_state(
            &serde_json::to_vec(&serde_json::json!({
                "schema": "ukai.jail.state/1", "attempt_id": id, "os": "linux", "arch": "x86_64",
                "gc_actions": [
                    {"action": "gc_removing_cgroup", "at": "t0", "verified_empty": true,
                     "execution_cgroup": {"path": "/a", "device": 1, "inode": 2}},
                    {"action": "gc_removing_cgroup", "at": "t0", "verified_empty": true,
                     "registered": "name_only",
                     "execution_cgroup": {"path": "/b", "device": null, "inode": null}},
                    {"action": "gc_removing_cgroup", "at": "t0",
                     "execution_cgroup": {"path": "/c", "device": 1, "inode": 2}},
                    {"action": "gc_finished", "at": "t9"},
                ],
            }))
            .unwrap(),
            id,
        )
        .unwrap();
        let paths: Vec<_> = parsed
            .gc_verified
            .iter()
            .map(|leaf| leaf.path.clone())
            .collect();
        assert_eq!(paths, [std::path::PathBuf::from("/a"), "/b".into()]);
        assert_eq!(parsed.gc_finished.as_deref(), Some("t9"));
        assert_eq!(parsed.attempt_id, id);
    }
}
