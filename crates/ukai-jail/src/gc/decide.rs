//! The decision, pure: [`Facts`] in, the next probe or a [`Decision`] out.
//! Every "may gc touch this" rule lives here and is tested without a host.

use super::host::{
    GuardianRecord, HostIdentity, LeafProbe, LeafRecord, Liveness, OwnerRecord, TargetToken,
};
use super::view::{LeafSource, ReceiptView, StateView, recorded_leaf};
use crate::records::Os;

/// Everything `gc` knows about one leased attempt when it decides.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Facts {
    /// Who is asking.
    pub host: HostIdentity,
    /// Jail state, or why it is corrupt.
    pub state: Result<StateView, String>,
    /// The last receipt (`None`: none was written), or why it is corrupt.
    pub receipt: Result<Option<ReceiptView>, String>,
    /// The owner's liveness, once [`Next::ProbeOwner`] was answered.
    pub owner: Option<Liveness>,
    /// The leaf probe, once [`Next::ProbeLeaf`] was answered.
    pub leaf: Option<LeafProbe>,
    /// J16 (jail-macos.md §4.9): the guardian's custodian record
    /// (`guardian.json`), read tolerantly — absent or corrupt means absent.
    pub guardian_record: Option<GuardianRecord>,
    /// The guardian's liveness, once [`Next::ProbeGuardian`] was answered.
    pub guardian: Option<Liveness>,
    /// The operator ran `gc --abandon ATTEMPT` for this attempt: the one
    /// explicit way out of an unverified end (§4.9).
    pub abandon: bool,
}

/// What [`decide`] needs next.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Next {
    /// Ask the host about this owner, then decide again.
    ProbeOwner(OwnerRecord),
    /// Ask the host about this leaf, then decide again.
    ProbeLeaf(LeafRecord),
    // N7
    /// Ask the host about the leaf registered by this name only, then
    /// decide again.
    ProbeNamedLeaf(std::path::PathBuf),
    /// J16 (jail-macos.md §4.9): ask the host whether the guardian is
    /// alive, then decide again.
    ProbeGuardian,
    /// Done.
    Decided(Decision),
}

/// Why an attempt is retained untouched.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Retention {
    /// The report's reason.
    pub reason: String,
    /// A state or receipt that could not be read: §6.4's failed state
    /// access, so `gc` exits 1.
    pub failed_access: bool,
}

/// What may be done with the execution cgroup.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CgroupStep {
    /// Nothing to do and nothing worth reporting.
    Nothing,
    /// Nothing to do now, and something is retained: the report says what
    /// and why (a later pass decides again).
    Report(String),
    /// J4 wave 3 (G4): nothing is, or ever will be, left for gc to do with
    /// the cgroup (removed earlier, gone, never registered, another boot's);
    /// the report says which.
    Settled(String),
    /// A populated, positively identified orphan of this boot: kill it
    /// through `cgroup.kill`, verify it empty, remove it.
    Terminate(LeafRecord),
    /// An empty, positively identified leaf: remove it.
    Remove(LeafRecord),
    // N7
    /// An empty leaf registered by name only: remove it (never kill it).
    RemoveNamed(std::path::PathBuf),
}

/// What may be done with managed scratch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScratchStep {
    /// Nothing to do: gc already removed it.
    NotApplicable,
    /// Kept; why.
    Keep(String),
    /// The tree's end is already established; how.
    Now(String),
    /// Removable once the cgroup step verifies the leaf empty.
    AfterCgroup,
}

/// What [`decide`] established about the recorded supervisor.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OwnerVerdict {
    /// Alive: the same boot, pid and birth time.
    Alive,
    /// Its liveness cannot be established; why.
    Unknown(String),
    /// Dead: another boot, no process with its pid, a reused pid, or an
    /// exited process; which.
    Dead(String),
}

impl OwnerVerdict {
    /// The report's spelling: `alive`, `unknown: <why>` or `dead: <how>`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            OwnerVerdict::Alive => "alive".to_owned(),
            OwnerVerdict::Unknown(why) => format!("unknown: {why}"),
            OwnerVerdict::Dead(how) => format!("dead: {how}"),
        }
    }
}

/// J16 (jail-macos.md §4.9): the custody step a macOS decision takes, after
/// the recorded supervisor was established dead.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CustodyStep {
    /// Not a custody question (Linux, or the attempt was settled before it).
    Nothing,
    /// Same boot, the guardian's record says `drained`: the tree's end is
    /// verified by the guardian. Cleanup is permitted, as for
    /// `gc_terminated_orphan`; the receipt is left as written.
    Verified,
    /// Same boot, no record or `not_drained`: `SIGKILL` to the receipt's
    /// recorded target, by audit token. The tree's end stays unverified
    /// (`tree_unknown`) and the vendor lease stays held.
    KillTarget(TargetToken),
    /// The operator ran `gc --abandon ATTEMPT`: the end is accepted, the
    /// lease and resources are released, the receipt is left as written and
    /// the attempt stays on disk.
    Abandoned,
}

impl CustodyStep {
    /// Whether this step proves that the resources a lost lease holds may
    /// be released: a custody the guardian verified, or an end the operator
    /// accepted. A killed target never does: the other descendants are in
    /// no record, so the end is unverified and the lease is held.
    #[must_use]
    pub fn releases_hold(&self) -> bool {
        matches!(self, CustodyStep::Verified | CustodyStep::Abandoned)
    }
}

/// What [`decide`] allows for one attempt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decision {
    /// `Some`: touch nothing (and do not resume J3 cleanup either).
    pub retain: Option<Retention>,
    /// What was established about the owner, when it was asked.
    pub owner: Option<OwnerVerdict>,
    /// The execution cgroup.
    pub cgroup: CgroupStep,
    /// Managed scratch.
    pub scratch: ScratchStep,
    /// Audit 2026-09-25-2, S4: the owner is dead, jail state never
    /// registered an execution leaf, and no receipt was ever written — so
    /// nothing was ever charged to a tree and no record claims otherwise.
    /// Only this combination may clean vendor state without a verified
    /// leaf: a receipt that exists (even one claiming an unverified tree)
    /// keeps the conservative retention.
    pub tree_never_existed: bool,
    /// J16 (jail-macos.md §4.9): the custody step, on macOS.
    pub custody: CustodyStep,
}

impl Decision {
    /// Whether the owner was established dead (J4 wave 2: what permits
    /// removing its leftover temporary files).
    #[must_use]
    pub fn owner_dead(&self) -> bool {
        matches!(self.owner, Some(OwnerVerdict::Dead(_)))
    }
}

fn retained(reason: String, failed_access: bool, owner: Option<OwnerVerdict>) -> Next {
    Next::Decided(Decision {
        retain: Some(Retention {
            reason,
            failed_access,
        }),
        owner,
        cgroup: CgroupStep::Nothing,
        scratch: ScratchStep::NotApplicable,
        tree_never_existed: false,
        custody: CustodyStep::Nothing,
    })
}

/// The basis of a scratch removal the receipt itself permits.
const RECEIPT_PROVES_END: &str = "the receipt proves the tree's end";

/// What may be done with managed scratch whatever the cgroup step allows.
#[derive(Clone, Copy)]
struct ScratchRule {
    /// The receipt records lost boundary integrity.
    integrity_lost: bool,
    /// An earlier pass removed the scratch (`gc_removed_scratch`).
    removed: bool,
    /// The receipt proves the tree's end ([`ReceiptView::proves_tree_end`]).
    proven: bool,
}

impl ScratchRule {
    /// The scratch step, given what the cgroup step alone would allow. Lost
    /// integrity keeps the scratch for explicit recovery in every boot (J4
    /// wave 3, G6); scratch gc already removed needs nothing; and a receipt
    /// that proves the tree's end lets gc remove it now, whether or not
    /// vendor state was registered: the supervisor's own removal may have
    /// stopped at its bound, and nothing else would ever finish it.
    fn or(self, unproven: ScratchStep) -> ScratchStep {
        if self.integrity_lost {
            ScratchStep::Keep("boundary integrity was lost".to_owned())
        } else if self.removed {
            ScratchStep::NotApplicable
        } else if self.proven {
            ScratchStep::Now(RECEIPT_PROVES_END.to_owned())
        } else {
            unproven
        }
    }

    /// Keeps the scratch for `reason`, unless [`ScratchRule::or`] decides.
    fn keep(self, reason: &str) -> ScratchStep {
        self.or(ScratchStep::Keep(reason.to_owned()))
    }
}

fn decided(owner: OwnerVerdict, cgroup: CgroupStep, scratch: ScratchStep) -> Next {
    decided_custody(owner, cgroup, scratch, CustodyStep::Nothing)
}

/// `decided` with a custody step (jail-macos.md §4.9).
fn decided_custody(
    owner: OwnerVerdict,
    cgroup: CgroupStep,
    scratch: ScratchStep,
    custody: CustodyStep,
) -> Next {
    Next::Decided(Decision {
        retain: None,
        owner: Some(owner),
        cgroup,
        scratch,
        tree_never_existed: false,
        custody,
    })
}

/// The macOS custody decision, after the supervisor is established dead.
/// A live or unreadable guardian retains the whole attempt, even for
/// `--abandon`. Only confirmed custodian loss permits an operator release;
/// that release stays distinct from guardian proof on every later pass.
/// Without a release or drained proof, a token signal does not verify the
/// whole tree and cannot release the vendor lease.
fn decide_macos(
    facts: &Facts,
    state: &StateView,
    receipt: Option<&ReceiptView>,
    verdict: OwnerVerdict,
    tree_verified: bool,
    scratch: ScratchRule,
) -> Next {
    // Nothing on this platform keeps an execution cgroup; the generic
    // cgroup steps do not apply.
    let no_cgroup = CgroupStep::Settled("this platform keeps no execution cgroup".to_owned());
    // The attempt is retained whole while either custodian lives. The
    // supervisor's liveness is the verdict; the guardian's is asked here.
    if facts
        .guardian_record
        .as_ref()
        .is_some_and(GuardianRecord::probeable)
    {
        let Some(guardian) = &facts.guardian else {
            return Next::ProbeGuardian;
        };
        match guardian {
            Liveness::Alive => {
                return retained(
                    "the recorded guardian is alive; it is a custodian of the attempt, so \
                     nothing is touched while it lives"
                        .to_owned(),
                    false,
                    Some(verdict),
                );
            }
            Liveness::Unknown(reason) => {
                return retained(
                    format!("the guardian's liveness is unknown ({reason})"),
                    false,
                    Some(verdict),
                );
            }
            Liveness::Gone | Liveness::Reused | Liveness::Exited => {}
        }
    }
    if facts.abandon
        && !state.custody_released
        && !facts
            .guardian_record
            .as_ref()
            .is_some_and(GuardianRecord::probeable)
    {
        return retained(
            "the guardian's identity is absent; its death cannot be confirmed in this boot"
                .to_owned(),
            false,
            Some(verdict),
        );
    }
    if facts.abandon || state.custody_abandoned {
        return decided_custody(
            verdict,
            no_cgroup,
            ScratchStep::Now("the operator abandoned the attempt".to_owned()),
            CustodyStep::Abandoned,
        );
    }
    if state.custody_released {
        return decided_custody(
            verdict,
            no_cgroup,
            scratch.keep("nothing is left to release"),
            CustodyStep::Verified,
        );
    }
    if tree_verified {
        return decided(
            verdict,
            no_cgroup,
            scratch.or(ScratchStep::Now(RECEIPT_PROVES_END.to_owned())),
        );
    }
    if receipt.is_some_and(|receipt| receipt.tree_end.integrity_lost) {
        return decided(
            verdict,
            CgroupStep::Report(
                "retained: the receipt records lost boundary integrity; the attempt is kept \
                 for explicit recovery until `gc --abandon` releases it"
                    .to_owned(),
            ),
            scratch.keep("boundary integrity was lost"),
        );
    }
    if facts
        .guardian_record
        .as_ref()
        .is_some_and(|record| record.drained == Some(true))
    {
        return decided_custody(
            verdict,
            no_cgroup,
            ScratchStep::Now("the guardian's record says the tree drained".to_owned()),
            CustodyStep::Verified,
        );
    }
    // No record, or not_drained: both custodians were lost, or the stop
    // failed. Kill the target the receipt recorded, by audit token; the
    // lease stays held, because the other descendants are in no record.
    match receipt.and_then(|receipt| receipt.target) {
        Some(target) => decided_custody(
            verdict,
            no_cgroup,
            scratch.keep("the tree's end is not verified"),
            CustodyStep::KillTarget(target),
        ),
        None => decided(
            verdict,
            CgroupStep::Report(
                "retained: the receipt records no target identity, so nothing is killed and \
                 the tree's end stays unverified"
                    .to_owned(),
            ),
            scratch.keep("the tree's end is not verified"),
        ),
    }
}

/// `decided` with the S4 fact: see [`Decision::tree_never_existed`].
fn decided_with(
    owner: OwnerVerdict,
    cgroup: CgroupStep,
    scratch: ScratchStep,
    tree_never_existed: bool,
) -> Next {
    Next::Decided(Decision {
        retain: None,
        owner: Some(owner),
        cgroup,
        scratch,
        tree_never_existed,
        custody: CustodyStep::Nothing,
    })
}

/// Decides what `gc` may do with one attempt whose lease it holds.
///
/// Rules, in order; the first that applies decides:
/// 1. Corrupt jail state or receipt: retain everything, failed state access.
/// 2. Another OS or architecture claimed it: retain everything.
/// 3. No owner identity, no current boot, or records that disagree about the
///    boot: the cgroup is unverifiable and kept; J3 cleanup may resume.
/// 4. Another boot: its processes cannot be alive, and no cgroup at the
///    recorded path is the original, so no cgroup is probed or touched; the
///    tree ended with that boot (managed scratch may go, unless integrity
///    was lost: J4 wave 3, G6).
/// 5. This boot: ask whether the owner is alive. Alive: retain everything.
///    Unknown: the cgroup is kept. Dead: go on.
/// 6. No leaf recorded, a malformed one (its name not this attempt's
///    `ukai-<attempt id>.leaf` included: J4 wave 3, G2), or lost integrity:
///    keep.
/// 7. A leaf an earlier pass removed: done; the tree's end was verified then.
/// 8. Ask the host about the leaf. Only the recorded cgroup itself is acted
///    on: populated and not verified empty by the supervisor, terminate and
///    remove; empty, remove. Absent after an earlier pass verified it empty:
///    done, the tree's end is verified (J4 wave 3, G3). Otherwise absent,
///    replaced or unverifiable: keep.
///
/// Managed scratch follows the cgroup step, except under rules 3 to 8 when
/// the receipt itself proves the tree's end ([`ReceiptView::proves_tree_end`]):
/// gc then removes it whatever the cgroup step, with or without vendor state
/// (the supervisor's own bounded removal may have stopped), and lost
/// integrity keeps it in every rule.
#[must_use]
pub fn decide(facts: &Facts) -> Next {
    let state = match &facts.state {
        Ok(state) => state,
        Err(reason) => {
            return retained(
                format!(
                    "corrupt jail-state.json ({reason}): quarantined by reporting; nothing is \
                     cleaned from a state gc cannot read"
                ),
                true,
                None,
            );
        }
    };
    if state.os != facts.host.os.as_str() || state.arch != facts.host.arch {
        return retained(
            format!(
                "foreign platform: the attempt was claimed on {}/{} and this is {}/{}; its \
                 resources are retained",
                state.os,
                state.arch,
                facts.host.os.as_str(),
                facts.host.arch
            ),
            false,
            None,
        );
    }
    let receipt = match &facts.receipt {
        Ok(receipt) => receipt.as_ref(),
        Err(reason) => {
            return retained(
                format!(
                    "corrupt jail.json ({reason}): quarantined by reporting; nothing is cleaned \
                     on a receipt gc cannot read"
                ),
                true,
                None,
            );
        }
    };
    // The supervisor verified the tree's end: no orphan is left to end.
    let tree_verified = receipt.is_some_and(|receipt| receipt.tree_end.verified_empty);
    // Audit 2026-09-25-2, S4: no receipt was ever written.
    let receipt_is_none = receipt.is_none();
    let source = recorded_leaf(state, receipt);
    let recorded = matches!(source, LeafSource::Recorded(_) | LeafSource::NamedOnly(_));
    // J4 wave 3 (G6): lost integrity keeps the leaf and the scratch for
    // explicit recovery in every boot, so it is read before the boot rule.
    let integrity_lost = receipt.is_some_and(|receipt| receipt.tree_end.integrity_lost);
    let scratch = ScratchRule {
        integrity_lost,
        removed: state.gc_removed_scratch,
        proven: receipt.is_some_and(ReceiptView::proves_tree_end),
    };
    // An unverified end keeps whatever scratch exists; a reason is reported.
    let keep_scratch = |reason: &str| scratch.keep(reason);
    let keep_leaf = |reason: String| {
        if recorded {
            CgroupStep::Report(format!("retained: {reason}"))
        } else {
            CgroupStep::Nothing
        }
    };
    let Some(owner) = &state.owner else {
        return decided(
            OwnerVerdict::Unknown("jail state records no owner birth identity".to_owned()),
            keep_leaf("the owner cannot be identified".to_owned()),
            keep_scratch("the tree's end is not verified"),
        );
    };
    let Some(host_boot) = &facts.host.boot_id else {
        return decided(
            OwnerVerdict::Unknown("this host's boot identity cannot be read".to_owned()),
            keep_leaf("the boot cannot be compared".to_owned()),
            keep_scratch("the tree's end is not verified"),
        );
    };
    if let Some(receipt_boot) = receipt.and_then(|receipt| receipt.boot_id.as_ref())
        && *receipt_boot != owner.boot_id
    {
        return decided(
            OwnerVerdict::Unknown("jail state and the receipt name different boots".to_owned()),
            keep_leaf("the records disagree about the boot, so no cgroup is identified".to_owned()),
            keep_scratch("the tree's end is not verified"),
        );
    }
    if owner.boot_id != *host_boot {
        // J16 (jail-macos.md §4.9): an explicit abandon releases even an
        // attempt of another boot, whose §14.2 path would otherwise keep a
        // lost-integrity attempt in every boot.
        if facts.host.os == Os::Macos && (facts.abandon || state.custody_abandoned) {
            return decided_custody(
                OwnerVerdict::Dead("recorded in another boot".to_owned()),
                CgroupStep::Settled(
                    "recorded in another boot: the operator abandoned the attempt".to_owned(),
                ),
                ScratchStep::Now("the operator abandoned the attempt".to_owned()),
                CustodyStep::Abandoned,
            );
        }
        // §14.2: "After host reboot, the old processes cannot be alive, but
        // any reused cgroup path must not be treated as the original
        // resource." Nothing is asked about the leaf or the owner's pid.
        let scratch = scratch.or(ScratchStep::Now(
            "the tree ended with the boot it ran in".to_owned(),
        ));
        let text = "recorded in another boot: a cgroup at that path now is not the original \
                    resource and is never touched";
        let cgroup = match (recorded, integrity_lost) {
            (false, _) => CgroupStep::Nothing,
            (true, true) => CgroupStep::Report(format!(
                "retained: {text}; the receipt records lost boundary integrity"
            )),
            (true, false) => CgroupStep::Settled(text.to_owned()),
        };
        return decided(
            OwnerVerdict::Dead("recorded in another boot".to_owned()),
            cgroup,
            scratch,
        );
    }

    let Some(liveness) = &facts.owner else {
        return Next::ProbeOwner(owner.clone());
    };
    let owner_text = match liveness {
        Liveness::Alive => {
            return retained(
                format!(
                    "the recorded supervisor (pid {}, same boot and birth time) is alive though \
                     it holds no lease; it is the only killer while it lives, so nothing is \
                     touched",
                    owner.pid
                ),
                false,
                Some(OwnerVerdict::Alive),
            );
        }
        Liveness::Unknown(reason) => {
            return decided(
                OwnerVerdict::Unknown(reason.clone()),
                keep_leaf(format!("the owner's liveness is unknown ({reason})")),
                keep_scratch("the tree's end is not verified"),
            );
        }
        Liveness::Gone => "no process has its pid",
        Liveness::Reused => "its pid was reused (another birth time)",
        Liveness::Exited => "exited, not yet reaped",
    };
    let verdict = OwnerVerdict::Dead(owner_text.to_owned());

    // J16 (jail-macos.md §4.9): macOS custody. There is no execution
    // cgroup to verify; the tree's end is verified by the guardian's
    // record, by the receipt itself, or accepted by the operator.
    if facts.host.os == Os::Macos {
        return decide_macos(facts, state, receipt, verdict, tree_verified, scratch);
    }

    let key = match source {
        LeafSource::Recorded(leaf) => LeafKey::Identified(leaf),
        // J4 W2-S: N7
        LeafSource::NamedOnly(path) => LeafKey::Named(path),
        LeafSource::NotRecorded(reason) => {
            let cgroup = if tree_verified {
                CgroupStep::Nothing
            } else {
                CgroupStep::Settled(format!("not_recorded: {reason}"))
            };
            // Audit 2026-09-25-2, S4: with no leaf ever registered AND no
            // receipt ever written, nothing was charged to a tree and no
            // record claims otherwise — the vendor state may be cleaned. A
            // receipt, even one claiming an unverified tree, keeps the
            // retention (its claim may be the only witness of a tree this
            // state root never learned to name).
            return decided_with(
                verdict,
                cgroup,
                keep_scratch("no registered leaf verifies the tree's end"),
                receipt_is_none,
            );
        }
        LeafSource::Malformed(reason) => {
            return decided(
                verdict,
                CgroupStep::Report(format!("retained: {reason}")),
                keep_scratch("no registered leaf verifies the tree's end"),
            );
        }
    };
    if integrity_lost {
        return decided(
            verdict,
            CgroupStep::Report(
                "retained: the receipt records lost boundary integrity; the leaf is kept for \
                 explicit recovery"
                    .to_owned(),
            ),
            keep_scratch("boundary integrity was lost"),
        );
    }
    if key.removed_earlier(state) {
        return decided(
            verdict,
            CgroupStep::Settled("removed by gc earlier".to_owned()),
            scratch.or(ScratchStep::Now(key.removed_earlier_basis().to_owned())),
        );
    }
    let Some(probe) = &facts.leaf else {
        return key.probe();
    };
    match (probe, key) {
        // J4 wave 3 (G3): an earlier pass saw this leaf empty and began to
        // remove it (or killed its tree and saw it empty), and it is gone: a
        // crash or a failed record after its `rmdir` finishes here.
        (LeafProbe::Absent, key) if key.verified_earlier(state) => decided(
            verdict,
            CgroupStep::Settled(GONE_AFTER_GC.to_owned()),
            scratch.or(ScratchStep::Now(GONE_AFTER_GC.to_owned())),
        ),
        (LeafProbe::Absent, key) => decided(
            verdict,
            if tree_verified {
                CgroupStep::Nothing
            } else {
                CgroupStep::Settled(key.absent().to_owned())
            },
            keep_scratch(key.absent_scratch()),
        ),
        (LeafProbe::Replaced, LeafKey::Identified(_)) => decided(
            verdict,
            CgroupStep::Report(
                "retained: replaced; the path names another cgroup, which is never touched"
                    .to_owned(),
            ),
            keep_scratch("the recorded leaf was replaced"),
        ),
        (LeafProbe::Unverifiable(reason), LeafKey::Identified(_)) => decided(
            verdict,
            CgroupStep::Report(format!("retained: {reason}")),
            keep_scratch("the recorded leaf cannot be verified"),
        ),
        (LeafProbe::Replaced | LeafProbe::Unverifiable(_), LeafKey::Named(_)) => decided(
            verdict,
            CgroupStep::Report(format!(
                "retained: registered by name only, and {}",
                match probe {
                    LeafProbe::Unverifiable(reason) => reason.as_str(),
                    _ => "the path names another cgroup",
                }
            )),
            keep_scratch("the registered leaf cannot be verified"),
        ),
        // Nothing identifies a leaf registered by name only beyond its name
        // and place, and this attempt placed nothing in it: it is never
        // killed.
        (LeafProbe::Identified { populated: true }, LeafKey::Named(_)) => decided(
            verdict,
            CgroupStep::Report(
                "retained: registered by name only (its identity was never recorded, and \
                 this attempt placed nothing in it), yet populated: a cgroup gc cannot \
                 identify is never killed"
                    .to_owned(),
            ),
            keep_scratch("the registered leaf is populated by something else"),
        ),
        (LeafProbe::Identified { populated: true }, LeafKey::Identified(_)) if tree_verified => {
            decided(
                verdict,
                CgroupStep::Report(
                    "retained: populated after the supervisor verified the tree's end, so what \
                     is in it is not this attempt's orphan"
                        .to_owned(),
                ),
                keep_scratch("the recorded leaf is populated by something else"),
            )
        }
        (LeafProbe::Identified { populated: true }, LeafKey::Identified(leaf)) => decided(
            verdict,
            CgroupStep::Terminate(leaf),
            ScratchStep::AfterCgroup,
        ),
        (LeafProbe::Identified { populated: false }, key) => {
            decided(verdict, key.removal(), scratch.or(ScratchStep::AfterCgroup))
        }
    }
}

/// The report of a leaf an earlier pass verified empty that is now gone.
const GONE_AFTER_GC: &str = "removed: gone after an earlier gc verified it empty \
                             (gc_terminated_orphan or gc_removing_cgroup), so the tree's end \
                             is verified";

/// The registered execution leaf [`decide`] acts on.
enum LeafKey {
    /// Identified right after `mkdir`, before anything was placed in it.
    Identified(LeafRecord),
    /// N7: registered by name only. The supervisor died between naming it
    /// (P15) and identifying it (P16), before anything could be placed in
    /// it: an empty one is removed, a populated one (which this attempt never
    /// put there) is retained, and it is never killed.
    Named(std::path::PathBuf),
}

impl LeafKey {
    /// Whether an earlier pass removed it (`gc_removed_cgroup`).
    fn removed_earlier(&self, state: &StateView) -> bool {
        match self {
            LeafKey::Identified(leaf) => state.gc_removed.contains(leaf),
            LeafKey::Named(path) => state.gc_removed.iter().any(|leaf| leaf.path == *path),
        }
    }

    /// The scratch basis of a leaf an earlier pass removed.
    fn removed_earlier_basis(&self) -> &'static str {
        match self {
            LeafKey::Identified(_) => "an earlier gc verified the leaf empty and removed it",
            LeafKey::Named(_) => "an earlier gc removed the leaf registered by name only, empty",
        }
    }

    /// Whether an earlier pass verified it empty (J4 wave 3, G3).
    fn verified_earlier(&self, state: &StateView) -> bool {
        match self {
            LeafKey::Identified(leaf) => state
                .gc_verified
                .iter()
                .any(|verified| verified.is_of(leaf)),
            LeafKey::Named(path) => state
                .gc_verified
                .iter()
                .any(|verified| verified.path == *path),
        }
    }

    /// The question to ask the host about it.
    fn probe(self) -> Next {
        match self {
            LeafKey::Identified(leaf) => Next::ProbeLeaf(leaf),
            LeafKey::Named(path) => Next::ProbeNamedLeaf(path),
        }
    }

    /// The report of a leaf that is absent.
    fn absent(&self) -> &'static str {
        match self {
            LeafKey::Identified(_) => {
                "absent: the recorded leaf no longer exists, so the tree's end cannot be verified \
                 through it"
            }
            LeafKey::Named(_) => {
                "absent: registered by name before its creation, and no cgroup of that name exists"
            }
        }
    }

    /// Why scratch is kept when the leaf is absent.
    fn absent_scratch(&self) -> &'static str {
        match self {
            LeafKey::Identified(_) => "the recorded leaf is gone",
            LeafKey::Named(_) => "the registered leaf does not exist",
        }
    }

    /// The removal of an empty one.
    fn removal(self) -> CgroupStep {
        match self {
            LeafKey::Identified(leaf) => CgroupStep::Remove(leaf),
            LeafKey::Named(path) => CgroupStep::RemoveNamed(path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gc::leaf_name_of;
    use crate::gc::view::{RegisteredLeaf, VerifiedLeaf};
    use crate::records::Os;

    /// Audit 2026-09-25-2, S4: only an owner established dead with no leaf
    /// ever registered and no receipt ever written proves nothing was ever
    /// charged to a tree; a leaf, a live or unknown owner, or another boot's
    /// claim each withdraw the proof.
    #[test]
    fn only_a_dead_owner_with_no_leaf_and_no_receipt_never_charged_a_tree() {
        let mut no_leaf = state();
        no_leaf.leaf = None;
        let mut never = facts(no_leaf.clone(), receipt(None));
        never.receipt = Ok(None);
        assert!(decision(decide(&never)).tree_never_existed);
        let mut with_leaf = never.clone();
        with_leaf.state = Ok(state());
        with_leaf.leaf = Some(LeafProbe::Absent);
        assert!(!decision(decide(&with_leaf)).tree_never_existed);
        let mut unknown = never.clone();
        unknown.owner = Some(Liveness::Unknown("x".to_owned()));
        assert!(!decision(decide(&unknown)).tree_never_existed);
        let mut alive = never.clone();
        alive.owner = Some(Liveness::Alive);
        assert!(!decision(decide(&alive)).tree_never_existed);
        let mut other_boot = never;
        other_boot.host.boot_id = Some("boot-b".to_owned());
        assert!(!decision(decide(&other_boot)).tree_never_existed);
    }

    const BOOT: &str = "boot-a";

    fn host() -> HostIdentity {
        HostIdentity {
            os: Os::Linux,
            arch: "x86_64".to_owned(),
            boot_id: Some(BOOT.to_owned()),
        }
    }

    fn leaf() -> LeafRecord {
        LeafRecord {
            path: "/sys/fs/cgroup/x/ukai-att_00000000-0000-4000-8000-000000000001.leaf".into(),
            device: 1,
            inode: 2,
        }
    }

    pub(super) fn state() -> StateView {
        StateView {
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
            owner: Some(OwnerRecord {
                pid: 77,
                boot_id: BOOT.to_owned(),
                start_time_ticks: 5,
            }),
            leaf: Some(RegisteredLeaf::Identified(leaf())),
            gc_removed: Vec::new(),
            gc_verified: Vec::new(),
            gc_removed_scratch: false,
            custody_released: false,
            custody_abandoned: false,
            gc_finished: None,
        }
    }

    pub(super) fn receipt(tree_empty: Option<bool>) -> ReceiptView {
        ReceiptView {
            phase: crate::records::Phase::Enforced,
            tree_end: crate::lifecycle::TreeEnd::from_text(
                crate::lifecycle::Integrity::Verified.as_str(),
                crate::lifecycle::BoundaryKind::PidNamespace.as_str(),
                tree_empty,
            ),
            boot_id: Some(BOOT.to_owned()),
            leaf: LeafSource::Recorded(leaf()),
            target: None,
        }
    }

    pub(super) fn facts(state: StateView, receipt: ReceiptView) -> Facts {
        Facts {
            host: host(),
            state: Ok(state),
            receipt: Ok(Some(receipt)),
            owner: Some(Liveness::Gone),
            leaf: Some(LeafProbe::Identified { populated: true }),
            guardian_record: None,
            guardian: None,
            abandon: false,
        }
    }

    pub(super) fn decision(next: Next) -> Decision {
        match next {
            Next::Decided(decision) => decision,
            other => panic!("not decided: {other:?}"),
        }
    }

    #[test]
    fn only_a_dead_owners_identified_populated_unverified_leaf_is_terminated() {
        let base = facts(state(), receipt(None));
        assert_eq!(
            decision(decide(&base)).cgroup,
            CgroupStep::Terminate(leaf())
        );
        // Each precondition, removed, leaves nothing to terminate.
        let mut alive = base.clone();
        alive.owner = Some(Liveness::Alive);
        assert!(decision(decide(&alive)).retain.is_some());
        let mut verified = base.clone();
        verified.receipt = Ok(Some(receipt(Some(true))));
        assert!(matches!(
            decision(decide(&verified)).cgroup,
            CgroupStep::Report(_)
        ));
        for probe in [
            LeafProbe::Absent,
            LeafProbe::Replaced,
            LeafProbe::Unverifiable("x".to_owned()),
        ] {
            let mut other = base.clone();
            other.leaf = Some(probe);
            assert!(matches!(
                decision(decide(&other)).cgroup,
                CgroupStep::Report(_) | CgroupStep::Settled(_)
            ));
        }
        let mut lost = base.clone();
        let mut lost_receipt = receipt(None);
        lost_receipt.tree_end.integrity_lost = true;
        lost.receipt = Ok(Some(lost_receipt));
        assert!(matches!(
            decision(decide(&lost)).cgroup,
            CgroupStep::Report(_)
        ));
    }

    #[test]
    fn nothing_is_probed_before_it_is_needed() {
        let mut unprobed = facts(state(), receipt(None));
        unprobed.owner = None;
        unprobed.leaf = None;
        assert!(matches!(decide(&unprobed), Next::ProbeOwner(_)));
        unprobed.owner = Some(Liveness::Reused);
        assert_eq!(decide(&unprobed), Next::ProbeLeaf(leaf()));
        // Another boot: neither probe, whatever the answers would be.
        let mut other_boot = facts(state(), receipt(None));
        other_boot.owner = None;
        other_boot.leaf = None;
        other_boot.host.boot_id = Some("boot-b".to_owned());
        let decided = decision(decide(&other_boot));
        assert!(matches!(decided.cgroup, CgroupStep::Settled(_)));
        assert!(matches!(decided.scratch, ScratchStep::Now(_)));
    }

    #[test]
    fn disagreeing_or_missing_identities_never_reach_the_leaf() {
        let mut disagree = facts(state(), receipt(None));
        disagree.receipt = Ok(Some(ReceiptView {
            boot_id: Some("boot-b".to_owned()),
            ..receipt(None)
        }));
        assert!(matches!(
            decision(decide(&disagree)).cgroup,
            CgroupStep::Report(_)
        ));
        let mut no_boot = facts(state(), receipt(None));
        no_boot.host.boot_id = None;
        assert!(matches!(
            decision(decide(&no_boot)).cgroup,
            CgroupStep::Report(_)
        ));
        let mut no_owner = facts(state(), receipt(None));
        no_owner.state = Ok(StateView {
            owner: None,
            ..state()
        });
        assert!(matches!(
            decision(decide(&no_owner)).cgroup,
            CgroupStep::Report(_)
        ));
        let mut unknown = facts(state(), receipt(None));
        unknown.owner = Some(Liveness::Unknown("x".to_owned()));
        assert!(matches!(
            decision(decide(&unknown)).cgroup,
            CgroupStep::Report(_)
        ));
    }

    #[test]
    fn a_leaf_gc_removed_is_never_probed_again() {
        let mut again = facts(
            StateView {
                gc_removed: vec![leaf()],
                ..state()
            },
            receipt(None),
        );
        again.leaf = None;
        let decided = decision(decide(&again));
        assert_eq!(
            decided.cgroup,
            CgroupStep::Settled("removed by gc earlier".to_owned())
        );
        assert!(matches!(decided.scratch, ScratchStep::Now(_)));
    }

    // N7
    #[test]
    fn the_leaf_comes_from_jail_state_and_must_agree_with_the_receipt() {
        let base = facts(state(), receipt(None));
        // No receipt at all: jail state alone registers the leaf.
        let mut unreceipted = base.clone();
        unreceipted.receipt = Ok(None);
        assert_eq!(
            decision(decide(&unreceipted)).cgroup,
            CgroupStep::Terminate(leaf())
        );
        // A receipt alone is not a registration.
        let mut receipt_only = base.clone();
        receipt_only.state = Ok(StateView {
            leaf: None,
            ..state()
        });
        assert!(matches!(
            decision(decide(&receipt_only)).cgroup,
            CgroupStep::Settled(text) if text.starts_with("not_recorded")
        ));
        // Disagreeing records are retained, never probed.
        let mut disagree = base.clone();
        disagree.leaf = None;
        disagree.state = Ok(StateView {
            leaf: Some(RegisteredLeaf::Identified(LeafRecord {
                inode: 3,
                ..leaf()
            })),
            ..state()
        });
        assert!(matches!(
            decision(decide(&disagree)).cgroup,
            CgroupStep::Report(text) if text.contains("different")
        ));
    }

    #[test]
    fn a_leaf_named_only_is_removed_when_empty_and_never_killed() {
        let named = |probe: Option<LeafProbe>| {
            let mut facts = facts(
                StateView {
                    leaf: Some(RegisteredLeaf::Named(leaf().path)),
                    ..state()
                },
                receipt(None),
            );
            facts.receipt = Ok(None);
            facts.leaf = probe;
            facts
        };
        assert_eq!(decide(&named(None)), Next::ProbeNamedLeaf(leaf().path));
        assert_eq!(
            decision(decide(&named(Some(LeafProbe::Identified {
                populated: false
            }))))
            .cgroup,
            CgroupStep::RemoveNamed(leaf().path)
        );
        for probe in [
            LeafProbe::Identified { populated: true },
            LeafProbe::Absent,
            LeafProbe::Replaced,
            LeafProbe::Unverifiable("x".to_owned()),
        ] {
            let decided = decision(decide(&named(Some(probe.clone()))));
            assert!(
                matches!(
                    decided.cgroup,
                    CgroupStep::Report(_) | CgroupStep::Settled(_)
                ),
                "{probe:?}: {decided:?}"
            );
        }
        // Removed by an earlier pass: never probed again.
        let mut again = named(None);
        again.state = Ok(StateView {
            leaf: Some(RegisteredLeaf::Named(leaf().path)),
            gc_removed: vec![leaf()],
            ..state()
        });
        assert_eq!(
            decision(decide(&again)).cgroup,
            CgroupStep::Settled("removed by gc earlier".to_owned())
        );
    }

    #[test]
    fn a_registration_of_another_attempts_leaf_is_never_probed() {
        for registered in [
            RegisteredLeaf::Identified(LeafRecord {
                path: "/sys/fs/cgroup/x/ukai-att_00000000-0000-4000-8000-000000000002.leaf".into(),
                ..leaf()
            }),
            RegisteredLeaf::Named(
                "/sys/fs/cgroup/x/ukai-att_00000000-0000-4000-8000-000000000002.leaf".into(),
            ),
            RegisteredLeaf::Named("/sys/fs/cgroup/x/app.slice".into()),
        ] {
            let mut facts = facts(
                StateView {
                    leaf: Some(registered.clone()),
                    ..state()
                },
                receipt(None),
            );
            facts.receipt = Ok(None);
            facts.leaf = None;
            let decided = decision(decide(&facts));
            assert!(
                matches!(&decided.cgroup, CgroupStep::Report(text) if text.contains("not this attempt's")),
                "{registered:?}: {decided:?}"
            );
        }
    }

    #[test]
    fn a_leaf_gone_after_gc_saw_it_empty_verifies_the_tree() {
        for verified in [
            VerifiedLeaf::from(leaf()),
            VerifiedLeaf {
                path: leaf().path,
                identity: None,
            },
        ] {
            let named = verified.identity.is_none();
            let mut facts = facts(
                StateView {
                    leaf: Some(if named {
                        RegisteredLeaf::Named(leaf().path)
                    } else {
                        RegisteredLeaf::Identified(leaf())
                    }),
                    gc_verified: vec![verified],
                    ..state()
                },
                receipt(None),
            );
            facts.receipt = Ok(None);
            facts.leaf = Some(LeafProbe::Absent);
            let decided = decision(decide(&facts));
            assert!(
                matches!(decided.cgroup, CgroupStep::Settled(_)),
                "{decided:?}"
            );
            assert!(
                matches!(decided.scratch, ScratchStep::Now(_)),
                "{decided:?}"
            );
        }
        // Without gc's record, a gone leaf verifies nothing.
        let decided = decision(decide(&Facts {
            leaf: Some(LeafProbe::Absent),
            ..facts(state(), receipt(None))
        }));
        assert!(
            matches!(decided.scratch, ScratchStep::Keep(_)),
            "{decided:?}"
        );
    }

    #[test]
    fn s4_abandon_never_changes_linux_decisions() {
        for boot in ["boot-a", "boot-b"] {
            let mut lost = receipt(None);
            lost.tree_end.integrity_lost = true;
            let mut baseline = facts(state(), lost);
            baseline.host.boot_id = Some(boot.to_owned());
            let mut abandon = baseline.clone();
            abandon.abandon = true;
            assert_eq!(decide(&baseline), decide(&abandon));
        }
    }

    #[test]
    fn lost_integrity_keeps_scratch_in_another_boot_too() {
        let mut lost = receipt(None);
        lost.tree_end.integrity_lost = true;
        let mut facts = facts(state(), lost);
        facts.host.boot_id = Some("boot-b".to_owned());
        facts.owner = None;
        facts.leaf = None;
        let decided = decision(decide(&facts));
        assert!(
            matches!(decided.scratch, ScratchStep::Keep(_)),
            "{decided:?}"
        );
        assert!(
            matches!(decided.cgroup, CgroupStep::Report(_)),
            "{decided:?}"
        );
    }

    /// G2: `receipt_is_none` in the tree-never-existed test. Without it gc
    /// treats a dead owner's enforced receipt as if none had been written and
    /// cleans the vendor state, though the receipt may be the only witness of
    /// a tree this state root never learned to name (audit 2026-09-25-2, S4).
    #[test]
    fn an_enforced_receipt_is_not_a_tree_that_never_existed() {
        let mut no_leaf = state();
        no_leaf.leaf = None;
        let mut enforced = receipt(None);
        enforced.leaf =
            LeafSource::NotRecorded("the receipt registers no execution cgroup".to_owned());
        // Dead owner, no registered leaf, an enforced receipt: the receipt
        // withdraws the proof, whatever it claims about the tree.
        let decided = decision(decide(&facts(no_leaf.clone(), enforced)));
        assert!(
            !decided.tree_never_existed,
            "an enforced receipt keeps the vendor state (audit 2026-09-25-2, S4)"
        );
        assert!(decided.retain.is_none());
        assert!(
            matches!(decided.scratch, ScratchStep::Keep(_)),
            "{:?}",
            decided.scratch
        );
        // The same state with no receipt at all is the tree-never-existed
        // case, and it still cleans.
        let mut facts_none = facts(no_leaf, receipt(None));
        facts_none.receipt = Ok(None);
        let decided = decision(decide(&facts_none));
        assert!(decided.tree_never_existed, "{decided:?}");
        assert!(decided.retain.is_none());
    }

    /// G4: lost boundary integrity retains a name-only leaf's scratch, like
    /// an identified leaf's, for explicit recovery.
    #[test]
    fn lost_integrity_retains_a_name_only_leafs_scratch() {
        let own = leaf_name_of("att_00000000-0000-4000-8000-000000000001");
        let mut named = state();
        named.leaf = Some(RegisteredLeaf::Named(
            std::path::Path::new("/sys/fs/cgroup/x").join(&own),
        ));
        let mut lost = receipt(None);
        lost.tree_end.integrity_lost = true;
        lost.leaf = LeafSource::NotRecorded("the receipt registers no execution cgroup".to_owned());
        let decided = decision(decide(&facts(named, lost)));
        assert!(
            matches!(decided.cgroup, CgroupStep::Report(_)),
            "{:?}",
            decided.cgroup
        );
        assert!(
            matches!(decided.scratch, ScratchStep::Keep(_)),
            "lost integrity keeps the scratch of a name-only leaf too: {:?}",
            decided.scratch
        );
    }
}

/// J16 (jail-macos.md §4.9): the macOS custody arms, driven through the
/// same pure [`decide`] with macOS-shaped facts. Portable: both lanes run
/// these.
#[cfg(test)]
mod macos_tests {
    use super::tests::{decision, facts, receipt, state};
    use super::*;

    const SESSION: &str = "boot-session-a";

    fn macos_host() -> HostIdentity {
        HostIdentity {
            os: Os::Macos,
            arch: "aarch64".to_owned(),
            boot_id: Some(SESSION.to_owned()),
        }
    }

    /// A macOS claim: same shape the supervisor writes, no cgroup, the
    /// owner's start in epoch seconds (pbi_start_tvsec).
    fn macos_state() -> StateView {
        StateView {
            attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
            os: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            owner: Some(OwnerRecord {
                pid: 77,
                boot_id: SESSION.to_owned(),
                start_time_ticks: 1_700_000_000,
            }),
            leaf: None,
            gc_removed: Vec::new(),
            gc_verified: Vec::new(),
            gc_removed_scratch: false,
            custody_released: false,
            custody_abandoned: false,
            gc_finished: None,
        }
    }

    /// A macOS receipt: native custody, `tree_unknown`, and the target's
    /// recorded audit-token identity.
    fn macos_receipt() -> ReceiptView {
        ReceiptView {
            phase: crate::records::Phase::Enforced,
            tree_end: crate::lifecycle::TreeEnd::from_text(
                crate::lifecycle::Integrity::Verified.as_str(),
                crate::lifecycle::BoundaryKind::NativeTree.as_str(),
                None,
            ),
            boot_id: Some(SESSION.to_owned()),
            leaf: LeafSource::NotRecorded("macos".to_owned()),
            target: Some(TargetToken {
                pid: 4242,
                pidversion: 91,
            }),
        }
    }

    fn macos_facts() -> Facts {
        let mut base = facts(macos_state(), macos_receipt());
        base.host = macos_host();
        base.guardian_record = Some(GuardianRecord {
            pid: Some(88),
            pidversion: Some(17),
            boot_session: Some(SESSION.to_owned()),
            drained: Some(false),
        });
        base.guardian = Some(Liveness::Gone);
        base.leaf = None;
        base
    }

    #[test]
    fn same_boot_with_a_drained_record_verifies_custody() {
        let mut drained = macos_facts();
        drained.guardian_record.as_mut().unwrap().drained = Some(true);
        let decided = decision(decide(&drained));
        assert_eq!(decided.custody, CustodyStep::Verified);
        assert!(decided.custody.releases_hold());
        assert!(!decided.owner_dead() || decided.retain.is_none());
    }

    #[test]
    fn same_boot_without_a_drained_record_kills_the_recorded_target() {
        let decided = decision(decide(&macos_facts()));
        assert_eq!(
            decided.custody,
            CustodyStep::KillTarget(TargetToken {
                pid: 4242,
                pidversion: 91
            })
        );
        assert!(!decided.custody.releases_hold(), "the lease stays held");
    }

    #[test]
    fn a_receipt_without_a_target_identity_is_retained_whole() {
        let mut no_target = macos_facts();
        no_target.receipt = Ok(Some(ReceiptView {
            target: None,
            ..macos_receipt()
        }));
        let decided = decision(decide(&no_target));
        // Nothing is killed and the end stays unverified: the lease is held.
        assert!(matches!(decided.cgroup, CgroupStep::Report(_)));
        assert_eq!(decided.custody, CustodyStep::Nothing);
    }

    #[test]
    fn abandon_releases_after_both_custodians_are_gone() {
        let decided = decision(decide(&macos_facts()));
        assert!(matches!(decided.custody, CustodyStep::KillTarget(_)));
        let mut abandoned = macos_facts();
        abandoned.abandon = true;
        let decided = decision(decide(&abandoned));
        assert_eq!(decided.custody, CustodyStep::Abandoned);
        assert!(decided.custody.releases_hold());
    }

    #[test]
    fn a_live_or_unreadable_guardian_retains_the_attempt() {
        let mut alive = macos_facts();
        alive.guardian = Some(Liveness::Alive);
        assert!(decision(decide(&alive)).retain.is_some());
        let mut unknown = macos_facts();
        unknown.guardian = Some(Liveness::Unknown("cannot read".to_owned()));
        let decided = decision(decide(&unknown));
        assert!(decided.retain.is_some() || matches!(decided.cgroup, CgroupStep::Report(_)));
    }

    #[test]
    fn the_guardian_is_probed_only_when_a_record_can_name_one() {
        let mut unprobed = macos_facts();
        unprobed.guardian = None;
        assert_eq!(decide(&unprobed), Next::ProbeGuardian);
        let mut no_record = macos_facts();
        no_record.guardian_record = None;
        no_record.guardian = None;
        // A lost guardian (no record) with a target to kill.
        assert!(matches!(
            decision(decide(&no_record)).custody,
            CustodyStep::KillTarget(_)
        ));
    }

    #[test]
    fn a_receipt_proving_the_trees_end_is_left_alone() {
        let mut settled = macos_facts();
        settled.receipt = Ok(Some(ReceiptView {
            tree_end: crate::lifecycle::TreeEnd::from_text(
                crate::lifecycle::Integrity::Verified.as_str(),
                crate::lifecycle::BoundaryKind::NativeTree.as_str(),
                Some(true),
            ),
            ..macos_receipt()
        }));
        let decided = decision(decide(&settled));
        assert_eq!(decided.custody, CustodyStep::Nothing);
        assert!(matches!(decided.scratch, ScratchStep::Now(_)));
    }

    #[test]
    fn another_boot_ends_the_custody_but_keeps_lost_integrity() {
        let mut other = macos_facts();
        other.host.boot_id = Some("boot-session-b".to_owned());
        let decided = decision(decide(&other));
        assert_eq!(decided.custody, CustodyStep::Nothing);
        assert!(matches!(decided.scratch, ScratchStep::Now(_)));
        // And the operator's abandon releases it even so.
        other.abandon = true;
        let decided = decision(decide(&other));
        assert_eq!(decided.custody, CustodyStep::Abandoned);
        let mut lost = macos_receipt();
        lost.tree_end.integrity_lost = true;
        let mut lost_boot = facts(macos_state(), lost);
        lost_boot.host = macos_host();
        lost_boot.host.boot_id = Some("boot-session-b".to_owned());
        assert!(matches!(
            decision(decide(&lost_boot)).scratch,
            ScratchStep::Keep(_)
        ));
        lost_boot.abandon = true;
        assert!(matches!(
            decision(decide(&lost_boot)).custody,
            CustodyStep::Abandoned
        ));
    }

    #[test]
    fn an_earlier_pass_custody_record_decides_the_same_again() {
        let mut released = macos_state();
        released.custody_released = true;
        let mut facts_released = facts(released, macos_receipt());
        facts_released.host = macos_host();
        facts_released.guardian_record = macos_facts().guardian_record;
        facts_released.guardian = Some(Liveness::Gone);
        let decided = decision(decide(&facts_released));
        assert_eq!(decided.custody, CustodyStep::Verified);
    }

    #[test]
    fn a_linux_shaped_attempt_never_reaches_the_custody_arms() {
        // The Linux facts of `tests::facts`, unchanged: the leaf machinery
        // decides, the custody step stays Nothing.
        let linux = facts(state(), receipt(None));
        let decided = decision(decide(&linux));
        assert_eq!(decided.custody, CustodyStep::Nothing);
        assert_eq!(decided.cgroup, CgroupStep::Terminate(leaf_record()));
    }

    fn leaf_record() -> LeafRecord {
        LeafRecord {
            path: "/sys/fs/cgroup/x/ukai-att_00000000-0000-4000-8000-000000000001.leaf".into(),
            device: 1,
            inode: 2,
        }
    }
}
