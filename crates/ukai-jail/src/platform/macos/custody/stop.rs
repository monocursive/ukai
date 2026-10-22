//! The stop machine (jail-macos §4.5): guard, freeze, kill, drain.
//!
//! # Safety (the drain proof, §4.5)
//!
//! [`StopMachine::tick`] returns [`StopResult::Drained`] only when the
//! membership table is empty **and** the stream has never gapped **and** no
//! integrity loss was seen. A gap or an integrity loss vetoes `Drained` even
//! with an empty table: ES delivers a client's messages strictly serially in
//! enqueue order, and a fork's message is enqueued inside the fork, so an
//! empty table with a contiguous stream means every descendant was reported
//! and has exited. A gapped stream can hide a live descendant behind the
//! dropped messages, so `NotDrained::Gap` is the only honest answer. The
//! property is tested in `macos_custody_core.rs` ("never drained under a gap
//! or integrity flag, even with an empty table").
//!
//! # Liveness
//!
//! Time never comes from a clock inside the core: every call takes `now_ns`,
//! so tests are deterministic and the budget is exactly what the caller
//! feeds. The settle interval (initial 20 ms) and the budget (initial 5 s)
//! are construction parameters.

use super::table::MembershipTable;

/// Signal numbers, spelled for macOS.
pub const SIGSTOP: i32 = libc::SIGSTOP;
pub const SIGKILL: i32 = libc::SIGKILL;

/// The signalling boundary: the real custodian calls the shim's
/// `proc_signal_with_audittoken` and gets the errno; tests record calls.
pub trait Signaller {
    /// Signals `sig` at the member named by the audit token; returns errno.
    fn signal(&mut self, token: &[u32; 8], sig: i32) -> i32;
}

/// Why a stop did not drain (§4.4, §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopNotDrainedReason {
    /// The custody stream gapped: a descendant can hide behind dropped
    /// messages. `tree_empty` is impossible.
    Gap,
    /// A member changed user, or the table filled: the custodian can no
    /// longer answer for the tree.
    Integrity,
    /// The stop ran past its budget: `tree_unknown`, and the custodian keeps
    /// working.
    Budget,
}

/// How a stop ended, with its counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopResult {
    Drained {
        elapsed_ns: u64,
        sweeps: u64,
        signalled: u64,
    },
    NotDrained {
        reason: StopNotDrainedReason,
        elapsed_ns: u64,
        sweeps: u64,
        signalled: u64,
    },
}

impl StopResult {
    pub fn drained(&self) -> bool {
        matches!(self, StopResult::Drained { .. })
    }

    pub fn elapsed_ns(&self) -> u64 {
        match *self {
            StopResult::Drained { elapsed_ns, .. } | StopResult::NotDrained { elapsed_ns, .. } => {
                elapsed_ns
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Not yet begun.
    Idle,
    /// Guard armed, freeze sweeps running.
    Freezing,
    /// Freeze settled; kill sweeps running.
    Killing,
    /// A result was produced; the machine answers nothing further.
    Finished,
}

/// The stop of one custodian, driven by its [`super::Custodian`].
pub struct StopMachine {
    settle_ns: u64,
    budget_ns: u64,
    start_ns: Option<u64>,
    next_sweep_ns: u64,
    phase: Phase,
    guard_active: bool,
    gap: bool,
    integrity: bool,
    sweeps: u64,
    signalled: u64,
    /// A member arrived since the previous sweep began (freeze rule: the
    /// sweep completes only when no new member has arrived).
    arrived_since_sweep: bool,
    /// Members that answered `ESRCH` with no exit event: an exec from before
    /// the guard is still unprocessed; the member is re-signalled with its
    /// new token when the exec event arrives (§4.5 step 2). Bounded by the
    /// table capacity, like the table.
    pending_exec_retries: Vec<i32>,
    resume_phase: Phase,
    finished_reason: Option<StopNotDrainedReason>,
    best_effort: bool,
}

impl StopMachine {
    /// `settle_ns` is the freeze sweep interval (initial 20 ms); `budget_ns`
    /// the stop budget (initial 5 s). `capacity` bounds the pending-retry
    /// list, preallocated here like the membership table (§4.1 rule 4).
    pub fn new(settle_ns: u64, budget_ns: u64, capacity: usize) -> Self {
        Self {
            settle_ns,
            budget_ns,
            start_ns: None,
            next_sweep_ns: 0,
            phase: Phase::Idle,
            guard_active: false,
            gap: false,
            integrity: false,
            sweeps: 0,
            signalled: 0,
            arrived_since_sweep: false,
            pending_exec_retries: Vec::with_capacity(capacity),
            resume_phase: Phase::Idle,
            finished_reason: None,
            best_effort: false,
        }
    }

    /// Configure an idle stop without replacing its sticky evidence or
    /// allocating another retry vector.
    pub fn configure(&mut self, settle_ns: u64, budget_ns: u64) {
        if self.phase == Phase::Idle {
            self.settle_ns = settle_ns;
            self.budget_ns = budget_ns;
        }
    }

    /// Extend a budget-exhausted stop in place. Its phase, evidence,
    /// original start time, counters and pending retries survive the tail.
    pub fn extend_budget(&mut self, budget_ns: u64) -> bool {
        if self.phase != Phase::Finished
            || self.finished_reason != Some(StopNotDrainedReason::Budget)
            || budget_ns <= self.budget_ns
        {
            return false;
        }
        self.budget_ns = budget_ns;
        self.phase = self.resume_phase;
        self.finished_reason = None;
        true
    }

    /// Resume signalling known members after evidence loss. This never
    /// clears the veto: completion still reports Gap/Integrity, even if all
    /// known members exit. Only the guardian uses the bounded continuation.
    pub fn continue_after_loss(&mut self, budget_ns: u64) -> bool {
        if self.phase != Phase::Finished
            || self.best_effort
            || !matches!(
                self.finished_reason,
                Some(StopNotDrainedReason::Gap | StopNotDrainedReason::Integrity)
            )
        {
            return false;
        }
        self.best_effort = true;
        self.budget_ns = budget_ns;
        self.phase = self.resume_phase;
        self.finished_reason = None;
        true
    }

    /// Exit events retire retry slots, including an ESRCH followed directly
    /// by exit (there need not be another exec).
    pub fn on_exit(&mut self, token: &[u32; 8]) {
        let pid = super::table::token_pid(token);
        self.pending_exec_retries.retain(|pending| *pending != pid);
    }

    /// Whether the stop has begun (the arrival and exec hooks act only then).
    pub fn begun(&self) -> bool {
        self.phase != Phase::Idle
    }

    /// The caller arms the guard client G′; the machine records
    /// `guard_active` (§4.5 step 1). The supervisor's stop has no guard and
    /// never calls this; safety is unaffected, liveness is weaker.
    pub fn arm_guard(&mut self) {
        if self.phase == Phase::Idle {
            self.guard_active = true;
        }
    }

    pub fn guard_active(&self) -> bool {
        self.guard_active
    }

    /// The stream gapped (from the sequence tracker or the shim's sticky
    /// flag). Sticky, and a permanent veto on `Drained`.
    pub fn mark_gap(&mut self) {
        self.gap = true;
    }

    /// An integrity loss (a setuid exec, a full table). Sticky veto.
    pub fn mark_integrity(&mut self) {
        self.integrity = true;
    }

    pub fn gap(&self) -> bool {
        self.gap
    }

    pub fn integrity(&self) -> bool {
        self.integrity
    }

    pub fn sweeps(&self) -> u64 {
        self.sweeps
    }

    pub fn signalled(&self) -> u64 {
        self.signalled
    }

    /// Starts the stop at `now_ns`, moving straight into the freeze (§4.5
    /// step 2). The guard step belongs to the caller's client setup.
    pub fn begin(&mut self, now_ns: u64) {
        if self.phase != Phase::Idle {
            return; // Repeated stop requests are idempotent, never a restart.
        }
        self.start_ns = Some(now_ns);
        self.next_sweep_ns = now_ns;
        self.phase = Phase::Freezing;
    }

    fn elapsed_ns(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.start_ns.unwrap_or(now_ns))
    }

    /// The custodian reports a newly entered member while it holds no
    /// signaller: the arrival holds the freeze open, and the next sweep
    /// signals the member. Call [`StopMachine::on_arrival`] instead when the
    /// caller can signal at once (§4.5 steps 2–3).
    pub fn note_arrival(&mut self) {
        if self.phase == Phase::Freezing || self.phase == Phase::Killing {
            self.arrived_since_sweep = true;
        }
    }

    /// The custodian reports a newly entered member. It is signalled at once
    /// (SIGSTOP in the freeze, SIGKILL from the kill on): a member that
    /// arrives mid-stop never gets to run (§4.5 steps 2–3).
    pub fn on_arrival(&mut self, token: &[u32; 8], signaller: &mut dyn Signaller) {
        if self.phase != Phase::Freezing && self.phase != Phase::Killing {
            return;
        }
        let sig = match self.phase {
            Phase::Freezing => SIGSTOP,
            _ => SIGKILL,
        };
        self.arrived_since_sweep = true;
        self.signalled = self.signalled.saturating_add(1);
        let errno = signaller.signal(token, sig);
        if errno == libc::ESRCH {
            self.note_esrch(token);
        }
    }

    /// The custodian reports a member's exec. If the member answered `ESRCH`
    /// during the stop — an exec from before the guard still unprocessed —
    /// it is re-signalled now, with the new token (§4.5 step 2). Either way
    /// a freshly execed member is not stopped, so the freeze keeps sweeping.
    pub fn on_exec(&mut self, token: &[u32; 8], signaller: &mut dyn Signaller) {
        if self.phase != Phase::Freezing && self.phase != Phase::Killing {
            return;
        }
        let pid = super::table::token_pid(token);
        if let Some(index) = self
            .pending_exec_retries
            .iter()
            .position(|pending| *pending == pid)
        {
            self.pending_exec_retries.swap_remove(index);
            self.signalled = self.signalled.saturating_add(1);
            let sig = match self.phase {
                Phase::Freezing => SIGSTOP,
                _ => SIGKILL,
            };
            let errno = signaller.signal(token, sig);
            if errno == libc::ESRCH {
                self.note_esrch(token);
            }
        }
    }

    /// `ESRCH` for a member with no exit event (§4.5 step 2): an unprocessed
    /// exec is pending. The member is retried when its exec event arrives.
    pub fn note_esrch(&mut self, token: &[u32; 8]) {
        let pid = super::table::token_pid(token);
        if !self.pending_exec_retries.contains(&pid) {
            if self.pending_exec_retries.len() < self.pending_exec_retries.capacity() {
                self.pending_exec_retries.push(pid);
            } else {
                // More pending retries than members cannot happen below the
                // per-user process limit; treat it as an integrity loss
                // rather than grow (§4.1 rule 4).
                self.integrity = true;
            }
        }
    }

    fn sweep(&mut self, table: &mut MembershipTable, signaller: &mut dyn Signaller, sig: i32) {
        self.sweeps = self.sweeps.saturating_add(1);
        let freeze = sig == SIGSTOP;
        if freeze {
            table.mark_all_unstopped();
        }
        for index in 0..table.slot_count() {
            let Some(token) = table
                .entry_at(index)
                .filter(|entry| entry.live)
                .map(|entry| entry.token)
            else {
                continue;
            };
            self.signalled = self.signalled.saturating_add(1);
            match signaller.signal(&token, sig) {
                0 if freeze => {
                    // The sweep's SIGSTOP landed: the member is stopped.
                    table.mark_stopped(&token);
                }
                libc::ESRCH => {
                    // No exit event for this member: an exec from before the
                    // guard is still unprocessed; the member is re-signalled
                    // with its new token when the exec event arrives (§4.5
                    // step 2).
                    self.note_esrch(&token);
                }
                _ => {}
            }
        }
    }

    /// Advances the stop at `now_ns`; `Some(result)` ends it.
    ///
    /// The drain check runs first and vetoes on the gap and integrity flags
    /// even when the table is empty — the safety claim of §4.5.
    pub fn tick(
        &mut self,
        now_ns: u64,
        table: &mut MembershipTable,
        signaller: &mut dyn Signaller,
    ) -> Option<StopResult> {
        if self.phase == Phase::Idle || self.phase == Phase::Finished {
            return None;
        }
        let elapsed = self.elapsed_ns(now_ns);
        // The drain condition (§4.5 step 4): an empty table, a contiguous
        // stream and no user change. The gap and integrity vetoes come
        // first — a gapped stream can hold a live descendant no exit event
        // will ever name, and a user change means the custodian can no
        // longer answer for the tree — even with an empty table.
        let loss = if self.gap {
            Some(StopNotDrainedReason::Gap)
        } else if self.integrity {
            Some(StopNotDrainedReason::Integrity)
        } else {
            None
        };
        if let Some(reason) = loss
            && (!self.best_effort || table.live_count() == 0 || elapsed >= self.budget_ns)
        {
            return Some(self.finish(reason, elapsed));
        }
        if table.live_count() == 0 {
            if !table.root_entered() {
                self.mark_gap();
                return Some(self.finish(StopNotDrainedReason::Gap, elapsed));
            }
            self.phase = Phase::Finished;
            return Some(StopResult::Drained {
                elapsed_ns: elapsed,
                sweeps: self.sweeps,
                signalled: self.signalled,
            });
        }
        if elapsed >= self.budget_ns {
            return Some(self.finish(StopNotDrainedReason::Budget, elapsed));
        }
        match self.phase {
            Phase::Freezing => {
                if now_ns >= self.next_sweep_ns {
                    self.sweep(table, signaller, SIGSTOP);
                    // A full sweep finds every member stopped and no new
                    // member has arrived since the previous sweep (§4.5
                    // step 2): the freeze ends. Arrivals since the previous
                    // sweep reset only after they have vetoed completion.
                    let settled = !self.arrived_since_sweep && table.all_stopped();
                    self.arrived_since_sweep = false;
                    if settled {
                        self.phase = Phase::Killing;
                    }
                    self.next_sweep_ns = now_ns.saturating_add(self.settle_ns);
                }
            }
            Phase::Killing => {
                if now_ns >= self.next_sweep_ns {
                    self.sweep(table, signaller, SIGKILL);
                    self.next_sweep_ns = now_ns.saturating_add(self.settle_ns);
                }
            }
            Phase::Idle | Phase::Finished => {}
        }
        None
    }

    fn finish(&mut self, reason: StopNotDrainedReason, elapsed: u64) -> StopResult {
        self.resume_phase = self.phase;
        self.phase = Phase::Finished;
        self.finished_reason = Some(reason);
        StopResult::NotDrained {
            reason,
            elapsed_ns: elapsed,
            sweeps: self.sweeps,
            signalled: self.signalled,
        }
    }
}
