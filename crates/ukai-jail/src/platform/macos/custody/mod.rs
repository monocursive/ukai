//! The pure custody core (jail-macos §4.4, §4.5): sequence tracking,
//! membership and the stop machine, combined in [`Custodian`].
//!
//! # Preallocation discipline (§4.1 rule 4)
//!
//! A [`Custodian`] allocates at construction only: the membership table's
//! slots and the stop machine's pending-retry list, both bounded by the
//! capacity ([`table_capacity`] over `kern.maxprocperuid`). After
//! construction, [`Custodian::apply_event`] and [`Custodian::tick`] acquire
//! nothing: the table reuses slots on exit and reports a full table as an
//! integrity loss rather than grow, and the pending-retry list does the
//! same. Exhausting process slots or memory therefore cannot block a stop.
#![cfg(target_os = "macos")]

pub mod seq;
pub mod stop;
pub mod table;

use crate::platform::macos::es::EsEvent;

pub use seq::{CustodyKind, SeqTracker};
pub use stop::{SIGKILL, SIGSTOP, Signaller, StopMachine, StopNotDrainedReason, StopResult};
pub use table::{
    AUDIT_TOKEN_EUID, AUDIT_TOKEN_PID, AUDIT_TOKEN_PIDVERSION, AUDIT_TOKEN_RGID, AUDIT_TOKEN_RUID,
    Entry as MembershipEntry, ExecOutcome, MAX_TABLE_CAPACITY, MembershipError, MembershipTable,
    table_capacity,
};

/// Outcome of [`Custodian::apply_event`], for records and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    ForkEntered,
    ForkKnown,
    ExecReplaced,
    ExecEntered,
    /// A setuid exec (§4.4): an integrity loss.
    ExecUidChanged,
    ExitRemoved,
    /// An exit the table never held; the sequence tracker's view governs.
    ExitUnknown,
    /// A registered custodian, counted in the stream but never a member.
    CustodianIgnored,
}

/// One custodian's view: its stream sequence, its membership table and, at
/// a stop, its [`StopMachine`].
pub struct Custodian {
    seq: SeqTracker,
    table: MembershipTable,
    stop: StopMachine,
    integrity: bool,
    custodians: [Option<[u32; 8]>; 2],
}

impl Custodian {
    /// Creates the custodian with a table of `capacity` slots
    /// ([`table_capacity`] over the host's `kern.maxprocperuid`). This is
    /// the only allocation on the custody path.
    pub fn new(capacity: usize) -> Self {
        Self {
            seq: SeqTracker::new(),
            table: MembershipTable::new(capacity),
            stop: StopMachine::new(0, 0, capacity),
            integrity: false,
            custodians: [None; 2],
        }
    }

    /// The stop parameters are fixed at construction: the settle interval
    /// (initial 20 ms) and the budget (initial 5 s) of §4.5.
    pub fn with_stop(mut self, settle_ns: u64, budget_ns: u64) -> Self {
        self.stop.configure(settle_ns, budget_ns);
        self
    }

    /// Register the launcher PID before applying or replaying its events.
    /// An empty table cannot prove a drain until this root entered it.
    pub fn expect_root(&mut self, pid: i32) {
        self.table.expect_root(pid);
    }

    /// Exclude a known custodian from membership. Register its initial token
    /// before handshake replay; subsequent execs update that identity until
    /// its exit. A later PID reuse is not excluded. Two slots cover S and G.
    pub fn register_custodian(&mut self, token: [u32; 8]) -> Result<(), MembershipError> {
        let slot = self
            .custodians
            .iter()
            .position(|known| *known == Some(token))
            .or_else(|| self.custodians.iter().position(Option::is_none));
        let Some(slot) = slot else {
            self.mark_integrity();
            return Err(MembershipError::Full);
        };
        self.custodians[slot] = Some(token);
        if self.table.contains_token(&token) {
            let _ = self.table.exit(&token);
            self.stop.on_exit(&token);
        }
        Ok(())
    }

    /// Replay already-drained handshake events in original delivery order,
    /// with their sequence numbers. No allocation, filtering or reordering.
    pub fn replay_handshake(&mut self, events: &[crate::platform::macos::es::EsPoll]) {
        for event in events {
            self.apply_polled(event);
        }
    }

    pub fn apply_polled(&mut self, polled: &crate::platform::macos::es::EsPoll) -> Applied {
        use crate::platform::macos::es::{EVENT_EXEC, EVENT_EXIT, EVENT_FORK};
        let (kind, raw) = match polled.event {
            EsEvent::Fork { .. } => (CustodyKind::Fork, EVENT_FORK),
            EsEvent::Exec { .. } => (CustodyKind::Exec, EVENT_EXEC),
            EsEvent::Exit { .. } => (CustodyKind::Exit, EVENT_EXIT),
        };
        if polled.kind != raw {
            self.note_stream_gap();
        }
        self.apply_sequenced(kind, polled.global_seq, polled.seq, &polled.event)
    }

    /// The production stop path: apply the event and signal arrivals and
    /// stale-token exec retries immediately, before the next sweep.
    pub fn apply_polled_during_stop(
        &mut self,
        polled: &crate::platform::macos::es::EsPoll,
        signaller: &mut dyn Signaller,
    ) -> Applied {
        let applied = self.apply_polled(polled);
        match applied {
            Applied::ForkEntered | Applied::ExecEntered => {
                self.on_arrival(polled.event.token(), signaller)
            }
            Applied::ExecReplaced | Applied::ExecUidChanged => {
                self.on_exec_retry(polled.event.token(), signaller)
            }
            _ => {}
        }
        applied
    }

    pub fn extend_stop_budget(&mut self, budget_ns: u64) -> bool {
        self.stop.extend_budget(budget_ns)
    }

    pub fn continue_stop_after_loss(&mut self, budget_ns: u64) -> bool {
        self.stop.continue_after_loss(budget_ns)
    }

    /// Feeds one custody event from the ES stream. Never allocates: the
    /// table is preallocated and reuses slots (see the module documentation).
    pub fn apply_event(&mut self, event: &EsEvent) -> Applied {
        // §4.4: the first event naming a member enters it; exec replaces the
        // token; exit removes it and frees its slot. The sequence tracker
        // sees every message, gaps included.
        let token = event.token();
        if let Some(index) = self.custodians.iter().position(|known| {
            known.is_some_and(|known| {
                known == *token
                    || (matches!(event, EsEvent::Exec { .. })
                        && table::token_pid(&known) == table::token_pid(token))
            })
        }) {
            self.custodians[index] = if matches!(event, EsEvent::Exit { .. }) {
                None
            } else {
                Some(*token)
            };
            return Applied::CustodianIgnored;
        }
        match *event {
            EsEvent::Fork { token } if self.table.contains_token(&token) => Applied::ForkKnown,
            EsEvent::Fork { token } => match self.table.enter(token) {
                Ok(()) => {
                    self.on_entry();
                    Applied::ForkEntered
                }
                Err(MembershipError::Full) => {
                    // §4.4: a full table is an integrity loss.
                    self.mark_integrity();
                    Applied::ForkKnown
                }
                Err(_) => Applied::ForkKnown,
            },
            EsEvent::Exec { token } => match self.table.exec(token) {
                Ok(ExecOutcome::Replaced) => {
                    self.stop.note_arrival();
                    Applied::ExecReplaced
                }
                Ok(ExecOutcome::Entered) => {
                    self.stop.note_arrival();
                    Applied::ExecEntered
                }
                Ok(ExecOutcome::UidChanged) => {
                    // §4.4: the custodians can no longer signal the member.
                    self.mark_integrity();
                    Applied::ExecUidChanged
                }
                Err(_) => {
                    self.mark_integrity();
                    Applied::ExecReplaced
                }
            },
            EsEvent::Exit { token, status: _ } => match self.table.exit(&token) {
                Ok(()) => {
                    self.stop.on_exit(&token);
                    Applied::ExitRemoved
                }
                Err(_) => {
                    // An exit for a member the table never held: ES enqueues
                    // a fork's message inside the fork (§4.5 safety), so the
                    // fork's message was lost. The stream is gapped, whatever
                    // the sequence numbers say.
                    self.stop.mark_gap();
                    Applied::ExitUnknown
                }
            },
        }
    }

    /// The entry hook: a member that arrives during a stop holds the freeze
    /// open, and the caller signals it from the next tick's sweep. A caller
    /// that can signal at once uses [`Custodian::on_arrival`].
    fn on_entry(&mut self) {
        self.stop.note_arrival();
    }

    /// The caller-driven arrival of §4.5 steps 2–3: the member is signalled
    /// at once, with the caller's signaller.
    pub fn on_arrival(&mut self, token: &[u32; 8], signaller: &mut dyn Signaller) {
        self.stop.on_arrival(token, signaller);
    }

    /// The caller-driven exec of §4.5 step 2: a member that answered ESRCH
    /// during the stop is re-signalled now, with its new token.
    pub fn on_exec_retry(&mut self, token: &[u32; 8], signaller: &mut dyn Signaller) {
        self.stop.on_exec(token, signaller);
    }

    /// The shim's sticky gap flag (ring overflow or a malformed message).
    pub fn note_stream_gap(&mut self) {
        self.stop.mark_gap();
    }

    /// An integrity loss other than a setuid exec (§4.4): a full table.
    pub fn mark_integrity(&mut self) {
        self.integrity = true;
        self.stop.mark_integrity();
    }

    /// The sequenced form of [`Custodian::apply_event`]: the ES message's
    /// `global_seq_num` and per-type `seq_num` travel with the event.
    pub fn apply_sequenced(
        &mut self,
        kind: CustodyKind,
        global_seq: u64,
        seq: u64,
        event: &EsEvent,
    ) -> Applied {
        self.seq.apply(kind, global_seq, seq);
        if self.seq.gapped() {
            self.stop.mark_gap();
        }
        self.apply_event(event)
    }

    /// Arms the guard client G′ before the stop begins (§4.5 step 1); the
    /// machine records `guard_active`.
    pub fn arm_guard(&mut self) {
        self.stop.arm_guard();
    }

    /// Starts the stop at `now_ns` (§4.5 steps 2–4).
    pub fn begin_stop(&mut self, now_ns: u64) {
        self.stop.begin(now_ns);
    }

    /// Advances the stop; `Some(result)` is its end.
    pub fn tick(&mut self, now_ns: u64, signaller: &mut dyn Signaller) -> Option<StopResult> {
        self.stop.tick(now_ns, &mut self.table, signaller)
    }

    /// The sequence tracker, for records.
    pub fn seq(&self) -> &SeqTracker {
        &self.seq
    }

    /// The membership table, for records and the launch handshake.
    pub fn table(&self) -> &MembershipTable {
        &self.table
    }

    /// The membership table, mutable: only tests and the launch handshake
    /// enter members outside the event stream.
    pub fn table_mut(&mut self) -> &mut MembershipTable {
        &mut self.table
    }

    /// The stop machine, for records and tests.
    pub fn stop(&self) -> &StopMachine {
        &self.stop
    }

    /// Whether the stream has ever gapped (§4.4): a sequence jump, an
    /// invalid-version input, the shim's sticky flag, or an exit whose fork
    /// the table never held.
    pub fn gapped(&self) -> bool {
        self.seq.gapped() || self.stop.gap()
    }

    /// Whether an integrity loss was seen: a setuid exec or a full table.
    pub fn integrity_loss(&self) -> bool {
        self.integrity || self.stop.integrity()
    }

    /// Whether the table holds this exact audit token (§4.3 step 5: the
    /// guardian answers `prepared` once its table holds the launcher's token).
    pub fn contains_token(&self, token: &[u32; 8]) -> bool {
        self.table.contains_token(token)
    }

    /// Live members.
    pub fn live_count(&self) -> usize {
        self.table.live_count()
    }
}
