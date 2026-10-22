//! The membership table of a custodian (jail-macos §4.4).
//!
//! Preallocated at construction for the attempt's members — the caller
//! passes `kern.maxprocperuid` clamped by [`table_capacity`] — and never
//! resized: a slot is reused when its member exits, and a full table is an
//! integrity loss that cannot happen below the per-user process limit
//! (§4.1 rule 4, rule 6). Nothing here allocates after construction.

/// The documented clamp on `kern.maxprocperuid`. A host cannot be trusted to
/// name an unbounded table, so the capacity stops here.
pub const MAX_TABLE_CAPACITY: usize = 4096;

/// The table size for a host whose per-user process limit is
/// `maxprocperuid` (§4.1 rule 4).
pub fn table_capacity(maxprocperuid: usize) -> usize {
    maxprocperuid.clamp(1, MAX_TABLE_CAPACITY)
}

/// One member: its current audit token and process identity.
///
/// `stopped` is the stop machine's bookkeeping (frozen by a successful
/// freeze sweep); it is not part of the §4.4 membership record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub token: [u32; 8],
    pub pid: i32,
    pub pidversion: u32,
    pub live: bool,
    pub stopped: bool,
}

/// `audit_token_t` field positions, measured against the libbsm accessors on
/// the record Mac (K98: `audit_token_to_pid` → `val[5]`,
/// `audit_token_to_pidversion` → `val[7]`, `audit_token_to_ruid` → `val[0]`;
/// asserted live in `macos_custody_core.rs` against `getpid`/`getuid`).
pub const AUDIT_TOKEN_PID: usize = 5;
pub const AUDIT_TOKEN_PIDVERSION: usize = 7;
pub const AUDIT_TOKEN_RUID: usize = 0;
pub const AUDIT_TOKEN_RGID: usize = 2;

/// The PID a token names.
pub fn token_pid(token: &[u32; 8]) -> i32 {
    token[AUDIT_TOKEN_PID] as i32
}

/// The PID version a token names (replaced at every exec, §4.1 rule 3).
pub fn token_pidversion(token: &[u32; 8]) -> u32 {
    token[AUDIT_TOKEN_PIDVERSION]
}

/// The real user ID a token names.
pub fn token_ruid(token: &[u32; 8]) -> u32 {
    token[AUDIT_TOKEN_RUID]
}

/// Why an entry left the table, or why it could not be entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipError {
    /// The table is full: an integrity loss (§4.4).
    Full,
    /// The member was not in the table.
    Unknown,
}

/// Outcome of an exec against a member (§4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecOutcome {
    /// The token was replaced; the member keeps its slot.
    Replaced,
    /// The target's user ID differs from the member's: a setuid program the
    /// profile missed, an integrity loss (§4.4). The token is still
    /// recorded; signalling it is another matter, and the stop says so.
    UidChanged,
    /// The exec named a member the table had not seen: its entry.
    Entered,
}

/// The PID-keyed table of members, capacity fixed at construction.
pub struct MembershipTable {
    slots: Vec<Option<Entry>>,
}

impl MembershipTable {
    /// Preallocates `capacity` slots; the last allocation of the table.
    pub fn new(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    /// Locates the member by PID. The table is PID-keyed (§4.4): exec
    /// replaces the PID version, so a member cannot be found by its current
    /// version, and an exit frees the slot before the PID can be reused.
    fn find(&self, token: &[u32; 8]) -> Option<usize> {
        let pid = token_pid(token);
        self.slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|entry| entry.pid == pid))
    }

    /// The first event naming a member (§4.4): it enters with its token. A
    /// full table is an integrity loss; the caller must treat
    /// `Err(MembershipError::Full)` as one.
    pub fn enter(&mut self, token: [u32; 8]) -> Result<(), MembershipError> {
        if self.find(&token).is_some() {
            return Ok(());
        }
        let entry = Entry {
            token,
            pid: token_pid(&token),
            pidversion: token_pidversion(&token),
            live: true,
            stopped: false,
        };
        // Reuse a freed slot in place; grow only inside the fixed capacity.
        if let Some(slot) = self.slots.iter_mut().position(|slot| slot.is_none()) {
            self.slots[slot] = Some(entry);
            return Ok(());
        }
        if self.slots.len() < self.slots.capacity() {
            self.slots.push(Some(entry));
            debug_assert!(self.slots.len() <= self.slots.capacity());
            return Ok(());
        }
        Err(MembershipError::Full)
    }

    /// `NOTIFY_EXEC` of a member (§4.4): the token is replaced by the
    /// target's. A changed user ID is `ExecOutcome::UidChanged` (an
    /// integrity loss); a changed group ID alone is not.
    pub fn exec(&mut self, token: [u32; 8]) -> Result<ExecOutcome, MembershipError> {
        let uid = token_ruid(&token);
        match self.find(&token) {
            Some(index) => {
                let entry = self.slots[index]
                    .as_mut()
                    .expect("find returned a live index");
                let outcome = if token_ruid(&entry.token) != uid {
                    ExecOutcome::UidChanged
                } else {
                    ExecOutcome::Replaced
                };
                entry.token = token;
                entry.stopped = false;
                Ok(outcome)
            }
            None => {
                self.enter(token)?;
                Ok(ExecOutcome::Entered)
            }
        }
    }

    /// `NOTIFY_EXIT` of a member (§4.4): the member leaves and its slot is
    /// reused. `Err(Unknown)` names an exit the table never held — the
    /// sequence tracker, not the table, decides what that means.
    pub fn exit(&mut self, token: &[u32; 8]) -> Result<(), MembershipError> {
        match self.find(token) {
            Some(index) => {
                self.slots[index] = None;
                Ok(())
            }
            None => Err(MembershipError::Unknown),
        }
    }

    /// Live members, in slot order. Never allocates beyond construction.
    pub fn live(&self) -> impl Iterator<Item = &Entry> {
        self.slots
            .iter()
            .filter_map(|slot| slot.as_ref().filter(|entry| entry.live))
    }

    pub fn live_count(&self) -> usize {
        self.live().count()
    }

    /// The number of slots backing the table, live or freed.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// The entry in slot `index`, if that slot is held.
    pub fn entry_at(&self, index: usize) -> Option<&Entry> {
        self.slots.get(index).and_then(Option::as_ref)
    }

    /// Whether the table holds a member with this exact audit token.
    pub fn contains_token(&self, token: &[u32; 8]) -> bool {
        self.slots
            .iter()
            .filter_map(|slot| slot.as_ref())
            .any(|entry| entry.live && entry.token == *token)
    }

    /// The stop machine's freeze bookkeeping: marks every live member
    /// not-stopped (a `SIGCONT` the kernel delivered passes neither ES nor
    /// Seatbelt, so a resumed member is re-frozen by the next sweep, §4.5
    /// step 2).
    pub fn mark_all_unstopped(&mut self) {
        for slot in self.slots.iter_mut().filter_map(Option::as_mut) {
            slot.stopped = false;
        }
    }

    /// Whether every live member is marked stopped.
    pub fn all_stopped(&self) -> bool {
        self.live().all(|entry| entry.stopped)
    }

    /// Marks the member stopped, by token. False when the member is unknown.
    pub fn mark_stopped(&mut self, token: &[u32; 8]) -> bool {
        match self.find(token) {
            Some(index) => {
                self.slots[index]
                    .as_mut()
                    .expect("find returned a live index")
                    .stopped = true;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(pid: u32, pidversion: u32, uid: u32) -> [u32; 8] {
        let mut token = [0u32; 8];
        token[AUDIT_TOKEN_PID] = pid;
        token[AUDIT_TOKEN_PIDVERSION] = pidversion;
        token[AUDIT_TOKEN_RUID] = uid;
        token
    }

    #[test]
    fn a_slot_is_reused_after_its_member_exits() {
        let mut table = MembershipTable::new(2);
        table.enter(token(100, 1, 501)).expect("the first member");
        table.enter(token(101, 1, 501)).expect("the second member");
        assert!(table.contains_token(&token(100, 1, 501)));
        table.exit(&token(100, 1, 501)).expect("the exiting member");
        assert!(!table.contains_token(&token(100, 1, 501)));
        table.enter(token(102, 1, 501)).expect("the reused slot");
        assert_eq!(table.live_count(), 2);
        assert_eq!(table.capacity(), 2);
    }

    #[test]
    fn an_exec_replaces_the_member_token() {
        let mut table = MembershipTable::new(2);
        table.enter(token(100, 1, 501)).expect("the member");
        let execed = token(100, 2, 501);
        assert_eq!(table.exec(execed), Ok(ExecOutcome::Replaced));
        assert!(table.contains_token(&execed));
        assert!(!table.contains_token(&token(100, 1, 501)));
        assert_eq!(table.live_count(), 1);
    }

    #[test]
    fn a_setuid_exec_is_detected_as_a_uid_change() {
        let mut table = MembershipTable::new(2);
        table.enter(token(100, 1, 501)).expect("the member");
        let setuid = token(100, 2, 0);
        assert_eq!(table.exec(setuid), Ok(ExecOutcome::UidChanged));
        // The new token is recorded — the custodian can still name the member.
        assert!(table.contains_token(&setuid));
    }

    #[test]
    fn a_gid_only_change_is_not_an_integrity_loss() {
        let mut table = MembershipTable::new(2);
        table.enter(token(100, 1, 501)).expect("the member");
        let regrouped = {
            let mut token = token(100, 2, 501);
            token[AUDIT_TOKEN_RGID] = 20;
            token
        };
        assert_eq!(table.exec(regrouped), Ok(ExecOutcome::Replaced));
    }

    #[test]
    fn a_full_table_is_reported_and_never_grows() {
        let mut table = MembershipTable::new(2);
        table.enter(token(100, 1, 501)).expect("the first member");
        table.enter(token(101, 1, 501)).expect("the second member");
        assert_eq!(table.enter(token(102, 1, 501)), Err(MembershipError::Full));
        assert_eq!(table.live_count(), 2);
        // The failed entry allocated nothing: the capacity still holds two.
        assert_eq!(table.capacity(), 2);
    }

    #[test]
    fn an_exit_of_an_unknown_member_is_named() {
        let mut table = MembershipTable::new(2);
        assert_eq!(
            table.exit(&token(100, 1, 501)),
            Err(MembershipError::Unknown)
        );
    }

    #[test]
    fn table_capacity_clamps_the_host_limit() {
        assert_eq!(table_capacity(0), 1);
        assert_eq!(table_capacity(1024), 1024);
        assert_eq!(
            table_capacity(usize::MAX),
            MAX_TABLE_CAPACITY,
            "the documented clamp bounds the table"
        );
    }
}
