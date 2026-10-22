//! Custody stream sequencing (jail-macos §4.4).
//!
//! Every custody message carries `global_seq_num` overall and `seq_num` per
//! event type. ESMessage.h documents increments but no initial baseline.
//! Initial 0 or 1 is accepted (both conventions); a higher first value is
//! conservatively a gap. Drops before the first delivered value remain
//! undetectable within that ambiguity, so `contiguous` describes observed
//! continuity, not verified delivery from client creation. Root entry is an
//! independent prerequisite for a drain. Any subsequent jump —
//! missing or repeated — marks the stream `gapped` permanently for the rest
//! of the attempt. The prototype's exact rule is kept: a message too old to
//! carry the custody fields (`m->version < 4`, measured) is an
//! invalid-version input and gaps the stream.

/// The three custody event kinds (§4.1 rule 3: nothing else is subscribed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyKind {
    Fork,
    Exec,
    Exit,
}

impl CustodyKind {
    const INDEX: usize = 3;

    fn index(self) -> usize {
        match self {
            CustodyKind::Fork => 0,
            CustodyKind::Exec => 1,
            CustodyKind::Exit => 2,
        }
    }
}

/// Tracks `global_seq_num` and the per-type `seq_num` of one custody stream.
pub struct SeqTracker {
    global: Option<u64>,
    per_type: [Option<u64>; CustodyKind::INDEX],
    counts: [u64; CustodyKind::INDEX],
    gapped: bool,
}

impl SeqTracker {
    pub fn new() -> Self {
        Self {
            global: None,
            per_type: [None; CustodyKind::INDEX],
            counts: [0; CustodyKind::INDEX],
            gapped: false,
        }
    }

    /// Records one message. A jump in either sequence — forward (dropped
    /// messages) or backward (reordered, impossible per ES but never
    /// assumed) — marks the stream gapped permanently (§4.4).
    pub fn apply(&mut self, kind: CustodyKind, global_seq: u64, seq: u64) {
        if self.gapped {
            self.counts[kind.index()] = self.counts[kind.index()].saturating_add(1);
            return;
        }
        if (self.global.is_none() && global_seq > 1)
            || (self.per_type[kind.index()].is_none() && seq > 1)
        {
            self.gapped = true;
            self.counts[kind.index()] = self.counts[kind.index()].saturating_add(1);
            return;
        }
        match self.global {
            None => self.global = Some(global_seq),
            // The prototype's rule: `global_seq_num != sequence + 1` is a gap.
            Some(previous) if Some(global_seq) == previous.checked_add(1) => {
                self.global = Some(global_seq)
            }
            Some(_) => {
                self.gapped = true;
                self.counts[kind.index()] = self.counts[kind.index()].saturating_add(1);
                return;
            }
        }
        let slot = &mut self.per_type[kind.index()];
        match *slot {
            None => *slot = Some(seq),
            Some(previous) if Some(seq) == previous.checked_add(1) => *slot = Some(seq),
            Some(_) => self.gapped = true,
        }
        self.counts[kind.index()] = self.counts[kind.index()].saturating_add(1);
    }

    /// Whether the stream has ever gapped. Sticky.
    pub fn gapped(&self) -> bool {
        self.gapped
    }

    /// The safety-critical negation: no gap was ever seen.
    pub fn contiguous(&self) -> bool {
        !self.gapped
    }

    /// Events counted per kind, gaps included.
    pub fn counts(&self) -> [u64; CustodyKind::INDEX] {
        self.counts
    }
}

impl Default for SeqTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequence_ok(tracker: &mut SeqTracker) {
        tracker.apply(CustodyKind::Fork, 1, 1);
        tracker.apply(CustodyKind::Exec, 2, 1);
        tracker.apply(CustodyKind::Exit, 3, 1);
        assert!(tracker.contiguous());
        assert_eq!(tracker.counts(), [1, 1, 1]);
    }

    #[test]
    fn first_seen_initializes_and_a_clean_stream_stays_contiguous() {
        let mut tracker = SeqTracker::new();
        assert!(tracker.contiguous());
        sequence_ok(&mut tracker);
    }

    #[test]
    fn a_global_jump_marks_the_stream_gapped_permanently() {
        let mut tracker = SeqTracker::new();
        tracker.apply(CustodyKind::Fork, 1, 1);
        tracker.apply(CustodyKind::Fork, 3, 2);
        assert!(tracker.gapped());
        // Later messages, even perfectly sequenced, never clear it.
        tracker.apply(CustodyKind::Fork, 4, 3);
        assert!(tracker.gapped());
    }

    #[test]
    fn a_per_type_jump_marks_the_stream_gapped() {
        let mut tracker = SeqTracker::new();
        tracker.apply(CustodyKind::Fork, 1, 1);
        tracker.apply(CustodyKind::Exec, 2, 1);
        tracker.apply(CustodyKind::Exit, 3, 1);
        // A dropped exec: the global sequence advances by one, the exec
        // sequence by two (§4.4: a jump in either number counts dropped
        // messages).
        tracker.apply(CustodyKind::Exec, 4, 3);
        assert!(tracker.gapped());
    }

    #[test]
    fn a_regression_is_also_a_gap() {
        let mut tracker = SeqTracker::new();
        tracker.apply(CustodyKind::Fork, 5, 5);
        tracker.apply(CustodyKind::Fork, 5, 5);
        assert!(tracker.gapped());
    }
}
