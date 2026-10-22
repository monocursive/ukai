//! Custody stream sequencing (jail-macos §4.4).
//!
//! Every custody message carries `global_seq_num` overall and `seq_num` per
//! event type. The first seen value initializes the tracker; any jump —
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
            self.counts[kind.index()] += 1;
            return;
        }
        match self.global {
            None => self.global = Some(global_seq),
            // The prototype's rule: `global_seq_num != sequence + 1` is a gap.
            Some(previous) if global_seq == previous + 1 => self.global = Some(global_seq),
            Some(_) => {
                self.gapped = true;
                self.counts[kind.index()] += 1;
                return;
            }
        }
        let slot = &mut self.per_type[kind.index()];
        match *slot {
            None => *slot = Some(seq),
            Some(previous) if seq == previous + 1 => *slot = Some(seq),
            Some(_) => self.gapped = true,
        }
        self.counts[kind.index()] += 1;
    }

    /// The invalid-version input of the prototype's rule: a message whose
    /// version predates the custody fields gaps the stream permanently.
    pub fn apply_invalid_version(&mut self) {
        self.gapped = true;
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
    fn an_invalid_version_input_gaps_the_stream() {
        let mut tracker = SeqTracker::new();
        sequence_ok(&mut tracker);
        tracker.apply_invalid_version();
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
