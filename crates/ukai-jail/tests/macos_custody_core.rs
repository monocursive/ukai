//! J16 custody core and ES shim (jail-macos §4.1, §4.4, §4.5).
//!
//! The first half drives the pure custody core — sequence tracking, the
//! membership table and the stop machine — through adversarial event
//! sequences: deep fork chains, parallel-fork interleavings, exec token
//! changes mid-stop, fork-in-flight during the kill, ESRCH pending-exec
//! retries, budget overruns, and the §4.5 safety property that a stop is
//! never `Drained` while a gap or an integrity loss stands, even with an
//! empty table.
//!
//! The second half runs against this Mac's live EndpointSecurity interface
//! (K98 row-1 evidence): client creation without the entitlement, the
//! continuous clock and this process's audit token. These never skip: on the
//! mac CI lane they are the measurement, and on a developer Mac they are the
//! same measurement.
#![cfg(target_os = "macos")]

use ukai_jail::platform::macos::custody::{
    AUDIT_TOKEN_PID, AUDIT_TOKEN_PIDVERSION, AUDIT_TOKEN_RUID, Custodian, CustodyKind,
    MAX_TABLE_CAPACITY, MembershipError, Signaller, StopNotDrainedReason, StopResult,
    table_capacity,
};
use ukai_jail::platform::macos::es::{self, EsEvent, EsNewResult};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A synthetic audit token with the measured libbsm field layout.
fn token(pid: u32, pidversion: u32, uid: u32) -> [u32; 8] {
    let mut token = [0u32; 8];
    token[AUDIT_TOKEN_RUID] = uid;
    token[AUDIT_TOKEN_PID] = pid;
    token[AUDIT_TOKEN_PIDVERSION] = pidversion;
    token
}

fn fork(
    global: u64,
    type_seq: u64,
    pid: u32,
    pidversion: u32,
    uid: u32,
) -> (CustodyKind, u64, u64, EsEvent) {
    (
        CustodyKind::Fork,
        global,
        type_seq,
        EsEvent::Fork {
            token: token(pid, pidversion, uid),
        },
    )
}

fn exec(
    global: u64,
    type_seq: u64,
    pid: u32,
    pidversion: u32,
    uid: u32,
) -> (CustodyKind, u64, u64, EsEvent) {
    (
        CustodyKind::Exec,
        global,
        type_seq,
        EsEvent::Exec {
            token: token(pid, pidversion, uid),
        },
    )
}

fn exit(
    global: u64,
    type_seq: u64,
    pid: u32,
    pidversion: u32,
    uid: u32,
) -> (CustodyKind, u64, u64, EsEvent) {
    (
        CustodyKind::Exit,
        global,
        type_seq,
        EsEvent::Exit {
            token: token(pid, pidversion, uid),
            status: 0,
        },
    )
}

fn feed(custodian: &mut Custodian, events: &[(CustodyKind, u64, u64, EsEvent)]) {
    if let Some((_, _, _, event)) = events.first()
        && custodian.seq().counts() == [0; 3]
    {
        custodian.expect_root(event.token()[AUDIT_TOKEN_PID] as i32);
    }
    for (kind, global, seq, event) in events {
        custodian.apply_sequenced(*kind, *global, *seq, event);
    }
}

/// What the signaller saw, and how it answers.
#[derive(Default)]
struct RecordingSignaller {
    calls: Vec<([u32; 8], i32)>,
    /// PIDs that answer ESRCH (a member whose token is stale).
    esrch: Vec<u32>,
}

impl RecordingSignaller {
    fn calls_to(&self, pid: u32, sig: i32) -> usize {
        self.calls
            .iter()
            .filter(|(token, call_sig)| token[AUDIT_TOKEN_PID] == pid && *call_sig == sig)
            .count()
    }
}

impl Signaller for RecordingSignaller {
    fn signal(&mut self, token: &[u32; 8], sig: i32) -> i32 {
        self.calls.push((*token, sig));
        if self.esrch.contains(&token[AUDIT_TOKEN_PID]) {
            3 // ESRCH
        } else {
            0
        }
    }
}

const SETTLE_NS: u64 = 20_000_000;
const BUDGET_NS: u64 = 5_000_000_000;

/// Advances a stop in `settle_ns` steps until it ends or `max_ticks` pass.
fn run(
    custodian: &mut Custodian,
    signaller: &mut RecordingSignaller,
    mut now: u64,
    max_ticks: u64,
) -> Option<StopResult> {
    for _ in 0..max_ticks {
        if let Some(result) = custodian.tick(now, signaller) {
            return Some(result);
        }
        now += SETTLE_NS;
    }
    None
}

// ---------------------------------------------------------------------------
// Sequence tracking (§4.4)
// ---------------------------------------------------------------------------

#[test]
fn a_gap_from_a_dropped_message_vetoes_the_drain_even_with_an_empty_table() {
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    // Two members live out their lives; then the second's exit event for
    // seq 2 is dropped: the next exit message carries seq 3 while the
    // global sequence advanced by one (§4.4: a jump in either number).
    feed(
        &mut custodian,
        &[
            fork(1, 1, 100, 1, 501),
            exec(2, 1, 100, 2, 501),
            fork(3, 2, 101, 1, 501),
            exec(4, 2, 101, 2, 501),
            exit(5, 1, 100, 2, 501),
            exit(6, 3, 101, 2, 501),
        ],
    );
    assert!(custodian.gapped());
    assert_eq!(custodian.live_count(), 0, "the table is empty");
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    let result = run(&mut custodian, &mut signaller, 0, 8).expect("the stop ends");
    assert_eq!(
        result,
        StopResult::NotDrained {
            reason: StopNotDrainedReason::Gap,
            elapsed_ns: 0,
            sweeps: 0,
            signalled: 0,
        },
        "§4.5 safety: a gap makes tree_empty impossible even with an empty table"
    );
    assert!(!result.drained());
}

#[test]
fn an_exit_that_precedes_its_fork_marks_the_stream_gapped() {
    // ES enqueues a fork's message inside the fork (§4.5 safety), so an exit
    // for a member whose fork never arrived is evidence of dropped messages,
    // not of an empty tree — even with perfectly sequenced numbers.
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    feed(&mut custodian, &[fork(1, 1, 100, 1, 501)]);
    let unknown_exit = exit(2, 1, 200, 1, 501);
    custodian.apply_sequenced(
        unknown_exit.0,
        unknown_exit.1,
        unknown_exit.2,
        &unknown_exit.3,
    );
    feed(&mut custodian, &[exit(3, 2, 100, 1, 501)]);
    assert!(custodian.gapped(), "the unknown exit marks the stream");
    assert_eq!(custodian.live_count(), 0);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    assert_eq!(
        run(&mut custodian, &mut signaller, 0, 4).expect("the stop ends"),
        StopResult::NotDrained {
            reason: StopNotDrainedReason::Gap,
            elapsed_ns: 0,
            sweeps: 0,
            signalled: 0,
        }
    );
}

// ---------------------------------------------------------------------------
// Membership (§4.4)
// ---------------------------------------------------------------------------

#[test]
fn deep_fork_chains_reuse_their_slots_and_drain() {
    let mut custodian = Custodian::new(16).with_stop(SETTLE_NS, BUDGET_NS);
    custodian.expect_root(1000);
    // A chain of 16 members; every fourth exits before the next fork, so the
    // live set stays inside the table while far more than 8 PIDs pass
    // through it (slot reuse, §4.4).
    let mut global = 1u64;
    let mut exit_seq = 1u64;
    for depth in 0..16u32 {
        let pid = 1000 + depth;
        let arrival = fork(global, depth as u64 + 1, pid, 1, 501);
        custodian.apply_sequenced(arrival.0, arrival.1, arrival.2, &arrival.3);
        global += 1;
        if depth % 4 == 3 {
            let member_exit = exit(global, exit_seq, pid, 1, 501);
            custodian.apply_sequenced(member_exit.0, member_exit.1, member_exit.2, &member_exit.3);
            global += 1;
            exit_seq += 1;
        }
    }
    assert!(custodian.seq().contiguous());
    let live_at_stop = custodian.live_count();
    assert_eq!(live_at_stop, 12, "the four exits freed their slots");
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    // Let the freeze and kill settle, then the remaining members exit.
    assert!(custodian.tick(0, &mut signaller).is_none());
    assert!(custodian.tick(SETTLE_NS, &mut signaller).is_none());
    for depth in 0..16u32 {
        if depth % 4 != 3 {
            let member_exit = exit(global, exit_seq, 1000 + depth, 1, 501);
            custodian.apply_sequenced(member_exit.0, member_exit.1, member_exit.2, &member_exit.3);
            global += 1;
            exit_seq += 1;
        }
    }
    let result = custodian
        .tick(2 * SETTLE_NS, &mut signaller)
        .expect("the stop ends");
    assert!(
        matches!(result, StopResult::Drained { sweeps: 2, .. }),
        "{result:?}"
    );
}

#[test]
fn parallel_fork_interleavings_drain() {
    // Eight branches forked in parallel (the interleaving order the prototype
    // measured with many forking threads, K92), then exited interleaved.
    let mut custodian = Custodian::new(table_capacity(64)).with_stop(SETTLE_NS, BUDGET_NS);
    let mut events = Vec::new();
    let mut global = 1u64;
    for round in 0..4u32 {
        for branch in 0..8u32 {
            let pid = 2000 + branch * 10 + round;
            events.push(fork(
                global,
                (round as u64) * 8 + branch as u64 + 1,
                pid,
                1,
                501,
            ));
            global += 1;
        }
    }
    let mut exit_seq = 1u64;
    for round in 0..4u32 {
        for branch in (0..8u32).rev() {
            let pid = 2000 + branch * 10 + round;
            events.push(exit(global, exit_seq, pid, 1, 501));
            global += 1;
            exit_seq += 1;
        }
    }
    feed(&mut custodian, &events);
    assert_eq!(custodian.live_count(), 0);
    assert!(custodian.seq().contiguous());
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    assert!(
        run(&mut custodian, &mut signaller, 0, 4)
            .expect("the stop ends")
            .drained()
    );
}

#[test]
fn a_full_table_is_an_integrity_loss_during_the_stop() {
    let mut custodian = Custodian::new(2).with_stop(SETTLE_NS, BUDGET_NS);
    feed(
        &mut custodian,
        &[fork(1, 1, 100, 1, 501), fork(2, 2, 101, 1, 501)],
    );
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    // First tick: the freeze sweep SIGSTOPs both.
    assert!(custodian.tick(0, &mut signaller).is_none());
    // A third member cannot fit: the table reports it, the stop says
    // integrity, and the table did not grow.
    let arrival = fork(3, 3, 102, 1, 501);
    custodian.apply_sequenced(arrival.0, arrival.1, arrival.2, &arrival.3);
    assert!(custodian.integrity_loss());
    assert!(custodian.table().capacity() == 2);
    assert_eq!(
        run(&mut custodian, &mut signaller, SETTLE_NS, 8).expect("the stop ends"),
        StopResult::NotDrained {
            reason: StopNotDrainedReason::Integrity,
            elapsed_ns: SETTLE_NS,
            sweeps: 1,
            signalled: 2, // the freeze sweep; the arrival's signal is the next sweep's
        }
    );
}

// ---------------------------------------------------------------------------
// The stop (§4.5)
// ---------------------------------------------------------------------------

#[test]
fn a_clean_stop_freezes_kills_and_drains() {
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    feed(
        &mut custodian,
        &[
            fork(1, 1, 100, 1, 501),
            fork(2, 2, 101, 1, 501),
            fork(3, 3, 102, 1, 501),
        ],
    );
    custodian.arm_guard();
    assert!(custodian.stop().guard_active());
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    // First tick: the freeze sweep SIGSTOPs all three, nobody arrived, the
    // freeze ends. Second tick: the kill sweep. Exits then drain it.
    let exit_events: Vec<_> = [100u32, 101, 102]
        .into_iter()
        .enumerate()
        .map(|(index, pid)| exit(4 + index as u64, index as u64 + 1, pid, 1, 501))
        .collect();
    let mut drained = None;
    let mut pending = exit_events.into_iter();
    let mut now = 0u64;
    for _ in 0..16 {
        if let Some(result) = custodian.tick(now, &mut signaller) {
            drained = Some(result);
            break;
        }
        now += SETTLE_NS;
        if now == 2 * SETTLE_NS {
            // The kill has swept; the members exit.
            for (kind, global, seq, event) in pending.by_ref() {
                custodian.apply_sequenced(kind, global, seq, &event);
            }
        }
    }
    let result = drained.expect("the stop ends");
    assert!(
        matches!(result, StopResult::Drained { sweeps: 2, .. }),
        "{result:?}"
    );
    // SIGSTOP to all three in the freeze sweep, SIGKILL to all three in the
    // kill sweep.
    for pid in [100u32, 101, 102] {
        assert_eq!(signaller.calls_to(pid, 17), 1, "member {pid} frozen once");
        assert_eq!(signaller.calls_to(pid, 9), 1, "member {pid} killed once");
    }
    assert_eq!(result.elapsed_ns(), 2 * SETTLE_NS);
}

#[test]
fn an_esrch_member_is_re_signalled_when_its_exec_arrives() {
    // A member whose exec from before the guard is still unprocessed: its
    // table token is stale, so the freeze sweep answers ESRCH. The member
    // stays unaccounted for — the freeze cannot complete — until its exec
    // event replaces the token and the next sweep reaches the new one
    // (§4.5 step 2).
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    feed(&mut custodian, &[fork(1, 1, 100, 1, 501)]);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    signaller.esrch.push(100);
    // Tick 1: the sweep SIGSTOPs the stale token and gets ESRCH.
    assert!(custodian.tick(0, &mut signaller).is_none());
    assert_eq!(signaller.calls_to(100, 17), 1);
    assert!(
        custodian.tick(SETTLE_NS, &mut signaller).is_none(),
        "the freeze keeps sweeping"
    );
    assert_eq!(signaller.calls_to(100, 17), 2);
    // The exec arrives with the new PID version; the table token is
    // replaced and the caller re-signals the member through on_exec_retry.
    let retry = exec(2, 1, 100, 2, 501);
    custodian.apply_sequenced(retry.0, retry.1, retry.2, &retry.3);
    signaller.esrch.clear();
    assert!(
        custodian.tick(2 * SETTLE_NS, &mut signaller).is_none(),
        "the freeze ends"
    );
    assert_eq!(
        signaller.calls_to(100, 17),
        3,
        "signalled again with the new token"
    );
    // The kill sweep and the exit drain the stop.
    assert!(custodian.tick(3 * SETTLE_NS, &mut signaller).is_none());
    let member_exit = exit(3, 1, 100, 2, 501);
    custodian.apply_sequenced(member_exit.0, member_exit.1, member_exit.2, &member_exit.3);
    let result = custodian
        .tick(4 * SETTLE_NS, &mut signaller)
        .expect("the stop ends");
    assert!(result.drained(), "{result:?}");
    // The machine-level retry: a pending ESRCH member whose exec arrives is
    // re-signalled immediately with the new token, by the caller.
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    feed(&mut custodian, &[fork(1, 1, 100, 1, 501)]);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    signaller.esrch.push(100);
    assert!(custodian.tick(0, &mut signaller).is_none());
    let retry = exec(2, 1, 100, 2, 501);
    custodian.apply_sequenced(retry.0, retry.1, retry.2, &retry.3);
    signaller.esrch.clear();
    custodian.on_exec_retry(&token(100, 2, 501), &mut signaller);
    assert_eq!(
        signaller.calls_to(100, 17),
        2,
        "the pending retry is re-signalled at once"
    );
}

#[test]
fn a_member_re_reported_running_is_re_frozen_by_the_sweeps() {
    // A kernel SIGCONT passes neither ES nor Seatbelt (§4.5 step 2), so a
    // stopped member resumed outside the stream is invisible; what the
    // stream does show is the member's new fork. A member that arrives
    // during the kill is killed at once, and the drain waits for its exit.
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    feed(&mut custodian, &[fork(1, 1, 100, 1, 501)]);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    assert!(
        custodian.tick(0, &mut signaller).is_none(),
        "the freeze sweeps"
    );
    assert!(
        custodian.tick(SETTLE_NS, &mut signaller).is_none(),
        "the kill sweeps"
    );
    // The stopped member forked before it was stopped: a fork in flight
    // surfaces now, after the kill sweep. The arrival holds the stop open
    // and the next tick's sweep kills it (§4.5 step 3).
    let late_child = fork(2, 2, 101, 1, 501);
    custodian.apply_sequenced(late_child.0, late_child.1, late_child.2, &late_child.3);
    // The stop is not done: the child still owes its exit event.
    assert!(custodian.tick(2 * SETTLE_NS, &mut signaller).is_none());
    assert_eq!(
        signaller.calls_to(101, 9),
        1,
        "the in-flight child is killed by the sweep"
    );
    let child_exit = exit(3, 1, 101, 1, 501);
    custodian.apply_sequenced(child_exit.0, child_exit.1, child_exit.2, &child_exit.3);
    let parent_exit = exit(4, 2, 100, 1, 501);
    custodian.apply_sequenced(parent_exit.0, parent_exit.1, parent_exit.2, &parent_exit.3);
    let result = custodian
        .tick(3 * SETTLE_NS, &mut signaller)
        .expect("the stop ends");
    assert!(result.drained(), "{result:?}");
}

#[test]
fn an_exec_token_change_mid_stop_keeps_the_member_signallable() {
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    feed(&mut custodian, &[fork(1, 1, 100, 1, 501)]);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    assert!(custodian.tick(0, &mut signaller).is_none());
    // The member execs (same user): its token's PID version changes.
    let execed = exec(2, 1, 100, 2, 501);
    custodian.apply_sequenced(execed.0, execed.1, execed.2, &execed.3);
    // The kill reaches the new token, and only the new token.
    assert!(custodian.tick(SETTLE_NS, &mut signaller).is_none());
    assert_eq!(signaller.calls_to(100, 9), 1);
    let member_exit = exit(3, 1, 100, 2, 501);
    custodian.apply_sequenced(member_exit.0, member_exit.1, member_exit.2, &member_exit.3);
    assert!(
        run(&mut custodian, &mut signaller, 2 * SETTLE_NS, 8)
            .expect("ends")
            .drained()
    );
}

#[test]
fn a_setuid_exec_mid_stop_is_an_integrity_veto() {
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    feed(&mut custodian, &[fork(1, 1, 100, 1, 501)]);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    assert!(custodian.tick(0, &mut signaller).is_none());
    let setuid = exec(2, 1, 100, 2, 0);
    custodian.apply_sequenced(setuid.0, setuid.1, setuid.2, &setuid.3);
    let result = run(&mut custodian, &mut signaller, SETTLE_NS, 8).expect("the stop ends");
    assert_eq!(
        result,
        StopResult::NotDrained {
            reason: StopNotDrainedReason::Integrity,
            elapsed_ns: SETTLE_NS,
            sweeps: 1,
            signalled: 1,
        }
    );
}

#[test]
fn the_budget_overrun_names_the_budget() {
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, 3 * SETTLE_NS);
    feed(&mut custodian, &[fork(1, 1, 100, 1, 501)]);
    custodian.begin_stop(0);
    // The member never exits; the signaller keeps succeeding. The stop runs
    // out of budget and says `budget`, keeping `tree_unknown`.
    let mut signaller = RecordingSignaller::default();
    let mut now = 0u64;
    let result = loop {
        if let Some(result) = custodian.tick(now, &mut signaller) {
            break result;
        }
        now += SETTLE_NS;
    };
    assert_eq!(
        result,
        StopResult::NotDrained {
            reason: StopNotDrainedReason::Budget,
            elapsed_ns: 3 * SETTLE_NS,
            sweeps: 3,
            signalled: 3,
        }
    );
}

#[test]
fn freeze_settles_only_when_no_new_member_arrives_between_sweeps() {
    // A workload that keeps forking during the freeze holds the freeze open
    // until a full sweep finds everyone stopped and no arrival since the
    // previous sweep.
    let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller::default();
    custodian.expect_root(100);
    // A new member arrives before each of the first two sweeps.
    for (index, pid) in [100u32, 101].into_iter().enumerate() {
        let arrival = fork(index as u64 + 1, index as u64 + 1, pid, 1, 501);
        custodian.apply_sequenced(arrival.0, arrival.1, arrival.2, &arrival.3);
        assert!(
            custodian
                .tick(index as u64 * SETTLE_NS, &mut signaller)
                .is_none()
        );
    }
    // No new arrival before this sweep: everyone is stopped and the freeze
    // ends; the kill sweep follows.
    assert!(custodian.tick(2 * SETTLE_NS, &mut signaller).is_none());
    assert!(
        signaller.calls_to(100, 17) >= 2,
        "re-frozen after each arrival"
    );
    assert!(signaller.calls_to(101, 17) >= 2);
    // The kill sweep runs while both members are still live.
    assert!(custodian.tick(3 * SETTLE_NS, &mut signaller).is_none());
    assert_eq!(
        signaller.calls_to(100, 9),
        1,
        "killed once in the kill sweep"
    );
    assert_eq!(signaller.calls_to(101, 9), 1);
    // Drain with exits.
    for (index, pid) in [100u32, 101].into_iter().enumerate() {
        let member_exit = exit(index as u64 + 3, index as u64 + 1, pid, 1, 501);
        custodian.apply_sequenced(member_exit.0, member_exit.1, member_exit.2, &member_exit.3);
    }
    let result = run(&mut custodian, &mut signaller, 4 * SETTLE_NS, 8).expect("the stop ends");
    assert!(result.drained(), "{result:?}");
}

#[test]
fn never_drained_while_a_gap_or_integrity_stands_even_with_an_empty_table() {
    // The §4.5 safety claim, as a property over adversarial combinations:
    // no tick of no stop machine in any state below returns Drained while
    // the gap or integrity flag stands, whatever the table holds.
    for gap in [false, true] {
        for integrity in [false, true] {
            for members in [0usize, 1, 3] {
                let mut custodian = Custodian::new(8).with_stop(SETTLE_NS, BUDGET_NS);
                for pid in 0..members as u32 {
                    let arrival = fork(pid as u64 + 1, pid as u64 + 1, 300 + pid, 1, 501);
                    custodian.apply_sequenced(arrival.0, arrival.1, arrival.2, &arrival.3);
                }
                if gap {
                    custodian.note_stream_gap();
                }
                if integrity {
                    custodian.mark_integrity();
                }
                custodian.begin_stop(0);
                let mut signaller = RecordingSignaller::default();
                let mut now = 0u64;
                let mut ended = None;
                for _ in 0..40 {
                    if let Some(result) = custodian.tick(now, &mut signaller) {
                        ended = Some(result);
                        break;
                    }
                    now += SETTLE_NS;
                }
                if let Some(result) = ended {
                    assert!(
                        !result.drained() || !(gap || integrity),
                        "drained under gap={gap} integrity={integrity}: {result:?}"
                    );
                    if gap {
                        assert_eq!(
                            result,
                            StopResult::NotDrained {
                                reason: StopNotDrainedReason::Gap,
                                elapsed_ns: 0,
                                sweeps: 0,
                                signalled: 0,
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn adversarial_interleavings_never_drain_into_a_false_empty_tree() {
    // A deterministic xorshift drive over fork/exec/exit sequences with
    // occasional gaps: whenever the stream is gapped, the stop must answer
    // Gap, never Drained (§4.5 safety), whatever the table holds.
    let mut state = 0x2545F4914F6CDD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..32u64 {
        let mut custodian = Custodian::new(table_capacity(16)).with_stop(SETTLE_NS, 12 * SETTLE_NS);
        let mut global = 1u64;
        let mut fork_seq = 0u64;
        let mut exec_seq = 0u64;
        let mut exit_seq = 0u64;
        let mut live: Vec<(u32, u32)> = Vec::new();
        for _ in 0..40u64 {
            let roll = next() % 4;
            let pid = 400 + (next() % 8) as u32;
            match roll {
                0 | 1 => {
                    fork_seq += 1;
                    let pidversion = 1 + (next() % 3) as u32;
                    let event = fork(global, fork_seq, pid, pidversion, 501);
                    if global == 1 {
                        custodian.expect_root(pid as i32);
                    }
                    custodian.apply_sequenced(event.0, event.1, event.2, &event.3);
                    global += 1;
                    live.retain(|(seen, _)| *seen != pid);
                    live.push((pid, pidversion));
                }
                2 if !live.is_empty() => {
                    let index = (next() as usize) % live.len();
                    let (seen, version) = live.swap_remove(index);
                    exit_seq += 1;
                    let event = exit(global, exit_seq, seen, version, 501);
                    custodian.apply_sequenced(event.0, event.1, event.2, &event.3);
                    global += 1;
                }
                _ if !live.is_empty() => {
                    let index = (next() as usize) % live.len();
                    let (seen, _) = live[index];
                    let new_version = 2 + (next() % 4) as u32;
                    exec_seq += 1;
                    let event = exec(global, exec_seq, seen, new_version, 501);
                    custodian.apply_sequenced(event.0, event.1, event.2, &event.3);
                    global += 1;
                    live[index].1 = new_version;
                }
                _ => {}
            }
        }
        if round % 4 == 0 {
            custodian.note_stream_gap();
        }
        custodian.begin_stop(0);
        let mut signaller = RecordingSignaller::default();
        // Freeze and kill settle; then ES delivers the exits the kills
        // caused, and the stop drains.
        let mut now = 0u64;
        let mut ended = None;
        for _ in 0..64 {
            if let Some(result) = custodian.tick(now, &mut signaller) {
                ended = Some(result);
                break;
            }
            now += SETTLE_NS;
            if now == 2 * SETTLE_NS {
                let remaining: Vec<[u32; 8]> = (0..custodian.table().slot_count())
                    .filter_map(|index| custodian.table().entry_at(index))
                    .filter(|entry| entry.live)
                    .map(|entry| entry.token)
                    .collect();
                for member_token in remaining {
                    exit_seq += 1;
                    let member_exit = (
                        CustodyKind::Exit,
                        global,
                        exit_seq,
                        EsEvent::Exit {
                            token: member_token,
                            status: 9,
                        },
                    );
                    custodian.apply_sequenced(
                        member_exit.0,
                        member_exit.1,
                        member_exit.2,
                        &member_exit.3,
                    );
                    global += 1;
                }
            }
        }
        let result = ended.expect("every adversarial stop ends");
        if custodian.gapped() {
            assert!(
                !result.drained(),
                "round {round}: drained under a gap: {result:?}"
            );
        } else if !custodian.integrity_loss() {
            assert!(
                result.drained(),
                "round {round}: a clean stream must drain: {result:?}"
            );
        }
    }
}

#[test]
fn the_engine_documents_and_honors_its_preallocation() {
    // §4.1 rule 4: the table never grows past its capacity, and a stop
    // machine built with the same capacity holds its pending-retry list
    // within it. `MembershipError::Full` is the evidence of the clamp.
    let mut custodian = Custodian::new(table_capacity(3));
    for pid in 0..3u32 {
        let arrival = fork(pid as u64 + 1, pid as u64 + 1, 500 + pid, 1, 501);
        custodian.apply_sequenced(arrival.0, arrival.1, arrival.2, &arrival.3);
    }
    let overflow = fork(4, 4, 503, 1, 501);
    custodian.apply_sequenced(overflow.0, overflow.1, overflow.2, &overflow.3);
    assert!(matches!(
        custodian.table_mut().enter(match overflow.3 {
            EsEvent::Fork { token } => token,
            _ => unreachable!(),
        }),
        Err(MembershipError::Full)
    ));
    assert!(custodian.integrity_loss());
    assert_eq!(custodian.table().capacity(), table_capacity(3));
    assert_eq!(table_capacity(u64::MAX as usize), MAX_TABLE_CAPACITY);
}

// ---------------------------------------------------------------------------
// This Mac (K98 row-1 evidence; never skipped)
// ---------------------------------------------------------------------------

#[test]
fn client_creation_without_the_entitlement_refuses_not_entitled() {
    match es::CustodyClient::new() {
        // The mapped enum is the assertion; the raw code is recorded for the
        // K98 row-1 record.
        Err(result @ EsNewResult::NotEntitled) => {
            println!(
                "K98 row 1: es_new_descendants_client refused, raw result code {}",
                result.raw()
            );
        }
        Err(other) => panic!(
            "this Mac refused client creation with an unexpected result: {:?} (raw {})",
            other,
            other.raw()
        ),
        Ok(_client) => panic!(
            "client creation succeeded on an unentitled Mac (raw result {}); \
             the K98 row-1 expectation is wrong",
            EsNewResult::Success.raw()
        ),
    }
}

#[test]
fn the_continuous_clock_is_monotonic_across_reads() {
    let first = es::continuous_time_ns();
    let second = es::continuous_time_ns();
    assert!(
        second >= first,
        "mach_continuous_time went backwards: {first} then {second}"
    );
    println!(
        "K98: continuous clock advanced {} ns across two reads",
        second - first
    );
}

#[test]
fn this_process_audit_token_reads_pid_and_uid() {
    let token = es::self_token().expect("task_info(TASK_AUDIT_TOKEN)");
    // SAFETY: getuid takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    assert_eq!(
        token[AUDIT_TOKEN_PID] as u32,
        std::process::id(),
        "audit token field {} is the PID on this Mac",
        AUDIT_TOKEN_PID
    );
    assert_eq!(
        token[AUDIT_TOKEN_RUID], uid,
        "audit token field {} is the real UID on this Mac",
        AUDIT_TOKEN_RUID
    );
}

// Fix-wave regressions: these use the existing public API so they also run
// unchanged against 2da5c8d13.
#[test]
fn regression_c5_token_layout_matches_libbsm() {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AuditToken {
        val: [u32; 8],
    }
    #[link(name = "bsm")]
    unsafe extern "C" {
        fn audit_token_to_ruid(token: AuditToken) -> u32;
        fn audit_token_to_rgid(token: AuditToken) -> u32;
    }
    let token = AuditToken {
        val: [101, 102, 103, 104, 105, 106, 107, 108],
    };
    // SAFETY: libbsm takes this fixed eight-word token by value.
    unsafe {
        assert_eq!(token.val[AUDIT_TOKEN_RUID], audit_token_to_ruid(token));
        assert_eq!(
            token.val[ukai_jail::platform::macos::custody::AUDIT_TOKEN_RGID],
            audit_token_to_rgid(token)
        );
    }
}

#[test]
fn regression_c6_empty_without_root_never_drains() {
    let mut custodian = Custodian::new(1).with_stop(1, 10);
    custodian.begin_stop(0);
    assert!(
        !custodian
            .tick(0, &mut RecordingSignaller::default())
            .unwrap()
            .drained()
    );
}

#[test]
fn regression_c8_exec_into_full_table_is_integrity_loss() {
    let mut custodian = Custodian::new(1);
    custodian.apply_event(&EsEvent::Fork {
        token: token(100, 1, 501),
    });
    custodian.apply_event(&EsEvent::Exec {
        token: token(101, 2, 501),
    });
    assert!(custodian.integrity_loss());
}

#[test]
fn regression_l1_exited_esrch_entries_do_not_exhaust_retries() {
    let mut custodian = Custodian::new(1).with_stop(1, 100);
    custodian.begin_stop(0);
    let mut signaller = RecordingSignaller {
        esrch: vec![100, 101, 102],
        ..Default::default()
    };
    for pid in 100..103 {
        custodian.apply_event(&EsEvent::Fork {
            token: token(pid, 1, 501),
        });
        assert!(
            custodian
                .tick(u64::from(pid - 100), &mut signaller)
                .is_none()
        );
        custodian.apply_event(&EsEvent::Exit {
            token: token(pid, 1, 501),
            status: 0,
        });
        assert!(
            !custodian.integrity_loss(),
            "retry for exited PID {pid} leaked"
        );
    }
}

#[test]
fn regression_l4_noninitial_first_sequence_is_a_gap() {
    let mut tracker = ukai_jail::platform::macos::custody::SeqTracker::new();
    tracker.apply(CustodyKind::Fork, 5000, 700);
    assert!(tracker.gapped());
}

#[test]
fn regression_c2_begin_twice_does_not_panic() {
    let mut custodian = Custodian::new(1).with_stop(1, 10);
    custodian.begin_stop(0);
    custodian.begin_stop(1);
}

#[test]
fn registered_custodian_exit_is_not_a_member_exit_or_gap() {
    use ukai_jail::platform::macos::custody::Applied;
    let mut custody = Custodian::new(4).with_stop(1, 100);
    let guardian = token(99, 1, 501);
    custody.register_custodian(guardian).unwrap();
    custody.expect_root(100);
    feed(&mut custody, &[fork(1, 1, 100, 1, 501)]);
    let outcome = custody.apply_sequenced(
        CustodyKind::Exit,
        2,
        1,
        &EsEvent::Exit {
            token: guardian,
            status: 9,
        },
    );
    assert_eq!(outcome, Applied::CustodianIgnored);
    assert!(!custody.gapped());
    assert_eq!(custody.live_count(), 1);
    // The exclusion ends with this identity's exit, not every future PID 99.
    custody.apply_sequenced(
        CustodyKind::Fork,
        3,
        2,
        &EsEvent::Fork {
            token: token(99, 20, 501),
        },
    );
    assert_eq!(custody.live_count(), 2);
}

#[test]
fn handshake_replay_preserves_root_exec_exit_and_sequences() {
    use ukai_jail::platform::macos::es::EsPoll;
    let mut custody = Custodian::new(4).with_stop(1, 100);
    custody.expect_root(100);
    let guardian = token(99, 1, 501);
    custody.register_custodian(guardian).unwrap();
    let events = [
        EsPoll {
            kind: es::EVENT_FORK,
            global_seq: 1,
            seq: 1,
            event: EsEvent::Fork { token: guardian },
        },
        EsPoll {
            kind: es::EVENT_FORK,
            global_seq: 2,
            seq: 2,
            event: EsEvent::Fork {
                token: token(100, 1, 501),
            },
        },
        EsPoll {
            kind: es::EVENT_EXEC,
            global_seq: 3,
            seq: 1,
            event: EsEvent::Exec {
                token: token(100, 2, 501),
            },
        },
        EsPoll {
            kind: es::EVENT_EXIT,
            global_seq: 4,
            seq: 1,
            event: EsEvent::Exit {
                token: token(100, 2, 501),
                status: 0,
            },
        },
    ];
    custody.replay_handshake(&events);
    assert_eq!(custody.seq().counts(), [2, 1, 1]);
    assert_eq!(custody.live_count(), 0);
    custody.begin_stop(0);
    assert!(
        custody
            .tick(0, &mut RecordingSignaller::default())
            .unwrap()
            .drained()
    );
}

#[test]
fn an_unrelated_member_cannot_substitute_for_root_entry() {
    let mut custody = Custodian::new(4).with_stop(1, 100);
    custody.expect_root(100);
    custody.apply_event(&EsEvent::Fork {
        token: token(101, 1, 501),
    });
    custody.apply_event(&EsEvent::Exit {
        token: token(101, 1, 501),
        status: 0,
    });
    custody.begin_stop(0);
    assert!(
        !custody
            .tick(0, &mut RecordingSignaller::default())
            .unwrap()
            .drained()
    );
}

#[test]
fn effective_uid_change_is_an_integrity_loss_even_when_real_uid_stays() {
    let mut custody = Custodian::new(1);
    let mut before = token(100, 1, 501);
    before[1] = 501; // effective UID, independently of our exported constant
    custody.apply_event(&EsEvent::Fork { token: before });
    let mut after = before;
    after[7] += 1;
    after[1] = 0;
    custody.apply_event(&EsEvent::Exec { token: after });
    assert!(custody.integrity_loss());
}

#[test]
fn stop_configuration_keeps_existing_gap_and_integrity_evidence() {
    for integrity in [true, false] {
        let mut custody = Custodian::new(1);
        custody.expect_root(100);
        custody.apply_event(&EsEvent::Fork {
            token: token(100, 1, 501),
        });
        custody.apply_event(&EsEvent::Exit {
            token: token(100, 1, 501),
            status: 0,
        });
        if integrity {
            custody.mark_integrity();
        } else {
            custody.note_stream_gap();
        }
        let mut custody = custody.with_stop(1, 100);
        custody.begin_stop(0);
        assert!(
            !custody
                .tick(0, &mut RecordingSignaller::default())
                .unwrap()
                .drained()
        );
    }
}

#[test]
fn exec_holds_freeze_open_and_clears_stopped_mark_m23_m27() {
    let mut custody = Custodian::new(2).with_stop(10, 100);
    custody.expect_root(100);
    custody.begin_stop(0);
    custody.apply_event(&EsEvent::Fork {
        token: token(100, 1, 501),
    });
    let mut signals = RecordingSignaller::default();
    custody.tick(0, &mut signals); // Arrival keeps this first freeze open.
    assert!(custody.table().entry_at(0).unwrap().stopped);
    custody.apply_event(&EsEvent::Exec {
        token: token(100, 2, 501),
    });
    let member = custody.table().entry_at(0).unwrap();
    assert!(
        !member.stopped,
        "M27: exec invalidates the old stopped mark"
    );
    assert_eq!(member.pidversion, 2);
    custody.tick(10, &mut signals); // Exec arrived between freeze sweeps.
    custody.tick(20, &mut signals); // First quiet sweep can finish the freeze.
    assert_eq!(
        signals.calls_to(100, libc::SIGKILL),
        0,
        "M23: exec holds the freeze open"
    );
    custody.tick(30, &mut signals);
    assert_eq!(signals.calls_to(100, libc::SIGKILL), 1);
}

#[test]
fn r3_c4_exited_custodian_cannot_exempt_a_reused_pid_on_exec() {
    use ukai_jail::platform::macos::custody::Applied;
    let mut custody = Custodian::new(2);
    let old = token(200, 1, 501);
    let replacement = token(200, 2, 501);
    custody.register_custodian(old).unwrap();
    assert_eq!(
        custody.apply_event(&EsEvent::Exit {
            token: old,
            status: 0
        }),
        Applied::CustodianIgnored
    );
    assert_eq!(
        custody.apply_event(&EsEvent::Exec { token: replacement }),
        Applied::ExecEntered
    );
    assert!(custody.table().contains_token(&replacement));
    assert_eq!(
        custody.apply_event(&EsEvent::Exit {
            token: replacement,
            status: 0
        }),
        Applied::ExitRemoved
    );
    assert!(!custody.gapped());
    // Retiring the exemption also frees one of the two custodian slots.
    custody.register_custodian(token(201, 1, 501)).unwrap();
    custody.register_custodian(token(202, 1, 501)).unwrap();
}

#[test]
fn r3_c4_only_the_exact_current_token_can_remove_a_member() {
    use ukai_jail::platform::macos::custody::Applied;
    let current = token(100, 2, 501);
    for word in 0..8 {
        let mut custody = Custodian::new(1).with_stop(1, 10);
        custody.expect_root(100);
        custody.apply_event(&EsEvent::Fork { token: current });
        let mut stale = current;
        stale[word] = stale[word].wrapping_add(1);
        assert_eq!(
            custody.apply_event(&EsEvent::Exit {
                token: stale,
                status: 0
            }),
            Applied::ExitUnknown,
            "word {word}"
        );
        assert!(custody.table().contains_token(&current), "word {word}");
        assert_eq!(custody.live_count(), 1);
        assert!(custody.gapped());
        assert_eq!(
            custody.apply_event(&EsEvent::Exit {
                token: current,
                status: 0
            }),
            Applied::ExitRemoved
        );
        custody.begin_stop(0);
        assert!(
            !custody
                .tick(0, &mut RecordingSignaller::default())
                .unwrap()
                .drained()
        );
    }
}
