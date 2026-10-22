//! The guardian's stop (jail-macos §4.5): arm the guard, then drive the
//! freeze/kill/drain machine from `custody/` to its end, with the stop's
//! tail: the budget is initial 5 s, and past it the guardian **keeps
//! stopping** for up to initial 60 s before finishing (§4.5 "After the
//! budget").
//!
//! The control flow over the pure machine is all this module owns: the
//! machine's sweeps, gap veto and drain proof are `custody::StopMachine`'s.
//! Events reach the machine through [`GuardianStop::apply`], which the
//! event loop calls for every drained custody message; the machine signals
//! a newly arrived member at once (`SIGSTOP`), which is §4.5 step 2's "and
//! to each newly reported member on arrival".

use crate::platform::macos::custody::{Custodian, StopResult};
use crate::platform::macos::custody_io::{self, CustodyClient};

/// The cooperative stop budget, initial 5 s (§4.5).
pub const STOP_BUDGET_MS: u64 = 5_000;
/// How long the guardian keeps stopping past the budget, initial 60 s.
pub const STOP_TAIL_MS: u64 = 60_000;
/// The settle interval between sweeps, initial 20 ms (§4.5 step 2).
pub const SETTLE_MS: u64 = 20;

/// The stop's outcome for the record.
pub struct StopOutcome {
    pub result: StopResult,
    /// Whether G′ was armed; `false` when there was no guard client or the
    /// subscription failed — the stop then proceeded unguarded and the
    /// record says so (§4.5 step 1).
    pub guard_armed: bool,
    /// Denials G′ delivered during the stop.
    pub guard_denials: u64,
}

/// The guardian's stop driver: the custody core plus the guard client.
pub struct GuardianStop {
    custody: Custodian,
    guard: Option<CustodyClient>,
}

impl GuardianStop {
    /// Assemble the stop from the custodian the event loop has fed and the
    /// guard client G′ created at startup (`None` when its creation failed,
    /// which the record then reports as unguarded).
    pub fn new(custody: Custodian, guard: Option<CustodyClient>) -> Self {
        // The §4.5 numbers, stated here rather than defaulted: a 20 ms
        // settle between sweeps and the initial 5 s budget.
        let custody = custody.with_stop(ms(SETTLE_MS), ms(STOP_BUDGET_MS));
        Self { custody, guard }
    }

    /// Run the stop to its end (or its 60 s tail) and report the outcome.
    /// The caller has already applied every queued event.
    pub fn run(mut self, now_ns: u64) -> (StopOutcome, Option<CustodyClient>) {
        // Step 1: arm G′. A failure records `guard_armed=false` and the
        // stop proceeds unguarded — liveness is weaker, safety is not
        // affected (§4.5 step 1, §4.6).
        let mut guard_armed = false;
        if let Some(guard) = self.guard.as_ref() {
            guard_armed = custody_io::arm_guard(guard);
        }
        if guard_armed {
            self.custody.arm_guard();
        }

        // Steps 2–4 within the budget.
        self.custody.begin_stop(now_ns);
        let mut signaller = custody_io::EsSignaller;
        let mut result = self.drive(now_ns, now_ns + ms(STOP_BUDGET_MS), &mut signaller);

        // Past the budget: keep stopping until the tail (§4.5), then finish
        // with whatever the last attempt decided.
        if let StopResult::NotDrained {
            reason: crate::platform::macos::custody::StopNotDrainedReason::Budget,
            ..
        } = result
        {
            let tail_end = now_ns + ms(STOP_BUDGET_MS) + ms(STOP_TAIL_MS);
            // `begin` restarts the machine's clock with the tail as budget;
            // the second end is the one the record keeps.
            self.custody.begin_stop(now_ns + ms(STOP_BUDGET_MS));
            result = self.drive(now_ns + ms(STOP_BUDGET_MS), tail_end, &mut signaller);
        }

        let guard_denials = self
            .guard
            .as_ref()
            .map(CustodyClient::guard_denials)
            .unwrap_or(0);
        (
            StopOutcome {
                result,
                guard_armed,
                guard_denials,
            },
            self.guard.take(),
        )
    }

    /// Tick the machine until it answers, servicing the guard's denial
    /// queue. The machine gates its own sweeps by the settle interval
    /// against the live continuous clock; the loop sleeps a millisecond
    /// between ticks, well under the 20 ms settle.
    fn drive(
        &mut self,
        _start_ns: u64,
        end_ns: u64,
        signaller: &mut custody_io::EsSignaller,
    ) -> StopResult {
        loop {
            if let Some(guard) = self.guard.as_ref() {
                // The shim denies inline; this only drains the queue.
                let _ = guard.drain(0);
            }
            let now = custody_io::continuous_time_ns();
            if let Some(result) = self.custody.tick(now, signaller) {
                return result;
            }
            if now >= end_ns {
                // The machine's own budget answers first in practice; this
                // bounds a pathologically slow clock.
                return StopResult::NotDrained {
                    reason: crate::platform::macos::custody::StopNotDrainedReason::Budget,
                    elapsed_ns: now - _start_ns,
                    sweeps: self.custody.stop().sweeps(),
                    signalled: self.custody.stop().signalled(),
                };
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

fn ms(value: u64) -> u64 {
    value * 1_000_000
}
