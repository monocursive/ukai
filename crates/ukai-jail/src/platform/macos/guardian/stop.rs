//! Drive G throughout freeze, kill and the bounded tail (§4.5). Every tick
//! polls custody events; arrivals and pending exec retries are signalled
//! immediately. G′ denies inline and needs no polling or sync allocation.

use crate::platform::macos::custody::{Custodian, Signaller, StopNotDrainedReason, StopResult};
use crate::platform::macos::custody_io::{self, CustodyClient};
use crate::platform::macos::es::EsPoll;

pub const STOP_BUDGET_MS: u64 = 5_000;
pub const STOP_TAIL_MS: u64 = 60_000;
pub const SETTLE_MS: u64 = 20;

/// The production source and deterministic stand-ins share this boundary.
pub trait CustodySource {
    fn poll(&mut self) -> Option<EsPoll>;
    fn gapped(&self) -> bool;
    fn synchronize(&mut self, timeout_ms: u32) -> bool;
}

impl CustodySource for &CustodyClient {
    fn poll(&mut self) -> Option<EsPoll> {
        self.poll_full()
    }
    fn gapped(&self) -> bool {
        self.ring_overflowed()
    }
    fn synchronize(&mut self, timeout_ms: u32) -> bool {
        self.drain(timeout_ms)
    }
}

pub trait StopClock {
    fn now_ns(&mut self) -> u64;
    fn wait_tick(&mut self);
}

struct ContinuousClock;
impl StopClock for ContinuousClock {
    fn now_ns(&mut self) -> u64 {
        custody_io::continuous_time_ns()
    }
    fn wait_tick(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

pub struct StopOutcome {
    pub result: StopResult,
    pub guard_armed: bool,
    pub guard_denials: u64,
    /// Includes events delivered during the stop, not just before it.
    pub counts: [u64; 3],
    pub members_peak: usize,
}

pub struct GuardianStop {
    custody: Custodian,
    guard: Option<CustodyClient>,
}

impl GuardianStop {
    pub fn new(custody: Custodian, guard: Option<CustodyClient>) -> Self {
        Self {
            custody: custody.with_stop(ms(SETTLE_MS), ms(STOP_BUDGET_MS)),
            guard,
        }
    }

    /// Compatibility entry point. Without G, no stream can prove a drain.
    /// Live callers use `run_with_source` instead.
    pub fn run(self, now_ns: u64) -> (StopOutcome, Option<CustodyClient>) {
        struct Missing;
        impl CustodySource for Missing {
            fn poll(&mut self) -> Option<EsPoll> {
                None
            }
            fn gapped(&self) -> bool {
                true
            }
            fn synchronize(&mut self, _: u32) -> bool {
                false
            }
        }
        self.run_with_io(
            now_ns,
            &mut Missing,
            &mut ContinuousClock,
            &mut custody_io::EsSignaller,
        )
    }

    pub fn run_with_source(
        self,
        now_ns: u64,
        client: &CustodyClient,
    ) -> (StopOutcome, Option<CustodyClient>) {
        self.run_with_io(
            now_ns,
            &mut &*client,
            &mut ContinuousClock,
            &mut custody_io::EsSignaller,
        )
    }

    /// Runs the exact production loop with injectable ES, clock and signal
    /// boundaries. All storage was allocated before release.
    pub fn run_with_io(
        mut self,
        now_ns: u64,
        source: &mut dyn CustodySource,
        clock: &mut dyn StopClock,
        signaller: &mut dyn Signaller,
    ) -> (StopOutcome, Option<CustodyClient>) {
        let guard_armed = self.guard.as_ref().is_some_and(custody_io::arm_guard);
        if guard_armed {
            self.custody.arm_guard();
        }
        // EOF may precede delivery of the spawn event. Synchronize once,
        // then poll G before any empty-table decision. A failed barrier
        // cannot establish a complete prefix and is conservatively a gap.
        if !source.synchronize(SETTLE_MS as u32) {
            self.custody.note_stream_gap();
        }
        self.custody.begin_stop(now_ns);
        let mut peak = self.custody.live_count();
        let mut in_tail = false;
        let result = loop {
            // Bound one batch so a producer cannot starve the clock/sweeps.
            for _ in 0..4096 {
                let Some(event) = source.poll() else {
                    break;
                };
                self.custody.apply_polled_during_stop(&event, signaller);
                peak = peak.max(self.custody.live_count());
            }
            if source.gapped() {
                self.custody.note_stream_gap();
            }
            let now = clock.now_ns();
            if let Some(result) = self.custody.tick(now, signaller) {
                if matches!(
                    result,
                    StopResult::NotDrained {
                        reason: StopNotDrainedReason::Budget,
                        ..
                    }
                ) && !in_tail
                    && self
                        .custody
                        .extend_stop_budget(ms(STOP_BUDGET_MS + STOP_TAIL_MS))
                {
                    in_tail = true;
                    continue;
                }
                if matches!(
                    result,
                    StopResult::NotDrained {
                        reason: StopNotDrainedReason::Gap | StopNotDrainedReason::Integrity,
                        ..
                    }
                ) && self.custody.live_count() != 0
                    && self
                        .custody
                        .continue_stop_after_loss(ms(STOP_BUDGET_MS + STOP_TAIL_MS))
                {
                    continue;
                }
                break result;
            }
            clock.wait_tick();
        };
        let guard_denials = self.guard.as_ref().map_or(0, CustodyClient::guard_denials);
        (
            StopOutcome {
                result,
                guard_armed,
                guard_denials,
                counts: self.custody.seq().counts(),
                members_peak: peak,
            },
            self.guard.take(),
        )
    }
}

const fn ms(value: u64) -> u64 {
    value * 1_000_000
}
