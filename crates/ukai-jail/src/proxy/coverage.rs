//! The proxy's trace sink and its `proxy.net` accounting (§11.4).
//!
//! Shared by every platform's outside proxy: each proxy result becomes a
//! proxy-source `net.connect` event on the proxy's own sequence (§13.1), and
//! the tally of what reached the trace is what `proxy.net` coverage is
//! computed from at settlement. The Linux `agent` bridge and the macOS
//! loopback bridge (jail-macos.md §4.10) both serve through it.

use std::sync::Mutex;
use std::time::SystemTime;

#[cfg(target_os = "macos")]
use crate::observer::CoverageSummary;
use crate::observer::{ClassSummary, CoverageClass};
use crate::proxy::{self, ProxyDecision, ProxyResult, ProxySink};
use crate::records::{Gap, SourceStatus};
use crate::trace::Priority;
use crate::trace::SharedTrace;

#[derive(Default)]
struct Tally {
    seq: u64,
    delivered: u64,
    lost: u64,
    /// Denials that were resolver capacity, not policy.
    resolver_refused: u64,
}

/// Writes each proxy result as a proxy-source `net.connect` event on the
/// proxy's own sequence (§13.1), and counts what reached the trace.
pub(crate) struct TraceSink {
    attempt_id: String,
    trace: Option<SharedTrace>,
    tally: Mutex<Tally>,
}

impl TraceSink {
    /// A sink over the attempt's trace, when one was configured.
    pub(crate) fn new(attempt_id: &str, trace: Option<SharedTrace>) -> Self {
        Self {
            attempt_id: attempt_id.to_owned(),
            trace,
            tally: Mutex::new(Tally::default()),
        }
    }

    /// The accounting snapshot for [`coverage`].
    #[must_use]
    pub(crate) fn account(&self) -> (u64, u64, u64) {
        let tally = crate::sync::lock(&self.tally);
        (tally.delivered, tally.lost, tally.resolver_refused)
    }
}

impl ProxySink for TraceSink {
    fn emit(&self, result: ProxyResult) {
        let mut tally = crate::sync::lock(&self.tally);
        tally.seq += 1;
        let event = proxy::proxy_event(
            &result,
            &self.attempt_id,
            tally.seq,
            SystemTime::now(),
            crate::platform::elapsed_since_start_ns(),
        );
        let delivered = match self.trace.as_ref() {
            Some(trace) => match trace.lock() {
                Ok(mut writer) => writer.write_event(&event, Priority::Normal).is_ok(),
                Err(_) => false,
            },
            // No trace was configured (a doctor probe): nothing was claimed
            // to be collected, so nothing is lost.
            None => true,
        };
        if delivered {
            tally.delivered += 1;
        } else {
            tally.lost += 1;
        }
        if result.decision == ProxyDecision::Deny
            && result.reason == crate::proxy::Reason::ResolverOverloaded
        {
            tally.resolver_refused += 1;
        }
    }
}

/// What the proxy's accounting established at the end of an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    /// Results that reached the trace.
    pub delivered: u64,
    /// Results the trace refused.
    pub lost: u64,
    /// Denials that were resolver capacity, not policy.
    pub resolver_refused: u64,
    /// Accepted connections whose result the drain did not deliver; `None`
    /// when the proxy was never stopped and drained.
    pub missing: Option<u64>,
    /// When the proxy was seen to stop serving on its own, in supervisor
    /// nanoseconds; requests after it were refused and have no result.
    pub stopped_at: Option<u128>,
    /// Now, in supervisor nanoseconds.
    pub now: u128,
}

/// `proxy.net` from the proxy's accounting (§11.4): active with the count of
/// results delivered to the trace only when the drain completed
/// (`missing == Some(0)`), nothing was lost in transport and the proxy never
/// stopped on its own; otherwise degraded, with a null count and a gap per
/// cause naming the class and, where it is known, the number of missing
/// results. A proxy that was never stopped and drained is never complete.
#[must_use]
pub fn coverage(account: &Account) -> ClassSummary {
    let gap = |start: u128, reason: &str, lost_count: Option<u64>| Gap {
        classes: vec![CoverageClass::ProxyNet.as_str().to_owned()],
        source: "proxy".to_owned(),
        start_ns: start.to_string(),
        end_ns: Some(account.now.to_string()),
        reason: reason.to_owned(),
        lost_count,
    };
    let mut gaps = Vec::new();
    match account.missing {
        None => gaps.push(gap(0, "proxy_not_drained", None)),
        Some(missing) if missing > 0 || account.lost > 0 => gaps.push(gap(
            0,
            if missing > 0 {
                "proxy_drain_incomplete"
            } else {
                "proxy_result_undelivered"
            },
            Some(missing + account.lost),
        )),
        Some(_) => {}
    }
    if let Some(stopped_at) = account.stopped_at {
        // How many requests the dead proxy refused is not knowable.
        gaps.push(gap(stopped_at, "proxy_stopped", None));
    }
    let status = if gaps.is_empty() {
        SourceStatus::Active
    } else {
        SourceStatus::Degraded
    };
    ClassSummary {
        status,
        observed_count: (status == SourceStatus::Active).then_some(account.delivered),
        gaps,
        resolver_refused: account.resolver_refused,
    }
}

/// Applies [`coverage`] of `account` to a summary's `proxy.net` class, the
/// settlement step every platform shares.
#[cfg(target_os = "macos")]
pub fn apply_coverage(summary: &mut CoverageSummary, account: &Account) {
    let class = coverage(account);
    summary.sources.proxy = class.status;
    summary.gaps.extend(class.gaps.iter().cloned());
    summary.classes.insert(CoverageClass::ProxyNet, class);
}
