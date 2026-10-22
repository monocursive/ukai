//! Rule 6 (jail-macos §4.1): before it spawns the launcher, the guardian
//! lowers its own `RLIMIT_NPROC` soft **and** hard limit to the operator's
//! current same-UID process count plus a headroom (initial 1024). Every
//! member inherits the limit and cannot raise it without root, so a fork
//! storm stops at the headroom and a stop has a bounded set to freeze.
//!
//! Count actual PID records returned by libproc's real-UID filter. Sizing
//! calls are allocation estimates, never counts. All allocation occurs
//! before release; the query retries if the returned array fills up.

/// The initial headroom over the operator's current process count.
pub const NPROC_HEADROOM: u32 = 1024;

/// The pure math of rule 6: the lowered limit from the current same-UID
/// process count and the headroom. Saturating at `i64::MAX` because
/// `rlimit_t` on macOS is a 64-bit integer; never a wrap.
pub fn lowered_limit(current_processes: u64, headroom: u64) -> u64 {
    current_processes
        .saturating_add(headroom)
        .min(i64::MAX as u64)
}

#[derive(Debug)]
pub struct RlimitError(&'static str, String);

impl std::fmt::Display for RlimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl std::error::Error for RlimitError {}

fn os_error(step: &'static str) -> RlimitError {
    RlimitError(step, std::io::Error::last_os_error().to_string())
}

unsafe extern "C" {
    fn proc_listpids(
        kind: u32,
        uid: u32,
        buffer: *mut libc::c_void,
        bytes: libc::c_int,
    ) -> libc::c_int;
}
const PROC_RUID_ONLY: u32 = 5; // sys/proc_info.h

/// Count actual records in a complete real-UID-filtered PID snapshot.
pub fn current_process_count_for_uid(uid: u32) -> Result<u64, RlimitError> {
    // SAFETY: the null-buffer call returns the estimated byte capacity.
    let estimate = unsafe { proc_listpids(PROC_RUID_ONLY, uid, std::ptr::null_mut(), 0) };
    if estimate < 0 {
        return Err(os_error("process count: proc_listpids size"));
    }
    let mut slots = (estimate as usize / std::mem::size_of::<i32>()).saturating_add(1024);
    for _ in 0..8 {
        if slots > 1_048_576 {
            break;
        }
        let mut pids = vec![0i32; slots];
        let bytes = std::mem::size_of_val(pids.as_slice());
        // SAFETY: libproc receives the exact capacity of an initialized PID array.
        let used =
            unsafe { proc_listpids(PROC_RUID_ONLY, uid, pids.as_mut_ptr().cast(), bytes as i32) };
        if used < 0 {
            return Err(os_error("process count: proc_listpids read"));
        }
        if (used as usize) < bytes && (used as usize).is_multiple_of(std::mem::size_of::<i32>()) {
            return Ok((used as usize / std::mem::size_of::<i32>()) as u64);
        }
        slots = slots.saturating_mul(2);
    }
    Err(RlimitError(
        "process count",
        "unstable or oversized PID snapshot".to_owned(),
    ))
}

/// Clamp against the inherited hard ceiling; insufficient room is a named
/// prelaunch refusal, never an attempted hard-limit increase or reduced claim.
pub fn limit_with_headroom(current: u64, headroom: u64, hard: u64) -> Result<u64, RlimitError> {
    let desired = current
        .checked_add(headroom)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| RlimitError("insufficient_headroom", "process count overflow".to_owned()))?;
    let clamped = desired.min(hard);
    if clamped < desired {
        return Err(RlimitError(
            "insufficient_headroom",
            format!("need {desired}, inherited hard limit {hard}"),
        ));
    }
    Ok(clamped)
}

/// Lower `RLIMIT_NPROC` soft and hard to `limit`. The caller runs before
/// release; a failure refuses the attempt (§4.3 step 3).
pub fn lower_nproc(limit: u64) -> Result<(), RlimitError> {
    // SAFETY: getrlimit/setrlimit on the calling process with a stack
    // rlimit value; no invariants beyond the syscall contract.
    unsafe {
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NPROC, &mut current) != 0 {
            return Err(os_error("RLIMIT_NPROC: getrlimit"));
        }
        let limit = limit_with_headroom(0, limit, current.rlim_max)? as libc::rlim_t;
        let lowered = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };
        if libc::setrlimit(libc::RLIMIT_NPROC, &lowered) != 0 {
            return Err(os_error("RLIMIT_NPROC: setrlimit"));
        }
    }
    Ok(())
}

/// The rule-6 step whole: count this operator's processes, add the headroom,
/// lower both limits. Returns the limit applied.
pub fn apply() -> Result<u64, RlimitError> {
    // SAFETY: plain getuid.
    let uid = unsafe { libc::getuid() };
    let count = current_process_count_for_uid(uid)?;
    let limit = lowered_limit(count, u64::from(NPROC_HEADROOM));
    lower_nproc(limit)?;
    Ok(limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The math is the contract every member inherits: current + headroom,
    // saturating, never wrapping.
    #[test]
    fn adds_headroom() {
        assert_eq!(lowered_limit(312, 1024), 1336);
        assert_eq!(lowered_limit(0, 1024), 1024);
    }

    #[test]
    fn saturates_instead_of_wrapping() {
        assert_eq!(lowered_limit(u64::MAX, 1024), i64::MAX as u64);
        assert_eq!(lowered_limit(i64::MAX as u64, 1), i64::MAX as u64);
    }

    // The count answers on this host and is at least one (this test runs).
    // The kernel's RUID filter is what rule 6 needs; another UID's count is
    // not expected to match ours.
    #[test]
    fn counts_this_operators_processes() {
        // SAFETY: plain getuid.
        let uid = unsafe { libc::getuid() };
        let count = current_process_count_for_uid(uid).expect("sysctl answers");
        assert!(count > 0);
    }

    #[test]
    fn insufficient_headroom_is_named_before_setrlimit() {
        assert!(
            limit_with_headroom(900, 200, 1000)
                .unwrap_err()
                .to_string()
                .starts_with("insufficient_headroom:")
        );
        assert_eq!(limit_with_headroom(900, 100, 1000).unwrap(), 1000);
        assert_eq!(limit_with_headroom(100, 100, 1000).unwrap(), 200);
    }

    // Isolate the irreversible hard-limit change in a child test process.
    #[test]
    fn lowers_both_limits() {
        const CHILD: &str = "UKAI_TEST_NPROC_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::macos::guardian::rlimit::tests::lowers_both_limits",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // SAFETY: process-local rlimits in this isolated child only.
        unsafe {
            let mut original: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut original), 0);
            let count = current_process_count_for_uid(libc::getuid()).unwrap();
            let limit = limit_with_headroom(count, 32, original.rlim_max).unwrap();
            lower_nproc(limit).unwrap();
            let mut check: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut check), 0);
            assert_eq!((check.rlim_cur, check.rlim_max), (limit, limit));
            assert!(
                lower_nproc(original.rlim_max.saturating_add(1))
                    .unwrap_err()
                    .to_string()
                    .starts_with("insufficient_headroom:")
            );
        }
    }
}
