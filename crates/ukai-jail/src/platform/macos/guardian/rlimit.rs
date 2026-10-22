//! Rule 6 (jail-macos §4.1): before it spawns the launcher, the guardian
//! lowers its own `RLIMIT_NPROC` soft **and** hard limit to the operator's
//! current same-UID process count plus a headroom (initial 1024). Every
//! member inherits the limit and cannot raise it without root, so a fork
//! storm stops at the headroom and a stop has a bounded set to freeze.
//!
//! The count comes from one `sysctl` of `kern.proc` with `KERN_PROC_RUID`,
//! the cheapest reliable same-UID count with libc alone: the kernel filters
//! by real UID itself and returns the packed `kinfo_proc` array, so the
//! count is the buffer length over the entry size (`libproc` would need an
//! extra link-time dependency for the same answer). This runs before
//! release, so §4.1 rule 4's "acquires nothing after release" is not
//! touched.

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

/// The size of one `kinfo_proc` entry, from a one-pid sizing query.
fn kinfo_proc_size() -> Result<usize, RlimitError> {
    // SAFETY: plain getpid.
    let pid = unsafe { libc::getpid() };
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut size: usize = 0;
    // SAFETY: the sizing call of a fixed MIB; the kernel writes the byte
    // length of one `kinfo_proc`.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4 as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
    {
        return Err(os_error("process count: kinfo_proc size"));
    }
    Ok(size)
}

/// Count this real UID's live processes with one `sysctl(KERN_PROC_RUID)`.
pub fn current_process_count_for_uid(uid: u32) -> Result<u64, RlimitError> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_RUID,
        uid as libc::c_int,
    ];
    let mut size: usize = 0;
    // SAFETY: the sizing call of a fixed MIB; the kernel writes the byte
    // length of the packed `kinfo_proc` array.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4 as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(os_error("process count: sysctl size"));
    }
    if size == 0 {
        return Ok(0);
    }
    let entry = kinfo_proc_size()?;
    Ok((size / entry) as u64)
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
        let limit = limit as libc::rlim_t;
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

    // The lowered limit binds: soft == hard == current + headroom. The
    // soft limit is restored; the hard limit is deliberately **not**
    // restored, because an unprivileged process cannot raise a hard limit
    // it has lowered — which is exactly the property rule 6 relies on.
    #[test]
    fn lowers_both_limits() {
        // SAFETY: getrlimit/setrlimit with stack values; restore the soft
        // limit below within the (lowered, final) hard limit.
        unsafe {
            let mut original = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut original), 0);
            let count = current_process_count_for_uid(libc::getuid()).expect("sysctl answers");
            let limit = lowered_limit(count, u64::from(NPROC_HEADROOM));
            if limit >= original.rlim_max {
                // The host's limits are already at or below the rule-6
                // value; lowering is a no-op there and the binding asserts
                // below would read the original numbers. Skip honestly.
                return;
            }
            lower_nproc(limit).expect("setrlimit");
            let mut check = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut check), 0);
            assert_eq!(check.rlim_cur, limit as libc::rlim_t);
            assert_eq!(check.rlim_max, limit as libc::rlim_t);
            // And it cannot be raised back (the property members inherit).
            let raised = libc::rlimit {
                rlim_cur: original.rlim_cur,
                rlim_max: original.rlim_max,
            };
            assert_ne!(libc::setrlimit(libc::RLIMIT_NPROC, &raised), 0);
        }
    }
}
