//! Rule 6 (jail-macos §4.1): before it spawns the launcher, the guardian
//! lowers its own `RLIMIT_NPROC` soft **and** hard limit to the operator's
//! current same-UID process count plus a headroom (initial 1024), without
//! raising either inherited limit. Kernel read-back must confirm both. Every
//! member inherits the limit and cannot raise it without root, so a fork
//! storm stops at the headroom and a stop has a bounded set to freeze.
//!
//! **Amended 2026-11-02 (measured in the 2026-11-01 spike):** a default
//! host's `kern.maxprocperuid` is 1333, and the spike's guardian refused
//! during preparation wanting 1376/1378 slots. When the full 1024 does not
//! fit under the inherited ceiling, the allowance is now the inherited
//! ceiling itself — never raised, still kernel-bounded, and the membership
//! table is sized for exactly that ceiling — provided the ceiling still
//! clears the operator's snapshot by [`MIN_PROCESS_HEADROOM`]; below that
//! there is no room for a tree at all and preparation refuses with the
//! remedy named. The receipt records the applied allowance and whether it
//! was clamped.
//!
//! Count actual PID records returned by libproc's real-UID filter. Sizing
//! calls are allocation estimates, never counts. All allocation occurs
//! before release; the query retries if the returned array fills up.

/// The required headroom over the operator's process-count snapshot.
/// `apply` refuses unless kernel read-back proves this entire allowance.
pub const PROCESS_HEADROOM: u64 = 1024;

/// The smallest allowance above the operator's snapshot any attempt may
/// start with (amended rule 6). Below this even the first workload forks
/// would fail, so preparation refuses and names the remedy instead.
pub const MIN_PROCESS_HEADROOM: u64 = 128;

/// What rule 6 applied: the ceiling members inherit, the allowance above
/// the operator's snapshot, and whether the full
/// [`PROCESS_HEADROOM`] did not fit and the inherited ceiling stands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedAllowance {
    pub limit: u64,
    pub headroom: u64,
    pub clamped: bool,
}

/// Compatibility name for callers using the original 32-bit constant.
pub const NPROC_HEADROOM: u32 = PROCESS_HEADROOM as u32;

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
    lower_nproc_with(limit, read_nproc, |lowered| {
        // SAFETY: a process-local syscall with a valid rlimit value.
        if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, lowered) } != 0 {
            Err(os_error("RLIMIT_NPROC: setrlimit"))
        } else {
            Ok(())
        }
    })
}

fn read_nproc() -> Result<libc::rlimit, RlimitError> {
    let mut value = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills the valid stack value for this process.
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut value) } != 0 {
        Err(os_error("RLIMIT_NPROC: getrlimit"))
    } else {
        Ok(value)
    }
}

fn lower_nproc_with(
    limit: u64,
    mut get: impl FnMut() -> Result<libc::rlimit, RlimitError>,
    mut set: impl FnMut(&libc::rlimit) -> Result<(), RlimitError>,
) -> Result<(), RlimitError> {
    let inherited = get()?;
    let limit = limit_with_headroom(0, limit, inherited.rlim_max)?;
    if limit > inherited.rlim_cur {
        return Err(RlimitError(
            "insufficient_headroom",
            format!("need {limit}, inherited soft limit {}", inherited.rlim_cur),
        ));
    }
    set(&libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    })?;
    // Darwin can return success while clamping NPROC to kern.maxprocperuid.
    // The requested limit is not evidence of the allowance actually inherited.
    let effective = get()?;
    if effective.rlim_cur < limit || effective.rlim_max < limit {
        return Err(RlimitError(
            "insufficient_headroom",
            format!(
                "need {limit}, kernel applied soft {} hard {}",
                effective.rlim_cur, effective.rlim_max
            ),
        ));
    }
    if effective.rlim_cur != limit || effective.rlim_max != limit {
        return Err(RlimitError(
            "RLIMIT_NPROC: read-back",
            "kernel did not lower both limits to the requested ceiling".to_owned(),
        ));
    }
    Ok(())
}

/// The amended rule-6 decision, pure for tests: the allowance for a given
/// snapshot and inherited limits. `Ok` with `clamped: false` lowers to
/// `current + PROCESS_HEADROOM`; `Ok` with `clamped: true` keeps the
/// inherited ceiling (never raising either limit); `Err` names the floor
/// and the remedy when even the minimum does not fit.
pub fn allowance_for(current: u64, soft: u64, hard: u64) -> Result<AppliedAllowance, RlimitError> {
    let desired = current.saturating_add(PROCESS_HEADROOM).min(i64::MAX as u64);
    let ceiling = soft.min(hard);
    if desired <= ceiling {
        return Ok(AppliedAllowance {
            limit: desired,
            headroom: PROCESS_HEADROOM,
            clamped: false,
        });
    }
    if ceiling >= current.saturating_add(MIN_PROCESS_HEADROOM) {
        return Ok(AppliedAllowance {
            limit: ceiling,
            headroom: ceiling - current,
            clamped: true,
        });
    }
    Err(RlimitError(
        "insufficient_headroom",
        format!(
            "need at least {MIN_PROCESS_HEADROOM} above the operator's {current} processes, \
             inherited soft {soft} hard {hard}; close processes or raise kern.maxprocperuid"
        ),
    ))
}

/// The supervisor-side view of the amended rule-6 decision, taken at
/// prepare time before any member exists (the same snapshot domain the
/// guardian's authoritative [`apply`] uses moments later): what the
/// receipt records as the planned allowance. The guardian still gates the
/// run with its own read and refuses on any disagreement.
pub fn plan_allowance() -> Result<AppliedAllowance, RlimitError> {
    // SAFETY: plain getuid.
    let uid = unsafe { libc::getuid() };
    let count = current_process_count_for_uid(uid)?;
    let inherited = read_nproc()?;
    allowance_for(count, inherited.rlim_cur, inherited.rlim_max)
}

/// The rule-6 step whole: count this operator's processes, decide the
/// allowance, apply it. The normal path lowers both limits with kernel
/// read-back; the clamped path leaves the inherited limits untouched
/// (never raising) and re-reads them once to confirm the ceiling still
/// clears the floor. Returns what was applied, for the receipt.
pub fn apply() -> Result<AppliedAllowance, RlimitError> {
    // SAFETY: plain getuid.
    let uid = unsafe { libc::getuid() };
    let count = current_process_count_for_uid(uid)?;
    let inherited = read_nproc()?;
    let planned = allowance_for(count, inherited.rlim_cur, inherited.rlim_max)?;
    if planned.clamped {
        // Nothing to set: the members inherit the ceiling as it stands. A
        // re-read confirms no concurrent change moved the ceiling between
        // decision and use; a moved limit is a refusal, not a race to
        // re-decide against.
        let effective = read_nproc()?;
        let confirmed = allowance_for(count, effective.rlim_cur, effective.rlim_max)?;
        if confirmed != planned {
            return Err(RlimitError(
                "insufficient_headroom",
                "inherited limits changed during preparation".to_owned(),
            ));
        }
        return Ok(planned);
    }
    lower_nproc(planned.limit)?;
    Ok(planned)
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

    // The amended rule-6 decision, on the 2026-11-01 spike's measured
    // default-host shape: 352 same-UID processes against a 1333 ceiling.
    #[test]
    fn a_default_host_ceiling_clamps_instead_of_refusing() {
        let applied = allowance_for(352, 1333, 1333).expect("clamped allowance");
        assert_eq!(
            applied,
            AppliedAllowance {
                limit: 1333,
                headroom: 1333 - 352,
                clamped: true
            }
        );
        // The unclamped shape is unchanged where the full headroom fits.
        assert_eq!(
            allowance_for(300, 2000, 2000).unwrap(),
            AppliedAllowance {
                limit: 300 + PROCESS_HEADROOM,
                headroom: PROCESS_HEADROOM,
                clamped: false
            }
        );
        // A tight inherited soft limit also clamps to itself, never raises.
        let clamped = allowance_for(500, 1200, 2000).unwrap();
        assert_eq!(clamped.limit, 1200);
        assert!(clamped.clamped);
        // Below the minimum floor the refusal names numbers and remedy.
        let refusal = allowance_for(1300, 1333, 1333).unwrap_err().to_string();
        assert!(refusal.starts_with("insufficient_headroom:"), "{refusal}");
        assert!(refusal.contains("close processes or raise kern.maxprocperuid"), "{refusal}");
        assert!(allowance_for(u64::MAX, 2000, 2000).is_err(), "overflow refuses");
    }

    #[test]
    fn r3_c1_kernel_read_back_must_confirm_the_full_headroom_and_ceiling() {
        use std::cell::Cell;
        let count = 750;
        let desired = count + PROCESS_HEADROOM;
        for (soft, hard, expected) in [
            (desired, desired, None),
            (desired - 1, desired, Some("insufficient_headroom:")),
            (desired, desired - 1, Some("insufficient_headroom:")),
            (desired - 1, desired - 1, Some("insufficient_headroom:")),
            (desired, desired + 1, Some("RLIMIT_NPROC: read-back:")),
        ] {
            let reads = Cell::new(0);
            let set_called = Cell::new(false);
            let result = lower_nproc_with(
                desired,
                || {
                    let previous = reads.get();
                    reads.set(previous + 1);
                    Ok(if previous == 0 {
                        libc::rlimit {
                            rlim_cur: 5000,
                            rlim_max: 6000,
                        }
                    } else {
                        assert!(set_called.get());
                        libc::rlimit {
                            rlim_cur: soft,
                            rlim_max: hard,
                        }
                    })
                },
                |requested| {
                    assert_eq!((requested.rlim_cur, requested.rlim_max), (desired, desired));
                    set_called.set(true);
                    Ok(()) // Success does not imply the kernel applied what we asked.
                },
            );
            assert_eq!(
                reads.get(),
                2,
                "must inspect the effective kernel allowance"
            );
            if let Some(prefix) = expected {
                assert!(result.unwrap_err().to_string().starts_with(prefix));
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    fn r3_c1_apply_never_raises_the_inherited_soft_limit() {
        const CHILD: &str = "UKAI_TEST_NPROC_SOFT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::macos::guardian::rlimit::tests::r3_c1_apply_never_raises_the_inherited_soft_limit",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
            assert!(stdout.contains("soft-limit fixture ran"), "{stdout}");
            return;
        }
        // SAFETY: all limit changes are confined to this child process.
        unsafe {
            let mut original: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut original), 0);
            let inherited = libc::rlimit {
                rlim_cur: original.rlim_cur.min(u64::from(NPROC_HEADROOM) - 1),
                rlim_max: original.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_NPROC, &inherited), 0);
            let count = current_process_count_for_uid(libc::getuid()).unwrap();
            let result = apply();
            let mut after: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut after), 0);
            assert_eq!(
                after.rlim_cur, inherited.rlim_cur,
                "operator's soft ceiling changed"
            );
            // Amended rule 6: a soft ceiling below the full headroom no
            // longer refuses — the ceiling itself is the allowance as long
            // as it clears the snapshot by the minimum. Both shapes keep
            // the soft limit untouched; only a floor violation refuses.
            let floor_fits = inherited.rlim_cur >= count + MIN_PROCESS_HEADROOM;
            match (result, floor_fits) {
                (Ok(applied), true) => {
                    assert!(applied.clamped, "clamped to the inherited soft ceiling");
                    assert_eq!(applied.limit, inherited.rlim_cur);
                }
                (Err(error), false) => {
                    assert!(error.to_string().starts_with("insufficient_headroom:"));
                }
                (result, fits) => panic!("apply() disagreed with the floor: {result:?} fits={fits}"),
            }
        }
        println!("soft-limit fixture ran");
    }

    #[test]
    fn r3_c3_isolated_limit_test_emits_one_harness_result() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "platform::macos::guardian::rlimit::tests::lowers_both_limits",
                "--nocapture",
            ])
            .env_remove("UKAI_TEST_NPROC_CHILD")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.matches("test result:").count(),
            1,
            "nested harness results corrupt suite_clean: {stdout}"
        );
        assert_eq!(stdout.matches("running 1 test").count(), 1, "{stdout}");
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
    }

    // Isolate the irreversible hard-limit change in a child test process.
    #[test]
    fn lowers_both_limits() {
        const CHILD: &str = "UKAI_TEST_NPROC_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform::macos::guardian::rlimit::tests::lowers_both_limits",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
            assert!(stdout.contains("lowered-limit fixture ran"), "{stdout}");
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
        println!("lowered-limit fixture ran");
    }
}
