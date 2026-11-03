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
//! remedy named.
//!
//! **D13 (2026-11-03):** the clamped path lowers both limits too: soft and
//! hard become the inherited ceiling `min(soft, hard)`, with the same kernel
//! read-back as the normal path. Before, it set nothing, so where the
//! inherited soft limit sat below the hard limit a member could raise its
//! soft limit back up to `min(hard, kern.maxprocperuid)`: Darwin caps every
//! non-root `RLIMIT_NPROC` at `kern.maxprocperuid` (measured on this Mac,
//! non-root: a soft 12000 request succeeds but reads back 10666, soft 16000
//! fails with `EINVAL`, and `(5000, 16000)` reads back `(5000, 10666)`). On
//! a default host the soft limit already sits at `kern.maxprocperuid`
//! (soft 10666, hard 16000 here), so that gained nothing; it mattered only
//! where the operator's soft limit was lower. The guardian reports the
//! allowance the kernel confirmed
//! twice: in the `allowance` frame on B, right before `ready`
//! ([`AppliedAllowance::encode_frame`]), which every receipt from
//! `prepared` on records, and in its record (`process_allowance`), which the
//! supervisor checks against the frame.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AppliedAllowance {
    pub limit: u64,
    pub headroom: u64,
    pub clamped: bool,
}

/// The B frame's prefix (guardian → supervisor, jail-macos §4.3 step 3):
/// `allowance ` + limit (`u64` LE) + headroom (`u64` LE) + clamped (one
/// byte, 0 or 1). The guardian sends it exactly once, after kernel
/// read-back confirmed both limits and immediately before `ready`.
pub const ALLOWANCE_FRAME: &[u8] = b"allowance ";

/// The frame's body length after the prefix.
const ALLOWANCE_BODY_BYTES: usize = 8 + 8 + 1;

impl AppliedAllowance {
    /// Whether the three values are a shape [`allowance_for`] can produce:
    /// the headroom fits under the limit, an unclamped allowance carries
    /// the full [`PROCESS_HEADROOM`], and a clamped one at least
    /// [`MIN_PROCESS_HEADROOM`] and less than the full headroom.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.limit <= i64::MAX as u64
            && self.headroom <= self.limit
            && if self.clamped {
                (MIN_PROCESS_HEADROOM..PROCESS_HEADROOM).contains(&self.headroom)
            } else {
                self.headroom == PROCESS_HEADROOM
            }
    }

    /// The `allowance` frame payload (without the length prefix).
    #[must_use]
    pub fn encode_frame(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ALLOWANCE_FRAME.len() + ALLOWANCE_BODY_BYTES);
        frame.extend_from_slice(ALLOWANCE_FRAME);
        frame.extend_from_slice(&self.limit.to_le_bytes());
        frame.extend_from_slice(&self.headroom.to_le_bytes());
        frame.push(u8::from(self.clamped));
        frame
    }

    /// Decode a frame body (the bytes after [`ALLOWANCE_FRAME`]). A wrong
    /// length, a clamp byte other than 0 or 1, or a shape rule 6 cannot
    /// produce is an error: the supervisor refuses rather than record it.
    pub fn decode_frame_body(body: &[u8]) -> Result<Self, &'static str> {
        let Ok(body) = <[u8; ALLOWANCE_BODY_BYTES]>::try_from(body) else {
            return Err("allowance frame: bad length");
        };
        let word = |range: std::ops::Range<usize>| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&body[range]);
            u64::from_le_bytes(bytes)
        };
        let clamped = match body[16] {
            0 => false,
            1 => true,
            _ => return Err("allowance frame: clamp flag is neither 0 nor 1"),
        };
        let allowance = Self {
            limit: word(0..8),
            headroom: word(8..16),
            clamped,
        };
        if !allowance.is_consistent() {
            return Err("allowance frame: a shape rule 6 cannot apply");
        }
        Ok(allowance)
    }
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
    lower_nproc_with(limit, read_nproc, set_nproc)
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
/// `current + PROCESS_HEADROOM`; `Ok` with `clamped: true` lowers both
/// limits to the inherited ceiling `min(soft, hard)` (never raising
/// either); `Err` names the floor and the remedy when even the minimum
/// does not fit.
pub fn allowance_for(current: u64, soft: u64, hard: u64) -> Result<AppliedAllowance, RlimitError> {
    let desired = current
        .saturating_add(PROCESS_HEADROOM)
        .min(i64::MAX as u64);
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

/// The rule-6 step whole: count this operator's processes, decide the
/// allowance, and lower soft **and** hard to its limit with kernel
/// read-back — on both paths. Clamped, the limit is the inherited ceiling
/// `min(soft, hard)`: the lower of the two stays where it is and the other
/// comes down to it, so no member can raise its soft limit above it (left
/// unset, it could, up to `min(hard, kern.maxprocperuid)`). Neither limit is
/// ever raised, and a kernel that
/// applies anything but the exact limit refuses ([`lower_nproc`]). Returns
/// what the kernel confirmed: the guardian reports it on B and in its
/// record, and the receipt records that report (§4.1 rule 6).
pub fn apply() -> Result<AppliedAllowance, RlimitError> {
    // SAFETY: plain getuid.
    let uid = unsafe { libc::getuid() };
    let count = current_process_count_for_uid(uid)?;
    apply_with(count, read_nproc, set_nproc)
}

fn set_nproc(lowered: &libc::rlimit) -> Result<(), RlimitError> {
    // SAFETY: a process-local syscall with a valid rlimit value.
    if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, lowered) } != 0 {
        Err(os_error("RLIMIT_NPROC: setrlimit"))
    } else {
        Ok(())
    }
}

/// [`apply`] over injected limit calls, for tests: decide from the first
/// read, then lower through [`lower_nproc_with`] (which re-reads, refuses
/// any raise, sets both, and reads back).
fn apply_with(
    count: u64,
    mut get: impl FnMut() -> Result<libc::rlimit, RlimitError>,
    set: impl FnMut(&libc::rlimit) -> Result<(), RlimitError>,
) -> Result<AppliedAllowance, RlimitError> {
    let inherited = get()?;
    let allowance = allowance_for(count, inherited.rlim_cur, inherited.rlim_max)?;
    lower_nproc_with(allowance.limit, get, set)?;
    Ok(allowance)
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
        assert!(
            refusal.contains("close processes or raise kern.maxprocperuid"),
            "{refusal}"
        );
        assert!(
            allowance_for(u64::MAX, 2000, 2000).is_err(),
            "overflow refuses"
        );
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

    /// Run one named test of this module in a child test process with
    /// `marker` set, so its irreversible limit changes never reach the
    /// harness running the suite; returns the child's stdout.
    fn run_isolated(name: &str, marker: &str) -> String {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("platform::macos::guardian::rlimit::tests::{name}"),
                "--nocapture",
            ])
            .env(marker, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
        stdout
    }

    fn nproc() -> libc::rlimit {
        // SAFETY: getrlimit fills a valid stack value.
        unsafe {
            let mut value: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_NPROC, &mut value), 0);
            value
        }
    }

    fn set(cur: u64, max: u64) -> libc::c_int {
        // SAFETY: a process-local setrlimit in an isolated child.
        unsafe {
            libc::setrlimit(
                libc::RLIMIT_NPROC,
                &libc::rlimit {
                    rlim_cur: cur,
                    rlim_max: max,
                },
            )
        }
    }

    // In-process, in an isolated child: a soft ceiling below the full
    // headroom and below the hard limit (the shape where the old clamped
    // path set nothing, so a member could raise its soft limit up to
    // min(hard, kern.maxprocperuid)). Amended rule 6 clamps to that soft
    // ceiling; D13: the hard limit comes down to it, and no later raise of
    // either limit succeeds.
    #[test]
    fn r3_c1_apply_never_raises_the_inherited_soft_limit() {
        const CHILD: &str = "UKAI_TEST_NPROC_SOFT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let stdout = run_isolated("r3_c1_apply_never_raises_the_inherited_soft_limit", CHILD);
            assert!(stdout.contains("soft-limit fixture ran"), "{stdout}");
            assert!(
                stdout.contains("branch=clamped") || stdout.contains("branch=floor"),
                "{stdout}"
            );
            return;
        }
        let original = nproc();
        // SAFETY: plain getuid.
        let count = current_process_count_for_uid(unsafe { libc::getuid() }).unwrap();
        // Below the hard limit by construction (soft <= hard always), so the
        // hard limit is strictly above the ceiling before apply().
        let soft = (count + PROCESS_HEADROOM / 2).min(original.rlim_cur.saturating_sub(1));
        assert_eq!(set(soft, original.rlim_max), 0);
        // The kernel may clamp the hard limit to kern.maxprocperuid; what
        // apply() inherits is what reads back now.
        let before = nproc();
        assert_eq!(before.rlim_cur, soft);
        assert!(
            before.rlim_max > before.rlim_cur,
            "fixture: hard above soft"
        );
        let result = apply();
        let after = nproc();
        assert!(
            after.rlim_cur <= before.rlim_cur && after.rlim_max <= before.rlim_max,
            "apply() raised a limit: {before:?} -> {after:?}"
        );
        assert_eq!(
            after.rlim_cur, before.rlim_cur,
            "operator's soft ceiling changed"
        );
        match result {
            Ok(applied) => {
                assert!(applied.clamped, "clamped to the inherited soft ceiling");
                assert!(applied.is_consistent(), "{applied:?}");
                assert_eq!(applied.limit, before.rlim_cur);
                // D13: the hard limit is the ceiling now. Before, a member
                // could raise its soft limit up to min(hard,
                // kern.maxprocperuid), which is `before.rlim_max` here: the
                // kernel already capped the fixture's hard limit on set.
                assert_eq!(after.rlim_max, applied.limit, "hard limit not lowered");
                let limit = applied.limit;
                for (cur, max) in [
                    (limit + 1, limit),
                    (limit + 1, limit + 1),
                    (limit + 1, before.rlim_max),
                    (limit, before.rlim_max),
                ] {
                    assert_ne!(set(cur, max), 0, "raise to ({cur}, {max}) succeeded");
                }
                let still = nproc();
                assert_eq!((still.rlim_cur, still.rlim_max), (limit, limit));
                println!("branch=clamped");
            }
            Err(error) => {
                // Only a floor violation refuses, and it touches neither.
                assert!(
                    before.rlim_cur < count + MIN_PROCESS_HEADROOM + 64,
                    "refused with room: {error}"
                );
                assert!(error.to_string().starts_with("insufficient_headroom:"));
                assert_eq!(
                    (after.rlim_cur, after.rlim_max),
                    (before.rlim_cur, before.rlim_max)
                );
                println!("branch=floor");
            }
        }
        println!("soft-limit fixture ran");
    }

    // In-process, in an isolated child: below the floor the refusal comes
    // from the decision, before any setrlimit, so neither limit moves.
    #[test]
    fn d13_apply_below_the_floor_touches_neither_limit() {
        const CHILD: &str = "UKAI_TEST_NPROC_FLOOR_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let stdout = run_isolated("d13_apply_below_the_floor_touches_neither_limit", CHILD);
            assert!(stdout.contains("floor fixture ran"), "{stdout}");
            return;
        }
        let original = nproc();
        // SAFETY: plain getuid.
        let count = current_process_count_for_uid(unsafe { libc::getuid() }).unwrap();
        let soft = (count + 16).min(original.rlim_cur);
        assert_eq!(set(soft, original.rlim_max), 0);
        let before = nproc();
        let error = apply().unwrap_err().to_string();
        assert!(error.starts_with("insufficient_headroom:"), "{error}");
        assert!(
            error.contains("close processes or raise kern.maxprocperuid"),
            "{error}"
        );
        let after = nproc();
        assert_eq!(
            (after.rlim_cur, after.rlim_max),
            (before.rlim_cur, before.rlim_max)
        );
        println!("floor fixture ran");
    }

    /// What one [`apply_on`] run left: the result, the final `(soft, hard)`
    /// and every `(soft, hard)` set request.
    struct FakeRun {
        result: Result<AppliedAllowance, RlimitError>,
        end: (u64, u64),
        calls: Vec<(u64, u64)>,
    }

    /// [`apply_with`] over a fake kernel cell: `set` stores exactly what it
    /// is asked and, like an unprivileged caller, refuses any hard-limit
    /// raise or a soft limit above the hard one.
    fn apply_on(count: u64, start: (u64, u64)) -> FakeRun {
        let cell = std::cell::Cell::new(start);
        let mut calls = Vec::new();
        let result = apply_with(
            count,
            || {
                let (rlim_cur, rlim_max) = cell.get();
                Ok(libc::rlimit { rlim_cur, rlim_max })
            },
            |requested| {
                calls.push((requested.rlim_cur, requested.rlim_max));
                if requested.rlim_max > cell.get().1 || requested.rlim_cur > requested.rlim_max {
                    return Err(RlimitError("RLIMIT_NPROC: setrlimit", "EPERM".to_owned()));
                }
                cell.set((requested.rlim_cur, requested.rlim_max));
                Ok(())
            },
        );
        FakeRun {
            result,
            end: cell.get(),
            calls,
        }
    }

    // D13 on the decision-plus-set path, with a fake kernel: every shape
    // that runs ends with soft == hard == the allowance's limit, and no
    // requested value is above what was inherited.
    #[test]
    fn d13_every_applied_shape_lowers_soft_and_hard_to_the_limit() {
        for (count, start, clamped) in [
            // This Mac's default shape: soft 10666 under hard 16000.
            (300, (10666, 16000), false),
            (10_000, (10666, 16000), true),
            // A tight soft limit under a loose hard limit.
            (500, (1200, 2000), true),
            // The 2026-11-01 spike's default-host shape, soft == hard.
            (352, (1333, 1333), true),
            (300, (2000, 2000), false),
        ] {
            let FakeRun { result, end, calls } = apply_on(count, start);
            let applied = result.unwrap_or_else(|e| panic!("{count} {start:?}: {e}"));
            assert_eq!(applied.clamped, clamped, "{count} {start:?}");
            assert!(applied.is_consistent(), "{applied:?}");
            assert_eq!(
                calls,
                vec![(applied.limit, applied.limit)],
                "{count} {start:?}"
            );
            assert_eq!(end, (applied.limit, applied.limit), "{count} {start:?}");
            assert!(
                end.0 <= start.0 && end.1 <= start.1,
                "raised: {start:?} -> {end:?}"
            );
            if clamped {
                assert_eq!(applied.limit, start.0.min(start.1));
            } else {
                assert_eq!(applied.limit, count + PROCESS_HEADROOM);
            }
        }
        // Below the floor nothing is set at all.
        let FakeRun { result, end, calls } = apply_on(1300, (1333, 2000));
        assert!(result.is_err());
        assert!(calls.is_empty());
        assert_eq!(end, (1333, 2000));
    }

    // A kernel that reports success but leaves the hard limit where it was
    // (what the old clamped path amounted to) is refused, not recorded.
    #[test]
    fn d13_clamped_read_back_must_show_the_hard_limit_lowered() {
        let reads = std::cell::Cell::new(0);
        let error = apply_with(
            500,
            || {
                reads.set(reads.get() + 1);
                Ok(libc::rlimit {
                    rlim_cur: 1200,
                    rlim_max: 2000,
                })
            },
            |_| Ok(()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.starts_with("RLIMIT_NPROC: read-back:"), "{error}");
        assert_eq!(reads.get(), 3, "decide, re-read, read back");
    }

    #[test]
    fn d13_the_allowance_frame_round_trips_and_refuses_impossible_shapes() {
        for allowance in [
            AppliedAllowance {
                limit: 1336,
                headroom: PROCESS_HEADROOM,
                clamped: false,
            },
            AppliedAllowance {
                limit: 1333,
                headroom: 668,
                clamped: true,
            },
        ] {
            let frame = allowance.encode_frame();
            let body = frame.strip_prefix(ALLOWANCE_FRAME).expect("prefix");
            assert_eq!(AppliedAllowance::decode_frame_body(body), Ok(allowance));
        }
        let good = AppliedAllowance {
            limit: 1333,
            headroom: 668,
            clamped: true,
        }
        .encode_frame();
        let body = &good[ALLOWANCE_FRAME.len()..];
        assert!(AppliedAllowance::decode_frame_body(&body[..16]).is_err());
        let mut long = body.to_vec();
        long.push(0);
        assert!(AppliedAllowance::decode_frame_body(&long).is_err());
        let mut flag = body.to_vec();
        flag[16] = 2;
        assert!(AppliedAllowance::decode_frame_body(&flag).is_err());
        for (limit, headroom, clamped) in [
            (100, 1024, false),      // headroom above the limit
            (2000, 900, false),      // unclamped without the full headroom
            (2000, 1024, true),      // clamped with the full headroom
            (1000, 64, true),        // clamped below the floor
            (u64::MAX, 1024, false), // beyond rlimit_t
        ] {
            let frame = AppliedAllowance {
                limit,
                headroom,
                clamped,
            }
            .encode_frame();
            assert!(
                AppliedAllowance::decode_frame_body(&frame[ALLOWANCE_FRAME.len()..]).is_err(),
                "{limit} {headroom} {clamped}"
            );
        }
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
