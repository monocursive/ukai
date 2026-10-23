//! Mach/libproc primitives do not require Endpoint Security or its SDK APIs.
//! Keep them available for clocks, process identity and GC in either build.
#[repr(C)]
struct AuditToken {
    val: [u32; 8],
}

unsafe extern "C" {
    fn proc_signal_with_audittoken(token: *mut AuditToken, sig: i32) -> i32;
    static mach_task_self_: u32;
    fn task_info(task: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
    fn mach_continuous_time() -> u64;
}

/// `proc_signal_with_audittoken`; returns the errno. The only signalling path
/// in the design — a PID never goes through `kill(2)` (§4.1 rule 5).
pub fn signal_by_token(token: &[u32; 8], sig: i32) -> i32 {
    // SAFETY: a local copy has the eight-word audit_token_t layout and
    // stays live for the synchronous libproc call.
    unsafe {
        let mut token = AuditToken { val: *token };
        proc_signal_with_audittoken(&raw mut token, sig)
    }
}

/// This process's audit token (`task_info(TASK_AUDIT_TOKEN)`).
pub fn self_token() -> Option<[u32; 8]> {
    let mut token = [0u32; 8];
    let mut count = 8;
    // TASK_AUDIT_TOKEN=15, TASK_AUDIT_TOKEN_COUNT=8 (<mach/task_info.h>).
    // SAFETY: the task port is this process's, and the output is eight words.
    if unsafe {
        task_info(
            mach_task_self_,
            15,
            token.as_mut_ptr().cast(),
            &raw mut count,
        )
    } == 0
        && count == 8
    {
        Some(token)
    } else {
        None
    }
}

/// `mach_continuous_time` ticks; counts sleep, as the wall deadline must
/// (§4.3 step 6). Convert once with [`mach_timebase_info`] to nanoseconds.
pub fn continuous_time() -> u64 {
    // SAFETY: the function takes no arguments and cannot fail unsafely.
    unsafe { mach_continuous_time() }
}

/// `mach_continuous_time` converted to nanoseconds on the continuous clock.
pub fn continuous_time_ns() -> u64 {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    // Declared in <mach/mach_time.h>; libc exposes it only behind the
    // deprecated `mach2` pairing, so the one-call declaration lives here.
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> u32;
    }
    let mut timebase = Timebase { numer: 0, denom: 0 };
    // SAFETY: `timebase` is a valid out record; the call returns
    // KERN_SUCCESS or leaves the record with a zero denominator, which the
    // fallback covers.
    let (numer, denom) = if unsafe { mach_timebase_info(&mut timebase) } == 0 {
        (timebase.numer as u64, timebase.denom as u64)
    } else {
        (1, 1)
    };
    if denom == 0 {
        return 0;
    }
    ((u128::from(continuous_time()) * u128::from(numer)) / u128::from(denom))
        .min(u128::from(u64::MAX)) as u64
}
