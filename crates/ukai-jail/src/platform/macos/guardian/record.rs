//! The guardian record (`ukai.jail.guardian-record/1`, jail-macos §4.4).
//!
//! The supervisor creates the file before it spawns the guardian; the
//! guardian writes it **once**, when its stop ends, and sends the same JSON
//! as the final frame on B. `gc` reads it to learn how a stop ended once the
//! supervisor is gone (§4.9): `drained` lets it verify the tree's end on the
//! same boot; `not_drained` with the reason (`gap`, `integrity` or `budget`)
//! keeps the attempt's `tree_unknown`.
//!
//! Timestamps are nanoseconds on the continuous clock (`mach_continuous_time`,
//! which counts sleep), so `started_at`/`ended_at` are comparable with the
//! supervisor's wall deadline and across a host sleep (§4.3 step 6). Tokens
//! are the eight `u32` audit-token words; `boot_session` is
//! `kern.bootsessionuuid`, how `gc` tells a reboot from a same-boot loss.

use serde::Serialize;

use crate::platform::macos::custody::StopNotDrainedReason;
use crate::platform::macos::custody::StopResult;
use crate::platform::macos::custody_io::Token;

pub const SCHEMA: &str = "ukai.jail.guardian-record/1";

#[derive(Clone, Serialize)]
pub struct GuardianRecord {
    pub schema: &'static str,
    pub drained: bool,
    /// `None` when drained; otherwise why the stop did not drain.
    pub reason: Option<&'static str>,
    pub forks: u64,
    pub execs: u64,
    pub exits: u64,
    pub guard_denials: u64,
    pub sweeps: u64,
    pub signalled: u64,
    /// Continuous-clock nanoseconds at the guardian's start.
    pub started_at: u64,
    /// Continuous-clock nanoseconds when the stop ended.
    pub ended_at: u64,
    pub own_token: Token,
    /// The launcher's first token, as sent from A after `blocked` (§4.3
    /// step 5); all zeros when the stop came first.
    pub launcher_first_token: Token,
    /// `kern.bootsessionuuid`.
    pub boot_session: String,
    pub members_peak: usize,
    /// Whether G′ was armed for the stop; `false` also when the
    /// subscription failed and the stop proceeded unguarded (§4.5 step 1).
    pub guard_armed: bool,
    /// ES documents increments, not a first-value baseline. Drops before
    /// the first delivered message cannot be distinguished within the
    /// accepted 0/1 start convention; disclose this on every record.
    pub sequence_start: &'static str,
}

/// Map the engine's failure reason to the record's reason vocabulary.
pub fn reason_name(reason: StopNotDrainedReason) -> &'static str {
    match reason {
        StopNotDrainedReason::Gap => "gap",
        StopNotDrainedReason::Integrity => "integrity",
        StopNotDrainedReason::Budget => "budget",
    }
}

/// Render the record as the exact bytes written to the file and sent on B.
pub fn render(record: &GuardianRecord) -> String {
    let mut value = serde_json::to_string(record).unwrap_or_default();
    value.push('\n');
    value
}

/// Serialize once into bounded stack storage and attempt both sinks. The
/// file was opened before release. Failure of one sink never suppresses the
/// other; the record and B carry identical bytes when both writes succeed.
pub fn deliver(
    record: &GuardianRecord,
    file: &mut dyn std::io::Write,
    b: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut wire = [0u8; super::frames::MAX_FRAME_BYTES + 4];
    wire[4..11].copy_from_slice(b"record ");
    let mut json = std::io::Cursor::new(&mut wire[11..]);
    serde_json::to_writer(&mut json, record).map_err(std::io::Error::other)?;
    json.write_all(b"\n")?;
    let end = 11 + json.position() as usize;
    wire[..4].copy_from_slice(&((end - 4) as u32).to_le_bytes());
    let persisted = file.write_all(&wire[11..end]).and_then(|()| file.flush());
    let sent = b.write_all(&wire[..end]);
    persisted.and(sent)
}

/// The guardian's tallies that travel with the stop result into the record.
pub struct StopFacts {
    /// Custody event counts, in `Fork, Exec, Exit` order.
    pub counts: [u64; 3],
    pub guard_denials: u64,
    pub started_at: u64,
    pub ended_at: u64,
    pub members_peak: usize,
    pub guard_armed: bool,
}

/// Build the record from a stop's result and the guardian's tallies.
pub fn from_stop_result(
    result: &StopResult,
    facts: StopFacts,
    own_token: Token,
    launcher_first_token: Token,
    boot_session: String,
) -> GuardianRecord {
    let (drained, reason, sweeps, signalled) = match *result {
        StopResult::Drained {
            elapsed_ns: _,
            sweeps,
            signalled,
        } => (true, None, sweeps, signalled),
        StopResult::NotDrained {
            reason,
            elapsed_ns: _,
            sweeps,
            signalled,
        } => (false, Some(reason_name(reason)), sweeps, signalled),
    };
    GuardianRecord {
        schema: SCHEMA,
        drained,
        reason,
        forks: facts.counts[0],
        execs: facts.counts[1],
        exits: facts.counts[2],
        guard_denials: facts.guard_denials,
        sweeps,
        signalled,
        started_at: facts.started_at,
        ended_at: facts.ended_at,
        own_token,
        launcher_first_token,
        boot_session,
        members_peak: facts.members_peak,
        guard_armed: facts.guard_armed,
        sequence_start: "unverified",
    }
}

/// `kern.bootsessionuuid` via `sysctlbyname` (the kernel does not export a
/// MIB constant for it). An empty string when the kernel does not answer:
/// the record still writes, and `gc` then treats the boot session as
/// unknown rather than guessing.
pub fn boot_session_uuid() -> String {
    const NAME: &[u8] = b"kern.bootsessionuuid\0";
    let mut size = 0usize;
    // SAFETY: plain sysctlbyname queries with a fixed, kernel-known name;
    // the first call sizes the buffer, the second reads into it.
    unsafe {
        if libc::sysctlbyname(
            NAME.as_ptr().cast(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
            || size == 0
        {
            return String::new();
        }
        let mut buffer = vec![0u8; size];
        if libc::sysctlbyname(
            NAME.as_ptr().cast(),
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return String::new();
        }
        buffer.truncate(size);
        // The kernel returns a NUL-terminated UUID string.
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::macos::custody::StopNotDrainedReason;

    fn drained_result() -> StopResult {
        StopResult::Drained {
            elapsed_ns: 100,
            sweeps: 5,
            signalled: 9,
        }
    }

    // The JSON shape is the contract `gc` reads (§4.9): schema string,
    // `drained`, an optional reason, counts, continuous-clock timestamps,
    // the two eight-word tokens, the boot session, the peak and whether the
    // guard was armed.
    #[test]
    fn renders_contract_shape() {
        let own = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let launcher = [9u32, 10, 11, 12, 13, 14, 15, 16];
        let record = from_stop_result(
            &drained_result(),
            StopFacts {
                counts: [12, 30, 42],
                guard_denials: 0,
                started_at: 100,
                ended_at: 200,
                members_peak: 9,
                guard_armed: true,
            },
            own,
            launcher,
            "boot-uuid".to_owned(),
        );
        let json = render(&record);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["schema"], "ukai.jail.guardian-record/1");
        assert_eq!(value["sequence_start"], "unverified");
        assert_eq!(value["drained"], true);
        assert_eq!(value["reason"], serde_json::Value::Null);
        assert_eq!(value["forks"], 12);
        assert_eq!(value["execs"], 30);
        assert_eq!(value["exits"], 42);
        assert_eq!(value["guard_denials"], 0);
        assert_eq!(value["sweeps"], 5);
        assert_eq!(value["signalled"], 9);
        assert_eq!(value["started_at"], 100);
        assert_eq!(value["ended_at"], 200);
        assert_eq!(
            value["own_token"],
            serde_json::json!([1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(
            value["launcher_first_token"],
            serde_json::json!([9, 10, 11, 12, 13, 14, 15, 16])
        );
        assert_eq!(value["boot_session"], "boot-uuid");
        assert_eq!(value["members_peak"], 9);
        assert_eq!(value["guard_armed"], true);
        assert!(json.ends_with('\n'));
    }

    // A stop that did not drain names exactly one of the three reasons.
    #[test]
    fn renders_not_drained_reasons() {
        for (reason, name) in [
            (StopNotDrainedReason::Gap, "gap"),
            (StopNotDrainedReason::Integrity, "integrity"),
            (StopNotDrainedReason::Budget, "budget"),
        ] {
            let result = StopResult::NotDrained {
                reason,
                elapsed_ns: 1,
                sweeps: 1,
                signalled: 1,
            };
            let json = render(&from_stop_result(
                &result,
                StopFacts {
                    counts: [0; 3],
                    guard_denials: 0,
                    started_at: 0,
                    ended_at: 0,
                    members_peak: 0,
                    guard_armed: false,
                },
                [0; 8],
                [0; 8],
                String::new(),
            ));
            let value: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
            assert_eq!(value["drained"], false);
            assert_eq!(value["reason"], serde_json::json!(name));
        }
    }

    // `boot_session_uuid` answers on this host (or, only if the kernel
    // refuses, with the empty string — never an error path).
    #[test]
    fn boot_session_is_a_uuid_or_empty() {
        let session = boot_session_uuid();
        assert!(session.is_empty() || session.len() == 36);
    }
}
