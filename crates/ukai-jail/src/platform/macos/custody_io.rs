//! The guardian's custody I/O facade: the one module the guardian mode reads
//! the ES shim (`super::es`) and the pure custody engine (`super::custody`)
//! through.
//!
//! Guardian mode stays small (jail-macos §4.1 rule 2: libc, the ES shim and
//! audit-token signalling). Everything the guardian uses from the shim
//! passes through the re-exports and the small setup helpers here, so the
//! binding between the two slices is visible in one file.
//!
//! The split of responsibility mirrors §4.3 step 3: a **custody client G**
//! is created, unmuted, checked against the read-back mute set and
//! subscribed to the three custody events; the **guard client G′** is a
//! second descendants client, unmuted and muted on the guardian's own
//! process (`es_mute_process`), subscribed to nothing until a stop (§4.5
//! step 1 arms it, and a failed arm proceeds unguarded and records it). The
//! shim's `prepare_guard` sets and reads back
//! `ES_DEADLINE_MISS_MODE_FAIL_CLOSED` before readiness, at step 3.

use crate::platform::macos::custody::{CustodyKind, Signaller};
use crate::platform::macos::es;

pub use crate::platform::macos::custody::{
    self, Custodian, MAX_TABLE_CAPACITY, StopResult, table_capacity,
};
pub use crate::platform::macos::es::{
    CustodyClient, EsEvent, EsNewResult, continuous_time_ns, self_token, signal_by_token,
};

/// An audit token: eight `u32` words.
pub type Token = [u32; 8];

/// The one-line refusal name for a client-creation result (§4.3 step 1:
/// refuse naming the result code). Unknown codes print raw, so a future
/// macOS release can still add a variant without lying.
#[must_use]
pub fn es_new_result_name(result: EsNewResult) -> String {
    match result {
        EsNewResult::Success => "SUCCESS".to_owned(),
        EsNewResult::InvalidArgument => "ERR_INVALID_ARGUMENT".to_owned(),
        EsNewResult::Internal => "ERR_INTERNAL".to_owned(),
        EsNewResult::NotEntitled => "ERR_NOT_ENTITLED".to_owned(),
        EsNewResult::NotPermitted => "ERR_NOT_PERMITTED".to_owned(),
        EsNewResult::NotPrivileged => "ERR_NOT_PRIVILEGED".to_owned(),
        EsNewResult::TooManyClients => "ERR_TOO_MANY_CLIENTS".to_owned(),
        EsNewResult::Other(raw) => format!("ERR_ES_NEW_{raw}"),
    }
}

/// Create client G: a descendants client (§4.3 step 3).
///
/// # Errors
/// The mapped `es_new_client_result_t`, for the one-line refusal.
pub fn create_custody_client() -> Result<CustodyClient, EsNewResult> {
    CustodyClient::new()
}

/// The unmute-and-check of §4.3 step 1: unmute every default-muted path and
/// target path, read `es_muted_paths_events` back for each of the three
/// custody events, and refuse naming any event still muted. Then subscribe
/// the custody events.
pub fn setup_custody(client: &CustodyClient) -> Result<(), String> {
    if !client.unmute_all() {
        return Err("es_unmute_all failed".to_owned());
    }
    for (kind, name) in [
        (CustodyKind::Fork, "NOTIFY_FORK"),
        (CustodyKind::Exec, "NOTIFY_EXEC"),
        (CustodyKind::Exit, "NOTIFY_EXIT"),
    ] {
        if client.muted_paths_events(event_type_of(kind)) {
            return Err(format!("{name} still muted after unmute_all"));
        }
    }
    if !client.subscribe_custody() {
        return Err("es_subscribe failed for the custody events".to_owned());
    }
    Ok(())
}

/// Prepare G′ at step 3; a failure refuses before ready/spawn. Only the
/// authorization subscription is deferred until the stop.
pub fn setup_guard(client: &CustodyClient) -> Result<(), String> {
    setup_guard_with(client)
}

trait GuardSetup {
    fn fail_closed(&self) -> bool;
    fn unmute(&self) -> bool;
    fn mute_guardian(&self) -> bool;
}

impl GuardSetup for CustodyClient {
    fn fail_closed(&self) -> bool {
        self.prepare_guard()
    }
    fn unmute(&self) -> bool {
        self.unmute_all()
    }
    fn mute_guardian(&self) -> bool {
        self.mute_self()
    }
}

fn setup_guard_with(client: &impl GuardSetup) -> Result<(), String> {
    if !client.fail_closed() {
        return Err("ES_DEADLINE_MISS_MODE_FAIL_CLOSED set/readback failed".to_owned());
    }
    if !client.unmute() {
        return Err("es_unmute_all failed on the guard client".to_owned());
    }
    if !client.mute_guardian() {
        return Err("es_mute_process failed for the guardian".to_owned());
    }
    Ok(())
}

/// Arm G′ at a stop (§4.5 step 1): subscribe `AUTH_SIGNAL`,
/// `AUTH_PROC_SUSPEND_RESUME` and `AUTH_EXEC` with fail-closed deadline
/// mode, denying every delivered request inline. `false` means the stop
/// proceeds unguarded and the record says so.
pub fn arm_guard(client: &CustodyClient) -> bool {
    client.subscribe_guard()
}

/// Shim-internal kinds; the C boundary maps these to SDK enum values.
fn event_type_of(kind: CustodyKind) -> u32 {
    match kind {
        CustodyKind::Fork => es::EVENT_FORK,
        CustodyKind::Exec => es::EVENT_EXEC,
        CustodyKind::Exit => es::EVENT_EXIT,
    }
}

/// Map a drained message's raw kind to the custody kind; `None` for
/// anything outside the custody set (which the sticky gap flag already
/// records).
#[must_use]
pub fn custody_kind(kind: u32) -> Option<CustodyKind> {
    match kind {
        es::EVENT_FORK => Some(CustodyKind::Fork),
        es::EVENT_EXEC => Some(CustodyKind::Exec),
        es::EVENT_EXIT => Some(CustodyKind::Exit),
        _ => None,
    }
}

/// The real signalling route (§4.1 rule 5): `proc_signal_with_audittoken`,
/// errno returned as the trait's currency.
pub struct EsSignaller;

impl Signaller for EsSignaller {
    fn signal(&mut self, token: &[u32; 8], sig: i32) -> i32 {
        signal_by_token(token, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Fake {
        calls: RefCell<Vec<&'static str>>,
        fail_closed: bool,
    }
    impl GuardSetup for Fake {
        fn fail_closed(&self) -> bool {
            self.calls.borrow_mut().push("fail_closed");
            self.fail_closed
        }
        fn unmute(&self) -> bool {
            self.calls.borrow_mut().push("unmute");
            true
        }
        fn mute_guardian(&self) -> bool {
            self.calls.borrow_mut().push("mute");
            true
        }
    }
    #[test]
    fn guard_setup_verifies_fail_closed_before_readiness() {
        for available in [true, false] {
            let fake = Fake {
                calls: RefCell::new(Vec::new()),
                fail_closed: available,
            };
            let result = setup_guard_with(&fake);
            if available {
                assert!(result.is_ok());
                assert_eq!(*fake.calls.borrow(), ["fail_closed", "unmute", "mute"]);
            } else {
                assert!(result.unwrap_err().contains("FAIL_CLOSED"));
                assert_eq!(*fake.calls.borrow(), ["fail_closed"]);
            }
        }
    }
}
