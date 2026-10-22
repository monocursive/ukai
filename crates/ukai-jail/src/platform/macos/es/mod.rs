//! Safe Rust bindings over the ES custody shim (`shim.c`).
//!
//! The shim holds every raw pointer; these wrappers expose fixed-size values
//! only (jail-macos §4.1 rule 3). `CustodyClient` is the custody client of
//! §4.3 step 1; the guard-client wrappers of §4.3 step 3 and §4.5 step 1 sit
//! on the same type because they are one process's second ES client, created
//! with the same fixed-size discipline.
#![cfg(target_os = "macos")]

use std::ptr;

/// Shim-internal custody event numbers. They mirror the `UKAI_ES_EVENT_*`
/// enum in `shim.h`; both sides count on the fixed mapping.
pub const EVENT_FORK: u32 = 1;
pub const EVENT_EXEC: u32 = 2;
pub const EVENT_EXIT: u32 = 3;

mod shim {
    // Declared in shim.h; compiled by build.rs with the EndpointSecurity
    // and CoreFoundation frameworks.
    unsafe extern "C" {
        pub fn ukai_es_new_descendants(out: *mut *mut UkaiEsClient) -> i32;
        pub fn ukai_es_unmute_all(client: *mut UkaiEsClient) -> bool;
        pub fn ukai_es_muted_paths_events(client: *mut UkaiEsClient, event_type: u32) -> bool;
        pub fn ukai_es_subscribe_custody(client: *mut UkaiEsClient) -> bool;
        pub fn ukai_es_subscribe_guard(client: *mut UkaiEsClient) -> bool;
        pub fn ukai_es_mute_self(client: *mut UkaiEsClient) -> bool;
        pub fn ukai_es_poll(client: *mut UkaiEsClient, out: *mut UkaiEsEvent) -> bool;
        pub fn ukai_es_ring_overflowed(client: *mut UkaiEsClient) -> bool;
        pub fn ukai_es_drain(client: *mut UkaiEsClient, timeout_ms: u32) -> bool;
        pub fn ukai_es_guard_denials(client: *const UkaiEsClient) -> u64;
        pub fn ukai_es_signal(token: *const u32, sig: i32) -> i32;
        pub fn ukai_es_self_token(out: *mut u32) -> bool;
        pub fn ukai_es_continuous_time() -> u64;
        pub fn ukai_es_delete(client: *mut UkaiEsClient) -> bool;
    }

    #[repr(C)]
    pub struct UkaiEsClient {
        _private: [u8; 0],
    }

    /// The fixed 64-byte custody record of §4.1 rule 3.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct UkaiEsEvent {
        pub kind: i32,
        pub global_seq: u64,
        pub seq: u64,
        pub token: [u32; 8],
        pub exit_status: i32,
    }
}

/// One custody event, decoded to the fixed fields the handlers may read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EsEvent {
    Fork { token: [u32; 8] },
    Exec { token: [u32; 8] },
    Exit { token: [u32; 8], status: i32 },
}

impl EsEvent {
    /// The member's audit token, whatever the event kind.
    pub fn token(&self) -> &[u32; 8] {
        match self {
            EsEvent::Fork { token } | EsEvent::Exec { token } | EsEvent::Exit { token, .. } => {
                token
            }
        }
    }
}

/// One drained custody message: the decoded event plus the sequence numbers
/// and raw kind the gap detection reads (§4.4).
pub struct EsPoll {
    pub event: EsEvent,
    /// EVENT_FORK / EVENT_EXEC / EVENT_EXIT.
    pub kind: u32,
    pub global_seq: u64,
    pub seq: u64,
}

/// `es_new_client_result_t`, mapped. The variant list mirrors
/// `ESClient.h` in enum order; `Other` carries any code a future macOS
/// release adds, so a refusal can still name the raw result (§4.3 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EsNewResult {
    Success,
    InvalidArgument,
    Internal,
    NotEntitled,
    NotPermitted,
    NotPrivileged,
    TooManyClients,
    Other(i32),
}

impl EsNewResult {
    pub(crate) fn from_raw(raw: i32) -> Self {
        match raw {
            0 => EsNewResult::Success,
            1 => EsNewResult::InvalidArgument,
            2 => EsNewResult::Internal,
            3 => EsNewResult::NotEntitled,
            4 => EsNewResult::NotPermitted,
            5 => EsNewResult::NotPrivileged,
            6 => EsNewResult::TooManyClients,
            other => EsNewResult::Other(other),
        }
    }

    /// The raw `es_new_client_result_t` number, for records and refusals.
    pub fn raw(self) -> i32 {
        match self {
            EsNewResult::Success => 0,
            EsNewResult::InvalidArgument => 1,
            EsNewResult::Internal => 2,
            EsNewResult::NotEntitled => 3,
            EsNewResult::NotPermitted => 4,
            EsNewResult::NotPrivileged => 5,
            EsNewResult::TooManyClients => 6,
            EsNewResult::Other(raw) => raw,
        }
    }
}

/// A descendants ES custody client (§4.3 step 1) that can also carry the
/// guard subscription (§4.5 step 1). Created, driven and deleted from one
/// thread; `Send` but deliberately not `Sync`.
pub struct CustodyClient {
    raw: ptr::NonNull<shim::UkaiEsClient>,
}

// SAFETY: the shim client is independent of any Rust thread state; ES clients
// are driven from one thread at a time, which the ownership model here
// enforces by construction (no `Sync`).
unsafe impl Send for CustodyClient {}

impl CustodyClient {
    /// `es_new_descendants_client` through the shim. On failure nothing is
    /// kept and the mapped result names the cause (§4.3 step 1).
    pub fn new() -> Result<Self, EsNewResult> {
        let mut raw = ptr::null_mut();
        // SAFETY: `raw` is a valid out pointer; on success the shim returns a
        // client that stays valid until `ukai_es_delete`.
        let result = EsNewResult::from_raw(unsafe { shim::ukai_es_new_descendants(&mut raw) });
        match ptr::NonNull::new(raw) {
            Some(raw) if result == EsNewResult::Success => Ok(Self { raw }),
            _ => Err(if result == EsNewResult::Success {
                EsNewResult::Internal
            } else {
                result
            }),
        }
    }

    /// `es_unmute_all_paths` + `es_unmute_all_target_paths` (§4.3 step 1).
    pub fn unmute_all(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_es_new_descendants`.
        unsafe { shim::ukai_es_unmute_all(self.raw.as_ptr()) }
    }

    /// Whether `event_type` is still muted by the default mute set. The
    /// creation sequence refuses the client if any of the three custody
    /// events answers true (§4.3 step 1).
    pub fn muted_paths_events(&self, event_type: u32) -> bool {
        // SAFETY: `self.raw` is a live client; the shim releases the mute
        // list the framework returns.
        unsafe { shim::ukai_es_muted_paths_events(self.raw.as_ptr(), event_type) }
    }

    /// Subscribes NOTIFY_FORK, NOTIFY_EXEC and NOTIFY_EXIT — nothing else
    /// (§4.1 rule 3).
    pub fn subscribe_custody(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_es_new_descendants`.
        unsafe { shim::ukai_es_subscribe_custody(self.raw.as_ptr()) }
    }

    /// The guard subscription of §4.5 step 1: AUTH_SIGNAL,
    /// AUTH_PROC_SUSPEND_RESUME and AUTH_EXEC, fail-closed deadline mode set
    /// and read back, every request denied inline without caching. Returns
    /// false if any step failed; the stop then proceeds unguarded (§4.5).
    pub fn subscribe_guard(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_es_new_descendants`.
        unsafe { shim::ukai_es_subscribe_guard(self.raw.as_ptr()) }
    }

    /// `es_mute_process` on this process (§4.3 step 3: the guardian mutes
    /// itself on the guard client).
    pub fn mute_self(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_es_new_descendants`.
        unsafe { shim::ukai_es_mute_self(self.raw.as_ptr()) }
    }

    /// Drains one event from the ring, or `None` when it is empty.
    pub fn poll(&self) -> Option<EsEvent> {
        self.poll_full().map(|polled| polled.event)
    }

    /// [`CustodyClient::poll`] plus the sequencing fields the custody gap
    /// detection needs (§4.4: `global_seq_num` overall, `seq_num` per type).
    /// An event kind outside the custody set cannot appear here — the shim
    /// never enqueues one — but if it did, `event` would be unusable while
    /// the shim's sticky gap flag reports the stream.
    pub fn poll_full(&self) -> Option<EsPoll> {
        let mut raw = shim::UkaiEsEvent {
            kind: 0,
            global_seq: 0,
            seq: 0,
            token: [0; 8],
            exit_status: 0,
        };
        // SAFETY: `self.raw` is a live client and `raw` a valid out record.
        if unsafe { shim::ukai_es_poll(self.raw.as_ptr(), &mut raw) } {
            let event = match raw.kind as u32 {
                EVENT_FORK => EsEvent::Fork { token: raw.token },
                EVENT_EXEC => EsEvent::Exec { token: raw.token },
                EVENT_EXIT => EsEvent::Exit {
                    token: raw.token,
                    status: raw.exit_status,
                },
                _ => return None,
            };
            Some(EsPoll {
                event,
                kind: raw.kind as u32,
                global_seq: raw.global_seq,
                seq: raw.seq,
            })
        } else {
            None
        }
    }

    /// The sticky stream-gap flag (§4.4): ring overflow, a message older
    /// than the custody fields, or an event type outside the custody set.
    pub fn ring_overflowed(&self) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_es_new_descendants`.
        unsafe { shim::ukai_es_ring_overflowed(self.raw.as_ptr()) }
    }

    /// `es_sync_client` bounded by `timeout_ms` (the drain of §4.5 step 4).
    pub fn drain(&self, timeout_ms: u32) -> bool {
        // SAFETY: `self.raw` is a live client from `ukai_es_new_descendants`.
        unsafe { shim::ukai_es_drain(self.raw.as_ptr(), timeout_ms) }
    }

    /// Denials the guard callback has answered so far.
    pub fn guard_denials(&self) -> u64 {
        // SAFETY: `self.raw` is a live client from `ukai_es_new_descendants`.
        unsafe { shim::ukai_es_guard_denials(self.raw.as_ptr()) }
    }

    /// `es_delete_client` and the shim's own teardown. The client is consumed.
    pub fn delete(self) -> bool {
        // SAFETY: `self.raw` is a live client, deleted exactly once; the shim
        // frees the ring and the semaphore with it.
        let deleted = unsafe { shim::ukai_es_delete(self.raw.as_ptr()) };
        std::mem::forget(self);
        deleted
    }
}

impl Drop for CustodyClient {
    fn drop(&mut self) {
        // A client dropped without an explicit `delete` is still released, so
        // no test or early return leaks an ES client.
        // SAFETY: `self.raw` is a live client, deleted exactly once.
        unsafe { shim::ukai_es_delete(self.raw.as_ptr()) };
    }
}

/// `proc_signal_with_audittoken`; returns the errno. The only signalling path
/// in the design — a PID never goes through `kill(2)` (§4.1 rule 5).
pub fn signal_by_token(token: &[u32; 8], sig: i32) -> i32 {
    // SAFETY: `token` points at a fixed [u32; 8]; the shim copies it into an
    // `audit_token_t` and calls the libproc function.
    unsafe { shim::ukai_es_signal(token.as_ptr(), sig) }
}

/// This process's audit token (`task_info(TASK_AUDIT_TOKEN)`).
pub fn self_token() -> Option<[u32; 8]> {
    let mut token = [0u32; 8];
    // SAFETY: `token` is a valid out buffer of exactly 8 words.
    if unsafe { shim::ukai_es_self_token(token.as_mut_ptr()) } {
        Some(token)
    } else {
        None
    }
}

/// `mach_continuous_time` ticks; counts sleep, as the wall deadline must
/// (§4.3 step 6). Convert once with [`mach_timebase_info`] to nanoseconds.
pub fn continuous_time() -> u64 {
    // SAFETY: the function takes no arguments and cannot fail unsafely.
    unsafe { shim::ukai_es_continuous_time() }
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
    continuous_time() * numer / denom
}
