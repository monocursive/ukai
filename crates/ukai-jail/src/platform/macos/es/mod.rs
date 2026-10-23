//! Safe Rust bindings over the ES custody shim (`shim.c`).
//!
//! The shim holds every raw pointer; these wrappers expose fixed-size values
//! only (jail-macos §4.1 rule 3). `CustodyClient` is the custody client of
//! §4.3 step 1; the guard-client wrappers of §4.3 step 3 and §4.5 step 1 sit
//! on the same type because they are one process's second ES client, created
//! with the same fixed-size discipline.
#![cfg(target_os = "macos")]

#[cfg(not(ukai_es_sdk_absent))]
mod client;
#[cfg(ukai_es_sdk_absent)]
#[path = "absent.rs"]
mod client;
mod system;
pub use client::CustodyClient;
pub use system::{continuous_time, continuous_time_ns, self_token, signal_by_token};

/// This binary was built without the required Endpoint Security SDK APIs.
pub const SDK_ABSENT_REASON: &str = crate::capability::REASON_ES_SDK_ABSENT;

/// Shim-internal custody event numbers. They mirror the `UKAI_ES_EVENT_*`
/// enum in `shim.h`; both sides count on the fixed mapping.
pub const EVENT_FORK: u32 = 1;
pub const EVENT_EXEC: u32 = 2;
pub const EVENT_EXIT: u32 = 3;

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
    /// Build-time absence, not a result returned by Endpoint Security.
    SdkAbsent,
}

impl EsNewResult {
    #[cfg(any(not(ukai_es_sdk_absent), test))]
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

    /// The raw `es_new_client_result_t` number, or -1 for build-time SDK absence.
    /// No framework call or framework result is claimed by that sentinel.
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
            EsNewResult::SdkAbsent => -1,
        }
    }
}
