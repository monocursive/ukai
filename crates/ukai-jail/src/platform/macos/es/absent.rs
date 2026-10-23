//! No safe code can construct a client when the SDK probe failed.
use super::{EsEvent, EsNewResult, EsPoll};

pub struct CustodyClient {
    _private: (),
}

impl CustodyClient {
    pub fn new() -> Result<Self, EsNewResult> {
        Err(EsNewResult::SdkAbsent)
    }
    pub fn unmute_all(&self) -> bool {
        false
    }
    pub fn muted_paths_events(&self, _event_type: u32) -> bool {
        true
    }
    pub fn subscribe_custody(&self) -> bool {
        false
    }
    pub fn prepare_guard(&self) -> bool {
        false
    }
    pub fn subscribe_guard(&self) -> bool {
        false
    }
    pub fn mute_self(&self) -> bool {
        false
    }
    pub fn poll(&self) -> Option<EsEvent> {
        None
    }
    pub fn poll_full(&self) -> Option<EsPoll> {
        None
    }
    pub fn ring_overflowed(&self) -> bool {
        true
    }
    pub fn drain(&self, _timeout_ms: u32) -> bool {
        false
    }
    pub fn guard_denials(&self) -> u64 {
        0
    }
    pub fn delete(self) -> bool {
        false
    }
}
