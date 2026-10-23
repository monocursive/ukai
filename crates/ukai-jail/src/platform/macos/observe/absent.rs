//! No observation stream exists when the required SDK APIs are absent.
use super::{ObsEvent, ObsMessage};
use crate::platform::macos::es::EsNewResult;

pub struct ObserveClient {
    _private: (),
}

impl ObserveClient {
    pub fn new() -> Result<Self, EsNewResult> {
        Err(EsNewResult::SdkAbsent)
    }
    pub fn unmute_all(&self) -> bool {
        false
    }
    pub fn muted_paths_events(&self, _event_type: u32) -> bool {
        true
    }
    pub fn verify_unmuted(&self) -> bool {
        false
    }
    pub fn subscribe(&self) -> bool {
        false
    }
    pub fn mute_self(&self) -> bool {
        false
    }
    pub fn exclude_token(&mut self, _token: &[u32; 8]) -> bool {
        false
    }
    pub fn poll(&self) -> Option<ObsEvent> {
        None
    }
    pub fn poll_message(&self) -> Option<ObsMessage> {
        None
    }
    pub fn gap(&self) -> bool {
        true
    }
    pub fn invalid(&self) -> bool {
        true
    }
    pub fn dropped(&self) -> u64 {
        0
    }
    pub fn drain(&self, _timeout_ms: u32) -> bool {
        false
    }
    pub fn delete(self) -> bool {
        false
    }
}
