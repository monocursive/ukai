use super::{ObsAction, ObsEvent, ObsMessage};
use crate::platform::macos::es::EsNewResult;

mod ffi {
    #[repr(C)]
    pub struct Client {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct Event {
        pub kind: i32,
        pub event_type: u32,
        pub global_seq: u64,
        pub seq: u64,
        pub token: [u32; 8],
        pub modified: i32,
        pub ignored: i32,
        pub path_len: u16,
        pub path2_len: u16,
        pub path: [u8; 1024],
        pub path2: [u8; 1024],
    }
    unsafe extern "C" {
        pub fn ukai_obs_new_descendants(out: *mut *mut Client) -> i32;
        pub fn ukai_obs_unmute_all(client: *mut Client) -> bool;
        pub fn ukai_obs_muted_paths_events(client: *mut Client, event_type: u32) -> bool;
        pub fn ukai_obs_verify_unmuted(client: *mut Client) -> bool;
        pub fn ukai_obs_subscribe(client: *mut Client) -> bool;
        pub fn ukai_obs_mute_self(client: *mut Client) -> bool;
        pub fn ukai_obs_exclude_token(client: *mut Client, token: *const u32) -> bool;
        pub fn ukai_obs_poll(client: *mut Client, event: *mut Event) -> bool;
        pub fn ukai_obs_gap(client: *const Client) -> bool;
        pub fn ukai_obs_invalid(client: *const Client) -> bool;
        pub fn ukai_obs_dropped(client: *const Client) -> u64;
        pub fn ukai_obs_drain(client: *mut Client, timeout_ms: u32) -> bool;
        pub fn ukai_obs_delete(client: *mut Client) -> bool;
    }
}

/// Owned client, driven from exactly one thread at a time. A setup error is
/// returned to the caller; there is no implicit fallback from required evidence.
pub struct ObserveClient {
    raw: std::ptr::NonNull<ffi::Client>,
}
// SAFETY: no thread-local Rust state; ownership serializes all API calls. Not Sync.
unsafe impl Send for ObserveClient {}
impl ObserveClient {
    pub fn new() -> Result<Self, EsNewResult> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: valid out pointer; the shim only sets it on success.
        let result = EsNewResult::from_raw(unsafe { ffi::ukai_obs_new_descendants(&mut raw) });
        match std::ptr::NonNull::new(raw) {
            Some(raw) if result == EsNewResult::Success => Ok(Self { raw }),
            _ => Err(if result == EsNewResult::Success {
                EsNewResult::Internal
            } else {
                result
            }),
        }
    }
    pub fn unmute_all(&self) -> bool {
        // SAFETY: owned live client.
        unsafe { ffi::ukai_obs_unmute_all(self.raw.as_ptr()) }
    }
    pub fn muted_paths_events(&self, event_type: u32) -> bool {
        // SAFETY: owned live client; the shim frees the readback list.
        unsafe { ffi::ukai_obs_muted_paths_events(self.raw.as_ptr(), event_type) }
    }
    pub fn verify_unmuted(&self) -> bool {
        // SAFETY: owned live client; checks every subscribed ES type.
        unsafe { ffi::ukai_obs_verify_unmuted(self.raw.as_ptr()) }
    }
    pub fn subscribe(&self) -> bool {
        // SAFETY: owned live client. Freezes the helper table before callbacks.
        unsafe { ffi::ukai_obs_subscribe(self.raw.as_ptr()) }
    }
    /// Legacy ES process mute. ObserveRun uses exact-token exclusion instead:
    /// process mute can hide instigated events and the launcher's exec image.
    pub fn mute_self(&self) -> bool {
        // SAFETY: owned live client.
        unsafe { ffi::ukai_obs_mute_self(self.raw.as_ptr()) }
    }
    pub fn exclude_token(&mut self, token: &[u32; 8]) -> bool {
        // SAFETY: token is eight live words; shim refuses changes after subscribe.
        unsafe { ffi::ukai_obs_exclude_token(self.raw.as_ptr(), token.as_ptr()) }
    }
    /// Legacy one-path projection. Native runs use poll_message.
    pub fn poll(&self) -> Option<ObsEvent> {
        self.poll_message().map(|message| message.event)
    }
    pub fn poll_message(&self) -> Option<ObsMessage> {
        // SAFETY: fixed C record of integers/byte arrays has a valid zero value.
        let mut raw: ffi::Event = unsafe { std::mem::zeroed() };
        // SAFETY: owned client and correctly sized output buffer.
        if !unsafe { ffi::ukai_obs_poll(self.raw.as_ptr(), &mut raw) } {
            return None;
        }
        let action = ObsAction::from_raw(raw.kind)?;
        // The shim bounds both lengths; refuse malformed records defensively.
        let path = raw.path.get(..usize::from(raw.path_len))?.to_vec();
        let path2 = raw.path2.get(..usize::from(raw.path2_len))?.to_vec();
        Some(ObsMessage {
            event: ObsEvent {
                kind: action.kind(),
                global_seq: raw.global_seq,
                seq: raw.seq,
                token: raw.token,
                path,
            },
            event_type: raw.event_type,
            action,
            path2: matches!(action, ObsAction::Rename | ObsAction::Link).then_some(path2),
            ignored: raw.ignored != 0,
        })
    }
    pub fn gap(&self) -> bool {
        // SAFETY: owned live client, atomic read.
        unsafe { ffi::ukai_obs_gap(self.raw.as_ptr()) }
    }
    pub fn invalid(&self) -> bool {
        // SAFETY: owned live client, atomic read.
        unsafe { ffi::ukai_obs_invalid(self.raw.as_ptr()) }
    }
    pub fn dropped(&self) -> u64 {
        // SAFETY: owned live client, atomic read.
        unsafe { ffi::ukai_obs_dropped(self.raw.as_ptr()) }
    }
    pub fn drain(&self, timeout_ms: u32) -> bool {
        // SAFETY: owned live client; callback only captures its private semaphore.
        unsafe { ffi::ukai_obs_drain(self.raw.as_ptr(), timeout_ms) }
    }
    pub fn delete(self) -> bool {
        // SAFETY: consumed once. ES invalidates the client even on error.
        let deleted = unsafe { ffi::ukai_obs_delete(self.raw.as_ptr()) };
        std::mem::forget(self);
        deleted
    }
}
impl Drop for ObserveClient {
    fn drop(&mut self) {
        // SAFETY: unique owner; on shutdown error the shim retains callback state.
        unsafe { ffi::ukai_obs_delete(self.raw.as_ptr()) };
    }
}
