//! The Endpoint Security entitlement probe (jail-macos.md §4.10).
//!
//! `tree_termination` on macOS is `es_descendants`: a native Endpoint
//! Security descendants client, whose creation the system grants only to a
//! process carrying `com.apple.developer.endpoint-security.client`. The
//! probe creates a real client through the custody shim's bindings
//! (`super::es`) and deletes it again, so a capability row never claims
//! custody the system did not grant.

use super::es::{CustodyClient, EsNewResult};

/// What one attempt to create an ES descendants client established.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EsProbeResult {
    /// The client was created and deleted: the process is entitled.
    Entitled,
    /// The system refused the client. `raw_code` is the framework's own
    /// `es_new_client_result_t` value, reported verbatim.
    NotEntitled { raw_code: i32 },
    /// The framework's client capacity is exhausted; retry may succeed.
    TooManyClients { raw_code: i32 },
    /// The framework answered with an error that is not a refusal of this
    /// process: the reason names the raw result.
    Unavailable { reason: String },
}

/// The entitlement probe, so a test can state the result instead of asking
/// this host for it.
pub trait EsProbe {
    /// Creates and deletes one ES descendants client.
    fn es_probe(&self) -> EsProbeResult;
}

/// The real probe.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RealEsProbe;

impl EsProbe for RealEsProbe {
    fn es_probe(&self) -> EsProbeResult {
        match CustodyClient::new() {
            // The client's `Drop` (or `delete`) releases it; the probe holds
            // nothing else.
            Ok(client) => {
                drop(client);
                EsProbeResult::Entitled
            }
            Err(result) => probe_failure(result),
        }
    }
}

fn probe_failure(result: EsNewResult) -> EsProbeResult {
    let raw_code = result.raw();
    match result {
        EsNewResult::NotEntitled => EsProbeResult::NotEntitled { raw_code },
        EsNewResult::TooManyClients => EsProbeResult::TooManyClients { raw_code },
        _ => EsProbeResult::Unavailable {
            reason: format!("es_new_descendants_client returned {raw_code}"),
        },
    }
}

/// The probe `doctor` and `run` use.
#[must_use]
pub fn es_probe() -> EsProbeResult {
    RealEsProbe.es_probe()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_many_clients_is_typed_without_collapsing_other_failures() {
        assert_eq!(
            probe_failure(EsNewResult::from_raw(6)),
            EsProbeResult::TooManyClients { raw_code: 6 }
        );
        assert_eq!(
            probe_failure(EsNewResult::from_raw(3)),
            EsProbeResult::NotEntitled { raw_code: 3 }
        );
        for raw in [1, 2, 4, 5, 99] {
            assert_eq!(
                probe_failure(EsNewResult::from_raw(raw)),
                EsProbeResult::Unavailable {
                    reason: format!("es_new_descendants_client returned {raw}")
                }
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_live_probe_answers_without_skippping() {
        // The live answer depends on the host: entitled here means
        // `Entitled`; an unentitled host answers `NotEntitled` with the
        // framework's own code. The probe always answers; it never skips.
        match es_probe() {
            EsProbeResult::Entitled => {}
            EsProbeResult::NotEntitled { raw_code } => {
                println!("es_new_descendants_client raw code: {raw_code}");
                assert_ne!(raw_code, 0);
            }
            EsProbeResult::TooManyClients { raw_code } => {
                assert_eq!(raw_code, 6);
            }
            EsProbeResult::Unavailable { reason } => {
                println!("the ES client could not be created: {reason}");
            }
        }
    }
}
