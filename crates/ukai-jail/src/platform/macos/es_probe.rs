//! The Endpoint Security entitlement probe (jail-macos.md §4.10).
//!
//! `tree_termination` on macOS is `es_descendants`: a native Endpoint
//! Security descendants client, whose creation the system grants only to a
//! process carrying `com.apple.developer.endpoint-security.client`. The
//! probe creates a real client through the custody shim's bindings
//! (`super::es`) and deletes it again, so a capability row never claims
//! custody the system did not grant.

use super::es::CustodyClient;

/// What one attempt to create an ES descendants client established.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EsProbeResult {
    /// The client was created and deleted: the process is entitled.
    Entitled,
    /// The system refused the client. `raw_code` is the framework's own
    /// `es_new_client_result_t` value, reported verbatim.
    NotEntitled { raw_code: i32 },
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
            Err(result) => {
                let not_entitled = matches!(result, super::es::EsNewResult::NotEntitled);
                let raw_code = result.raw();
                if not_entitled {
                    EsProbeResult::NotEntitled { raw_code }
                } else {
                    EsProbeResult::Unavailable {
                        reason: format!("es_new_descendants_client returned {raw_code}"),
                    }
                }
            }
        }
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
            EsProbeResult::Unavailable { reason } => {
                println!("the ES client could not be created: {reason}");
            }
        }
    }
}
