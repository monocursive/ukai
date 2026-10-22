//! The macOS platform: policy inspection and measured native mechanisms.
//! Execution is development-only (`UKAI_JAIL_MACOS_NATIVE=dev`), off by
//! default. Even when enabled, missing custody, staging or observation
//! guarantees refuse before the workload is created.

mod es_probe;
mod requirements;

// J18 (jail-macos.md §6): the `--vm` tier — the warm guest platform, its
// wire protocol, transport record and the `vm stop` client.
#[cfg(target_os = "macos")]
pub mod vm;

use crate::capability::{Capability, CapabilityScope, Requirement};
use crate::platform::{
    PlanRequest, Platform, PlatformIdentity, PreparedExecution, PreparedPlan, Sinks, kernel_release,
};
use crate::records::{ErrorCode, ErrorStage, JailError, Os, Remediation, rfc3339_utc};

/// The bridge on the shared loopback (jail-macos.md §4.10): the two
/// OS-assigned ephemeral ports and the per-attempt secret the child's proxy
/// URLs carry.
pub mod bridge;
use std::time::SystemTime;
// J16 (jail-macos.md §4): the ES shim bindings and the pure custody engine.
// Both modules are file-level `cfg(target_os = "macos")`, so this declaration
// compiles away on Linux.
/// The supervisor side of the boundary (jail-macos §4.3–§4.6, §4.8).
#[cfg(target_os = "macos")]
pub mod boundary;
/// The ES shim bindings and the pure custody engine; the guardian's facade
/// over them (jail-macos.md §4).
#[cfg(target_os = "macos")]
pub mod custody;
/// The guardian's custody I/O facade over the shim and the custody engine.
#[cfg(target_os = "macos")]
pub mod custody_io;
#[cfg(target_os = "macos")]
pub mod es;
/// The guardian: the second custodian (jail-macos §4.2–§4.6).
#[cfg(target_os = "macos")]
pub mod guardian;
/// The macOS launcher mode `__launch-macos` (jail-macos §4.3 step 4).
#[cfg(target_os = "macos")]
pub mod launcher;
/// Native observation, the third ES client (jail-macos §5, J17); its C
/// shim lives in `observe/` and compiles with the custody shim.
#[cfg(target_os = "macos")]
pub mod observe;
#[cfg(target_os = "macos")]
pub mod relay;
#[cfg(target_os = "macos")]
pub mod sandbox;
#[cfg(target_os = "macos")]
pub mod setuid;

/// Deliberate opt-in to the unshipped native tier. No other value enables it.
#[must_use]
pub fn native_enabled() -> bool {
    std::env::var_os("UKAI_JAIL_MACOS_NATIVE").is_some_and(|value| value == "dev")
}

/// Refuse before probes or workload creation when the development gate is off.
pub fn require_native_enabled() -> Result<(), JailError> {
    if native_enabled() {
        return Ok(());
    }
    Err(JailError::new(ErrorCode::UnsupportedPlatform, ErrorStage::Probing, Remediation::Unsupported,
        "native macOS execution is disabled; UKAI_JAIL_MACOS_NATIVE=dev explicitly enables the unshipped development tier".to_owned()))
}

/// The macOS platform implementation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MacosPlatform;

/// The supervisor's birth identity (§7): pid, `kern.bootsessionuuid` and the
/// process start in epoch seconds (`proc_pidinfo`'s `pbi_start_tvsec`), the
/// convention gc's boot-facts reader uses across pid reuse and reboots.
/// `None` when the kernel does not answer: the state file then says so
/// rather than guessing.
#[cfg(target_os = "macos")]
#[must_use]
pub fn owner_identity() -> Option<crate::platform::OwnerIdentity> {
    // SAFETY: getpid takes no arguments.
    let pid = unsafe { libc::getpid() } as u32;
    let boot_id = crate::platform::macos::guardian::record::boot_session_uuid();
    // `pbi_start_tvsec` is `PROC_PIDTBSDINFO`'s process start in epoch
    // seconds, the same field gc's macOS owner facts read.
    // SAFETY: `bsd` is a plain stack record the call fills within.
    let mut bsd: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    // SAFETY: the out pointer and size name exactly `bsd`.
    let got = unsafe {
        libc::proc_pidinfo(
            pid as libc::pid_t,
            libc::PROC_PIDTBSDINFO,
            0,
            std::ptr::from_mut(&mut bsd).cast(),
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    if got != std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int {
        return None;
    }
    Some(crate::platform::OwnerIdentity {
        pid,
        boot_id,
        start_time_ticks: bsd.pbi_start_tvsec,
    })
}

impl MacosPlatform {
    /// The refusal `prepare` returns when the platform genuinely cannot
    /// proceed (§4.3 step 1's codes come from `boundary::prepare` itself).
    #[must_use]
    pub fn unsupported_error() -> JailError {
        JailError::new(
            ErrorCode::UnsupportedPlatform,
            ErrorStage::Probing,
            Remediation::Unsupported,
            "execution is not implemented for this platform".to_owned(),
        )
    }

    /// The capability scope a requirement is measured at.
    pub(super) fn scope_for(requirement: Requirement) -> CapabilityScope {
        match requirement {
            Requirement::SyscallFilter => CapabilityScope::Process,
            _ => CapabilityScope::Tree,
        }
    }
}

impl Platform for MacosPlatform {
    fn identity(&self) -> PlatformIdentity {
        PlatformIdentity {
            os: Os::Macos,
            arch: std::env::consts::ARCH.to_owned(),
            kernel: kernel_release(),
        }
    }

    /// The supervisor's birth identity (§7): the pid plus the boot session
    /// and the process start the kernel reports, in the convention gc's
    /// boot-facts reader uses.
    fn owner_identity(&self) -> Option<crate::platform::OwnerIdentity> {
        owner_identity()
    }

    fn probe(&self, plan: &PlanRequest) -> Vec<Capability> {
        // A run measures what its plan asks about; `doctor` runs every probe
        // through `probe_all`. The probes themselves are cheap (one dlopen,
        // one sandbox-exec child, two binds, two sysctls), but the rows a
        // run records are only the ones its plan needs.
        let probes = requirements::run_probes();
        let measured_at = rfc3339_utc(SystemTime::now());
        requirements::derive(plan, &probes, &measured_at)
    }

    fn probe_all(&self, plan: &PlanRequest) -> Vec<Capability> {
        let probes = requirements::run_probes();
        let measured_at = rfc3339_utc(SystemTime::now());
        let mut out = requirements::derive(plan, &probes, &measured_at);
        out.extend(requirements::probe_rows(&probes, &measured_at));
        out
    }

    fn prepare(
        &self,
        plan: PreparedPlan,
        sinks: Sinks,
    ) -> Result<Box<dyn PreparedExecution>, JailError> {
        // §4.3: the native tier builds a real boundary; the refusal
        // (`unsupported_error`) stays for the genuine refusals of §4.3
        // step 1, which `boundary::prepare` names.
        boundary::prepare(plan, sinks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityStatus;
    use crate::platform::REASON_UNSUPPORTED_PLATFORM;
    use crate::policy::{ProfileName, ResolveInputs, ScratchRoot};

    fn plan_for(profile: ProfileName) -> PlanRequest {
        let baseline = crate::profiles::baseline(profile, Os::Macos, &|_| None);
        let inputs = ResolveInputs {
            platform: Os::Macos,
            base_profile: profile,
            policy_name: profile.as_str().to_owned(),
            baseline,
            workspace: b"/work".to_vec(),
            scratch: ScratchRoot::Managed,
            vendor_state: None,
            operator_home: None,
            translation_prefixes: Vec::new(),
            layers: Vec::new(),
        };
        let resolved = crate::policy::resolve(&inputs).expect("resolves");
        PlanRequest {
            snapshot: resolved.snapshot,
            requirements: resolved.requirements,
        }
    }

    #[test]
    fn the_unimplemented_requirements_stay_unsupported_and_unmeasured() {
        for profile in [ProfileName::Tool, ProfileName::None] {
            let plan = plan_for(profile);
            let capabilities = MacosPlatform.probe(&plan);
            assert!(
                capabilities
                    .iter()
                    .any(|capability| capability.name == "execution_boundary")
                    == (profile == ProfileName::None),
                "{profile:?} derives `none`'s boundary requirement exactly"
            );
            for capability in &capabilities {
                let unimplemented = capability.name == "execution_boundary"
                    || capability.name == "closed_set_observation"
                    || capability.name == "credential_staging"
                    || capability.name.starts_with("limit:") && capability.name != "limit:wall";
                if unimplemented {
                    assert_eq!(
                        capability.status,
                        CapabilityStatus::Unsupported,
                        "{}",
                        capability.name
                    );
                    assert!(!capability.satisfies());
                    assert_eq!(
                        capability.measured_at, None,
                        "{}: no probe applies",
                        capability.name
                    );
                    assert_eq!(
                        capability.reason_code.as_deref(),
                        Some(REASON_UNSUPPORTED_PLATFORM)
                    );
                } else {
                    // §4.10: every other row is a real measurement of this
                    // host — it may answer available or unavailable, never
                    // claim a probe that did not run.
                    assert!(
                        capability.measured_at.is_some(),
                        "{} claims no measurement",
                        capability.name
                    );
                }
            }
        }
    }

    #[test]
    fn probe_all_reports_every_probe_row_for_doctor() {
        let plan = plan_for(ProfileName::Tool);
        let capabilities = MacosPlatform.probe_all(&plan);
        for name in requirements::PROBE_NAMES {
            if *name == "es_notify" && !crate::profiles::J17_OBSERVE {
                continue;
            }
            let row = capabilities
                .iter()
                .find(|capability| &capability.name == name)
                .unwrap_or_else(|| panic!("probe_all reports {name}"));
            assert!(row.measured_at.is_some(), "{name}");
        }
    }

    #[test]
    fn prepare_refuses_rather_than_returning_a_successful_no_op() {
        let plan = plan_for(ProfileName::None);
        let prepared = MacosPlatform.prepare(
            PreparedPlan {
                attempt_id: "att_00000000-0000-4000-8000-000000000001".to_owned(),
                attempt_dir: std::path::PathBuf::from("/nonexistent"),
                request: plan,
                argv: vec![b"/bin/true".to_vec()],
                prepare_deadline: crate::platform::ContinuousDeadline::after(
                    std::time::Duration::from_secs(30),
                ),
                workspace: std::path::PathBuf::from("/work"),
                config_dir: std::path::PathBuf::from("/nonexistent"),
                launch: None,
                proxy: None,
                pinned_roots: Vec::new(),
                exec_pins: Vec::new(),
            },
            Sinks { trace: None },
        );
        let error = match prepared {
            Ok(_) => panic!("macOS must not produce a prepared execution"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::UnsupportedPlatform);
        assert_eq!(error.exit_code(), 125);
    }
}
