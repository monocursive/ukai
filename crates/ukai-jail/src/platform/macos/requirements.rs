//! From probe results to the plan's capabilities (jail-macos.md §4.10).
//!
//! The macOS answer table: `es_descendants` terminates the tree, a Seatbelt
//! profile contains the filesystem and filters syscalls, the network is a
//! denied-by-default profile over a loopback bridge, and custody-dependent
//! answers (`limit:wall`, closed-set observation, the resource boundaries)
//! follow the ES entitlement. Every `available` row names a probe that
//! actually ran on this host; the platform's own gaps stay `unsupported` and
//! unmeasured.

use crate::capability::{Capability, CapabilityScope, CapabilityStatus, Requirement};
use crate::platform::{PlanRequest, REASON_UNSUPPORTED_PLATFORM};
use crate::policy::LimitKey;

use super::es_probe::{self, EsProbeResult};

/// One probe's measured result, before it becomes a capability row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ProbeRow {
    pub(super) name: &'static str,
    pub(super) status: CapabilityStatus,
    pub(super) mechanism: &'static str,
    pub(super) reason: &'static str,
    pub(super) evidence: String,
}

impl ProbeRow {
    fn new(name: &'static str, mechanism: &'static str) -> Self {
        ProbeRow {
            name,
            status: CapabilityStatus::Available,
            mechanism,
            reason: "ok",
            evidence: String::new(),
        }
    }

    fn unavailable(mut self, reason: &'static str, evidence: String) -> Self {
        self.status = CapabilityStatus::Unavailable;
        self.reason = reason;
        self.evidence = evidence;
        self
    }
}

// The probe names, so `doctor` reports them and tests can enumerate them.
#[cfg(test)]
pub(super) const PROBE_NAMES: &[&str] = &[
    "es_descendants",
    "es_notify",
    "seatbelt_profile",
    "loopback_bind",
    "bootsessionuuid",
    "maxprocperuid",
];

/// Runs every probe this platform has, for `doctor` and for the requirement
/// derivation. None of them is expensive: one `dlopen`, one `sandbox-exec`
/// child, two loopback binds, two sysctls and, since J17 (§5), the
/// creation and deletion of the observation client.
pub(super) fn run_probes() -> Vec<ProbeRow> {
    let mut rows = vec![
        es_row(),
        seatbelt_row(),
        loopback_row(),
        bootsessionuuid_row(),
        maxprocperuid_row(),
    ];
    if crate::profiles::J17_OBSERVE {
        rows.push(es_notify_row());
    }
    rows
}

/// Creates and deletes a real ES descendants client (§4.10: the boundary is
/// `native_tree` under native custody, and only an entitled client proves
/// the system grants one).
fn es_row() -> ProbeRow {
    if !super::native_enabled() {
        return ProbeRow::new("es_descendants", "es_descendants").unavailable(
            "native_development_disabled",
            "UKAI_JAIL_MACOS_NATIVE=dev is not set".into(),
        );
    }
    match es_probe::es_probe() {
        EsProbeResult::Entitled => ProbeRow::new("es_descendants", "es_descendants"),
        EsProbeResult::NotEntitled { raw_code } => {
            ProbeRow::new("es_descendants", "es_descendants").unavailable(
                "es_not_entitled",
                format!("es_new_descendants_client={raw_code}"),
            )
        }
        EsProbeResult::Unavailable { reason } => {
            ProbeRow::new("es_descendants", "es_descendants").unavailable("es_unavailable", reason)
        }
    }
}

/// Compile the production template with production runtime roots and run
/// `/usr/bin/true`, so an invalid deny filter cannot satisfy the capability.
fn seatbelt_row() -> ProbeRow {
    const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
    let params = super::sandbox::ProfileParams {
        read_only: super::sandbox::runtime_roots(),
        ..super::sandbox::ProfileParams::default()
    };
    let profile = super::sandbox::generate(&params);
    let row = ProbeRow::new("seatbelt_profile", "seatbelt_profile");
    let Ok(metadata) = std::fs::metadata(SANDBOX_EXEC) else {
        return row.unavailable(
            "sandbox_exec_missing",
            format!("{SANDBOX_EXEC} is not present"),
        );
    };
    use std::os::unix::fs::PermissionsExt as _;
    if metadata.permissions().mode() & 0o111 == 0 {
        return row.unavailable(
            "sandbox_exec_missing",
            format!("{SANDBOX_EXEC} is not executable"),
        );
    }
    match run_with_timeout(
        std::process::Command::new(SANDBOX_EXEC)
            .arg("-p")
            .arg(profile)
            .arg("/usr/bin/true"),
        std::time::Duration::from_secs(5),
    ) {
        None => row.unavailable(
            "sandbox_exec_timeout",
            "the profile compile did not finish within 5s".to_owned(),
        ),
        Some(Ok(status)) if status.success() => {
            let mut complete = row;
            complete.evidence = format!("{SANDBOX_EXEC} profile-compile=ok");
            complete
        }
        Some(Ok(status)) => row.unavailable(
            "profile_compile_failed",
            format!("sandbox-exec exited with {status}"),
        ),
        Some(Err(error)) => row.unavailable(
            "profile_compile_failed",
            format!("sandbox-exec could not run: {error}"),
        ),
    }
}

/// Runs a command, answering `None` when it did not exit within `timeout`
/// (the child is killed, not left behind).
fn run_with_timeout(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> Option<std::io::Result<std::process::ExitStatus>> {
    let mut child = command.spawn().ok()?;
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(Ok(status)),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(error) => return Some(Err(error)),
        }
    }
}

/// Two ephemeral loopback ports bind, which is what the bridge and its
/// proxy need of the host (§4.10: the bridge keeps jail-v2's two ports on
/// ephemeral loopback ports).
fn loopback_row() -> ProbeRow {
    let row = ProbeRow::new("loopback_bind", "seatbelt-deny-network+loopback-bridge");
    let first = std::net::TcpListener::bind(("127.0.0.1", 0));
    let second = std::net::TcpListener::bind(("127.0.0.1", 0));
    match (first, second) {
        (Ok(first), Ok(second)) => {
            let Ok(first) = first.local_addr() else {
                return row.unavailable(
                    "loopback_bind_failed",
                    "the bound socket has no local address".to_owned(),
                );
            };
            let Ok(second) = second.local_addr() else {
                return row.unavailable(
                    "loopback_bind_failed",
                    "the bound socket has no local address".to_owned(),
                );
            };
            let mut complete = row;
            complete.evidence = format!("ports={},{}", first.port(), second.port());
            complete
        }
        (first, second) => row.unavailable(
            "loopback_bind_failed",
            format!(
                "first={:?} second={:?}",
                first.err().map(|e| e.to_string()),
                second.err().map(|e| e.to_string())
            ),
        ),
    }
}

/// `kern.bootsessionuuid`: the continuous boot session the two custodians'
/// wall clock is anchored to (§4.10: `limit:wall` on the continuous clock).
fn bootsessionuuid_row() -> ProbeRow {
    let row = ProbeRow::new("bootsessionuuid", "sysctl");
    match sysctl_string("kern.bootsessionuuid") {
        Some(value) if !value.is_empty() => {
            let mut complete = row;
            complete.evidence = "present".to_owned();
            complete
        }
        _ => row.unavailable(
            "sysctl_unavailable",
            "kern.bootsessionuuid did not answer".to_owned(),
        ),
    }
}

/// `kern.maxprocperuid`: the per-uid process ceiling a native tree lives
/// under, which `doctor` reports so the operator sees the host's own bound.
fn maxprocperuid_row() -> ProbeRow {
    let row = ProbeRow::new("maxprocperuid", "sysctl");
    match sysctl_int("kern.maxprocperuid") {
        Some(value) => {
            let mut complete = row;
            complete.evidence = value.to_string();
            complete
        }
        None => row.unavailable(
            "sysctl_unavailable",
            "kern.maxprocperuid did not answer".to_owned(),
        ),
    }
}

/// Creates and deletes the real §5 observation client (J17): the same
/// entitlement proof the custody probe makes, for the supervisor's third
/// ES client. Mechanism `es_notify`.
fn es_notify_row() -> ProbeRow {
    // I5: observation is not wired into runs in phase 1. Entitlement alone
    // cannot establish a capability that the run does not actually attach.
    ProbeRow::new("es_notify", "es_notify").unavailable(
        "observer_not_wired",
        "native observation is not wired into runs".into(),
    )
}

/// Reads one sysctl variable as an integer.
fn sysctl_int(name: &str) -> Option<i32> {
    use std::ffi::CString;

    // SAFETY: the name is a NUL-terminated string for the call's lifetime.
    let name = CString::new(name).ok()?;
    let mut value: i32 = 0;
    let mut size = std::mem::size_of::<i32>();
    // SAFETY: the value and its size are live locals the call writes within.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::from_mut(&mut value).cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size != std::mem::size_of::<i32>()
    {
        return None;
    }
    Some(value)
}

/// Reads one sysctl variable as a trimmed string.
fn sysctl_string(name: &str) -> Option<String> {
    use std::ffi::CString;

    // SAFETY: the name is a NUL-terminated string for the call's lifetime.
    let name = CString::new(name).ok()?;
    let mut size: usize = 0;
    // SAFETY: `size` is a live local the call writes the value's length
    // into; a null oldp buffer makes sysctlbyname report only the size.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
    {
        return None;
    }
    let mut buffer = vec![0_u8; size];
    // SAFETY: the buffer is live, its length is exactly what the first call
    // reported, and sysctlbyname writes only within it.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    buffer.truncate(size);
    let end = buffer
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf8_lossy(&buffer[..end]).trim().to_owned())
}

/// Which probes establish a requirement, the mechanism it names and the
/// scope it is measured at. `None` for a requirement the platform does not
/// implement at all (§4.10), which stays `unsupported` and unmeasured.
fn inputs_for(
    requirement: Requirement,
) -> Option<(&'static [&'static str], &'static str, CapabilityScope)> {
    match requirement {
        Requirement::TreeTermination => {
            Some((&["es_descendants"], "es_descendants", CapabilityScope::Tree))
        }
        Requirement::FilesystemContainment => Some((
            &["seatbelt_profile"],
            "seatbelt_profile",
            CapabilityScope::Tree,
        )),
        Requirement::SyscallFilter => Some((
            &["seatbelt_profile"],
            "seatbelt_profile",
            CapabilityScope::Process,
        )),
        // Existing-and-root coverage comes from explicit resolved denies.
        // Future nested directories are not claimed; all_descendants refuses.
        Requirement::ProtectedCoverage(crate::policy::ProtectedCoverage::AllDescendants) => None,
        Requirement::ProtectedCoverage(_) => Some((
            &["seatbelt_profile"],
            "seatbelt_profile",
            CapabilityScope::Tree,
        )),
        Requirement::NetworkNone => Some((
            &["seatbelt_profile", "loopback_bind"],
            "seatbelt-deny-network",
            CapabilityScope::Tree,
        )),
        Requirement::NetworkProxy => Some((
            &["seatbelt_profile", "loopback_bind"],
            "seatbelt-deny-network+outside-proxy+loopback-bridge",
            CapabilityScope::Tree,
        )),
        Requirement::CredentialStaging => None,
        Requirement::ClosedSetObservation | Requirement::ExecutionBoundary => None,
        Requirement::OwnerLossTermination => None,
        Requirement::Limit(LimitKey::Wall) => Some((
            &[],
            "both-custodians-continuous-clock",
            CapabilityScope::Tree,
        )),
        Requirement::Limit(_) => None,
    }
}

/// One requirement's capability from the probe results.
pub(super) fn capability_for(
    requirement: Requirement,
    probes: &[ProbeRow],
    measured_at: &str,
) -> Capability {
    // The wall is enforced by both custodians on the continuous clock, which
    // only exists under native custody: without an ES client there is no
    // custodian to hold the deadline.
    if requirement == Requirement::Limit(LimitKey::Wall) {
        let es = probes
            .iter()
            .find(|row| row.name == "es_descendants")
            .expect("the probe set carries the ES row");
        let (status, reason) = if es.status == CapabilityStatus::Available {
            (CapabilityStatus::Available, "ok")
        } else {
            (CapabilityStatus::Unavailable, es.reason)
        };
        return Capability {
            name: requirement.to_string(),
            status,
            scope: CapabilityScope::Tree,
            mechanism: Some("both-custodians-continuous-clock".to_owned()),
            reason_code: Some(reason.to_owned()),
            measured_at: Some(measured_at.to_owned()),
            evidence_ref: Some("supervisor".to_owned()),
        };
    }
    // J18: a kernel-bound lifetime boundary is a VM tier answer; native
    // macOS custody refuses it with its own reason (jail-macos.md §6).
    if requirement == Requirement::OwnerLossTermination {
        return Capability {
            name: requirement.to_string(),
            status: CapabilityStatus::Unsupported,
            scope: CapabilityScope::Tree,
            mechanism: None,
            reason_code: Some(crate::capability::REASON_OWNER_LOSS_REQUIRES_VM.to_owned()),
            measured_at: None,
            evidence_ref: None,
        };
    }
    let Some((names, mechanism, scope)) = inputs_for(requirement) else {
        return Capability::unsupported(
            requirement.to_string(),
            super::MacosPlatform::scope_for(requirement),
            REASON_UNSUPPORTED_PLATFORM,
        );
    };
    let mut status = CapabilityStatus::Available;
    let mut reason = "ok".to_owned();
    let mut evidence = String::new();
    for name in names {
        let Some(row) = probes.iter().find(|row| row.name == *name) else {
            status = CapabilityStatus::Skipped;
            reason = "probe_not_run".to_owned();
            break;
        };
        if row.status != CapabilityStatus::Available {
            status = row.status;
            reason = row.reason.to_owned();
            evidence = row.evidence.clone();
            break;
        }
    }
    Capability {
        name: requirement.to_string(),
        status,
        scope,
        mechanism: Some(mechanism.to_owned()),
        reason_code: Some(reason),
        measured_at: Some(measured_at.to_owned()),
        evidence_ref: (!evidence.is_empty()).then_some(evidence),
    }
}

/// The plan's requirement rows from the probe results.
pub(super) fn derive(
    plan: &PlanRequest,
    probes: &[ProbeRow],
    measured_at: &str,
) -> Vec<Capability> {
    plan.requirements
        .iter()
        .map(|requirement| capability_for(*requirement, probes, measured_at))
        .collect()
}

/// The probe rows themselves, for `doctor --json`, so it reports what was
/// measured and not only what the plan happened to ask for (§14.1).
pub(super) fn probe_rows(probes: &[ProbeRow], measured_at: &str) -> Vec<Capability> {
    probes
        .iter()
        .map(|row| Capability {
            name: row.name.to_owned(),
            status: row.status,
            scope: CapabilityScope::Host,
            mechanism: Some(row.mechanism.to_owned()),
            reason_code: Some(row.reason.to_owned()),
            measured_at: Some(measured_at.to_owned()),
            evidence_ref: (!row.evidence.is_empty()).then(|| row.evidence.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unavailable(name: &str, reason: &str) -> ProbeRow {
        let mut row = ProbeRow::new(
            PROBE_NAMES
                .iter()
                .copied()
                .find(|probe| *probe == name)
                .expect("a known probe name"),
            "test",
        );
        row = row.unavailable(
            match reason {
                "es_not_entitled" => "es_not_entitled",
                _ => "failed",
            },
            String::new(),
        );
        row
    }

    fn all_available() -> Vec<ProbeRow> {
        PROBE_NAMES
            .iter()
            .map(|name| {
                let mut row = ProbeRow::new(name, "test");
                row.evidence = "ok".to_owned();
                row
            })
            .collect()
    }

    #[test]
    fn the_unimplemented_requirements_stay_unsupported_and_unmeasured() {
        let probes = run_probes();
        let measured_at = "2026-10-22T00:00:00Z";
        for requirement in [
            Requirement::ClosedSetObservation,
            Requirement::CredentialStaging,
            Requirement::ExecutionBoundary,
            Requirement::Limit(LimitKey::Pids),
            Requirement::Limit(LimitKey::Mem),
            Requirement::Limit(LimitKey::Swap),
            Requirement::Limit(LimitKey::Cpu),
            Requirement::Limit(LimitKey::Storage),
            Requirement::Limit(LimitKey::Inodes),
        ]
        .into_iter()
        .filter(|requirement| {
            !(*requirement == Requirement::ClosedSetObservation && crate::profiles::J17_OBSERVE)
        }) {
            let capability = capability_for(requirement, &probes, measured_at);
            assert_eq!(
                capability.status,
                CapabilityStatus::Unsupported,
                "{}",
                requirement
            );
            assert_eq!(
                capability.reason_code.as_deref(),
                Some(REASON_UNSUPPORTED_PLATFORM),
                "{}",
                requirement
            );
            assert_eq!(capability.measured_at, None, "{}", requirement);
            assert!(!capability.satisfies(), "{}", requirement);
        }
    }

    #[test]
    fn every_probed_requirement_is_measured() {
        let probes = run_probes();
        let measured_at = "2026-10-22T00:00:00Z";
        for requirement in [
            Requirement::TreeTermination,
            Requirement::FilesystemContainment,
            Requirement::SyscallFilter,
            Requirement::NetworkNone,
            Requirement::ProtectedCoverage(crate::policy::ProtectedCoverage::ExistingAndRoot),
            Requirement::Limit(LimitKey::Wall),
        ] {
            let capability = capability_for(requirement, &probes, measured_at);
            assert_eq!(
                capability.measured_at,
                Some(measured_at.to_owned()),
                "{} claims a measurement",
                requirement
            );
        }
    }

    #[test]
    fn an_unentitled_es_refuses_the_tree_and_the_wall_with_its_own_reason() {
        let mut probes = all_available();
        let measured_at = "2026-10-22T00:00:00Z";
        let not_entitled = unavailable("es_descendants", "es_not_entitled");
        let index = probes
            .iter()
            .position(|row| row.name == "es_descendants")
            .expect("the ES row");
        probes[index] = not_entitled;
        for requirement in [
            Requirement::TreeTermination,
            Requirement::Limit(LimitKey::Wall),
        ] {
            let capability = capability_for(requirement, &probes, measured_at);
            assert_eq!(
                capability.status,
                CapabilityStatus::Unavailable,
                "{}",
                requirement
            );
            assert_eq!(
                capability.reason_code.as_deref(),
                Some("es_not_entitled"),
                "{}",
                requirement
            );
            assert!(!capability.satisfies(), "{}", requirement);
        }
        // Everything that does not rest on custody stays available.
        assert!(
            capability_for(Requirement::FilesystemContainment, &probes, measured_at).satisfies()
        );
    }

    #[test]
    fn a_failed_seatbelt_compile_refuses_the_profile_backed_requirements() {
        let mut probes = all_available();
        let measured_at = "2026-10-22T00:00:00Z";
        let index = probes
            .iter()
            .position(|row| row.name == "seatbelt_profile")
            .expect("the seatbelt row");
        probes[index] = unavailable("seatbelt_profile", "failed");
        for requirement in [
            Requirement::FilesystemContainment,
            Requirement::SyscallFilter,
            Requirement::ProtectedCoverage(crate::policy::ProtectedCoverage::ExistingAndRoot),
        ] {
            assert!(!capability_for(requirement, &probes, measured_at).satisfies());
        }
        // Network containment also needs the actual deny-network profile.
        assert!(!capability_for(Requirement::NetworkNone, &probes, measured_at).satisfies());
    }

    #[test]
    fn the_probe_rows_carry_their_evidence_for_doctor() {
        let probes = run_probes();
        let measured_at = "2026-10-22T00:00:00Z";
        let rows = probe_rows(&probes, measured_at);
        assert_eq!(
            rows.len(),
            PROBE_NAMES.len() - usize::from(!crate::profiles::J17_OBSERVE)
        );
        for row in &rows {
            assert_eq!(row.scope, CapabilityScope::Host);
            assert_eq!(row.measured_at, Some(measured_at.to_owned()));
        }
    }

    /// Entitlement alone proves neither observation wiring nor staging.
    #[test]
    fn unwired_observation_and_staging_cannot_be_available_even_with_entitlement() {
        for requirement in [
            Requirement::ClosedSetObservation,
            Requirement::CredentialStaging,
        ] {
            let cap = capability_for(requirement, &all_available(), "now");
            assert_eq!(cap.status, CapabilityStatus::Unsupported);
            assert_eq!(cap.measured_at, None);
        }
    }
}
