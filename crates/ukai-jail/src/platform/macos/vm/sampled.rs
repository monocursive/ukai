//! Sampling evidence never authorizes execution or changes its verified outcome.
use super::{protocol, record};
use crate::state::anchored::{self, Dir, Kind, Name};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::path::Path;

pub(super) const FILE: &str = "sampled-exposure.json";
const PATH: &str = "evidence/sampled-exposure.json";
const MAX: usize = protocol::MAX_FILE;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    readable: u64,
    unreadable: u64,
    oversize: u64,
    vanished: u64,
    unstable: u64,
    capped: u64,
}
impl Counts {
    fn total(&self) -> u128 {
        [
            self.readable,
            self.unreadable,
            self.oversize,
            self.vanished,
            self.unstable,
            self.capped,
        ]
        .into_iter()
        .map(u128::from)
        .sum()
    }
    fn failed(&self) -> bool {
        self.unreadable != 0
            || self.oversize != 0
            || self.vanished != 0
            || self.unstable != 0
            || self.capped != 0
    }
    fn bounded_by(&self, total: &Self) -> bool {
        self.readable <= total.readable
            && self.unreadable <= total.unreadable
            && self.oversize <= total.oversize
            && self.vanished <= total.vanished
            && self.unstable <= total.unstable
            && self.capped <= total.capped
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reads {
    environment: Counts,
    argv: Counts,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentity {
    pid: u64,
    starttime: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorIdentity {
    pid: u64,
    #[serde(deserialize_with = "nullable_u64")]
    starttime: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableIdentity {
    dev: u64,
    ino: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Process {
    pid: u64,
    starttime: u64,
    roles: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hit {
    pid: u64,
    starttime: u64,
    channel: String,
    representation: String,
    identity_stable: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    read_bytes: u64,
    process_count: u64,
    tick_bytes: u64,
    tick_ns: u64,
    hit_count: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lifecycle {
    #[serde(deserialize_with = "nullable_u64")]
    started_ns: Option<u64>,
    #[serde(deserialize_with = "nullable_u64")]
    supervisor_exit_observed_ns: Option<u64>,
    #[serde(deserialize_with = "nullable_u64")]
    stopped_ns: Option<u64>,
    stop_reason: String,
}
fn nullable_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    host_attempt_id: String,
    service_boot_id: String,
    guest_attempt_id: String,
    guest_boot_id: String,
    catalog_sha256: String,
    executable_sha256: String,
    sampler_sha256: String,
    guest_receipt_sha256: String,
    finished: bool,
    actual_values_retained: bool,
    scope: String,
    continuous_coverage_claimed: bool,
    arbitrary_memory_examined: bool,
    period_ns: u64,
    #[serde(deserialize_with = "nullable_u64")]
    first_ns: Option<u64>,
    #[serde(deserialize_with = "nullable_u64")]
    last_ns: Option<u64>,
    observed_interval_ns: u64,
    maximum_gap_ns: u64,
    maximum_tick_duration_ns: u64,
    tick_count: u64,
    late_poll_count: u64,
    missed_tick_count: u64,
    reads: Reads,
    verified_program_reads: Reads,
    verified_program_observed: bool,
    receipt_program_reads: Reads,
    receipt_program_observed: bool,
    observation_incomplete: bool,
    #[serde(deserialize_with = "unique_errors")]
    scan_errors: BTreeMap<String, u64>,
    hits: Vec<Hit>,
    processes: Vec<Process>,
    supervisor: SupervisorIdentity,
    receipt_process: ProcessIdentity,
    catalog_executable_identity: ExecutableIdentity,
    workload_uid: u64,
    limits: Limits,
    lifecycle: Lifecycle,
    #[serde(default, deserialize_with = "present_gate")]
    managed_gate: Option<ManagedGate>,
}

// A Prepared receipt is independently parsed in the same integer-only domain
// as its canonical digest. serde_json::Value alone would accept duplicate keys.
struct StrictValue(serde_json::Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("duplicate-free integer JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, StrictValue(value))) =
                    map.next_entry::<String, StrictValue>()?
                {
                    if values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(StrictValue(values.into()))
            }
        }
        d.deserialize_any(Visitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedGate {
    schema: String,
    prepared_receipt_sha256: String,
    prepared_receipt_digest: String,
    prepared_process: ProcessIdentity,
    prepared_observed_ns: u64,
    prepared_validated_ns: u64,
    #[serde(deserialize_with = "nullable_u64")]
    armed_observed_ns: Option<u64>,
    #[serde(deserialize_with = "nullable_u64")]
    release_started_ns: Option<u64>,
    #[serde(deserialize_with = "nullable_u64")]
    release_completed_ns: Option<u64>,
    #[serde(deserialize_with = "nullable_string")]
    failure: Option<String>,
}
fn nullable_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}
fn present_gate<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<ManagedGate>, D::Error> {
    ManagedGate::deserialize(d).map(Some)
}
fn exact_keys(value: &serde_json::Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}
fn string_list(value: &serde_json::Value) -> Option<Vec<&str>> {
    value
        .as_array()?
        .iter()
        .map(serde_json::Value::as_str)
        .collect()
}
fn string_set(value: &serde_json::Value) -> Option<BTreeSet<&str>> {
    let array = value.as_array()?;
    let values: BTreeSet<_> = array
        .iter()
        .map(serde_json::Value::as_str)
        .collect::<Option<_>>()?;
    (values.len() == array.len()).then_some(values)
}
fn prefixed_digest(value: &serde_json::Value) -> bool {
    value
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .is_some_and(crate::guest_program::is_sha256)
}

// Live inspect follows verify_bound_guest_receipt and verify_applied_limits
// against the stored host plan. These digest/equality checks bind records; they
// do not independently reconstruct policy or network authority from a digest.
fn managed_complete(
    report: &Report,
    receipt: &serde_json::Value,
    binding: &protocol::ReceiptBinding,
    native: &protocol::NativeProgramBinding,
    prepared_raw: &[u8],
    entry: &crate::guest_program::CatalogEntry,
) -> Option<bool> {
    use serde_json::{Value, json};
    let gate = report.managed_gate.as_ref()?;
    let StrictValue(prepared) = serde_json::from_slice(prepared_raw).ok()?;
    let canonical = crate::records::semantic::receipt_digest(&prepared).ok()?;
    let requirements = [
        "tree_termination",
        "closed_set_observation",
        "filesystem_containment",
        "syscall_filter",
        "network_proxy",
        "protected_coverage:existing_and_root",
        "limit:wall",
        "limit:pids",
        "limit:mem",
        "limit:swap",
        "execution_boundary",
        "credential_staging",
    ]
    .into_iter()
    .collect();
    let policy = &prepared["policy"];
    let identity = json!({"pid":report.receipt_process.pid,"identity":{"kind":"linux_boot_start","value":{
        "boot_id":binding.guest_boot_id,"pid":report.receipt_process.pid,"start_time_ticks":report.receipt_process.starttime}}});
    let attempt = prepared["attempt_id"].as_str()?;
    let uuid = attempt.strip_prefix("att_")?.parse::<uuid::Uuid>().ok()?;
    if gate.schema != "ukai.vm.managed-native-gate/1"
        || gate.prepared_receipt_sha256 != crate::guest_program::sha256(prepared_raw)
        || gate.prepared_receipt_digest != canonical
        || gate.prepared_process.pid != report.receipt_process.pid
        || gate.prepared_process.starttime != report.receipt_process.starttime
        || report.receipt_process.pid > u64::from(u32::MAX)
        || uuid.get_version_num() != 4
        || uuid.get_variant() != uuid::Variant::RFC4122
        || format!("att_{uuid}") != attempt
        || prepared["platform"]["os"] != "linux"
        || prepared["platform"]["arch"] != "aarch64"
        || prepared["jail"]["component"] != "ukai-jail"
        || prepared["jail"]["backend"] != "bubblewrap"
        || prepared["platform"] != receipt["platform"]
        || prepared["jail"] != receipt["jail"]
        || prepared["schema"] != "ukai.jail.receipt/1"
        || attempt != binding.guest_attempt_id
        || prepared["attempt_id"] != receipt["attempt_id"]
        || prepared["process"] != identity
        || receipt["process"] != identity
        || prepared["phase"] != "prepared"
        || prepared["exec_observed"] != false
        || prepared["outcome"]
            != json!({"kind":"pending","code":null,"signal":null,"cause":null,"error":null})
        || prepared["containment"] != "enforced"
        || prepared["child_protection"] != "enforced"
        || prepared["errors"] != json!([])
        || prepared.get("cleanup_error").is_none()
        || !prepared["cleanup_error"].is_null()
        || !prepared["vendor_state"].is_null()
        || prepared["lifetime"]["boundary"] != "pid_namespace"
        || prepared["lifetime"].get("tree_empty").is_none()
        || !prepared["lifetime"]["tree_empty"].is_null()
        || prepared["lifetime"]["integrity"] != "verified"
        || prepared["lifetime"]["verification_scope"] != "attempt_tree"
        || prepared["observer"]
            != json!({"backend":null,"set":null,"attached":false,
            "sources":{"wrapper":"supported","audit":"unsupported","proxy":"unsupported"},"gaps":[]})
        || prepared["credentials"]
            != json!([{"id":native.selected_credential_id,"mode":"vault","never_staged":true,
            "digest":null,"digest_unavailable_reason":"never_staged"}])
        || policy["name"] != "agent"
        || policy["observe"] != "on"
        || policy["evidence"] != "strict"
        || policy["digest"] != native.policy_digest
        || policy["digest"] != receipt["policy"]["digest"]
        || prepared["argv_digest"] != native.resolved_argv_digest
        || prepared["argv_digest"] != receipt["argv_digest"]
        || !exact_keys(
            policy,
            &[
                "name",
                "digest",
                "observe",
                "evidence",
                "requirements",
                "grants",
            ],
        )
        || string_set(&policy["requirements"]) != Some(requirements)
    {
        return None;
    }
    let grants = policy["grants"].as_array()?;
    let final_grants = receipt["policy"]["grants"].as_array()?;
    let canonical_rows = |rows: &[Value]| -> Option<Vec<Vec<u8>>> {
        let mut rows = rows
            .iter()
            .map(crate::canonical::to_jcs)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        rows.sort();
        Some(rows)
    };
    if canonical_rows(grants)? != canonical_rows(final_grants)? {
        return None;
    }
    let root = json!({"kind":"read_only","value":entry.install_root,"by":"program_resolution"});
    let mut root_count = 0;
    let mut hosts = Vec::new();
    for grant in grants {
        if !exact_keys(grant, &["kind", "value", "by"]) {
            return None;
        }
        if grant == &root {
            root_count += 1;
        } else if grant["kind"] == "allow_host" && grant["by"] == "operator" {
            hosts.push(grant["value"].as_str()?);
        } else {
            return None;
        }
    }
    if root_count != 1 {
        return None;
    }
    let applied = &prepared["applied"];
    let fs = &applied["filesystem"];
    let mounts = fs["mounts"].as_array()?;
    let mut allowed = string_list(&applied["network"]["allowed_hosts"])?;
    allowed.sort();
    hosts.sort();
    let tls_only = match applied["network"].get("tls_only") {
        None => Vec::new(),
        Some(value) => string_list(value)?,
    };
    if fs["mechanism"] != "bubblewrap-binds"
        || fs["protected_coverage"] != "existing_and_root"
        || !mounts.iter().all(|row| {
            exact_keys(row, &["path", "mode"])
                && row["path"].is_string()
                && matches!(row["mode"].as_str(), Some("ro" | "rw" | "hidden"))
        })
        || !mounts.contains(&json!({"path":entry.install_root,"mode":"ro"}))
        || !mounts.contains(&json!({"path":"/mnt/workspace","mode":"rw"}))
        || applied["network"]["mode"] != "proxy"
        || applied["network"]["mechanism"]
            != "network-namespace+outside-http-proxy+loopback-bridge+unix-peer-mediation"
        || applied["network"] != receipt["applied"]["network"]
        || allowed != hosts
        || tls_only.iter().any(|host| !hosts.contains(host))
        || applied["syscalls"]["mechanism"] != "seccomp-bpf+seccomp-user-notification"
        || !prefixed_digest(&applied["syscalls"]["digest"])
        || !applied["terminal"].is_null()
    {
        return None;
    }
    for key in ["environment_names", "removed_environment_names"] {
        if !applied[key].as_array()?.iter().all(|value| {
            value.as_str().is_some_and(|s| {
                !s.is_empty()
                    && s.bytes().enumerate().all(|(i, c)| {
                        c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                    })
            })
        }) {
            return None;
        }
    }
    let limits = applied["limits"].as_array()?;
    let final_limits = receipt["applied"]["limits"].as_array()?;
    if limits.len() != 4 || final_limits.len() != 4 {
        return None;
    }
    let mut seen = BTreeSet::new();
    for row in limits {
        if !exact_keys(
            row,
            &[
                "key",
                "requested",
                "required",
                "applied",
                "mechanism",
                "scope",
                "hit",
            ],
        ) {
            return None;
        }
        let key = row["key"].as_str()?;
        if !seen.insert(key) {
            return None;
        }
        let requested = row["requested"].as_str()?;
        let number = requested.parse::<u64>().ok()?;
        let mechanism = match key {
            "wall" if number > 0 => "boottime-deadline",
            "pids" if requested == "64" => "pids.max",
            "mem" if requested == "536870912" => "memory.max",
            "swap" if requested == "0" => "memory.swap.max",
            _ => return None,
        };
        let matching: Vec<_> = final_limits
            .iter()
            .filter(|other| other["key"] == key)
            .collect();
        if number.to_string() != requested
            || row["required"] != true
            || row["applied"] != true
            || row["scope"] != "tree"
            || row["mechanism"] != mechanism
            || !(row["hit"].is_null() || row["hit"] == false)
            || matching.len() != 1
            || ["requested", "required", "applied", "scope"]
                .iter()
                .any(|k| row[k] != matching[0][k])
        {
            return None;
        }
    }
    if gate.failure.as_deref().is_some_and(|failure| {
        ![
            "control_invalid",
            "prepared_invalid",
            "source_changed",
            "arming_failed",
            "release_failed",
            "cancelled",
            "early_stop",
        ]
        .contains(&failure)
    }) || gate.prepared_observed_ns > gate.prepared_validated_ns
        || gate.prepared_validated_ns > report.lifecycle.started_ns?
        || gate
            .armed_observed_ns
            .is_some_and(|armed| report.first_ns.is_none_or(|first| first > armed))
        || gate
            .release_started_ns
            .is_some_and(|release| gate.armed_observed_ns.is_none_or(|armed| armed > release))
        || gate.release_completed_ns.is_some_and(|completed| {
            gate.release_started_ns
                .is_none_or(|release| release > completed)
        })
    {
        return None;
    }
    Some(
        gate.failure.is_none()
            && gate
                .release_completed_ns
                .zip(report.lifecycle.supervisor_exit_observed_ns)
                .is_some_and(|(completed, exited)| completed <= exited)
            && report
                .lifecycle
                .supervisor_exit_observed_ns
                .zip(report.lifecycle.stopped_ns)
                .is_some_and(|(exited, stopped)| exited <= stopped)
            && report
                .last_ns
                .zip(report.lifecycle.supervisor_exit_observed_ns)
                .is_some_and(|(last, exited)| last <= exited)
            && report.lifecycle.stop_reason == "supervisor_exit"
            && receipt["exec_observed"] == true
            && receipt["phase"] == "settled"
            && receipt["lifetime"]["tree_empty"] == true
            && receipt["lifetime"]["integrity"] == "verified"
            && receipt["cleanup_error"].is_null(),
    )
}

fn unique_errors<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, u64>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, u64>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique error counters")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut value = BTreeMap::new();
            while let Some((key, count)) = map.next_entry::<String, u64>()? {
                if value.insert(key, count).is_some() {
                    return Err(serde::de::Error::custom("duplicate error counter"));
                }
            }
            Ok(value)
        }
    }
    d.deserialize_map(Unique)
}

fn read_file(attempt: &Path, relative: &str) -> Result<Vec<u8>, &'static str> {
    let root = Dir::open_trusted(attempt).map_err(|_| "attempt_unreadable")?;
    let (evidence, name) = if let Some(name) = relative.strip_prefix("evidence/") {
        (
            root.open_dir_at(&Name::new(b"evidence").unwrap(), None)
                .map_err(|_| "evidence_unreadable")?,
            name,
        )
    } else {
        (root, relative)
    };
    let name = Name::new(name.as_bytes()).map_err(|_| "report_path_invalid")?;
    let before = evidence.stat_at(&name).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "report_missing"
        } else {
            "report_unreadable"
        }
    })?;
    if before.kind != Kind::Regular || before.nlink != 1 || before.size > MAX as u64 {
        return Err("report_not_bounded_regular");
    }
    let mut file = evidence
        .open_read_at(&name, Some(&before))
        .map_err(|_| "report_open_failed")?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "report_read_failed")?;
    let after = anchored::fstat(file.as_fd()).map_err(|_| "report_stat_failed")?;
    let current = evidence.stat_at(&name).map_err(|_| "report_replaced")?;
    if !before.unchanged_since(&after)
        || !before.unchanged_since(&current)
        || bytes.len() as u64 != before.size
    {
        return Err("report_changed");
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn valid(
    report: &Report,
    receipt: &serde_json::Value,
    receipt_sha256: &str,
    binding: &protocol::ReceiptBinding,
    native: &protocol::NativeProgramBinding,
    supervisor_pid: u32,
    sampler: &str,
    managed: Option<bool>,
) -> bool {
    let pid = receipt
        .pointer("/process/identity/value/pid")
        .and_then(serde_json::Value::as_u64);
    let start = receipt
        .pointer("/process/identity/value/start_time_ticks")
        .and_then(serde_json::Value::as_u64);
    let is_managed = report.schema == protocol::SAMPLED_EXPOSURE_CONTRACT;
    if (!is_managed && report.schema != protocol::SAMPLED_EXPOSURE_CONTRACT_V2)
        || is_managed != report.managed_gate.is_some()
        || is_managed != managed.is_some()
        || !report.finished
        || report.actual_values_retained
        || report.scope
            != if is_managed {
                "managed-native-periodic-readable-environment-and-argv-only"
            } else {
                "periodic-readable-environment-and-argv-only"
            }
        || report.continuous_coverage_claimed
        || report.arbitrary_memory_examined
        || report.host_attempt_id != binding.attempt_id
        || report.service_boot_id != binding.boot_id
        || report.guest_attempt_id != binding.guest_attempt_id
        || report.guest_boot_id != binding.guest_boot_id
        || report.catalog_sha256 != native.catalog_sha256
        || report.executable_sha256 != native.executable_sha256
        || report.sampler_sha256 != sampler
        || report.guest_receipt_sha256 != receipt_sha256
        || receipt
            .pointer("/process/identity/kind")
            .and_then(serde_json::Value::as_str)
            != Some("linux_boot_start")
        || receipt
            .pointer("/process/identity/value/boot_id")
            .and_then(serde_json::Value::as_str)
            != Some(binding.guest_boot_id.as_str())
        || Some(report.receipt_process.pid) != pid
        || Some(report.receipt_process.starttime) != start
        || report.receipt_process.pid == 0
        || report.receipt_process.starttime == 0
        || report.supervisor.pid == 0
        || report.supervisor.pid != u64::from(supervisor_pid)
        || report.supervisor.starttime == Some(0)
        || report.workload_uid == 0
        || report.workload_uid > u64::from(u32::MAX)
        || report.period_ns != 100_000_000
        || report.limits.read_bytes != 2 * 1024 * 1024
        || report.limits.process_count != 4096
        || report.limits.tick_bytes != 16 * 1024 * 1024
        || report.limits.tick_ns != 50_000_000
        || report.limits.hit_count != 4096
        || report.hits.len() > 4096
        || report.processes.len() > 4096
        || !report
            .verified_program_reads
            .environment
            .bounded_by(&report.reads.environment)
        || !report
            .verified_program_reads
            .argv
            .bounded_by(&report.reads.argv)
        || !report
            .receipt_program_reads
            .environment
            .bounded_by(&report.verified_program_reads.environment)
        || !report
            .receipt_program_reads
            .argv
            .bounded_by(&report.verified_program_reads.argv)
    {
        return false;
    }
    if ![
        "manual",
        "requested",
        "supervisor_exit",
        "worker_failed",
        "join_timeout",
    ]
    .contains(&report.lifecycle.stop_reason.as_str())
    {
        return false;
    }
    if report.lifecycle.stop_reason == "manual" {
        if report.lifecycle.started_ns.is_some()
            || report.lifecycle.stopped_ns.is_some()
            || report.lifecycle.supervisor_exit_observed_ns.is_some()
        {
            return false;
        }
    } else {
        let Some(started) = report.lifecycle.started_ns else {
            return false;
        };
        if report.first_ns.is_some_and(|first| first < started)
            || report.lifecycle.stopped_ns.is_some_and(|stopped| {
                stopped < started || report.last_ns.is_some_and(|last| last > stopped)
            })
            || report
                .lifecycle
                .supervisor_exit_observed_ns
                .is_some_and(|exit| {
                    exit < started
                        || (report
                            .lifecycle
                            .stopped_ns
                            .is_some_and(|stopped| exit > stopped)
                            && !report.observation_incomplete)
                })
        {
            return false;
        }
    }
    let interval = match (report.first_ns, report.last_ns, report.tick_count) {
        (None, None, 0) => 0,
        (Some(first), Some(last), ticks) if ticks > 0 => match last.checked_sub(first) {
            Some(value) => value,
            None => return false,
        },
        _ => return false,
    };
    if report.observed_interval_ns != interval
        || report.maximum_gap_ns > interval
        || (report.tick_count > 1
            && (interval == 0
                || report.maximum_gap_ns == 0
                || u128::from(interval)
                    > u128::from(report.maximum_gap_ns) * u128::from(report.tick_count - 1)))
        || report.late_poll_count > report.tick_count.saturating_sub(1)
        || report.missed_tick_count > interval / report.period_ns
        || (report.tick_count <= 1
            && (interval != 0 || report.maximum_gap_ns != 0 || report.missed_tick_count != 0))
        || ((report.maximum_gap_ns > report.period_ns) != (report.late_poll_count > 0))
        || ((report.maximum_gap_ns >= report.period_ns.saturating_mul(2))
            != (report.missed_tick_count > 0))
    {
        return false;
    }
    let total = report.reads.environment.total();
    if total != report.reads.argv.total()
        || report.verified_program_reads.environment.total()
            != report.verified_program_reads.argv.total()
        || report.receipt_program_reads.environment.total()
            != report.receipt_program_reads.argv.total()
        || report.receipt_program_reads.environment.total() > u128::from(report.tick_count)
        || total > u128::from(report.tick_count) * u128::from(report.limits.process_count)
    {
        return false;
    }
    let error_codes = [
        "malformed_stat",
        "malformed_status",
        "tick_time_cap",
        "tick_byte_cap",
        "nonregular_proc_file",
        "oversize",
        "boot_identity_changed",
        "nonregular_executable",
        "identity_cap",
        "hit_cap",
        "identity_changed",
        "proc_root_changed",
        "invalid_pid_entry",
        "process_cap",
        "supervisor_unobserved",
        "selected_process_vanished",
        "selected_process_unreadable",
        "inventory_vanished",
        "inventory_unreadable",
        "proc_root_vanished",
        "proc_root_unreadable",
        "monitor_initialization_failed",
        "monitor_worker_failed",
        "monitor_join_timeout",
    ];
    if report
        .scan_errors
        .iter()
        .any(|(code, count)| *count == 0 || !error_codes.contains(&code.as_str()))
        || (report.maximum_tick_duration_ns > report.limits.tick_ns
            && !report.scan_errors.contains_key("tick_time_cap"))
    {
        return false;
    }
    let positive = report.verified_program_reads.environment.readable > 0
        && report.verified_program_reads.argv.readable > 0;
    let receipt_positive = report.receipt_program_reads.environment.readable > 0
        && report.receipt_program_reads.argv.readable > 0;
    let supervisor_observed = report.processes.iter().any(|process| {
        process.pid == report.supervisor.pid
            && Some(process.starttime) == report.supervisor.starttime
            && process.roles.iter().any(|role| role == "supervisor")
    });
    let incomplete = managed == Some(false)
        || !report.scan_errors.is_empty()
        || !positive
        || !receipt_positive
        || !supervisor_observed
        || report.tick_count == 0
        || report.reads.environment.failed()
        || report.reads.argv.failed();
    if report.verified_program_observed != positive
        || report.receipt_program_observed != receipt_positive
        || report.observation_incomplete != incomplete
    {
        return false;
    }
    // Startup may fail before the supervisor's birth can be read. Never fill
    // that unknown generation using the separate workload receipt identity.
    if report.supervisor.starttime.is_none()
        && (report.tick_count != 0
            || total != 0
            || !report.processes.is_empty()
            || !report.hits.is_empty()
            || !report
                .scan_errors
                .contains_key("monitor_initialization_failed"))
    {
        return false;
    }
    // An initialization failure may know no executable identity at all. Every
    // report with observations must identify the actual catalog inode.
    if report.catalog_executable_identity.ino == 0
        && (report.catalog_executable_identity.dev != 0
            || report.tick_count != 0
            || positive
            || !report
                .scan_errors
                .contains_key("monitor_initialization_failed"))
    {
        return false;
    }
    let mut identities = BTreeSet::new();
    let roles = [
        "supervisor",
        "descendant",
        "workload_uid",
        "catalog_program",
    ];
    for process in &report.processes {
        if process.pid == 0
            || process.starttime == 0
            || !identities.insert((process.pid, process.starttime))
            || process.roles.is_empty()
            || process
                .roles
                .iter()
                .any(|role| !roles.contains(&role.as_str()))
            || process.roles.iter().collect::<BTreeSet<_>>().len() != process.roles.len()
        {
            return false;
        }
    }
    if positive
        && !report
            .processes
            .iter()
            .any(|process| process.roles.iter().any(|role| role == "catalog_program"))
    {
        return false;
    }
    if receipt_positive
        && !report.processes.iter().any(|process| {
            process.pid == report.receipt_process.pid
                && process.starttime == report.receipt_process.starttime
                && process.roles.iter().any(|role| role == "catalog_program")
        })
    {
        return false;
    }
    for hit in &report.hits {
        if hit.pid == 0
            || hit.starttime == 0
            || !["environment", "argv"].contains(&hit.channel.as_str())
            || !["raw", "base64", "base64url", "hex", "url", "json"]
                .contains(&hit.representation.as_str())
            || (!incomplete
                && (!hit.identity_stable || !identities.contains(&(hit.pid, hit.starttime))))
        {
            return false;
        }
    }
    true
}

fn status(
    kind: &str,
    path: Option<&str>,
    sha256: Option<String>,
    reason: Option<&str>,
) -> record::SampledExposure {
    record::SampledExposure {
        status: kind.into(),
        path: path.map(str::to_owned),
        sha256,
        reason: reason.map(str::to_owned),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn inspect(
    attempt: &Path,
    receipt: &serde_json::Value,
    receipt_sha256: &str,
    binding: &protocol::ReceiptBinding,
    native: &protocol::NativeProgramBinding,
    supervisor_pid: Option<u32>,
    sampler: Option<&str>,
    export_error: Option<&str>,
    required_contract: Option<&str>,
) -> record::SampledExposure {
    if let Some(reason) = export_error {
        return status("invalid", None, None, Some(reason));
    }
    let bytes = match read_file(attempt, PATH) {
        Ok(bytes) => bytes,
        Err(reason) => {
            return status(
                if reason == "report_missing" {
                    "unavailable"
                } else {
                    "invalid"
                },
                None,
                None,
                Some(reason),
            );
        }
    };
    let hash = crate::guest_program::sha256(&bytes);
    if binding.sampled_exposure_sha256.as_deref() != Some(&hash) {
        return status(
            "invalid",
            Some(PATH),
            Some(hash),
            Some("report_hash_mismatch"),
        );
    }
    let Some(sampler) = sampler else {
        return status(
            "unavailable",
            Some(PATH),
            Some(hash),
            Some("sampler_source_unpinned"),
        );
    };
    if !crate::guest_program::is_sha256(sampler) {
        return status(
            "invalid",
            Some(PATH),
            Some(hash),
            Some("sampler_source_invalid"),
        );
    }
    let Some(supervisor_pid) = supervisor_pid else {
        return status(
            "unavailable",
            Some(PATH),
            Some(hash),
            Some("released_supervisor_missing"),
        );
    };
    let report: Report = match serde_json::from_slice(&bytes) {
        Ok(report) => report,
        Err(_) => return status("invalid", Some(PATH), Some(hash), Some("report_malformed")),
    };
    if required_contract.is_some_and(|required| {
        required != protocol::SAMPLED_EXPOSURE_CONTRACT || report.schema != required
    }) {
        return status(
            "invalid",
            Some(PATH),
            Some(hash),
            Some("report_contract_mismatch"),
        );
    }
    let managed = if report.schema == protocol::SAMPLED_EXPOSURE_CONTRACT {
        let checked = (|| {
            let raw = read_file(attempt, "evidence/managed-prepared.json").ok()?;
            let catalog_raw = read_file(attempt, "guest-native-catalog.json").ok()?;
            let catalog =
                crate::guest_program::Catalog::parse(&catalog_raw, &native.catalog_sha256).ok()?;
            let entry = catalog
                .entries
                .iter()
                .find(|entry| entry.id == native.entry_id)?;
            if entry.executable_sha256 != native.executable_sha256
                || entry.profile_sha256 != native.profile_sha256
            {
                return None;
            }
            managed_complete(&report, receipt, binding, native, &raw, entry)
        })();
        let Some(complete) = checked else {
            return status(
                "invalid",
                Some(PATH),
                Some(hash),
                Some("managed_gate_binding_or_shape"),
            );
        };
        Some(complete)
    } else {
        None
    };
    if !valid(
        &report,
        receipt,
        receipt_sha256,
        binding,
        native,
        supervisor_pid,
        sampler,
        managed,
    ) {
        return status(
            "invalid",
            Some(PATH),
            Some(hash),
            Some("report_binding_or_shape"),
        );
    }
    status(
        if report.observation_incomplete {
            "incomplete"
        } else {
            "complete"
        },
        Some(PATH),
        Some(hash),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    const REPORT: &[u8] = include_bytes!("../../../../vm/fixtures/sampled-exposure-report.json");
    const RECEIPT: &[u8] = include_bytes!("../../../../vm/fixtures/sampled-exposure-receipt.json");
    fn context() -> (
        Value,
        protocol::ReceiptBinding,
        protocol::NativeProgramBinding,
        String,
    ) {
        let context: Value = serde_json::from_slice(include_bytes!(
            "../../../../vm/fixtures/sampled-exposure-context.json"
        ))
        .unwrap();
        let string = |key: &str| context[key].as_str().unwrap().to_owned();
        let native = protocol::NativeProgramBinding {
            catalog_sha256: string("catalog_sha256"),
            executable_sha256: string("executable_sha256"),
            entry_id: "example".into(),
            profile_sha256: "b".repeat(64),
            selected_credential_id: "token".into(),
            state: "attempt".into(),
            request_argv_digest: "sha256:request".into(),
            resolved_argv_digest: "sha256:resolved".into(),
            policy_digest: "sha256:policy".into(),
        };
        let binding = protocol::ReceiptBinding {
            attempt_id: string("host_attempt_id"),
            boot_id: string("service_boot_id"),
            guest_attempt_id: string("guest_attempt_id"),
            guest_boot_id: string("guest_boot_id"),
            profile: "agent".into(),
            argv_digest: "sha256:resolved".into(),
            native_program: Some(native.clone()),
            sampled_exposure_sha256: Some(crate::guest_program::sha256(REPORT)),
        };
        (
            serde_json::from_slice(RECEIPT).unwrap(),
            binding,
            native,
            string("sampler_sha256"),
        )
    }
    fn judge(bytes: &[u8]) -> record::SampledExposure {
        judge_with_supervisor(bytes, Some(10))
    }
    fn judge_with_supervisor(bytes: &[u8], supervisor: Option<u32>) -> record::SampledExposure {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("evidence")).unwrap();
        std::fs::write(dir.path().join(PATH), bytes).unwrap();
        let (receipt, mut binding, native, sampler) = context();
        binding.sampled_exposure_sha256 = Some(crate::guest_program::sha256(bytes));
        inspect(
            dir.path(),
            &receipt,
            &crate::guest_program::sha256(RECEIPT),
            &binding,
            &native,
            supervisor,
            Some(&sampler),
            None,
            None,
        )
    }
    const MANAGED: &[u8] = include_bytes!("../../../../vm/fixtures/managed-sampled-exposure.json");
    fn managed_judge(fixture: &Value) -> record::SampledExposure {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("evidence")).unwrap();
        let report = serde_json::to_vec(&fixture["report"]).unwrap();
        std::fs::write(dir.path().join(PATH), &report).unwrap();
        std::fs::write(
            dir.path().join("evidence/managed-prepared.json"),
            fixture["prepared_raw"].as_str().unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("guest-native-catalog.json"),
            fixture["catalog_raw"].as_str().unwrap(),
        )
        .unwrap();
        let raw = fixture["receipt_raw"].as_str().unwrap();
        let receipt = serde_json::from_str(raw).unwrap();
        let mut binding: protocol::ReceiptBinding =
            serde_json::from_value(fixture["binding"].clone()).unwrap();
        binding.sampled_exposure_sha256 = Some(crate::guest_program::sha256(&report));
        inspect(
            dir.path(),
            &receipt,
            &crate::guest_program::sha256(raw.as_bytes()),
            &binding,
            &serde_json::from_value(fixture["native"].clone()).unwrap(),
            Some(10),
            fixture["sampler_sha256"].as_str(),
            None,
            Some(protocol::SAMPLED_EXPOSURE_CONTRACT),
        )
    }
    fn replace_prepared(fixture: &mut Value, prepared: Value) {
        let bytes = serde_json::to_vec(&prepared).unwrap();
        fixture["report"]["managed_gate"]["prepared_receipt_sha256"] =
            crate::guest_program::sha256(&bytes).into();
        fixture["report"]["managed_gate"]["prepared_receipt_digest"] =
            crate::records::semantic::receipt_digest(&prepared)
                .unwrap()
                .into();
        fixture["prepared_raw"] = String::from_utf8(bytes).unwrap().into();
    }
    #[test]
    fn managed_manual_vector_and_rehashed_prepared_authority_mutations() {
        let original: Value = serde_json::from_slice(MANAGED).unwrap();
        assert_eq!(managed_judge(&original).status, "complete");
        for (pointer, value) in [
            ("/platform/os", json!("macos")),
            ("/jail/backend", json!("fake")),
            ("/phase", json!("running")),
            ("/exec_observed", json!(true)),
            ("/outcome/kind", json!("unknown")),
            ("/outcome/code", json!(0)),
            ("/containment", json!("unknown")),
            ("/child_protection", json!("refused")),
            ("/errors", json!(["not_ready"])),
            ("/cleanup_error", json!({})),
            ("/vendor_state", json!({})),
            ("/process/pid", json!(12)),
            ("/process/identity/value/start_time_ticks", json!(102)),
            ("/process/identity/value/boot_id", json!("other")),
            ("/policy/digest", json!("sha256:wrong")),
            ("/policy/requirements", json!(["execution_boundary"])),
            ("/policy/grants", json!([])),
            ("/observer/attached", json!(true)),
            ("/credentials/0/id", json!("other")),
            ("/argv_digest", json!("sha256:wrong")),
            ("/applied/filesystem/mounts", json!([])),
            ("/applied/network/tls_only", json!([])),
            ("/applied/syscalls/digest", json!("unbound")),
            ("/applied/limits/0/requested", json!("21000")),
            ("/applied/limits/1/required", json!(1)),
            ("/applied/limits/2/hit", json!(true)),
            ("/applied/environment_names", json!(["TOKEN=secret"])),
            ("/applied/terminal", json!({})),
        ] {
            let mut fixture = original.clone();
            let mut prepared: Value =
                serde_json::from_str(fixture["prepared_raw"].as_str().unwrap()).unwrap();
            *prepared.pointer_mut(pointer).unwrap() = value;
            replace_prepared(&mut fixture, prepared);
            assert_eq!(managed_judge(&fixture).status, "invalid", "{pointer}");
        }
    }
    #[test]
    fn managed_required_prepared_null_fields_cannot_be_omitted() {
        let original: Value = serde_json::from_slice(MANAGED).unwrap();
        for (parent, key) in [
            ("", "cleanup_error"),
            ("/lifetime", "tree_empty"),
            ("/outcome", "error"),
            ("/observer", "backend"),
            ("/credentials/0", "digest"),
            ("/applied/limits/0", "hit"),
        ] {
            let mut fixture = original.clone();
            let mut prepared: Value =
                serde_json::from_str(fixture["prepared_raw"].as_str().unwrap()).unwrap();
            prepared
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            replace_prepared(&mut fixture, prepared);
            assert_eq!(managed_judge(&fixture).status, "invalid", "{parent}/{key}");
        }
    }
    #[test]
    fn managed_duplicate_grants_preserve_multiplicity_and_omitted_empty_tls() {
        let mut fixture: Value = serde_json::from_slice(MANAGED).unwrap();
        let mut prepared: Value =
            serde_json::from_str(fixture["prepared_raw"].as_str().unwrap()).unwrap();
        let mut receipt: Value =
            serde_json::from_str(fixture["receipt_raw"].as_str().unwrap()).unwrap();
        for value in [&mut prepared, &mut receipt] {
            let grant = value["policy"]["grants"][1].clone();
            value["policy"]["grants"]
                .as_array_mut()
                .unwrap()
                .push(grant);
            value["applied"]["network"]["allowed_hosts"]
                .as_array_mut()
                .unwrap()
                .push(json!("api.example.com:443"));
            value["applied"]["network"]
                .as_object_mut()
                .unwrap()
                .remove("tls_only");
        }
        fixture["receipt_raw"] = serde_json::to_string(&receipt).unwrap().into();
        fixture["report"]["guest_receipt_sha256"] =
            crate::guest_program::sha256(fixture["receipt_raw"].as_str().unwrap().as_bytes())
                .into();
        replace_prepared(&mut fixture, prepared.clone());
        assert_eq!(managed_judge(&fixture).status, "complete");
        prepared["policy"]["grants"].as_array_mut().unwrap().pop();
        replace_prepared(&mut fixture, prepared);
        assert_eq!(managed_judge(&fixture).status, "invalid");
    }
    #[test]
    fn managed_fast_exit_partial_release_and_mixed_schema_never_claim_complete() {
        let original: Value = serde_json::from_slice(MANAGED).unwrap();
        for (key, value) in [
            ("schema", json!("unknown")),
            ("prepared_observed_ns", json!(true)),
            ("prepared_validated_ns", json!(99)),
            ("armed_observed_ns", json!(299)),
            ("release_started_ns", json!(399)),
            ("release_completed_ns", json!(499)),
            ("failure", json!("new_failure")),
            ("prepared_process", json!({"pid":10,"starttime":100})),
        ] {
            let mut fixture = original.clone();
            fixture["report"]["managed_gate"][key] = value;
            assert_eq!(managed_judge(&fixture).status, "invalid", "{key}");
        }
        let mut fixture = original.clone();
        fixture["report"]["managed_gate"]["release_completed_ns"] = json!(200000850);
        assert_eq!(managed_judge(&fixture).status, "invalid");
        fixture["report"]["observation_incomplete"] = json!(true);
        assert_eq!(
            managed_judge(&fixture).status,
            "incomplete",
            "fast exit is not malformed chronology"
        );
        for key in [
            "armed_observed_ns",
            "release_started_ns",
            "release_completed_ns",
        ] {
            fixture["report"]["managed_gate"][key] = Value::Null;
        }
        fixture["report"]["managed_gate"]["failure"] = json!("arming_failed");
        assert_eq!(managed_judge(&fixture).status, "incomplete");
        for managed in [Value::Null, json!({})] {
            fixture = original.clone();
            fixture["report"]["managed_gate"] = managed;
            assert_eq!(managed_judge(&fixture).status, "invalid");
        }
        fixture = original.clone();
        fixture["report"]["schema"] = protocol::SAMPLED_EXPOSURE_CONTRACT_V2.into();
        assert_eq!(
            managed_judge(&fixture).status,
            "invalid",
            "current Session cannot downgrade"
        );
    }
    #[test]
    fn managed_prepared_raw_duplicate_and_generation_refuse() {
        let original: Value = serde_json::from_slice(MANAGED).unwrap();
        let mut fixture = original.clone();
        let raw = fixture["prepared_raw"].as_str().unwrap().replace(
            "\"phase\": \"prepared\"",
            "\"phase\": \"prepared\", \"phase\": \"prepared\"",
        );
        fixture["report"]["managed_gate"]["prepared_receipt_sha256"] =
            crate::guest_program::sha256(raw.as_bytes()).into();
        fixture["prepared_raw"] = raw.into();
        assert_eq!(managed_judge(&fixture).status, "invalid");
        fixture = original.clone();
        fixture["prepared_raw"] = format!("{} ", fixture["prepared_raw"].as_str().unwrap()).into();
        assert_eq!(managed_judge(&fixture).status, "invalid");
        fixture = original;
        let mut catalog: Value =
            serde_json::from_str(fixture["catalog_raw"].as_str().unwrap()).unwrap();
        catalog["entries"][0]["install_root"] = json!("/tmp/forged");
        fixture["catalog_raw"] = serde_json::to_string(&catalog).unwrap().into();
        assert_eq!(managed_judge(&fixture).status, "invalid");
    }
    #[test]
    fn supervisor_and_receipt_process_are_distinct_and_both_are_bound() {
        let value: Value = serde_json::from_slice(REPORT).unwrap();
        assert_ne!(value["supervisor"], value["receipt_process"]);
        assert_eq!(judge(REPORT).status, "complete");
        assert_eq!(judge_with_supervisor(REPORT, Some(11)).status, "invalid");
        assert_eq!(judge_with_supervisor(REPORT, Some(0)).status, "invalid");
        assert_eq!(judge_with_supervisor(REPORT, None).status, "unavailable");

        let mut other_program = value.clone();
        for channel in ["environment", "argv"] {
            for count in other_program["receipt_program_reads"][channel]
                .as_object_mut()
                .unwrap()
                .values_mut()
            {
                *count = json!(0);
            }
        }
        other_program["receipt_program_observed"] = json!(false);
        other_program["observation_incomplete"] = json!(true);
        assert_eq!(
            judge(&serde_json::to_vec(&other_program).unwrap()).status,
            "incomplete",
            "other catalog processes cannot supply the receipt process's observations"
        );
        other_program["observation_incomplete"] = json!(false);
        assert_eq!(
            judge(&serde_json::to_vec(&other_program).unwrap()).status,
            "invalid"
        );

        let mut inflation = value;
        for key in ["reads", "verified_program_reads", "receipt_program_reads"] {
            for channel in ["environment", "argv"] {
                inflation[key][channel]["readable"] = json!(3);
            }
        }
        assert_eq!(
            judge(&serde_json::to_vec(&inflation).unwrap()).status,
            "invalid",
            "one receipt process cannot be counted twice in a sampling tick"
        );
    }
    #[test]
    fn unknown_supervisor_birth_is_only_an_explicit_zero_observation_startup_failure() {
        let mut value: Value = serde_json::from_slice(REPORT).unwrap();
        value["supervisor"]["starttime"] = Value::Null;
        assert_eq!(
            judge(&serde_json::to_vec(&value).unwrap()).status,
            "invalid"
        );
        for key in ["reads", "verified_program_reads", "receipt_program_reads"] {
            for channel in ["environment", "argv"] {
                for count in value[key][channel].as_object_mut().unwrap().values_mut() {
                    *count = json!(0);
                }
            }
        }
        for key in [
            "tick_count",
            "observed_interval_ns",
            "maximum_gap_ns",
            "maximum_tick_duration_ns",
            "late_poll_count",
            "missed_tick_count",
        ] {
            value[key] = json!(0);
        }
        value["first_ns"] = Value::Null;
        value["last_ns"] = Value::Null;
        value["processes"] = json!([]);
        value["hits"] = json!([]);
        value["catalog_executable_identity"] = json!({"dev":0, "ino":0});
        value["verified_program_observed"] = json!(false);
        value["receipt_program_observed"] = json!(false);
        value["observation_incomplete"] = json!(true);
        value["scan_errors"] = json!({"monitor_initialization_failed":1});
        assert_eq!(
            judge(&serde_json::to_vec(&value).unwrap()).status,
            "incomplete"
        );
        value["scan_errors"] = json!({"monitor_worker_failed":1});
        assert_eq!(
            judge(&serde_json::to_vec(&value).unwrap()).status,
            "invalid"
        );
    }
    #[test]
    fn actual_sampler_fixture_and_valid_incomplete_reports_are_separate_from_execution() {
        assert_eq!(judge(REPORT).status, "complete");
        let mut value: Value = serde_json::from_slice(REPORT).unwrap();
        value["scan_errors"] = json!({"monitor_worker_failed":1});
        value["observation_incomplete"] = json!(true);
        value["lifecycle"]["stop_reason"] = json!("worker_failed");
        value["lifecycle"]["supervisor_exit_observed_ns"] = json!(100_000_004);
        assert_eq!(
            judge(&serde_json::to_vec(&value).unwrap()).status,
            "incomplete",
            "a failed worker may stop before the caller observes supervisor exit"
        );
        value["observation_incomplete"] = json!(false);
        assert_eq!(
            judge(&serde_json::to_vec(&value).unwrap()).status,
            "invalid",
            "reported complete cannot hide sticky errors"
        );
        let mut hit: Value = serde_json::from_slice(REPORT).unwrap();
        hit["hits"] = json!([{"pid":11,"starttime":101,"channel":"environment","representation":"raw","identity_stable":true}]);
        assert_eq!(
            judge(&serde_json::to_vec(&hit).unwrap()).status,
            "complete",
            "complete sampling is not a no-exposure verdict"
        );
    }
    #[test]
    fn identity_shape_counts_and_source_pins_are_recomputed() {
        for (pointer, replacement) in [
            ("/host_attempt_id", json!("other")),
            ("/service_boot_id", json!("other")),
            ("/guest_attempt_id", json!("other")),
            ("/guest_boot_id", json!("other")),
            ("/catalog_sha256", json!("a".repeat(64))),
            ("/executable_sha256", json!("a".repeat(64))),
            ("/sampler_sha256", json!("a".repeat(64))),
            ("/guest_receipt_sha256", json!("a".repeat(64))),
            ("/supervisor/pid", json!(11)),
            ("/supervisor/starttime", json!(101)),
            ("/receipt_process/pid", json!(10)),
            ("/receipt_process/starttime", json!(100)),
            ("/receipt_program_observed", json!(false)),
            ("/receipt_program_reads/argv/readable", json!(99)),
            ("/reads/environment/readable", json!(true)),
            ("/verified_program_reads/argv/readable", json!(99)),
            ("/tick_count", json!(0)),
            ("/period_ns", json!(1)),
            ("/actual_values_retained", json!(true)),
            ("/continuous_coverage_claimed", json!(true)),
            ("/lifecycle/stopped_ns", json!(0)),
            ("/late_poll_count", json!(1)),
            ("/missed_tick_count", json!(1)),
            ("/reads/environment/readable", json!(5)),
            ("/catalog_executable_identity/ino", json!(0)),
            ("/observation_incomplete", json!(true)),
            ("/verified_program_observed", json!(false)),
        ] {
            let mut value: Value = serde_json::from_slice(REPORT).unwrap();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert_eq!(
                judge(&serde_json::to_vec(&value).unwrap()).status,
                "invalid",
                "{pointer}"
            );
        }
        for pointer in [
            "/first_ns",
            "/last_ns",
            "/lifecycle/started_ns",
            "/lifecycle/stopped_ns",
            "/lifecycle/supervisor_exit_observed_ns",
        ] {
            let mut value: Value = serde_json::from_slice(REPORT).unwrap();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            value
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert_eq!(
                judge(&serde_json::to_vec(&value).unwrap()).status,
                "invalid",
                "missing nullable field {pointer}"
            );
        }
        let mut inflated: Value = serde_json::from_slice(REPORT).unwrap();
        for key in ["reads", "verified_program_reads"] {
            for channel in ["environment", "argv"] {
                inflated[key][channel]["readable"] = json!(u64::MAX);
            }
        }
        assert_eq!(
            judge(&serde_json::to_vec(&inflated).unwrap()).status,
            "invalid",
            "matching inflated counters exceed the bounded process population per tick"
        );
        let mut value: Value = serde_json::from_slice(REPORT).unwrap();
        value["raw_environment"] = json!("must not be admitted");
        assert_eq!(
            judge(&serde_json::to_vec(&value).unwrap()).status,
            "invalid"
        );
        let duplicate = String::from_utf8(REPORT.to_vec()).unwrap().replacen(
            "\"scan_errors\": {}",
            "\"scan_errors\": {\"hit_cap\":1,\"hit_cap\":0}",
            1,
        );
        assert_eq!(judge(duplicate.as_bytes()).status, "invalid");
    }
    #[test]
    fn anchored_report_read_refuses_links_oversize_duplicates_and_missing_provenance() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("evidence")).unwrap();
        let (receipt, binding, native, sampler) = context();
        let check = |pin, error| {
            inspect(
                dir.path(),
                &receipt,
                &crate::guest_program::sha256(RECEIPT),
                &binding,
                &native,
                Some(10),
                pin,
                error,
                None,
            )
        };
        assert_eq!(check(Some(sampler.as_str()), None).status, "unavailable");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, REPORT).unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join(PATH)).unwrap();
        assert_eq!(check(Some(sampler.as_str()), None).status, "invalid");
        std::fs::remove_file(dir.path().join(PATH)).unwrap();
        std::fs::hard_link(&outside, dir.path().join(PATH)).unwrap();
        assert_eq!(check(Some(sampler.as_str()), None).status, "invalid");
        std::fs::remove_file(dir.path().join(PATH)).unwrap();
        std::fs::write(dir.path().join(PATH), vec![b'x'; MAX + 1]).unwrap();
        assert_eq!(check(Some(sampler.as_str()), None).status, "invalid");
        std::fs::write(dir.path().join(PATH), REPORT).unwrap();
        assert_eq!(check(None, None).status, "unavailable");
        assert_eq!(check(Some("bad-pin"), None).status, "invalid");
        assert_eq!(
            check(Some(sampler.as_str()), Some("duplicate_report")).status,
            "invalid"
        );
    }
}
