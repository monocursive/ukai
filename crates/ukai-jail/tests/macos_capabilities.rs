//! J16: the macOS capability answers, the doctor rows and the §4.10
//! baseline behavior (jail-macos.md §4.10).
//!
//! Everything here drives the built binary, because the macOS platform
//! module is crate-private: what an operator sees is the contract. The live
//! ES probe never skips — this Mac's own answer (`NotEntitled`, or
//! `Unavailable` where the framework is absent) is the assertion.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::{Command, Output};

mod common;

struct Harness {
    temp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

impl Harness {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = common::private_tempdir();
        let make = |name: &str, mode: u32| {
            let path = temp.path().join(name);
            std::fs::create_dir(&path).expect("a directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
            path
        };
        Harness {
            data: make("data", 0o700),
            config: make("config", 0o700),
            work: make("work", 0o755),
            temp,
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.path())
            .env("UKAI_DATA_DIR", &self.data)
            .env("UKAI_CONFIG_DIR", &self.config)
            .current_dir(&self.work)
            .args(arguments)
            .output()
            .expect("the binary runs")
    }

    fn json(&self, arguments: &[&str]) -> serde_json::Value {
        let output = self.run(arguments);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{arguments:?} must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("JSON on stdout")
    }
}

fn doctor_json(harness: &Harness) -> serde_json::Value {
    let output = harness.run(&["doctor", "--json"]);
    assert_eq!(output.status.code(), Some(125));
    serde_json::from_slice(&output.stdout).expect("doctor prints JSON on stdout")
}

fn capability<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["capabilities"]
        .as_array()
        .expect("capability rows")
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("a `{name}` row"))
}

/// §4.10: the plan's probed requirements are real measurements of this
/// host; the platform's own gaps stay `unsupported` and unmeasured.
#[test]
fn doctor_rows_answer_the_section_4_10_table() {
    let harness = Harness::new();
    let report = doctor_json(&harness);
    assert_eq!(report["ready"], serde_json::json!(false));

    // The probe rows `doctor` measures on this platform, every one named and
    // measured.
    for name in [
        "es_descendants",
        "seatbelt_profile",
        "loopback_bind",
        "bootsessionuuid",
        "maxprocperuid",
    ] {
        let row = capability(&report, name);
        assert!(
            !row["measured_at"].is_null(),
            "{name} ran: {}",
            row["status"]
        );
    }
    // tree_termination rides the live ES probe: unentitled or frameworkless
    // here, either way it refuses with its own reason, never a skip.
    let tree = capability(&report, "tree_termination");
    assert_eq!(tree["status"], serde_json::json!("unavailable"));
    let reason = tree["reason_code"].as_str().expect("a reason code");
    assert!(
        reason == "es_not_entitled" || reason == "es_unavailable",
        "the ES probe names its own refusal: {reason}"
    );
    println!("es_descendants reason: {reason}");
    if reason == "es_not_entitled" {
        let evidence = tree["evidence_ref"].as_str().expect("the raw code");
        println!("es_new_descendants_client raw code: {evidence}");
    }
    // The profile-backed rows measure the host.
    for name in ["filesystem_containment", "syscall_filter"] {
        let row = capability(&report, name);
        assert_eq!(row["status"], serde_json::json!("available"), "{name}");
        assert_eq!(row["mechanism"], serde_json::json!("seatbelt_profile"));
    }
    let loopback = capability(&report, "loopback_bind");
    assert_eq!(loopback["status"], serde_json::json!("available"));

    // The wall needs custody, so it follows the ES answer.
    let wall = capability(&report, "limit:wall");
    assert_eq!(
        wall["mechanism"],
        serde_json::json!("both-custodians-continuous-clock")
    );

    // The platform's gaps stay unsupported and unmeasured. `none` is not the
    // default plan, so ask for one explicitly.
    let output = harness.run(&["doctor", "--json", "--profile", "none"]);
    assert_eq!(output.status.code(), Some(125));
    let none: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor prints JSON");
    let boundary = capability(&none, "execution_boundary");
    assert_eq!(boundary["status"], serde_json::json!("unsupported"));
    assert_eq!(
        boundary["reason_code"],
        serde_json::json!("unsupported_platform")
    );
    assert!(boundary["measured_at"].is_null());
}

/// The doctor text names exactly the §4.10 rows.
#[test]
fn the_doctor_text_names_the_macos_rows() {
    let harness = Harness::new();
    let output = harness.run(&["doctor"]);
    assert_eq!(output.status.code(), Some(125));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for prefix in [
        "macos_es_descendants",
        "macos_seatbelt_profile",
        "macos_loopback_bind",
        "macos_bootsessionuuid",
        "macos_maxprocperuid",
    ] {
        assert!(
            stdout.contains(prefix),
            "the doctor text names {prefix}: {stdout}"
        );
    }
}

/// §4.10: `--profile none` refuses before exec, because without a sandbox
/// nothing defends the custodians.
#[test]
fn profile_none_refuses_with_an_unsupported_plan() {
    let harness = Harness::new();
    let marker = harness.work.join("marker-none");
    let output = harness.run(&[
        "run",
        "--profile",
        "none",
        "--",
        "/usr/bin/touch",
        marker.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(125));
    assert!(!marker.exists(), "nothing runs without a boundary");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported_platform") || stderr.contains("missing_capability"),
        "the refusal is the capability gate's: {stderr}"
    );
}

/// §4.10: every explicit tree ceiling refuses, because there is no
/// supervisor-owned resource boundary on this platform.
#[test]
fn an_explicit_tree_ceiling_refuses() {
    let harness = Harness::new();
    let output = harness.run(&["run", "--limit", "pids=64", "--", "/usr/bin/true"]);
    assert_eq!(
        output.status.code(),
        Some(125),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("limit:pids") || stderr.contains("missing_capability"),
        "the refusal names the unsupported ceiling: {stderr}"
    );
}

/// §4.10 with the §5 flip: while [`J17_OBSERVE`] is off the macOS baseline
/// is `observe = off`, and a layer that turns observation on refuses with
/// `unsupported_platform` naming J17; an explicit `--observe off` over that
/// baseline stays allowed. With J17 on, the baseline is `observe = on`: the
/// snapshot carries it, `--observe on` resolves, and `--observe off` stays
/// an explicit narrowing.
#[test]
fn observe_mode_follows_the_j17_switch() {
    let harness = Harness::new();
    if !ukai_jail::profiles::J17_OBSERVE {
        let output = harness.run(&["run", "--observe", "on", "--", "/usr/bin/true"]);
        assert_eq!(
            output.status.code(),
            Some(125),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unsupported_platform"),
            "the observe-on refusal is unsupported_platform: {stderr}"
        );
        assert!(
            stderr.contains("J17"),
            "the refusal names the milestone that lifts it: {stderr}"
        );
    }

    // `--observe off` is explicit and allowed at resolution.
    let expected = if ukai_jail::profiles::J17_OBSERVE {
        "on"
    } else {
        "off"
    };
    let report = harness.json(&["explain", "--json", "--observe", "off"]);
    assert_eq!(
        report["policy"]["snapshot"]["observation"]["mode"],
        serde_json::json!("off")
    );
    // And so is the baseline alone: no layer, the J17 mode.
    let report = harness.json(&["explain", "--json"]);
    assert_eq!(
        report["policy"]["snapshot"]["observation"]["mode"],
        serde_json::json!(expected)
    );
}

/// §4.10: `build`'s memory ceiling is preferred on macOS, recorded as not
/// applied instead of required, so resolving `build` without an explicit
/// ceiling no longer refuses at resolution.
#[test]
fn build_resolves_without_an_explicit_memory_ceiling() {
    let harness = Harness::new();
    let report = harness.json(&["explain", "--json", "--profile", "build"]);
    let limits = &report["policy"]["snapshot"]["limits"];
    let mem = limits
        .as_object()
        .expect("the limits table")
        .get("mem")
        .expect("the baseline's preferred memory ceiling");
    assert_eq!(mem["required"], serde_json::json!(false));
    assert_eq!(mem["value"], serde_json::json!("2147483648"));
}

/// §4.11: a group-writable program directory whose group is not exactly
/// {root, the operator} still refuses. The operator's own primary group
/// stands in for a foreign group: it is not `admin`, so J12's rule keeps
/// its refusal (this Mac's `staff` lists no members, which the rule
/// refuses — the shape a nested group hides in).
#[test]
fn a_group_writable_directory_outside_the_rule_refuses() {
    use std::os::unix::fs::PermissionsExt as _;
    let harness = Harness::new();
    // `--from-path` defaults the workspace to a repository top level.
    std::fs::create_dir(harness.work.join(".git")).expect("a repository");
    std::fs::write(harness.work.join(".git/HEAD"), b"ref: refs/heads/main\n").expect("HEAD");
    let bin = harness.temp.path().join("wide-bin");
    std::fs::create_dir(&bin).expect("a directory");
    let program = bin.join("probe-launch");
    std::fs::copy("/usr/bin/true", &program).expect("a copy of true");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("executable");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).expect("group-writable");
    std::fs::create_dir(harness.config.join("launch")).expect("the launch directory");
    std::fs::write(
        harness.config.join("launch").join("probe-launch.toml"),
        b"name = \"probe-launch\"\njail = \"tool\"\n",
    )
    .expect("the launch profile");
    std::fs::set_permissions(
        harness.config.join("launch").join("probe-launch.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("private profile");
    let mut path = std::ffi::OsString::from(&bin);
    path.push(":/usr/bin:/bin");
    let output = Command::new(env!("CARGO_BIN_EXE_ukai-jail"))
        .env_clear()
        .env("PATH", &path)
        .env("HOME", harness.temp.path())
        .env("UKAI_DATA_DIR", &harness.data)
        .env("UKAI_CONFIG_DIR", &harness.config)
        .current_dir(&harness.work)
        .args(["run", "--launch", "probe-launch", "--from-path"])
        .output()
        .expect("the binary runs");
    assert_eq!(
        output.status.code(),
        Some(125),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("0775") || stderr.contains("group"),
        "the refusal names the group-writable mode: {stderr}"
    );
}

/// The doctor text keeps its X05 line shape for the capability rows.
#[test]
fn capability_lines_keep_their_shape() {
    let harness = Harness::new();
    let output = harness.run(&["doctor"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("capability tree_termination "),
        "the tree row is a capability line: {stdout}"
    );
    assert!(
        stdout.contains("capability limit:wall "),
        "the wall row is a capability line: {stdout}"
    );
}
