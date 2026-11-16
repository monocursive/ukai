#![cfg(target_os = "linux")]
//! The observer's own defects: places where the ptrace observer could
//! report coverage as complete when it is not. D1, a child's own seccomp
//! filter takes calls away from it; D2, a call under another ABI; D6,
//! critical facts behind a full lifecycle backlog. The `j4_dN_…` tests carry
//! those labels.
//!
//! Each was written before its fix and failed without it. The shape is the
//! observer suite's (`common/observer.rs`): a C fixture built at test time
//! (`fixtures/observer_j4.c`) is the inside launcher (it installs the
//! narrowing filter this crate produces, blocks on its release pipe, then
//! execs), the test seizes it with `Tracer::attach`, and what the observer
//! said is compared with what the fixture says the kernel returned. The two
//! `none` receipt checks run the real `ukai-jail` over the same fixture.
//!
//! Every process these tests trace is one they start; nothing on the host is
//! inspected or changed.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;
#[cfg(not(target_arch = "x86_64"))]
use ukai_fixture::harness;
use ukai_fixture::harness::{Jail, Run};
use ukai_jail::platform::linux::tracer::{
    ClosedOp, GapReason, OpSet, TracerConfig, TracerEvent, narrowing_filter_bytes,
};

// The shared tracer scaffolding, and the contract checks for the two `none`
// receipts below.
mod common;

use common::observer::{
    Fixture, Observed, Report, Work, attach, collect, launch, launch_tool, primary, serial,
};

static FIXTURE: Fixture = Fixture {
    name: "observer_j4",
    source: include_str!("fixtures/observer_j4.c"),
    pthread: true,
    filter: narrowing_filter_bytes,
};

fn setup(name: &str) -> Option<Work> {
    FIXTURE.setup(name, &[])
}

fn foreign_abis() -> bool {
    if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        return true;
    }
    ukai_fixture::harness::skip_or_fail(
        "the i386/x32 and ARM32 EABI fixtures require x86_64 or aarch64; \
         a 32-bit compat ABI on this architecture is not exercised by the fixture",
    );
    false
}

struct ForeignTarget {
    argv: Vec<String>,
    created: String,
    native: String,
}

#[cfg(target_arch = "x86_64")]
fn foreign_target(work: &Work) -> Option<ForeignTarget> {
    let created = work.path("by-i386");
    let native = work.path("native");
    Some(ForeignTarget {
        argv: vec![
            work.helper_s(),
            "foreign".into(),
            created.clone(),
            work.path("by-x32"),
            native.clone(),
        ],
        created,
        native,
    })
}

/// AArch64 needs a different executable to enter AArch32. Build a static
/// ELF32 EABI helper with no libc/loader, then require its sentinel under a
/// direct exec before trusting any observer result. Missing cross-binutils or
/// CPU/kernel compat support stays a named strict-conformance failure.
#[cfg(target_arch = "aarch64")]
fn foreign_target(work: &Work) -> Option<ForeignTarget> {
    use std::process::Command;

    let source = work.dir().join("arm32.S");
    let object = work.dir().join("arm32.o");
    let helper = work.dir().join("arm32");
    std::fs::write(&source, include_str!("fixtures/observer_j4_arm32.S"))
        .expect("write the ARM32 assembly");
    let commands = [
        (
            "/usr/bin/arm-linux-gnueabihf-as",
            vec![
                OsString::from("-march=armv7-a"),
                OsString::from("-o"),
                object.clone().into(),
                source.into(),
            ],
        ),
        (
            "/usr/bin/arm-linux-gnueabihf-ld",
            vec![
                OsString::from("-static"),
                OsString::from("--build-id=none"),
                OsString::from("-e"),
                OsString::from("_start"),
                OsString::from("-o"),
                helper.clone().into(),
                object.into(),
            ],
        ),
    ];
    for (tool, args) in commands {
        if !Path::new(tool).exists() {
            harness::skip_or_fail(&format!(
                "ARM32 foreign-ABI fixture requires {tool} (cross-binutils)"
            ));
            return None;
        }
        let output = Command::new(tool)
            .args(args)
            .output()
            .expect("run cross-binutils");
        assert!(
            output.status.success(),
            "{tool}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let elf = std::fs::read(&helper).expect("read ARM32 executable");
    assert!(elf.len() >= 52, "complete ELF32 header");
    assert_eq!(&elf[..7], b"\x7fELF\x01\x01\x01", "ELF32, little-endian");
    let word = |at| u16::from_le_bytes([elf[at], elf[at + 1]]);
    assert_eq!(word(16), 2, "ET_EXEC, not a wrapper script");
    assert_eq!(word(18), 40, "EM_ARM, not AArch64");
    assert_eq!(elf[39], 5, "ARM EABI version 5");
    let phoff = u32::from_le_bytes(elf[28..32].try_into().unwrap()) as usize;
    for index in 0..usize::from(word(44)) {
        let at = phoff + index * usize::from(word(42));
        let kind = u32::from_le_bytes(elf[at..at + 4].try_into().unwrap());
        assert_ne!(kind, 3, "no PT_INTERP: the kernel executes ARM32 directly");
    }
    let direct = work.path("arm32-direct");
    let mut child = match Command::new(&helper).arg(&direct).spawn() {
        Ok(child) => child,
        Err(error) if error.raw_os_error() == Some(libc::ENOEXEC) => {
            harness::skip_or_fail(
                "CPU/kernel cannot directly execute the ARM32 EABI positive control",
            );
            return None;
        }
        Err(error) => panic!("exec the ARM32 positive control: {error}"),
    };
    let mut status = None;
    let finished = common::within(Duration::from_secs(20), || {
        status = child.try_wait().expect("wait for ARM32 positive control");
        status.is_some()
    });
    if !finished {
        let _ = child.kill();
        let _ = child.wait();
        panic!("ARM32 positive control exceeded its 20-second watchdog");
    }
    assert!(
        status.unwrap().success(),
        "ARM32 syscall positive control failed: {status:?}"
    );
    assert_eq!(
        std::fs::read(&direct).expect("direct ARM32 sentinel"),
        b"arm32\n"
    );
    eprintln!("ARM32 ELF32 EABI direct execution created the exact sentinel");
    let created = work.path("by-arm32");
    let native = work.path("native");
    Some(ForeignTarget {
        argv: vec![
            work.helper_s(),
            "foreign-arm32".into(),
            helper.to_string_lossy().into_owned(),
            created.clone(),
            native.clone(),
        ],
        created,
        native,
    })
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn foreign_target(_: &Work) -> Option<ForeignTarget> {
    harness::skip_or_fail("the foreign-ABI fixtures support only x86_64 and aarch64");
    None
}

#[cfg(target_arch = "x86_64")]
fn foreign_results(work: &Work, reports: &[Report], observed: &Observed) -> u64 {
    let i386_open = Report::find(reports, "i386_open");
    assert_eq!(i386_open.errno, 0, "the i386 open ran: {i386_open:?}");
    let x32_open = Report::find(reports, "x32_openat");
    assert_eq!(
        Report::find(reports, "i386_no_such_call").errno,
        libc::ENOSYS
    );
    assert!(
        !observed.primaries().contains(&work.path("by-x32")),
        "a foreign x32 call is never decoded from the native table"
    );
    [i386_open, x32_open]
        .iter()
        .filter(|r| r.errno != libc::ENOSYS)
        .count() as u64
}

#[cfg(target_arch = "aarch64")]
fn foreign_results(work: &Work, reports: &[Report], observed: &Observed) -> u64 {
    assert_eq!(Report::find(reports, "arm32_exit").raw, 0);
    assert_eq!(
        std::fs::read(work.path("by-arm32")).expect("traced ARM32 sentinel"),
        b"arm32\n"
    );
    assert_eq!(
        observed.summary.foreign_rejected, 1,
        "only the nonexistent ARM syscall is ENOSYS"
    );
    assert_eq!(
        observed.summary.loss.foreign_abi, 3,
        "ARM open/write/close each returned once"
    );
    // A user-mode binfmt emulator would make native calls and cannot satisfy
    // this exact foreign-ABI account, even if its direct sentinel succeeded.
    3
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn foreign_results(_: &Work, _: &[Report], _: &Observed) -> u64 {
    unreachable!("unsupported ABI was refused before launching")
}

impl Observed {
    /// The primary path of every result.
    fn primaries(&self) -> Vec<String> {
        self.syscalls().into_iter().map(primary).collect()
    }

    /// Gaps whose reason has this name. Matched by the name the receipt
    /// carries, which is what a consumer sees.
    fn gaps_named(&self, name: &str) -> Vec<(OpSet, Option<u64>)> {
        self.gaps()
            .into_iter()
            .filter(|(reason, _, _)| reason.as_str() == name)
            .map(|(_, ops, count)| (ops, count))
            .collect()
    }

    /// Every event but the forks, one per line.
    fn describe(&self) -> String {
        self.events
            .iter()
            .filter(|e| !matches!(e, TracerEvent::Fork { .. }))
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    }
}

/// Run `argv` under the observer's filter only, the `none` shape.
fn observe(work: &Work, argv: &[&str]) -> (Vec<Report>, Observed) {
    let mut run = launch(work, argv);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    (reports, collect(tracer, Duration::from_secs(60)))
}

// ===========================================================================
// D1: a child's own seccomp filter can take calls away from the observer
// ===========================================================================

/// D1, the listener. A child that installs its own filter with a
/// notification listener and answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE` runs
/// a closed-set call with no ptrace stop: `USER_NOTIF` outranks the
/// narrowing filter's `TRACE`. The observer cannot see that call, so it must
/// say so, for every class, from the moment the listener exists.
#[test]
fn j4_d1_a_child_notification_listener_is_a_gap_in_every_class() {
    let _serial = serial();
    let Some(work) = setup("d1-listener") else {
        return;
    };
    let helper = work.helper_s();
    let hidden = work.path("hidden");
    let seen = work.path("seen");
    let (reports, observed) = observe(&work, &[&helper, "listener", &hidden, &seen]);

    let listener = Report::find(&reports, "listener");
    assert!(
        listener.raw >= 0,
        "the listener was installed: {listener:?}"
    );
    let open = Report::find(&reports, "hidden_open");
    assert_eq!(open.errno, 0, "the continued openat ran: {open:?}");
    assert!(
        Path::new(&hidden).exists(),
        "and it created its file, with no trace stop for the observer"
    );
    assert!(
        !observed.primaries().iter().any(|p| p == &hidden),
        "the continued call is invisible to ptrace:\n  {}",
        observed.describe()
    );
    assert!(
        observed.primaries().iter().any(|p| p == &seen),
        "a call the listener does not take is still observed:\n  {}",
        observed.describe()
    );
    let gaps = observed.gaps_named("child_notification_listener");
    assert_eq!(
        gaps.len(),
        1,
        "a child's notification listener must be a named gap, not active coverage:\n  {}",
        observed.describe()
    );
    assert_eq!(
        gaps[0].0,
        OpSet::ALL,
        "any closed-set call may be continued"
    );
    assert_eq!(gaps[0].1, None, "how many calls it hid is not known");
}

/// D1, the named exclusion (integrator decision S3). A listener-less filter
/// of the child's own that fails a closed-set call (`SECCOMP_RET_ERRNO`
/// outranks `TRACE`) takes that call away before the observer's stop, but
/// the refused call had no effect. So its result is not observed and is not
/// a gap either: "a result the child's own filter refuses before the
/// observer's stop is not observed; it had no effect". (Passes on the base as
/// well: it pins the exclusion, so an inner Landlock/seccomp sandbox under
/// strict evidence is not stopped for it.)
#[test]
fn j4_d1_exclusion_a_filter_that_refuses_a_call_is_not_a_gap() {
    let _serial = serial();
    let Some(work) = setup("d1-errno") else {
        return;
    };
    refusing_filter_case(&work, "seccomp");
}

/// D1, the same exclusion through `prctl(PR_SET_SECCOMP)`, which cannot ask
/// for a listener at all.
#[test]
fn j4_d1_exclusion_holds_for_a_filter_installed_through_prctl() {
    let _serial = serial();
    let Some(work) = setup("d1-prctl") else {
        return;
    };
    refusing_filter_case(&work, "prctl");
}

fn refusing_filter_case(work: &Work, method: &str) {
    let helper = work.helper_s();
    let denied = work.path("denied");
    let seen = work.path("seen");
    let (reports, observed) = observe(work, &[&helper, "errno-filter", method, &denied, &seen]);

    assert_eq!(Report::find(&reports, "install").errno, 0, "{reports:?}");
    let mkdir = Report::find(&reports, "preempted_mkdir");
    assert_eq!(mkdir.errno, libc::EPERM, "the child's filter failed mkdir");
    assert!(!Path::new(&denied).exists(), "and it had no effect");
    assert_eq!(
        observed.of_op(ClosedOp::Mkdir).len(),
        0,
        "the refused call is not observed:\n  {}",
        observed.describe()
    );
    assert!(observed.primaries().iter().any(|p| p == &seen));
    let gaps: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| matches!(e, TracerEvent::Gap { .. }))
        .collect();
    assert!(
        gaps.is_empty(),
        "a refusal with no effect is the named exclusion, not a gap: {gaps:?}"
    );
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// D1, the extra stop. A child's own filter returning `SECCOMP_RET_TRACE`
/// reaches this tracer as a stop the narrowing filter did not ask for. On a
/// number outside the closed set it is continued untouched — never decoded,
/// never counted as loss, never labelled as a filter that is not the
/// observer's — and on a closed-set number it is the one stop the call has,
/// reported once.
#[test]
fn j4_d1_a_child_trace_request_is_continued_not_mislabelled() {
    let _serial = serial();
    let Some(work) = setup("d1-trace") else {
        return;
    };
    let helper = work.helper_s();
    let made = work.path("made");
    let (reports, observed) = observe(&work, &[&helper, "trace-request", &made]);

    assert_eq!(Report::find(&reports, "install").errno, 0, "{reports:?}");
    let getpid = Report::find(&reports, "getpid");
    assert!(getpid.raw > 0, "getpid ran after its stop: {getpid:?}");
    assert_eq!(Report::find(&reports, "mkdir").errno, 0);
    let gaps: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| matches!(e, TracerEvent::Gap { .. }))
        .collect();
    assert!(
        gaps.is_empty(),
        "a stop the child's own filter asked for is not a loss:\n  {}",
        observed.describe()
    );
    assert_eq!(
        observed.of_op(ClosedOp::Mkdir).len(),
        1,
        "the closed-set call it also traced is reported once:\n  {}",
        observed.describe()
    );
    assert!(observed.primaries().iter().any(|p| p == &made));
    assert_eq!(
        observed.summary.loss.total(),
        0,
        "{:?}",
        observed.summary.loss
    );
}

/// D1, the contained profiles: `tool` and `build` refuse a notification
/// listener outright (`EPERM`), whatever the high word of the argument, and
/// still let the child stack a plain filter.
#[test]
fn j4_d1_the_tool_baseline_refuses_a_notification_listener() {
    let _serial = serial();
    let Some(work) = setup("d1-tool") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch_tool(&work, &[&helper, "tool-listener"]);
    let tracer = attach(run.pid, TracerConfig::default());
    run.release();
    let reports = run.lines();
    let observed = collect(tracer, Duration::from_secs(60));

    let listener = Report::find(&reports, "new_listener");
    assert_eq!(
        listener.errno,
        libc::EPERM,
        "the tool baseline must refuse a notification listener: {listener:?}"
    );
    assert_eq!(
        Report::find(&reports, "new_listener_high_word").errno,
        libc::EPERM
    );
    assert_eq!(Report::find(&reports, "plain_filter").errno, 0);
    assert!(
        observed
            .gaps_named("child_notification_listener")
            .is_empty(),
        "a refused listener hides nothing"
    );
}

// ===========================================================================
// D2: a call under another ABI in `none`
// ===========================================================================

/// D2. Without a containment baseline nothing refuses a compat ABI,
/// so the narrowing filter must stop on them, and the observer — which
/// decodes only the native table — must record each one it cannot attribute
/// as a gap in every class, labelled foreign, never as a native result. A
/// call the kernel refused as nonexistent (`ENOSYS`, which is what x32 gets
/// on a kernel built without it) had no effect and is not a loss.
#[test]
fn j4_d2_a_foreign_abi_call_without_a_baseline_is_a_gap() {
    let _serial = serial();
    if !foreign_abis() {
        return;
    }
    let Some(work) = setup("d2-foreign") else {
        return;
    };
    let Some(target) = foreign_target(&work) else {
        return;
    };
    let argv: Vec<_> = target.argv.iter().map(String::as_str).collect();
    let (reports, observed) = observe(&work, &argv);
    assert!(
        Path::new(&target.created).exists(),
        "the foreign call created its file"
    );
    let expected = foreign_results(&work, &reports, &observed);
    assert_eq!(Report::find(&reports, "native_open").errno, 0);

    let named = observed.primaries();
    assert!(
        named.iter().any(|p| p == &target.native),
        "the native call is seen"
    );
    assert!(
        !named.iter().any(|p| p == &target.created),
        "a foreign call is never decoded from the native table: {named:?}"
    );
    let gaps = observed.gaps_named("foreign_abi");
    assert!(
        !gaps.is_empty(),
        "a foreign-ABI call in `none` must be a gap, not silence:\n  {}",
        observed.describe()
    );
    for (ops, _) in &gaps {
        assert_eq!(*ops, OpSet::ALL, "a call nothing decoded may be any class");
    }
    let counted: u64 = gaps.iter().filter_map(|(_, count)| *count).sum();
    assert_eq!(
        counted,
        expected,
        "one per foreign call that returned something other than ENOSYS\n  {}",
        observed.describe()
    );
}

// ===========================================================================
// D6: critical facts behind a full lifecycle backlog
// ===========================================================================

/// D6. The outbox bounds lifecycle facts at a count. Checked before the
/// exemption for critical facts, that bound drops a target's `Exit` and a
/// `Gap` once the backlog is full. The budget is filled first here
/// — twenty thousand fork facts nobody reads, with the byte budget raised so
/// the count bound is the one reached — then the fixture causes a gap and
/// exits. Both must reach the consumer, the gap ahead of the exit.
#[test]
fn j4_d6_critical_facts_survive_a_full_lifecycle_backlog() {
    /// How long the observer may take to reap the fixture with twenty
    /// thousand facts ahead of its exit; past it, the account is read as it
    /// stands.
    const REAP_BOUND: Duration = Duration::from_secs(120);
    let _serial = serial();
    let Some(work) = setup("d6-backlog") else {
        return;
    };
    let helper = work.helper_s();
    let mut run = launch(&work, &[&helper, "forks-then-trace", "20000"]);
    let target = run.pid;
    let tracer = attach(
        run.pid,
        TracerConfig {
            queue_bytes_max: 64 * 1024 * 1024,
            ..TracerConfig::default()
        },
    );
    run.release();
    // Nothing is read until the observer has reaped the fixture, so every
    // fact, the exit included, waits in the observer's own buffer. Its
    // stdout closes before its death is reported, hence the reap and not EOF.
    let reports = run.lines();
    let _ = common::within(REAP_BOUND, || {
        !Path::new(&format!("/proc/{target}")).exists()
    });
    std::thread::sleep(Duration::from_millis(500));
    let observed = collect(tracer, Duration::from_secs(300));
    println!(
        "d6: forked={} lifecycle_dropped={} emitted={} gaps={}",
        Report::find(&reports, "forked").raw,
        observed.summary.loss.lifecycle_dropped,
        observed.summary.emitted,
        observed.summary.gaps
    );

    assert!(Report::find(&reports, "forked").raw >= 20_000 - 10);
    assert_eq!(Report::find(&reports, "install").errno, 0);
    assert!(
        observed.summary.loss.lifecycle_dropped > 0,
        "the lifecycle budget must be full before the critical facts: {:?}",
        observed.summary.loss
    );
    let exit = observed.events.iter().position(|e| {
        matches!(e, TracerEvent::Exit { pid, status, .. }
            if *pid == target && libc::WIFEXITED(*status) && libc::WEXITSTATUS(*status) == 0)
    });
    let gap = observed.events.iter().position(|e| {
        matches!(e, TracerEvent::Gap { reason, .. } if *reason == GapReason::UnexpectedTraceStop)
    });
    let dropped_facts: Vec<&TracerEvent> = observed
        .events
        .iter()
        .filter(|e| {
            matches!(e, TracerEvent::Gap { reason, ops, .. }
                if *reason == GapReason::LifecycleDropped && !ops.is_empty())
        })
        .collect();
    assert!(
        exit.is_some(),
        "the target's exit must survive a full lifecycle backlog; dropped: {dropped_facts:?}"
    );
    assert!(
        gap.is_some(),
        "and so must a gap; dropped: {dropped_facts:?}"
    );
    assert!(gap < exit, "the gap is delivered ahead of what followed it");
    assert!(
        dropped_facts.is_empty(),
        "only bookkeeping facts may be dropped: {dropped_facts:?}"
    );
    assert!(matches!(
        observed.events.last(),
        Some(TracerEvent::Finished)
    ));
}

// ===========================================================================
// The same two defects, end to end, in a `none` receipt
// ===========================================================================

fn none_run(work: &Work, evidence: &str, argv: &[&str]) -> Run {
    let workspace = work.dir().join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace");
    Jail::new()
        .expect("a private harness")
        .arg("run")
        .arg("--profile")
        .arg("none")
        .arg("--evidence")
        .arg(evidence)
        .arg("--workspace")
        .arg(&workspace)
        .trace()
        .control()
        .target(argv.iter().map(OsString::from))
        .run()
        .expect("the jail runs")
}

fn gap_reasons(receipt: &Value) -> Vec<String> {
    receipt["observer"]["gaps"]
        .as_array()
        .map(|gaps| {
            gaps.iter()
                .filter_map(|gap| gap["reason"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// D1 in a receipt: a `none` child with its own notification listener. The
/// receipt must not read `active`, and strict evidence stops the attempt.
#[test]
fn j4_d1_none_a_child_listener_degrades_the_receipt_and_strict_stops() {
    let _serial = serial();
    if !common::delegated_leaf() {
        return;
    }
    let Some(work) = setup("d1-none") else {
        return;
    };
    let helper = work.helper_s();
    let hidden = work.path("hidden");
    let seen = work.path("seen");
    let run = none_run(&work, "strict", &[&helper, "listener", &hidden, &seen]);
    let receipt = common::settled(&run);
    let reasons = gap_reasons(&receipt);
    assert!(
        reasons.iter().any(|r| r == "child_notification_listener"),
        "the receipt must name the listener gap: {:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
        assert_eq!(entry["observed_count"], Value::Null, "{class}");
    }
    assert_eq!(
        receipt["outcome"]["cause"], "evidence_loss",
        "strict evidence stops the attempt: {:#}",
        receipt["outcome"]
    );
}

/// D2 in a receipt: a `none` child making compat calls, best-effort so the
/// run completes. Every audit class is degraded and says why.
#[test]
fn j4_d2_none_a_foreign_abi_call_degrades_the_receipt() {
    let _serial = serial();
    if !foreign_abis() || !common::delegated_leaf() {
        return;
    }
    let Some(work) = setup("d2-none") else {
        return;
    };
    let Some(target) = foreign_target(&work) else {
        return;
    };
    let argv: Vec<_> = target.argv.iter().map(String::as_str).collect();
    let run = none_run(&work, "best-effort", &argv);
    let receipt = common::settled(&run);
    assert!(Path::new(&target.created).exists(), "the foreign call ran");
    #[cfg(target_arch = "aarch64")]
    assert_eq!(
        std::fs::read(&target.created).expect("jailed ARM32 sentinel"),
        b"arm32\n"
    );
    // Best-effort: the loss is an error of the run, not a stop of the child.
    assert_eq!(
        receipt["outcome"]["kind"], "exited",
        "{:#}",
        receipt["outcome"]
    );
    assert_eq!(receipt["outcome"]["code"], 0, "{:#}", receipt["outcome"]);
    assert!(
        gap_reasons(&receipt).iter().any(|r| r == "foreign_abi"),
        "the receipt must name the foreign-ABI gap: {:#}",
        receipt["coverage"]
    );
    for class in ["exec", "fs.write", "fs.deny", "net"] {
        let entry = &receipt["coverage"][class];
        assert_eq!(entry["status"], "degraded", "{class}: {entry:#}");
    }
}
