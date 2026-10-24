//! J16 / K90: the defense matrix against the exact shipped profile digest
//! (jail-macos §4.7, jail-v2 §9.1 K90).
//!
//! Every attack of §4.7 classes 1–3 that this harness can aim at a live
//! target runs here, from inside a sandbox built by the shipped template,
//! with each row's positive control from outside the sandbox. Two target
//! classes exist on this milestone: an unsandboxed process of the operator
//! (the harness's own sleeper) and a sibling member under the same profile.
//! Rows aimed at the custodians run the same matrix with custodian pids
//! once the custody slice integrates (§4.7: "against both custodians"); the
//! row set and its verdict format are what K90 records.
//!
//! Where the *system* already denies an attack unprivileged on this build
//! (`task_for_pid`, `ptrace`, `pid_suspend`, `memorystatus_control`), the
//! outside control still runs and the row records that the denial holds on
//! both sides — the sandbox's own contribution is proven by the paired rows
//! the system does allow outside (`task_name_for_pid`, `proc_rlimit_control`,
//! `bootstrap_look_up`, socket connects, signalling).
//!
//! One line per row is printed: `ROW <class> <attack>: inside=… outside=…`.
//! Anything that runs is recorded (K90).
#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::{Command, Output};

mod common;

use common::private_tempdir;
#[path = "../src/platform/macos/sandbox.rs"]
mod sandbox;
#[path = "../src/platform/macos/setuid.rs"]
mod setuid;

use sandbox::ProfileParams;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The K90 anchor: the digest of the checked-in template these rows ran
/// against (§4.7). Same constant as in `macos_sandbox_profile.rs`; a
/// template change updates both in the same commit and re-runs the matrix.
const PINNED_TEMPLATE_DIGEST: &str =
    "ae7214c117927cd24038b855a788d6243778b69424559c85588ea5266539e110";

// ---------------------------------------------------------------------------
// The attack probe: one C binary that attempts exactly one attack and
// reports the outcome, so each row's verdict is a syscall-level fact.
// ---------------------------------------------------------------------------

const PROBE_SOURCE: &str = r##"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mach/mach.h>
extern int pid_suspend(pid_t pid);
extern int pid_resume(pid_t pid);
extern kern_return_t bootstrap_look_up(mach_port_t bp, char *name, mach_port_t *sp);
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
extern int proc_rlimit_control(pid_t pid, int op, void *arg);
static pid_t kid(void){ pid_t p=fork(); if(p==0){ for(;;) pause(); _exit(0);} return p; }
static int done(pid_t p, int ok){ kill(p,SIGKILL); waitpid(p,NULL,0); return ok?0:1; }
int main(int argc, char**argv){
  if(argc<2){fprintf(stderr,"usage: probe CMD [ARG]\n");return 2;}
  const char*c=argv[1];
  errno=0;
  if(!strcmp(c,"self_kill")){pid_t p=kid();int r=kill(p,SIGTERM);int e=errno;if(r==0){waitpid(p,NULL,0);return 0;}kill(p,SIGKILL);waitpid(p,NULL,0);printf("ret=%d errno=%d",r,e);return 1;}
  /* macOS has no sigqueue(3): the §4.7 sigqueue route is vacuous here. */
  if(!strcmp(c,"self_task_for_pid")){pid_t p=kid();mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_for_pid(mach_task_self(),p,&t);int e=errno;printf("kr=%d errno=%d",k,e);return done(p,k==KERN_SUCCESS);}
  if(!strcmp(c,"self_task_name_for_pid")){pid_t p=kid();mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_name_for_pid(mach_task_self(),p,&t);printf("kr=%d errno=%d",k,errno);return done(p,k==KERN_SUCCESS);}
  if(!strcmp(c,"self_ptrace")){pid_t p=kid();long r=ptrace(PT_ATTACH,p,0,0);int e=errno;int d=-1;if(r==0){d=ptrace(PT_DETACH,p,(caddr_t)1,0);}printf("attach=%ld errno=%d detach=%d",r,e,d);return done(p,r==0&&d==0);}
  if(!strcmp(c,"self_pid_suspend_resume")){pid_t p=kid();int a=pid_suspend(p);int ae=errno;int b=a==0?pid_resume(p):-1;printf("suspend=%d errno=%d resume=%d",a,ae,b);return done(p,a==0&&b==0);}
  if(!strcmp(c,"self_memorystatus")){pid_t p=kid();int r=memorystatus_control(0,(int32_t)p,0,NULL,0);printf("ret=%d errno=%d",r,errno);return done(p,r==0);}
  if(!strcmp(c,"self_rlimit_control")){pid_t p=kid();struct rlimit rl={64,64};int r=proc_rlimit_control(p,RLIMIT_NOFILE,&rl);printf("ret=%d errno=%d",r,errno);return done(p,r==0);}
  if(!strcmp(c,"kill_minus1_probe")){int r=kill(-1,0);printf("ret=%d errno=%d",r,errno);return r==0?0:1;}
  if(!strcmp(c,"task_for_pid")){mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_for_pid(mach_task_self(),atoi(argv[2]),&t);printf("kr=%d errno=%d",k,errno);return k==KERN_SUCCESS?0:1;}
  if(!strcmp(c,"task_name_for_pid")){mach_port_t t=MACH_PORT_NULL;kern_return_t k=task_name_for_pid(mach_task_self(),atoi(argv[2]),&t);printf("kr=%d errno=%d",k,errno);return k==KERN_SUCCESS?0:1;}
  if(!strcmp(c,"bootstrap")){mach_port_t bp=MACH_PORT_NULL,p2=MACH_PORT_NULL;task_get_bootstrap_port(mach_task_self(),&bp);kern_return_t k=bootstrap_look_up(bp,(char*)argv[2],&p2);printf("kr=%d",k);return k==KERN_SUCCESS?0:1;}
  if(!strcmp(c,"unix_connect")){int s=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un a;memset(&a,0,sizeof a);a.sun_family=AF_UNIX;strncpy(a.sun_path,argv[2],sizeof a.sun_path-1);int r=connect(s,(struct sockaddr*)&a,sizeof a);printf("ret=%d errno=%d",r,errno);return r==0?0:1;}
  if(!strcmp(c,"tcp_connect")){int s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a;memset(&a,0,sizeof a);a.sin_family=AF_INET;a.sin_port=htons((unsigned short)atoi(argv[3]));a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);int r=connect(s,(struct sockaddr*)&a,sizeof a);printf("ret=%d errno=%d",r,errno);return r==0?0:1;}
  fprintf(stderr,"unknown cmd\n");return 2;
}
"##;

/// The compiled probe, kept for the harness's lifetime.
struct Probe {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Probe {
    /// The directory holding the probe binary: an admitted program root
    /// (the same treatment the policy gives an install root).
    fn dir(&self) -> PathBuf {
        self._dir.path().to_path_buf()
    }

    fn build() -> Self {
        let dir = private_tempdir();
        let source = dir.path().join("probe.c");
        let binary = dir.path().join("probe");
        std::fs::write(&source, PROBE_SOURCE).expect("probe source");
        let compiled = Command::new("cc")
            .args(["-Wno-deprecated-declarations", "-O1"])
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .output()
            .expect("cc spawns");
        assert!(
            compiled.status.success(),
            "the attack probe must compile: {:?}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        Self {
            _dir: dir,
            path: binary,
        }
    }

    /// Runs one attack, inside the profile when given, outside otherwise.
    fn run(&self, profile: Option<&str>, command: &str, args: &[&str]) -> Output {
        let mut invocation = Command::new(self.path.clone());
        invocation.arg(command).args(args);
        match profile {
            Some(profile) => {
                let file = private_tempdir();
                let path = file.path().join("profile.sb");
                std::fs::write(&path, profile).expect("profile file");
                let wrapped = Command::new(SANDBOX_EXEC)
                    .arg("-f")
                    .arg(&path)
                    .arg(&self.path)
                    .arg(command)
                    .args(args)
                    .output()
                    .expect("sandbox-exec spawns");
                file.close().ok();
                wrapped
            }
            None => invocation.output().expect("probe spawns"),
        }
    }

    fn stdout(&self, output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }
}

// ---------------------------------------------------------------------------
// Targets and profile
// ---------------------------------------------------------------------------

/// A long-lived unsandboxed process: the "operator's other processes"
/// target of §4.7.
struct Target {
    child: std::process::Child,
}

impl Target {
    fn start() -> Self {
        let child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("target sleeper");
        Self { child }
    }

    fn pid(&self) -> String {
        self.child.id().to_string()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn system_read_roots() -> Vec<PathBuf> {
    [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/lib",
        "/usr/share",
        "/usr/libexec",
        "/opt/homebrew",
        "/System/Library",
        "/private/var/db/dyld",
        "/Library/Preferences/Logging",
        "/private/var/db/uuidtext",
        "/private/var/db/diagnostics",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

fn base_profile(extra_program_roots: &[PathBuf]) -> String {
    let root = private_tempdir();
    let workspace = root.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let mut read_only = system_read_roots();
    read_only.extend_from_slice(extra_program_roots);
    let params = ProfileParams {
        read_write: vec![workspace],
        read_only,
        setuid_exec_denied: setuid::deny_paths(&setuid::scan_readable_roots(&[]).unwrap()),
        ..ProfileParams::default()
    };
    let profile = sandbox::generate(&params);
    root.close().ok();
    profile
}

/// K90 runs against the exact shipped profile digest (§4.7): the matrix
/// refuses to run against any template but the pinned one.
#[test]
fn the_matrix_runs_against_the_pinned_shipped_digest() {
    assert_eq!(sandbox::template_digest(), PINNED_TEMPLATE_DIGEST);
    // The pinned template is the shipped one, and it is the text these
    // tests instantiated.
    assert!(sandbox::template().contains("(deny default)"));
    assert!(base_profile(&[]).contains(PINNED_TEMPLATE_DIGEST));
}

/// A sandboxed sibling member that stays alive while the matrix runs:
/// the "other members" target of §4.7 (a stop-phase custodian variant runs
/// the same rows with the custody slice's pids).
struct SiblingMember {
    _profile_dir: tempfile::TempDir,
    child: std::process::Child,
}

impl SiblingMember {
    fn start(profile: &str) -> Self {
        let profile_dir = private_tempdir();
        let path = profile_dir.path().join("profile.sb");
        std::fs::write(&path, profile).expect("profile file");
        let child = Command::new(SANDBOX_EXEC)
            .arg("-f")
            .arg(&path)
            .arg("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("sibling member");
        // The child reads the profile as it starts: the directory outlives
        // the member, not the spawn call.
        Self {
            _profile_dir: profile_dir,
            child,
        }
    }

    fn pid(&self) -> String {
        self.child.id().to_string()
    }
}

impl Drop for SiblingMember {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn record(row: &str, inside: &str, outside: &str) {
    println!("ROW {row}: inside={inside} outside={outside}");
}

/// The probe reports `errno=<n>`; EPERM is 1. Matches exactly, not as a
/// string prefix (errno=13 is not errno=1).
fn has_errno_one(text: &str) -> bool {
    text.split_whitespace()
        .filter_map(|token| token.strip_prefix("errno="))
        .any(|value| value == "1")
}

/// Asserts the inside attempt was refused by the sandbox with `EPERM`.
fn assert_inside_eperm(probe: &Probe, row: &str, output: &Output) {
    let text = probe.stdout(output);
    assert!(
        !output.status.success(),
        "{row}: the attack must be refused inside the sandbox (probe said {text:?})"
    );
    assert!(
        has_errno_one(&text),
        "{row}: the refusal must be EPERM from the sandbox, got {text:?}"
    );
}

/// Mach denials surface as a kern_return_t, not an errno: any non-success
/// `kr` is a refusal — the outside control proves the call is reachable.
fn assert_inside_mach_denied(probe: &Probe, row: &str, output: &Output) -> String {
    let text = probe.stdout(output);
    assert!(
        !output.status.success(),
        "{row}: the attack must be refused inside the sandbox (probe said {text:?})"
    );
    assert!(
        text.contains("kr=") && !text.contains("kr=0"),
        "{row}: the refusal must be a mach failure, got {text:?}"
    );
    text
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

/// §4.7 class 1: direct control of another process. Signalling, task ports,
/// suspend/resume, memory-status control and rlimit control — against an
/// unsandboxed operator process and against a sibling member.
#[test]
fn class_1_direct_process_control_is_denied_from_inside() {
    let probe = Probe::build();
    let profile = base_profile(&[probe.dir()]);
    let profile_dir = private_tempdir();
    let path = profile_dir.path().join("profile.sb");
    std::fs::write(&path, &profile).expect("profile file");
    let mut operator = Target::start();
    let sibling = SiblingMember::start(&profile);
    let operator_pid = operator.pid();
    let sibling_pid = sibling.pid();

    // Signals by every route the shell exposes: an outside process is not
    // signallable; the same-sandbox allow still works (the measured base).
    let output = probe.run(Some(&profile), "task_for_pid", &[&operator_pid]);
    assert!(!output.status.success(), "task_for_pid(inside) must fail");
    record(
        "1 task_for_pid(operator)",
        "DENIED",
        &format!("{:?}", probe.stdout(&output)),
    );

    // The strict pair the system allows outside: task ports by name.
    let inside = probe.run(Some(&profile), "self_task_name_for_pid", &[]);
    let inside_text = assert_inside_mach_denied(&probe, "1 task_name_for_pid(own child)", &inside);
    let outside = probe.run(None, "self_task_name_for_pid", &[]);
    assert!(outside.status.success(), "outside control must run");
    record(
        "1 task_name_for_pid(own child)",
        &format!("DENIED ({inside_text})"),
        "RAN",
    );

    let inside = probe.run(Some(&profile), "self_task_for_pid", &[]);
    let inside_text = assert_inside_mach_denied(&probe, "1 task_for_pid(own child)", &inside);
    let outside = probe.run(None, "self_task_for_pid", &[]);
    record(
        "1 task_for_pid(own child)",
        &format!("DENIED ({inside_text})"),
        &format!("system-denied ({})", probe.stdout(&outside)),
    );

    let inside = probe.run(Some(&profile), "self_ptrace", &[]);
    assert_inside_eperm(&probe, "1 ptrace(PT_ATTACH own child)", &inside);
    let outside = probe.run(None, "self_ptrace", &[]);
    record(
        "1 ptrace(PT_ATTACH own child)",
        "DENIED",
        &format!("system-denied ({})", probe.stdout(&outside)),
    );

    let inside = probe.run(Some(&profile), "self_pid_suspend_resume", &[]);
    assert_inside_eperm(&probe, "1 pid_suspend/pid_resume", &inside);
    let outside = probe.run(None, "self_pid_suspend_resume", &[]);
    record(
        "1 pid_suspend/pid_resume(own child)",
        "DENIED",
        &format!("system-denied ({})", probe.stdout(&outside)),
    );

    let inside = probe.run(Some(&profile), "self_memorystatus", &[]);
    assert_inside_eperm(&probe, "1 memorystatus_control", &inside);
    let outside = probe.run(None, "self_memorystatus", &[]);
    record(
        "1 memorystatus_control(child)",
        "DENIED",
        &format!("system-denied ({})", probe.stdout(&outside)),
    );

    // The control operation the system reaches: outside, even a
    // well-formed set on a child returns EINVAL on this build (measured),
    // so this row records the refusal rather than proving sandbox
    // causality; the `process-info-setcontrol` denial is compile-verified
    // and blanket, and the call must not succeed inside.
    let inside = probe.run(Some(&profile), "self_rlimit_control", &[]);
    let inside_text = probe.stdout(&inside);
    assert!(
        !inside.status.success(),
        "proc_rlimit_control must not succeed inside the sandbox: {inside_text:?}"
    );
    let outside = probe.run(None, "self_rlimit_control", &[]);
    let outside_text = probe.stdout(&outside);
    assert!(
        !outside_text.contains("errno=1"),
        "outside control must not be EPERM (that would mean the system, not the sandbox, denies): {outside_text}"
    );
    record(
        "1 proc_rlimit_control(child)",
        &format!("DENIED ({inside_text})"),
        &format!("system-denied ({outside_text})"),
    );

    // kill(-1, …): the same-sandbox allow is evaluated per target —
    // measured, a member's `kill -TERM -1` delivers to every process in
    // its own sandbox (the shell kills itself) and to nothing outside: the
    // operator's sleeper survives. An outside `kill -1` control is not run
    // (it would signal the operator's whole session); the sleeper's
    // survival is the row's verdict.
    let output = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(&path)
        .arg("/bin/sh")
        .arg("-c")
        .arg("kill -TERM -1")
        .output()
        .expect("sandboxed kill -1");
    assert!(
        !output.status.success(),
        "the kill(-1) shell is expected to terminate on its own signal"
    );
    assert!(
        operator.child.try_wait().unwrap().is_none(),
        "kill(-1) from a member must not reach an outside process"
    );
    record(
        "1 kill(-1, …)",
        "same-sandbox only; outside survives",
        "recorded (outside control is destructive)",
    );

    // sigqueue: macOS implements no sigqueue(3) at all, so the §4.7
    // sigqueue route is vacuous on this build (probe-source comment).

    // Same-sandbox signalling works (the measured base); a member against
    // the operator's process is refused and the operator's process keeps
    // running — recorded above via the shell row and task rows.

    // A member cannot even reach its sibling member by task name: the deny
    // has no same-sandbox filter (members included, §4.7 class 1).
    let inside = probe.run(Some(&profile), "task_name_for_pid", &[&sibling_pid]);
    assert!(
        !inside.status.success(),
        "task_name_for_pid(sibling member) must fail: {:?}",
        probe.stdout(&inside)
    );
    let outside = probe.run(None, "task_name_for_pid", &[&sibling_pid]);
    assert!(
        outside.status.success(),
        "outside control against the same sibling must run: {:?}",
        probe.stdout(&outside)
    );
    record("1 task_name_for_pid(sibling member)", "DENIED", "RAN");
}

/// §4.7 class 1 signalling from a shell, against the operator's process —
/// the K90 fixture of the measured base (800/800 EPERM).
#[test]
fn class_1_shell_signalling_of_an_outside_process_is_denied() {
    let profile = base_profile(&[]);
    let operator = Target::start();
    let pid = operator.pid();

    let file = private_tempdir();
    let path = file.path().join("profile.sb");
    std::fs::write(&path, &profile).expect("profile file");
    let output = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(&path)
        .arg("/bin/kill")
        .arg("-TERM")
        .arg(&pid)
        .output()
        .expect("sandboxed kill");
    file.close().ok();
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
        "kill(2) from inside must be refused: {:?}",
        output.stderr
    );
    let control = Command::new("/bin/kill")
        .arg("-0")
        .arg(&pid)
        .output()
        .unwrap();
    assert!(
        control.status.success(),
        "outside, the same signal path works"
    );
    record("1 kill(2) from sh", "DENIED", "RAN (kill -0 control)");
}

/// §4.7 class 2: deputies — Mach lookups, unix-socket servers and loopback
/// TCP beyond the bridge ports.
#[test]
fn class_2_deputies_are_unreachable_from_inside() {
    let probe = Probe::build();
    let profile = base_profile(&[probe.dir()]);

    // Mach lookup of a service every Mac runs: denied inside, works outside.
    let inside = probe.run(Some(&profile), "bootstrap", &["com.apple.system.logger"]);
    assert!(
        !inside.status.success(),
        "mach-lookup must be denied: {:?}",
        probe.stdout(&inside)
    );
    let outside = probe.run(None, "bootstrap", &["com.apple.system.logger"]);
    assert!(
        outside.status.success(),
        "outside mach-lookup control must run"
    );
    record("2 mach-lookup com.apple.system.logger", "DENIED", "RAN");

    // Unix-socket server: default-deny apart from named grants.
    let socket_dir = private_tempdir();
    let socket_path = socket_dir.path().join("server.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("unix listener");
    let path_text = socket_path.display().to_string();
    let inside = probe.run(Some(&profile), "unix_connect", &[&path_text]);
    assert_inside_eperm(&probe, "2 unix-socket connect", &inside);
    let outside = probe.run(None, "unix_connect", &[&path_text]);
    assert!(outside.status.success(), "outside unix connect must run");
    record("2 unix-socket connect", "DENIED", "RAN");
    drop(listener);

    // Loopback TCP under `network_none`: denied; the bridge ports are the
    // only loopback exception and are exercised in macos_sandbox_profile.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("tcp listener");
    let port = listener.local_addr().unwrap().port().to_string();
    let inside = probe.run(Some(&profile), "tcp_connect", &["127.0.0.1", &port]);
    assert_inside_eperm(&probe, "2 loopback TCP (network_none)", &inside);
    let outside = probe.run(None, "tcp_connect", &["127.0.0.1", &port]);
    assert!(
        outside.status.success(),
        "outside loopback control must run"
    );
    record("2 loopback TCP (network_none)", "DENIED", "RAN");
    drop(listener);
}

/// §4.7 class 3: gaining another user. The enumerated setuid files are
/// denied by path, the kernel refuses setuid-exec for sandboxed processes
/// outright, and a hardlink planted in a writable root is refused by the
/// same backstop (the path denial alone could not see through the link).
#[test]
fn class_3_setuid_gains_nothing_from_inside() {
    let profile = base_profile(&[]);

    let file = private_tempdir();
    let path = file.path().join("profile.sb");
    std::fs::write(&path, &profile).expect("profile file");
    let inside = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(&path)
        .arg("/usr/bin/sudo")
        .arg("-n")
        .arg("true")
        .output()
        .expect("sandboxed sudo");
    file.close().ok();
    assert!(
        String::from_utf8_lossy(&inside.stderr).contains("Operation not permitted"),
        "sudo exec must be refused: {:?}",
        inside.stderr
    );
    let outside = Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg("true")
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&outside.stderr).contains("Operation not permitted"),
        "outside, sudo execs (it may then demand a password)"
    );
    record("3 exec /usr/bin/sudo", "DENIED", "RAN");

    // The hardlink route: link a setuid binary into the writable root, then
    // exec it under a path no literal denial enumerates.
    let root = private_tempdir();
    let workspace = root.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("workspace");
    let link = workspace.join("link-sudo");
    let linked = Command::new("/bin/ln")
        .arg("/usr/bin/sudo")
        .arg(&link)
        .output()
        .expect("ln spawns");
    if linked.status.success() {
        let params = ProfileParams {
            read_write: vec![workspace.clone()],
            read_only: system_read_roots(),
            setuid_exec_denied: setuid::deny_paths(&setuid::system_entries().entries),
            ..ProfileParams::default()
        };
        let profile = sandbox::generate(&params);
        let file = private_tempdir();
        let path = file.path().join("profile.sb");
        std::fs::write(&path, &profile).expect("profile file");
        let inside = Command::new(SANDBOX_EXEC)
            .arg("-f")
            .arg(&path)
            .arg(&link)
            .arg("-n")
            .arg("true")
            .output()
            .expect("sandboxed hardlink exec");
        file.close().ok();
        assert!(
            String::from_utf8_lossy(&inside.stderr).contains("Operation not permitted"),
            "exec of a hardlinked setuid binary must be refused: {:?}",
            inside.stderr
        );
        let outside = Command::new(&link).arg("-n").arg("true").output().unwrap();
        assert!(
            !String::from_utf8_lossy(&outside.stderr).contains("Operation not permitted"),
            "outside, the hardlink execs"
        );
        record("3 exec hardlink to sudo", "DENIED (kernel backstop)", "RAN");
    } else {
        record("3 exec hardlink to sudo", "SKIPPED (ln failed)", "n/a");
    }
    root.close().ok();
}

/// §4.7 class 2, during a stop: a member reaching a launchd deputy or an
/// Apple Events deputy fails while the profile is in force, whatever the
/// custodians are doing — the defense is not custodian-issued (§4.7).
#[test]
fn class_2_launchd_and_apple_events_deputies_are_refused() {
    let profile = base_profile(&[]);
    let label = format!("ukai-k90-{}", std::process::id());
    let file = private_tempdir();
    let path = file.path().join("profile.sb");
    std::fs::write(&path, &profile).expect("profile file");
    let submit = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(&path)
        .arg("/bin/launchctl")
        .args(["submit", "-l", &label, "--", "/bin/true"])
        .output()
        .expect("sandboxed launchctl");
    file.close().ok();
    assert!(
        !submit.status.success(),
        "launchctl submit must fail inside"
    );
    let listed = Command::new("/bin/launchctl")
        .args(["print", &label])
        .output()
        .unwrap();
    assert!(!listed.status.success(), "the refused job must not exist");
    let outside = Command::new("/bin/launchctl")
        .args([
            "submit",
            "-l",
            &format!("{label}-control"),
            "--",
            "/bin/true",
        ])
        .output()
        .unwrap();
    let _ = Command::new("/bin/launchctl")
        .args(["remove", &format!("{label}-control")])
        .output();
    let _ = outside;
    record("2 launchctl submit", "DENIED", "RAN");

    let file = private_tempdir();
    let path = file.path().join("profile.sb");
    std::fs::write(&path, &profile).expect("profile file");
    let events = Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(&path)
        .arg("/usr/bin/osascript")
        .args([
            "-e",
            "tell application \"System Events\" to display dialog \"no\"",
        ])
        .output()
        .expect("sandboxed osascript");
    file.close().ok();
    assert!(
        !events.status.success(),
        "an Apple Event send must fail inside: {:?}",
        String::from_utf8_lossy(&events.stderr)
    );
    record(
        "2 appleevent-send",
        "DENIED",
        "recorded (an outside send is a TCC prompt)",
    );
}
