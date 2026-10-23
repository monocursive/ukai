//! The host seam: the only place `gc` asks the host anything or changes it
//! (the recorded owner's liveness, and the identity-checked probe, kill and
//! removal of the execution cgroup; on Linux `platform::linux::reconcile`).

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::Path;
use std::time::Duration;

use crate::records::Os;
use crate::supervisor::Context;

/// Who is running `gc`: the platform identity and the current boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HostIdentity {
    /// The OS this build runs on.
    pub os: Os,
    /// The architecture string the platform records in state.
    pub arch: String,
    /// The current boot, where the platform can name one.
    pub boot_id: Option<String>,
}

/// The supervisor birth identity jail state recorded (§7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OwnerRecord {
    /// The pid as recorded: a number, never an address by itself.
    pub pid: u32,
    /// The boot it was recorded in.
    pub boot_id: String,
    /// Linux `/proc/<pid>/stat` field 22, or macOS epoch-second birth time.
    pub start_time_ticks: u64,
}

/// J16 (jail-macos.md §4.8): the target's recorded identity, the parts of
/// its audit token the receipt carries (`process.identity.kind =
/// macos_audit_token`). The kernel validates the pid version inside the
/// token (`proc_find_audit_token`, xnu `kern_proc.c`: pid is `val[5]`, the
/// pid version `val[7]`), so a kill through it is safe after pid reuse and
/// a no-op after a later exec.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TargetToken {
    /// The target's pid (`token.val[5]`).
    pub pid: u32,
    /// The target's pid version (`token.val[7]`).
    pub pidversion: u32,
}

/// The guardian's record (`guardian.json`, `ukai.jail.guardian-record/1`),
/// read tolerantly: absent or corrupt records supply no usable identity.
/// Only a genuinely absent file can support pre-preparation refusal proof
/// (jail-macos.md §4.9). Only the identity and verdict fields are read.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct GuardianRecord {
    /// The guardian's pid, from `own_token` word 5.
    pub pid: Option<u32>,
    /// The guardian's pid version, from `own_token` word 7.
    pub pidversion: Option<u32>,
    /// The boot session the guardian recorded; `None`, or an empty string
    /// (the kernel refused the sysctl), means gc cannot compare boots.
    pub boot_session: Option<String>,
    /// Whether the guardian drained the tree's members.
    pub drained: Option<bool>,
}

impl GuardianRecord {
    /// Whether gc can ask the host anything about this guardian.
    #[must_use]
    pub fn probeable(&self) -> bool {
        self.pid.is_some()
    }
}

/// What the host says about a recorded owner in this boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Liveness {
    /// The pid names the recorded process, and it has not exited.
    Alive,
    /// No process has the pid.
    Gone,
    /// The pid names a process born at another time: the pid was reused.
    Reused,
    /// The recorded process has exited and is not yet reaped.
    Exited,
    /// Liveness could not be read; the reason says why.
    Unknown(String),
}

/// An execution cgroup as its registration names it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LeafRecord {
    /// The leaf's path as created.
    pub path: std::path::PathBuf,
    /// Its device at creation.
    pub device: u64,
    /// Its inode at creation.
    pub inode: u64,
}

/// What the host found at a recorded leaf's path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LeafProbe {
    /// Nothing is there.
    Absent,
    /// A cgroup with another identity is there.
    Replaced,
    /// The registration or what is there cannot be verified; why.
    Unverifiable(String),
    /// The recorded cgroup itself, and whether any process is in it.
    Identified {
        /// `populated` from its `cgroup.events` (recursive).
        populated: bool,
    },
}

/// Why a host change `gc` asked for did not happen: the step that failed,
/// and the OS error, errno included, when there was one. gc's report carries
/// its text ([`fmt::Display`]).
#[derive(Debug)]
pub struct HostFailure {
    step: Cow<'static, str>,
    source: Option<io::Error>,
}

impl HostFailure {
    /// `step` failed for a reason no syscall reported.
    #[must_use]
    pub fn new(step: impl Into<Cow<'static, str>>) -> HostFailure {
        HostFailure {
            step: step.into(),
            source: None,
        }
    }

    /// `step` failed with the OS error `source`.
    #[must_use]
    pub fn os(step: &'static str, source: io::Error) -> HostFailure {
        HostFailure {
            step: Cow::Borrowed(step),
            source: Some(source),
        }
    }
}

impl fmt::Display for HostFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{}: {source}", self.step),
            None => f.write_str(&self.step),
        }
    }
}

impl std::error::Error for HostFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Every host question and every host change `gc` makes.
pub trait Host {
    /// The platform and the current boot.
    fn identity(&self) -> HostIdentity;
    /// Whether the recorded owner (of this boot) is alive.
    fn owner(&self, owner: &OwnerRecord) -> Liveness;
    /// What is at the recorded leaf's path.
    fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe;
    /// Re-identifies the leaf, writes its `cgroup.kill` and waits at most
    /// `budget` for it to empty.
    ///
    /// # Errors
    /// Why the leaf was not identified, killed or seen empty.
    fn terminate_leaf(&self, leaf: &LeafRecord, budget: Duration) -> Result<(), HostFailure>;
    /// Re-identifies the leaf, checks it is empty and removes it (and any
    /// empty child cgroups), spending at most `entries` directory entries.
    ///
    /// # Errors
    /// Why the leaf was not identified, not empty or not removed.
    fn remove_leaf(&self, leaf: &LeafRecord, entries: &mut usize) -> Result<(), HostFailure>;
    /// What is at a leaf jail state registers by name only (a supervisor
    /// that died between the name and the identity, N7). `Identified` means
    /// only a cgroup v2 directory with an execution leaf's name directly
    /// under this user's delegated subtree; nothing recorded proves more.
    fn probe_named_leaf(&self, path: &Path) -> LeafProbe;
    /// Removes a leaf registered by name only, when it is empty (the kernel
    /// refuses to remove a populated cgroup). Never kills. Returns the
    /// identity of what it removed.
    ///
    /// # Errors
    /// Why the leaf was not found, not empty or not removed.
    fn remove_named_leaf(
        &self,
        path: &Path,
        entries: &mut usize,
    ) -> Result<(u64, u64), HostFailure>;
    /// J16 (jail-macos.md §4.9): whether the guardian a custodian record
    /// describes is alive. A custodian is dead when its audit token no
    /// longer matches, or when the boot session differs. The default reads
    /// no custodian identity, which retains the attempt.
    fn guardian(&self, _: &GuardianRecord) -> Liveness {
        Liveness::Unknown("no custodian identity is read here".to_owned())
    }
    /// J16 (jail-macos.md §4.9): sends `SIGKILL` to the receipt's recorded
    /// target, by audit token. Safe after pid reuse (the kernel checks the
    /// pid version in the token). `ESRCH` is an unsuccessful signal: the
    /// target was not found by its recorded token. Signal 0 is never sent:
    /// with `proc_signal_with_audittoken` it is unusable (`EINVAL`). The default
    /// refuses, which keeps everything.
    ///
    /// # Errors
    /// Why the signal was not delivered, including a stale or absent token.
    fn kill_target(&self, _: &TargetToken) -> Result<(), HostFailure> {
        Err(HostFailure::new("no audit-token kill exists here"))
    }
}

/// The host `gc` runs on: the platform's identity, and on Linux the
/// identity-checked mechanisms of `platform::linux::reconcile`.
pub(super) struct NativeHost {
    identity: HostIdentity,
}

impl NativeHost {
    pub(super) fn new(ctx: &Context) -> NativeHost {
        let platform = ctx.platform.state_identity();
        NativeHost {
            identity: HostIdentity {
                os: platform.os,
                arch: platform.arch,
                boot_id: ctx.platform.owner_identity().map(|owner| owner.boot_id),
            },
        }
    }
}

/// J16 (jail-macos.md §4.9): the macOS host. The boot identity is the boot
/// session (`kern.bootsessionuuid`); custodian liveness is a
/// `proc_pidinfo(PROC_PIDTBSDINFO)` read; the §4.9 kill is
/// `proc_signal_with_audittoken` with the receipt's recorded token words.
#[cfg(target_os = "macos")]
mod native {
    use super::{GuardianRecord, HostFailure, Liveness, NativeHost, OwnerRecord, TargetToken};

    /// No cgroup mechanism exists on this platform.
    const NO_MECHANISM: &str = "this platform has no execution cgroup mechanism";

    /// The kernel's `proc_bsdinfo` (sys/proc_info.h), only the fields gc
    /// reads. Field order and padding follow the C layout exactly.
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        rfu_1: u32,
        pbi_comm: [u8; 16],
        pbi_name: [u8; 32],
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: i32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    /// The kernel's `audit_token_t` (mach/message.h).
    #[repr(C)]
    struct AuditToken {
        val: [u32; 8],
    }

    // SAFETY: the signatures match the SDK's libproc declarations
    // (libproc.h, mach/message.h); macOS links them from libSystem.
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
        fn proc_signal_with_audittoken(token: *mut AuditToken, sig: libc::c_int) -> libc::c_int;
        fn sysctlbyname(
            name: *const libc::c_char,
            oldp: *mut libc::c_void,
            oldlenp: *mut libc::size_t,
            newp: *mut libc::c_void,
            newlen: libc::size_t,
        ) -> libc::c_int;
    }

    const PROC_PIDTBSDINFO: libc::c_int = 3;
    /// sys/proc.h: the process is awaiting collection by its parent.
    const SZOMB: u32 = 5;

    /// The current boot session (`kern.bootsessionuuid`), or `None` when the
    /// kernel refuses the sysctl (nothing is ever fabricated in its place).
    #[must_use]
    pub fn boot_session() -> Option<String> {
        let name = b"kern.bootsessionuuid\0";
        let mut buffer = [0u8; 64];
        let mut length = buffer.len();
        // SAFETY: `name` is NUL-terminated and outlives the call; `buffer`
        // and `length` describe writable space sysctlbyname fills.
        let ok = unsafe {
            sysctlbyname(
                name.as_ptr().cast(),
                buffer.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if ok != 0 || length == 0 || length > buffer.len() {
            return None;
        }
        Some(String::from_utf8_lossy(&buffer[..length - 1]).into_owned())
    }

    /// Reads a live pid's birth identity, or why it cannot be read.
    fn bsdinfo(pid: u32) -> Result<ProcBsdInfo, Liveness> {
        let mut info = ProcBsdInfo {
            pbi_flags: 0,
            pbi_status: 0,
            pbi_xstatus: 0,
            pbi_pid: 0,
            pbi_ppid: 0,
            pbi_uid: 0,
            pbi_gid: 0,
            pbi_ruid: 0,
            pbi_rgid: 0,
            pbi_svuid: 0,
            pbi_svgid: 0,
            rfu_1: 0,
            pbi_comm: [0; 16],
            pbi_name: [0; 32],
            pbi_nfiles: 0,
            pbi_pgid: 0,
            pbi_pjobc: 0,
            e_tdev: 0,
            e_tpgid: 0,
            pbi_nice: 0,
            pbi_start_tvsec: 0,
            pbi_start_tvusec: 0,
        };
        // SAFETY: `info` is a valid `proc_bsdinfo`-sized buffer outliving
        // the call; `PROC_PIDTBSDINFO` fills exactly that shape.
        let got = unsafe {
            proc_pidinfo(
                pid as libc::c_int,
                PROC_PIDTBSDINFO,
                0,
                std::ptr::addr_of_mut!(info).cast(),
                std::mem::size_of::<ProcBsdInfo>() as libc::c_int,
            )
        };
        if got == 0 {
            // ESRCH: no process has the pid. Anything else is a read this
            // host cannot establish, and §14.2 keeps what it cannot read.
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ESRCH) => Err(Liveness::Gone),
                _ => Err(Liveness::Unknown(
                    "proc_pidinfo could not read the process".to_owned(),
                )),
            };
        }
        Ok(info)
    }

    /// The shared liveness rule: alive iff the pid names a live process
    /// whose recorded start matches (jail-macos.md §4.9: "a custodian is
    /// dead when its audit token no longer matches, or when the boot
    /// session differs"; the caller compares boots).
    fn liveness(pid: u32, start_time_secs: Option<u64>) -> Liveness {
        match bsdinfo(pid) {
            Err(why) => why,
            Ok(info) if info.pbi_status & SZOMB == SZOMB => Liveness::Exited,
            Ok(info) if start_time_secs.is_some_and(|start| start != info.pbi_start_tvsec) => {
                Liveness::Reused
            }
            Ok(_) => Liveness::Alive,
        }
    }

    impl NativeHost {
        /// Sends `SIGKILL` through the recorded token words. The kernel
        /// re-validates the pid version inside the token
        /// (`proc_find_audit_token`), so a reused pid is `ESRCH`, which is
        /// the no-op the spec calls for.
        ///
        /// Signal 0 is never used here: `psignal_by_audit_token` rejects it
        /// (`EINVAL`), so it cannot serve as a liveness probe.
        pub(super) fn kill_by_token(token: &TargetToken) -> Result<(), HostFailure> {
            let mut audittoken = AuditToken { val: [0; 8] };
            audittoken.val[5] = token.pid;
            audittoken.val[7] = token.pidversion;
            // SAFETY: `audittoken` is a valid `audit_token_t` outliving the
            // call; `proc_signal_with_audittoken` reads it and signals.
            let error = unsafe { proc_signal_with_audittoken(&mut audittoken, libc::SIGKILL) };
            signal_result(error, std::io::Error::last_os_error())
        }
    }

    /// libproc versions may return an errno directly; a syscall-style -1
    /// instead uses errno. Never consult a stale errno for a positive result.
    fn signal_result(rc: libc::c_int, errno: std::io::Error) -> Result<(), HostFailure> {
        if rc == 0 {
            return Ok(());
        }
        let error = if rc > 0 {
            std::io::Error::from_raw_os_error(rc)
        } else {
            errno
        };
        Err(HostFailure::os(
            if error.raw_os_error() == Some(libc::ESRCH) {
                "target not found by its recorded token; no signal delivered and tree end unverified"
            } else {
                "proc_signal_with_audittoken"
            },
            error,
        ))
    }

    impl super::Host for NativeHost {
        fn identity(&self) -> super::HostIdentity {
            let mut identity = self.identity.clone();
            if identity.boot_id.is_none() {
                identity.boot_id = boot_session();
            }
            identity
        }

        fn owner(&self, owner: &OwnerRecord) -> Liveness {
            liveness(owner.pid, Some(owner.start_time_ticks))
        }

        fn guardian(&self, record: &GuardianRecord) -> Liveness {
            let Some(pid) = record.pid else {
                return Liveness::Unknown("the record names no guardian pid".to_owned());
            };
            // The pid version cannot be re-read from user space without the
            // token calls; a pid that was reused reads as alive, which
            // keeps the attempt — the safe side.
            liveness(pid, None)
        }

        fn probe_leaf(&self, _: &super::LeafRecord) -> super::LeafProbe {
            super::LeafProbe::Unverifiable(NO_MECHANISM.to_owned())
        }

        fn terminate_leaf(
            &self,
            _: &super::LeafRecord,
            _: std::time::Duration,
        ) -> Result<(), HostFailure> {
            Err(HostFailure::new(NO_MECHANISM))
        }

        fn remove_leaf(&self, _: &super::LeafRecord, _: &mut usize) -> Result<(), HostFailure> {
            Err(HostFailure::new(NO_MECHANISM))
        }

        fn probe_named_leaf(&self, _: &std::path::Path) -> super::LeafProbe {
            super::LeafProbe::Unverifiable(NO_MECHANISM.to_owned())
        }

        fn remove_named_leaf(
            &self,
            _: &std::path::Path,
            _: &mut usize,
        ) -> Result<(u64, u64), HostFailure> {
            Err(HostFailure::new(NO_MECHANISM))
        }

        fn kill_target(&self, token: &TargetToken) -> Result<(), HostFailure> {
            Self::kill_by_token(token)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn s3_token_signal_handles_direct_errno_and_syscall_errno() {
            for (rc, errno) in [(libc::ESRCH, libc::EPERM), (-1, libc::ESRCH)] {
                let error =
                    signal_result(rc, std::io::Error::from_raw_os_error(errno)).unwrap_err();
                assert!(error.to_string().contains("target not found"), "{error}");
            }
            let denied = signal_result(libc::EPERM, std::io::Error::from_raw_os_error(libc::ESRCH))
                .unwrap_err();
            assert!(!denied.to_string().contains("target not found"));
            assert!(signal_result(0, std::io::Error::from_raw_os_error(libc::ESRCH)).is_ok());
        }
    }
}

/// J16 (jail-macos.md §4.3, §4.9): this host's boot session
/// (`kern.bootsessionuuid`), the boot identity macOS records and compares.
/// `None` when the kernel refuses the sysctl; nothing is fabricated.
#[cfg(target_os = "macos")]
#[must_use]
pub fn boot_session() -> Option<String> {
    native::boot_session()
}

/// On Linux: the identity-checked mechanisms of `platform::linux::reconcile`.
#[cfg(target_os = "linux")]
impl Host for NativeHost {
    fn identity(&self) -> HostIdentity {
        self.identity.clone()
    }

    fn owner(&self, owner: &OwnerRecord) -> Liveness {
        crate::platform::linux::reconcile::owner_liveness(owner)
    }

    fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe {
        crate::platform::linux::reconcile::probe_leaf(leaf)
    }

    fn terminate_leaf(&self, leaf: &LeafRecord, budget: Duration) -> Result<(), HostFailure> {
        crate::platform::linux::reconcile::terminate_leaf(leaf, budget)
    }

    fn remove_leaf(&self, leaf: &LeafRecord, entries: &mut usize) -> Result<(), HostFailure> {
        crate::platform::linux::reconcile::remove_leaf(leaf, entries)
    }

    fn probe_named_leaf(&self, path: &Path) -> LeafProbe {
        crate::platform::linux::reconcile::probe_named_leaf(path)
    }

    fn remove_named_leaf(
        &self,
        path: &Path,
        entries: &mut usize,
    ) -> Result<(u64, u64), HostFailure> {
        crate::platform::linux::reconcile::remove_named_leaf(path, entries)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const NO_MECHANISM: &str = "this platform has no execution cgroup mechanism";

/// Anywhere else: no process birth identity and no execution cgroup, so
/// nothing is verified and nothing is acted on.
#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
impl Host for NativeHost {
    fn identity(&self) -> HostIdentity {
        self.identity.clone()
    }

    fn owner(&self, _: &OwnerRecord) -> Liveness {
        Liveness::Unknown("this platform reads no process birth identity".to_owned())
    }

    fn probe_leaf(&self, _: &LeafRecord) -> LeafProbe {
        LeafProbe::Unverifiable(NO_MECHANISM.to_owned())
    }

    fn terminate_leaf(&self, _: &LeafRecord, _: Duration) -> Result<(), HostFailure> {
        Err(HostFailure::new(NO_MECHANISM))
    }

    fn remove_leaf(&self, _: &LeafRecord, _: &mut usize) -> Result<(), HostFailure> {
        Err(HostFailure::new(NO_MECHANISM))
    }

    fn probe_named_leaf(&self, _: &Path) -> LeafProbe {
        LeafProbe::Unverifiable(NO_MECHANISM.to_owned())
    }

    fn remove_named_leaf(&self, _: &Path, _: &mut usize) -> Result<(u64, u64), HostFailure> {
        Err(HostFailure::new(NO_MECHANISM))
    }
}
