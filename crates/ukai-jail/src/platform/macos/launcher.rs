//! The macOS launcher: `ukai-jail __launch-macos`, the final boundary's
//! inside process (jail-macos.md §4.3 step 4, jail-v1 §8.3).
//!
//! `sandbox-exec` applies the profile and execs this mode; it runs **inside**
//! the profile. Its argv grammar mirrors the Linux launcher's but is
//! macOS-shaped:
//!
//! ```text
//! ukai-jail __launch-macos --release-fd N --error-fd M
//!                          [--terminal-slave S] [--sigmask HEX] -- ARGV...
//! ```
//!
//! # The inheritance contract for R and E
//!
//! The guardian received the launcher's ends of R and E from the supervisor
//! and passed them through `posix_spawn` to `sandbox-exec` with
//! `posix_spawn_file_actions_addinherit_np`, which clears close-on-exec on
//! the child's copy, so they survive `sandbox-exec`'s exec (§4.3, step 4:
//! "the launcher's ends of R and E, which must survive `sandbox-exec`'s exec
//! until the launcher marks them"). This launcher therefore holds them, and
//! marks **its own copies** close-on-exec at its start — the one place the
//! marks belong, because the target must inherit neither pipe.
//!
//! # The terminal
//!
//! `setpgid`/`tcsetpgrp` are **not** here: in terminal mode the relay's pty
//! slave arrives as the launch block's stdio (the child's standard
//! descriptors), and the guardian's spawn starts a new session
//! (`POSIX_SPAWN_SETSID`), so the slave is not yet any session's controlling
//! terminal. This launcher takes it with `TIOCSCTTY` and then marks it
//! close-on-exec. A failure is reported as the exec's, with the Linux
//! launcher's `DETAIL_TERMINAL` code: nothing was executed.
//!
//! # The blocked report
//!
//! The Linux launcher's error pipe carries `errno` as one little-endian
//! `u32`, then an optional detail `u32` (see
//! [`crate::platform::linux::launch::decode_exec_failure`]). `blocked` is not
//! in that format — an errno of zero is no errno — so it is the one 8-byte
//! report `errno = 0, detail = 0`, written in one `write`. Every real report
//! carries a nonzero errno, so the decoding supervisor can tell them apart
//! by the first word.
//!
//! One report is not an errno at all: when the bootstrap strip's Mach trap
//! fails, the first word is its `kern_return_t` and the detail is
//! [`DETAIL_BOOTSTRAP_STRIP`], so the supervisor names the Mach result
//! (`bootstrap_strip:KERN_…`) instead of reading it as whatever errno shares
//! its number (`KERN_NO_ACCESS` is 8, `ENOEXEC`'s number).
//!
//! # Discipline
//!
//! Like the Linux launcher: everything that allocates happens before the
//! blocked report; after it the launcher only calls `read`, `write`,
//! `sigprocmask`, `signal`, `close`, `execve` and `_exit`, plus the one
//! scalar Mach trap of [`strip_bootstrap_port`] immediately before the
//! exec (§4.7 class 2 — see that function).

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt as _;

/// Exit codes, mirroring the Linux launcher's conventions.
pub const EXIT_NO_RELEASE: i32 = 124;
pub const EXIT_USAGE: i32 = 125;
pub const EXIT_INTERNAL: i32 = 126;
pub const EXIT_EXEC_FAILED: i32 = 127;

/// The launcher's detail code for an `ENOENT` from a file that exists: what
/// is missing is the interpreter its `#!` line names. The Linux launcher's
/// value, so the supervisor's mapping is one table.
pub const DETAIL_INTERPRETER_MISSING: u32 = 1;
/// The launcher's detail code for a controlling terminal it could not take.
/// The Linux launcher's value.
pub const DETAIL_TERMINAL: u32 = 3;
/// macOS only: the bootstrap strip's `task_set_special_port` failed, and the
/// report's first word is that call's `kern_return_t`, not an errno. Nothing
/// was executed. Unused by the Linux launcher (its codes are 1–3).
pub const DETAIL_BOOTSTRAP_STRIP: u32 = 4;

/// A failed target exec as the error pipe reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecFailure {
    /// The kernel's errno for the exec.
    pub errno: i32,
    /// The file named exists, and `errno` is `ENOENT`: its interpreter is
    /// what was not found (X04).
    pub interpreter_missing: bool,
    /// The controlling terminal could not be taken; nothing was executed.
    pub terminal: bool,
    /// The bootstrap strip failed: `errno` holds a Mach `kern_return_t`,
    /// not an errno, and nothing was executed.
    pub bootstrap_strip: bool,
}

/// The errno's name, as the receipts spell it. The common exec errors are
/// named; anything else is `unknown` rather than a guess.
#[must_use]
pub fn errno_name(errno: i32) -> &'static str {
    match errno {
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::ENOEXEC => "ENOEXEC",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ESTALE => "ESTALE",
        libc::ETXTBSY => "ETXTBSY",
        libc::ENOMEM => "ENOMEM",
        libc::EFAULT => "EFAULT",
        libc::EMFILE => "EMFILE",
        libc::ENOTTY => "ENOTTY",
        libc::EINVAL => "EINVAL",
        _ => "unknown",
    }
}

/// Decode an exec failure report: the errno, then an optional detail code —
/// the Linux launcher's exact byte conventions. `None` for a report that
/// does not decode.
#[must_use]
pub fn decode_exec_failure(bytes: &[u8]) -> Option<ExecFailure> {
    if bytes.len() < 4 {
        return None;
    }
    let errno = i32::from_le_bytes(bytes[..4].try_into().ok()?);
    if errno == 0 {
        return None;
    }
    let detail = bytes
        .get(4..8)
        .and_then(|four| <[u8; 4]>::try_from(four).ok())
        .map(u32::from_le_bytes);
    Some(ExecFailure {
        errno,
        interpreter_missing: errno == libc::ENOENT
            && bytes.len() == 8
            && detail == Some(DETAIL_INTERPRETER_MISSING),
        terminal: bytes.len() == 8 && detail == Some(DETAIL_TERMINAL),
        bootstrap_strip: bytes.len() == 8 && detail == Some(DETAIL_BOOTSTRAP_STRIP),
    })
}

/// The `mach/kern_return.h` name of a Mach result, for the results
/// `task_set_special_port` can return and their neighbours (values from the
/// SDK header); anything else
/// is its number, never a guess.
#[must_use]
pub fn kern_return_name(kr: i32) -> String {
    let name = match kr {
        1 => "KERN_INVALID_ADDRESS",
        2 => "KERN_PROTECTION_FAILURE",
        3 => "KERN_NO_SPACE",
        4 => "KERN_INVALID_ARGUMENT",
        5 => "KERN_FAILURE",
        6 => "KERN_RESOURCE_SHORTAGE",
        7 => "KERN_NOT_RECEIVER",
        8 => "KERN_NO_ACCESS",
        15 => "KERN_INVALID_NAME",
        16 => "KERN_INVALID_TASK",
        17 => "KERN_INVALID_RIGHT",
        18 => "KERN_INVALID_VALUE",
        20 => "KERN_INVALID_CAPABILITY",
        46 => "KERN_NOT_SUPPORTED",
        53 => "KERN_DENIED",
        _ => return format!("kern_return_t({kr})"),
    };
    name.to_owned()
}

/// The errno name and the detail of a failed exec's report, as the
/// supervisor hands them to the run: `("unknown", None)` for a report that
/// does not decode.
#[must_use]
pub fn exec_failure_parts(bytes: &[u8]) -> (String, Option<ExecFailureDetail>) {
    match decode_exec_failure(bytes) {
        Some(failure) if failure.bootstrap_strip => (
            format!("bootstrap_strip:{}", kern_return_name(failure.errno)),
            None,
        ),
        Some(failure) => {
            let detail = if failure.interpreter_missing {
                Some(ExecFailureDetail::InterpreterMissing)
            } else if failure.terminal {
                Some(ExecFailureDetail::TerminalUnavailable)
            } else {
                None
            };
            (errno_name(failure.errno).to_owned(), detail)
        }
        None => ("unknown".to_owned(), None),
    }
}

use crate::platform::ExecFailureDetail;

/// The subcommand name, for diagnostics.
const SUBCOMMAND: &str = "__launch-macos";

/// The blocked report: `errno = 0, detail = 0` (see the module header).
fn blocked_bytes() -> [u8; 8] {
    [0u8; 8]
}

/// Whether the first word of an error-pipe report is the blocked sentinel.
#[must_use]
pub fn is_blocked_report(bytes: &[u8]) -> bool {
    bytes == blocked_bytes()
}

/// One parsed launcher invocation.
struct LaunchArgs {
    release_fd: i32,
    error_fd: i32,
    terminal_slave: Option<i32>,
    sigmask: u64,
    argv: Vec<Vec<u8>>,
}

/// Why the argv grammar refused.
enum Usage {
    Missing(&'static str),
    Bad(String, String),
    NoArgv,
}

impl std::fmt::Debug for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Usage::Missing(what) => write!(f, "missing {what}"),
            Usage::Bad(what, why) => write!(f, "{what}: {why}"),
            Usage::NoArgv => write!(f, "no command after `--`"),
        }
    }
}

/// Parses the grammar above. `Err` is a usage refusal; the process exits 125
/// with one stderr line and nothing else.
fn parse(args: &[OsString]) -> Result<LaunchArgs, Usage> {
    let mut release_fd: Option<i32> = None;
    let mut error_fd: Option<i32> = None;
    let mut terminal_slave: Option<i32> = None;
    let mut sigmask = 0u64;
    let mut rest = args;
    while let Some(flag) = rest.first() {
        let Some(flag) = flag.to_str() else {
            return Err(Usage::Bad("flag".to_owned(), "not UTF-8".to_owned()));
        };
        if flag == "--" {
            rest = &rest[1..];
            break;
        }
        let missing = || {
            Usage::Missing(match flag {
                "--release-fd" => "--release-fd N",
                "--error-fd" => "--error-fd M",
                "--terminal-slave" => "--terminal-slave S",
                _ => "--sigmask HEX",
            })
        };
        let raw: Vec<u8> = match rest.get(1) {
            Some(value) => value.as_bytes().to_vec(),
            None => return Err(missing()),
        };
        match flag {
            "--release-fd" | "--error-fd" | "--terminal-slave" => {
                let value: i32 = std::str::from_utf8(&raw)
                    .ok()
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(|| {
                        Usage::Bad(flag.to_owned(), "not a descriptor number".to_owned())
                    })?;
                match flag {
                    "--release-fd" => release_fd = Some(value),
                    "--error-fd" => error_fd = Some(value),
                    _ => terminal_slave = Some(value),
                }
                rest = &rest[2..];
            }
            "--sigmask" => {
                let text = std::str::from_utf8(&raw)
                    .map_err(|_| Usage::Bad("--sigmask".to_owned(), "not UTF-8".to_owned()))?;
                sigmask = u64::from_str_radix(text.trim_start_matches("0x"), 16)
                    .map_err(|_| Usage::Bad("--sigmask".to_owned(), "not a hex mask".to_owned()))?;
                rest = &rest[2..];
            }
            _ => return Err(Usage::Bad("flag".to_owned(), flag.to_owned())),
        }
    }
    if rest.is_empty() {
        return Err(Usage::NoArgv);
    }
    let Some(release_fd) = release_fd else {
        return Err(Usage::Missing("--release-fd N"));
    };
    let Some(error_fd) = error_fd else {
        return Err(Usage::Missing("--error-fd M"));
    };
    Ok(LaunchArgs {
        release_fd,
        error_fd,
        terminal_slave,
        sigmask,
        argv: rest.iter().map(|part| part.as_bytes().to_vec()).collect(),
    })
}

/// Write all of `bytes` to `fd`. Async-signal-safe: one loop over `write`.
fn write_fully(fd: i32, bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: the buffer is live and only `written` past its start is
        // touched.
        let n = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if n <= 0 {
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            return;
        }
        written += n as usize;
    }
}

/// The thread-local errno, as the Linux launcher reads it.
fn errno() -> i32 {
    // SAFETY: `__error` is libSystem's thread-local errno location.
    unsafe { *libc::__error() }
}

/// A report's bytes: `word` (an errno, or the strip's `kern_return_t`) as one
/// little-endian `u32`, and `detail` beside it when it is not zero (the
/// Linux launcher's exact byte conventions); the second value is how many
/// of the eight bytes to write. No allocation.
fn report_bytes(word: i32, detail: u32) -> ([u8; 8], usize) {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&word.to_le_bytes());
    if detail == 0 {
        return (bytes, 4);
    }
    bytes[4..].copy_from_slice(&detail.to_le_bytes());
    (bytes, 8)
}

/// Write the [`report_bytes`] of `word` and `detail`, then exit with `code`.
fn report_and_exit(fd: i32, word: i32, detail: u32, code: i32) -> ! {
    let (bytes, length) = report_bytes(word, detail);
    write_fully(fd, &bytes[..length]);
    // SAFETY: _exit takes a scalar and never returns.
    unsafe { libc::_exit(code) };
}

/// Whether `path` names an existing object (the X04 distinction: an `ENOENT`
/// from a file that exists names its `#!` interpreter). Async-signal-safe.
fn exists(path: &CString) -> bool {
    // SAFETY: `path` is a live NUL-terminated string; F_OK checks existence.
    unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::F_OK, 0) == 0 }
}

/// The C runtime's `environ`, for `execve` (libc exposes no static on darwin).
fn environ() -> *const *const libc::c_char {
    unsafe extern "C" {
        static environ: *const *const libc::c_char;
    }
    // SAFETY: `environ` is the C runtime's own pointer, valid for the life
    // of the process.
    unsafe { environ }
}

// The Mach surface the bootstrap strip needs: libSystem's task-special-port
// calls and the `bootstrap_port` global the C runtime caches. Nothing here
// allocates; each is one scalar trap or one store.
unsafe extern "C" {
    static mut bootstrap_port: libc::natural_t;
    fn mach_task_self() -> libc::natural_t;
    fn task_set_special_port(
        task: libc::natural_t,
        which: libc::c_int,
        port: libc::natural_t,
    ) -> libc::c_int;
}

/// `TASK_BOOTSTRAP_PORT` (mach/task_special_ports.h): the task special port
/// a child's `bootstrap_port` global is initialized from at `exec`.
const TASK_BOOTSTRAP_PORT: libc::c_int = 4;

/// §4.7 class 2, measured 2026-11-02: SBPL `(version 1)` has no filter for
/// Mach sends to the inherited bootstrap port, and launchd's audit-token
/// sandbox checks do not cover kickstart, so a member holding that port can
/// direct launchd to run an unsandboxed deputy — through `launchctl`
/// (whose exec the profile also denies, for a clean `EPERM`) or through any
/// hand-rolled MIG/XPC client, whose pipe is built from exactly that port
/// (measured; see the K90 direct-client row). The launcher therefore
/// removes the port immediately before the exec: every such client then
/// fails locally, and the target and all its descendants inherit no
/// bootstrap at all (measured: exec'd `launchctl` dies client-side without
/// reaching launchd). Fail closed — without the strip nothing runs.
///
/// Async-signal-safe: one trap on the task's own special port, one store to
/// the cached global, no allocation, no other process touched.
fn strip_bootstrap_port() -> Result<(), libc::c_int> {
    // SAFETY: `mach_task_self` is a trap returning the caller's own task
    // port; setting special port 4 to MACH_PORT_NULL replaces the inherited
    // bootstrap with no port (permitted unprivileged for one's own task,
    // measured).
    let kr = unsafe { task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, 0) };
    if kr != libc::KERN_SUCCESS {
        return Err(kr);
    }
    // The C runtime's cached global must not outlive the port it named.
    // SAFETY: a single word store to libSystem's own global, before any
    // code that could read it runs again.
    unsafe { bootstrap_port = 0 };
    Ok(())
}

/// §4.7 class 2's last step before the exec: `strip` the bootstrap port,
/// or report its Mach result on `error_fd` as the first word with
/// [`DETAIL_BOOTSTRAP_STRIP`] beside it, and exit [`EXIT_INTERNAL`] —
/// nothing runs. Returns only when the strip succeeded. Async-signal-safe
/// when `strip` is.
///
/// The supervisor receives this report after the release, on the same pipe
/// and through the same decoder as a failed target exec
/// ([`exec_failure_parts`] names it `bootstrap_strip:KERN_…`), and the run
/// records it the way it records a failed exec (`exec_error`). It is the
/// launcher's own containment step failing before the target ran; giving it
/// a containment classification instead is a supervisor change (the
/// run-event and attempt mapping), not one this report can make.
fn require_bootstrap_strip(error_fd: i32, strip: impl FnOnce() -> Result<(), libc::c_int>) {
    if let Err(kr) = strip() {
        report_and_exit(error_fd, kr, DETAIL_BOOTSTRAP_STRIP, EXIT_INTERNAL);
    }
}

/// The dispatch entry (`main.rs`'s `__launch-macos` arm). Never returns.
pub fn launch_main(args: &[OsString]) -> ! {
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            crate::diag!("ukai-jail {SUBCOMMAND}: {err}");
            std::process::exit(EXIT_USAGE);
        }
    };
    for (fd, what) in [
        (parsed.release_fd, "--release-fd"),
        (parsed.error_fd, "--error-fd"),
    ] {
        // SAFETY: F_GETFD takes a descriptor number and dereferences nothing.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            crate::diag!("ukai-jail {SUBCOMMAND}: {what} {fd} is not open");
            std::process::exit(EXIT_USAGE);
        }
    }

    // §4.3 step 4: mark this launcher's ends of R and E close-on-exec. The
    // marks survive the exec of the target only because they are set here,
    // after sandbox-exec's exec — see the module header for the inheritance
    // contract that delivered them.
    for fd in [parsed.release_fd, parsed.error_fd] {
        // SAFETY: F_SETFD takes scalars and dereferences nothing.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let errno = errno();
            report_and_exit(parsed.error_fd, errno, 0, EXIT_INTERNAL);
        }
    }

    // Terminal mode (§4.11): the relay's pty slave is this new session's
    // controlling terminal or nothing is. A failure is the exec's, with the
    // Linux launcher's terminal detail: nothing was executed.
    if let Some(slave) = parsed.terminal_slave {
        // SAFETY: the ioctl takes a descriptor number and a scalar flag.
        if unsafe { libc::ioctl(slave, libc::TIOCSCTTY as libc::c_ulong, 0) } < 0 {
            let errno = errno();
            report_and_exit(parsed.error_fd, errno, DETAIL_TERMINAL, EXIT_EXEC_FAILED);
        }
        // SAFETY: F_SETFD takes scalars and dereferences nothing.
        if unsafe { libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let errno = errno();
            report_and_exit(parsed.error_fd, errno, DETAIL_TERMINAL, EXIT_EXEC_FAILED);
        }
    }

    // Build the exec arguments now: after the blocked report, allocation is
    // forbidden. `execve`, never a PATH search (§4.11: program resolution is
    // the supervisor's, before release) and no `fexecve` — macOS has no
    // `fexecve`, so there are no exec pins to recheck here either.
    let argv_c: Vec<CString> = parsed
        .argv
        .iter()
        .map(|part| match CString::new(part.as_slice()) {
            Ok(cstring) => cstring,
            Err(_) => {
                crate::diag!("ukai-jail {SUBCOMMAND}: argument contains NUL");
                std::process::exit(EXIT_USAGE);
            }
        })
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|part| part.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let program = argv_c[0].clone();
    drop(parsed.argv);

    // ---- no allocation past this line ----

    // Report `blocked` on E (§4.3 step 4), then wait on R.
    write_fully(parsed.error_fd, &blocked_bytes());

    let mut byte = [0u8; 1];
    let released = loop {
        // SAFETY: the buffer is one live byte and the length matches.
        let n = unsafe {
            libc::read(
                parsed.release_fd,
                byte.as_mut_ptr().cast::<libc::c_void>(),
                1,
            )
        };
        if n == 1 {
            break true;
        }
        if n == 0 {
            break false;
        }
        if errno() == libc::EINTR {
            continue;
        }
        report_and_exit(parsed.error_fd, errno(), 0, EXIT_INTERNAL);
    };
    if !released {
        // End-of-file on R without a release: the supervisor tore the
        // prepared boundary down. Nothing runs.
        // SAFETY: _exit takes a scalar and never returns.
        unsafe { libc::_exit(EXIT_NO_RELEASE) };
    }

    // SAFETY: closing a descriptor this process owns; the target must not
    // see the release pipe.
    unsafe { libc::close(parsed.release_fd) };

    // The target's signal state (jail-v1 §8.3): the supervisor's mask back,
    // `SIGPIPE` at its default so a closed socket kills as everywhere else.
    // SAFETY: sigprocmask and signal take scalars or plain stack data.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        for bit in 0..64 {
            if parsed.sigmask & (1u64 << bit) != 0 {
                libc::sigaddset(&mut mask, bit as libc::c_int + 1);
            }
        }
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const mask, std::ptr::null_mut());
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    // The last step before the exec (§4.7 class 2): with no bootstrap port
    // there is no route from this member to the launchd control plane, for
    // any client. A refusal here reports as internal and nothing runs; the
    // Mach result travels with its own detail code, never as an errno.
    require_bootstrap_strip(parsed.error_fd, strip_bootstrap_port);

    // SAFETY: `program` and `argv_ptrs` are a NUL-terminated string and a
    // NULL-terminated pointer array, all live for the call, and `environ` is
    // this process's own. execve only returns on failure.
    unsafe { libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), environ()) };
    let errno = errno();
    // X04: the kernel answers ENOENT both for a program that is not there
    // and for one whose `#!` interpreter is not there; a program that exists
    // tells the two apart. No PATH search ran, so there is one candidate.
    let detail = if errno == libc::ENOENT && exists(&program) {
        DETAIL_INTERPRETER_MISSING
    } else {
        0
    };
    report_and_exit(parsed.error_fd, errno, detail, EXIT_EXEC_FAILED);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_bootstrap_port_is_the_special_port_four() {
        // The value mach/task_special_ports.h defines; measured against the
        // running task: task_get_special_port(4) returns the cached
        // `bootstrap_port` global's port. The strip's correctness rests on
        // this identity, so the constant is pinned here.
        assert_eq!(TASK_BOOTSTRAP_PORT, 4);
    }

    #[test]
    fn blocked_is_the_eight_zero_bytes_and_nothing_else_is() {
        assert!(is_blocked_report(&[0u8; 8]));
        assert!(!is_blocked_report(&[0, 0, 0, 0]));
        assert!(!is_blocked_report(&libc::ENOENT.to_le_bytes()));
        // A real exec failure always carries a nonzero errno word.
        let mut report = [0u8; 8];
        report[..4].copy_from_slice(&libc::ENOENT.to_le_bytes());
        report[4..].copy_from_slice(&DETAIL_INTERPRETER_MISSING.to_le_bytes());
        assert!(!is_blocked_report(&report));
    }

    // Review §5: a failed bootstrap strip is a Mach result, not an errno.
    // KERN_NO_ACCESS shares ENOEXEC's number and KERN_PROTECTION_FAILURE
    // ENOENT's; in the errno slot they read as those exec errors.
    #[test]
    fn a_bootstrap_strip_failure_names_its_kern_return_not_an_errno() {
        for (kr, name) in [
            (8, "bootstrap_strip:KERN_NO_ACCESS"),
            (2, "bootstrap_strip:KERN_PROTECTION_FAILURE"),
            (4, "bootstrap_strip:KERN_INVALID_ARGUMENT"),
            (5, "bootstrap_strip:KERN_FAILURE"),
            (12345, "bootstrap_strip:kern_return_t(12345)"),
        ] {
            let (bytes, length) = report_bytes(kr, DETAIL_BOOTSTRAP_STRIP);
            let report = &bytes[..length];
            assert!(!is_blocked_report(report), "fail closed: never `blocked`");
            let failure = decode_exec_failure(report).expect("decodes");
            assert!(failure.bootstrap_strip);
            assert!(!failure.interpreter_missing && !failure.terminal);
            assert_eq!(exec_failure_parts(report), (name.to_owned(), None));
        }
        // The errno slot keeps its meaning for real errnos.
        let (bytes, length) = report_bytes(libc::ENOEXEC, 0);
        assert_eq!(length, 4);
        assert_eq!(
            exec_failure_parts(&bytes[..length]),
            ("ENOEXEC".to_owned(), None)
        );
        let (bytes, length) = report_bytes(libc::ENOENT, DETAIL_INTERPRETER_MISSING);
        assert_eq!(
            exec_failure_parts(&bytes[..length]),
            (
                "ENOENT".to_owned(),
                Some(ExecFailureDetail::InterpreterMissing)
            )
        );
    }

    /// Runs `step` in a forked child that is handed the write end of a
    /// fresh error pipe, as the launcher's E; the child `_exit(0)`s if the
    /// step returns. Returns everything the child wrote and its exit code.
    /// The child calls only async-signal-safe code, as the launcher does.
    fn on_the_error_pipe(step: impl FnOnce(i32)) -> (Vec<u8>, i32) {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid out array for `pipe`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the child runs only `step` (a write and `_exit`) and
        // `_exit`; the parent waits for it below.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: closing the child's copy of the read end.
            unsafe { libc::close(fds[0]) };
            step(fds[1]);
            // SAFETY: _exit takes a scalar and never returns.
            unsafe { libc::_exit(0) };
        }
        // SAFETY: closing the parent's copy of the write end.
        unsafe { libc::close(fds[1]) };
        // SAFETY: the read end is this process's own, owned by the File.
        let mut error = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut error, &mut bytes).unwrap();
        let mut status = 0;
        // SAFETY: waiting for the child forked above, into a live int.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "status {status:#x}");
        (bytes, libc::WEXITSTATUS(status))
    }

    // Review F5 (N16): the report the launcher actually sends when the
    // strip fails — written by the sending path itself, in a child that
    // exits as the launcher would — carries the strip's detail, so the
    // supervisor's decoder names the Mach result rather than the errno that
    // shares its number. A strip that succeeds writes nothing.
    #[test]
    fn a_failed_strip_sends_its_kern_return_with_the_strip_detail_and_exits_internal() {
        for (kr, name) in [
            (8, "bootstrap_strip:KERN_NO_ACCESS"),
            (2, "bootstrap_strip:KERN_PROTECTION_FAILURE"),
            (5, "bootstrap_strip:KERN_FAILURE"),
            (12345, "bootstrap_strip:kern_return_t(12345)"),
        ] {
            let (report, code) = on_the_error_pipe(|fd| require_bootstrap_strip(fd, || Err(kr)));
            assert_eq!(code, EXIT_INTERNAL, "nothing runs after a failed strip");
            assert_eq!(report.len(), 8, "{report:?}");
            assert_eq!(report[4..], DETAIL_BOOTSTRAP_STRIP.to_le_bytes());
            assert!(!is_blocked_report(&report));
            assert_eq!(exec_failure_parts(&report), (name.to_owned(), None));
        }
        let (report, code) = on_the_error_pipe(|fd| require_bootstrap_strip(fd, || Ok(())));
        assert_eq!((report, code), (Vec::new(), 0));
        // The production strip, on the child's own task: it succeeds
        // unprivileged and reports nothing.
        let (report, code) =
            on_the_error_pipe(|fd| require_bootstrap_strip(fd, strip_bootstrap_port));
        assert_eq!((report, code), (Vec::new(), 0));
    }

    #[test]
    fn the_grammar_takes_its_flags_and_stops_at_the_double_dash() {
        let args: Vec<OsString> = [
            "--release-fd",
            "7",
            "--error-fd",
            "8",
            "--sigmask",
            "0",
            "--",
            "/bin/true",
            "-v",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let parsed = parse(&args).expect("parses");
        assert_eq!(parsed.release_fd, 7);
        assert_eq!(parsed.error_fd, 8);
        assert_eq!(parsed.terminal_slave, None);
        assert_eq!(parsed.sigmask, 0);
        assert_eq!(parsed.argv, vec![b"/bin/true".to_vec(), b"-v".to_vec()]);
    }

    #[test]
    fn the_grammar_refuses_the_shapes_that_cannot_run() {
        let no_release: Vec<OsString> = ["--error-fd", "8", "--", "x"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(matches!(parse(&no_release), Err(Usage::Missing(_))));
        let no_argv: Vec<OsString> = ["--release-fd", "7", "--error-fd", "8"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(matches!(parse(&no_argv), Err(Usage::NoArgv)));
        let unknown: Vec<OsString> = ["--wat", "--release-fd", "7", "--error-fd", "8", "--", "x"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(matches!(parse(&unknown), Err(Usage::Bad(w, _)) if w == "flag"));
        let bad_mask: Vec<OsString> = [
            "--release-fd",
            "7",
            "--error-fd",
            "8",
            "--sigmask",
            "zz",
            "--",
            "x",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        assert!(matches!(parse(&bad_mask), Err(Usage::Bad(w, _)) if w == "--sigmask"));
    }

    #[test]
    fn the_terminal_flag_and_a_hex_mask_are_taken() {
        let args: Vec<OsString> = [
            "--release-fd",
            "3",
            "--error-fd",
            "4",
            "--terminal-slave",
            "9",
            "--sigmask",
            "800",
            "--",
            "prog",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let parsed = parse(&args).expect("parses");
        assert_eq!(parsed.terminal_slave, Some(9));
        assert_eq!(parsed.sigmask, 0x800);
    }
}
