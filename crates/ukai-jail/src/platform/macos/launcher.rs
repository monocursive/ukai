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
//! # Discipline
//!
//! Like the Linux launcher: everything that allocates happens before the
//! blocked report; after it the launcher only calls `read`, `write`,
//! `sigprocmask`, `signal`, `close`, `execve` and `_exit`.

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
    })
}

/// The errno name and the detail of a failed exec's report, as the
/// supervisor hands them to the run: `("unknown", None)` for a report that
/// does not decode.
#[must_use]
pub fn exec_failure_parts(bytes: &[u8]) -> (String, Option<ExecFailureDetail>) {
    match decode_exec_failure(bytes) {
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

/// Write `errno` as one little-endian `u32`, and `detail` beside it when it
/// is not zero (the Linux launcher's exact byte conventions), then exit with
/// `code`.
fn report_and_exit(fd: i32, errno_value: i32, detail: u32, code: i32) -> ! {
    if detail == 0 {
        write_fully(fd, &errno_value.to_le_bytes());
    } else {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&errno_value.to_le_bytes());
        bytes[4..].copy_from_slice(&detail.to_le_bytes());
        write_fully(fd, &bytes);
    }
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
