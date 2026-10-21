//! `ukai-jail`: run an operator-supplied argv under an explicit policy and
//! record what was applied, what was observed and what remains unknown.
//!
//! The module layout follows jail-v1 §4. Portable code owns CLI parsing,
//! configuration provenance, policy narrowing, profile expansion, capability
//! requirements, lifecycle transitions, redaction, record encoding and resource
//! budgets; [`platform`] owns everything native.

/// Write one diagnostic line to standard error, ignoring a failed write.
///
/// `eprintln!` panics when the write fails, which replaces the exit code the
/// caller is about to return (§6.4) with a panic's 101. Standard error is
/// whatever the operator passed, including a descriptor that rejects writes
/// (an io_uring, which the run then refuses): a diagnostic that cannot be
/// written is dropped, and the exit code stands.
///
/// The rendered line is escaped through
/// [`escape_control`](crate::records::escape_control) (Security 2026-09-27,
/// audit 3 A6): untrusted text reaches diagnostics through messages and
/// interpolated config values, so no raw `ESC`, `BEL`, `CR` or `LF` can
/// address the terminal or forge a second line. The trailing newline is
/// written after the escaped text, so the line stays one line.
pub fn diagnostic(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let line = crate::records::escape_control(&args.to_string());
    let write = || {
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(line.as_bytes());
        let _ = stderr.write_all(b"\n");
    };
    // J14: while an attached command may hold the terminal's foreground, a
    // write from this background process must not be stopped by `TOSTOP`,
    // nor wait without bound on a terminal whose output the command
    // suspended (`TCOOFF`): a line that cannot be written within the bound
    // is dropped rather than holding the supervisor (review F2).
    if crate::terminal::attached() {
        // SAFETY: isatty takes a descriptor number.
        if unsafe { libc::isatty(2) } == 1 {
            let mut bytes = line.into_bytes();
            bytes.push(b'\n');
            crate::terminal::with_sigttou_blocked(|| {
                let _ = crate::terminal::write_bounded(2, &bytes, crate::terminal::RESET_BOUND);
            });
        } else {
            crate::terminal::with_sigttou_blocked(write);
        }
    } else {
        write();
    }
}

/// [`diagnostic`] with `format!` syntax: a non-panicking `eprintln!`.
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {
        $crate::diagnostic(format_args!($($arg)*))
    };
}

pub mod canonical;
pub mod capability;
pub mod cleanup;
pub mod cli;
pub mod commands;
pub mod config;
pub mod credential_store;
pub mod credentials;
pub(crate) mod environment;
pub mod gc;
pub mod journal;
pub mod launch_profile;
pub mod learn;
pub mod lifecycle;
pub mod network;
pub mod observer;
pub mod persistent;
pub mod platform;
pub mod policy;
pub mod profiles;
pub mod program;
pub mod proxy;
pub mod records;
pub mod state;
pub mod summary;
pub mod supervisor;
pub(crate) mod sync;
pub(crate) mod sys;
pub mod terminal;
pub mod trace;
pub(crate) mod vault;
