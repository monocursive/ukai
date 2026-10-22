//! The one `posix_spawn` of `sandbox-exec` (jail-macos §4.3 step 4).
//!
//! The guardian interprets nothing in the launch block: it turns the block
//! into `posix_spawn` arguments and nothing else. The composition is
//! `sandbox-exec -p <profile> -- <launcher argv…>`; the generated SBPL text
//! rides on argv because `sandbox-exec -p` takes the profile there. The
//! supervisor allocated the pty (terminal mode) and passed the slave fd
//! through the block; taking it as controlling terminal with `TIOCSCTTY` is
//! the launcher's job inside the profile — `posix_spawn` cannot do it for
//! the child, and `POSIX_SPAWN_SETSID` (every launcher starts a new
//! session) leaves the child without a controlling terminal to inherit.
//!
//! The signal attributes carry §4.2: `POSIX_SPAWN_SETSIGDEF` restores the
//! terminal signals to their default disposition and `POSIX_SPAWN_SETSIGMASK`
//! restores the supervisor's inherited mask — the guardian's ignored
//! dispositions must not leak into the workload. After the spawn the guardian
//! closes its copies of R, E, the stdio sources and the pty slave, so
//! end-of-file means what it does on Linux (jail-v1 §8.3).

use std::ffi::CString;

use super::launch_block::{FdAction, LaunchBlock};

// The macOS libSystem calls libc does not wrap (edition-2024 declarations).
//
// `posix_spawn_file_actions_addinherit_np` clears close-on-exec on the
// child's copy of `fd` (the launcher's ends of R and E must survive
// `sandbox-exec`'s exec, §4.3).
unsafe extern "C" {
    fn posix_spawn_file_actions_addinherit_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;
    /// `posix_spawn_file_actions_addchdir`: the child's working directory.
    fn posix_spawn_file_actions_addchdir(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

/// `POSIX_SPAWN_SETSID` (sys/spawn.h): the child starts a new session —
/// every launcher does (§4.3 step 2).
const POSIX_SPAWN_SETSID: libc::c_int = 0x0400;

#[derive(Debug)]
pub struct SpawnError(&'static str, String);

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl std::error::Error for SpawnError {}

fn os(step: &'static str) -> SpawnError {
    SpawnError(step, std::io::Error::last_os_error().to_string())
}

/// A `CString` for a spawn argument or environment entry; NUL inside a field
/// is refused, not truncated.
fn cstring(step: &'static str, value: &str) -> Result<CString, SpawnError> {
    CString::new(value.as_bytes()).map_err(|_| SpawnError(step, "embedded NUL".to_owned()))
}

/// Build the full sandbox-exec argv:
/// `[sandbox-exec, -p, <profile>, --] + child_argv`.
pub fn sandbox_exec_argv(block: &LaunchBlock) -> Result<Vec<CString>, SpawnError> {
    let mut argv = Vec::with_capacity(4 + block.child_argv.len());
    argv.push(cstring("sandbox-exec path", &block.sandbox_exec_path)?);
    argv.push(cstring("-p", "-p")?);
    argv.push(cstring("profile", &block.sbpl_profile_source)?);
    argv.push(cstring("--", "--")?);
    for argument in &block.child_argv {
        argv.push(cstring("launcher argv", argument)?);
    }
    Ok(argv)
}

/// The child's environment, exactly the block's `child_envp`.
fn envp(block: &LaunchBlock) -> Result<Vec<CString>, SpawnError> {
    block
        .child_envp
        .iter()
        .map(|variable| cstring("launcher envp", variable))
        .collect()
}

/// One `posix_spawn` of `sandbox-exec` from the block. Returns the child's
/// PID; closing the guardian's descriptor copies afterwards is the caller's
/// [`close_after_spawn`].
pub fn spawn_sandbox_exec(block: &LaunchBlock) -> Result<i32, SpawnError> {
    let argv = sandbox_exec_argv(block)?;
    let envp = envp(block)?;
    let path = argv[0].clone();

    let mut actions = libc::posix_spawn_file_actions_t::default();
    // SAFETY: each call initializes or extends `actions`, which lives across
    // the spawn and is destroyed below; no pointers are retained into them.
    unsafe {
        if libc::posix_spawn_file_actions_init(&mut actions) != 0 {
            return Err(os("posix_spawn_file_actions_init"));
        }
    }
    // SAFETY: documented pairing with the init above; runs before every
    // early return past this point.
    struct Actions(libc::posix_spawn_file_actions_t);
    impl Drop for Actions {
        fn drop(&mut self) {
            // SAFETY: `self.0` was initialized and is destroyed once.
            unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
        }
    }
    let mut actions = Actions(actions);
    // SAFETY: `actions.0` is an initialized actions record for the rest of
    // this function; fd numbers come from the validated launch block.
    unsafe {
        if !block.working_dir.is_empty() {
            let dir = cstring("working directory", &block.working_dir)?;
            if posix_spawn_file_actions_addchdir(&mut actions.0, dir.as_ptr()) != 0 {
                return Err(os("posix_spawn_file_actions_addchdir"));
            }
        }
        for (target, action) in block.stdio.iter().enumerate() {
            let target = target as i32;
            match action {
                FdAction::Null => {
                    let devnull = cstring("/dev/null", "/dev/null")?;
                    if libc::posix_spawn_file_actions_addopen(
                        &mut actions.0,
                        target,
                        devnull.as_ptr(),
                        libc::O_RDWR,
                        0,
                    ) != 0
                    {
                        return Err(os("posix_spawn_file_actions_addopen"));
                    }
                }
                FdAction::Fd(source) => {
                    if libc::posix_spawn_file_actions_adddup2(&mut actions.0, *source, target) != 0
                    {
                        return Err(os("posix_spawn_file_actions_adddup2"));
                    }
                }
            }
        }
        // The launcher's ends of R and E must survive sandbox-exec's exec
        // until the launcher marks them (§4.3); they arrive close-on-exec,
        // so the child's copies are cleared explicitly. The pty slave is
        // inherited the same way in terminal mode.
        let mut inherited = vec![block.launcher_read_fd, block.launcher_error_fd];
        for action in block.stdio {
            if let FdAction::Fd(source) = action {
                inherited.push(source);
            }
        }
        for fd in inherited {
            if fd < 0 {
                continue;
            }
            if posix_spawn_file_actions_addinherit_np(&mut actions.0, fd) != 0 {
                return Err(os("posix_spawn_file_actions_addinherit_np"));
            }
        }
    }

    let mut attributes = libc::posix_spawnattr_t::default();
    // SAFETY: init before use, destroy on scope exit below.
    unsafe {
        if libc::posix_spawnattr_init(&mut attributes) != 0 {
            return Err(os("posix_spawnattr_init"));
        }
    }
    struct Attributes(libc::posix_spawnattr_t);
    impl Drop for Attributes {
        fn drop(&mut self) {
            // SAFETY: `self.0` was initialized and is destroyed once.
            unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
        }
    }
    let mut attributes = Attributes(attributes);
    // SAFETY: `attributes.0` is initialized; flags, sigsets and the mask are
    // the spawn attributes of §4.2/§4.3.
    unsafe {
        let mut flags = 0;
        if block.setsid {
            flags |= POSIX_SPAWN_SETSID;
        }
        // SETSIGDEF: the listed signals back to their default disposition.
        let mut sigdef: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut sigdef) != 0 {
            return Err(os("sigemptyset"));
        }
        for signum in &block.sigdef {
            if libc::sigaddset(&mut sigdef, *signum) != 0 {
                return Err(os("sigaddset"));
            }
        }
        if libc::posix_spawnattr_setsigdefault(&mut attributes.0, &sigdef) != 0 {
            return Err(os("posix_spawnattr_setsigdefault"));
        }
        flags |= libc::POSIX_SPAWN_SETSIGDEF;
        // SETSIGMASK: the supervisor's inherited mask, restored for the
        // launcher so the workload does not inherit the custodians' mask.
        let mut sigmask: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut sigmask) != 0 {
            return Err(os("sigemptyset"));
        }
        for bit in 0..64 {
            if block.sigmask & (1 << bit) != 0 && libc::sigaddset(&mut sigmask, bit + 1) != 0 {
                return Err(os("sigaddset"));
            }
        }
        if libc::posix_spawnattr_setsigmask(&mut attributes.0, &sigmask) != 0 {
            return Err(os("posix_spawnattr_setsigmask"));
        }
        flags |= libc::POSIX_SPAWN_SETSIGMASK;
        if libc::posix_spawnattr_setflags(&mut attributes.0, flags as libc::c_short) != 0 {
            return Err(os("posix_spawnattr_setflags"));
        }
    }

    // `posix_spawn`'s `char *const argv[]` is a const array of **mutable**
    // pointers, historically; the elements are cast accordingly.
    let mut argv_raw: Vec<*mut libc::c_char> =
        argv.iter().map(|entry| entry.as_ptr().cast_mut()).collect();
    argv_raw.push(std::ptr::null_mut());
    let mut envp_raw: Vec<*mut libc::c_char> =
        envp.iter().map(|entry| entry.as_ptr().cast_mut()).collect();
    envp_raw.push(std::ptr::null_mut());

    let mut pid: libc::pid_t = 0;
    // SAFETY: argv/envp are NUL-terminated arrays with null sentinels; the
    // actions and attributes records above are live for this call.
    let result = unsafe {
        libc::posix_spawn(
            &mut pid,
            path.as_ptr(),
            &actions.0,
            &attributes.0,
            argv_raw.as_ptr(),
            envp_raw.as_ptr(),
        )
    };
    if result != 0 {
        return Err(SpawnError("posix_spawn", format!("errno {result}")));
    }
    Ok(pid)
}

/// Close everything the guardian held only until the spawn returned (§4.3
/// step 4): the launcher's ends of R and E, the stdio sources of the block,
/// and any fd listed as a terminal. Idempotent per fd: an already-closed fd
/// is skipped.
pub fn close_after_spawn(block: &LaunchBlock) {
    let mut fds = vec![block.launcher_read_fd, block.launcher_error_fd];
    for action in block.stdio {
        if let FdAction::Fd(source) = action {
            fds.push(source);
        }
    }
    for fd in fds {
        if fd >= 0 {
            // SAFETY: plain close of a descriptor this process owns.
            unsafe { libc::close(fd) };
        }
    }
}
