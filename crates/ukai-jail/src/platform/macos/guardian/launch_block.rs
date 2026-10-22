//! The launch block: the binary description of the launcher spawn the
//! supervisor hands the guardian on an inherited descriptor (jail-macos
//! §4.3 step 2).
//!
//! A tiny format this crate fully controls: no serde, no JSON, fixed grammar.
//! Everything is little-endian.
//!
//! ```text
//! u32  magic      = 0x554A4C42 ("UJLB")
//! u32  version    = 1
//! u32  len        bytes  sandbox_exec_path   (UTF-8, no NUL)
//! u32  len        bytes  sbpl_profile_source (the generated SBPL text;
//!                         <= MAX_PROFILE_BYTES, refuse bigger)
//! u32  argc       then argc × (u32 len + bytes)   child_argv  (launcher argv)
//! u32  envc       then envc × (u32 len + bytes)   child_envp  ("K=V", no NUL)
//! u32  len        bytes  working_dir         ("" = no chdir file action)
//!    ×3 stdio actions, stdin then stdout then stderr:
//! u8   kind       0 = /dev/null, 1 = dup the given descriptor
//! i32  fd         (kind 1 only; e.g. the relay's pty slave)
//! u32  sigdef_n   then sigdef_n × i32             POSIX_SPAWN_SETSIGDEF list
//! u64             POSIX_SPAWN_SETSIGMASK mask
//! u8   setsid     0 or 1 (POSIX_SPAWN_SETSID: every launcher a new session)
//! i32  fd         the launcher's release pipe R (guardian closes after spawn)
//! i32  fd         the launcher's error pipe E   (ditto)
//! u8   terminal   0 or 1: the pty slave named by a stdio action is the relay's
//!                 controlling terminal. The SUPERVISOR allocates the pty and
//!                 passes the slave through the block; taking it with
//!                 TIOCSCTTY is the launcher's job (§4.3 step 4), inside the
//!                 profile — `posix_spawn` cannot do it for the child.
//! u32  grace_ms   the cooperative grace the wall watchdog adds
//! ```
//!
//! Truncation, trailing bytes, a bad magic or version, an oversized profile
//! or a non-UTF-8 field are all refused: the guardian interprets nothing in
//! the block beyond turning it into `posix_spawn` arguments (§4.3 rule), but
//! it still parses exactly.

/// The generated SBPL profile is bounded; a bigger one is a supervisor bug,
/// not something to truncate.
pub const MAX_PROFILE_BYTES: u32 = 1 << 20;

const MAGIC: u32 = 0x554A_4C42;
const VERSION: u32 = 1;

/// A standard-descriptor action for the launcher's spawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdAction {
    /// Open `/dev/null` read/write on this descriptor.
    Null,
    /// `dup2` the given descriptor (held by the guardian) onto this one.
    Fd(i32),
}

/// The parsed launch block. Field-by-field documentation is in the module
/// header; the guardian turns this into one `posix_spawn` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchBlock {
    pub sandbox_exec_path: String,
    pub sbpl_profile_source: String,
    pub child_argv: Vec<String>,
    pub child_envp: Vec<String>,
    pub working_dir: String,
    pub stdio: [FdAction; 3],
    pub sigdef: Vec<i32>,
    pub sigmask: u64,
    pub setsid: bool,
    pub launcher_read_fd: i32,
    pub launcher_error_fd: i32,
    pub terminal: bool,
    pub grace_ms: u32,
}

#[derive(Debug)]
pub struct LaunchBlockError(&'static str);

impl std::fmt::Display for LaunchBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for LaunchBlockError {}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, want: usize) -> Result<&'a [u8], LaunchBlockError> {
        let end = self
            .at
            .checked_add(want)
            .ok_or(LaunchBlockError("launch block: length overflow"))?;
        if end > self.bytes.len() {
            return Err(LaunchBlockError("launch block: truncated"));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, LaunchBlockError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, LaunchBlockError> {
        let raw = self.take(4)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn i32(&mut self) -> Result<i32, LaunchBlockError> {
        Ok(self.u32()? as i32)
    }

    fn u64(&mut self) -> Result<u64, LaunchBlockError> {
        let raw = self.take(8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(raw);
        Ok(u64::from_le_bytes(bytes))
    }

    fn string(&mut self, what: &'static str) -> Result<String, LaunchBlockError> {
        let len = self.u32()? as usize;
        let raw = self.take(len)?;
        std::str::from_utf8(raw)
            .map(ToOwned::to_owned)
            .map_err(|_| LaunchBlockError(what))
    }

    fn fd_action(&mut self) -> Result<FdAction, LaunchBlockError> {
        match self.u8()? {
            0 => Ok(FdAction::Null),
            1 => Ok(FdAction::Fd(self.i32()?)),
            _ => Err(LaunchBlockError("launch block: bad stdio action")),
        }
    }
}

/// Decode a launch block. The whole buffer must be consumed: trailing bytes
/// mean the supervisor and the guardian disagree about the format, and the
/// spawn must not happen.
pub fn decode(bytes: &[u8]) -> Result<LaunchBlock, LaunchBlockError> {
    let mut reader = Reader::new(bytes);
    if reader.u32()? != MAGIC {
        return Err(LaunchBlockError("launch block: bad magic"));
    }
    if reader.u32()? != VERSION {
        return Err(LaunchBlockError("launch block: unsupported version"));
    }
    let sandbox_exec_path = reader.string("launch block: sandbox-exec path")?;
    let profile_len = reader.u32()? as usize;
    if profile_len as u32 > MAX_PROFILE_BYTES {
        return Err(LaunchBlockError("launch block: profile too large"));
    }
    let sbpl_profile_source = std::str::from_utf8(reader.take(profile_len)?)
        .map_err(|_| LaunchBlockError("launch block: profile"))?
        .to_owned();
    let argc = reader.u32()?;
    let mut child_argv = Vec::new();
    for _ in 0..argc {
        child_argv.push(reader.string("launch block: argv")?);
    }
    let envc = reader.u32()?;
    let mut child_envp = Vec::new();
    for _ in 0..envc {
        child_envp.push(reader.string("launch block: envp")?);
    }
    let working_dir = reader.string("launch block: working directory")?;
    let stdio = [
        reader.fd_action()?,
        reader.fd_action()?,
        reader.fd_action()?,
    ];
    let sigdef_n = reader.u32()?;
    let mut sigdef = Vec::new();
    for _ in 0..sigdef_n {
        sigdef.push(reader.i32()?);
    }
    let sigmask = reader.u64()?;
    let setsid = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(LaunchBlockError("launch block: bad setsid flag")),
    };
    let launcher_read_fd = reader.i32()?;
    let launcher_error_fd = reader.i32()?;
    let terminal = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(LaunchBlockError("launch block: bad terminal flag")),
    };
    let grace_ms = reader.u32()?;
    if reader.at != bytes.len() {
        return Err(LaunchBlockError("launch block: trailing bytes"));
    }
    Ok(LaunchBlock {
        sandbox_exec_path,
        sbpl_profile_source,
        child_argv,
        child_envp,
        working_dir,
        stdio,
        sigdef,
        sigmask,
        setsid,
        launcher_read_fd,
        launcher_error_fd,
        terminal,
        grace_ms,
    })
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.u32(value as u32);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u32(value.len() as u32);
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn fd_action(&mut self, action: &FdAction) {
        match action {
            FdAction::Null => self.u8(0),
            FdAction::Fd(fd) => {
                self.u8(1);
                self.i32(*fd);
            }
        }
    }
}

/// Encode a launch block.
pub fn encode(block: &LaunchBlock) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u32(MAGIC);
    writer.u32(VERSION);
    writer.string(&block.sandbox_exec_path);
    writer.string(&block.sbpl_profile_source);
    writer.u32(block.child_argv.len() as u32);
    for argument in &block.child_argv {
        writer.string(argument);
    }
    writer.u32(block.child_envp.len() as u32);
    for variable in &block.child_envp {
        writer.string(variable);
    }
    writer.string(&block.working_dir);
    for action in &block.stdio {
        writer.fd_action(action);
    }
    writer.u32(block.sigdef.len() as u32);
    for signum in &block.sigdef {
        writer.i32(*signum);
    }
    writer.u64(block.sigmask);
    writer.u8(u8::from(block.setsid));
    writer.i32(block.launcher_read_fd);
    writer.i32(block.launcher_error_fd);
    writer.u8(u8::from(block.terminal));
    writer.u32(block.grace_ms);
    writer.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LaunchBlock {
        LaunchBlock {
            sandbox_exec_path: "/usr/bin/sandbox-exec".to_owned(),
            sbpl_profile_source: "(version 1)(allow default)".to_owned(),
            child_argv: vec!["/bin/ukai-jail".to_owned(), "--launch".to_owned()],
            child_envp: vec!["PATH=/usr/bin:/bin".to_owned(), "TZ=UTC".to_owned()],
            working_dir: "/tmp".to_owned(),
            stdio: [FdAction::Null, FdAction::Fd(7), FdAction::Fd(7)],
            sigdef: vec![1, 2, 3, 17, 18, 20, 21, 22, 23, 24, 28],
            sigmask: 0x0002_0000,
            setsid: true,
            launcher_read_fd: 4,
            launcher_error_fd: 5,
            terminal: true,
            grace_ms: 2000,
        }
    }

    // The codec round-trips a full block, including every boundary the
    // grammar has: three stdio actions, an eleven-signal SETSIGDEF list
    // (§4.2: the terminal signals back to default plus the supervisor's
    // inherited mask), a nonempty working directory and both flag bytes.
    #[test]
    fn round_trips() {
        let block = sample();
        assert_eq!(decode(&encode(&block)).unwrap(), block);
    }

    // An empty argv and empty environment are legal; the launcher argv may
    // be supplied entirely by the supervisor's own conventions.
    #[test]
    fn empty_argv_and_env() {
        let mut block = sample();
        block.child_argv.clear();
        block.child_envp.clear();
        block.working_dir.clear();
        block.stdio = [FdAction::Null; 3];
        block.terminal = false;
        assert_eq!(decode(&encode(&block)).unwrap(), block);
    }

    // An argv entry may itself be empty (a length-prefixed zero).
    #[test]
    fn empty_argument_bytes() {
        let mut block = sample();
        block.child_argv = vec![String::new(), String::new()];
        assert_eq!(decode(&encode(&block)).unwrap(), block);
    }

    // A profile over the documented maximum is refused before anything
    // spawns: an oversized profile is a supervisor bug, not a truncation.
    #[test]
    fn refuses_oversized_profile() {
        let mut block = sample();
        block.sbpl_profile_source = "x".repeat(MAX_PROFILE_BYTES as usize + 1);
        let encoded = encode(&block);
        let error = decode(&encoded).unwrap_err();
        assert!(error.to_string().contains("too large"));
    }

    // A profile exactly at the maximum still round-trips.
    #[test]
    fn accepts_profile_at_bound() {
        let mut block = sample();
        block.sbpl_profile_source = "x".repeat(MAX_PROFILE_BYTES as usize);
        let encoded = encode(&block);
        assert_eq!(decode(&encoded).unwrap(), block);
    }

    // Truncation anywhere is refused; test the last byte and an empty input.
    #[test]
    fn refuses_truncation() {
        let encoded = encode(&sample());
        assert!(decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(decode(&[]).is_err());
    }

    // Trailing bytes mean a format disagreement; the spawn must not happen.
    #[test]
    fn refuses_trailing_bytes() {
        let mut encoded = encode(&sample());
        encoded.push(0);
        assert!(decode(&encoded).is_err());
    }

    // A wrong magic or version is refused outright.
    #[test]
    fn refuses_bad_magic_and_version() {
        let mut encoded = encode(&sample());
        encoded[0] ^= 0xff;
        assert!(decode(&encoded).is_err());
        let mut encoded = encode(&sample());
        encoded[4] ^= 0xff;
        assert!(decode(&encoded).is_err());
    }

    // A non-UTF-8 field is refused rather than lossily accepted.
    #[test]
    fn refuses_non_utf8_path() {
        let mut encoded = encode(&sample());
        let start = 8 + 4; // magic + version + path length
        encoded[start] = 0xff;
        assert!(decode(&encoded).is_err());
    }

    // Both stdio action kinds behave as documented, and a kind byte outside
    // {0, 1} is refused.
    #[test]
    fn refuses_bad_stdio_kind() {
        let mut block = sample();
        block.child_argv.clear();
        block.child_envp.clear();
        // The first stdio kind byte sits right after the working-directory
        // string: magic + version + path + profile + dir, each with its
        // length prefix (empty argv and envp contribute only their counts).
        let mut bytes = encode(&block);
        let first_kind = 8
            + (4 + block.sandbox_exec_path.len())
            + (4 + block.sbpl_profile_source.len())
            + (4 + block.working_dir.len())
            + 8; // argc and envc counts
        bytes[first_kind] = 9;
        assert!(decode(&bytes).is_err());
    }
}
