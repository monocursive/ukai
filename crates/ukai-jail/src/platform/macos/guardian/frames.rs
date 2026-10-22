//! The A and B pipe frame grammar (jail-macos §4.3).
//!
//! A frame is `u32` little-endian length, then that many bytes. On **A**
//! (supervisor → guardian):
//!
//! - `launcher-token ` + 32 bytes: the launcher's current audit token as
//!   eight `u32` words, sent after the launcher reports `blocked` (§4.3
//!   step 5). The guardian answers `token-seen` on B once client G's table
//!   holds the same token.
//! - `release-deadline ` + 8 bytes: the wall deadline in continuous-clock
//!   nanoseconds from release (§4.3 step 6).
//!
//! On **B** (guardian → supervisor): `ready` (§4.3 step 3), `token-seen`
//! (step 5), and the final `record ` + JSON bytes holding exactly the
//! guardian record written to disk (§4.4).
//!
//! End-of-file on A means stop, whatever frames are pending (§4.3).

/// Hard bound shared by both custodians, on A and B payloads (I1).
pub const MAX_FRAME_BYTES: usize = 4096;
/// Explicit release with no wall watchdog (I2); A's EOF still stops.
pub const NO_DEADLINE: u64 = u64::MAX;

pub const TOKEN_BYTES: usize = 8 * std::mem::size_of::<u32>();

const LAUNCHER_TOKEN: &[u8] = b"launcher-token ";
const RELEASE_DEADLINE: &[u8] = b"release-deadline ";
const READY: &[u8] = b"ready";
const TOKEN_SEEN: &[u8] = b"token-seen";
const RECORD: &[u8] = b"record ";

pub type Token = [u32; 8];

/// Decode one frame from `payload`. `Ok(None)` is an idle tick: nothing
/// complete has arrived. `Err` means the supervisor disagrees about the
/// grammar — the guardian stops rather than guess.
pub fn decode_frame(payload: &[u8]) -> Result<Option<Frame>, &'static str> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err("guardian: frame length outside 1..=MAX_FRAME_BYTES");
    }
    if let Some(rest) = payload.strip_prefix(LAUNCHER_TOKEN) {
        let token = token_from_bytes(rest)?;
        return Ok(Some(Frame::LauncherToken(token)));
    }
    if let Some(rest) = payload.strip_prefix(RELEASE_DEADLINE) {
        if rest.len() != 8 {
            return Err("guardian: release-deadline frame: bad length");
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(rest);
        return Ok(Some(Frame::ReleaseDeadline(u64::from_le_bytes(bytes))));
    }
    Err("guardian: unknown frame on A")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    LauncherToken(Token),
    ReleaseDeadline(u64),
}

fn token_from_bytes(bytes: &[u8]) -> Result<Token, &'static str> {
    if bytes.len() != TOKEN_BYTES {
        return Err("guardian: launcher-token frame: bad length");
    }
    let (chunks, rest) = bytes.as_chunks::<4>();
    if !rest.is_empty() {
        return Err("guardian: partial token word");
    }
    let mut token = [0u32; 8];
    for (word, raw) in token.iter_mut().zip(chunks) {
        *word = u32::from_le_bytes(*raw);
    }
    Ok(token)
}

/// The `launcher-token` frame bytes.
pub fn encode_launcher_token(token: &Token) -> Vec<u8> {
    let mut frame = Vec::with_capacity(LAUNCHER_TOKEN.len() + TOKEN_BYTES);
    frame.extend_from_slice(LAUNCHER_TOKEN);
    for word in token {
        frame.extend_from_slice(&word.to_le_bytes());
    }
    frame
}

/// The `release-deadline` frame bytes.
pub fn encode_release_deadline(deadline_ns: u64) -> Vec<u8> {
    let mut frame = Vec::with_capacity(RELEASE_DEADLINE.len() + 8);
    frame.extend_from_slice(RELEASE_DEADLINE);
    frame.extend_from_slice(&deadline_ns.to_le_bytes());
    frame
}

/// Explicitly disable the wall watchdog; A stays open until the stop.
pub fn encode_release_without_deadline() -> Vec<u8> {
    encode_release_deadline(NO_DEADLINE)
}

pub fn wall_deadline(value: u64) -> Option<u64> {
    (value != NO_DEADLINE).then_some(value)
}

/// The `ready` frame bytes.
pub fn encode_ready() -> Vec<u8> {
    READY.to_vec()
}

/// The `token-seen` frame bytes.
pub fn encode_token_seen() -> Vec<u8> {
    TOKEN_SEEN.to_vec()
}

/// The final `record` frame bytes (the same JSON written to disk).
pub fn encode_record(json: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(RECORD.len() + json.len());
    frame.extend_from_slice(RECORD);
    frame.extend_from_slice(json.as_bytes());
    frame
}

/// A length-prefixed writer over an owned buffer: the caller drains
/// `take_outgoing` onto the pipe when it is writable.
#[derive(Default)]
pub struct FrameWriter {
    buffer: Vec<u8>,
}

impl FrameWriter {
    pub fn queue(&mut self, frame: Vec<u8>) -> Result<(), &'static str> {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err("invalid frame length");
        }
        self.buffer.reserve(frame.len() + 4);
        self.buffer
            .extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.buffer.extend_from_slice(&frame);
        Ok(())
    }

    pub fn pending(&self) -> bool {
        !self.buffer.is_empty()
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }
}

/// The length-prefixed reader over A. `Feed::Eof` means end-of-file: stop.
pub struct FrameReader {
    buffer: [u8; MAX_FRAME_BYTES + 4],
    used: usize,
    failed: bool,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self {
            buffer: [0; MAX_FRAME_BYTES + 4],
            used: 0,
            failed: false,
        }
    }
}

/// What a read of A produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Feed {
    /// Zero or more complete frames, then no more input yet.
    Frames(Vec<Result<Frame, &'static str>>),
    /// End-of-file: the stop trigger (§4.3).
    Eof,
}

impl FrameReader {
    /// Bytes needed for the next prefix or payload. Reading at most this
    /// amount lets the live loop deliver one fixed-size value without a Vec.
    pub fn wanted(&self) -> usize {
        if self.used < 4 {
            return 4 - self.used;
        }
        let length = u32::from_le_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;
        (4 + length).saturating_sub(self.used).min(MAX_FRAME_BYTES)
    }

    pub fn read_one(&mut self, bytes: &[u8], eof: bool) -> Result<Option<Frame>, &'static str> {
        if self.failed {
            return Err("guardian: frame stream already invalid");
        }
        if eof && self.used != 0 {
            self.failed = true;
            return Err("guardian: truncated frame at EOF");
        }
        if bytes.len() > self.wanted() {
            self.failed = true;
            return Err("guardian: read crosses a frame boundary");
        }
        self.buffer[self.used..self.used + bytes.len()].copy_from_slice(bytes);
        self.used += bytes.len();
        if self.used < 4 {
            return Ok(None);
        }
        let length = u32::from_le_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            self.failed = true;
            return Err("guardian: invalid frame length");
        }
        if self.used != 4 + length {
            return Ok(None);
        }
        let result = decode_frame(&self.buffer[4..self.used]);
        self.used = 0;
        self.failed = result.is_err();
        result
    }

    /// Batched convenience API for callers outside the allocation-free live
    /// guardian loop. Backing storage remains bounded for arbitrary splits.
    pub fn read(&mut self, mut bytes: &[u8], eof: bool) -> Feed {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let count = self.wanted().min(bytes.len());
            match self.read_one(&bytes[..count], false) {
                Ok(Some(frame)) => frames.push(Ok(frame)),
                Ok(None) => {}
                Err(error) => {
                    frames.push(Err(error));
                    return Feed::Frames(frames);
                }
            }
            bytes = &bytes[count..];
        }
        if eof {
            if let Err(error) = self.read_one(&[], true) {
                frames.push(Err(error));
            } else if frames.is_empty() {
                return Feed::Eof;
            }
        }
        Feed::Frames(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> Token {
        [1, 0xdead_beef, 3, 4, 5, 6, 7, 8]
    }

    // A frame fed byte-by-byte decodes only when complete; the grammar holds
    // across arbitrary splits, which is what poll(2) delivers.
    #[test]
    fn frames_survive_fragmented_reads() {
        let mut reader = FrameReader::default();
        let bytes = encode_launcher_token(&token());
        let mut framed = (bytes.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        for (index, byte) in framed.iter().enumerate() {
            let feed = reader.read(&[*byte], false);
            match index + 1 == framed.len() {
                true => assert!(matches!(
                    feed,
                    Feed::Frames(one) if one.len() == 1
                        && one[0] == Ok(Frame::LauncherToken(token()))
                )),
                false => assert_eq!(feed, Feed::Frames(vec![])),
            }
        }
    }

    // Two frames in one read both arrive; an unknown name is an error, not a
    // guess.
    #[test]
    fn batched_and_unknown_frames() {
        let mut framed = Vec::new();
        for frame in [encode_ready_frame(&token()), encode_deadline_frame(1234)] {
            framed.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            framed.extend_from_slice(&frame);
        }
        let mut reader = FrameReader::default();
        let feed = reader.read(&framed, false);
        let Feed::Frames(frames) = feed else {
            panic!("frames expected");
        };
        assert_eq!(frames.len(), 2);
        assert!(frames[0].is_ok());
        assert_eq!(frames[1], Ok(Frame::ReleaseDeadline(1234)));
        // An unknown frame name is a hard error.
        let mut reader = FrameReader::default();
        let junk = b"nonsense ";
        let mut framed = (junk.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(junk);
        assert!(matches!(
            reader.read(&framed, false),
            Feed::Frames(one) if one[0].is_err()
        ));
    }

    // An empty final read is end-of-file: the stop trigger.
    #[test]
    fn eof_is_the_stop_trigger() {
        let mut reader = FrameReader::default();
        assert_eq!(reader.read(&[], true), Feed::Eof);
    }

    // The writer prefixes lengths and drains whole frames in order.
    #[test]
    fn writer_round_trips() {
        let mut writer = FrameWriter::default();
        writer.queue(encode_ready_frame(&token())).unwrap();
        writer.queue(encode_deadline_frame(7)).unwrap();
        let outgoing = writer.take_outgoing();
        assert!(!writer.pending());
        let mut reader = FrameReader::default();
        let Feed::Frames(frames) = reader.read(&outgoing, false) else {
            panic!("frames expected");
        };
        assert_eq!(
            frames,
            vec![
                Ok(Frame::LauncherToken(token())),
                Ok(Frame::ReleaseDeadline(7))
            ]
        );
    }

    fn encode_ready_frame(token_: &Token) -> Vec<u8> {
        encode_launcher_token(token_)
    }

    fn encode_deadline_frame(deadline: u64) -> Vec<u8> {
        encode_release_deadline(deadline)
    }
}
