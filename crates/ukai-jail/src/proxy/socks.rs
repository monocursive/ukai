//! RFC 1928 CONNECT only, plus the RFC 1929 username-and-password
//! subnegotiation when the attempt's bridge carries a secret. DNS resolution
//! remains in the shared proxy policy.
use super::{ProxyAuth, Reason, Transport};
use crate::network::{Destination, Host, normalize_host};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// The protocol version byte that starts every SOCKS5 message.
const VERSION: u8 = 5;
/// The method that needs no credentials.
const NO_AUTHENTICATION: u8 = 0;
/// The RFC 1929 username-and-password method.
const USERPASS: u8 = 2;
/// The method answer when the client offers no acceptable method.
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
/// Commands (RFC 1928 §4).
const CONNECT: u8 = 1;
const BIND: u8 = 2;
/// Address types (RFC 1928 §5).
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;
/// The RFC 1929 subnegotiation: its version byte and status codes (§2).
const AUTH_VERSION: u8 = 1;
const AUTH_SUCCESS: u8 = 0;
const AUTH_FAILURE: u8 = 1;

/// The reply codes the proxy sends (RFC 1928 §6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reply {
    Succeeded = 0,
    GeneralFailure = 1,
    NotAllowed = 2,
    ConnectionRefused = 5,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

/// Which protocol the client speaks, judged by its first byte without
/// consuming it. `Ok(None)`: it closed without sending one.
pub fn detect(stream: &UnixStream, deadline: Instant) -> Result<Option<Transport>, Reason> {
    stream
        .set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(std::time::Duration::from_millis(1)),
        ))
        .map_err(|_| Reason::InternalError)?;
    let mut byte = 0u8;
    // MSG_PEEK selects the protocol without consuming HTTP's request byte.
    let n = loop {
        // SAFETY: `byte` is a writable one-byte buffer that outlives the
        // call, the length passed is 1, and the descriptor belongs to
        // `stream`, which is borrowed (open) for the call.
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                (&raw mut byte).cast(),
                1,
                libc::MSG_PEEK,
            )
        };
        if n >= 0 {
            break n;
        }
        match std::io::Error::last_os_error().kind() {
            // A signal may interrupt the one-byte peek; retry it rather
            // than mislabeling a live request.
            std::io::ErrorKind::Interrupted => continue,
            // A reset or broken peer sent nothing: the same silence as a
            // closed one, not a header timeout.
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                return Ok(None);
            }
            _ => return Err(Reason::HeaderTimeout),
        }
    };
    Ok((n != 0).then_some(if byte == VERSION {
        Transport::Socks5
    } else {
        Transport::Http
    }))
}

fn read(stream: &UnixStream, bytes: &mut [u8], deadline: Instant) -> Result<(), Reason> {
    let mut at = 0;
    while at < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Reason::HeaderTimeout);
        }
        match stream.set_read_timeout(Some(remaining)) {
            Ok(()) => {}
            // macOS refuses to shorten a Unix socket's receive timeout once
            // its peer has closed (EINVAL). The window armed on the previous
            // iteration is still in force — the call failed to change it,
            // not to clear it — and the peer's close is pending as EOF, so
            // the read below ends the loop at once.
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
            Err(_) => return Err(Reason::InternalError),
        }
        match (&*stream).read(&mut bytes[at..]) {
            Ok(0) => return Err(Reason::ClientClosed),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Reason::HeaderTimeout),
        }
    }
    Ok(())
}

/// Writes whole bytes within the origin timeout: the client stopped
/// listening, so there is nothing left to serve.
fn write_all(stream: &UnixStream, bytes: &[u8]) -> Result<(), Reason> {
    stream
        .set_write_timeout(Some(super::origin::TIMEOUT))
        .map_err(|_| Reason::InternalError)?;
    let result = (&*stream)
        .write_all(bytes)
        .map_err(|_| Reason::ClientClosed);
    let _ = stream.set_write_timeout(None);
    result
}

pub fn request(stream: &UnixStream, deadline: Instant) -> Result<Destination, Reason> {
    request_with_auth(stream, deadline, None)
}

/// Reads one SOCKS5 CONNECT, as [`request`], with the bridge's per-attempt
/// secret when the attempt carries one (jail-macos.md §4.10).
///
/// With `auth`, only RFC 1929 username-and-password (method `0x02`) is
/// acceptable: a client that does not offer it is answered `0xff` and
/// refused, and one that does must present `auth` exactly in the
/// subnegotiation (one-byte version, length-prefixed name and password) or
/// is answered the `0x01` failure status and the connection closes. Without
/// `auth`, the exchange is the Linux bridge's: only method `0x00` is
/// acceptable and nothing else is read.
pub fn request_with_auth(
    stream: &UnixStream,
    deadline: Instant,
    auth: Option<&ProxyAuth>,
) -> Result<Destination, Reason> {
    request_reporting_auth(stream, deadline, auth, || {})
}

/// Reports the verified secret before replying or reading the command, so
/// a later refusal or disconnect still belongs to the authenticated attempt.
pub(super) fn request_reporting_auth(
    stream: &UnixStream,
    deadline: Instant,
    auth: Option<&ProxyAuth>,
    authenticated: impl FnOnce(),
) -> Result<Destination, Reason> {
    let mut head = [0; 2];
    read(stream, &mut head, deadline)?;
    if head[0] != VERSION || head[1] == 0 {
        return Err(Reason::MalformedRequest);
    }
    let mut methods = vec![0; usize::from(head[1])];
    read(stream, &mut methods, deadline)?;
    let wanted = auth.map_or(NO_AUTHENTICATION, |_| USERPASS);
    let method = if methods.contains(&wanted) {
        wanted
    } else {
        NO_ACCEPTABLE_METHOD
    };
    write_all(stream, &[VERSION, method])?;
    if method == NO_ACCEPTABLE_METHOD {
        return Err(if auth.is_some() {
            Reason::ProxyAuthRequired
        } else {
            Reason::UnsupportedRequest
        });
    }
    if let Some(auth) = auth {
        let mut version = [0];
        read(stream, &mut version, deadline)?;
        if version[0] != AUTH_VERSION {
            return Err(Reason::MalformedRequest);
        }
        let mut length = [0];
        read(stream, &mut length, deadline)?;
        let mut name = vec![0; usize::from(length[0])];
        read(stream, &mut name, deadline)?;
        let mut length = [0];
        read(stream, &mut length, deadline)?;
        let mut password = vec![0; usize::from(length[0])];
        read(stream, &mut password, deadline)?;
        let accepted = auth.matches(&name, &password);
        if accepted {
            authenticated();
        }
        let status = if accepted { AUTH_SUCCESS } else { AUTH_FAILURE };
        write_all(stream, &[AUTH_VERSION, status])?;
        if !accepted {
            // RFC 1929 §2: the client "must close the connection" after a
            // failure status; we close our side too, so nothing follows.
            return Err(Reason::ProxyAuthRequired);
        }
    }
    let mut header = [0; 4];
    read(stream, &mut header, deadline)?;
    if header[0] != VERSION || header[2] != 0 {
        return Err(Reason::MalformedRequest);
    }
    if header[1] != CONNECT {
        // Read the rest of the request before answering: closing over
        // unread bytes makes Linux reset the connection, which can discard
        // this reply before the client reads it.
        let address = match header[3] {
            IPV4 => 4,
            IPV6 => 16,
            DOMAIN => {
                let mut len = [0];
                read(stream, &mut len, deadline)?;
                usize::from(len[0])
            }
            _ => 0,
        };
        let mut rest = vec![0; address + 2];
        if header[3] == IPV4 || header[3] == IPV6 || header[3] == DOMAIN {
            read(stream, &mut rest, deadline)?;
        }
        reply(
            stream,
            if header[1] == BIND {
                Reply::NotAllowed
            } else {
                Reply::CommandNotSupported
            },
        )?;
        return Err(Reason::UnsupportedRequest);
    }
    let host = match header[3] {
        IPV4 => {
            let mut ip = [0; 4];
            read(stream, &mut ip, deadline)?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
        }
        IPV6 => {
            let mut ip = [0; 16];
            read(stream, &mut ip, deadline)?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(ip)))
        }
        DOMAIN => {
            let mut len = [0];
            read(stream, &mut len, deadline)?;
            if len[0] == 0 {
                return Err(Reason::MalformedRequest);
            }
            let mut bytes = vec![0; usize::from(len[0])];
            read(stream, &mut bytes, deadline)?;
            normalize_host(std::str::from_utf8(&bytes).map_err(|_| Reason::MalformedRequest)?)
                .map_err(|_| Reason::MalformedRequest)?
        }
        _ => {
            reply(stream, Reply::AddressTypeNotSupported)?;
            return Err(Reason::UnsupportedRequest);
        }
    };
    let mut port = [0; 2];
    read(stream, &mut port, deadline)?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(Reason::MalformedRequest);
    }
    let _ = stream.set_read_timeout(None);
    Ok(Destination { host, port })
}

/// A reply with an all-zero IPv4 bound address: the proxy never discloses
/// the address it connected from.
pub fn reply(stream: &UnixStream, reply: Reply) -> Result<(), Reason> {
    write_all(stream, &[VERSION, reply as u8, 0, IPV4, 0, 0, 0, 0, 0, 0])
}
