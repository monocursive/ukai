//! The bridge on the shared loopback (jail-macos.md §4.10).
//!
//! macOS has no network namespace, so there is no isolated loopback and no
//! fixed port a same-uid process could not equally reach. The bridge keeps
//! jail-v2's two ports, HTTP and SOCKS5, but binds both on OS-assigned
//! ephemeral loopback ports and requires the attempt's secret on both: HTTP
//! Basic authentication (RFC 7617) on the HTTP port and RFC 1929 username
//! and password on the SOCKS5 port. The seatbelt profile admits the child's
//! outbound loopback to exactly these two ports, and the secret in the
//! child's proxy URLs is what separates the attempt from every other
//! same-uid process that can address the loopback.
//!
//! The listeners are served by the ordinary userspace proxy
//! ([`crate::proxy`]), which this crate compiles for darwin; the serving
//! loop that accepts on them is wired by the launcher, as on Linux.

use std::io;
use std::net::{Ipv4Addr, TcpListener};

use crate::proxy::ProxyAuth;

/// The only address the bridge listens on, as on Linux.
pub const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The bridge's two listeners together with the configuration that
/// describes them: the launcher serves the listeners, the profile generator
/// reads the configuration.
pub struct Bound {
    /// The HTTP proxy listener.
    pub http: TcpListener,
    /// The SOCKS5 listener.
    pub socks: TcpListener,
    /// The ports and the secret the child's proxy URLs are built from.
    pub config: BridgeConfig,
}

/// What the profile generator and the launcher know about one attempt's
/// bridge: its two OS-assigned ports and the secret both require.
#[derive(Clone)]
pub struct BridgeConfig {
    /// The HTTP proxy port, OS-assigned.
    pub http_port: u16,
    /// The SOCKS5 port, OS-assigned.
    pub socks_port: u16,
    /// The per-attempt secret both ports require.
    pub auth: ProxyAuth,
}

/// Binds both listeners on OS-assigned loopback ports — `127.0.0.1:0`
/// twice, so no fixed port is occupied and the ports are not predictable —
/// and returns them with their configuration.
///
/// # Errors
/// Either bind fails, or either listener's assigned port cannot be read
/// back.
pub fn bind(auth: ProxyAuth) -> io::Result<Bound> {
    let http = TcpListener::bind((LOOPBACK, 0))?;
    let socks = TcpListener::bind((LOOPBACK, 0))?;
    let http_port = http.local_addr()?.port();
    let socks_port = socks.local_addr()?.port();
    Ok(Bound {
        http,
        socks,
        config: BridgeConfig {
            http_port,
            socks_port,
            auth,
        },
    })
}

impl BridgeConfig {
    /// `HTTP_PROXY`'s value: the HTTP proxy with the attempt's secret in its
    /// userinfo. [`ProxyAuth::generate`] makes both URL-safe, so nothing is
    /// escaped here.
    #[must_use]
    pub fn proxy_url(&self) -> String {
        format!(
            "http://{}:{}@{LOOPBACK}:{}",
            self.auth.user, self.auth.password, self.http_port
        )
    }

    /// `ALL_PROXY`'s value: SOCKS5 with names resolved by the proxy, and the
    /// attempt's secret in its userinfo.
    #[must_use]
    pub fn socks_url(&self) -> String {
        format!(
            "socks5h://{}:{}@{LOOPBACK}:{}",
            self.auth.user, self.auth.password, self.socks_port
        )
    }

    /// The proxy environment the child runs with: the three proxy variables
    /// in both spellings and an empty `NO_PROXY`, as on Linux (jail-v1
    /// §10), each URL carrying the attempt's secret.
    #[must_use]
    pub fn environment(&self) -> Vec<(&'static str, String)> {
        let (http, socks) = (self.proxy_url(), self.socks_url());
        vec![
            ("HTTP_PROXY", http.clone()),
            ("HTTPS_PROXY", http.clone()),
            ("ALL_PROXY", socks.clone()),
            ("http_proxy", http.clone()),
            ("https_proxy", http),
            ("all_proxy", socks),
            ("NO_PROXY", String::new()),
            ("no_proxy", String::new()),
        ]
    }
}

/// How many connections the relay keeps at once (initial). Over the bound a
/// connection is closed at once; the child's proxy client retries, and the
/// bound keeps a runaway workload from threading the supervisor to death.
pub const MAX_RELAYS: usize = 256;

/// Serves both listeners: every accepted connection is relayed byte for
/// byte to the outside proxy's Unix socket, where policy and the per-attempt
/// secret are enforced. Vault staging is unavailable; enabling it also needs
/// the authenticated origin preamble. This raw relay interprets nothing.
///
/// # Errors
/// A thread cannot be started.
pub fn serve(bound: Bound, proxy_socket: &std::path::Path) -> io::Result<Serving> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize},
    };
    let stop = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    // On a partial spawn failure, the owned Serving cancels and joins the
    // first loop too. Never leave a detached listener behind.
    let mut serving = Serving {
        stop,
        threads: Vec::with_capacity(2),
    };
    for listener in [bound.http, bound.socks] {
        listener.set_nonblocking(true)?;
        let stop = Arc::clone(&serving.stop);
        let in_flight = Arc::clone(&in_flight);
        let socket = proxy_socket.to_path_buf();
        serving.threads.push(
            std::thread::Builder::new()
                .name("ukai-macos-bridge".into())
                .spawn(move || accept_loop(listener, socket, stop, in_flight))?,
        );
    }
    Ok(serving)
}

/// Dropping the relay cancels bounded reads/writes and joins every worker,
/// including idle connections. No reliance on shutdown waking accept on Darwin.
pub struct Serving {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

const RELAY_TICK: std::time::Duration = std::time::Duration::from_millis(25);

fn accept_loop(
    listener: TcpListener,
    socket: std::path::PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::Ordering::SeqCst;
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    while !stop.load(SeqCst) {
        let mut i = 0;
        while i < workers.len() {
            if workers[i].is_finished() {
                let _ = workers.swap_remove(i).join();
            } else {
                i += 1;
            }
        }
        let (client, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(RELAY_TICK);
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        // One shared bound across both listeners; a load then increment races.
        if in_flight
            .fetch_update(SeqCst, SeqCst, |n| (n < MAX_RELAYS).then_some(n + 1))
            .is_err()
        {
            continue;
        }
        let counter = std::sync::Arc::clone(&in_flight);
        let stop = std::sync::Arc::clone(&stop);
        let socket = socket.clone();
        match std::thread::Builder::new()
            .name("ukai-macos-relay".into())
            .spawn(move || {
                if let Ok(upstream) = connect_upstream(&socket, &stop) {
                    relay(client, upstream, &stop);
                }
                counter.fetch_sub(1, SeqCst);
            }) {
            Ok(worker) => workers.push(worker),
            Err(_) => {
                in_flight.fetch_sub(1, SeqCst);
            }
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

/// A nonblocking Unix connect: even a full/unresponsive proxy backlog must
/// not hold Serving::drop. Owned socket, bounded poll, cancellation checked.
fn connect_upstream(
    path: &std::path::Path,
    stop: &std::sync::atomic::AtomicBool,
) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: socket takes scalars; on success the stream immediately owns it.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a new owned socket.
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;
    // SAFETY: fcntl uses only the owned descriptor and scalar flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr_un is plain C data; filled and bounded below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid proxy socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as _;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = std::mem::size_of_val(&address) as u8;
    }
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as libc::c_char;
    }
    // SAFETY: address and its size match; connect does not retain the pointer.
    let result = unsafe {
        libc::connect(
            fd,
            (&raw const address).cast(),
            std::mem::size_of_val(&address) as _,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if stop.load(std::sync::atomic::Ordering::SeqCst)
                || std::time::Instant::now() >= deadline
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "proxy connect cancelled",
                ));
            }
            let mut poll = libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: one live pollfd, finite timeout.
            if unsafe { libc::poll(&raw mut poll, 1, 25) } > 0 {
                break;
            }
        }
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn copy_direction(
    mut from: impl io::Read,
    mut to: impl io::Write,
    stop: &std::sync::atomic::AtomicBool,
) {
    let mut buffer = [0u8; 16 * 1024];
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let count = match from.read(&mut buffer) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if transient(&e) => continue,
            Err(_) => return,
        };
        let mut offset = 0;
        while offset < count && !stop.load(std::sync::atomic::Ordering::SeqCst) {
            match to.write(&buffer[offset..count]) {
                Ok(0) => return,
                Ok(n) => offset += n,
                Err(e) if transient(&e) => continue,
                Err(_) => return,
            }
        }
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// Responses flow upstream -> child. Preserve half-close so a client may
/// finish its request and still read the response. Cancellation ends both.
fn relay(
    client: std::net::TcpStream,
    upstream: std::os::unix::net::UnixStream,
    stop: &std::sync::atomic::AtomicBool,
) {
    // Darwin inherits O_NONBLOCK from the listening socket. Restore blocking
    // I/O here so socket timeouts bound each copy step without busy polling.
    if client.set_nonblocking(false).is_err()
        || client.set_read_timeout(Some(RELAY_TICK)).is_err()
        || client.set_write_timeout(Some(RELAY_TICK)).is_err()
        || upstream.set_read_timeout(Some(RELAY_TICK)).is_err()
        || upstream.set_write_timeout(Some(RELAY_TICK)).is_err()
    {
        return;
    }
    std::thread::scope(|scope| {
        let sender = scope.spawn(|| {
            copy_direction(&client, &upstream, stop);
            let _ = upstream.shutdown(std::net::Shutdown::Write);
        });
        copy_direction(&upstream, &client, stop);
        let _ = client.shutdown(std::net::Shutdown::Both);
        let _ = upstream.shutdown(std::net::Shutdown::Both);
        let _ = sender.join();
    });
}
