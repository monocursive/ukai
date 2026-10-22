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
/// byte to the outside proxy's Unix socket, where the policy, the vault and
/// the per-attempt secret are enforced. The relay interprets nothing.
///
/// # Errors
/// A thread cannot be started.
pub fn serve(bound: Bound, proxy_socket: &std::path::Path) -> io::Result<Serving> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let in_flight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut threads = Vec::with_capacity(2);
    let mut fds = Vec::with_capacity(2);
    for listener in [bound.http, bound.socks] {
        use std::os::fd::AsRawFd as _;
        fds.push(listener.as_raw_fd());
        let stop = std::sync::Arc::clone(&stop);
        let in_flight = std::sync::Arc::clone(&in_flight);
        let socket = proxy_socket.to_path_buf();
        threads.push(
            std::thread::Builder::new()
                .name("ukai-macos-bridge".to_owned())
                .spawn(move || accept_loop(listener, socket, stop, in_flight))?,
        );
    }
    Ok(Serving { stop, threads, fds })
}

/// The running relay. Dropping it stops both accept loops (a blocking
/// `accept` is woken by shutting the listener's socket down) and waits for
/// the loops and the connections in flight to end.
pub struct Serving {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
    fds: Vec<std::ffi::c_int>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for fd in &self.fds {
            // SAFETY: a scalar shutdown of a listening socket this relay
            // owns; it only wakes the blocked `accept` with an error.
            unsafe { libc::shutdown(*fd, libc::SHUT_RDWR) };
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    socket: std::path::PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let Ok((client, _)) = listener.accept() else {
            continue;
        };
        if in_flight.load(std::sync::atomic::Ordering::SeqCst) >= MAX_RELAYS {
            continue;
        }
        let Ok(upstream) = std::os::unix::net::UnixStream::connect(&socket) else {
            continue;
        };
        in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let counter = std::sync::Arc::clone(&in_flight);
        let spawned = std::thread::Builder::new()
            .name("ukai-macos-relay".to_owned())
            .spawn(move || {
                relay(client, upstream);
                counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        if spawned.is_err() {
            in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Copies bytes both ways until either side ends. The first direction to
/// end closes the other (a half-closed proxy connection is not kept open
/// for a child that will never write again), and errors end the relay: the
/// child's proxy client retries a dropped connection itself.
fn relay(client: std::net::TcpStream, upstream: std::os::unix::net::UnixStream) {
    let client_read = match client.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let upstream_write = match upstream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let to_upstream = std::thread::Builder::new()
        .name("ukai-macos-relay".to_owned())
        .spawn(move || {
            let _ = std::io::copy(&mut &client_read, &mut &upstream_write);
        });
    let _ = std::io::copy(&mut &client, &mut &upstream);
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = upstream.shutdown(std::net::Shutdown::Both);
    let _ = to_upstream.map(|thread| thread.join());
}
