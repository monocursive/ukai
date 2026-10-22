//! J16: the bridge on the shared loopback (jail-macos.md §4.10), live.
//!
//! The whole file is gated to macOS: the module under test lives in the
//! platform's macOS tree, and its claims — two OS-assigned ephemeral ports,
//! the secret in the child's URLs, a handshake through a real TCP connect —
//! are about the platform the profile runs on. On Linux the file compiles
//! to nothing.
//!
//! Each test's server side is one accepted connection driven through the
//! proxy's own SOCKS5 and HTTP halves with the attempt's secret, so the
//! handshakes here are the ones a bridge connection speaks, over a real
//! loopback TCP socket.

#![cfg(target_os = "macos")]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use ukai_jail::network::Destination;
use ukai_jail::platform::macos::bridge::{self, BridgeConfig};
use ukai_jail::proxy::{ProxyAuth, Reason, http, socks};

/// Upper bound for any wait. Never reached when the behaviour is correct.
const WAIT: Duration = Duration::from_secs(10);
/// `ukai:secret` as base64: the credentials the HTTP-lane tests present.
const BASIC_CREDENTIALS: &str = "dWthaTpzZWNyZXQ=";

/// Accepts one connection on `listener` and runs the proxy's SOCKS5 half on
/// it with `auth`, answering an accepted CONNECT with the SOCKS success
/// reply. The result is the parse: the destination, or the safe reason the
/// handshake failed with.
///
/// The proxy's halves speak `UnixStream`; the accepted descriptor is a TCP
/// socket. On this platform both are connected BSD sockets, and the proxy
/// uses the descriptor only for reads, writes and socket timeouts, so it is
/// taken over as a `UnixStream`, which closes it.
fn accept_tcp(listener: &TcpListener) -> (TcpStream, std::net::SocketAddr) {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        match listener.accept() {
            Ok(connection) => {
                connection.0.set_nonblocking(false).unwrap();
                return connection;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "TCP accept timed out");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("TCP accept failed: {error}"),
        }
    }
}

fn accept_unix(listener: &std::os::unix::net::UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "Unix accept timed out");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("Unix accept failed: {error}"),
        }
    }
}

fn serve_socks_once(
    listener: &TcpListener,
    auth: ProxyAuth,
) -> thread::JoinHandle<Result<Destination, Reason>> {
    let listener = listener.try_clone().expect("cloneable");
    thread::spawn(move || {
        let (accepted, _) = accept_tcp(&listener);
        // SAFETY: the descriptor came from `into_raw_fd` on the accepted
        // stream immediately above — open, connected, and owned by this
        // thread alone — and the `UnixStream` takes sole ownership of it and
        // closes it on drop. Everything the proxy calls on it (`read`,
        // `write`, socket timeouts) is valid on a TCP socket.
        let stream = unsafe { UnixStream::from_raw_fd(accepted.into_raw_fd()) };
        match socks::request_with_auth(&stream, Instant::now() + WAIT, Some(&auth)) {
            Ok(destination) => {
                socks::reply(&stream, socks::Reply::Succeeded).expect("replied");
                Ok(destination)
            }
            Err(reason) => Err(reason),
        }
    })
}

/// Accepts one connection on `listener` and serves the proxy's HTTP half
/// with `auth`: one request head, answered `200 Connection Established`
/// when it carries the secret and the refusal response otherwise. The
/// result is the response bytes written.
fn serve_http_once(listener: &TcpListener, auth: ProxyAuth) -> thread::JoinHandle<Vec<u8>> {
    let listener = listener.try_clone().expect("cloneable");
    thread::spawn(move || {
        let (accepted, _) = accept_tcp(&listener);
        // SAFETY: as in `serve_socks_once`: sole ownership of an open,
        // connected TCP descriptor moves to the `UnixStream`, which closes
        // it on drop.
        let mut stream = unsafe { UnixStream::from_raw_fd(accepted.into_raw_fd()) };
        let deadline = Instant::now() + WAIT;
        let response = match http::read_head(&stream, 8192, deadline) {
            Ok(head) => match http::parse_request_with_auth(head.head(), 80, Some(&auth)) {
                Ok(_request) => b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec(),
                Err(reason) => http::error_response(reason),
            },
            Err(http::HeadError::NoBytes) => Vec::new(),
            Err(http::HeadError::Reject(reason)) => http::error_response(reason),
        };
        let _ = stream.write_all(&response);
        response
    })
}

/// A client connected to `port`, its reads bounded by `WAIT`.
fn connect(port: u16) -> TcpStream {
    let client = TcpStream::connect(("127.0.0.1", port)).expect("the listener answers");
    client.set_read_timeout(Some(WAIT)).expect("read timeout");
    client.set_write_timeout(Some(WAIT)).expect("write timeout");
    client
}

/// Writes a method-selection greeting and reads the method chosen.
fn writes_greeting(client: &mut TcpStream, methods: &[u8]) -> [u8; 2] {
    let mut greeting = vec![5, methods.len() as u8];
    greeting.extend_from_slice(methods);
    client.write_all(&greeting).unwrap();
    let mut chosen = [0; 2];
    client.read_exact(&mut chosen).unwrap();
    chosen
}

/// The RFC 1929 subnegotiation frame for a name and password.
fn userpass_frame(user: &str, password: &str) -> Vec<u8> {
    let mut frame = vec![1, user.len() as u8];
    frame.extend_from_slice(user.as_bytes());
    frame.push(password.len() as u8);
    frame.extend_from_slice(password.as_bytes());
    frame
}

#[test]
fn the_bridge_binds_two_distinct_ephemeral_loopback_ports() {
    let bound = bridge::bind(ProxyAuth::generate()).expect("both bind");
    let http = bound.http.local_addr().unwrap();
    let socks = bound.socks.local_addr().unwrap();
    assert_eq!(http.ip().to_string(), "127.0.0.1");
    assert_eq!(socks.ip().to_string(), "127.0.0.1");
    assert_eq!(bound.config.http_port, http.port());
    assert_eq!(bound.config.socks_port, socks.port());
    assert_ne!(bound.config.http_port, 0);
    assert_ne!(bound.config.socks_port, 0);
    assert_ne!(bound.config.http_port, bound.config.socks_port);
}

#[test]
fn the_urls_and_the_environment_carry_the_secret_in_both_spellings() {
    let config = BridgeConfig {
        http_port: 49152,
        socks_port: 49153,
        auth: ProxyAuth {
            user: "ukai".to_owned(),
            password: "deadbeef".to_owned(),
        },
    };
    assert_eq!(config.proxy_url(), "http://ukai:deadbeef@127.0.0.1:49152");
    assert_eq!(
        config.socks_url(),
        "socks5h://ukai:deadbeef@127.0.0.1:49153"
    );
    let environment = config.environment();
    for (name, value) in [
        ("HTTP_PROXY", "http://ukai:deadbeef@127.0.0.1:49152"),
        ("HTTPS_PROXY", "http://ukai:deadbeef@127.0.0.1:49152"),
        ("ALL_PROXY", "socks5h://ukai:deadbeef@127.0.0.1:49153"),
        ("http_proxy", "http://ukai:deadbeef@127.0.0.1:49152"),
        ("https_proxy", "http://ukai:deadbeef@127.0.0.1:49152"),
        ("all_proxy", "socks5h://ukai:deadbeef@127.0.0.1:49153"),
    ] {
        assert!(
            environment
                .iter()
                .any(|(key, seen)| *key == name && seen == value),
            "{name}"
        );
    }
    for name in ["NO_PROXY", "no_proxy"] {
        assert!(
            environment
                .iter()
                .any(|(key, seen)| *key == name && seen.is_empty()),
            "{name}"
        );
    }
    assert_eq!(environment.len(), 8);
}

#[test]
fn a_socks5_handshake_with_the_secret_succeeds_over_real_tcp() {
    let bound = bridge::bind(ProxyAuth::generate()).unwrap();
    let server = serve_socks_once(&bound.socks, bound.config.auth.clone());
    let mut client = connect(bound.config.socks_port);
    // The client offers both methods; the bridge must pick RFC 1929.
    assert_eq!(writes_greeting(&mut client, &[0, 2]), [5, 2]);
    let auth = &bound.config.auth;
    client
        .write_all(&userpass_frame(&auth.user, &auth.password))
        .unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).unwrap();
    assert_eq!(status, [1, 0]);
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
        .unwrap();
    assert_eq!(
        server.join().unwrap().expect("accepted").to_string(),
        "127.0.0.1:443"
    );
    // The success reply reaches the client through the real socket.
    let mut reply = [0; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn a_wrong_secret_fails_the_socks5_handshake_and_closes() {
    let bound = bridge::bind(ProxyAuth::generate()).unwrap();
    let server = serve_socks_once(&bound.socks, bound.config.auth.clone());
    let mut client = connect(bound.config.socks_port);
    assert_eq!(writes_greeting(&mut client, &[0, 2]), [5, 2]);
    let user = bound.config.auth.user.clone();
    client
        .write_all(&userpass_frame(&user, "not-the-secret"))
        .unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).unwrap();
    assert_eq!(status, [1, 1]);
    assert_eq!(
        server.join().unwrap().unwrap_err(),
        Reason::ProxyAuthRequired
    );
    // The bridge closes its side after the failure status.
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
}

#[test]
fn an_http_connect_without_the_secret_is_answered_407_over_real_tcp() {
    let bound = bridge::bind(ProxyAuth::generate()).unwrap();
    let server = serve_http_once(&bound.http, bound.config.auth.clone());
    let mut client = connect(bound.config.http_port);
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let response = std::str::from_utf8(&response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"),
        "{response:?}"
    );
    assert!(
        response.contains("Proxy-Authenticate: Basic realm=\"ukai\"\r\n"),
        "{response:?}"
    );
    assert_eq!(
        std::str::from_utf8(&server.join().unwrap()).unwrap(),
        response
    );
}

#[test]
fn an_http_connect_with_the_secret_is_accepted_over_real_tcp() {
    let bound = bridge::bind(ProxyAuth {
        user: "ukai".to_owned(),
        password: "secret".to_owned(),
    })
    .unwrap();
    let server = serve_http_once(&bound.http, bound.config.auth.clone());
    let mut client = connect(bound.config.http_port);
    client
        .write_all(
            format!(
                "CONNECT example.com:443 HTTP/1.1\r\n\
                 Proxy-Authorization: Basic {BASIC_CREDENTIALS}\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    assert_eq!(server.join().unwrap(), response);
}

#[test]
fn serving_relays_both_directions_and_drops_with_idle_connections() {
    use std::os::unix::net::UnixListener;
    let dir = common::private_tempdir();
    let path = dir.path().join("proxy");
    let proxy = UnixListener::bind(&path).unwrap();
    let bound = bridge::bind(ProxyAuth::generate()).unwrap();
    let port = bound.config.http_port;
    let serving = bridge::serve(bound, &path).unwrap();
    let mut client = connect(port);
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut upstream = accept_unix(&proxy);
    upstream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(b"request").unwrap();
    let mut request = [0u8; 7];
    upstream.read_exact(&mut request).unwrap();
    upstream.write_all(b"reply").unwrap();
    let mut reply = [0u8; 5];
    let response = client.read_exact(&mut reply);
    // A live idle connection must be cancelled too, not just the accept loops.
    let (sent, received) = std::sync::mpsc::channel();
    thread::spawn(move || {
        drop(serving);
        sent.send(()).unwrap();
    });
    let dropped = received.recv_timeout(Duration::from_secs(2));
    assert_eq!(request, *b"request");
    assert!(
        response.is_ok(),
        "upstream response never reached the child: {response:?}"
    );
    assert_eq!(reply, *b"reply");
    assert!(dropped.is_ok(), "Serving::drop did not finish within 2s");
}

#[test]
fn serving_drop_without_clients_is_bounded() {
    let dir = common::private_tempdir();
    let serving = bridge::serve(
        bridge::bind(ProxyAuth::generate()).unwrap(),
        &dir.path().join("unused"),
    )
    .unwrap();
    // Ensure both threads have entered their accept loop.
    thread::sleep(Duration::from_millis(50));
    let (sent, received) = std::sync::mpsc::channel();
    thread::spawn(move || {
        drop(serving);
        sent.send(()).unwrap();
    });
    assert!(received.recv_timeout(Duration::from_secs(2)).is_ok());
}

#[test]
fn a_wrong_http_basic_secret_is_answered_407() {
    let bound = bridge::bind(ProxyAuth {
        user: "ukai".into(),
        password: "actual-secret".into(),
    })
    .unwrap();
    let server = serve_http_once(&bound.http, bound.config.auth.clone());
    let mut client = connect(bound.config.http_port);
    client.write_all(format!("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {BASIC_CREDENTIALS}\r\n\r\n").as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 407 "), "{response}");
    server.join().unwrap();
}

#[test]
fn a_half_closed_request_receives_its_reply_and_drop_is_bounded() {
    use std::net::Shutdown;
    use std::os::unix::net::UnixListener;
    let dir = common::private_tempdir();
    let path = dir.path().join("proxy");
    let proxy = UnixListener::bind(&path).unwrap();
    let bound = bridge::bind(ProxyAuth::generate()).unwrap();
    let port = bound.config.http_port;
    let serving = bridge::serve(bound, &path).unwrap();
    let mut client = connect(port);
    let mut upstream = accept_unix(&proxy);
    upstream.set_read_timeout(Some(WAIT)).unwrap();
    upstream.set_write_timeout(Some(WAIT)).unwrap();
    client.write_all(b"half request").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut request = Vec::new();
    let received_request = upstream.read_to_end(&mut request);
    upstream.write_all(b"whole response").unwrap();
    upstream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    let received_response = client.read_to_end(&mut response);
    let (sent, received) = std::sync::mpsc::channel();
    thread::spawn(move || {
        drop(serving);
        let _ = sent.send(());
    });
    assert!(
        received.recv_timeout(Duration::from_secs(2)).is_ok(),
        "drop must remain bounded after half close"
    );
    assert!(received_request.is_ok(), "{received_request:?}");
    assert!(received_response.is_ok(), "{received_response:?}");
    assert_eq!(request, b"half request");
    assert_eq!(response, b"whole response");
}
