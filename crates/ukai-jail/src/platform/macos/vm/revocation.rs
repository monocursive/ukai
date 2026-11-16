//! A credential-source watch independent of guest-output delivery. Only IDs
//! cross this control lane. The captured generation never adopts replacements.
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::{POLL_STEP, control, protocol};
use crate::vault::lifecycle::Lease;

#[derive(Clone)]
pub(super) enum Sources {
    Local(Lease),
    Guest(crate::vault::transport::SourceLease),
}
impl Default for Sources {
    fn default() -> Self {
        Self::Local(Lease::default())
    }
}
impl From<Lease> for Sources {
    fn from(value: Lease) -> Self {
        Self::Local(value)
    }
}
impl Sources {
    pub(super) fn check(&self) -> Result<(), ()> {
        let valid = match self {
            Self::Local(lease) => lease.check().is_ok(),
            Self::Guest(lease) => lease.check(),
        };
        if valid { Ok(()) } else { Err(()) }
    }
    fn ids(&self) -> Vec<String> {
        match self {
            Self::Local(lease) => lease.ids(),
            Self::Guest(lease) => lease.ids(),
        }
    }
}

const WATCHING: u8 = 0;
const REQUESTED: u8 = 1;
const ACKNOWLEDGED: u8 = 2;
const SETTLED: u8 = 3;
const SEND_FAILED: u8 = 4;
const TIMED_OUT: u8 = 5;
const PANICKED: u8 = 6;
const STOPPED: u8 = 7;
const ACK_BUDGET: Duration = Duration::from_secs(2);
const JOIN_BUDGET: Duration = Duration::from_millis(100);

struct Shared {
    state: AtomicU8,
    deadline: OnceLock<Instant>,
}

pub(super) struct Watch {
    shared: Arc<Shared>,
    ids: Vec<String>,
    writer: UnixStream,
    stop: mpsc::Sender<()>,
    done: mpsc::Receiver<()>,
    worker: Option<JoinHandle<()>>,
}

/// Unwinding or an unexpected early worker exit revokes the exact attempt's
/// write half even if the main thread is blocked on the operator's stdout.
struct FailClosed<'a> {
    shared: &'a Shared,
    writer: &'a UnixStream,
    done: mpsc::Sender<()>,
}
impl Drop for FailClosed<'_> {
    fn drop(&mut self) {
        let state = self.shared.state.load(Ordering::Acquire);
        if std::thread::panicking() || !matches!(state, ACKNOWLEDGED | SETTLED | STOPPED) {
            if std::thread::panicking() || matches!(state, WATCHING | REQUESTED) {
                self.shared.state.store(PANICKED, Ordering::Release);
            }
            let _ = self.writer.shutdown(Shutdown::Write);
        }
        let _ = self.done.send(());
    }
}

impl Watch {
    pub(super) fn start(
        connection: &control::AttemptConnection,
        lease: Sources,
    ) -> Result<Self, String> {
        Self::start_check(
            connection.clone_writer().map_err(|e| e.to_string())?,
            lease.ids(),
            move || lease.check().is_ok(),
            POLL_STEP,
            ACK_BUDGET,
        )
    }

    fn start_check(
        writer: UnixStream,
        ids: Vec<String>,
        check: impl Fn() -> bool + Send + 'static,
        poll_step: Duration,
        ack_budget: Duration,
    ) -> Result<Self, String> {
        writer.set_nonblocking(true).map_err(|e| e.to_string())?;
        let shared = Arc::new(Shared {
            state: AtomicU8::new(WATCHING),
            deadline: OnceLock::new(),
        });
        let (stop, stopping) = mpsc::channel();
        let (done_sender, done) = mpsc::channel();
        let worker = if ids.is_empty() {
            None
        } else {
            let state = Arc::clone(&shared);
            let socket = writer.try_clone().map_err(|e| e.to_string())?;
            let request = protocol::encode(&protocol::ToVm::RevokeSecrets { ids: ids.clone() })
                .map_err(|e| e.to_string())?;
            Some(
                std::thread::Builder::new()
                    .name("vm-vault-lease".to_owned())
                    .spawn(move || {
                        let _guard = FailClosed {
                            shared: &state,
                            writer: &socket,
                            done: done_sender,
                        };
                        loop {
                            match state.state.load(Ordering::Acquire) {
                                WATCHING => {
                                    if !check() {
                                        // Deadline begins before sending, including any socket
                                        // backpressure; publication precedes a possible fast ACK.
                                        let deadline = Instant::now() + ack_budget;
                                        let _ = state.deadline.set(deadline);
                                        if state
                                            .state
                                            .compare_exchange(
                                                WATCHING,
                                                REQUESTED,
                                                Ordering::AcqRel,
                                                Ordering::Acquire,
                                            )
                                            .is_err()
                                        {
                                            continue;
                                        }
                                        let result = control::write_before(
                                            &socket,
                                            &request,
                                            deadline,
                                            || {
                                                matches!(
                                                    state.state.load(Ordering::Acquire),
                                                    SETTLED | STOPPED
                                                )
                                            },
                                        );
                                        if result.is_err() {
                                            // A verified settlement may race the pending send.
                                            let _ = state.state.compare_exchange(
                                                REQUESTED,
                                                SEND_FAILED,
                                                Ordering::AcqRel,
                                                Ordering::Acquire,
                                            );
                                            return;
                                        }
                                    }
                                }
                                REQUESTED => {
                                    if state
                                        .deadline
                                        .get()
                                        .is_none_or(|deadline| Instant::now() >= *deadline)
                                    {
                                        let _ = state.state.compare_exchange(
                                            REQUESTED,
                                            TIMED_OUT,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        );
                                        return;
                                    }
                                }
                                _ => return,
                            }
                            let wait = if state.state.load(Ordering::Acquire) == REQUESTED {
                                state
                                    .deadline
                                    .get()
                                    .unwrap()
                                    .saturating_duration_since(Instant::now())
                                    .min(Duration::from_millis(20))
                            } else {
                                poll_step
                            };
                            match stopping.recv_timeout(wait) {
                                Err(mpsc::RecvTimeoutError::Timeout) => {}
                                _ => return,
                            }
                        }
                    })
                    .map_err(|e| format!("credential watch could not start: {e}"))?,
            )
        };
        Ok(Self {
            shared,
            ids,
            writer,
            stop,
            done,
            worker,
        })
    }

    pub(super) fn check(&self) -> Result<(), String> {
        if self.shared.state.load(Ordering::Acquire) == REQUESTED
            && self
                .shared
                .deadline
                .get()
                .is_some_and(|deadline| Instant::now() >= *deadline)
            && self
                .shared
                .state
                .compare_exchange(REQUESTED, TIMED_OUT, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let _ = self.writer.shutdown(Shutdown::Write);
        }
        match self.shared.state.load(Ordering::Acquire) {
            SEND_FAILED => Err("credential revocation transport failed".to_owned()),
            TIMED_OUT => Err(
                "the guest did not acknowledge credential revocation within its budget".to_owned(),
            ),
            PANICKED => Err("the credential revocation watch stopped unexpectedly".to_owned()),
            _ => Ok(()),
        }
    }

    pub(super) fn acknowledge(&self, ids: &[String]) -> Result<(), String> {
        // Check the absolute deadline here too: a delayed worker wake must
        // never make an already-expired ACK acceptable.
        if ids != self.ids
            || self
                .shared
                .deadline
                .get()
                .is_none_or(|deadline| Instant::now() >= *deadline)
            || self
                .shared
                .state
                .compare_exchange(REQUESTED, ACKNOWLEDGED, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            let _ = self.writer.shutdown(Shutdown::Write);
            return Err(
                "the guest acknowledged unexpected or late credential revocation".to_owned(),
            );
        }
        // Do not accept an ACK if this thread was descheduled between the
        // initial time check and publishing acknowledgement.
        if self
            .shared
            .deadline
            .get()
            .is_none_or(|at| Instant::now() >= *at)
        {
            self.shared.state.store(TIMED_OUT, Ordering::Release);
            let _ = self.writer.shutdown(Shutdown::Write);
            return Err("the guest acknowledged late credential revocation".to_owned());
        }
        let _ = self.stop.send(());
        Ok(())
    }

    /// Only called after receipt, outcome, cleanup and outside tree witness
    /// verification. Settlement ends the authority; it is not a revocation ACK.
    pub(super) fn settled(&self) -> Result<(), String> {
        loop {
            self.check()?;
            let old = self.shared.state.load(Ordering::Acquire);
            if !matches!(old, WATCHING | REQUESTED | ACKNOWLEDGED | SETTLED) {
                continue;
            }
            if self
                .shared
                .state
                .compare_exchange(old, SETTLED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let _ = self.stop.send(());
                return Ok(());
            }
        }
    }

    #[cfg(test)]
    pub(super) fn acknowledged(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) == ACKNOWLEDGED
    }

    #[cfg(test)]
    pub(super) fn is_settled(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) == SETTLED
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // Do not let a cloned writer extend the attempt lease after its owner
        // drops. Shutdown is immediate even if a filesystem check stalls.
        let _ = self.writer.shutdown(Shutdown::Write);
        self.shared.state.store(STOPPED, Ordering::Release);
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            // Filesystem reads can stall in the kernel. Never join such a
            // worker indefinitely: it owns only the already-cancelled socket
            // clone and captured lease until it returns. No hard filesystem
            // read deadline is claimed by this output-independent watch.
            let deadline = Instant::now() + JOIN_BUDGET;
            let _ = self.done.recv_timeout(JOIN_BUDGET);
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::sync::atomic::AtomicBool;

    #[test]
    fn a_full_control_socket_spends_the_same_budget_and_then_half_closes() {
        let (mut writer, mut peer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let mut filled = 0;
        // A final one-byte probe ensures even the small revoke frame cannot
        // fit. No reader drains this connection until the watcher has exited.
        for buffer in [&[b'x'; 65536][..], &b"x"[..]] {
            loop {
                match writer.write(buffer) {
                    Ok(n) => filled += n,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    result => panic!("unexpected fill result: {result:?}"),
                }
                assert!(
                    filled < 16 * 1024 * 1024,
                    "socket never applied backpressure"
                );
            }
        }
        let start = Instant::now();
        let watch = Watch::start_check(
            writer,
            vec!["api".into()],
            || false,
            Duration::from_millis(10),
            Duration::from_millis(100),
        )
        .unwrap();
        watch.done.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(watch.check().is_err());
        assert!(!watch.acknowledged());
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut data = Vec::new();
        peer.read_to_end(&mut data).unwrap();
        assert_eq!(
            data,
            vec![b'x'; filled],
            "send never completed, but EOF must arrive"
        );
    }

    #[test]
    fn a_missing_or_unprocessed_ack_closes_the_lease_without_main_thread_polling() {
        let (writer, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let watch = Watch::start_check(
            writer,
            vec!["api".into()],
            || false,
            Duration::from_millis(10),
            Duration::from_millis(100),
        )
        .unwrap();
        let mut request = String::new();
        BufReader::new(&mut peer).read_line(&mut request).unwrap();
        assert!(request.contains("revoke_secrets"));
        let started = Instant::now();
        assert_eq!(
            peer.read(&mut [0]).unwrap(),
            0,
            "worker must half-close even without a main poll"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(watch.check().is_err());
        assert!(!watch.acknowledged());
    }

    #[test]
    fn a_worker_panic_cancels_its_exact_attempt() {
        let (writer, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let watch = Watch::start_check(
            writer,
            vec!["api".into()],
            || panic!("test watch panic"),
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert!(watch.check().is_err());
    }

    #[test]
    fn drop_is_bounded_even_if_a_filesystem_check_is_stalled() {
        let (writer, mut peer) = UnixStream::pair().unwrap();
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let (entered, observed) = mpsc::channel();
        let watch = Watch::start_check(
            writer,
            vec!["api".into()],
            move || {
                entered.send(()).unwrap();
                while !worker_release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                true
            },
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .unwrap();
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        drop(watch);
        let elapsed = started.elapsed();
        release.store(true, Ordering::Release);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn ack_cannot_win_after_the_absolute_deadline_even_if_worker_has_not_checked() {
        let (writer, mut peer) = UnixStream::pair().unwrap();
        let watch = Watch::start_check(
            writer,
            vec![],
            || true,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        watch
            .shared
            .deadline
            .set(Instant::now() - Duration::from_millis(1))
            .unwrap();
        watch.shared.state.store(REQUESTED, Ordering::Release);
        assert!(watch.acknowledge(&[]).is_err());
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert!(!watch.acknowledged());
    }
}
