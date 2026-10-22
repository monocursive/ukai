use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::JoinHandle;
use std::time::Duration;

use super::{ObserveClient, ObserveJournal};
use crate::observer::CoverageSummary;
use crate::platform::macos::es::EsNewResult;
use crate::trace::SharedTrace;

#[derive(Debug)]
pub enum ObserveStartError {
    Client(EsNewResult),
    Setup(&'static str),
    Worker(std::io::Error),
}
impl std::fmt::Display for ObserveStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "observation could not start: {self:?}")
    }
}
impl std::error::Error for ObserveStartError {}

/// Start after custody and before release. Failure must refuse required
/// observation before exec. While running, the worker continuously consumes the
/// bounded shim ring; finish only after custody has stopped the workload.
///
/// `fs.write` remains degraded for uncovered mutations, so attaching this API
/// alone does not make strict full-mutation evidence available.
pub struct ObserveRun {
    stop: Option<SyncSender<()>>,
    worker: Option<JoinHandle<ObserveJournal>>,
    attempt_id: String,
    trace: SharedTrace,
    workspace: Vec<u8>,
}
impl ObserveRun {
    pub fn start(
        attempt_id: &str,
        trace: SharedTrace,
        workspace: &[u8],
        muted_tokens: &[[u32; 8]],
    ) -> Result<Self, ObserveStartError> {
        if trace.is_poisoned() {
            return Err(ObserveStartError::Setup("trace_writer_poisoned"));
        }
        let workspace = canonical_workspace(workspace)?;
        let mut client = ObserveClient::new().map_err(ObserveStartError::Client)?;
        if !client.unmute_all() || !client.verify_unmuted() {
            return Err(ObserveStartError::Setup("paths_still_muted"));
        }
        // Every jail helper is excluded, not only the supervisor. No ES process
        // mute is installed: it could hide a new image or an instigated child.
        for token in muted_tokens {
            if !client.exclude_token(token) {
                return Err(ObserveStartError::Setup("helper_exclusion_failed"));
            }
        }
        if !client.subscribe() {
            return Err(ObserveStartError::Setup("subscribe_failed"));
        }
        let journal = ObserveJournal::new(attempt_id, Some(trace.clone()), &workspace);
        let (stop, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("ukai-observe".into())
            .spawn(move || consume(client, journal, receiver))
            .map_err(ObserveStartError::Worker)?;
        Ok(Self {
            stop: Some(stop),
            worker: Some(worker),
            attempt_id: attempt_id.into(),
            trace,
            workspace,
        })
    }

    /// Drains (bounded to one second), deletes the ES client, and merges only
    /// observation into the caller's known coverage (e.g. proxy/limits).
    #[must_use]
    pub fn finish(mut self, mut known: CoverageSummary) -> CoverageSummary {
        known.attached = true;
        self.finish_inner().summary(known)
    }

    fn finish_inner(&mut self) -> ObserveJournal {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.worker.take().expect("one finish per observer").join() {
            Ok(journal) => journal,
            Err(_) => {
                let mut journal = ObserveJournal::new(
                    &self.attempt_id,
                    Some(self.trace.clone()),
                    &self.workspace,
                );
                journal.mark_gap("observation_worker_panicked");
                journal
            }
        }
    }
}
impl Drop for ObserveRun {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.finish_inner();
        }
    }
}

/// Resolve the directory before ES attaches. The kernel's F_GETPATH resolves
/// symlinks (including /var -> /private/var) and returns the stored case on a
/// case-insensitive volume; realpath alone can preserve the caller's spelling.
/// Only this preparation touches the namespace: event paths must not be looked
/// up after delivery, when renames or unlinks may already have happened.
fn canonical_workspace(workspace: &[u8]) -> Result<Vec<u8>, ObserveStartError> {
    if !workspace.starts_with(b"/") || workspace.contains(&0) {
        return Err(ObserveStartError::Setup("workspace_not_absolute"));
    }
    use std::os::fd::AsRawFd;
    use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(std::path::Path::new(std::ffi::OsStr::from_bytes(workspace)))
        .map_err(|_| ObserveStartError::Setup("workspace_unresolvable"))?;
    let mut path = [0u8; libc::PATH_MAX as usize];
    // SAFETY: directory owns a live fd; F_GETPATH writes at most PATH_MAX bytes
    // into the supplied buffer. The fd stays open through the call.
    if unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } < 0 {
        return Err(ObserveStartError::Setup("workspace_path_unavailable"));
    }
    let end = path
        .iter()
        .position(|byte| *byte == 0)
        .filter(|end| *end > 0 && path[0] == b'/')
        .ok_or(ObserveStartError::Setup("workspace_path_unavailable"))?;
    Ok(path[..end].to_vec())
}

// This seam exercises the same worker loop with a deterministic synthetic source.
trait Source {
    fn poll_message(&mut self) -> Option<super::ObsMessage>;
    fn gap(&self) -> bool;
    fn dropped(&self) -> u64;
    fn invalid(&self) -> bool;
    fn drain(&mut self, timeout_ms: u32) -> bool;
    fn delete(self) -> bool;
}
impl Source for ObserveClient {
    fn poll_message(&mut self) -> Option<super::ObsMessage> {
        ObserveClient::poll_message(self)
    }
    fn gap(&self) -> bool {
        ObserveClient::gap(self)
    }
    fn dropped(&self) -> u64 {
        ObserveClient::dropped(self)
    }
    fn invalid(&self) -> bool {
        ObserveClient::invalid(self)
    }
    fn drain(&mut self, timeout_ms: u32) -> bool {
        ObserveClient::drain(self, timeout_ms)
    }
    fn delete(self) -> bool {
        ObserveClient::delete(self)
    }
}

fn poll(client: &mut impl Source, journal: &mut ObserveJournal) {
    // Bound each batch so heavy producers cannot starve stop processing.
    for _ in 0..1024 {
        let Some(message) = client.poll_message() else {
            break;
        };
        journal.record_message(&message);
    }
    // Consume both the sticky flag and exact ring-drop count, including drops
    // after the last delivered event (no later sequence can reveal those).
    if client.gap() {
        journal.record_shim_loss(client.dropped(), client.invalid());
    }
}
fn consume(
    mut client: impl Source,
    mut journal: ObserveJournal,
    stop: Receiver<()>,
) -> ObserveJournal {
    loop {
        poll(&mut client, &mut journal);
        match stop.recv_timeout(Duration::from_millis(5)) {
            Err(RecvTimeoutError::Timeout) => continue,
            _ => break,
        }
    }
    if !client.drain(1000) {
        journal.mark_gap("observation_drain_timeout");
    }
    poll(&mut client, &mut journal);
    if !client.delete() {
        journal.mark_gap("observation_delete_failed");
    }
    journal
}

#[cfg(test)]
mod tests {
    use super::super::{ObsAction, ObsEvent, ObsKind, ObsMessage};
    use super::*;
    use crate::observer::CoverageClass;
    use crate::records::SourceStatus;
    use crate::trace::{self, FileSink};
    #[test]
    fn r3_workspace_alias_matches_es_real_paths() {
        let workspace = canonical_workspace(b"/var").unwrap();
        assert_eq!(
            super::super::classify_path(b"/private/var/observed", &workspace),
            super::super::PathEvidence::WorkspaceRelative(b"observed".to_vec())
        );
    }

    #[test]
    fn r3_workspace_uses_on_disk_case_and_resolves_links() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap().join("MiXeD-Workspace");
        std::fs::create_dir(&real).unwrap();
        let case_variant = real.with_file_name("mixed-workspace");
        if case_variant.try_exists().unwrap() {
            let workspace = canonical_workspace(case_variant.as_os_str().as_bytes()).unwrap();
            assert_eq!(workspace, real.as_os_str().as_bytes());
            assert_eq!(
                super::super::classify_path(
                    real.join("observed").as_os_str().as_bytes(),
                    &workspace
                ),
                super::super::PathEvidence::WorkspaceRelative(b"observed".to_vec())
            );
        } else {
            // Case-sensitive volumes must refuse the non-existent variant.
            assert!(canonical_workspace(case_variant.as_os_str().as_bytes()).is_err());
        }
        let link = dir.path().join("workspace-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            canonical_workspace(link.as_os_str().as_bytes()).unwrap(),
            real.as_os_str().as_bytes()
        );
    }

    #[test]
    fn r3_start_refuses_unresolvable_workspace_before_creating_an_es_client() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"file").unwrap();
        for path in [file, dir.path().join("missing")] {
            let trace = trace::shared(FileSink::new(tempfile::tempfile().unwrap()));
            let result = ObserveRun::start("attempt", trace, path.as_os_str().as_bytes(), &[]);
            assert!(
                matches!(result, Err(ObserveStartError::Setup(_))),
                "invalid workspace must fail before ES setup"
            );
        }
    }

    struct Synthetic {
        next: u64,
        available: u64,
        loss: u64,
        drain_ok: bool,
        delete_ok: bool,
    }
    impl Source for Synthetic {
        fn poll_message(&mut self) -> Option<ObsMessage> {
            if self.next == self.available {
                return None;
            }
            let seq = self.next;
            self.next += 1;
            Some(ObsMessage {
                event: ObsEvent {
                    kind: ObsKind::Exec,
                    global_seq: seq,
                    seq,
                    token: [7; 8],
                    path: b"/bin/tool".to_vec(),
                },
                event_type: 1,
                action: ObsAction::Exec,
                path2: None,
                ignored: false,
            })
        }
        fn gap(&self) -> bool {
            self.loss > 0
        }
        fn dropped(&self) -> u64 {
            self.loss
        }
        fn invalid(&self) -> bool {
            false
        }
        fn drain(&mut self, timeout_ms: u32) -> bool {
            assert_eq!(timeout_ms, 1000);
            self.available += 1;
            self.drain_ok
        }
        fn delete(self) -> bool {
            assert_eq!(
                self.next, self.available,
                "drain event consumed before delete"
            );
            self.delete_ok
        }
    }
    fn run(source: Synthetic) -> ObserveJournal {
        let trace = trace::shared(FileSink::new(tempfile::tempfile().unwrap()));
        let journal = ObserveJournal::new(
            "att_00000000-0000-4000-8000-000000000001",
            Some(trace),
            b"/w",
        );
        let (stop, receiver) = mpsc::sync_channel(1);
        stop.send(()).unwrap();
        consume(source, journal, receiver)
    }
    #[test]
    fn worker_consumes_events_and_drains_before_deleting() {
        let journal = run(Synthetic {
            next: 0,
            available: 1,
            loss: 0,
            drain_ok: true,
            delete_ok: true,
        });
        assert_eq!(journal.count(CoverageClass::Exec), 2);
        assert_eq!(
            journal.summary(CoverageSummary::applied(true)).classes[&CoverageClass::Exec].status,
            SourceStatus::Active
        );
    }
    #[test]
    fn worker_reads_shim_loss_and_records_both_shutdown_failures() {
        let journal = run(Synthetic {
            next: 0,
            available: 1,
            loss: 7,
            drain_ok: false,
            delete_ok: false,
        });
        let gaps = journal.gaps();
        assert_eq!(
            gaps.iter()
                .find(|g| g.reason == "observation_ring_overflowed")
                .unwrap()
                .lost_count,
            Some(7)
        );
        assert!(gaps.iter().any(|g| g.reason == "observation_drain_timeout"));
        assert!(gaps.iter().any(|g| g.reason == "observation_delete_failed"));
        assert_eq!(
            journal.summary(CoverageSummary::applied(true)).classes[&CoverageClass::Exec].status,
            SourceStatus::Degraded
        );
    }
}
