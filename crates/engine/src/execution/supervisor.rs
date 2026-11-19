//! `WorkerSupervisor` (WE-P04, WC-003, ENG-033/035): owns one worker process,
//! its control channel, diagnostics drain and phase timers for one attempt.
//!
//! The attempt budget is the Store-created `Arc<AttemptTiming>` carried by the
//! `DispatchRecord`; the supervisor never creates, restarts or reconstructs it.
//! Phase bounds, the responsiveness probe, silence warnings and progress
//! coalescing are separate timers. Every exit path requests external
//! whole-tree termination; acknowledgement, EOF or a pong is never cleanup.
//! The worker's native identity is durably recorded through the
//! `LaunchLedger` right after a confirmed spawn and before any command; an
//! unrecorded worker is terminated without receiving one.
//! The result is a typed `AttemptExit`; nothing here commits an outcome.
use super::legality::{Observation, Phase, Session, SessionIdentity};
use super::progress::{AttemptPhase, ObservationUpdate, ProgressClass, ProgressCoalescer};
use super::types::{
    AttemptCleanup, AttemptEnd, AttemptExit, AttemptPlan, NeverLaunched, StopIntent,
};
use crate::store::cleanup::{AttemptRef, CleanupEvidence, fault_code};
use crate::store::execution::DispatchRecord;
use crate::store::launch_identity::LaunchRecord;
use crate::store::{CoreError, Store};
use crate::worker_protocol::{
    Assignment, CancelReason, CandidateReport, DiagnosticCapture, DiagnosticCategory, FrameDecoder,
    ProtocolViolation, decode_inbound,
};
use dissect3d_platform::{CleanupFault, WorkerIdentity};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

/// External termination of the whole worker tree. Only native closure
/// evidence (`CleanupEvidence`) confirms it.
pub(crate) trait SupervisedProcess: Send + 'static {
    /// The native identity established at spawn (creation evidence, not PID alone).
    fn identity(&self) -> WorkerIdentity;
    fn terminate_tree(&mut self, deadline: Instant) -> Result<CleanupEvidence, CleanupFault>;
}

/// Launch failures: whether any OS process may exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchFailure {
    /// Rejected before any process creation; nothing can survive.
    NotStarted,
    /// A process may exist without established ownership.
    Uncertain,
}

pub(crate) struct Launched<P, R, W, D> {
    pub(crate) process: P,
    pub(crate) control_from_worker: R,
    pub(crate) control_to_worker: W,
    pub(crate) diagnostics: D,
}

/// Blocking native launch of exactly one worker; runs off the runtime under
/// the launch bound. `launcher::PlatformLauncher` is the native implementation;
/// the in-memory fake exists only for codec/legality/timer tests.
pub(crate) trait WorkerLauncher: Send + 'static {
    type Process: SupervisedProcess;
    type Reader: AsyncRead + Unpin + Send + 'static;
    type Writer: AsyncWrite + Unpin + Send + 'static;
    type Diagnostics: AsyncRead + Unpin + Send + 'static;
    #[allow(clippy::type_complexity)]
    fn launch(
        self,
        session: &SessionIdentity,
    ) -> Result<Launched<Self::Process, Self::Reader, Self::Writer, Self::Diagnostics>, LaunchFailure>;
}

/// Durable record of a launched worker's identity (blocking; Store-backed in
/// production). It must succeed before the worker receives any command, so
/// restart recovery and the release check can bind cleanup to this worker.
pub(crate) trait LaunchLedger: Send + Sync + 'static {
    fn record_launch(&self, record: LaunchRecord) -> Result<(), CoreError>;
}
impl LaunchLedger for Store {
    fn record_launch(&self, record: LaunchRecord) -> Result<(), CoreError> {
        self.record_launch_identity(record)
    }
}

/// Safe cleanup code when the launch identity could not be durably recorded:
/// the Store would refuse a release, so holds stay until recovery (WE-P07).
pub(crate) const IDENTITY_UNRECORDED: &str = "cleanup_identity_unrecorded";

/// Control-channel reader/writer around the pure frame codec.
struct Control<R, W> {
    reader: R,
    writer: W,
    decoder: FrameDecoder,
    pending: Vec<u8>,
    offset: usize,
    eof: bool,
}
enum Inbound {
    Frame(String),
    Eof,
    Violation(ProtocolViolation),
}
impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Control<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            decoder: FrameDecoder::default(),
            pending: Vec::new(),
            offset: 0,
            eof: false,
        }
    }

    /// Cancel-safe: the only await is the read, and its bytes are stored
    /// before the next await.
    async fn next(&mut self) -> Inbound {
        let mut buffer = [0u8; 8192];
        loop {
            if let Some(frame) = self.decoder.next_frame() {
                return Inbound::Frame(frame);
            }
            if self.offset < self.pending.len() {
                match self.decoder.push(&self.pending[self.offset..]) {
                    Ok(used) => self.offset += used,
                    Err(violation) => return Inbound::Violation(violation),
                }
                continue;
            }
            if self.eof {
                return Inbound::Eof;
            }
            match self.reader.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    self.eof = true;
                    if let Err(violation) = self.decoder.finish() {
                        return Inbound::Violation(violation);
                    }
                }
                Ok(read) => {
                    self.pending.clear();
                    self.pending.extend_from_slice(&buffer[..read]);
                    self.offset = 0;
                }
            }
        }
    }

    /// Bounded write; a worker that stops reading cannot block supervision.
    async fn send(&mut self, frame: Vec<u8>, bound: Duration) -> bool {
        let write = async {
            self.writer.write_all(&frame).await?;
            self.writer.flush().await
        };
        matches!(tokio::time::timeout(bound, write).await, Ok(Ok(())))
    }
}

enum Verdict {
    Candidate(CandidateReport),
    End(AttemptEnd),
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}
fn remaining(at: Option<Instant>, fallback: Duration) -> Duration {
    at.map_or(fallback, |at| at.saturating_duration_since(Instant::now()))
}

struct Attempt<'a, R, W> {
    dispatch: &'a DispatchRecord,
    plan: &'a AttemptPlan,
    control: Control<R, W>,
    session: Session,
    coalescer: ProgressCoalescer,
    capture: Arc<Mutex<DiagnosticCapture>>,
    stop: watch::Receiver<StopIntent>,
    observations: &'a watch::Sender<Option<ObservationUpdate>>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Attempt<'_, R, W> {
    fn note(&self, category: DiagnosticCategory) {
        if let Ok(mut capture) = self.capture.lock() {
            capture.note(category);
        }
    }
    /// Enter a phase; a phase change is always offered for persistence.
    fn phase(&mut self, phase: AttemptPhase) {
        let update = self.coalescer.phase(phase, Instant::now());
        self.publish(update);
    }
    fn publish(&self, update: Option<ObservationUpdate>) {
        if let Some(update) = update {
            // Latest-only: a slow consumer sees the newest coalesced snapshot.
            self.observations.send_replace(Some(update));
        }
    }
    fn violation(&self) -> Verdict {
        self.note(DiagnosticCategory::ProtocolViolation);
        Verdict::End(AttemptEnd::ProtocolError)
    }

    /// Advance the protocol, returning the attempt's verdict.
    async fn drive(&mut self) -> Verdict {
        let limits = self.plan.limits;
        let timing = Arc::clone(&self.dispatch.timing);
        let mut phase_deadline = Some(Instant::now() + limits.handshake);
        let mut next_ping = Instant::now() + limits.ping_interval;
        let mut silent_since = Instant::now();
        loop {
            // Issue the next command when the session is ready for it.
            let issued = match self.session.phase() {
                Phase::Greeted => Some(self.session.configure(self.plan.resolution_handle.clone())),
                Phase::Configured => {
                    phase_deadline = Some(Instant::now() + limits.load);
                    self.phase(AttemptPhase::Loading);
                    Some(self.session.load(self.plan.resolution_handle.clone()))
                }
                Phase::Loaded => {
                    // The original budget, rechecked before permission (AD-01).
                    if timing.expired() {
                        self.note(DiagnosticCategory::DeadlineExceeded);
                        return Verdict::End(AttemptEnd::DeadlineExceeded);
                    }
                    phase_deadline = None;
                    silent_since = Instant::now();
                    self.phase(AttemptPhase::Executing);
                    Some(self.session.execute(
                        self.plan.inputs.clone(),
                        self.plan.output_staging_handle.clone(),
                        self.plan.effective_parameters_handle.clone(),
                    ))
                }
                _ => None,
            };
            if let Some(command) = issued {
                let Ok(frame) = command else {
                    return self.violation();
                };
                if !self
                    .control
                    .send(frame, remaining(phase_deadline, limits.handshake))
                    .await
                {
                    self.note(DiagnosticCategory::ControlUnresponsive);
                    return Verdict::End(AttemptEnd::WorkerFailed);
                }
                continue;
            }
            let executing = self.session.phase() == Phase::Executing;
            let silence_at = executing.then(|| silent_since + limits.silence_warning);
            let flush_at = self.coalescer.next_due();
            tokio::select! {
                biased;
                changed = self.stop.changed() => {
                    let intent = match changed {
                        Ok(()) => *self.stop.borrow_and_update(),
                        // The controller is gone: stop as for shutdown.
                        Err(_) => StopIntent::EngineShutdown,
                    };
                    if intent != StopIntent::Continue {
                        return Verdict::End(AttemptEnd::Stopped(intent));
                    }
                }
                () = sleep_until(timing.deadline()) => {
                    self.note(DiagnosticCategory::DeadlineExceeded);
                    return Verdict::End(AttemptEnd::DeadlineExceeded);
                }
                () = sleep_until(phase_deadline) => {
                    self.note(DiagnosticCategory::ControlUnresponsive);
                    return Verdict::End(AttemptEnd::WorkerFailed);
                }
                inbound = self.control.next() => {
                    let frame = match inbound {
                        Inbound::Frame(text) => text,
                        Inbound::Violation(_) => return self.violation(),
                        // Exit or closed control before a final report.
                        Inbound::Eof => return Verdict::End(AttemptEnd::WorkerFailed),
                    };
                    let observation = match decode_inbound(&frame)
                        .and_then(|frame| self.session.accept(frame))
                    {
                        Ok(observation) => observation,
                        Err(_) => return self.violation(),
                    };
                    match observation {
                        Observation::Candidate(report) => return Verdict::Candidate(report),
                        Observation::LoadFailed
                        | Observation::Rejected
                        | Observation::ExecutionFailed => {
                            self.note(DiagnosticCategory::WorkerDeclaredFailure);
                            return Verdict::End(AttemptEnd::WorkerFailed);
                        }
                        Observation::Progress { stage, fraction } => {
                            silent_since = Instant::now();
                            let (class, update) =
                                self.coalescer.report(&stage, fraction, Instant::now());
                            match class {
                                ProgressClass::Known => {}
                                ProgressClass::UnknownFraction => {
                                    self.note(DiagnosticCategory::UnknownProgress)
                                }
                                ProgressClass::UnlistedStage => {
                                    self.note(DiagnosticCategory::UnlistedStage)
                                }
                            }
                            self.publish(update);
                        }
                        // Responsiveness only: no bound, deadline or progress moves.
                        Observation::Pong
                        | Observation::Hello
                        | Observation::Configured
                        | Observation::Loaded
                        | Observation::CancelAcknowledged
                        | Observation::Released
                        | Observation::ShutdownAcknowledged => {}
                    }
                }
                () = sleep_until(Some(next_ping)) => {
                    next_ping = Instant::now() + limits.ping_interval;
                    if self.session.ping_outstanding() {
                        // Unresponsive control warns; it never fails the job.
                        self.note(DiagnosticCategory::ControlUnresponsive);
                    } else if let Ok(Some(ping)) = self.session.ping()
                        && !self.control.send(ping, limits.handshake).await
                    {
                        self.note(DiagnosticCategory::ControlUnresponsive);
                    }
                }
                () = sleep_until(flush_at) => {
                    let update = self.coalescer.flush(Instant::now());
                    self.publish(update);
                }
                () = sleep_until(silence_at) => {
                    self.note(DiagnosticCategory::SilentStage);
                    silent_since = Instant::now();
                }
            }
        }
    }

    /// Cooperative stop within its own bound; then external termination
    /// always follows. Late reports (including a candidate) are ignored.
    async fn cooperate(&mut self, verdict: &Verdict) {
        let limits = self.plan.limits;
        let reason = match verdict {
            Verdict::Candidate(_) => {
                if let Ok(frame) = self.session.shutdown("attempt_complete")
                    && self.control.send(frame, limits.shutdown).await
                {
                    self.await_ack(
                        |o| matches!(o, Observation::ShutdownAcknowledged),
                        limits.shutdown,
                    )
                    .await;
                }
                return;
            }
            Verdict::End(AttemptEnd::DeadlineExceeded) => CancelReason::Deadline,
            Verdict::End(AttemptEnd::Stopped(StopIntent::UserCancel)) => CancelReason::UserCancel,
            Verdict::End(AttemptEnd::Stopped(_)) => CancelReason::EngineShutdown,
            // Protocol errors and failures are contained without cooperation.
            Verdict::End(_) => return,
        };
        if let Ok(frame) = self.session.cancel(reason)
            && self.control.send(frame, limits.cooperative_cancel).await
        {
            self.await_ack(
                |o| matches!(o, Observation::CancelAcknowledged),
                limits.cooperative_cancel,
            )
            .await;
        }
    }

    async fn await_ack(&mut self, wanted: fn(&Observation) -> bool, bound: Duration) {
        let deadline = tokio::time::Instant::now() + bound;
        while let Ok(Inbound::Frame(text)) =
            tokio::time::timeout_at(deadline, self.control.next()).await
        {
            // Termination follows regardless; stopping traffic stays bounded.
            if let Ok(observation) = decode_inbound(&text).and_then(|f| self.session.accept(f))
                && wanted(&observation)
            {
                return;
            }
        }
    }
}

async fn terminate<P: SupervisedProcess>(mut process: P, bound: Duration) -> AttemptCleanup {
    let deadline = Instant::now() + bound;
    let task = tokio::task::spawn_blocking(move || process.terminate_tree(deadline));
    // The blocking call keeps ownership if it outlives this bound; the
    // uncertainty is reported and holds stay (WE-004: no bound proves cleanup).
    match tokio::time::timeout(bound, task).await {
        Ok(Ok(Ok(evidence))) => AttemptCleanup::Confirmed(evidence),
        Ok(Ok(Err(fault))) => AttemptCleanup::Fault(fault_code(fault)),
        Ok(Err(_)) => AttemptCleanup::Fault(fault_code(CleanupFault::NativeFailure)),
        Err(_) => AttemptCleanup::Fault(fault_code(CleanupFault::Deadline)),
    }
}

pub(crate) struct WorkerSupervisor;

impl WorkerSupervisor {
    /// Supervise one attempt end to end. `ledger` durably records the launch
    /// identity; `observations` receives coalesced phase/progress snapshots
    /// for the Store (latest only).
    pub(crate) async fn run<L: WorkerLauncher, K: LaunchLedger>(
        dispatch: &DispatchRecord,
        plan: AttemptPlan,
        launcher: L,
        ledger: Arc<K>,
        stop: watch::Receiver<StopIntent>,
        observations: &watch::Sender<Option<ObservationUpdate>>,
    ) -> AttemptExit {
        let capture = Arc::new(Mutex::new(DiagnosticCapture::default()));
        let summary = |capture: &Arc<Mutex<DiagnosticCapture>>| {
            capture
                .lock()
                .map(|c| c.summary())
                .unwrap_or_else(|_| DiagnosticCapture::default().summary())
        };
        let ended = |end, cleanup, capture: &Arc<Mutex<DiagnosticCapture>>| AttemptExit::Ended {
            end,
            cleanup,
            diagnostics: summary(capture),
        };
        let note = |category| {
            if let Ok(mut c) = capture.lock() {
                c.note(category);
            }
        };
        let intent = *stop.borrow();
        if intent != StopIntent::Continue {
            return ended(
                AttemptEnd::Stopped(intent),
                AttemptCleanup::NeverLaunched(NeverLaunched::new()),
                &capture,
            );
        }
        // The Store's original budget; a late start gets no new one (AD-01).
        if dispatch.timing.expired() {
            note(DiagnosticCategory::DeadlineExceeded);
            return ended(
                AttemptEnd::DeadlineExceeded,
                AttemptCleanup::NeverLaunched(NeverLaunched::new()),
                &capture,
            );
        }
        let limits = plan.limits;
        if !limits.within_contract() {
            note(DiagnosticCategory::LaunchFailed);
            return ended(
                AttemptEnd::LaunchFailed,
                AttemptCleanup::NeverLaunched(NeverLaunched::new()),
                &capture,
            );
        }
        let identity = SessionIdentity {
            session_id: dispatch.session_id.clone(),
            grant_id: dispatch.grant_id.clone(),
            assignment: Assignment {
                job_id: dispatch.job_id.as_str().to_owned(),
                attempt_id: dispatch.attempt_id.clone(),
            },
        };
        let launch_identity = identity.clone();
        let launch_deadline = tokio::time::Instant::now() + limits.launch;
        let launch = tokio::task::spawn_blocking(move || launcher.launch(&launch_identity));
        let launched = match tokio::time::timeout_at(launch_deadline, launch).await {
            Ok(Ok(Ok(launched))) => launched,
            Ok(Ok(Err(LaunchFailure::NotStarted))) => {
                note(DiagnosticCategory::LaunchFailed);
                return ended(
                    AttemptEnd::LaunchFailed,
                    AttemptCleanup::NeverLaunched(NeverLaunched::new()),
                    &capture,
                );
            }
            // Uncertain, panicked or still running past the launch bound.
            _ => {
                note(DiagnosticCategory::LaunchFailed);
                note(DiagnosticCategory::CleanupFault);
                return ended(
                    AttemptEnd::LaunchFailed,
                    AttemptCleanup::Fault("cleanup_launch_unverified"),
                    &capture,
                );
            }
        };
        // Record the native identity within the launch bound, before any
        // command. Failure, rejection or timeout (the write may still land)
        // leaves ownership undurable: no command is sent, the tree is
        // terminated, and holds stay because the Store would refuse release.
        let record = LaunchRecord {
            attempt: AttemptRef::from(dispatch),
            identity: launched.process.identity(),
        };
        let write = tokio::task::spawn_blocking(move || ledger.record_launch(record));
        if !matches!(
            tokio::time::timeout_at(launch_deadline, write).await,
            Ok(Ok(Ok(())))
        ) {
            note(DiagnosticCategory::LaunchFailed);
            note(DiagnosticCategory::CleanupFault);
            let Launched { process, .. } = launched;
            let cleanup = match terminate(process, limits.termination).await {
                AttemptCleanup::Confirmed(_) => AttemptCleanup::Fault(IDENTITY_UNRECORDED),
                other => other,
            };
            return ended(AttemptEnd::LaunchFailed, cleanup, &capture);
        }
        let Launched {
            process,
            control_from_worker,
            control_to_worker,
            mut diagnostics,
        } = launched;
        // Drain diagnostics separately so a full pipe cannot block the worker;
        // bytes past the cap are counted and discarded. Aborted after cleanup:
        // a surviving descendant may keep the pipe open.
        let drain_capture = Arc::clone(&capture);
        let drain = tokio::spawn(async move {
            let mut buffer = [0u8; 8192];
            while let Ok(read @ 1..) = diagnostics.read(&mut buffer).await {
                if let Ok(mut capture) = drain_capture.lock() {
                    capture.capture(&buffer[..read]);
                }
            }
        });
        let mut attempt = Attempt {
            dispatch,
            plan: &plan,
            control: Control::new(control_from_worker, control_to_worker),
            session: Session::new(identity, plan.expectation.clone()),
            coalescer: ProgressCoalescer::new(
                AttemptPhase::Handshake,
                limits.progress_interval,
                plan.stages,
            ),
            capture: Arc::clone(&capture),
            stop,
            observations,
        };
        let initial = attempt.coalescer.flush(Instant::now());
        attempt.publish(initial);
        let verdict = attempt.drive().await;
        attempt.phase(AttemptPhase::Stopping);
        attempt.cooperate(&verdict).await;
        drop(attempt);
        let cleanup = terminate(process, limits.termination).await;
        drain.abort();
        if matches!(cleanup, AttemptCleanup::Fault(_)) {
            note(DiagnosticCategory::CleanupFault);
        }
        match (verdict, cleanup) {
            (Verdict::Candidate(report), AttemptCleanup::Confirmed(evidence)) => {
                AttemptExit::Candidate {
                    report,
                    cleanup: evidence,
                    diagnostics: summary(&capture),
                }
            }
            (Verdict::Candidate(_), cleanup) => {
                ended(AttemptEnd::CleanupUnconfirmed, cleanup, &capture)
            }
            (Verdict::End(end), cleanup) => ended(end, cleanup, &capture),
        }
    }
}
