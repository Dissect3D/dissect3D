//! The execution controller (WE-P06; WE-002/003/004, RP-003). One owner task
//! runs every dispatch turn, so a committed `DispatchRecord` is launched once.
//!
//! For each committed attempt the owner first registers the attempt's stop
//! handle, keyed by attempt ID, and only then starts the attempt task. A
//! cancellation that finds the registered handle therefore reaches the
//! supervisor before or during launch, never after a missed window. A record
//! whose attempt ID is already registered (the Store's duplicate path returns
//! the live record) is never launched a second time.
//!
//! An attempt task runs on its own and is never dropped by the owner: once a
//! dispatch is committed it always reaches supervision cleanup and exactly
//! one routing step. A candidate goes to `publication::service::publish`, the
//! only path that succeeds a job; an ended attempt goes to finalization with
//! its cleanup facts. `NotOwned` and `Uncertain` are recorded for restart
//! reconciliation (WE-P07) and never retried. "Not owned" is not proof that
//! another writer finished the attempt, so the controller neither releases
//! nor forgets anything for it; the Store keeps whatever holds it has.
//!
//! The SQLite queue stays authoritative; the controller keeps no queue. A
//! turn runs at start, after every attempt ends, and on `wake`.
//!
//! The controller also records which workers it holds loaded (`loaded`) for
//! discovery: from the supervisor's first `executing` phase until the
//! attempt's cleanup is confirmed.
use super::loaded::{LoadedProfile, LoadedWorkers};
use super::scheduler::{DispatchStore, Eligibility, dispatch_turn, queued_blockers};
use super::shutdown::ShutdownClock;
use super::supervisor::{LaunchLedger, WorkerLauncher, WorkerSupervisor};
use super::types::{
    AttemptCleanup, AttemptEnd, AttemptExit, AttemptPlan, NeverLaunched, StopIntent,
};
use crate::CoreError;
use crate::execution::progress::{AttemptPhase, ObservationUpdate};
use crate::publication::service::{PublicationStore, PublishOutcome, PublishRequest, publish};
use crate::store::cleanup::AttemptRef;
use crate::store::execution::{DispatchRecord, QueuedCandidate};
use crate::store::finalize::{AttemptFinalization, AttemptObservation};
use dissect3d_api::{InputIdentity, JobId};
use dissect3d_platform::{AttemptRoot, OwnedRoot, PrivateInputReader};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, watch};

/// Most unreconciled entries kept; later ones are counted only.
const UNRECONCILED_MAX: usize = 64;

/// Finite controller bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutionLimits {
    /// Concurrent attempts. The CPU fixture profile runs one (WE-002).
    pub(crate) max_active: usize,
}
impl ExecutionLimits {
    pub(crate) const CONTROLLED: Self = Self { max_active: 1 };
}

/// One prepared attempt: its private files, verified launch and the inputs
/// publication re-verifies.
pub(crate) struct PreparedAttempt<L> {
    pub(crate) plan: AttemptPlan,
    pub(crate) launcher: L,
    pub(crate) staging: AttemptRoot,
    pub(crate) input: InputIdentity,
    pub(crate) input_reader: PrivateInputReader,
}

/// Verified prepared support, readiness and captured inputs, held outside
/// the Store (WE-P06/3 supplies the real one).
pub(crate) trait AttemptSource: Send + Sync + 'static {
    type Launcher: WorkerLauncher;
    /// Blocking eligibility of one queued job; reserves nothing.
    fn eligibility(&self, candidate: &QueuedCandidate) -> Eligibility;
    /// Blocking: create this attempt's private files and verified launch.
    /// A refusal means no process was started.
    fn prepare(&self, record: &DispatchRecord) -> Result<PreparedAttempt<Self::Launcher>, ()>;
}

/// The Store operations the controller needs.
pub(crate) trait ControllerStore:
    DispatchStore + PublicationStore + LaunchLedger + Send + Sync + 'static
{
    fn observe(&self, observation: AttemptObservation) -> Result<(), CoreError>;
    /// The committed stop intent of this instance's running attempt.
    fn stop_intent(&self, attempt: AttemptRef) -> Result<StopIntent, CoreError>;
}
impl ControllerStore for crate::Store {
    fn observe(&self, observation: AttemptObservation) -> Result<(), CoreError> {
        self.record_attempt_observation(observation).map(|_| ())
    }
    fn stop_intent(&self, attempt: AttemptRef) -> Result<StopIntent, CoreError> {
        self.attempt_stop_intent(attempt)
    }
}

/// Why an attempt or dispatch could not be settled by this instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unreconciled {
    /// A dispatch whose commit could not be established.
    Dispatch(JobId),
    /// The Store refused the attempt's outcome as not this instance's.
    NotOwned { job_id: JobId, attempt_id: String },
    /// Neither commit nor finalization could be established.
    Uncertain { job_id: JobId, attempt_id: String },
    /// A dispatch turn failed; records it may have committed are unknown.
    Turn,
}

#[derive(Default)]
struct Report {
    unreconciled: Vec<Unreconciled>,
    overflow: u64,
}
impl Report {
    fn push(&mut self, entry: Unreconciled) {
        if self.unreconciled.len() < UNRECONCILED_MAX {
            self.unreconciled.push(entry);
        } else {
            self.overflow += 1;
        }
    }
}

/// Stop handles of running attempts, keyed by attempt ID.
#[derive(Default)]
pub(crate) struct StopRegistry(Mutex<HashMap<String, (JobId, watch::Sender<StopIntent>)>>);
impl StopRegistry {
    /// Register before launch; `None` if this attempt is already registered.
    fn register(&self, record: &DispatchRecord) -> Option<watch::Receiver<StopIntent>> {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&record.attempt_id) {
            return None;
        }
        let (sender, receiver) = watch::channel(StopIntent::Continue);
        map.insert(record.attempt_id.clone(), (record.job_id.clone(), sender));
        Some(receiver)
    }
    fn remove(&self, attempt_id: &str) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(attempt_id);
    }
    /// Deliver a committed stop intent to the job's running attempt. The
    /// first intent stays; returns whether an attempt was registered.
    pub(crate) fn signal(&self, job_id: &JobId, intent: StopIntent) -> bool {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut found = false;
        for (job, sender) in map.values() {
            if job == job_id {
                found = true;
                sender.send_if_modified(|current| {
                    let first = *current == StopIntent::Continue && intent != StopIntent::Continue;
                    if first {
                        *current = intent;
                    }
                    first
                });
            }
        }
        found
    }
    /// Deliver an engine-wide stop intent to every registered attempt; each
    /// keeps an earlier intent (a user cancellation stays a cancellation).
    fn signal_all(&self, intent: StopIntent) {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for (_, sender) in map.values() {
            sender.send_if_modified(|current| {
                let first = *current == StopIntent::Continue && intent != StopIntent::Continue;
                if first {
                    *current = intent;
                }
                first
            });
        }
    }
}

pub(crate) struct ExecutionDependencies<S, A> {
    pub(crate) store: Arc<S>,
    pub(crate) root: Arc<OwnedRoot>,
    pub(crate) source: Arc<A>,
    pub(crate) limits: ExecutionLimits,
}

/// The running controller. Dropping every handle stops new turns; attempts
/// already dispatched still run to their outcome.
pub(crate) struct ExecutionHandle {
    wake: mpsc::Sender<()>,
    owned: Arc<Owned>,
}

/// State the owner task and every handle share.
struct Owned {
    stops: StopRegistry,
    report: Mutex<Report>,
    blocked: Mutex<HashMap<JobId, &'static str>>,
    loaded: Arc<LoadedWorkers>,
    /// The engine's shutdown deadline once shutdown began (WE-P07/3).
    clock: ShutdownClock,
    /// Shutdown began: no further dispatch turns.
    stopping: AtomicBool,
    /// Attempts dispatched and not yet routed to an outcome.
    active: watch::Sender<usize>,
}

impl ExecutionHandle {
    /// Ask for a dispatch turn (new acceptance or readiness change).
    /// Coalesces with a turn already requested.
    pub(crate) fn wake(&self) {
        let _ = self.wake.try_send(());
    }
    /// Deliver a durably committed stop intent (see `StopRegistry::signal`).
    pub(crate) fn signal(&self, job_id: &JobId, intent: StopIntent) -> bool {
        self.owned.stops.signal(job_id, intent)
    }
    /// A queued job's blocker as of the latest eligibility scan; `None` when
    /// it is eligible and waits for its turn, or is not queued.
    pub(crate) fn blocker(&self, job_id: &JobId) -> Option<&'static str> {
        let blocked = self.owned.blocked.lock().unwrap_or_else(|e| e.into_inner());
        blocked.get(job_id).copied()
    }
    /// The workers this controller holds loaded, for discovery observations.
    pub(crate) fn loaded(&self) -> Arc<LoadedWorkers> {
        Arc::clone(&self.owned.loaded)
    }
    /// Attempts and dispatches left for restart reconciliation, and how many
    /// more were not kept.
    pub(crate) fn unreconciled(&self) -> (Vec<Unreconciled>, u64) {
        let report = self.owned.report.lock().unwrap_or_else(|e| e.into_inner());
        (report.unreconciled.clone(), report.overflow)
    }

    /// WE-P07/3, WE-005: stop for engine shutdown within the core deadline.
    /// The Store's shutdown barrier is already committed, so nothing new
    /// dispatches or publishes; this stops further turns, delivers
    /// `EngineShutdown` to every running attempt (an earlier user
    /// cancellation stays), and waits for every attempt to reach its outcome.
    /// Each attempt's cooperative and termination phases are capped by the
    /// time left. `Clean` only when every attempt ended in time with
    /// confirmed cleanup and a settled outcome; otherwise the stop is
    /// reported unconfirmed, never clean, and the deadline is not extended.
    pub(crate) async fn shutdown(&self, deadline: Instant) -> ShutdownOutcome {
        self.owned.clock.begin(deadline);
        self.owned.stopping.store(true, Ordering::Release);
        self.owned.stops.signal_all(StopIntent::EngineShutdown);
        let mut active = self.owned.active.subscribe();
        let drained = matches!(
            tokio::time::timeout_at(deadline.into(), active.wait_for(|n| *n == 0)).await,
            Ok(Ok(_))
        );
        let settled = {
            let report = self.owned.report.lock().unwrap_or_else(|e| e.into_inner());
            report.overflow == 0
                && !report.unreconciled.iter().any(|entry| {
                    matches!(
                        entry,
                        Unreconciled::NotOwned { .. } | Unreconciled::Uncertain { .. }
                    )
                })
        };
        if drained && settled && !self.owned.loaded.any_unconfirmed() {
            ShutdownOutcome::Clean
        } else {
            ShutdownOutcome::Unconfirmed
        }
    }
}

/// How the execution side stopped for engine shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShutdownOutcome {
    Clean,
    /// An attempt outlived the deadline, or its cleanup or outcome is
    /// uncertain: holds stay and restart reconciles it.
    Unconfirmed,
}

/// Start the single owner of dispatch turns. Requires a Tokio runtime.
pub(crate) fn start<S: ControllerStore, A: AttemptSource>(
    deps: ExecutionDependencies<S, A>,
) -> ExecutionHandle {
    let (wake, wakes) = mpsc::channel(1);
    let owned = Arc::new(Owned {
        stops: StopRegistry::default(),
        report: Mutex::new(Report::default()),
        blocked: Mutex::new(HashMap::new()),
        loaded: Arc::new(LoadedWorkers::default()),
        clock: ShutdownClock::default(),
        stopping: AtomicBool::new(false),
        active: watch::channel(0).0,
    });
    tokio::spawn(own_turns(deps, wakes, Arc::clone(&owned)));
    let handle = ExecutionHandle { wake, owned };
    handle.wake();
    handle
}

async fn own_turns<S: ControllerStore, A: AttemptSource>(
    deps: ExecutionDependencies<S, A>,
    mut wakes: mpsc::Receiver<()>,
    owned: Arc<Owned>,
) {
    let (stops, report, blocked) = (&owned.stops, &owned.report, &owned.blocked);
    let max_active = deps.limits.max_active.max(1);
    // Each attempt sends exactly once, and at most `max_active` run.
    let (ended, mut endings) = mpsc::channel::<(String, Option<Unreconciled>)>(max_active);
    let mut active = 0usize;
    // Every handle is gone: no new turns, but stay until active attempts end
    // so their stop handles are not dropped (a dropped handle reads as an
    // engine stop the Store never committed).
    let mut closing = false;
    loop {
        tokio::select! {
            wake = wakes.recv(), if !closing => {
                if wake.is_none() {
                    closing = true;
                }
            }
            Some((attempt_id, unsettled)) = endings.recv() => {
                active -= 1;
                stops.remove(&attempt_id);
                if let Some(entry) = unsettled {
                    report.lock().unwrap_or_else(|e| e.into_inner()).push(entry);
                }
                // After the outcome is recorded, so a drained count implies it.
                owned.active.send_replace(active);
            }
        }
        if closing {
            if active == 0 {
                return;
            }
            continue;
        }
        // Shutdown began: attempts finish, nothing new is dispatched.
        if owned.stopping.load(Ordering::Acquire) {
            continue;
        }
        let free = max_active - active;
        let store = Arc::clone(&deps.store);
        let source = Arc::clone(&deps.source);
        let turn = tokio::task::spawn_blocking(move || {
            // A failing eligibility check blocks that job; it never unwinds
            // through the turn, which would drop records already committed.
            let eligibility = |candidate: &QueuedCandidate| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    source.eligibility(candidate)
                }))
                .unwrap_or(Eligibility::Blocked("eligibility_failed"))
            };
            // At capacity nothing is dispatched, but blockers stay current.
            let turn = (free > 0).then(|| dispatch_turn(&*store, eligibility, free));
            (turn, queued_blockers(&*store, eligibility))
        })
        .await;
        let turn = match turn {
            Ok((turn, scanned)) => {
                if let Ok(scanned) = scanned {
                    *blocked.lock().unwrap_or_else(|e| e.into_inner()) =
                        scanned.into_iter().collect();
                }
                match turn {
                    Some(turn) => Ok(turn),
                    None => continue,
                }
            }
            Err(error) => Err(error),
        };
        let Ok(turn) = turn else {
            report
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Unreconciled::Turn);
            continue;
        };
        if let Some(job) = turn.uncertain {
            report
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Unreconciled::Dispatch(job));
        }
        for record in turn.dispatched {
            // Registered before the attempt task exists, so before launch.
            let Some(stop) = stops.register(&record) else {
                continue;
            };
            active += 1;
            owned.active.send_replace(active);
            let attempt_id = record.attempt_id.clone();
            let ended = ended.clone();
            let store = Arc::clone(&deps.store);
            let root = Arc::clone(&deps.root);
            let source = Arc::clone(&deps.source);
            let attempt_owned = Arc::clone(&owned);
            tokio::spawn(async move {
                let job_id = record.job_id.clone();
                // A panic inside the attempt is an outcome nobody
                // established: report it, so the slot is never lost.
                let attempt = run_attempt(store, root, source, record, stop, attempt_owned);
                let outcome = tokio::spawn(attempt)
                    .await
                    .unwrap_or(PublishOutcome::Uncertain);
                let unsettled = match outcome {
                    PublishOutcome::Published(_) | PublishOutcome::Ended(_) => None,
                    PublishOutcome::NotOwned => Some(Unreconciled::NotOwned {
                        job_id,
                        attempt_id: attempt_id.clone(),
                    }),
                    PublishOutcome::Uncertain => Some(Unreconciled::Uncertain {
                        job_id,
                        attempt_id: attempt_id.clone(),
                    }),
                };
                let _ = ended.send((attempt_id, unsettled)).await;
            });
        }
    }
}

/// Finalize an attempt that ended without a candidate.
async fn finalize<S: ControllerStore>(
    store: Arc<S>,
    record: &DispatchRecord,
    end: AttemptEnd,
    cleanup: AttemptCleanup,
) -> PublishOutcome {
    let finalization = AttemptFinalization {
        attempt: AttemptRef::from(record),
        end,
        cleanup,
    };
    match tokio::task::spawn_blocking(move || store.finalize(finalization)).await {
        Ok(Ok(receipt)) => PublishOutcome::Ended(receipt),
        // Already terminal with another outcome, or not this attempt.
        Ok(Err(CoreError::Conflict)) => PublishOutcome::NotOwned,
        _ => PublishOutcome::Uncertain,
    }
}

/// Persist the latest coalesced observation until supervision ends.
/// Observations are progress only; a refused write changes no outcome. The
/// first `executing` phase (load acknowledged) records the worker as loaded.
async fn persist_observations<S: ControllerStore>(
    store: Arc<S>,
    record: DispatchRecord,
    loaded: Arc<LoadedWorkers>,
    mut updates: watch::Receiver<Option<ObservationUpdate>>,
) {
    let attempt = AttemptRef::from(&record);
    while updates.changed().await.is_ok() {
        let Some(update) = updates.borrow_and_update().clone() else {
            continue;
        };
        if update.phase == AttemptPhase::Executing
            && let Some(profile) = LoadedProfile::of_resolution(&record.resolved_json)
        {
            loaded.loaded(&record.attempt_id, profile, record.resources.clone());
        }
        let store = Arc::clone(&store);
        let observation = AttemptObservation {
            attempt: attempt.clone(),
            update,
        };
        let _ = tokio::task::spawn_blocking(move || store.observe(observation)).await;
    }
}

/// One committed attempt from preparation to exactly one routing step.
async fn run_attempt<S: ControllerStore, A: AttemptSource>(
    store: Arc<S>,
    root: Arc<OwnedRoot>,
    source: Arc<A>,
    record: DispatchRecord,
    stop: watch::Receiver<StopIntent>,
    owned: Arc<Owned>,
) -> PublishOutcome {
    let loaded = Arc::clone(&owned.loaded);
    // The stop handle is registered, so any cancellation committed from here
    // on is delivered to it. One committed before registration (between the
    // dispatch commit and now) is read here instead: nothing is launched.
    let reader = Arc::clone(&store);
    let attempt = AttemptRef::from(&record);
    let committed = tokio::task::spawn_blocking(move || reader.stop_intent(attempt)).await;
    match committed {
        Ok(Ok(StopIntent::Continue)) => {}
        Ok(Ok(intent)) => {
            let cleanup = AttemptCleanup::NeverLaunched(NeverLaunched::new());
            return finalize(store, &record, AttemptEnd::Stopped(intent), cleanup).await;
        }
        // Ownership cannot be established: never launch on a guess.
        _ => {
            let cleanup = AttemptCleanup::NeverLaunched(NeverLaunched::new());
            return finalize(store, &record, AttemptEnd::LaunchFailed, cleanup).await;
        }
    }
    let prepare_record = record.clone();
    let prepared = tokio::task::spawn_blocking(move || source.prepare(&prepare_record)).await;
    let Ok(Ok(prepared)) = prepared else {
        let cleanup = AttemptCleanup::NeverLaunched(NeverLaunched::new());
        return finalize(store, &record, AttemptEnd::LaunchFailed, cleanup).await;
    };
    let PreparedAttempt {
        plan,
        launcher,
        staging,
        input,
        input_reader,
    } = prepared;
    let (observed, updates) = watch::channel(None);
    let persisting = tokio::spawn(persist_observations(
        Arc::clone(&store),
        record.clone(),
        Arc::clone(&loaded),
        updates,
    ));
    let exit = WorkerSupervisor::run_until(
        &record,
        plan,
        launcher,
        Arc::clone(&store),
        stop,
        &observed,
        &owned.clock,
    )
    .await;
    // The last observation lands before the outcome is written.
    drop(observed);
    let _ = persisting.await;
    // Loaded state clears only with established cleanup.
    match &exit {
        AttemptExit::Candidate { .. }
        | AttemptExit::Ended {
            cleanup: AttemptCleanup::Confirmed(_) | AttemptCleanup::NeverLaunched(_),
            ..
        } => loaded.cleaned(&record.attempt_id),
        AttemptExit::Ended {
            cleanup: AttemptCleanup::Fault(_),
            ..
        } => loaded.cleanup_unconfirmed(&record.attempt_id),
    }
    match exit {
        AttemptExit::Candidate {
            report, cleanup, ..
        } => {
            let request = PublishRequest {
                dispatch: record,
                report,
                cleanup,
                staging,
                input,
                input_reader,
            };
            publish(store, root, request).await
        }
        AttemptExit::Ended { end, cleanup, .. } => finalize(store, &record, end, cleanup).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::supervisor_tests::dispatch;

    #[test]
    fn a_registered_attempt_is_never_registered_twice() {
        let stops = StopRegistry::default();
        let record = dispatch(None);
        assert!(stops.register(&record).is_some());
        assert!(stops.register(&record).is_none(), "same attempt ID");
        stops.remove(&record.attempt_id);
        assert!(stops.register(&record).is_some(), "after it ended");
    }

    #[test]
    fn the_first_stop_intent_stays() {
        let stops = StopRegistry::default();
        let record = dispatch(None);
        let stop = stops.register(&record).unwrap();
        assert!(stops.signal(&record.job_id, StopIntent::UserCancel));
        assert!(stops.signal(&record.job_id, StopIntent::EngineShutdown));
        assert_eq!(*stop.borrow(), StopIntent::UserCancel);
        let other = JobId::parse(format!("job_{}", "9".repeat(32))).unwrap();
        assert!(!stops.signal(&other, StopIntent::UserCancel));
    }
}
