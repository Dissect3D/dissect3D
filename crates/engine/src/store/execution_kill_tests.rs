//! WE-P07/4: engine death at named execution points, then restart.
//!
//! The child is this test executable hosting the engine's execution side: the
//! real Store, the real controller and real contained r2 workers (guardian on
//! Linux). It stops at one named point, the parent SIGKILLs it, then reopens
//! the Store exactly as restart does and runs restart reconciliation before
//! any dispatch. The explicit host binary covers death during execution and
//! signal shutdown (`execution_restart_tests`). Evidence is the host it ran on
//! (WSL2/ext4 here); it is not native acceptance on another platform.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "Fault and migration tests open the SQLite file directly to plant or inspect states \
              the store API cannot express; production opens only via store/schema.rs"
)]
use super::cleanup::AttemptRef;
use super::fixture_attempts_tests::{accept_r2, worker_launch};
use super::launch_identity::{LaunchRecord, decode, encode};
use super::results::{PublicationReservation, ReclaimBatch};
use super::results_commit::{CommitOutcome, PublicationCommit, PublicationReceipt};
use super::retry_tests::authorize;
use super::*;
use crate::execution::controller::{
    ControllerStore, ExecutionDependencies, ExecutionLimits, start,
};
use crate::execution::progress::AttemptPhase;
use crate::execution::scheduler::DispatchStore;
use crate::execution::supervisor::LaunchLedger;
use crate::execution::types::StopIntent;
use crate::execution_fixture::attempts::FixtureAttempts;
use crate::execution_fixture::preparation::{load, prepare};
use crate::publication::service::PublicationStore;
use crate::publication::storage::ResultLedger;
use crate::store::execution::{DispatchRecord, DispatchRequest, QueuedCandidate};
use crate::store::finalize::{AttemptFinalization, AttemptObservation, FinalizationReceipt};
use dissect3d_platform::{WorkerIdentity, process_matches};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

const POINT: &str = "D3_EXECUTION_KILL_POINT";
const DIR: &str = "D3_EXECUTION_KILL_DIR";
const MARKER: &str = "point";
const RETURNED: &str = "returned";

/// Where the child engine dies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    /// The worker tree is spawned; its launch identity is not written.
    BeforeIdentity,
    /// The launch identity is written; no control command was sent yet.
    AfterIdentity,
    /// Executing; user cancellation committed, not yet delivered.
    Cancel,
    /// Executing; the shutdown barrier committed, workers not yet stopped.
    Shutdown,
}
impl Point {
    fn name(self) -> &'static str {
        match self {
            Point::BeforeIdentity => "before-identity",
            Point::AfterIdentity => "after-identity",
            Point::Cancel => "cancel",
            Point::Shutdown => "shutdown",
        }
    }
    fn parse(name: &str) -> Point {
        [
            Point::BeforeIdentity,
            Point::AfterIdentity,
            Point::Cancel,
            Point::Shutdown,
        ]
        .into_iter()
        .find(|p| p.name() == name)
        .unwrap()
    }
}

/// The real Store, stopping the whole child at the configured point.
struct KillPoint {
    f: Fixture,
    point: Point,
    dir: PathBuf,
    auth: AuthContext,
    identity: std::sync::Mutex<Option<WorkerIdentity>>,
}
impl KillPoint {
    /// Publish the point and the worker identity for the parent, then wait
    /// to be killed. Nothing after this runs.
    fn stop(&self) -> ! {
        let identity = self.identity.lock().unwrap().clone().unwrap();
        let lines = [
            self.f.root.path().display().to_string(),
            encode(&identity).unwrap(),
        ];
        let staged = self.dir.join("point.tmp");
        std::fs::write(&staged, lines.join("\n")).unwrap();
        std::fs::rename(&staged, self.dir.join(MARKER)).unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}
impl DispatchStore for KillPoint {
    fn queued_candidates(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> Result<Vec<QueuedCandidate>, CoreError> {
        DispatchStore::queued_candidates(&self.f.store, after_sequence, limit)
    }
    fn dispatch(&self, request: DispatchRequest) -> Result<DispatchRecord, CoreError> {
        DispatchStore::dispatch(&self.f.store, request)
    }
}
impl ResultLedger for KillPoint {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError> {
        ResultLedger::reserve(&self.f.store, request)
    }
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError> {
        ResultLedger::mark_prepared(&self.f.store, result_id)
    }
    fn abandon(&self, result_id: &str) -> Result<(), CoreError> {
        ResultLedger::abandon(&self.f.store, result_id)
    }
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        ResultLedger::claim_reclaim(&self.f.store)
    }
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError> {
        ResultLedger::confirm_reclaimed(&self.f.store, objects)
    }
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError> {
        ResultLedger::known_objects(&self.f.store, names)
    }
}
impl PublicationStore for KillPoint {
    fn commit(&self, commit: PublicationCommit) -> Result<CommitOutcome, CoreError> {
        PublicationStore::commit(&self.f.store, commit)
    }
    fn committed_for(&self, attempt_id: &str) -> Result<Option<PublicationReceipt>, CoreError> {
        PublicationStore::committed_for(&self.f.store, attempt_id)
    }
    fn finalize(
        &self,
        finalization: AttemptFinalization,
    ) -> Result<FinalizationReceipt, CoreError> {
        PublicationStore::finalize(&self.f.store, finalization)
    }
}
impl LaunchLedger for KillPoint {
    fn record_launch(&self, record: LaunchRecord) -> Result<(), CoreError> {
        *self.identity.lock().unwrap() = Some(record.identity.clone());
        if self.point == Point::BeforeIdentity {
            self.stop();
        }
        let recorded = LaunchLedger::record_launch(&self.f.store, record);
        if self.point == Point::AfterIdentity && recorded.is_ok() {
            self.stop();
        }
        recorded
    }
}
impl ControllerStore for KillPoint {
    fn observe(&self, observation: AttemptObservation) -> Result<(), CoreError> {
        let executing = observation.update.phase == AttemptPhase::Executing;
        let job = observation.attempt.job_id.clone();
        ControllerStore::observe(&self.f.store, observation)?;
        if executing {
            match self.point {
                Point::Cancel => {
                    let effect = self
                        .f
                        .store
                        .cancel_execution_job(self.auth.clone(), job)
                        .unwrap();
                    assert_eq!(effect, "requested");
                    self.stop();
                }
                Point::Shutdown => {
                    let instance = self.f.store.identity().unwrap().instance_id;
                    self.f.store.signal_shutdown(instance, 5_000).unwrap();
                    self.stop();
                }
                Point::BeforeIdentity | Point::AfterIdentity => {}
            }
        }
        Ok(())
    }
    fn stop_intent(&self, attempt: AttemptRef) -> Result<StopIntent, CoreError> {
        ControllerStore::stop_intent(&self.f.store, attempt)
    }
}

/// Child mode: runs only when the parent below starts this executable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_kill_host() {
    let (Some(dir), Ok(point)) = (std::env::var_os(DIR), std::env::var(POINT)) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let point = Point::parse(&point);
    let parent = tempfile::Builder::new().tempdir_in(&dir).unwrap();
    prepare(&parent.path().join("engine"), &worker_launch()).unwrap();
    let f = Fixture::create(parent);
    let fixture = load(&f.root).unwrap();
    accept_r2(
        &f,
        &fixture,
        "killed",
        serde_json::json!({"hold_before_candidate": true}),
    );
    // Waits behind the held job (one active attempt), so restart must decide
    // whether it may dispatch.
    accept_r2(&f, &fixture, "waiting", serde_json::json!({}));
    let auth = authorize(&f);
    let root = Arc::new(OwnedRoot::open(f.root.path(), RootPurpose::EngineData).unwrap());
    let killer = Arc::new(KillPoint {
        f,
        point,
        dir: dir.clone(),
        auth,
        identity: std::sync::Mutex::new(None),
    });
    let _handle = start(ExecutionDependencies {
        store: killer,
        root: Arc::clone(&root),
        source: Arc::new(FixtureAttempts::new(fixture, root)),
        limits: ExecutionLimits::CONTROLLED,
    });
    // The point stops the child forever; reaching this means it never came.
    tokio::time::sleep(Duration::from_secs(90)).await;
    std::fs::write(dir.join(RETURNED), "point not reached").unwrap();
}

/// Kills and reaps the child on every exit path, including a failed assert.
struct Killed(std::process::Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start the child at `point`, SIGKILL it there, and return the engine root
/// and the worker tree it launched.
fn kill_at(point: Point, dir: &Path) -> (PathBuf, WorkerIdentity) {
    let child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "store::preparation_tests::execution_kill_tests::execution_kill_host",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(DIR, dir)
        .env(POINT, point.name())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Killed(child);
    let give_up = Instant::now() + Duration::from_secs(120);
    while !dir.join(MARKER).exists() {
        if let Ok(returned) = std::fs::read_to_string(dir.join(RETURNED)) {
            panic!("{point:?}: {returned}");
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr = String::new();
            let _ = std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr);
            panic!("{point:?}: child exited ({status}) before the point:\n{stderr}");
        }
        assert!(Instant::now() < give_up, "{point:?}: point not reached");
        std::thread::sleep(Duration::from_millis(5));
    }
    // SIGKILL: no destructor, flush, reply or worker stop runs after the point.
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let marker = std::fs::read_to_string(dir.join(MARKER)).unwrap();
    let mut lines = marker.lines();
    let root = PathBuf::from(lines.next().unwrap());
    let identity = decode(lines.next().unwrap()).unwrap();
    (root, identity)
}

/// Whether any member of the worker tree is still alive.
fn alive(identity: &WorkerIdentity) -> bool {
    std::iter::once(&identity.process)
        .chain(identity.guardian.as_ref())
        .any(|member| process_matches(member).unwrap())
}

/// What restart established for the killed attempt.
#[derive(Debug, PartialEq, Eq)]
struct Restarted {
    state: String,
    outcome: Option<String>,
    cleanup: String,
    reason: Option<String>,
    held: i64,
    results: i64,
    /// Whether the waiting job could take the killed attempt's resources.
    waiting_dispatched: bool,
}

/// Restart as the execution host does: open the Store (which interrupts
/// uncommitted running work), reconcile earlier workers, and only then try
/// the waiting job on the killed attempt's resources.
fn restart(root: &Path) -> Restarted {
    let owned = OwnedRoot::open(root, RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&owned).unwrap();
    let store = Store::open(owned, lease, &CorePolicy::default()).unwrap();
    crate::execution::recovery::reconcile(&store).unwrap();
    let db = Connection::open(root.join(DATABASE_NAME)).unwrap();
    let (job, attempt, state, outcome, cleanup, reason): (
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
    ) = db
        .query_row(
            "SELECT e.job_id,a.attempt_id,e.state,e.outcome_code,e.cleanup_status,e.cleanup_reason
             FROM job_execution e JOIN job_attempts a USING(job_id)",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .unwrap();
    let count = |sql: &str| -> i64 { db.query_row(sql, [attempt.as_str()], |r| r.get(0)).unwrap() };
    let held =
        count("SELECT count(*) FROM resource_reservations WHERE attempt_id=?1 AND released=0");
    let results = count("SELECT count(*) FROM results WHERE attempt_id=?1");
    let resources: Vec<String> = db
        .prepare("SELECT resource_id FROM resource_reservations WHERE attempt_id=?1")
        .unwrap()
        .query_map([attempt.as_str()], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let (waiting, resolved): (String, String) = db
        .query_row(
            "SELECT e.job_id,j.resolved_json FROM job_execution e JOIN jobs j USING(job_id)
             WHERE e.state='queued' AND e.job_id<>?1",
            [job.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let waiting_dispatched = store
        .dispatch_attempt(DispatchRequest {
            job_id: JobId::parse(waiting).unwrap(),
            expected_revision: 1,
            resolved_json: resolved,
            resources,
        })
        .is_ok();
    Restarted {
        state,
        outcome,
        cleanup,
        reason,
        held,
        results,
        waiting_dispatched,
    }
}

/// The Linux guardian ends the tree once its engine is gone (the
/// owner-death containment that restart relies on).
fn wait_until_gone(identity: &WorkerIdentity) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while alive(identity) {
        assert!(Instant::now() < deadline, "a survivor outlived its engine");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn death_before_the_launch_identity_is_written_keeps_the_holds_as_a_fault() {
    let dir = tempfile::tempdir().unwrap();
    let (root, tree) = kill_at(Point::BeforeIdentity, dir.path());
    wait_until_gone(&tree);
    // Even with the tree gone, restart has no recorded identity to prove it.
    assert_eq!(
        restart(&root),
        Restarted {
            state: "interrupted".into(),
            outcome: Some("engine_restarted".into()),
            cleanup: "fault".into(),
            reason: Some(crate::execution::recovery::IDENTITY_UNRECORDED.into()),
            held: 1,
            results: 0,
            waiting_dispatched: false,
        }
    );
}

#[test]
fn death_after_the_launch_identity_is_written_is_settled_before_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let (root, tree) = kill_at(Point::AfterIdentity, dir.path());
    let restarted = restart(&root);
    assert!(!alive(&tree), "restart left a recorded survivor alive");
    assert_eq!(
        (
            restarted.state.as_str(),
            restarted.outcome.as_deref(),
            restarted.cleanup.as_str()
        ),
        ("interrupted", Some("engine_restarted"), "confirmed"),
        "{restarted:?}"
    );
    assert_eq!((restarted.held, restarted.results), (0, 0));
    assert!(restarted.waiting_dispatched, "settled resources are free");
}

#[test]
fn death_after_a_committed_cancel_completes_the_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let (root, tree) = kill_at(Point::Cancel, dir.path());
    let restarted = restart(&root);
    assert!(!alive(&tree));
    assert_eq!(
        (
            restarted.state.as_str(),
            restarted.outcome.as_deref(),
            restarted.cleanup.as_str()
        ),
        ("canceled", None, "confirmed")
    );
    assert_eq!((restarted.held, restarted.results), (0, 0));
    assert!(restarted.waiting_dispatched);
}

#[test]
fn death_during_shutdown_records_the_shutdown_and_settles_the_worker() {
    let dir = tempfile::tempdir().unwrap();
    let (root, tree) = kill_at(Point::Shutdown, dir.path());
    let restarted = restart(&root);
    assert!(!alive(&tree));
    assert_eq!(
        (
            restarted.state.as_str(),
            restarted.outcome.as_deref(),
            restarted.cleanup.as_str()
        ),
        ("interrupted", Some("engine_shutdown"), "confirmed")
    );
    assert_eq!((restarted.held, restarted.results), (0, 0));
    assert!(restarted.waiting_dispatched);
}
