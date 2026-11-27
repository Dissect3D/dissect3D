//! RP-P03/6: process death around each durable publication step.
//!
//! The child is this test executable hosting the real Store and the real
//! publication sequence (capture, validation, durable preparation, commit);
//! no product host calls publication until WE-P06. It stops at one named
//! boundary, the parent SIGKILLs it, then reopens the Store exactly as restart
//! does and checks the recovered facts against the on-disk bytes. Process
//! death is one evidence class; injected faults and physical power loss are
//! separate ones.
#![expect(
    clippy::expect_used,
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
use super::launch_identity_tests::{evidence, launched};
use super::results::{PublicationReservation, ReclaimBatch};
use super::results_commit::{CommitOutcome, PublicationCommit, PublicationReceipt};
use super::retry_tests::{authorize, db};
use super::*;
use crate::publication::service::{PublicationStore, PublishRequest, publish_blocking};
use crate::publication::storage::ResultLedger;
use crate::store::finalize::{AttemptFinalization, FinalizationReceipt};
use crate::worker_protocol::{CandidateFile, CandidateReport};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

const TETRAHEDRON: &[u8] = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");
const STEP: &str = "D3_PUBLICATION_CRASH_STEP";
const DIR: &str = "D3_PUBLICATION_CRASH_DIR";
const MARKER: &str = "boundary";
const RETURNED: &str = "returned";

/// The durable boundaries the child stops at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// The allocation is reserved (`preparing`); no file is written yet.
    Reserved,
    /// Every file is durably written; the allocation is still `preparing`.
    Written,
    /// The allocation is `prepared`; the commit has not been requested.
    Prepared,
    /// As `Prepared`, after user cancellation committed.
    Canceled,
    /// Inside the success transaction, after its final check, before COMMIT.
    InCommit,
    /// COMMIT returned; nothing after it ran.
    Committed,
}
impl Step {
    const ALL: [Step; 6] = [
        Step::Reserved,
        Step::Written,
        Step::Prepared,
        Step::Canceled,
        Step::InCommit,
        Step::Committed,
    ];
    fn name(self) -> &'static str {
        match self {
            Step::Reserved => "reserved",
            Step::Written => "written",
            Step::Prepared => "prepared",
            Step::Canceled => "canceled",
            Step::InCommit => "in-commit",
            Step::Committed => "committed",
        }
    }
    fn parse(name: &str) -> Step {
        *Step::ALL.iter().find(|s| s.name() == name).unwrap()
    }
}

/// Publish the boundary for the parent, then wait to be killed.
fn mark(dir: &Path, lines: &[String]) -> ! {
    let staged = dir.join("boundary.tmp");
    std::fs::write(&staged, lines.join("\n")).unwrap();
    std::fs::rename(&staged, dir.join(MARKER)).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

/// The real Store, stopping at the configured boundary.
struct Boundary<'a> {
    store: &'a Store,
    step: Step,
    dir: PathBuf,
    ids: Vec<String>,
    auth: AuthContext,
    job: JobId,
}
impl Boundary<'_> {
    fn stop(&self, extra: &[String]) -> ! {
        let mut lines = self.ids.clone();
        lines.extend_from_slice(extra);
        mark(&self.dir, &lines)
    }
}
impl ResultLedger for Boundary<'_> {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError> {
        let reserved = ResultLedger::reserve(self.store, request);
        if self.step == Step::Reserved && reserved.is_ok() {
            self.stop(&[]);
        }
        reserved
    }
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError> {
        if self.step == Step::Written {
            self.stop(&[]);
        }
        ResultLedger::mark_prepared(self.store, result_id)
    }
    fn abandon(&self, result_id: &str) -> Result<(), CoreError> {
        ResultLedger::abandon(self.store, result_id)
    }
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        ResultLedger::claim_reclaim(self.store)
    }
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError> {
        ResultLedger::confirm_reclaimed(self.store, objects)
    }
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError> {
        ResultLedger::known_objects(self.store, names)
    }
}
impl PublicationStore for Boundary<'_> {
    fn commit(&self, commit: PublicationCommit) -> Result<CommitOutcome, CoreError> {
        match self.step {
            Step::Prepared => self.stop(&[]),
            Step::Canceled => {
                let state = self
                    .store
                    .cancel_execution_job(self.auth.clone(), self.job.clone())
                    .unwrap();
                assert_eq!(state, "requested");
                self.stop(&[]);
            }
            _ => {}
        }
        let committed = PublicationStore::commit(self.store, commit);
        if self.step == Step::Committed
            && let Ok(CommitOutcome::Committed(receipt)) = &committed
        {
            self.stop(&[
                receipt.result_id.clone(),
                receipt.publication_id.clone(),
                receipt.snapshot_revision.to_string(),
                receipt.publication_sequence.to_string(),
            ]);
        }
        committed
    }
    fn committed_for(&self, attempt_id: &str) -> Result<Option<PublicationReceipt>, CoreError> {
        PublicationStore::committed_for(self.store, attempt_id)
    }
    fn finalize(
        &self,
        finalization: AttemptFinalization,
    ) -> Result<FinalizationReceipt, CoreError> {
        PublicationStore::finalize(self.store, finalization)
    }
}

/// A real accepted mesh-copy job, dispatched and launched with a 600 s
/// budget, whose worker left an exact copy of its input in staging; returns
/// the complete publication request for it.
pub(super) fn publication_job(f: &Fixture) -> (JobId, AttemptRef, PublishRequest) {
    let input = f.capture();
    let request = f.request(&input);
    let job = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse("publish").unwrap(),
            request.clone(),
            f.candidate(&request),
        )
        .unwrap()
        .job_id;
    // No deadline interferes with a boundary held until a kill.
    db(f)
        .execute(
            "UPDATE job_execution SET timeout_ms=600000 WHERE job_id=?1",
            [job.as_str()],
        )
        .unwrap();
    let record = launched(f, &job);
    let attempt = AttemptRef::from(&record);
    let staging = f
        .root
        .create_attempt_root(
            &RelativePath::parse(format!("execution/attempts/{}/staging", attempt.attempt_id))
                .unwrap(),
        )
        .unwrap();
    std::fs::write(staging.worker_path().join("mesh.obj"), TETRAHEDRON).unwrap();
    std::fs::write(
        staging.worker_path().join("output.json"),
        br#"{"mesh":["mesh.obj"]}"#,
    )
    .unwrap();
    let input_reader = f
        .root
        .open_immutable_input(
            &RelativePath::parse(format!("inputs/data/{}.bin", input.input_id.as_str())).unwrap(),
        )
        .unwrap();
    let request = PublishRequest {
        dispatch: record,
        report: CandidateReport {
            description_handle: "output.json".into(),
            files: vec![CandidateFile {
                relative_name: "mesh.obj".into(),
                byte_length: TETRAHEDRON.len() as u64,
                sha256: Sha256::digest(TETRAHEDRON)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            }],
        },
        cleanup: evidence(&attempt),
        staging,
        input,
        input_reader,
    };
    (job, attempt, request)
}

/// Child mode: runs only when the parent below starts this executable.
#[test]
fn publication_crash_host() {
    let (Some(dir), Ok(step)) = (std::env::var_os(DIR), std::env::var(STEP)) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let step = Step::parse(&step);
    let f = Fixture::create(tempfile::Builder::new().tempdir_in(&dir).unwrap());
    let (job, attempt, request) = publication_job(&f);
    let auth = authorize(&f);
    let ids = vec![
        f.root.path().display().to_string(),
        attempt.attempt_id.clone(),
    ];
    if step == Step::InCommit {
        let (entered, in_commit) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel::<()>(1);
        f.store
            .sender
            .send(Command::Execution(
                execution::ExecutionCommand::HoldNextCommit(entered, resume),
            ))
            .ok()
            .unwrap();
        let (dir, ids) = (dir.clone(), ids.clone());
        std::thread::spawn(move || {
            let _never_released = release;
            in_commit.recv().unwrap();
            mark(&dir, &ids)
        });
    }
    let boundary = Boundary {
        store: &f.store,
        step,
        dir: dir.clone(),
        ids,
        auth,
        job,
    };
    let outcome = publish_blocking(&boundary, &f.root, request);
    // The boundary was never reached: report it instead of waiting.
    std::fs::write(dir.join(RETURNED), format!("{outcome:?}")).unwrap();
}

/// Kills and reaps the child on every exit path, including a failed assert.
struct Killed(std::process::Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start the child at `step`, kill it once it reports the boundary, and
/// return the marker lines.
fn crash_at(step: Step, dir: &Path) -> Vec<String> {
    let child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "store::preparation_tests::publication_crash_tests::publication_crash_host",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(DIR, dir)
        .env(STEP, step.name())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Killed(child);
    let give_up = Instant::now() + Duration::from_secs(60);
    while !dir.join(MARKER).exists() {
        if let Ok(returned) = std::fs::read_to_string(dir.join(RETURNED)) {
            panic!("{step:?}: publication finished without the boundary: {returned}");
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr = String::new();
            let _ = std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr);
            panic!("{step:?}: child exited ({status}) before the boundary:\n{stderr}");
        }
        assert!(Instant::now() < give_up, "{step:?}: boundary not reached");
        std::thread::sleep(Duration::from_millis(5));
    }
    // SIGKILL: no destructor, flush or reply runs after the boundary.
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    std::fs::read_to_string(dir.join(MARKER))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// (job state, outcome, attempt cleanup, allocation state, results rows)
type Recovered = (String, Option<String>, String, Option<String>, i64);

/// Reopen as restart does and check one boundary's recovered facts.
fn verify(step: Step, lines: &[String]) {
    let engine = PathBuf::from(&lines[0]);
    let attempt = lines[1].clone();
    let root = OwnedRoot::open(&engine, RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
    let db = Connection::open(engine.join(DATABASE_NAME)).unwrap();
    let recovered: Recovered = db
        .query_row(
            "SELECT e.state,e.outcome_code,a.cleanup_status,
                    (SELECT state FROM publication_allocations WHERE attempt_id=a.attempt_id),
                    (SELECT count(*) FROM results WHERE attempt_id=a.attempt_id)
             FROM job_execution e JOIN job_attempts a USING(job_id) WHERE a.attempt_id=?1",
            [attempt.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    let files: Vec<(String, u64, Vec<u8>)> = {
        let mut statement = db
            .prepare(
                "SELECT f.object_name,f.byte_length,f.sha256 FROM result_files f
                 JOIN publication_allocations a USING(result_id)
                 WHERE a.attempt_id=?1 ORDER BY f.object_name",
            )
            .unwrap();
        statement
            .query_map([attempt.as_str()], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? as u64, r.get(2)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let charged: u64 = files.iter().map(|f| f.1).sum();
    // Every durably written object holds exactly its recorded bytes.
    let exact_on_disk = || {
        for (name, length, sha256) in &files {
            let bytes = std::fs::read(engine.join("results/objects").join(name))
                .unwrap_or_else(|e| panic!("{step:?}: {name} missing: {e}"));
            assert_eq!(bytes.len() as u64, *length, "{step:?}: {name}");
            assert_eq!(Sha256::digest(&bytes).to_vec(), *sha256, "{step:?}: {name}");
        }
    };
    assert_eq!(files.len(), 2, "{step:?}: artifact and manifest reserved");
    let usage = store.result_usage().unwrap();
    match step {
        Step::Committed => {
            assert_eq!(
                recovered,
                (
                    "succeeded".into(),
                    None,
                    "confirmed".into(),
                    Some("published".into()),
                    1
                ),
                "{step:?}"
            );
            let receipt = store.publication_for_attempt(attempt.clone()).unwrap();
            let receipt = receipt.expect("committed success survives the kill");
            assert_eq!(
                [
                    receipt.result_id,
                    receipt.publication_id,
                    receipt.snapshot_revision.to_string(),
                    receipt.publication_sequence.to_string()
                ],
                lines[2..6],
                "the exact committed identity"
            );
            exact_on_disk();
            assert_eq!((usage.private_bytes, usage.published_bytes), (0, charged));
        }
        Step::Canceled => {
            // Durable cancellation intent and its cleanup hold survive.
            assert_eq!(
                recovered,
                (
                    "cancel_requested".into(),
                    None,
                    "pending".into(),
                    Some("prepared".into()),
                    0
                ),
                "{step:?}"
            );
            exact_on_disk();
            assert_eq!((usage.private_bytes, usage.published_bytes), (charged, 0));
        }
        _ => {
            let allocation = match step {
                Step::Reserved | Step::Written => "preparing",
                _ => "prepared",
            };
            assert_eq!(
                recovered,
                (
                    "interrupted".into(),
                    Some("engine_restarted".into()),
                    "pending".into(),
                    Some(allocation.into()),
                    0
                ),
                "{step:?}"
            );
            if step == Step::Reserved {
                for (name, _, _) in &files {
                    assert!(
                        !engine.join("results/objects").join(name).exists(),
                        "Reserved: {name} written before the boundary"
                    );
                }
            } else {
                exact_on_disk();
            }
            assert_eq!(usage.published_bytes, 0, "{step:?}");
            let unwritten = if allocation == "preparing" {
                charged
            } else {
                0
            };
            assert_eq!(
                (usage.private_bytes, usage.unwritten_bytes),
                (charged, unwritten),
                "{step:?}: charged until reclaimed"
            );
        }
    }
    if step != Step::Committed {
        assert_eq!(
            store.publication_for_attempt(attempt.clone()),
            Ok(None),
            "{step:?}: no salvage"
        );
    }
    // Only orphans of terminal work without a result become reclaimable:
    // never a committed result, never content held by pending cancellation.
    store.claim_publication_reclaim().unwrap();
    let after: Option<String> = db
        .query_row(
            "SELECT state FROM publication_allocations WHERE attempt_id=?1",
            [attempt.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    let expected = match step {
        Step::Committed => "published",
        Step::Canceled => "prepared",
        _ => "reclaiming",
    };
    assert_eq!(
        after.as_deref(),
        Some(expected),
        "{step:?}: reclamation scope"
    );
}

#[test]
fn process_death_around_each_publication_step_recovers_truthfully() {
    for step in Step::ALL {
        let dir = tempfile::tempdir().unwrap();
        let lines = crash_at(step, dir.path());
        verify(step, &lines);
    }
}
