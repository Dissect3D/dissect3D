//! RP-P03 publication composition: every candidate ends in exactly one
//! authoritative outcome. Capture, validation and preparation are real (native
//! files, real result SQL); commit and finalization are scripted, because their
//! transactions are verified on the real Store in `store/results_commit_tests`
//! and `store/finalize_tests`.
use super::*;
use crate::execution::types::{AttemptCleanup, AttemptEnd, StopIntent};
use crate::publication::service::{
    PublicationStore, PublishOutcome, PublishRequest, publish, publish_blocking,
};
use crate::store::cleanup::{CleanupEvidence, CleanupReceipt, test_identity};
use crate::store::execution::{AttemptTiming, DispatchRecord};
use crate::store::finalize::{AttemptFinalization, FinalizationPath, FinalizationReceipt};
use crate::store::results_commit::{
    CommitOutcome, CommitRefusal, CommittedFile, PublicationCommit, PublicationReceipt,
};
use crate::worker_protocol::{CandidateFile, CandidateReport};
use std::collections::VecDeque;

const DESCRIPTION: &[u8] = br#"{"mesh":["mesh.obj"]}"#;

/// The real result ledger plus scripted commit/lookup/finalize answers.
struct Scripted {
    ledger: Ledger,
    commits: Mutex<VecDeque<Result<CommitOutcome, CoreError>>>,
    lookup: Mutex<Option<Result<Option<PublicationReceipt>, CoreError>>>,
    seen_commits: Mutex<Vec<(Vec<CommittedFile>, dissect3d_platform::WorkerIdentity)>>,
    finalized: Mutex<Vec<AttemptEnd>>,
    /// Holds a scripted commit until the test releases it.
    commit_gate: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    /// A job state committed by another writer just before this commit.
    state_at_commit: Mutex<Option<&'static str>>,
}

impl ResultLedger for Scripted {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError> {
        self.ledger.reserve(request)
    }
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError> {
        self.ledger.mark_prepared(result_id)
    }
    fn abandon(&self, result_id: &str) -> Result<(), CoreError> {
        self.ledger.abandon(result_id)
    }
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        self.ledger.claim_reclaim()
    }
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError> {
        self.ledger.confirm_reclaimed(objects)
    }
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError> {
        self.ledger.known_objects(names)
    }
}

impl PublicationStore for Scripted {
    fn commit(&self, commit: PublicationCommit) -> Result<CommitOutcome, CoreError> {
        self.seen_commits
            .lock()
            .unwrap()
            .push((commit.files.clone(), commit.cleanup.identity().clone()));
        if let Some(state) = self.state_at_commit.lock().unwrap().take() {
            self.ledger
                .db()
                .execute("UPDATE job_execution SET state=?1", [state])
                .unwrap();
        }
        if let Some(gate) = self.commit_gate.lock().unwrap().take() {
            let _ = gate.recv_timeout(Duration::from_secs(10));
        }
        self.commits
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected commit")
    }
    fn committed_for(&self, _: &str) -> Result<Option<PublicationReceipt>, CoreError> {
        self.lookup
            .lock()
            .unwrap()
            .take()
            .expect("unexpected lookup")
    }
    fn finalize(&self, f: AttemptFinalization) -> Result<FinalizationReceipt, CoreError> {
        assert!(
            matches!(f.cleanup, AttemptCleanup::Confirmed(_)),
            "finalization always carries the native cleanup witness"
        );
        // As the real Store: running work needs a running outcome; a user
        // stop is accepted only once cancellation is committed.
        let state: String = self
            .ledger
            .db()
            .query_row("SELECT state FROM job_execution", [], |r| r.get(0))
            .unwrap();
        if state == "running" && matches!(f.end, AttemptEnd::Stopped(StopIntent::UserCancel)) {
            return Err(CoreError::Conflict);
        }
        self.finalized.lock().unwrap().push(f.end);
        Ok(FinalizationReceipt {
            receipt: CleanupReceipt {
                snapshot_revision: 3,
                changed: true,
            },
            path: FinalizationPath::Finalized,
        })
    }
}

struct Case {
    _parent: tempfile::TempDir,
    root: OwnedRoot,
    store: Scripted,
    dispatch: DispatchRecord,
}

impl Case {
    fn new() -> Self {
        let Env {
            parent,
            root,
            ledger,
            ..
        } = env();
        let (dispatch, _, _) = fixture();
        Case {
            _parent: parent,
            root,
            store: Scripted {
                ledger,
                commits: Mutex::default(),
                lookup: Mutex::default(),
                seen_commits: Mutex::default(),
                finalized: Mutex::default(),
                commit_gate: Mutex::default(),
                state_at_commit: Mutex::default(),
            },
            dispatch,
        }
    }
    fn script(self, answers: Vec<Result<CommitOutcome, CoreError>>) -> Self {
        *self.store.commits.lock().unwrap() = answers.into();
        self
    }
    /// A complete candidate in a fresh staging folder; `mesh` is what the
    /// worker wrote and reported.
    fn request(&self, mesh: &[u8]) -> PublishRequest {
        use sha2::{Digest, Sha256};
        let staging = self
            .root
            .create_attempt_root(
                &RelativePath::parse(format!(
                    "execution/attempts/{}/staging",
                    self.dispatch.attempt_id
                ))
                .unwrap(),
            )
            .unwrap();
        fs::write(staging.worker_path().join("mesh.obj"), mesh).unwrap();
        fs::write(staging.worker_path().join("output.json"), DESCRIPTION).unwrap();
        let input_name =
            RelativePath::parse("inputs/inp_11111111111111111111111111111111").unwrap();
        if self.root.read_file(&input_name, 1 << 20).is_err() {
            self.root.write_atomic(&input_name, MESH).unwrap();
        }
        let (_, _, inputs) = fixture();
        PublishRequest {
            dispatch: self.dispatch.clone(),
            report: CandidateReport {
                description_handle: "output.json".into(),
                files: vec![CandidateFile {
                    relative_name: "mesh.obj".into(),
                    byte_length: mesh.len() as u64,
                    sha256: Sha256::digest(mesh)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                }],
            },
            cleanup: CleanupEvidence::for_test(test_identity(&self.dispatch.session_id, "publish")),
            staging,
            input: inputs.identities[0].clone(),
            input_reader: self.root.open_immutable_input(&input_name).unwrap(),
        }
    }
    fn run(&self, mesh: &[u8]) -> PublishOutcome {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        publish_blocking(&self.store, &self.root, self.request(mesh))
    }
    fn set_state(&self, state: &str) {
        self.store
            .ledger
            .db()
            .execute("UPDATE job_execution SET state=?1", [state])
            .unwrap();
    }
    fn finalized(&self) -> Vec<AttemptEnd> {
        self.store.finalized.lock().unwrap().clone()
    }
    fn usage(&self) -> ResultUsage {
        results::usage(&mut self.store.ledger.db()).unwrap()
    }
    fn allocation(&self) -> Option<String> {
        self.store
            .ledger
            .db()
            .query_row("SELECT state FROM publication_allocations", [], |r| {
                r.get(0)
            })
            .ok()
    }
}

fn receipt() -> PublicationReceipt {
    PublicationReceipt {
        result_id: format!("res_{}", "a".repeat(32)),
        publication_id: format!("pub_{}", "a".repeat(32)),
        job_id: "job".into(),
        attempt_id: "att".into(),
        snapshot_revision: 3,
        publication_sequence: 1,
    }
}

fn ended() -> PublishOutcome {
    PublishOutcome::Ended(FinalizationReceipt {
        receipt: CleanupReceipt {
            snapshot_revision: 3,
            changed: true,
        },
        path: FinalizationPath::Finalized,
    })
}

#[test]
fn a_valid_copy_is_committed_with_its_durable_witnesses_and_the_cleanup_witness() {
    let case = Case::new().script(vec![Ok(CommitOutcome::Committed(receipt()))]);
    assert_eq!(case.run(MESH), PublishOutcome::Published(receipt()));
    assert!(case.finalized().is_empty());
    let seen = case.store.seen_commits.lock().unwrap();
    let (files, identity) = &seen[0];
    assert_eq!(
        *identity,
        test_identity(&case.dispatch.session_id, "publish")
    );
    let rows: Vec<(String, i64)> = {
        let db = case.store.ledger.db();
        let mut statement = db
            .prepare("SELECT object_name,byte_length FROM result_files ORDER BY object_name")
            .unwrap();
        statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let mut committed: Vec<(String, i64)> = files
        .iter()
        .map(|f| (f.object_name.clone(), f.byte_length as i64))
        .collect();
    committed.sort();
    assert_eq!(
        committed, rows,
        "the commit binds exactly the prepared rows"
    );
    assert_eq!(case.allocation().as_deref(), Some("prepared"));
}

#[test]
fn a_refused_candidate_fails_validation_before_anything_is_reserved() {
    // A different valid tetrahedron: generic geometry passes, fidelity fails.
    let other = b"v 0 0 0\nv 2 0 0\nv 0 2 0\nv 0 0 2\nf 1 2 3\nf 1 2 4\nf 1 3 4\nf 2 3 4\n";
    for mesh in [&other[..], b"v 0 0 0\nf 1 1 1\n", b""] {
        let case = Case::new();
        assert_eq!(case.run(mesh), ended());
        assert_eq!(case.finalized(), vec![AttemptEnd::ResultValidationFailed]);
        assert_eq!(case.usage(), ResultUsage::default(), "nothing reserved");
        assert!(case.store.seen_commits.lock().unwrap().is_empty());
    }
}

#[test]
fn a_preparation_storage_failure_fails_the_job_and_keeps_its_charge() {
    let case = Case::new();
    case.root
        .ensure_private_directory(&RelativePath::parse("results").unwrap())
        .unwrap();
    fs::write(case.root.path().join("results/objects"), b"not a directory").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            case.root.path().join("results/objects"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    assert_eq!(case.run(MESH), ended());
    assert_eq!(case.finalized(), vec![AttemptEnd::ResultStorageFailed]);
    assert_eq!(case.allocation().as_deref(), Some("failed"));
    assert!(case.usage().private_bytes > 0, "charged until reclaimed");
}

#[test]
fn an_expired_attempt_clock_ends_with_the_deadline_outcome_before_any_work() {
    let mut case = Case::new();
    case.dispatch.timing = Arc::new(AttemptTiming::for_supervision_test(Some(Duration::ZERO)));
    assert_eq!(case.run(MESH), ended());
    assert_eq!(case.finalized(), vec![AttemptEnd::DeadlineExceeded]);
    assert_eq!(case.usage(), ResultUsage::default());
}

#[test]
fn each_commit_refusal_ends_through_its_own_path() {
    let table = [
        (
            CommitRefusal::Canceled,
            Some(AttemptEnd::Stopped(StopIntent::UserCancel)),
        ),
        (
            CommitRefusal::ShutdownBarrier,
            Some(AttemptEnd::Stopped(StopIntent::EngineShutdown)),
        ),
        (
            CommitRefusal::DeadlineExpired,
            Some(AttemptEnd::DeadlineExceeded),
        ),
        (
            CommitRefusal::NotPrepared,
            Some(AttemptEnd::ResultStorageFailed),
        ),
        (CommitRefusal::NotRunning, None),
        (CommitRefusal::NotCurrentSession, None),
    ];
    for (refusal, end) in table {
        let case = Case::new().script(vec![Ok(CommitOutcome::Refused(refusal))]);
        if refusal == CommitRefusal::Canceled {
            // Cancellation committed after preparation, before the commit.
            *case.store.state_at_commit.lock().unwrap() = Some("cancel_requested");
        }
        let outcome = case.run(MESH);
        match end {
            Some(end) => {
                assert_eq!(outcome, ended(), "{refusal:?}");
                assert_eq!(case.finalized(), vec![end], "{refusal:?}");
            }
            None => {
                assert_eq!(outcome, PublishOutcome::NotOwned, "{refusal:?}");
                assert!(case.finalized().is_empty(), "{refusal:?}");
            }
        }
        // Prepared content stays private and charged for reconciliation.
        assert_eq!(
            case.allocation().as_deref(),
            Some("prepared"),
            "{refusal:?}"
        );
    }
}

#[test]
fn an_uncertain_commit_is_reconciled_by_reading_never_by_guessing() {
    // Committed after all: success, no failure recorded.
    let case = Case::new().script(vec![Err(CoreError::StoreUnavailable)]);
    *case.store.lookup.lock().unwrap() = Some(Ok(Some(receipt())));
    assert_eq!(case.run(MESH), PublishOutcome::Published(receipt()));
    assert!(case.finalized().is_empty());
    // Proven absent: a storage failure.
    let case = Case::new().script(vec![Err(CoreError::StoreUnavailable)]);
    *case.store.lookup.lock().unwrap() = Some(Ok(None));
    assert_eq!(case.run(MESH), ended());
    assert_eq!(case.finalized(), vec![AttemptEnd::ResultStorageFailed]);
    // Still unknown: nothing is recorded.
    let case = Case::new().script(vec![Err(CoreError::Busy)]);
    *case.store.lookup.lock().unwrap() = Some(Err(CoreError::StoreUnavailable));
    assert_eq!(case.run(MESH), PublishOutcome::Uncertain);
    assert!(case.finalized().is_empty());
    assert_eq!(case.allocation().as_deref(), Some("prepared"));
}

#[test]
fn a_definite_transaction_refusal_is_a_storage_failure() {
    for error in [CoreError::Conflict, CoreError::InvalidStore] {
        let case = Case::new().script(vec![Err(error)]);
        assert_eq!(case.run(MESH), ended(), "{error:?}");
        assert_eq!(case.finalized(), vec![AttemptEnd::ResultStorageFailed]);
    }
}

#[test]
fn a_caller_that_stops_waiting_does_not_stop_the_publication() {
    let case = Case::new().script(vec![Ok(CommitOutcome::Committed(receipt()))]);
    let (release, gate) = std::sync::mpsc::sync_channel(1);
    *case.store.commit_gate.lock().unwrap() = Some(gate);
    let request = case.request(MESH);
    let Case {
        _parent,
        root,
        store,
        ..
    } = case;
    let store = Arc::new(store);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let abandoned = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(50),
            publish(store.clone(), Arc::new(root), request),
        )
        .await
    });
    // The commit is held, so the caller certainly gave up first.
    assert!(abandoned.is_err(), "the caller stopped waiting");
    release.send(()).unwrap();
    // The abandoned publication still reaches and consumes its commit.
    let finished = Instant::now() + Duration::from_secs(10);
    while !store.commits.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < finished,
            "publication stopped with its caller"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(store.seen_commits.lock().unwrap().len(), 1);
}

#[test]
fn a_preparation_refused_by_the_ledger_is_a_storage_failure_not_a_lost_attempt() {
    // An allocation already exists for this attempt, so the reservation is
    // refused with Conflict, as any reservation insert failure also reports.
    let case = Case::new();
    {
        let db = case.store.ledger.db();
        db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        db.execute(
            "INSERT INTO publication_allocations
             SELECT 'res_'||substr(attempt_id,5),'pub_'||substr(attempt_id,5),job_id,attempt_id,
                    instance_id,'failed',1,1,1 FROM job_attempts",
            [],
        )
        .unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    }
    assert_eq!(case.run(MESH), ended());
    assert_eq!(case.finalized(), vec![AttemptEnd::ResultStorageFailed]);
    // A committed cancellation is refused at reservation and still completes
    // through finalization's cancellation path.
    let case = Case::new();
    case.set_state("cancel_requested");
    assert_eq!(case.run(MESH), ended());
    assert_eq!(case.finalized(), vec![AttemptEnd::ResultStorageFailed]);
}
