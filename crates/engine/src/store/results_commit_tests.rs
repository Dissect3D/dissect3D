//! RP-P03/1-/3 and /5: the authoritative publication transaction through the
//! real Store actor and a genuinely dispatched, launched attempt.
use super::cleanup::AttemptRef;
use super::launch_identity_tests::{evidence, launched};
use super::results_commit::{CommitOutcome, CommitRefusal, CommittedFile, PublicationCommit};
use super::retry_tests::{accept, db, dispatch};
use super::*;
use crate::store::results::{FileRole, PublicationReservation, ReservedFile, ResultUsage};

fn hex(c: char) -> String {
    c.to_string().repeat(32)
}

fn files(c: char) -> Vec<ReservedFile> {
    vec![
        ReservedFile {
            object_name: format!("art_{}", hex(c)),
            role: FileRole::Artifact,
            filename: "mesh.obj".into(),
            media_type: "application/octet-stream".into(),
            byte_length: 64,
            sha256: [3; 32],
        },
        ReservedFile {
            object_name: format!("pub_{}", hex(c)),
            role: FileRole::Manifest,
            filename: "manifest.json".into(),
            media_type: "application/json".into(),
            byte_length: 8,
            sha256: [4; 32],
        },
    ]
}

/// Reserve and prepare an allocation, as preparation would after its files
/// passed every barrier, and return the matching commit request.
fn prepared(f: &Fixture, attempt: &AttemptRef, c: char) -> PublicationCommit {
    let reserved = files(c);
    f.store
        .reserve_publication(PublicationReservation {
            result_id: format!("res_{}", hex(c)),
            publication_id: format!("pub_{}", hex(c)),
            job_id: attempt.job_id.as_str().to_owned(),
            attempt_id: attempt.attempt_id.clone(),
            files: reserved.clone(),
            available_space_bytes: u64::MAX / 4,
        })
        .unwrap();
    f.store
        .mark_publication_prepared(format!("res_{}", hex(c)))
        .unwrap();
    commit_for(attempt, c, &reserved)
}

fn commit_for(attempt: &AttemptRef, c: char, reserved: &[ReservedFile]) -> PublicationCommit {
    PublicationCommit {
        attempt: attempt.clone(),
        cleanup: evidence(attempt),
        result_id: format!("res_{}", hex(c)),
        publication_id: format!("pub_{}", hex(c)),
        manifest_version: "1.0".into(),
        published_at_ms: 1_700_000_000_000,
        files: reserved
            .iter()
            .map(|file| CommittedFile {
                object_name: file.object_name.clone(),
                role: file.role,
                byte_length: file.byte_length,
                sha256: file.sha256,
            })
            .collect(),
    }
}

fn running(f: &Fixture, key: &str) -> AttemptRef {
    let job = accept(f, key).job_id;
    AttemptRef::from(&launched(f, &job))
}

/// (job state, phase, outcome, job cleanup, attempt cleanup, revision,
///  allocation state, results rows, publication sequence, released reservations)
type Facts = (
    String,
    String,
    Option<String>,
    String,
    String,
    i64,
    Option<String>,
    i64,
    i64,
    i64,
);

fn facts(f: &Fixture, attempt: &AttemptRef) -> Facts {
    db(f)
        .query_row(
            "SELECT e.state,e.phase,e.outcome_code,e.cleanup_status,a.cleanup_status,
                    e.snapshot_revision,
                    (SELECT state FROM publication_allocations WHERE attempt_id=a.attempt_id),
                    (SELECT count(*) FROM results WHERE attempt_id=a.attempt_id),
                    (SELECT value FROM publication_sequence),
                    (SELECT count(*) FROM resource_reservations
                      WHERE attempt_id=a.attempt_id AND released=1)
             FROM job_execution e JOIN job_attempts a USING(job_id) WHERE a.attempt_id=?1",
            [attempt.attempt_id.as_str()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .unwrap()
}

fn refused(outcome: Result<CommitOutcome, CoreError>) -> CommitRefusal {
    match outcome {
        Ok(CommitOutcome::Refused(refusal)) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_eligible_commit_publishes_once_releases_with_cleanup_and_replays_its_receipt() {
    let f = Fixture::new();
    let attempt = running(&f, "commit-once");
    let commit = prepared(&f, &attempt, 'a');
    let before = facts(&f, &attempt);
    assert_eq!(before.5, 2, "accepted at 1, dispatched at 2");
    let Ok(CommitOutcome::Committed(receipt)) = f.store.commit_publication(commit.clone()) else {
        panic!("eligible commit refused")
    };
    assert_eq!(receipt.result_id, commit.result_id);
    assert_eq!(receipt.attempt_id, attempt.attempt_id);
    assert_eq!(receipt.job_id, attempt.job_id.as_str());
    assert_eq!(receipt.snapshot_revision, 3);
    assert_eq!(receipt.publication_sequence, 1);
    let after = facts(&f, &attempt);
    assert_eq!(
        after,
        (
            "succeeded".into(),
            "succeeded".into(),
            None,
            "confirmed".into(),
            "confirmed".into(),
            3,
            Some("published".into()),
            1,
            1,
            before.9 + 1,
        )
    );
    let usage = f.store.result_usage().unwrap();
    assert_eq!((usage.private_bytes, usage.published_bytes), (0, 72));
    // A repeated acknowledgement retrieval returns the original identity.
    assert_eq!(
        f.store.commit_publication(commit.clone()),
        Ok(CommitOutcome::Committed(receipt.clone()))
    );
    assert_eq!(
        f.store
            .publication_for_attempt(attempt.attempt_id.clone())
            .unwrap(),
        Some(receipt.clone())
    );
    // A different candidate cannot overwrite the terminal result.
    let mut other = commit_for(&attempt, 'b', &files('b'));
    other.cleanup = evidence(&attempt);
    assert_eq!(f.store.commit_publication(other), Err(CoreError::Conflict));
    assert_eq!(facts(&f, &attempt), after);
    // The terminal attempt no longer holds a live clock.
    assert_eq!(
        f.store.attempt_timing(attempt.attempt_id.clone()).err(),
        Some(CoreError::NotFound)
    );
}

#[test]
fn committed_cancellation_first_forbids_publication_and_publication_first_survives_cancel() {
    let f = Fixture::new();
    let auth = super::retry_tests::authorize(&f);
    // Cancel committed first.
    let first = running(&f, "cancel-first");
    let commit = prepared(&f, &first, 'c');
    assert_eq!(
        f.store
            .cancel_execution_job(auth.clone(), first.job_id.clone())
            .unwrap(),
        "requested"
    );
    let before = facts(&f, &first);
    assert_eq!(
        refused(f.store.commit_publication(commit)),
        CommitRefusal::Canceled
    );
    assert_eq!(facts(&f, &first), before, "nothing staged survives");
    // Publication committed first (a fresh host: one CPU attempt at a time).
    let f = Fixture::new();
    let auth = super::retry_tests::authorize(&f);
    let second = running(&f, "publish-first");
    let commit = prepared(&f, &second, 'd');
    assert!(matches!(
        f.store.commit_publication(commit),
        Ok(CommitOutcome::Committed(_))
    ));
    assert_eq!(
        f.store
            .cancel_execution_job(auth, second.job_id.clone())
            .unwrap(),
        "already_terminal"
    );
    assert_eq!(facts(&f, &second).0, "succeeded");
}

#[test]
fn an_expired_deadline_at_the_final_check_rolls_back_every_staged_change() {
    let f = Fixture::new();
    let job = accept(&f, "deadline").job_id;
    db(&f)
        .execute(
            "UPDATE job_execution SET timeout_ms=1 WHERE job_id=?1",
            [job.as_str()],
        )
        .unwrap();
    let attempt = AttemptRef::from(&launched(&f, &job));
    let timing = f.store.attempt_timing(attempt.attempt_id.clone()).unwrap();
    let deadline = timing.deadline().expect("captured 1 ms budget");
    let commit = prepared(&f, &attempt, 'e');
    while Instant::now() < deadline {
        std::thread::yield_now();
    }
    let before = facts(&f, &attempt);
    assert_eq!(
        refused(f.store.commit_publication(commit)),
        CommitRefusal::DeadlineExpired
    );
    // Not succeeded, not published, cleanup still pending, sequence unused:
    // the attempt can still be finalized with its deadline outcome.
    assert_eq!(facts(&f, &attempt), before);
    assert_eq!(before.0, "running");
    assert_eq!(before.3, "pending");
    assert!(
        f.store
            .publication_for_attempt(attempt.attempt_id.clone())
            .unwrap()
            .is_none()
    );
}

#[test]
fn the_shutdown_barrier_first_prevents_publication() {
    let f = Fixture::new();
    let attempt = running(&f, "shutdown-first");
    let commit = prepared(&f, &attempt, 'f');
    let instance = f.store.identity().unwrap().instance_id;
    f.store.signal_shutdown(instance, 5_000).unwrap();
    assert!(f.store.is_stopping());
    let before = facts(&f, &attempt);
    assert_eq!(
        refused(f.store.commit_publication(commit)),
        CommitRefusal::ShutdownBarrier
    );
    assert_eq!(facts(&f, &attempt), before);
    // The other order: a terminal commit made first keeps its success.
    let f = Fixture::new();
    let attempt = running(&f, "commit-first");
    let commit = prepared(&f, &attempt, '5');
    assert!(matches!(
        f.store.commit_publication(commit),
        Ok(CommitOutcome::Committed(_))
    ));
    let instance = f.store.identity().unwrap().instance_id;
    f.store.signal_shutdown(instance, 5_000).unwrap();
    assert_eq!(facts(&f, &attempt).0, "succeeded");
    assert_eq!(facts(&f, &attempt).7, 1);
}

#[test]
fn stale_identities_unprepared_allocations_and_unmatched_witnesses_never_publish() {
    let f = Fixture::new();
    // A dispatched attempt without a recorded launch: the cleanup witness
    // cannot match any launch identity.
    let job = accept(&f, "unlaunched").job_id;
    let unlaunched = AttemptRef::from(&dispatch(&f, &job));
    let commit = prepared(&f, &unlaunched, '1');
    let before = facts(&f, &unlaunched);
    assert_eq!(f.store.commit_publication(commit), Err(CoreError::Conflict));
    assert_eq!(facts(&f, &unlaunched), before);

    let f = Fixture::new();
    let attempt = running(&f, "stale");
    let commit = prepared(&f, &attempt, '2');
    let before = facts(&f, &attempt);
    // Another session's identity for the same attempt.
    let mut wrong = commit.clone();
    wrong.attempt.session_id = format!("ses_{}", hex('9'));
    assert_eq!(f.store.commit_publication(wrong), Err(CoreError::Conflict));
    // Another grant for the same attempt.
    let mut grant = commit.clone();
    grant.attempt.grant_id = format!("grt_{}", hex('9'));
    assert_eq!(f.store.commit_publication(grant), Err(CoreError::Conflict));
    // A file digest that differs from the prepared row.
    let mut changed = commit.clone();
    changed.files[0].sha256 = [9; 32];
    assert_eq!(
        f.store.commit_publication(changed),
        Err(CoreError::Conflict)
    );
    // A missing file.
    let mut missing = commit.clone();
    missing.files.pop();
    assert_eq!(
        f.store.commit_publication(missing),
        Err(CoreError::Conflict)
    );
    // An allocation that is not `prepared`.
    for state in ["preparing", "failed", "reclaiming"] {
        db(&f)
            .execute(
                "UPDATE publication_allocations SET state=?2 WHERE attempt_id=?1",
                [attempt.attempt_id.as_str(), state],
            )
            .unwrap();
        assert_eq!(
            refused(f.store.commit_publication(commit.clone())),
            CommitRefusal::NotPrepared,
            "{state}"
        );
    }
    db(&f)
        .execute(
            "UPDATE publication_allocations SET state='prepared' WHERE attempt_id=?1",
            [attempt.attempt_id.as_str()],
        )
        .unwrap();
    assert_eq!(facts(&f, &attempt), before);
    // Running work never has established cleanup outside this commit; a
    // recorded fault or confirmation is store corruption, not eligibility.
    for status in ["fault", "confirmed"] {
        db(&f)
            .execute(
                "UPDATE job_attempts SET cleanup_status=?2 WHERE attempt_id=?1",
                [attempt.attempt_id.as_str(), status],
            )
            .unwrap();
        db(&f)
            .execute(
                "UPDATE job_execution SET cleanup_status=?2 WHERE job_id=?1",
                [attempt.job_id.as_str(), status],
            )
            .unwrap();
        assert_eq!(
            f.store.commit_publication(commit.clone()),
            Err(CoreError::InvalidStore),
            "{status}"
        );
        assert_eq!(facts(&f, &attempt).7, 0, "{status}: nothing published");
    }
    // Terminal work (as finalization or recovery would leave it).
    db(&f)
        .execute(
            "UPDATE job_execution SET state='interrupted' WHERE job_id=?1",
            [attempt.job_id.as_str()],
        )
        .unwrap();
    assert_eq!(
        refused(f.store.commit_publication(commit)),
        CommitRefusal::NotRunning
    );
    assert_eq!(f.store.result_usage().unwrap().published_bytes, 0);
}

#[test]
fn a_running_attempt_without_its_live_clock_is_not_publishable() {
    let f = Fixture::new();
    let attempt = running(&f, "no-clock");
    let commit = prepared(&f, &attempt, '3');
    // Only this instance's dispatch registers the clock; restart never
    // reconstructs one. Simulate its absence by changing the attempt's owner.
    db(&f)
        .execute_batch(&format!(
            "INSERT INTO service_sessions VALUES('ins_{0}',0,1,'unclean');
             UPDATE job_attempts SET instance_id='ins_{0}' WHERE attempt_id='{1}';",
            hex('7'),
            attempt.attempt_id
        ))
        .unwrap();
    let before = facts(&f, &attempt);
    assert_eq!(
        refused(f.store.commit_publication(commit)),
        CommitRefusal::NotCurrentSession
    );
    assert_eq!(facts(&f, &attempt), before);
}

#[test]
fn an_injected_failure_inside_the_transaction_leaves_no_partial_publication() {
    let f = Fixture::new();
    let attempt = running(&f, "rollback");
    let commit = prepared(&f, &attempt, '4');
    let before = facts(&f, &attempt);
    // Fails the very last staged statement (the event insert).
    db(&f)
        .execute_batch(
            "CREATE TRIGGER fail_publication_event BEFORE INSERT ON job_events
             WHEN NEW.snapshot_revision=3 BEGIN SELECT RAISE(ABORT,'injected'); END;",
        )
        .unwrap();
    assert!(f.store.commit_publication(commit.clone()).is_err());
    assert_eq!(facts(&f, &attempt), before);
    assert!(
        f.store
            .publication_for_attempt(attempt.attempt_id.clone())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.store.result_usage().unwrap(),
        ResultUsage {
            private_bytes: 72,
            published_bytes: 0,
            unwritten_bytes: 0,
            records: 1
        }
    );
    // Once the fault clears, the same witnesses still publish exactly once.
    db(&f)
        .execute_batch("DROP TRIGGER fail_publication_event;")
        .unwrap();
    assert!(matches!(
        f.store.commit_publication(commit),
        Ok(CommitOutcome::Committed(_))
    ));
}

/// The publication composition wired to the real Store: a candidate whose
/// report disagrees with its bytes ends the job through real finalization with
/// `result_validation_failed`, releasing on the cleanup witness. Nothing is
/// reserved and no result exists.
#[test]
fn a_refused_candidate_finalizes_through_the_real_store() {
    use crate::publication::service::{PublishOutcome, PublishRequest, publish_blocking};
    use crate::worker_protocol::{CandidateFile, CandidateReport};
    let f = Fixture::new();
    let job = accept(&f, "refused").job_id;
    let record = launched(&f, &job);
    let attempt = AttemptRef::from(&record);
    let staging = f
        .root
        .create_attempt_root(
            &RelativePath::parse(format!("execution/attempts/{}/staging", attempt.attempt_id))
                .unwrap(),
        )
        .unwrap();
    std::fs::write(staging.worker_path().join("mesh.obj"), b"v 0 0 0\n").unwrap();
    std::fs::write(staging.worker_path().join("output.json"), b"{}").unwrap();
    let probe = RelativePath::parse("results/probe").unwrap();
    f.root.write_atomic(&probe, b"unused").unwrap();
    // Capture refuses first, so the input snapshot is never read.
    let identity: dissect3d_api::InputIdentity = serde_json::from_value(serde_json::json!({
        "input_id": format!("inp_{}", hex('1')),
        "media_type": "model/obj",
        "byte_length": 6,
        "sha256": hex('0').repeat(2),
    }))
    .unwrap();
    let outcome = publish_blocking(
        &f.store,
        &f.root,
        PublishRequest {
            dispatch: record,
            report: CandidateReport {
                description_handle: "output.json".into(),
                files: vec![CandidateFile {
                    relative_name: "mesh.obj".into(),
                    byte_length: 8,
                    // Not the digest of the bytes written above.
                    sha256: hex('f').repeat(2),
                }],
            },
            cleanup: evidence(&attempt),
            staging,
            input: identity,
            input_reader: f.root.open_immutable_input(&probe).unwrap(),
        },
    );
    assert!(matches!(outcome, PublishOutcome::Ended(_)), "{outcome:?}");
    let after = facts(&f, &attempt);
    assert_eq!(
        (
            after.0.as_str(),
            after.2.as_deref(),
            after.3.as_str(),
            after.4.as_str()
        ),
        (
            "failed",
            Some("result_validation_failed"),
            "confirmed",
            "confirmed"
        )
    );
    assert_eq!(
        (after.6, after.7),
        (None, 0),
        "nothing reserved or published"
    );
    assert_eq!(f.store.result_usage().unwrap(), ResultUsage::default());
}
