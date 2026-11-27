//! Supplementary attempt-deadline cases: WE-P03 dispatch-reply timing (AD-01/AD-02,
//! 2026-11-17) and RP-P03 publication timing (AD-01..AD-05, 2026-11-23).
//! Kept beside the Store because the timing record and the actor pause hook are
//! crate-private; the proposed `tests/attempt_deadline.rs` target would need new
//! public hooks. Dispatch stays inactive outside tests.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
use super::cleanup::AttemptRef;
use super::execution_page_tests::reopen;
use super::finalize::AttemptFinalization;
use super::launch_identity_tests::{evidence, launched};
use super::results_commit::{CommitOutcome, CommitRefusal, PublicationCommit};
use super::results_commit_tests::{facts, prepared, refused, running};
use super::retry_tests::{self, db};
use super::*;
use crate::execution::types::{AttemptCleanup, AttemptEnd};

fn timed_job(f: &Fixture, key: &str, timeout_ms: u64) -> (execution::DispatchRequest, JobId) {
    let mut req = f.request(&f.capture());
    req.execution.timeout_ms = Some(timeout_ms);
    let accepted = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse(key).unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap();
    (
        execution::DispatchRequest {
            job_id: accepted.job_id.clone(),
            expected_revision: 1,
            resolved_json: serde_json::to_string(&accepted.resolved).unwrap(),
            resources: vec!["cpu:fixture".into()],
        },
        accepted.job_id,
    )
}
fn attempt_of(f: &Fixture, job: &JobId) -> (String, i64) {
    db(f)
        .query_row(
            "SELECT a.attempt_id,e.snapshot_revision FROM job_attempts a
             JOIN job_execution e USING(job_id) WHERE a.job_id=?1",
            [job.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}
fn wait_until(deadline: Instant) {
    while Instant::now() < deadline {
        std::thread::yield_now();
    }
}

/// AD-01: a reply held across expiry carries the Store's original record. It
/// neither starts nor renews a budget, and the Store keeps the same record.
#[test]
fn delayed_dispatch_reply_cannot_renew_the_store_owned_timing_record() {
    let f = Fixture::new();
    let (request, job) = timed_job(&f, "delayed-reply", 5);
    let (reply, held) = mpsc::sync_channel(1);
    f.store
        .sender
        .send(Command::Execution(execution::ExecutionCommand::Dispatch(
            request, reply,
        )))
        .ok()
        .unwrap();
    // Without reading the reply, the Store already owns the live record.
    let (attempt, revision) = loop {
        let dispatched: i64 = db(&f)
            .query_row(
                "SELECT count(*) FROM job_attempts WHERE job_id=?1",
                [job.as_str()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if dispatched == 1 {
            break attempt_of(&f, &job);
        }
        std::thread::yield_now();
    };
    let owned = f.store.attempt_timing(attempt.clone()).unwrap();
    wait_until(owned.deadline().unwrap());
    let received_at = Instant::now();
    let delivered = held.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    assert!(Arc::ptr_eq(&delivered.timing, &owned));
    assert!(delivered.timing.started() < received_at);
    assert!(
        delivered.timing.expired(),
        "late receipt gets no new budget"
    );
    assert!(Arc::ptr_eq(
        &f.store.attempt_timing(attempt.clone()).unwrap(),
        &owned
    ));
    assert_eq!(attempt_of(&f, &job), (attempt, revision));
}

/// AD-01/AD-02: after an abandoned reply, a controller recovering the dispatch
/// obtains the same record, sees expiry before launch, and creates no attempt.
#[test]
fn recovering_an_abandoned_dispatch_returns_the_same_record_and_rechecks_expiry() {
    let f = Fixture::new();
    let (request, job) = timed_job(&f, "abandoned-reply", 5);
    let (reply, abandoned) = mpsc::sync_channel(1);
    drop(abandoned);
    f.store
        .sender
        .send(Command::Execution(execution::ExecutionCommand::Dispatch(
            request.clone(),
            reply,
        )))
        .ok()
        .unwrap();
    let recovered = f.store.dispatch_attempt(request.clone()).unwrap();
    let (attempt, revision) = attempt_of(&f, &job);
    assert_eq!(recovered.attempt_id, attempt);
    let owned = f.store.attempt_timing(attempt.clone()).unwrap();
    assert!(Arc::ptr_eq(&recovered.timing, &owned));
    wait_until(owned.deadline().unwrap());
    // A later recovery is the same record and must refuse launch on expiry.
    let again = f.store.dispatch_attempt(request).unwrap();
    assert!(Arc::ptr_eq(&again.timing, &owned));
    assert_eq!(again.timing.started(), recovered.timing.started());
    assert!(again.timing.expired());
    assert_eq!(attempt_of(&f, &job), (attempt, revision));
    assert_eq!(
        db(&f)
            .query_row("SELECT count(*) FROM job_attempts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

// RP-P03/3-/4 publication cases (2026-11-23). The final eligibility check is
// the Store's own sample of this record immediately before success COMMIT.

fn timed_running(f: &Fixture, key: &str, timeout_ms: i64) -> AttemptRef {
    let job = retry_tests::accept(f, key).job_id;
    db(f)
        .execute(
            "UPDATE job_execution SET timeout_ms=?2 WHERE job_id=?1",
            rusqlite::params![job.as_str(), timeout_ms],
        )
        .unwrap();
    AttemptRef::from(&launched(f, &job))
}
fn send_commit(
    f: &Fixture,
    commit: &PublicationCommit,
) -> mpsc::Receiver<Result<CommitOutcome, CoreError>> {
    let (reply, held) = mpsc::sync_channel(1);
    f.store
        .sender
        .send(Command::Execution(
            execution::ExecutionCommand::CommitPublication(Box::new(commit.clone()), reply),
        ))
        .ok()
        .unwrap();
    held
}
fn wait_for_result(f: &Fixture, attempt: &AttemptRef) {
    let give_up = Instant::now() + Duration::from_secs(5);
    while db(f)
        .query_row(
            "SELECT count(*) FROM results WHERE attempt_id=?1",
            [attempt.attempt_id.as_str()],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        == 0
    {
        assert!(Instant::now() < give_up, "the commit never landed");
        std::thread::yield_now();
    }
}
fn finalize_late(f: &Fixture, attempt: &AttemptRef) -> Result<(), CoreError> {
    f.store
        .finalize_attempt(AttemptFinalization {
            attempt: attempt.clone(),
            end: AttemptEnd::DeadlineExceeded,
            cleanup: AttemptCleanup::Confirmed(evidence(attempt)),
        })
        .map(|_| ())
}
/// (state, outcome, allocation, results rows)
fn outcome(f: &Fixture, attempt: &AttemptRef) -> (String, Option<String>, Option<String>, i64) {
    let facts = facts(f, attempt);
    (facts.0, facts.2, facts.6, facts.7)
}
fn published() -> (String, Option<String>, Option<String>, i64) {
    ("succeeded".into(), None, Some("published".into()), 1)
}

/// AD-01: an eligible success COMMIT whose reply is held until after expiry
/// stays committed. The late expiry cannot turn it into a deadline failure.
#[test]
fn an_eligible_commit_acknowledged_after_expiry_stays_committed() {
    let f = Fixture::new();
    let attempt = timed_running(&f, "late-ack", 1_000);
    let timing = f.store.attempt_timing(attempt.attempt_id.clone()).unwrap();
    let commit = prepared(&f, &attempt, 'a');
    let held = send_commit(&f, &commit);
    wait_for_result(&f, &attempt);
    wait_until(timing.deadline().unwrap());
    let Ok(CommitOutcome::Committed(receipt)) = held.recv_timeout(Duration::from_secs(2)).unwrap()
    else {
        panic!("an eligible commit acknowledged late was not reported committed")
    };
    assert!(timing.expired(), "acknowledged only after the deadline");
    assert_eq!(finalize_late(&f, &attempt), Err(CoreError::Conflict));
    assert_eq!(outcome(&f, &attempt), published());
    assert_eq!(
        f.store.publication_for_attempt(attempt.attempt_id.clone()),
        Ok(Some(receipt.clone()))
    );
    assert_eq!(
        f.store.commit_publication(commit),
        Ok(CommitOutcome::Committed(receipt))
    );
}

/// AD-01: the success COMMIT passed its final check in time but completes
/// only after expiry (the barrier stands in for a slow COMMIT/fsync). It
/// stays committed; nothing re-reads the clock after the check.
#[test]
fn an_eligible_commit_completing_after_expiry_stays_committed() {
    let f = Fixture::new();
    let attempt = timed_running(&f, "slow-commit", 1_000);
    let timing = f.store.attempt_timing(attempt.attempt_id.clone()).unwrap();
    let commit = prepared(&f, &attempt, '2');
    let (entered, in_commit) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    f.store
        .sender
        .send(Command::Execution(
            execution::ExecutionCommand::HoldNextCommit(entered, resume),
        ))
        .ok()
        .unwrap();
    let held = send_commit(&f, &commit);
    in_commit.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!timing.expired(), "the final check ran in time");
    wait_until(timing.deadline().unwrap());
    release.send(()).unwrap();
    let Ok(CommitOutcome::Committed(receipt)) = held.recv_timeout(Duration::from_secs(5)).unwrap()
    else {
        panic!("an eligible COMMIT completing late was not reported committed")
    };
    assert_eq!(finalize_late(&f, &attempt), Err(CoreError::Conflict));
    assert_eq!(outcome(&f, &attempt), published());
    assert_eq!(
        f.store.publication_for_attempt(attempt.attempt_id.clone()),
        Ok(Some(receipt))
    );
}

/// AD-01: the acknowledgement is lost entirely. Re-querying after expiry
/// returns the committed identity; nothing reports failure.
#[test]
fn a_lost_commit_acknowledgement_is_recovered_by_reading_after_expiry() {
    let f = Fixture::new();
    let attempt = timed_running(&f, "lost-ack", 1_000);
    let timing = f.store.attempt_timing(attempt.attempt_id.clone()).unwrap();
    let commit = prepared(&f, &attempt, 'b');
    drop(send_commit(&f, &commit));
    wait_for_result(&f, &attempt);
    wait_until(timing.deadline().unwrap());
    let receipt = f
        .store
        .publication_for_attempt(attempt.attempt_id.clone())
        .unwrap()
        .expect("committed before the acknowledgement was lost");
    assert_eq!(receipt.snapshot_revision, 3);
    assert_eq!(finalize_late(&f, &attempt), Err(CoreError::Conflict));
    assert_eq!(
        f.store.commit_publication(commit),
        Ok(CommitOutcome::Committed(receipt))
    );
    assert_eq!(outcome(&f, &attempt), published());
}

/// AD-02: the caller saw an eligible clock and enqueued the commit, but the
/// actor reached it only after expiry. The Store's fresh check refuses it and
/// nothing is staged; the attempt can still end with its deadline outcome.
#[test]
fn a_commit_enqueued_while_eligible_is_refused_when_the_actor_reaches_it_after_expiry() {
    let f = Fixture::new();
    let attempt = timed_running(&f, "queued-commit", 1_000);
    let timing = f.store.attempt_timing(attempt.attempt_id.clone()).unwrap();
    let commit = prepared(&f, &attempt, 'c');
    let before = facts(&f, &attempt);
    let (entered, paused) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    f.store
        .sender
        .send(Command::PauseExecutionQueue(entered, resume))
        .ok()
        .unwrap();
    paused.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(!timing.expired(), "eligible when the caller enqueued");
    let held = send_commit(&f, &commit);
    wait_until(timing.deadline().unwrap());
    release.send(()).unwrap();
    assert_eq!(
        refused(held.recv_timeout(Duration::from_secs(5)).unwrap()),
        CommitRefusal::DeadlineExpired
    );
    assert_eq!(facts(&f, &attempt), before);
    finalize_late(&f, &attempt).unwrap();
    let after = outcome(&f, &attempt);
    assert_eq!(
        (after.0.as_str(), after.1.as_deref(), after.3),
        ("failed", Some("execution_deadline_exceeded"), 0)
    );
}

/// Move the attempt's stored dispatch wall reading by `delta` milliseconds.
fn shift_dispatch_wall(f: &Fixture, attempt: &AttemptRef, delta: &str) {
    db(f)
        .execute(
            &format!("UPDATE job_attempts SET dispatched_at_ms=dispatched_at_ms{delta} WHERE attempt_id=?1"),
            [attempt.attempt_id.as_str()],
        )
        .unwrap();
}

/// AD-04: diagnostic wall-clock readings (the stored dispatch time and the
/// commit's publication time) move backward and forward; eligibility follows
/// only the monotonic record. The Store's own `now_ms()` is not injectable.
#[test]
fn diagnostic_wall_clock_readings_never_decide_publication_eligibility() {
    let f = Fixture::new();
    // Backward wall time while the monotonic budget remains: publishes.
    let eligible = timed_running(&f, "wall-back", 60_000);
    shift_dispatch_wall(&f, &eligible, "-3600000");
    let mut commit = prepared(&f, &eligible, 'd');
    commit.published_at_ms = 0;
    assert!(matches!(
        f.store.commit_publication(commit),
        Ok(CommitOutcome::Committed(_))
    ));
    assert_eq!(outcome(&f, &eligible), published());
    // Far-future wall time after the monotonic budget passed: refused.
    let expired = timed_running(&f, "wall-forward", 1);
    let timing = f.store.attempt_timing(expired.attempt_id.clone()).unwrap();
    shift_dispatch_wall(&f, &expired, "+3600000");
    let mut late = prepared(&f, &expired, 'e');
    late.published_at_ms = i64::MAX as u64;
    wait_until(timing.deadline().unwrap());
    assert_eq!(
        refused(f.store.commit_publication(late)),
        CommitRefusal::DeadlineExpired
    );
    assert_eq!(outcome(&f, &expired).0, "running");
}

/// AD-05: restart. An uncommitted active attempt with a prepared candidate
/// is interrupted with no live clock and is never salvaged; a success that
/// committed before restart stays successful however much time passed.
#[test]
fn restart_interrupts_an_uncommitted_candidate_and_keeps_a_committed_success() {
    let f = Fixture::new();
    let committed = timed_running(&f, "restart-done", 1_000);
    let committed_timing = f
        .store
        .attempt_timing(committed.attempt_id.clone())
        .unwrap();
    let Ok(CommitOutcome::Committed(receipt)) =
        f.store.commit_publication(prepared(&f, &committed, 'f'))
    else {
        panic!("eligible commit refused")
    };
    let active = running(&f, "restart-active");
    let candidate = prepared(&f, &active, '1');
    wait_until(committed_timing.deadline().unwrap());
    let f = reopen(f);
    assert_eq!(outcome(&f, &committed), published());
    assert_eq!(
        f.store
            .publication_for_attempt(committed.attempt_id.clone()),
        Ok(Some(receipt))
    );
    for attempt in [&committed, &active] {
        assert_eq!(
            f.store.attempt_timing(attempt.attempt_id.clone()).err(),
            Some(CoreError::NotFound),
            "restart never reconstructs a clock"
        );
    }
    let interrupted = facts(&f, &active);
    assert_eq!(
        (
            interrupted.0.as_str(),
            interrupted.4.as_str(),
            interrupted.7
        ),
        ("interrupted", "pending", 0)
    );
    assert_eq!(
        refused(f.store.commit_publication(candidate)),
        CommitRefusal::NotRunning
    );
    assert_eq!(facts(&f, &active), interrupted, "no salvage");
}
