//! WE-P03 supplementary dispatch-reply timing cases (AD-01/AD-02, 2026-11-17).
//! Kept beside the Store because the timing record and the actor pause hook are
//! crate-private; the proposed `tests/attempt_deadline.rs` target would need new
//! public hooks. Dispatch stays inactive outside tests.
use super::retry_tests::db;
use super::*;

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
