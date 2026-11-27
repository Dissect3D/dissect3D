//! WE-P07/3 durable engine-shutdown stop intent (2026-11-24). The shutdown
//! barrier transaction marks every running attempt with engine-shutdown stop
//! intent, keeps an earlier user cancellation and queued work as they are,
//! and is serialized with publication inside the Store. Restart after a
//! barrier that no outcome followed records the shutdown, not a plain restart.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
use super::cleanup::AttemptRef;
use super::execution_page_tests::reopen;
use super::launch_identity::LaunchRecord;
use super::launch_identity_tests::{launch_identity, launched, running_on};
use super::results_commit::CommitRefusal;
use super::results_commit_tests::{facts, prepared, refused};
use super::retry_tests::{accept, authorize, db};
use super::*;
use crate::execution::types::StopIntent;

/// (state, phase, revision, outcome, events)
fn job(f: &Fixture, job: &JobId) -> (String, String, i64, Option<String>, i64) {
    db(f)
        .query_row(
            "SELECT state,phase,snapshot_revision,outcome_code,
                    (SELECT count(*) FROM job_events WHERE job_id=?1)
             FROM job_execution WHERE job_id=?1",
            [job.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap()
}

/// One running, one user-canceled and one queued job.
fn three_jobs(f: &Fixture) -> (AttemptRef, AttemptRef, JobId) {
    let auth = authorize(f);
    let running = accept(f, "running").job_id;
    let running = AttemptRef::from(&launched(f, &running));
    let canceling = running_on(f, "canceling", "cpu:other");
    assert_eq!(
        f.store
            .cancel_execution_job(auth, canceling.job_id.clone())
            .unwrap(),
        "requested"
    );
    let queued = accept(f, "queued").job_id;
    (running, canceling, queued)
}

fn check_barrier_marks(f: &Fixture, barrier: impl FnOnce(&Fixture)) {
    let (running, canceling, queued) = three_jobs(f);
    let before = (
        job(f, &running.job_id),
        job(f, &canceling.job_id),
        job(f, &queued),
    );
    barrier(f);
    assert!(f.store.is_stopping());
    // Running work carries the intent, in one revision with its event.
    let (state, phase, revision, outcome, events) = job(f, &running.job_id);
    assert_eq!(
        (state.as_str(), phase.as_str()),
        ("running", "engine_stopping")
    );
    assert_eq!(revision, before.0.2 + 1);
    assert_eq!(events, before.0.4 + 1);
    assert_eq!(
        outcome, None,
        "no outcome before termination is established"
    );
    // The earlier user cancellation and the queued job are unchanged.
    assert_eq!(job(f, &canceling.job_id), before.1);
    assert_eq!(job(f, &queued), before.2);
    // The controller reads the committed intent, so nothing new launches.
    assert_eq!(
        f.store.attempt_stop_intent(running.clone()).unwrap(),
        StopIntent::EngineShutdown
    );
    assert_eq!(
        f.store.attempt_stop_intent(canceling).unwrap(),
        StopIntent::UserCancel
    );
}

#[test]
fn the_signal_barrier_durably_marks_running_attempts_only() {
    let f = Fixture::new();
    check_barrier_marks(&f, |f| {
        let instance = f.store.identity().unwrap().instance_id;
        f.store.signal_shutdown(instance, 5_000).unwrap();
    });
}

#[test]
fn the_requested_barrier_durably_marks_running_attempts_only() {
    let f = Fixture::new();
    check_barrier_marks(&f, |f| {
        let instance = f.store.identity().unwrap().instance_id;
        f.store
            .request_shutdown(
                f.auth.clone(),
                instance,
                IdempotencyKey::parse("stop-1").unwrap(),
            )
            .unwrap();
    });
}

#[test]
fn a_barrier_that_never_commits_marks_nothing() {
    let f = Fixture::new();
    let running = accept(&f, "running").job_id;
    let running = AttemptRef::from(&launched(&f, &running));
    let before = job(&f, &running.job_id);
    f.store.fail_next_shutdown_commit().unwrap();
    let instance = f.store.identity().unwrap().instance_id;
    assert!(
        f.store
            .request_shutdown(
                f.auth.clone(),
                instance,
                IdempotencyKey::parse("stop-1").unwrap(),
            )
            .is_err()
    );
    assert!(!f.store.is_stopping());
    assert_eq!(job(&f, &running.job_id), before);
    assert_eq!(
        f.store.attempt_stop_intent(running).unwrap(),
        StopIntent::Continue
    );
}

#[test]
fn the_durable_intent_refuses_publication_and_a_prior_success_stays() {
    let f = Fixture::new();
    let first = accept(&f, "published").job_id;
    let first = AttemptRef::from(&launched(&f, &first));
    let commit = prepared(&f, &first, 'a');
    assert!(f.store.commit_publication(commit).is_ok());
    let marked = running_on(&f, "marked", "cpu:other");
    f.store
        .record_launch_identity(LaunchRecord {
            attempt: marked.clone(),
            identity: launch_identity(&marked),
        })
        .unwrap();
    let candidate = prepared(&f, &marked, 'b');
    let instance = f.store.identity().unwrap().instance_id;
    f.store.signal_shutdown(instance, 5_000).unwrap();
    // Publication committed first stays successful and is not marked.
    assert_eq!(facts(&f, &first).0, "succeeded");
    assert_eq!(facts(&f, &first).1, "succeeded");
    // Intent committed first: the attempt never publishes.
    let before = facts(&f, &marked);
    assert_eq!(
        refused(f.store.commit_publication(candidate)),
        CommitRefusal::ShutdownBarrier
    );
    assert_eq!(facts(&f, &marked), before);
}

#[test]
fn restart_after_an_unfinished_barrier_records_the_shutdown_and_keeps_cancellation() {
    let f = Fixture::new();
    let (running, canceling, queued) = three_jobs(&f);
    let instance = f.store.identity().unwrap().instance_id;
    f.store.signal_shutdown(instance, 5_000).unwrap();
    // The engine dies before any attempt outcome is written.
    let f = reopen(f);
    let (state, _, _, outcome, _) = job(&f, &running.job_id);
    assert_eq!(state, "interrupted");
    assert_eq!(outcome.as_deref(), Some("engine_shutdown"));
    assert_eq!(job(&f, &canceling.job_id).0, "cancel_requested");
    assert_eq!(job(&f, &queued).0, "queued");
    // Without a barrier, restart stays a plain restart.
    let other = running_on(&f, "after-restart", "cpu:third");
    let f = reopen(f);
    assert_eq!(
        job(&f, &other.job_id).3.as_deref(),
        Some("engine_restarted")
    );
}
