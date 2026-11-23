//! WE-P06/1 dispatch turns against the real Store: FIFO among eligible jobs,
//! a blocked first job, atomic coordinated reservation, cancellation before
//! dispatch and concurrent duplicate requests.
use super::cleanup::AttemptRef;
use super::finalize::AttemptFinalization;
use super::launch_identity_tests::{evidence, record_launch};
use super::retry_tests::{accept, authorize, db};
use super::*;
use crate::execution::scheduler::{Eligibility, dispatch_turn};
use crate::execution::types::{AttemptCleanup, AttemptEnd};
use execution::QueuedCandidate;

fn on(resources: &[&str]) -> Eligibility {
    Eligibility::Ready {
        resources: resources.iter().map(|r| r.to_string()).collect(),
    }
}

/// (state, snapshot revision, attempt rows, held reservations)
fn facts(f: &Fixture, job: &JobId) -> (String, i64, i64, i64) {
    db(f)
        .query_row(
            "SELECT e.state,e.snapshot_revision,
                    (SELECT count(*) FROM job_attempts a WHERE a.job_id=e.job_id),
                    (SELECT count(*) FROM resource_reservations r JOIN job_attempts a
                      USING(attempt_id) WHERE a.job_id=e.job_id AND r.released=0)
             FROM job_execution e WHERE e.job_id=?1",
            [job.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

fn held(f: &Fixture, resource: &str) -> i64 {
    db(f)
        .query_row(
            "SELECT count(*) FROM resource_reservations WHERE resource_id=?1 AND released=0",
            [resource],
            |r| r.get(0),
        )
        .unwrap()
}

/// End an attempt with confirmed cleanup, releasing its reservations.
fn finish(f: &Fixture, record: &execution::DispatchRecord) {
    record_launch(f, record);
    let attempt = AttemptRef::from(record);
    f.store
        .finalize_attempt(AttemptFinalization {
            attempt: attempt.clone(),
            end: AttemptEnd::WorkerFailed,
            cleanup: AttemptCleanup::Confirmed(evidence(&attempt)),
        })
        .unwrap();
}

#[test]
fn eligible_jobs_dispatch_in_acceptance_order_past_a_blocked_first_job() {
    let f = Fixture::new();
    let blocked = accept(&f, "fifo-blocked").job_id;
    let second = accept(&f, "fifo-second").job_id;
    let third = accept(&f, "fifo-third").job_id;
    let check = |c: &QueuedCandidate| {
        if c.job_id == blocked {
            Eligibility::Blocked("profile_not_executable")
        } else {
            on(&["cpu:fixture"])
        }
    };
    let turn = dispatch_turn(&f.store, check, 8);
    assert_eq!(turn.dispatched.len(), 1);
    assert_eq!(turn.dispatched[0].job_id, second, "oldest eligible first");
    assert_eq!(
        turn.waiting,
        vec![third.clone()],
        "one CPU attempt at a time"
    );
    assert_eq!(
        turn.blocked,
        vec![(blocked.clone(), "profile_not_executable")]
    );
    // The blocked job keeps its place: still queued at revision 1, no
    // attempt and no reservation.
    assert_eq!(facts(&f, &blocked), ("queued".into(), 1, 0, 0));
    assert_eq!(facts(&f, &second), ("running".into(), 2, 1, 1));
    assert_eq!(facts(&f, &third), ("queued".into(), 1, 0, 0));
    // A repeated turn launches nothing new while the resource is held.
    let again = dispatch_turn(&f.store, check, 8);
    assert!(again.dispatched.is_empty());
    assert_eq!(facts(&f, &second).2, 1, "no duplicate attempt");
    // Once cleanup releases the resource, the next eligible job runs.
    finish(&f, &turn.dispatched[0]);
    let next = dispatch_turn(&f.store, check, 8);
    assert_eq!(next.dispatched.len(), 1);
    assert_eq!(next.dispatched[0].job_id, third);
    assert_eq!(facts(&f, &blocked), ("queued".into(), 1, 0, 0));
}

#[test]
fn a_coordinated_resource_set_is_reserved_whole_or_not_at_all() {
    let f = Fixture::new();
    let gpu_holder = accept(&f, "set-gpu").job_id;
    let first = dispatch_turn(&f.store, |_: &QueuedCandidate| on(&["gpu:0"]), 8);
    assert_eq!(first.dispatched[0].job_id, gpu_holder);
    let both = accept(&f, "set-both").job_id;
    let turn = dispatch_turn(
        &f.store,
        |_: &QueuedCandidate| on(&["cpu:fixture", "gpu:0"]),
        8,
    );
    assert!(turn.dispatched.is_empty());
    assert_eq!(turn.waiting, vec![both.clone()]);
    // The free half of the set was not reserved either.
    assert_eq!(held(&f, "cpu:fixture"), 0);
    assert_eq!(facts(&f, &both), ("queued".into(), 1, 0, 0));
    finish(&f, &first.dispatched[0]);
    let turn = dispatch_turn(
        &f.store,
        |_: &QueuedCandidate| on(&["cpu:fixture", "gpu:0"]),
        8,
    );
    assert_eq!(turn.dispatched[0].job_id, both);
    assert_eq!((held(&f, "cpu:fixture"), held(&f, "gpu:0")), (1, 1));
}

#[test]
fn a_job_canceled_before_dispatch_is_never_launched() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let canceled = accept(&f, "cancel-first").job_id;
    let later = accept(&f, "cancel-later").job_id;
    assert_eq!(
        f.store
            .cancel_execution_job(auth, canceled.clone())
            .unwrap(),
        "canceled_before_dispatch"
    );
    let turn = dispatch_turn(&f.store, |_: &QueuedCandidate| on(&["cpu:fixture"]), 8);
    assert_eq!(turn.dispatched.len(), 1);
    assert_eq!(turn.dispatched[0].job_id, later);
    let (state, _, attempts, reservations) = facts(&f, &canceled);
    assert_eq!((state.as_str(), attempts, reservations), ("canceled", 0, 0));
}

#[test]
fn concurrent_duplicate_dispatch_requests_create_one_attempt() {
    let f = Fixture::new();
    let job = accept(&f, "duplicate").job_id;
    let candidate = f.store.queued_candidates(0, 1).unwrap().remove(0);
    let request = execution::DispatchRequest {
        job_id: job.clone(),
        expected_revision: candidate.snapshot_revision,
        resolved_json: candidate.resolved_json,
        resources: vec!["cpu:fixture".into()],
    };
    let records: Vec<_> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| f.store.dispatch_attempt(request.clone())))
            .collect();
        threads.into_iter().map(|t| t.join().unwrap()).collect()
    });
    let attempts: Vec<String> = records.into_iter().map(|r| r.unwrap().attempt_id).collect();
    // Every caller gets the one live attempt; launch is keyed by its ID.
    assert!(attempts.iter().all(|a| *a == attempts[0]));
    assert_eq!(facts(&f, &job), ("running".into(), 2, 1, 1));
}

#[test]
fn queued_candidates_are_oldest_first_bounded_and_resume_after_a_sequence() {
    let f = Fixture::new();
    let jobs: Vec<JobId> = (0..3)
        .map(|i| accept(&f, &format!("page-{i}")).job_id)
        .collect();
    let first = f.store.queued_candidates(0, 2).unwrap();
    assert_eq!(
        first.iter().map(|c| c.job_id.clone()).collect::<Vec<_>>(),
        jobs[..2]
    );
    assert!(
        first
            .iter()
            .all(|c| c.storage_verified && c.snapshot_revision == 1)
    );
    let rest = f
        .store
        .queued_candidates(first[1].acceptance_sequence, 2)
        .unwrap();
    assert_eq!(
        rest.iter().map(|c| c.job_id.clone()).collect::<Vec<_>>(),
        jobs[2..]
    );
    assert_eq!(
        f.store.queued_candidates(0, 0),
        Err(CoreError::Conflict),
        "bounded"
    );
    assert_eq!(
        f.store.queued_candidates(0, execution::CANDIDATE_PAGE + 1),
        Err(CoreError::Conflict)
    );
}

/// Cancellation committed after the candidate read but before the dispatch
/// transaction: the Store refuses the stale request and nothing launches.
#[test]
fn a_cancellation_between_the_read_and_dispatch_prevents_the_launch() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let job = accept(&f, "cancel-window").job_id;
    let turn = dispatch_turn(
        &f.store,
        |c: &QueuedCandidate| {
            assert_eq!(
                f.store
                    .cancel_execution_job(auth.clone(), c.job_id.clone())
                    .unwrap(),
                "canceled_before_dispatch"
            );
            on(&["cpu:fixture"])
        },
        8,
    );
    assert!(turn.dispatched.is_empty());
    assert!(turn.uncertain.is_none() && turn.stopped.is_none());
    let (state, _, attempts, reservations) = facts(&f, &job);
    assert_eq!((state.as_str(), attempts, reservations), ("canceled", 0, 0));
}
