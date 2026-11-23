//! WE-P06/1 dispatch-turn decisions against a scripted Store. The real Store
//! transaction (atomic reservation, cancel-before-dispatch, duplicates) is
//! exercised in `store/dispatch_turn_tests.rs`.
use super::scheduler::{DispatchStore, Eligibility, dispatch_turn, queued_blockers};
use crate::CoreError;
use crate::store::execution::{AttemptTiming, DispatchRecord, DispatchRequest, QueuedCandidate};
use dissect3d_api::JobId;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

fn job(n: u32) -> JobId {
    JobId::parse(format!("job_{n:032x}")).unwrap()
}

fn candidate(n: u32) -> QueuedCandidate {
    QueuedCandidate {
        job_id: job(n),
        acceptance_sequence: i64::from(n),
        snapshot_revision: 1,
        resolved_json: format!("{{\"job\":{n}}}"),
        storage_verified: true,
    }
}

fn record(request: &DispatchRequest) -> DispatchRecord {
    DispatchRecord {
        job_id: request.job_id.clone(),
        attempt_id: format!("att_{}", &request.job_id.as_str()[4..]),
        session_id: "ses".into(),
        grant_id: "grt".into(),
        resolved_json: request.resolved_json.clone(),
        resources: request.resources.clone(),
        timeout_ms: None,
        timing: Arc::new(AttemptTiming::for_validation_test()),
    }
}

/// Queued candidates plus scripted dispatch answers per job; every dispatch
/// request is recorded.
#[derive(Default)]
struct Scripted {
    queued: Vec<QueuedCandidate>,
    answers: Mutex<HashMap<JobId, VecDeque<Result<(), CoreError>>>>,
    requests: Mutex<Vec<DispatchRequest>>,
    fail_reads_after: Mutex<Option<usize>>,
}

impl Scripted {
    fn new(queued: Vec<QueuedCandidate>) -> Self {
        Self {
            queued,
            ..Self::default()
        }
    }
    fn answer(self, n: u32, answers: Vec<Result<(), CoreError>>) -> Self {
        self.answers.lock().unwrap().insert(job(n), answers.into());
        self
    }
    fn dispatched_jobs(&self) -> Vec<JobId> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.job_id.clone())
            .collect()
    }
}

impl DispatchStore for Scripted {
    fn queued_candidates(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> Result<Vec<QueuedCandidate>, CoreError> {
        let mut reads = self.fail_reads_after.lock().unwrap();
        if let Some(left) = reads.as_mut() {
            if *left == 0 {
                return Err(CoreError::StoreUnavailable);
            }
            *left -= 1;
        }
        Ok(self
            .queued
            .iter()
            .filter(|c| c.acceptance_sequence > after_sequence)
            .take(limit)
            .cloned()
            .collect())
    }
    fn dispatch(&self, request: DispatchRequest) -> Result<DispatchRecord, CoreError> {
        self.requests.lock().unwrap().push(request.clone());
        let answer = self
            .answers
            .lock()
            .unwrap()
            .get_mut(&request.job_id)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(()));
        answer.map(|()| record(&request))
    }
}

fn ready(_: &QueuedCandidate) -> Eligibility {
    Eligibility::Ready {
        resources: vec!["cpu:fixture".into()],
    }
}

fn ids(records: &[DispatchRecord]) -> Vec<JobId> {
    records.iter().map(|r| r.job_id.clone()).collect()
}

#[test]
fn a_blocked_first_job_keeps_its_place_and_reserves_nothing_while_eligible_work_runs_in_order() {
    let store = Scripted::new(vec![candidate(1), candidate(2), candidate(3)])
        .answer(3, vec![Err(CoreError::Busy)]);
    let turn = dispatch_turn(
        &store,
        |c: &QueuedCandidate| {
            if c.job_id == job(1) {
                Eligibility::Blocked("profile_not_executable")
            } else {
                ready(c)
            }
        },
        8,
    );
    assert_eq!(ids(&turn.dispatched), vec![job(2)]);
    assert_eq!(turn.blocked, vec![(job(1), "profile_not_executable")]);
    assert_eq!(turn.waiting, vec![job(3)], "its resources are held");
    // The blocked job never reached the Store's reservation transaction.
    assert_eq!(store.dispatched_jobs(), vec![job(2), job(3)]);
    assert_eq!(turn.uncertain, None);
    assert_eq!(turn.stopped, None);
}

#[test]
fn each_request_carries_the_exact_captured_revision_resolution_and_resources() {
    let mut first = candidate(1);
    first.snapshot_revision = 1;
    let store = Scripted::new(vec![first.clone()]);
    let turn = dispatch_turn(
        &store,
        |_: &QueuedCandidate| Eligibility::Ready {
            resources: vec!["cpu:fixture".into(), "mem:fixture".into()],
        },
        8,
    );
    assert_eq!(turn.dispatched.len(), 1);
    let request = store.requests.lock().unwrap()[0].clone();
    assert_eq!(request.expected_revision, first.snapshot_revision);
    assert_eq!(request.resolved_json, first.resolved_json);
    assert_eq!(request.resources, vec!["cpu:fixture", "mem:fixture"]);
}

#[test]
fn the_turn_stops_at_its_dispatch_bound_in_acceptance_order() {
    let store = Scripted::new(vec![candidate(1), candidate(2)]);
    let turn = dispatch_turn(&store, ready, 1);
    assert_eq!(ids(&turn.dispatched), vec![job(1)]);
    assert_eq!(
        store.dispatched_jobs(),
        vec![job(1)],
        "the next is not tried"
    );
}

#[test]
fn a_job_changed_or_canceled_since_the_read_is_skipped_without_retry() {
    let store = Scripted::new(vec![candidate(1), candidate(2), candidate(3)])
        .answer(1, vec![Err(CoreError::Conflict)])
        .answer(2, vec![Err(CoreError::NotFound)]);
    let turn = dispatch_turn(&store, ready, 8);
    assert_eq!(ids(&turn.dispatched), vec![job(3)]);
    assert_eq!(store.dispatched_jobs(), vec![job(1), job(2), job(3)]);
}

#[test]
fn an_uncertain_dispatch_is_resolved_by_replaying_the_identical_request_once() {
    let store = Scripted::new(vec![candidate(1), candidate(2)])
        .answer(1, vec![Err(CoreError::StoreUnavailable), Ok(())])
        .answer(2, vec![Err(CoreError::Busy)]);
    let turn = dispatch_turn(&store, ready, 8);
    assert_eq!(ids(&turn.dispatched), vec![job(1)]);
    let requests = store.requests.lock().unwrap().clone();
    assert_eq!(requests[0].job_id, requests[1].job_id);
    assert_eq!(requests[0].expected_revision, requests[1].expected_revision);
    assert_eq!(requests[0].resources, requests[1].resources);
    assert_eq!(turn.uncertain, None);
}

#[test]
fn a_dispatch_still_uncertain_after_replay_stops_the_turn_and_is_reported() {
    let store = Scripted::new(vec![candidate(1), candidate(2)]).answer(
        1,
        vec![
            Err(CoreError::StoreUnavailable),
            Err(CoreError::StoreUnavailable),
        ],
    );
    let turn = dispatch_turn(&store, ready, 8);
    assert!(turn.dispatched.is_empty());
    assert_eq!(turn.uncertain, Some(job(1)));
    assert_eq!(turn.stopped, Some(CoreError::StoreUnavailable));
    assert_eq!(
        store.dispatched_jobs(),
        vec![job(1), job(1)],
        "no later job"
    );
}

#[test]
fn the_live_attempt_bound_stops_the_turn() {
    let store = Scripted::new(vec![candidate(1), candidate(2)])
        .answer(1, vec![Err(CoreError::LimitReached)]);
    let turn = dispatch_turn(&store, ready, 8);
    assert!(turn.dispatched.is_empty());
    assert_eq!(turn.stopped, Some(CoreError::LimitReached));
    assert_eq!(store.dispatched_jobs(), vec![job(1)]);
}

#[test]
fn eligible_work_behind_a_full_page_of_blocked_jobs_is_reached() {
    let queued: Vec<_> = (1..=70).map(candidate).collect();
    let store = Scripted::new(queued);
    let turn = dispatch_turn(
        &store,
        |c: &QueuedCandidate| {
            if c.job_id == job(70) {
                ready(c)
            } else {
                Eligibility::Blocked("inputs_unavailable")
            }
        },
        8,
    );
    assert_eq!(ids(&turn.dispatched), vec![job(70)]);
    assert_eq!(turn.blocked.len(), 69);
}

#[test]
fn a_failed_candidate_read_keeps_the_records_already_dispatched() {
    let queued: Vec<_> = (1..=40).map(candidate).collect();
    let store = Scripted::new(queued);
    *store.fail_reads_after.lock().unwrap() = Some(1);
    let turn = dispatch_turn(
        &store,
        |c: &QueuedCandidate| {
            if c.job_id == job(1) {
                ready(c)
            } else {
                Eligibility::Blocked("inputs_unavailable")
            }
        },
        8,
    );
    assert_eq!(ids(&turn.dispatched), vec![job(1)], "never dropped");
    assert_eq!(turn.stopped, Some(CoreError::StoreUnavailable));
}

#[test]
fn a_job_with_an_input_integrity_fault_is_blocked_without_asking_or_reserving() {
    let mut faulted = candidate(1);
    faulted.storage_verified = false;
    let store = Scripted::new(vec![faulted, candidate(2)]);
    let turn = dispatch_turn(
        &store,
        |c: &QueuedCandidate| {
            assert_ne!(c.job_id, job(1), "never asked about a faulted job");
            ready(c)
        },
        8,
    );
    assert_eq!(turn.blocked, vec![(job(1), "storage_integrity_fault")]);
    assert_eq!(store.dispatched_jobs(), vec![job(2)]);
}

/// Regression (WE-P06/1 QA): a COMMIT that landed but reported an error is
/// not in the Store's live set, so the replay answers Conflict (or Busy while
/// stopping). That must stay uncertain, never "changed, skip".
#[test]
fn a_replay_refused_after_an_uncertain_dispatch_stays_uncertain() {
    for replay in [CoreError::Conflict, CoreError::NotFound, CoreError::Busy] {
        let store = Scripted::new(vec![candidate(1), candidate(2)])
            .answer(1, vec![Err(CoreError::StoreUnavailable), Err(replay)]);
        let turn = dispatch_turn(&store, ready, 8);
        assert!(turn.dispatched.is_empty(), "{replay:?}");
        assert!(turn.waiting.is_empty(), "{replay:?}");
        assert_eq!(turn.uncertain, Some(job(1)), "{replay:?}");
        assert_eq!(
            turn.stopped,
            Some(CoreError::StoreUnavailable),
            "{replay:?}"
        );
        assert_eq!(store.dispatched_jobs(), vec![job(1), job(1)], "{replay:?}");
    }
}

#[test]
fn the_blocker_scan_reports_every_blocked_queued_job_and_reserves_nothing() {
    // More than one page, with blocked jobs on both pages.
    let mut queued: Vec<_> = (1..=40).map(candidate).collect();
    queued[2].storage_verified = false;
    let store = Scripted::new(queued);
    let blocked = queued_blockers(&store, |c| {
        if c.job_id == job(5) || c.job_id == job(38) {
            Eligibility::Blocked("profile_not_executable")
        } else {
            Eligibility::Ready {
                resources: vec!["cpu:fixture".into()],
            }
        }
    })
    .unwrap();
    assert_eq!(
        blocked,
        vec![
            (job(3), "storage_integrity_fault"),
            (job(5), "profile_not_executable"),
            (job(38), "profile_not_executable"),
        ]
    );
    assert!(
        store.dispatched_jobs().is_empty(),
        "a scan never dispatches"
    );
    *store.fail_reads_after.lock().unwrap() = Some(0);
    assert!(queued_blockers(&store, |_| Eligibility::Blocked("x")).is_err());
}
