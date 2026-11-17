//! WE-P03 retained-history accounting (2026-11-17): terminal jobs free their
//! queue slot but keep counting toward lifetime bindings and captured bytes, and
//! replay stays usable at every growth-capacity edge for submission and retry.
use super::retry_tests::{accept, authorize, canceled_source, prerequisites};
use super::*;
use crate::submission::SubmissionError;

fn submit(f: &Fixture, key: &str) -> Result<AcceptanceReceipt, SubmissionError> {
    let req = f.request(&f.capture());
    f.store.accept_execution_job(
        f.auth.clone(),
        IdempotencyKey::parse(key).unwrap(),
        req.clone(),
        f.candidate(&req),
    )
}
fn retry(
    f: &Fixture,
    auth: &AuthContext,
    key: &str,
    source: &JobId,
) -> Result<ExecutionAcceptance, SubmissionError> {
    f.store.retry_job(
        auth.clone(),
        IdempotencyKey::parse(key).unwrap(),
        source.clone(),
        prerequisites(f),
    )
}
fn captured_bytes(f: &Fixture) -> u64 {
    super::retry_tests::db(f)
        .query_row(
            "SELECT coalesce(sum(byte_length),0) FROM captured_inputs WHERE EXISTS
             (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as u64
}
fn limit_of(error: SubmissionError) -> Option<&'static str> {
    assert_eq!(error.code, ErrorCode::CapacityExceeded);
    error.limit
}

#[test]
fn a_terminal_job_frees_its_queue_slot() {
    let f = Fixture::new();
    let auth = authorize(&f);
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        queued: 1,
        ..Default::default()
    });
    let first = accept(&f, "first").job_id;
    assert_eq!(
        limit_of(submit(&f, "blocked").unwrap_err()),
        Some("queued_jobs_max")
    );
    f.store
        .cancel_execution_job(auth.clone(), first.clone())
        .unwrap();
    let second = submit(&f, "after-terminal").unwrap();
    // The slot is counted again by the new queued job, including for retry.
    assert_eq!(
        limit_of(retry(&f, &auth, "retry-blocked", &first).unwrap_err()),
        Some("queued_jobs_max")
    );
    f.store
        .cancel_execution_job(auth.clone(), second.job_id)
        .unwrap();
    retry(&f, &auth, "retry-after-terminal", &first).unwrap();
}

#[test]
fn terminal_and_retry_jobs_keep_counting_toward_lifetime_bindings() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    retry(&f, &auth, "retry", &source).unwrap();
    // One terminal submission binding plus one retry binding fill a cap of two;
    // neither terminal state nor the free queue slot releases a binding.
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        bindings: 2,
        ..Default::default()
    });
    assert_eq!(
        limit_of(submit(&f, "fresh").unwrap_err()),
        Some("submission_bindings_max")
    );
    assert_eq!(
        limit_of(retry(&f, &auth, "another-retry", &source).unwrap_err()),
        Some("submission_bindings_max")
    );
}

#[test]
fn terminal_inputs_stay_counted_once_and_a_retry_adds_no_captured_bytes() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let held = captured_bytes(&f);
    assert!(held > 0);
    // The cap equals what the terminal job still holds: a retry of it reuses
    // the same input records and adds nothing, but a new input does not fit.
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        captured_bytes: held,
        ..Default::default()
    });
    let retried = retry(&f, &auth, "retry", &source).unwrap();
    assert_eq!(captured_bytes(&f), held, "counted once per input record");
    f.store
        .cancel_execution_job(auth.clone(), retried.job_id)
        .unwrap();
    assert_eq!(captured_bytes(&f), held, "terminal state frees no bytes");
    assert_eq!(
        limit_of(submit(&f, "new-input").unwrap_err()),
        Some("captured_input_bytes_max")
    );
}

#[test]
fn inputs_referenced_by_terminal_jobs_are_never_cleanup_eligible() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let retried = retry(&f, &auth, "retry", &source).unwrap();
    f.store
        .cancel_execution_job(auth.clone(), retried.job_id)
        .unwrap();
    let referenced: String = super::retry_tests::db(&f)
        .query_row(
            "SELECT input_id FROM job_inputs WHERE job_id=?1",
            [source.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    // An unreferenced capture is the control that cleanup does run.
    let unreferenced = f.capture().input_id;
    let far_future = i64::MAX / 4;
    let claimed: Vec<_> = f
        .store
        .claim_input_cleanup_at(far_future)
        .unwrap()
        .into_iter()
        .map(|claim| claim.input_id)
        .collect();
    assert!(claimed.contains(&unreferenced), "control input is claimed");
    assert!(
        claimed.iter().all(|id| id.as_str() != referenced),
        "input of terminal jobs is never claimed"
    );
}

#[derive(Clone, Copy, Debug)]
enum Edge {
    QueueFull,
    BindingCap,
    CapturedBytes,
    FreeReserve,
}
impl Edge {
    fn limits(self) -> admission::AcceptanceLimits {
        let mut limits = admission::AcceptanceLimits::default();
        match self {
            Edge::QueueFull => limits.queued = 0,
            Edge::BindingCap => limits.bindings = 0,
            Edge::CapturedBytes => limits.captured_bytes = 0,
            Edge::FreeReserve => limits.free_reserve = u64::MAX,
        }
        limits
    }
    fn key(self) -> &'static str {
        match self {
            Edge::QueueFull => "queued_jobs_max",
            Edge::BindingCap => "submission_bindings_max",
            Edge::CapturedBytes => "captured_input_bytes_max",
            Edge::FreeReserve => "storage_free_reserve_bytes",
        }
    }
}

#[test]
fn submission_and_retry_replay_at_every_growth_capacity_edge() {
    for edge in [
        Edge::QueueFull,
        Edge::BindingCap,
        Edge::CapturedBytes,
        Edge::FreeReserve,
    ] {
        let f = Fixture::new();
        let auth = authorize(&f);
        let source = canceled_source(&f, &auth, "source");
        let retried = retry(&f, &auth, "retry", &source).unwrap();
        let other = canceled_source(&f, &auth, "other");
        let req = f.request(&f.capture());
        let key = IdempotencyKey::parse("submitted").unwrap();
        let submitted = f
            .store
            .accept_execution_job(f.auth.clone(), key.clone(), req.clone(), f.candidate(&req))
            .unwrap();
        f.store.set_test_job_limits(edge.limits());
        // Fresh work of both kinds is refused at this edge with its own key...
        assert_eq!(
            limit_of(submit(&f, "fresh").unwrap_err()),
            Some(edge.key()),
            "{edge:?} submission"
        );
        assert_eq!(
            limit_of(retry(&f, &auth, "fresh-retry", &other).unwrap_err()),
            Some(edge.key()),
            "{edge:?} retry"
        );
        // ...while replay of both still returns the original receipts.
        let replay = f
            .store
            .accept_execution_job(f.auth.clone(), key, req.clone(), f.candidate(&req))
            .unwrap();
        assert!(replay.replayed, "{edge:?} submission replay");
        assert_eq!(replay.job_id, submitted.job_id);
        let replay = retry(&f, &auth, "retry", &source).unwrap();
        assert!(replay.replayed, "{edge:?} retry replay");
        assert_eq!(replay.job_id, retried.job_id);
    }
}
