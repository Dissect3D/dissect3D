//! WE-P04 Store finalization and observation writers (2026-11-18). Dispatch
//! stays inactive; confirmed evidence comes only from the test constructor.
use super::cleanup::{AttemptRef, CleanupEvidence, CleanupOutcome, CleanupReport};
use super::execution_page_tests::reopen;
use super::finalize::{AttemptFinalization, AttemptObservation, FinalizationPath};
use super::retry_tests::{accept, authorize, db, dispatch};
use super::*;
use crate::execution::progress::{AttemptPhase, KnownProgress, ObservationUpdate};
use crate::execution::types::{AttemptCleanup, AttemptEnd, StopIntent};

/// (state, phase, outcome, job cleanup, reason, attempt cleanup, revision)
type Facts = (
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    String,
    i64,
);
fn facts(f: &Fixture, job: &JobId) -> Facts {
    db(f)
        .query_row(
            "SELECT e.state,e.phase,e.outcome_code,e.cleanup_status,e.cleanup_reason,
                    a.cleanup_status,e.snapshot_revision
             FROM job_execution e JOIN job_attempts a USING(job_id) WHERE e.job_id=?1",
            [job.as_str()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .unwrap()
}
fn held(f: &Fixture, attempt: &AttemptRef) -> i64 {
    db(f)
        .query_row(
            "SELECT count(*) FROM resource_reservations WHERE attempt_id=?1 AND released=0",
            [attempt.attempt_id.as_str()],
            |r| r.get(0),
        )
        .unwrap()
}
fn event_count(f: &Fixture, job: &JobId) -> i64 {
    db(f)
        .query_row(
            "SELECT count(*) FROM job_events WHERE job_id=?1",
            [job.as_str()],
            |r| r.get(0),
        )
        .unwrap()
}
fn finalization(
    attempt: &AttemptRef,
    end: AttemptEnd,
    cleanup: AttemptCleanup,
) -> AttemptFinalization {
    AttemptFinalization {
        attempt: attempt.clone(),
        end,
        cleanup,
    }
}
fn confirmed() -> AttemptCleanup {
    AttemptCleanup::Confirmed(CleanupEvidence::for_test())
}
fn running(f: &Fixture, key: &str) -> (JobId, AttemptRef) {
    let job = accept(f, key).job_id;
    let attempt = AttemptRef::from(&dispatch(f, &job));
    (job, attempt)
}

#[test]
fn each_typed_end_finalizes_running_work_with_its_safe_outcome_and_releases_on_confirmation() {
    let f = Fixture::new();
    for (i, (end, state, code)) in [
        (
            AttemptEnd::DeadlineExceeded,
            "failed",
            "execution_deadline_exceeded",
        ),
        (AttemptEnd::ProtocolError, "failed", "worker_protocol_error"),
        (AttemptEnd::LaunchFailed, "failed", "worker_launch_failed"),
        (AttemptEnd::WorkerFailed, "failed", "worker_failed"),
        (
            AttemptEnd::CleanupUnconfirmed,
            "failed",
            "cleanup_unconfirmed",
        ),
        (
            AttemptEnd::Stopped(StopIntent::EngineShutdown),
            "interrupted",
            "engine_shutdown",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (job, attempt) = running(&f, &format!("end-{i}"));
        let before = event_count(&f, &job);
        let receipt = f
            .store
            .finalize_attempt(finalization(&attempt, end, confirmed()))
            .unwrap();
        assert_eq!(receipt.path, FinalizationPath::Finalized);
        assert_eq!(
            (receipt.receipt.snapshot_revision, receipt.receipt.changed),
            (3, true)
        );
        assert_eq!(
            facts(&f, &job),
            (
                state.into(),
                state.into(),
                Some(code.into()),
                "confirmed".into(),
                None,
                "confirmed".into(),
                3
            ),
            "{end:?}"
        );
        // One revision, one event, reservations released, live timing gone.
        assert_eq!(event_count(&f, &job), before + 1);
        assert_eq!(held(&f, &attempt), 0);
        assert!(matches!(
            f.store.attempt_timing(attempt.attempt_id.clone()),
            Err(CoreError::NotFound)
        ));
        // The public read agrees.
        let snapshot = f
            .store
            .execution_job_snapshot(f.auth.clone(), job.clone())
            .unwrap();
        assert_eq!(snapshot.summary.outcome.unwrap().code, code);
    }
}

#[test]
fn cleanup_fault_keeps_holds_until_the_cleanup_writer_confirms_and_repeats_are_idempotent() {
    let f = Fixture::new();
    let (job, attempt) = running(&f, "fault");
    f.store
        .finalize_attempt(finalization(
            &attempt,
            AttemptEnd::WorkerFailed,
            AttemptCleanup::Fault("cleanup_deadline"),
        ))
        .unwrap();
    let after = facts(&f, &job);
    assert_eq!(
        (after.0.as_str(), after.3.as_str(), after.4.as_deref()),
        ("failed", "fault", Some("cleanup_deadline"))
    );
    assert_eq!(held(&f, &attempt), 1);
    // The live record stays until cleanup is reconciled.
    assert!(f.store.attempt_timing(attempt.attempt_id.clone()).is_ok());
    // An identical repeat writes nothing; another outcome conflicts.
    let repeat = f
        .store
        .finalize_attempt(finalization(
            &attempt,
            AttemptEnd::WorkerFailed,
            AttemptCleanup::Fault("cleanup_deadline"),
        ))
        .unwrap();
    assert!(!repeat.receipt.changed);
    assert!(matches!(
        f.store.finalize_attempt(finalization(
            &attempt,
            AttemptEnd::DeadlineExceeded,
            confirmed()
        )),
        Err(CoreError::Conflict)
    ));
    assert_eq!(facts(&f, &job), after);
    // Later established termination: the outcome stays failed.
    f.store
        .record_attempt_cleanup(CleanupReport {
            attempt: attempt.clone(),
            outcome: CleanupOutcome::Confirmed(CleanupEvidence::for_test()),
        })
        .unwrap();
    let last = facts(&f, &job);
    assert_eq!(
        (last.0.as_str(), last.2.as_deref(), last.3.as_str()),
        ("failed", Some("worker_failed"), "confirmed")
    );
    assert_eq!(held(&f, &attempt), 0);
}

#[test]
fn committed_user_cancellation_wins_over_a_later_failure_finalization() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let (job, attempt) = running(&f, "canceled");
    f.store.cancel_execution_job(auth, job.clone()).unwrap();
    let receipt = f
        .store
        .finalize_attempt(finalization(
            &attempt,
            AttemptEnd::DeadlineExceeded,
            confirmed(),
        ))
        .unwrap();
    assert_eq!(receipt.path, FinalizationPath::Cancellation);
    let after = facts(&f, &job);
    assert_eq!(
        (after.0.as_str(), after.2.as_deref(), after.3.as_str()),
        ("canceled", None, "confirmed")
    );
    // A repeat on the canceled job is an idempotent cancellation-path repeat.
    let repeat = f
        .store
        .finalize_attempt(finalization(
            &attempt,
            AttemptEnd::Stopped(StopIntent::UserCancel),
            confirmed(),
        ))
        .unwrap();
    assert_eq!(
        (repeat.path, repeat.receipt.changed),
        (FinalizationPath::Cancellation, false)
    );
}

#[test]
fn stale_identity_user_stop_on_running_work_and_unsafe_codes_reject_without_writing() {
    let f = Fixture::new();
    let (job, attempt) = running(&f, "source");
    let before = (facts(&f, &job), event_count(&f, &job));
    let mut wrong = attempt.clone();
    wrong.session_id = "ses_0123456789abcdef0123456789abcdef".into();
    let rejected = [
        finalization(&wrong, AttemptEnd::WorkerFailed, confirmed()),
        finalization(
            &attempt,
            AttemptEnd::Stopped(StopIntent::UserCancel),
            confirmed(),
        ),
        finalization(
            &attempt,
            AttemptEnd::WorkerFailed,
            AttemptCleanup::Fault("C:\\Users\\path"),
        ),
    ];
    for f_ in rejected {
        assert!(matches!(
            f.store.finalize_attempt(f_),
            Err(CoreError::Conflict)
        ));
    }
    assert_eq!((facts(&f, &job), event_count(&f, &job)), before);
    assert_eq!(held(&f, &attempt), 1);
}

#[test]
fn coalesced_observations_persist_phase_and_known_progress_for_running_work_only() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let (job, attempt) = running(&f, "observed");
    let observe = |phase, progress: Option<(&'static str, f64)>| {
        f.store.record_attempt_observation(AttemptObservation {
            attempt: attempt.clone(),
            update: ObservationUpdate {
                phase,
                progress: progress.map(|(stage, fraction)| KnownProgress { stage, fraction }),
            },
        })
    };
    let r = observe(AttemptPhase::Executing, Some(("copy", 0.25))).unwrap();
    assert_eq!((r.snapshot_revision, r.changed), (3, true));
    let snapshot = f
        .store
        .execution_job_snapshot(f.auth.clone(), job.clone())
        .unwrap();
    assert_eq!(snapshot.summary.phase, "executing");
    let progress = snapshot.summary.progress.unwrap();
    assert_eq!((progress.stage.as_str(), progress.fraction), ("copy", 0.25));
    // The same snapshot again writes nothing.
    assert!(
        !observe(AttemptPhase::Executing, Some(("copy", 0.25)))
            .unwrap()
            .changed
    );
    // Unknown progress persists as null, never a guess.
    observe(AttemptPhase::Executing, None).unwrap();
    let snapshot = f
        .store
        .execution_job_snapshot(f.auth.clone(), job.clone())
        .unwrap();
    assert_eq!(snapshot.summary.progress, None);
    // Invalid values reject before the actor.
    for bad in [("copy", 1.5), ("copy", f64::NAN), ("Bad Stage", 0.5)] {
        assert!(matches!(
            observe(AttemptPhase::Executing, Some(bad)),
            Err(CoreError::Conflict)
        ));
    }
    // Once cancellation is committed, progress cannot overwrite it.
    f.store.cancel_execution_job(auth, job.clone()).unwrap();
    let canceled = facts(&f, &job);
    assert!(matches!(
        observe(AttemptPhase::Executing, Some(("copy", 0.9))),
        Err(CoreError::Conflict)
    ));
    assert_eq!(facts(&f, &job), canceled);
}

#[test]
fn ad04_wall_time_edits_cannot_move_the_store_owned_deadline() {
    let f = Fixture::new();
    let mut req = f.request(&f.capture());
    req.execution.timeout_ms = Some(60_000);
    let accepted = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse("wall-clock").unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap();
    let record = dispatch(&f, &accepted.job_id);
    let original = record.timing.deadline().unwrap();
    // Diagnostic wall readings jump backward and forward.
    for wall in [0_i64, 4_102_444_800_000, 1] {
        db(&f)
            .execute(
                "UPDATE job_attempts SET dispatched_at_ms=?2 WHERE attempt_id=?1",
                rusqlite::params![record.attempt_id, wall],
            )
            .unwrap();
        let timing = f.store.attempt_timing(record.attempt_id.clone()).unwrap();
        assert!(Arc::ptr_eq(&timing, &record.timing));
        assert_eq!(timing.deadline(), Some(original));
        assert!(!timing.expired());
    }
}

#[test]
fn ad05_restart_never_recreates_a_live_timer_or_accepts_a_late_outcome() {
    let f = Fixture::new();
    let (job, attempt) = running(&f, "restart");
    let f = reopen(f);
    // No live record exists, so no supervisor can be given one.
    assert!(matches!(
        f.store.attempt_timing(attempt.attempt_id.clone()),
        Err(CoreError::NotFound)
    ));
    let interrupted = facts(&f, &job);
    assert_eq!(interrupted.2.as_deref(), Some("engine_restarted"));
    // A late outcome from the previous run cannot replace the interruption.
    assert!(matches!(
        f.store.finalize_attempt(finalization(
            &attempt,
            AttemptEnd::WorkerFailed,
            confirmed()
        )),
        Err(CoreError::Conflict)
    ));
    assert_eq!(facts(&f, &job), interrupted);
    assert_eq!(held(&f, &attempt), 1);
}
