//! WE-P04 launch-identity record and release-time identity check
//! (2026-11-19). Dispatch stays inactive; identities and evidence come from
//! the test constructors, as a launch and its native witness would report them.
use super::cleanup::{AttemptRef, CleanupEvidence, CleanupOutcome, CleanupReport, test_identity};
use super::execution_page_tests::reopen;
use super::finalize::AttemptFinalization;
use super::launch_identity::LaunchRecord;
use super::retry_tests::{accept, authorize, db, dispatch};
use super::*;
use crate::execution::types::{AttemptCleanup, AttemptEnd, NeverLaunched};
use dissect3d_platform::{ProcessIdentity, WorkerIdentity};

/// The identity a test launch reports for `attempt`.
pub(super) fn launch_identity(attempt: &AttemptRef) -> WorkerIdentity {
    test_identity(&attempt.session_id, "launch")
}
/// Native evidence for the identity `launched` recorded.
pub(super) fn evidence(attempt: &AttemptRef) -> CleanupEvidence {
    CleanupEvidence::for_test(launch_identity(attempt))
}
fn record(attempt: &AttemptRef, identity: WorkerIdentity) -> LaunchRecord {
    LaunchRecord {
        attempt: attempt.clone(),
        identity,
    }
}
/// Dispatch, then record the launch identity as the supervisor does right
/// after a confirmed spawn.
pub(super) fn launched(f: &Fixture, job: &JobId) -> execution::DispatchRecord {
    let dispatched = dispatch(f, job);
    record_launch(f, &dispatched);
    dispatched
}
/// Record the launch identity of an attempt dispatched elsewhere.
pub(super) fn record_launch(f: &Fixture, dispatched: &execution::DispatchRecord) {
    let attempt = AttemptRef::from(dispatched);
    f.store
        .record_launch_identity(record(&attempt, launch_identity(&attempt)))
        .unwrap();
}

fn stored(f: &Fixture, attempt: &AttemptRef) -> Option<String> {
    db(f)
        .query_row(
            "SELECT native_identity_json FROM job_attempts WHERE attempt_id=?1",
            [attempt.attempt_id.as_str()],
            |r| r.get(0),
        )
        .unwrap()
}
/// Everything a rejected command must leave untouched: job and attempt
/// facts, events, held reservations and the recorded identity.
type Snapshot = (
    (
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
        i64,
    ),
    i64,
    i64,
    Option<String>,
);
fn snapshot(f: &Fixture, attempt: &AttemptRef) -> Snapshot {
    let db = db(f);
    let facts = db
        .query_row(
            "SELECT e.state,e.phase,e.outcome_code,e.cleanup_status,e.cleanup_reason,
                    a.cleanup_status,e.snapshot_revision
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
                ))
            },
        )
        .unwrap();
    let events = db
        .query_row(
            "SELECT count(*) FROM job_events WHERE job_id=?1",
            [attempt.job_id.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    let held = db
        .query_row(
            "SELECT count(*) FROM resource_reservations WHERE attempt_id=?1 AND released=0",
            [attempt.attempt_id.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    (facts, events, held, stored(f, attempt))
}
fn confirmed_report(attempt: &AttemptRef, identity: WorkerIdentity) -> CleanupReport {
    CleanupReport {
        attempt: attempt.clone(),
        outcome: CleanupOutcome::Confirmed(CleanupEvidence::for_test(identity)),
    }
}
fn fault_report(attempt: &AttemptRef) -> CleanupReport {
    CleanupReport {
        attempt: attempt.clone(),
        outcome: CleanupOutcome::Fault {
            reason: "cleanup_native_failure".into(),
        },
    }
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
fn running(f: &Fixture, key: &str) -> AttemptRef {
    let job = accept(f, key).job_id;
    AttemptRef::from(&dispatch(f, &job))
}
/// A second concurrently running attempt, on its own exclusive resource.
pub(super) fn running_on(f: &Fixture, key: &str, resource: &str) -> AttemptRef {
    let job = accept(f, key).job_id;
    let resolved: String = db(f)
        .query_row(
            "SELECT resolved_json FROM jobs WHERE job_id=?1",
            [job.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    let dispatched = f
        .store
        .dispatch_attempt(execution::DispatchRequest {
            job_id: job,
            expected_revision: 1,
            resolved_json: resolved,
            resources: vec![resource.into()],
        })
        .unwrap();
    AttemptRef::from(&dispatched)
}
/// Same session nonce, different creation evidence (a reused PID or another process).
fn other_identities(attempt: &AttemptRef) -> Vec<WorkerIdentity> {
    let base = launch_identity(attempt);
    let mut pid = base.clone();
    pid.process.pid += 1;
    let mut marker = base.clone();
    marker.process.start_marker.push('9');
    let mut guardian = base.clone();
    guardian.guardian = Some(ProcessIdentity {
        pid: 77,
        start_marker: "test-start-guardian".into(),
    });
    let mut session = base;
    session.session_nonce[0] ^= 1;
    vec![pid, marker, guardian, session]
}

#[test]
fn identity_is_recorded_once_privately_and_a_repeat_is_idempotent() {
    let f = Fixture::new();
    let attempt = running(&f, "source");
    assert_eq!(stored(&f, &attempt), None);
    let before = snapshot(&f, &attempt);
    f.store
        .record_launch_identity(record(&attempt, launch_identity(&attempt)))
        .unwrap();
    let recorded = stored(&f, &attempt).expect("identity recorded");
    let value: serde_json::Value = serde_json::from_str(&recorded).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["process"]["pid"], 4242);
    assert_eq!(value["process"]["start_marker"], "test-start-launch");
    assert_eq!(value["guardian"], serde_json::Value::Null);
    assert_eq!(value["session_nonce"], attempt.session_id["ses_".len()..]);
    // Private ownership metadata: no revision, event or public fact changes.
    let after = snapshot(&f, &attempt);
    assert_eq!(
        (&after.0, after.1, after.2),
        (&before.0, before.1, before.2)
    );
    // The same identity again is accepted without change.
    f.store
        .record_launch_identity(record(&attempt, launch_identity(&attempt)))
        .unwrap();
    assert_eq!(snapshot(&f, &attempt), after);
    // A different identity never replaces the record.
    for other in other_identities(&attempt) {
        assert!(
            matches!(
                f.store
                    .record_launch_identity(record(&attempt, other.clone())),
                Err(CoreError::Conflict)
            ),
            "{other:?}"
        );
    }
    assert_eq!(snapshot(&f, &attempt), after);
}

#[test]
fn malformed_unbound_stale_or_unowned_records_reject_without_writing() {
    let f = Fixture::new();
    let attempt = running(&f, "source");
    let before = snapshot(&f, &attempt);
    let base = launch_identity(&attempt);
    let mut bad = Vec::new();
    // Not bound to this attempt's session nonce.
    let mut nonce = base.clone();
    nonce.session_nonce = [0; 16];
    bad.push(record(&attempt, nonce));
    // Not real creation evidence.
    for marker in [
        String::new(),
        "m".repeat(129),
        "has space".into(),
        "é".into(),
    ] {
        let mut identity = base.clone();
        identity.process.start_marker = marker;
        bad.push(record(&attempt, identity));
    }
    let mut zero = base.clone();
    zero.process.pid = 0;
    bad.push(record(&attempt, zero));
    let mut guardian = base.clone();
    guardian.guardian = Some(ProcessIdentity {
        pid: 9,
        start_marker: String::new(),
    });
    bad.push(record(&attempt, guardian));
    // Stale or foreign attempt identities (nonce follows the wrong session).
    let unknown = "0123456789abcdef0123456789abcdef";
    for field in 0..3 {
        let mut wrong = attempt.clone();
        match field {
            0 => wrong.session_id = format!("ses_{unknown}"),
            1 => wrong.grant_id = format!("grt_{unknown}"),
            _ => wrong.attempt_id = format!("att_{unknown}"),
        }
        let identity = launch_identity(&wrong);
        bad.push(record(&wrong, identity));
    }
    let mut malformed = attempt.clone();
    malformed.grant_id = "grt_not-hex".into();
    bad.push(record(&malformed, base));
    for item in bad {
        assert!(
            matches!(
                f.store.record_launch_identity(item.clone()),
                Err(CoreError::Conflict)
            ),
            "{item:?}"
        );
    }
    assert_eq!(snapshot(&f, &attempt), before);
}

#[test]
fn identity_may_be_recorded_under_pending_cancellation_but_not_after_an_outcome() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let canceling = running(&f, "canceling");
    f.store
        .cancel_execution_job(auth.clone(), canceling.job_id.clone())
        .unwrap();
    // A cancellation committed while the worker was launching.
    f.store
        .record_launch_identity(record(&canceling, launch_identity(&canceling)))
        .unwrap();
    assert!(stored(&f, &canceling).is_some());

    let failed = running_on(&f, "failed", "cpu:second");
    f.store
        .finalize_attempt(finalization(
            &failed,
            AttemptEnd::WorkerFailed,
            AttemptCleanup::Fault("cleanup_deadline"),
        ))
        .unwrap();
    let before = snapshot(&f, &failed);
    assert!(matches!(
        f.store
            .record_launch_identity(record(&failed, launch_identity(&failed))),
        Err(CoreError::Conflict)
    ));
    assert_eq!(snapshot(&f, &failed), before);
}

#[test]
fn release_without_a_recorded_identity_is_rejected_without_writing() {
    let f = Fixture::new();
    let auth = authorize(&f);
    // Running work: finalization with native evidence but no launch record.
    let unrecorded = running(&f, "unrecorded");
    let before = snapshot(&f, &unrecorded);
    for end in [AttemptEnd::WorkerFailed, AttemptEnd::DeadlineExceeded] {
        assert!(matches!(
            f.store.finalize_attempt(finalization(
                &unrecorded,
                end,
                AttemptCleanup::Confirmed(evidence(&unrecorded)),
            )),
            Err(CoreError::Conflict)
        ));
    }
    assert_eq!(snapshot(&f, &unrecorded), before);
    // Pending cancellation: the cleanup writer rejects as well.
    f.store
        .cancel_execution_job(auth, unrecorded.job_id.clone())
        .unwrap();
    let canceling = snapshot(&f, &unrecorded);
    assert!(matches!(
        f.store
            .record_attempt_cleanup(confirmed_report(&unrecorded, launch_identity(&unrecorded))),
        Err(CoreError::Conflict)
    ));
    assert_eq!(snapshot(&f, &unrecorded), canceling);
    // An uncertain outcome is still recorded, and it keeps every hold.
    f.store
        .record_attempt_cleanup(fault_report(&unrecorded))
        .unwrap();
    let faulted = snapshot(&f, &unrecorded);
    assert_eq!(
        (faulted.0.0.as_str(), faulted.0.3.as_str(), faulted.2),
        ("cancel_requested", "fault", 1)
    );
}

#[test]
fn release_with_a_mismatched_identity_is_rejected_and_the_matching_one_releases() {
    let f = Fixture::new();
    let job = accept(&f, "source").job_id;
    let attempt = AttemptRef::from(&launched(&f, &job));
    let before = snapshot(&f, &attempt);
    for other in other_identities(&attempt) {
        assert!(
            matches!(
                f.store.finalize_attempt(finalization(
                    &attempt,
                    AttemptEnd::WorkerFailed,
                    AttemptCleanup::Confirmed(CleanupEvidence::for_test(other.clone())),
                )),
                Err(CoreError::Conflict)
            ),
            "{other:?}"
        );
    }
    // A launched worker can never be released as never-launched.
    assert!(matches!(
        f.store.finalize_attempt(finalization(
            &attempt,
            AttemptEnd::LaunchFailed,
            AttemptCleanup::NeverLaunched(NeverLaunched::for_test()),
        )),
        Err(CoreError::Conflict)
    ));
    assert_eq!(snapshot(&f, &attempt), before);
    // The witness for the recorded identity releases the holds.
    f.store
        .finalize_attempt(finalization(
            &attempt,
            AttemptEnd::WorkerFailed,
            AttemptCleanup::Confirmed(evidence(&attempt)),
        ))
        .unwrap();
    let released = snapshot(&f, &attempt);
    assert_eq!(
        (released.0.0.as_str(), released.0.3.as_str(), released.2),
        ("failed", "confirmed", 0)
    );
    // A repeat must still agree: a mismatched witness is refused, not "unchanged".
    for other in other_identities(&attempt) {
        assert!(matches!(
            f.store
                .record_attempt_cleanup(confirmed_report(&attempt, other)),
            Err(CoreError::Conflict)
        ));
    }
    assert!(
        !f.store
            .record_attempt_cleanup(confirmed_report(&attempt, launch_identity(&attempt)))
            .unwrap()
            .changed
    );
    assert_eq!(snapshot(&f, &attempt), released);
}

#[test]
fn a_never_launched_attempt_releases_without_an_identity() {
    let f = Fixture::new();
    let attempt = running(&f, "source");
    f.store
        .finalize_attempt(finalization(
            &attempt,
            AttemptEnd::LaunchFailed,
            AttemptCleanup::NeverLaunched(NeverLaunched::for_test()),
        ))
        .unwrap();
    let after = snapshot(&f, &attempt);
    assert_eq!(
        (
            after.0.0.as_str(),
            after.0.2.as_deref(),
            after.0.3.as_str(),
            after.2,
            after.3
        ),
        ("failed", Some("worker_launch_failed"), "confirmed", 0, None)
    );
}

#[test]
fn restart_keeps_the_recorded_identity_and_the_release_check_for_interrupted_attempts() {
    let f = Fixture::new();
    let recorded_job = accept(&f, "recorded").job_id;
    let recorded = AttemptRef::from(&launched(&f, &recorded_job));
    // The engine died between the confirmed spawn and the identity write.
    let unrecorded = running_on(&f, "unrecorded", "cpu:second");
    let identity = stored(&f, &recorded).unwrap();
    let f = reopen(f);
    // The record is durable; only `running` work became interrupted.
    assert_eq!(stored(&f, &recorded).as_deref(), Some(identity.as_str()));
    for attempt in [&recorded, &unrecorded] {
        let facts = snapshot(&f, attempt);
        assert_eq!(
            (
                facts.0.0.as_str(),
                facts.0.2.as_deref(),
                facts.0.3.as_str(),
                facts.2
            ),
            ("interrupted", Some("engine_restarted"), "pending", 1)
        );
    }
    // No worker of this instance owns either attempt: no identity can be
    // recorded or replaced after restart.
    for attempt in [&recorded, &unrecorded] {
        let before = snapshot(&f, attempt);
        assert!(matches!(
            f.store
                .record_launch_identity(record(attempt, launch_identity(attempt))),
            Err(CoreError::Conflict)
        ));
        assert_eq!(snapshot(&f, attempt), before);
    }
    // Unrecorded: confirmed release is refused and holds stay; a fault is recorded.
    let before = snapshot(&f, &unrecorded);
    assert!(matches!(
        f.store
            .record_attempt_cleanup(confirmed_report(&unrecorded, launch_identity(&unrecorded))),
        Err(CoreError::Conflict)
    ));
    assert_eq!(snapshot(&f, &unrecorded), before);
    f.store
        .record_attempt_cleanup(fault_report(&unrecorded))
        .unwrap();
    assert_eq!(snapshot(&f, &unrecorded).2, 1);
    // Recorded: a mismatched identity is refused; the recorded one releases,
    // and the outcome stays interrupted.
    let before = snapshot(&f, &recorded);
    for other in other_identities(&recorded) {
        assert!(matches!(
            f.store
                .record_attempt_cleanup(confirmed_report(&recorded, other)),
            Err(CoreError::Conflict)
        ));
    }
    assert_eq!(snapshot(&f, &recorded), before);
    f.store
        .record_attempt_cleanup(confirmed_report(&recorded, launch_identity(&recorded)))
        .unwrap();
    let released = snapshot(&f, &recorded);
    assert_eq!(
        (
            released.0.0.as_str(),
            released.0.2.as_deref(),
            released.0.3.as_str(),
            released.2
        ),
        ("interrupted", Some("engine_restarted"), "confirmed", 0)
    );
}

#[test]
fn never_launched_is_refused_for_an_attempt_this_instance_does_not_own() {
    let f = Fixture::new();
    let auth = authorize(&f);
    // Engine died between dispatch and any spawn record, with cancellation pending.
    let attempt = running(&f, "source");
    f.store
        .cancel_execution_job(auth, attempt.job_id.clone())
        .unwrap();
    let f = reopen(f);
    let before = snapshot(&f, &attempt);
    assert_eq!(before.0.0, "cancel_requested");
    assert!(matches!(
        f.store.finalize_attempt(finalization(
            &attempt,
            AttemptEnd::LaunchFailed,
            AttemptCleanup::NeverLaunched(NeverLaunched::for_test()),
        )),
        Err(CoreError::Conflict)
    ));
    assert_eq!(snapshot(&f, &attempt), before);
}
