//! WE-P03 cleanup-witness transitions at the Store seam (2026-11-18). Dispatch
//! stays inactive; confirmed evidence comes only from the test-only constructor.
use super::cleanup::{AttemptRef, CleanupEvidence, CleanupOutcome, CleanupReceipt, CleanupReport};
use super::execution_page_tests::reopen;
use super::retry_tests::{accept, authorize, db, dispatch, retry};
use super::*;

fn confirmed(attempt: &AttemptRef) -> CleanupReport {
    CleanupReport {
        attempt: attempt.clone(),
        outcome: CleanupOutcome::Confirmed(CleanupEvidence::for_test()),
    }
}
fn fault(attempt: &AttemptRef, reason: &str) -> CleanupReport {
    CleanupReport {
        attempt: attempt.clone(),
        outcome: CleanupOutcome::Fault {
            reason: reason.into(),
        },
    }
}
/// (state, phase, job cleanup, reason, attempt cleanup, revision)
type Facts = (String, String, String, Option<String>, String, i64);
fn facts(f: &Fixture, job: &JobId) -> Facts {
    db(f)
        .query_row(
            "SELECT e.state,e.phase,e.cleanup_status,e.cleanup_reason,a.cleanup_status,
                    e.snapshot_revision
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
fn events(f: &Fixture, job: &JobId) -> Vec<(i64, serde_json::Value)> {
    let db = db(f);
    let mut statement = db
        .prepare(
            "SELECT snapshot_revision,snapshot_json FROM job_events
             WHERE job_id=?1 ORDER BY snapshot_revision",
        )
        .unwrap();
    statement
        .query_map([job.as_str()], |r| {
            Ok((
                r.get(0)?,
                serde_json::from_str(&r.get::<_, String>(1)?).unwrap(),
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn cancel(f: &Fixture, auth: &AuthContext, job: &JobId) {
    assert_eq!(
        f.store
            .cancel_execution_job(auth.clone(), job.clone())
            .unwrap(),
        "requested"
    );
}
fn second_dispatch(f: &Fixture, key: &str) -> Result<execution::DispatchRecord, CoreError> {
    let job = accept(f, key).job_id;
    let resolved: String = db(f)
        .query_row(
            "SELECT resolved_json FROM jobs WHERE job_id=?1",
            [job.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    f.store.dispatch_attempt(execution::DispatchRequest {
        job_id: job,
        expected_revision: 1,
        resolved_json: resolved,
        resources: vec!["cpu:fixture".into()],
    })
}

#[test]
fn fault_keeps_holds_then_confirmed_releases_them_and_completes_cancellation() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let job = accept(&f, "source").job_id;
    let record = dispatch(&f, &job);
    let attempt = AttemptRef::from(&record);
    cancel(&f, &auth, &job);
    // Uncertain termination: cancellation stays requested and holds stay.
    let receipt = f
        .store
        .record_attempt_cleanup(fault(&attempt, "cleanup_deadline"))
        .unwrap();
    assert_eq!(
        receipt,
        CleanupReceipt {
            snapshot_revision: 4,
            changed: true
        }
    );
    assert_eq!(
        facts(&f, &job),
        (
            "cancel_requested".into(),
            "cancel_requested".into(),
            "fault".into(),
            Some("cleanup_deadline".into()),
            "fault".into(),
            4
        )
    );
    assert_eq!(held(&f, &attempt), 1);
    // The held resource blocks conflicting reuse.
    assert!(matches!(
        second_dispatch(&f, "blocked"),
        Err(CoreError::Busy)
    ));
    assert!(f.store.attempt_timing(attempt.attempt_id.clone()).is_ok());
    // Established termination: canceled, released and the reason cleared.
    let receipt = f.store.record_attempt_cleanup(confirmed(&attempt)).unwrap();
    assert_eq!(
        receipt,
        CleanupReceipt {
            snapshot_revision: 5,
            changed: true
        }
    );
    assert_eq!(
        facts(&f, &job),
        (
            "canceled".into(),
            "canceled".into(),
            "confirmed".into(),
            None,
            "confirmed".into(),
            5
        )
    );
    assert_eq!(held(&f, &attempt), 0);
    // The attempt is over; its live timing record is dropped.
    assert!(matches!(
        f.store.attempt_timing(attempt.attempt_id.clone()),
        Err(CoreError::NotFound)
    ));
    // The exclusive-reservation index now admits the released resource.
    second_dispatch(&f, "admitted").unwrap();
}

#[test]
fn confirmed_is_final_and_repeats_change_nothing() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let job = accept(&f, "source").job_id;
    let attempt = AttemptRef::from(&dispatch(&f, &job));
    cancel(&f, &auth, &job);
    f.store
        .record_attempt_cleanup(fault(&attempt, "cleanup_ownership_lost"))
        .unwrap();
    let before = (facts(&f, &job), events(&f, &job));
    // The same fault again: no revision, no event.
    assert_eq!(
        f.store
            .record_attempt_cleanup(fault(&attempt, "cleanup_ownership_lost"))
            .unwrap(),
        CleanupReceipt {
            snapshot_revision: 4,
            changed: false
        }
    );
    assert_eq!((facts(&f, &job), events(&f, &job)), before);
    f.store.record_attempt_cleanup(confirmed(&attempt)).unwrap();
    let after = (facts(&f, &job), events(&f, &job));
    assert_eq!(
        f.store.record_attempt_cleanup(confirmed(&attempt)).unwrap(),
        CleanupReceipt {
            snapshot_revision: 5,
            changed: false
        }
    );
    // Confirmed never returns to fault.
    assert!(matches!(
        f.store
            .record_attempt_cleanup(fault(&attempt, "cleanup_deadline")),
        Err(CoreError::Conflict)
    ));
    assert_eq!((facts(&f, &job), events(&f, &job)), after);
}

#[test]
fn stale_or_mismatched_identity_and_running_work_are_rejected_without_writing() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let job = accept(&f, "source").job_id;
    let attempt = AttemptRef::from(&dispatch(&f, &job));
    // Running work is finalized with its outcome, not by a cleanup report.
    let running = facts(&f, &job);
    for report in [confirmed(&attempt), fault(&attempt, "cleanup_deadline")] {
        assert!(matches!(
            f.store.record_attempt_cleanup(report),
            Err(CoreError::Conflict)
        ));
    }
    assert_eq!(facts(&f, &job), running);
    cancel(&f, &auth, &job);
    let other = accept(&f, "other").job_id;
    let before = (facts(&f, &job), events(&f, &job));
    let unknown = "0123456789abcdef0123456789abcdef";
    let mut stale = Vec::new();
    for edit in 0..4 {
        let mut wrong = attempt.clone();
        match edit {
            0 => wrong.session_id = format!("ses_{unknown}"),
            1 => wrong.grant_id = format!("grt_{unknown}"),
            2 => wrong.attempt_id = format!("att_{unknown}"),
            _ => wrong.job_id = other.clone(),
        }
        stale.push(wrong);
    }
    for wrong in &stale {
        assert!(
            matches!(
                f.store.record_attempt_cleanup(confirmed(wrong)),
                Err(CoreError::Conflict)
            ),
            "{wrong:?}"
        );
    }
    // Malformed identities and unsafe or oversized reasons reject before the actor.
    let mut malformed = attempt.clone();
    malformed.grant_id = "grt_not-hex".into();
    for report in [
        confirmed(&malformed),
        fault(&attempt, &"r".repeat(129)),
        fault(&attempt, ""),
        fault(&attempt, "Path C:\\Users"),
    ] {
        assert!(matches!(
            f.store.record_attempt_cleanup(report),
            Err(CoreError::Conflict)
        ));
    }
    assert_eq!((facts(&f, &job), events(&f, &job)), before);
    assert_eq!(held(&f, &attempt), 1);
    // A 128-byte safe reason is accepted.
    f.store
        .record_attempt_cleanup(fault(&attempt, &"r".repeat(128)))
        .unwrap();
}

#[test]
fn restart_interrupted_attempt_stays_held_until_cleanup_then_retry_is_accepted() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let job = accept(&f, "source").job_id;
    let attempt = AttemptRef::from(&dispatch(&f, &job));
    let f = reopen(f);
    assert_eq!(
        facts(&f, &job),
        (
            "interrupted".into(),
            "interrupted".into(),
            "pending".into(),
            None,
            "pending".into(),
            3
        )
    );
    assert_eq!(held(&f, &attempt), 1);
    let refused = |key: &str| retry(&f, &auth, key, &job).unwrap_err().code;
    assert_eq!(refused("pending"), ErrorCode::CleanupUnconfirmed);
    // Recovery cannot establish termination: fault keeps the hold and retry refused.
    f.store
        .record_attempt_cleanup(fault(&attempt, "cleanup_native_failure"))
        .unwrap();
    assert_eq!(held(&f, &attempt), 1);
    assert_eq!(refused("fault"), ErrorCode::CleanupUnconfirmed);
    // Later established termination: the outcome stays interrupted.
    f.store.record_attempt_cleanup(confirmed(&attempt)).unwrap();
    let (state, _, cleanup, reason, attempt_cleanup, revision) = facts(&f, &job);
    assert_eq!(
        (
            state.as_str(),
            cleanup.as_str(),
            reason,
            attempt_cleanup.as_str()
        ),
        ("interrupted", "confirmed", None, "confirmed")
    );
    assert_eq!(revision, 5);
    assert_eq!(held(&f, &attempt), 0);
    let accepted = retry(&f, &auth, "resolved", &job).unwrap();
    assert_eq!(accepted.retry_of, Some(job));
}

#[test]
fn restart_keeps_pending_cancellation_held_until_confirmed_cleanup_cancels_it() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let canceling = accept(&f, "canceling").job_id;
    let canceled_attempt = AttemptRef::from(&dispatch(&f, &canceling));
    cancel(&f, &auth, &canceling);
    // A second, still running job on another resource.
    let running = accept(&f, "running").job_id;
    let resolved: String = db(&f)
        .query_row(
            "SELECT resolved_json FROM jobs WHERE job_id=?1",
            [running.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    let running_attempt = AttemptRef::from(
        &f.store
            .dispatch_attempt(execution::DispatchRequest {
                job_id: running.clone(),
                expected_revision: 1,
                resolved_json: resolved,
                resources: vec!["cpu:other".into()],
            })
            .unwrap(),
    );
    let f = reopen(f);
    // Durable cancellation intent is authoritative across restart (WE-005,
    // ENG-031): no restart revision, the hold stays, and it awaits evidence.
    assert_eq!(
        facts(&f, &canceling),
        (
            "cancel_requested".into(),
            "cancel_requested".into(),
            "pending".into(),
            None,
            "pending".into(),
            3
        )
    );
    assert_eq!(held(&f, &canceled_attempt), 1);
    // Only `running` work is interrupted.
    assert_eq!(facts(&f, &running).0, "interrupted");
    assert_eq!(held(&f, &running_attempt), 1);
    // A second restart changes nothing either.
    let f = reopen(f);
    assert_eq!(facts(&f, &canceling).5, 3);
    f.store
        .record_attempt_cleanup(confirmed(&canceled_attempt))
        .unwrap();
    let (state, phase, cleanup, _, _, revision) = facts(&f, &canceling);
    assert_eq!(
        (state.as_str(), phase.as_str(), cleanup.as_str(), revision),
        ("canceled", "canceled", "confirmed", 4)
    );
    assert_eq!(held(&f, &canceled_attempt), 0);
    let states: Vec<String> = events(&f, &canceling)
        .iter()
        .map(|(_, e)| e["state"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(states, ["running", "cancel_requested", "canceled"]);
    assert!(
        events(&f, &canceling)
            .iter()
            .all(|(_, e)| e["outcome_code"].is_null())
    );
}

#[test]
fn each_cleanup_change_commits_one_revision_with_its_ordered_event() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let job = accept(&f, "source").job_id;
    let attempt = AttemptRef::from(&dispatch(&f, &job));
    cancel(&f, &auth, &job);
    f.store
        .record_attempt_cleanup(fault(&attempt, "cleanup_deadline"))
        .unwrap();
    f.store.record_attempt_cleanup(confirmed(&attempt)).unwrap();
    let events = events(&f, &job);
    let revisions: Vec<i64> = events.iter().map(|(r, _)| *r).collect();
    assert_eq!(revisions, vec![2, 3, 4, 5]);
    let summary: Vec<_> = events
        .iter()
        .map(|(r, e)| {
            assert_eq!(e["snapshot_revision"], *r);
            (
                e["state"].as_str().unwrap().to_owned(),
                e["cleanup_status"].as_str().unwrap().to_owned(),
                e["cleanup_reason"].as_str().map(str::to_owned),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("running".into(), "pending".into(), None),
            ("cancel_requested".into(), "pending".into(), None),
            (
                "cancel_requested".into(),
                "fault".into(),
                Some("cleanup_deadline".into())
            ),
            ("canceled".into(), "confirmed".into(), None),
        ]
    );
    // The public snapshot agrees with the newest event.
    assert_eq!(facts(&f, &job).5, 5);
}

#[test]
fn platform_faults_map_to_safe_reason_codes() {
    use dissect3d_platform::CleanupFault;
    for (fault, code) in [
        (CleanupFault::Deadline, "cleanup_deadline"),
        (CleanupFault::OwnershipLost, "cleanup_ownership_lost"),
        (CleanupFault::NativeFailure, "cleanup_native_failure"),
    ] {
        match CleanupOutcome::from(fault) {
            CleanupOutcome::Fault { reason } => assert_eq!(reason, code),
            CleanupOutcome::Confirmed(_) => panic!("a fault never confirms"),
        }
    }
}
