//! WE-P07/4 restart reconciliation (user decision 2026-11-24): attempts of a
//! dead engine instance, their recorded launch identities and real processes.
use super::cleanup::{AttemptRef, test_identity};
use super::execution_page_tests::reopen;
use super::launch_identity::LaunchRecord;
use super::launch_identity_tests::launched;
use super::retry_tests::{accept, authorize, db, dispatch};
use super::*;
use crate::execution::recovery::{IDENTITY_UNRECORDED, RecoveryReport, reconcile};
use dissect3d_platform::{ProcessIdentity, WorkerIdentity, process_matches};

/// (state, outcome, cleanup status, cleanup reason, held reservations)
fn facts(
    f: &Fixture,
    attempt: &AttemptRef,
) -> (String, Option<String>, String, Option<String>, i64) {
    db(f)
        .query_row(
            "SELECT e.state,e.outcome_code,e.cleanup_status,e.cleanup_reason,
                    (SELECT count(*) FROM resource_reservations r
                      WHERE r.attempt_id=?1 AND r.released=0)
             FROM job_execution e JOIN job_attempts a USING(job_id) WHERE a.attempt_id=?1",
            [attempt.attempt_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap()
}

/// The Linux start marker, in the platform's format (`linux-start-<ticks>`).
fn linux_identity(pid: u32) -> ProcessIdentity {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 1..]
        .split_whitespace()
        .collect();
    ProcessIdentity {
        pid,
        start_marker: format!("linux-start-{}", fields[19]),
    }
}

#[test]
fn a_dead_engines_worker_with_no_survivor_is_confirmed_by_owner_death_containment() {
    let f = Fixture::new();
    let job = accept(&f, "recovery-dead").job_id;
    // The test identity names no live process (pid 4242, test marker).
    let attempt = AttemptRef::from(&launched(&f, &job));
    let f = reopen(f);
    assert_eq!(facts(&f, &attempt).0, "interrupted");
    assert_eq!(facts(&f, &attempt).4, 1, "restart alone releases nothing");
    let report = reconcile(&f.store).unwrap();
    assert_eq!(
        report,
        RecoveryReport {
            confirmed: 1,
            faulted: 0
        }
    );
    assert_eq!(
        facts(&f, &attempt),
        (
            "interrupted".into(),
            Some("engine_restarted".into()),
            "confirmed".into(),
            Some("owner_death_containment".into()),
            0
        )
    );
    // A second pass finds nothing left.
    assert_eq!(reconcile(&f.store).unwrap(), RecoveryReport::default());
}

#[test]
fn an_attempt_without_a_recorded_identity_keeps_its_holds_as_a_fault() {
    let f = Fixture::new();
    let job = accept(&f, "recovery-unrecorded").job_id;
    let attempt = AttemptRef::from(&dispatch(&f, &job));
    let f = reopen(f);
    let report = reconcile(&f.store).unwrap();
    assert_eq!(
        report,
        RecoveryReport {
            confirmed: 0,
            faulted: 1
        }
    );
    let (state, _, cleanup, reason, held) = facts(&f, &attempt);
    assert_eq!(state, "interrupted");
    assert_eq!(
        (cleanup.as_str(), reason.as_deref(), held),
        ("fault", Some(IDENTITY_UNRECORDED), 1)
    );
    // Repeating it changes nothing.
    assert_eq!(reconcile(&f.store).unwrap(), report);
    assert_eq!(facts(&f, &attempt).4, 1);
}

#[test]
fn durable_cancellation_completes_as_canceled_once_cleanup_is_established() {
    let f = Fixture::new();
    let job = accept(&f, "recovery-cancel").job_id;
    let attempt = AttemptRef::from(&launched(&f, &job));
    let auth = authorize(&f);
    assert_eq!(
        f.store.cancel_execution_job(auth, job.clone()).unwrap(),
        "requested"
    );
    let f = reopen(f);
    assert_eq!(facts(&f, &attempt).0, "cancel_requested", "intent survives");
    reconcile(&f.store).unwrap();
    let (state, _, cleanup, _, held) = facts(&f, &attempt);
    assert_eq!(
        (state.as_str(), cleanup.as_str(), held),
        ("canceled", "confirmed", 0)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_live_survivor_is_ended_by_its_verified_identity() {
    let f = Fixture::new();
    let job = accept(&f, "recovery-survivor").job_id;
    let dispatched = dispatch(&f, &job);
    let attempt = AttemptRef::from(&dispatched);
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let survivor = linux_identity(child.id());
    let nonce = test_identity(&attempt.session_id, "launch").session_nonce;
    f.store
        .record_launch_identity(LaunchRecord {
            attempt: attempt.clone(),
            identity: WorkerIdentity {
                process: survivor.clone(),
                guardian: None,
                session_nonce: nonce,
            },
        })
        .unwrap();
    let f = reopen(f);
    let report = reconcile(&f.store).unwrap();
    assert_eq!(
        report,
        RecoveryReport {
            confirmed: 1,
            faulted: 0
        }
    );
    let _ = child.wait();
    assert!(!process_matches(&survivor).unwrap());
    let (_, _, cleanup, reason, held) = facts(&f, &attempt);
    assert_eq!(
        (cleanup.as_str(), reason.as_deref(), held),
        ("confirmed", Some("restart_survivor_terminated"), 0)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_reused_pid_is_never_killed_by_recovery() {
    let f = Fixture::new();
    let job = accept(&f, "recovery-reused").job_id;
    let dispatched = dispatch(&f, &job);
    let attempt = AttemptRef::from(&dispatched);
    // A live process now holds the recorded pid, born after the record.
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let live = linux_identity(child.id());
    let nonce = test_identity(&attempt.session_id, "launch").session_nonce;
    f.store
        .record_launch_identity(LaunchRecord {
            attempt: attempt.clone(),
            identity: WorkerIdentity {
                process: ProcessIdentity {
                    pid: live.pid,
                    start_marker: "linux-start-1".into(),
                },
                guardian: None,
                session_nonce: nonce,
            },
        })
        .unwrap();
    let f = reopen(f);
    reconcile(&f.store).unwrap();
    assert!(
        process_matches(&live).unwrap(),
        "the unrelated process lives"
    );
    assert_eq!(
        facts(&f, &attempt).3.as_deref(),
        Some("owner_death_containment")
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_corrupt_recorded_identity_fails_closed() {
    let f = Fixture::new();
    let job = accept(&f, "recovery-corrupt").job_id;
    let attempt = AttemptRef::from(&launched(&f, &job));
    let f = reopen(f);
    db(&f)
        .execute(
            "UPDATE job_attempts SET native_identity_json='{\"version\":1}' WHERE attempt_id=?1",
            [attempt.attempt_id.as_str()],
        )
        .unwrap();
    assert!(matches!(reconcile(&f.store), Err(CoreError::InvalidStore)));
    assert_eq!(facts(&f, &attempt).4, 1, "nothing released");
}
