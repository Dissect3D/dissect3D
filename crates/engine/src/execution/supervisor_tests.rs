//! WE-P04 supervisor core with the in-memory fake worker. These establish
//! codec/legality/timer behavior only: not a provider, a real process or
//! process-tree cleanup (see `process_fixture_tests` for real processes).
use super::fake_worker::{Behavior, FakeLauncher, LaunchMode, OnExecute, OnLoad, Record};
use super::legality_tests::expectation;
use super::progress::{AttemptPhase, ObservationUpdate};
use super::supervisor::WorkerSupervisor;
use super::types::*;
use crate::store::execution::{AttemptTiming, DispatchRecord};
use crate::worker_protocol::{ExecuteInput, random_id};
use dissect3d_api::JobId;
use dissect3d_platform::CleanupFault;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub(super) fn limits() -> SupervisionLimits {
    SupervisionLimits {
        launch: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        load: Duration::from_secs(2),
        cooperative_cancel: Duration::from_millis(300),
        termination: Duration::from_millis(500),
        shutdown: Duration::from_millis(300),
        ping_interval: Duration::from_millis(20),
        silence_warning: Duration::from_secs(5),
        progress_interval: Duration::from_millis(50),
    }
}
pub(super) fn plan(limits: SupervisionLimits) -> AttemptPlan {
    AttemptPlan {
        expectation: expectation(),
        resolution_handle: "res:1".into(),
        inputs: vec![ExecuteInput {
            role: "mesh".into(),
            handle: "in:1".into(),
            sha256: "c".repeat(64),
            byte_length: 10,
        }],
        output_staging_handle: "out:1".into(),
        effective_parameters_handle: "par:1".into(),
        stages: &["copy"],
        limits,
    }
}
pub(super) fn dispatch(timeout: Option<Duration>) -> DispatchRecord {
    DispatchRecord {
        job_id: JobId::parse(random_id("job_")).unwrap(),
        attempt_id: random_id("att_"),
        session_id: random_id("ses_"),
        grant_id: random_id("grt_"),
        resolved_json: "{}".into(),
        resources: vec!["cpu:fixture".into()],
        timeout_ms: timeout.map(|t| t.as_millis() as u64),
        timing: Arc::new(AttemptTiming::for_supervision_test(timeout)),
    }
}

/// Harness bound: a regression fails instead of hanging the suite.
pub(super) async fn bounded(run: impl std::future::Future<Output = AttemptExit>) -> AttemptExit {
    tokio::time::timeout(Duration::from_secs(15), run)
        .await
        .expect("supervision ended within the harness bound")
}

struct Run {
    exit: AttemptExit,
    record: Arc<Record>,
    observations: Vec<ObservationUpdate>,
}
async fn run_with(
    dispatch: &DispatchRecord,
    launcher: FakeLauncher,
    record: Arc<Record>,
    limits: SupervisionLimits,
    stop_after: Option<(Duration, StopIntent)>,
) -> Run {
    let (stop_tx, stop_rx) = watch::channel(StopIntent::Continue);
    let (obs_tx, mut obs_rx) = watch::channel(None);
    let collector = tokio::spawn(async move {
        let mut seen = Vec::new();
        while obs_rx.changed().await.is_ok() {
            if let Some(update) = obs_rx.borrow_and_update().clone() {
                seen.push(update);
            }
        }
        seen
    });
    // The sender stays alive for the whole run: a dropped controller would
    // itself mean "stop" (tested separately).
    let stop_tx = Arc::new(stop_tx);
    let stopper = stop_after.map(|(after, intent)| {
        let stop_tx = Arc::clone(&stop_tx);
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let _ = stop_tx.send(intent);
        })
    });
    let exit = bounded(WorkerSupervisor::run(
        dispatch,
        plan(limits),
        launcher,
        stop_rx,
        &obs_tx,
    ))
    .await;
    drop(obs_tx);
    drop(stop_tx);
    if let Some(stopper) = stopper {
        stopper.abort();
    }
    Run {
        exit,
        record,
        observations: collector.await.unwrap(),
    }
}
async fn run(behavior: Behavior, timeout: Option<Duration>) -> Run {
    let (launcher, record) = FakeLauncher::new(behavior);
    run_with(&dispatch(timeout), launcher, record, limits(), None).await
}
fn ended(exit: &AttemptExit) -> (AttemptEnd, &AttemptCleanup) {
    match exit {
        AttemptExit::Ended { end, cleanup, .. } => (*end, cleanup),
        AttemptExit::Candidate { .. } => panic!("unexpected candidate"),
    }
}
fn categories(exit: &AttemptExit) -> Vec<&'static str> {
    let diagnostics = match exit {
        AttemptExit::Candidate { diagnostics, .. } | AttemptExit::Ended { diagnostics, .. } => {
            diagnostics
        }
    };
    diagnostics.categories.iter().map(|(c, _)| *c).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_is_returned_only_after_shutdown_and_confirmed_tree_cleanup() {
    let r = run(Behavior::default(), None).await;
    match &r.exit {
        AttemptExit::Candidate { report, .. } => {
            assert_eq!(report.files.len(), 1);
            assert_eq!(report.files[0].relative_name, "mesh.obj");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(Record::count(&r.record.executes), 1);
    assert_eq!(Record::count(&r.record.shutdowns), 1);
    // External termination is always requested; a shutdown ack is not cleanup.
    assert_eq!(Record::count(&r.record.terminations), 1);
    // Latest-only delivery: the final snapshot is always observed.
    assert_eq!(
        r.observations.last().map(|o| o.phase),
        Some(AttemptPhase::Stopping)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_expiry_requests_external_cleanup_and_a_typed_failure_never_user_cancel() {
    // The worker answers every ping but never reports: pongs extend nothing.
    let behavior = Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let dispatch = dispatch(Some(Duration::from_millis(400)));
    let (launcher, record) = FakeLauncher::new(behavior);
    let r = run_with(&dispatch, launcher, record, limits(), None).await;
    let (end, cleanup) = ended(&r.exit);
    assert_eq!(end, AttemptEnd::DeadlineExceeded);
    assert!(matches!(cleanup, AttemptCleanup::Confirmed(_)));
    assert_eq!(r.record.cancel_reasons(), ["deadline"]);
    assert_eq!(Record::count(&r.record.terminations), 1);
    assert!(Record::count(&r.record.pings) >= 3, "pongs were answered");
    // Expiry follows the Store record's original start, not launch or pongs.
    let elapsed = dispatch.timing.started().elapsed();
    assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(400) + Duration::from_secs(2),
        "{elapsed:?}"
    );
    assert!(categories(&r.exit).contains(&"execution_deadline_exceeded"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pong_never_extends_the_load_bound_and_silent_control_only_warns() {
    let behavior = Behavior {
        on_load: OnLoad::Hang,
        ..Behavior::default()
    };
    let mut fast = limits();
    fast.load = Duration::from_millis(300);
    let (launcher, record) = FakeLauncher::new(behavior);
    let started = Instant::now();
    let r = run_with(&dispatch(None), launcher, record, fast, None).await;
    let (end, _) = ended(&r.exit);
    assert_eq!(end, AttemptEnd::WorkerFailed);
    assert!(started.elapsed() < Duration::from_millis(300) + Duration::from_secs(2));
    assert!(Record::count(&r.record.pings) >= 3);
    assert_eq!(Record::count(&r.record.executes), 0);
    // A worker that never pongs still is not failed for silence alone.
    let behavior = Behavior {
        pong: false,
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let (launcher, record) = FakeLauncher::new(behavior);
    let r = run_with(
        &dispatch(None),
        launcher,
        record,
        limits(),
        Some((Duration::from_millis(400), StopIntent::UserCancel)),
    )
    .await;
    assert_eq!(
        ended(&r.exit).0,
        AttemptEnd::Stopped(StopIntent::UserCancel)
    );
    assert!(categories(&r.exit).contains(&"control_unresponsive"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_violations_contain_the_worker_without_a_second_execute_or_candidate() {
    // Wrong session from the first frame.
    let behavior = Behavior {
        session_override: Some("ses_ffffffffffffffffffffffffffffffff"),
        ..Behavior::default()
    };
    let r = run(behavior, None).await;
    assert_eq!(ended(&r.exit).0, AttemptEnd::ProtocolError);
    assert_eq!(Record::count(&r.record.executes), 0);
    assert_eq!(Record::count(&r.record.terminations), 1);
    assert!(r.record.cancel_reasons().is_empty(), "no cooperation");
    // A stale duplicate `loaded`: execute was issued at most once.
    let behavior = Behavior {
        on_load: OnLoad::LoadedTwice,
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    };
    let r = run(behavior, None).await;
    assert_eq!(ended(&r.exit).0, AttemptEnd::ProtocolError);
    assert!(Record::count(&r.record.executes) <= 1);
    assert!(categories(&r.exit).contains(&"worker_protocol_violation"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declared_failures_and_early_exit_are_typed_worker_failures() {
    for (behavior, label) in [
        (
            Behavior {
                on_load: OnLoad::Fail,
                ..Behavior::default()
            },
            "load_failed",
        ),
        (
            Behavior {
                on_execute: OnExecute::Fail,
                ..Behavior::default()
            },
            "execution_failed",
        ),
        (
            Behavior {
                on_execute: OnExecute::Exit,
                ..Behavior::default()
            },
            "exit",
        ),
    ] {
        let r = run(behavior, None).await;
        let (end, cleanup) = ended(&r.exit);
        assert_eq!(end, AttemptEnd::WorkerFailed, "{label}");
        assert!(matches!(cleanup, AttemptCleanup::Confirmed(_)), "{label}");
        assert_eq!(Record::count(&r.record.terminations), 1, "{label}");
        // The worker's own `code` text never reaches diagnostics.
        let rendered = format!("{:?}", r.exit);
        assert!(!rendered.contains("secret") && !rendered.contains("models"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_cancel_discards_a_racing_candidate_and_cleanup_fault_blocks_a_candidate() {
    let behavior = Behavior {
        on_execute: OnExecute::Hang,
        candidate_after_cancel: true,
        ..Behavior::default()
    };
    let (launcher, record) = FakeLauncher::new(behavior);
    let r = run_with(
        &dispatch(None),
        launcher,
        record,
        limits(),
        Some((Duration::from_millis(200), StopIntent::UserCancel)),
    )
    .await;
    let (end, cleanup) = ended(&r.exit);
    assert_eq!(end, AttemptEnd::Stopped(StopIntent::UserCancel));
    assert!(matches!(cleanup, AttemptCleanup::Confirmed(_)));
    assert_eq!(r.record.cancel_reasons(), ["user_cancel"]);
    // Engine shutdown sends its own reason.
    let (launcher, record) = FakeLauncher::new(Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    });
    let r = run_with(
        &dispatch(None),
        launcher,
        record,
        limits(),
        Some((Duration::from_millis(200), StopIntent::EngineShutdown)),
    )
    .await;
    assert_eq!(
        ended(&r.exit).0,
        AttemptEnd::Stopped(StopIntent::EngineShutdown)
    );
    assert_eq!(r.record.cancel_reasons(), ["engine_shutdown"]);
    // A candidate without established termination is never a candidate.
    let (mut launcher, record) = FakeLauncher::new(Behavior::default());
    launcher.cleanup = Err(CleanupFault::OwnershipLost);
    let r = run_with(&dispatch(None), launcher, record, limits(), None).await;
    let (end, cleanup) = ended(&r.exit);
    assert_eq!(end, AttemptEnd::CleanupUnconfirmed);
    assert!(matches!(
        cleanup,
        AttemptCleanup::Fault("cleanup_ownership_lost")
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_or_stopped_attempts_never_launch_and_launch_failures_are_typed() {
    // The Store's budget already expired: no launch and no new budget (AD-01).
    let late = dispatch(Some(Duration::from_millis(1)));
    while !late.timing.expired() {
        std::thread::yield_now();
    }
    let (launcher, record) = FakeLauncher::new(Behavior::default());
    let r = run_with(&late, launcher, record, limits(), None).await;
    let (end, cleanup) = ended(&r.exit);
    assert_eq!(end, AttemptEnd::DeadlineExceeded);
    assert!(matches!(cleanup, AttemptCleanup::NeverLaunched(_)));
    assert_eq!(Record::count(&r.record.launches), 0);
    for (mode, never) in [
        (LaunchMode::NotStarted, true),
        (LaunchMode::Uncertain, false),
    ] {
        let (mut launcher, record) = FakeLauncher::new(Behavior::default());
        launcher.mode = mode;
        let r = run_with(&dispatch(None), launcher, record, limits(), None).await;
        let (end, cleanup) = ended(&r.exit);
        assert_eq!(end, AttemptEnd::LaunchFailed);
        if never {
            assert!(matches!(cleanup, AttemptCleanup::NeverLaunched(_)));
        } else {
            assert!(matches!(
                cleanup,
                AttemptCleanup::Fault("cleanup_launch_unverified")
            ));
        }
    }
    // Effective bounds never exceed the accepted ceilings.
    let mut raised = limits();
    raised.load = Duration::from_secs(31);
    let (launcher, record) = FakeLauncher::new(Behavior::default());
    let r = run_with(&dispatch(None), launcher, record, raised, None).await;
    assert_eq!(ended(&r.exit).0, AttemptEnd::LaunchFailed);
    assert_eq!(Record::count(&r.record.launches), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vanished_controller_stops_the_attempt_as_engine_shutdown() {
    let (launcher, record) = FakeLauncher::new(Behavior {
        on_execute: OnExecute::Hang,
        ..Behavior::default()
    });
    let (stop_tx, stop_rx) = watch::channel(StopIntent::Continue);
    let (obs_tx, _obs_rx) = watch::channel(None);
    let dispatch = dispatch(None);
    let dropper = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(stop_tx);
    });
    let exit = bounded(WorkerSupervisor::run(
        &dispatch,
        plan(limits()),
        launcher,
        stop_rx,
        &obs_tx,
    ))
    .await;
    dropper.await.unwrap();
    assert_eq!(
        ended(&exit).0,
        AttemptEnd::Stopped(StopIntent::EngineShutdown)
    );
    assert_eq!(record.cancel_reasons(), ["engine_shutdown"]);
    assert_eq!(Record::count(&record.terminations), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diagnostics_are_drained_and_capped_and_progress_is_coalesced() {
    let behavior = Behavior {
        diagnostics: 2 * 1_048_576,
        on_execute: OnExecute::ProgressThenCandidate(200),
        ..Behavior::default()
    };
    let r = run(behavior, None).await;
    let AttemptExit::Candidate { diagnostics, .. } = &r.exit else {
        panic!("{:?}", r.exit);
    };
    assert_eq!(diagnostics.bytes_retained, 1_048_576);
    assert!(diagnostics.truncated);
    // 200 reports become a handful of offered snapshots (the coalescer's
    // exact rules are covered by its pure tests); every value is a listed stage.
    assert!(r.observations.len() < 20, "{}", r.observations.len());
    assert!(
        r.observations
            .iter()
            .filter_map(|o| o.progress.as_ref())
            .all(|p| p.stage == "copy")
    );
}
