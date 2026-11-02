use dissect3d_platform::{current_process_identity, process_matches, wait_for_process_exit};
use std::time::Duration;

#[test]
fn process_marker_matches_only_the_observed_process_start() {
    let current = current_process_identity().expect("current process identity");
    assert!(process_matches(&current).expect("observe current process"));

    let mut stale = current.clone();
    stale.start_marker.push_str("-stale");
    assert!(!process_matches(&stale).expect("observe mismatched marker"));
    assert!(
        wait_for_process_exit(&stale, Duration::from_millis(1))
            .expect("bounded process observation")
    );
}

#[test]
fn current_process_exit_observation_returns_unconfirmed_at_its_deadline() {
    let current = current_process_identity().expect("current process identity");
    let started = std::time::Instant::now();
    let exited = wait_for_process_exit(&current, Duration::from_millis(100))
        .expect("bounded process observation");
    let elapsed = started.elapsed();
    assert!(!exited, "the current test process has not exited");
    assert!(elapsed >= Duration::from_millis(80), "elapsed: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
}
