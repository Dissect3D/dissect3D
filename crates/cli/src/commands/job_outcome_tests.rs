use super::*;
use crate::commands::observe::{ObserveEnd, ObserveTimeout};
use dissect3d_api::{
    ExecutionJobSnapshot, ExecutionJobState, ExecutionOutcome, JobId, decode_execution_json,
};

fn job_id() -> JobId {
    JobId::parse("job_0123456789abcdef0123456789abcdef").unwrap()
}

fn snapshot(state: ExecutionJobState) -> Box<ExecutionJobSnapshot> {
    let mut snap: ExecutionJobSnapshot = decode_execution_json(
        include_bytes!("../../../api/tests/fixtures/execution-snapshot.json"),
        262_144,
    )
    .unwrap();
    snap.summary.job_id = job_id();
    snap.summary.state = state;
    snap.summary.cancellation.requested = matches!(state, ExecutionJobState::Canceled);
    snap.summary.outcome = match state {
        ExecutionJobState::Failed => Some(ExecutionOutcome {
            code: "worker_failed".to_owned(),
            retryable: true,
        }),
        ExecutionJobState::Canceled => Some(ExecutionOutcome {
            code: "canceled".to_owned(),
            retryable: true,
        }),
        ExecutionJobState::Interrupted => Some(ExecutionOutcome {
            code: "engine_restarted".to_owned(),
            retryable: true,
        }),
        _ => None,
    };
    Box::new(snap)
}

#[test]
fn observe_timeout_enforces_cr_cs_03_bounds() {
    assert_eq!(ObserveTimeout::from_ms(0).err().unwrap().exit_code, 2);
    assert_eq!(ObserveTimeout::from_ms(999).err().unwrap().exit_code, 2);
    assert_eq!(
        ObserveTimeout::from_ms(86_400_001).err().unwrap().exit_code,
        2
    );
    assert_eq!(ObserveTimeout::parse("-1").err().unwrap().exit_code, 2);
    assert_eq!(ObserveTimeout::parse("abc").err().unwrap().exit_code, 2);
    assert_eq!(
        ObserveTimeout::from_ms(1_000)
            .ok()
            .unwrap()
            .duration()
            .as_millis(),
        1_000
    );
    assert_eq!(
        ObserveTimeout::from_ms(86_400_000)
            .ok()
            .unwrap()
            .duration()
            .as_millis(),
        86_400_000
    );
}

#[test]
fn exit_codes_match_every_promise_and_terminal_state() {
    let states = [
        (ExecutionJobState::Succeeded, 0, 0, 0),
        (ExecutionJobState::Failed, 0, 10, 10),
        (ExecutionJobState::Partial, 0, 11, 11),
        (ExecutionJobState::Canceled, 0, 12, 12),
        (ExecutionJobState::Interrupted, 0, 13, 13),
    ];
    for (state, watch_code, wait_code, run_code) in states {
        let end = ObserveEnd::Terminal(snapshot(state));
        assert_eq!(exit_code(Promise::Watch, &end), watch_code, "{state:?}");
        assert_eq!(exit_code(Promise::Wait, &end), wait_code, "{state:?}");
        assert_eq!(exit_code(Promise::Run, &end), run_code, "{state:?}");
    }
}

#[test]
fn exit_codes_match_non_terminal_observation_endings() {
    let cases = [
        (
            ObserveEnd::TimedOut {
                job_id: job_id(),
                last: None,
            },
            14,
        ),
        (
            ObserveEnd::TimedOut {
                job_id: job_id(),
                last: Some(snapshot(ExecutionJobState::Running)),
            },
            14,
        ),
        (
            ObserveEnd::Interrupted {
                job_id: job_id(),
                last: None,
            },
            18,
        ),
        (
            ObserveEnd::ReadsExhausted {
                job_id: job_id(),
                last: None,
            },
            3,
        ),
        (ObserveEnd::NotFound(job_id()), 19),
    ];
    for (end, expected) in cases {
        for promise in [Promise::Watch, Promise::Wait, Promise::Run] {
            assert_eq!(exit_code(promise, &end), expected);
        }
    }
}

#[test]
fn envelope_preserves_job_id_even_without_first_snapshot() {
    let id = job_id();
    for end in [
        ObserveEnd::TimedOut {
            job_id: id.clone(),
            last: None,
        },
        ObserveEnd::Interrupted {
            job_id: id.clone(),
            last: None,
        },
        ObserveEnd::ReadsExhausted {
            job_id: id.clone(),
            last: None,
        },
        ObserveEnd::NotFound(id.clone()),
    ] {
        let outcome = render_outcome("jobs watch", Promise::Watch, &end);
        let value = serde_json::to_value(&outcome).unwrap();
        assert_eq!(value["cli_output_version"], "1.0");
        assert_eq!(value["command"], "jobs watch");
        assert_eq!(value["ok"], false);
        assert_eq!(value["data"]["job_id"], id.as_str());
    }
}

#[test]
fn envelope_carries_snapshot_fields_and_stale_warning_when_interrupted_after_poll() {
    let snap = snapshot(ExecutionJobState::Running);
    let end = ObserveEnd::TimedOut {
        job_id: job_id(),
        last: Some(snap),
    };
    let outcome = render_outcome("jobs wait", Promise::Wait, &end);
    let value = serde_json::to_value(&outcome).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["category"], "observation_timeout");
    assert_eq!(value["data"]["job_id"], job_id().as_str());
    assert_eq!(value["data"]["state"], "running");
    assert_eq!(value["warnings"][0], "last_known_state_may_be_stale");
}
