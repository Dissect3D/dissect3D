use super::*;
use dissect3d_api::JobId;

fn job_id() -> JobId {
    JobId::parse("job_0123456789abcdef0123456789abcdef").unwrap()
}

#[test]
fn before_send_interrupt_stops_without_sending() {
    let mut sm = InterruptStateMachine::new();
    assert_eq!(sm.on_interrupt(), InterruptAction::StopNotSent);
}

#[test]
fn in_flight_first_interrupt_acks_and_second_exits_uncertain() {
    let mut sm = InterruptStateMachine::new();
    sm.enter_in_flight();
    assert_eq!(sm.on_interrupt(), InterruptAction::AckAndKeepWaiting);
    assert_eq!(sm.on_interrupt(), InterruptAction::ExitUncertain);
}

#[test]
fn in_flight_first_interrupt_then_receipt_sends_cancel_once_then_second_exits_detached() {
    let mut sm = InterruptStateMachine::new();
    let id = job_id();
    sm.enter_in_flight();
    assert_eq!(sm.on_interrupt(), InterruptAction::AckAndKeepWaiting);
    assert_eq!(
        sm.on_accepted(id.clone()),
        Some(InterruptAction::SendCancel(id))
    );
    // Second Ctrl+C during cancel wait exits 17 without sending another cancel.
    assert_eq!(sm.on_interrupt(), InterruptAction::ExitDetached);
    assert_eq!(sm.on_interrupt(), InterruptAction::ExitDetached);
}

#[test]
fn accepted_first_interrupt_sends_cancel_once_and_second_exits_detached() {
    let mut sm = InterruptStateMachine::new();
    let id = job_id();
    sm.enter_in_flight();
    assert_eq!(sm.on_accepted(id.clone()), None);
    assert_eq!(sm.on_interrupt(), InterruptAction::SendCancel(id));
    assert_eq!(sm.on_interrupt(), InterruptAction::ExitDetached);
}

#[test]
fn foreground_and_observation_printers_describe_accurate_ctrl_c_controls() {
    let snap: dissect3d_api::ExecutionJobSnapshot = dissect3d_api::decode_execution_json(
        include_bytes!("../../../../api/tests/fixtures/execution-snapshot.json"),
        262_144,
    )
    .unwrap();
    let fg = crate::commands::observe::ObserverPrinter::for_foreground().readiness_line(&snap);
    assert!(fg.contains("request cancellation"), "fg={fg}");
    assert!(!fg.contains("job keeps running"), "fg={fg}");

    let obs = crate::commands::observe::ObserverPrinter::new().readiness_line(&snap);
    assert!(obs.contains("job keeps running"), "obs={obs}");
    assert!(!obs.contains("request cancellation"), "obs={obs}");
}
