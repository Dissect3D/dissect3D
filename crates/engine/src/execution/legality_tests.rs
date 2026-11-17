//! WE-P04 session legality (WC-001/003, WE-004). Pure, in memory.
use super::legality::*;
use crate::worker_protocol::tests::{ATT, GRT, JOB, SES, frame, hello_payload};
use crate::worker_protocol::{
    Assignment, CancelReason, ExecuteInput, InboundFrame, ProtocolViolation, decode_inbound,
    random_id,
};
use serde_json::{Value, json};

pub(super) fn expectation() -> WorkerExpectation {
    WorkerExpectation {
        worker_build_sha256: "a".repeat(64),
        adapter_id: "test.mesh-copy".into(),
        adapter_revision: "fixture-r2".into(),
        required_features: vec!["cooperative_cancel".into()],
        resolution_sha256: "b".repeat(64),
    }
}
fn session() -> Session {
    Session::new(
        SessionIdentity {
            session_id: SES.into(),
            grant_id: GRT.into(),
            assignment: Assignment {
                job_id: JOB.into(),
                attempt_id: ATT.into(),
            },
        },
        expectation(),
    )
}
fn command_id(bytes: &[u8]) -> String {
    let value: Value = serde_json::from_slice(bytes).unwrap();
    value["command_id"].as_str().unwrap().to_owned()
}
fn inbound(text: String) -> InboundFrame {
    decode_inbound(&text).unwrap()
}
fn scoped(reply: Option<&str>) -> Vec<(&'static str, Value)> {
    let mut extra = vec![("job_id", JOB.into()), ("attempt_id", ATT.into())];
    if let Some(reply) = reply {
        extra.push(("in_reply_to", reply.into()));
    }
    extra
}
fn loaded(reply: &str) -> InboundFrame {
    inbound(frame(
        "loaded",
        json!({"grant_id": GRT, "resolution_sha256": "b".repeat(64)}),
        &scoped(Some(reply)),
    ))
}
fn execute(session: &mut Session) -> Result<Vec<u8>, ProtocolViolation> {
    session.execute(
        vec![ExecuteInput {
            role: "mesh".into(),
            handle: "in:1".into(),
            sha256: "c".repeat(64),
            byte_length: 10,
        }],
        "out:1".into(),
        "par:1".into(),
    )
}
/// Drive a session to `Loaded`; returns the configure and load command IDs.
fn to_loaded(session: &mut Session) -> (String, String) {
    session
        .accept(inbound(frame("hello", hello_payload(), &[])))
        .unwrap();
    let configure = command_id(&session.configure("res:1".into()).unwrap());
    session
        .accept(inbound(frame(
            "configured",
            json!({"accepted": true}),
            &[("in_reply_to", configure.clone().into())],
        )))
        .unwrap();
    let load = command_id(&session.load("res:1".into()).unwrap());
    assert!(!session.loaded());
    session.accept(loaded(&load)).unwrap();
    (configure, load)
}
fn candidate() -> InboundFrame {
    inbound(frame(
        "candidate",
        json!({"description_handle": "out:desc", "files": [
            {"relative_name": "mesh.obj", "byte_length": 10, "sha256": "d".repeat(64)}
        ]}),
        &scoped(None),
    ))
}

#[test]
fn hello_configure_load_execute_candidate_is_the_only_legal_order() {
    let mut s = session();
    // Nothing but hello before the handshake.
    assert_eq!(
        s.configure("res:1".into()),
        Err(ProtocolViolation::IllegalSequence)
    );
    assert_eq!(execute(&mut s), Err(ProtocolViolation::IllegalSequence));
    assert_eq!(
        s.accept(candidate()),
        Err(ProtocolViolation::IllegalSequence)
    );
    to_loaded(&mut s);
    assert!(s.loaded());
    assert_eq!(s.phase(), Phase::Loaded);
    assert!(!s.execute_issued());
    execute(&mut s).unwrap();
    assert_eq!(s.phase(), Phase::Executing);
    let progress = inbound(frame(
        "progress",
        json!({"stage": "copy", "fraction": 0.5}),
        &scoped(None),
    ));
    assert!(matches!(
        s.accept(progress),
        Ok(Observation::Progress { .. })
    ));
    assert!(matches!(
        s.accept(candidate()),
        Ok(Observation::Candidate(_))
    ));
    assert_eq!(s.phase(), Phase::Finished);
    // One execution report only.
    assert_eq!(
        s.accept(candidate()),
        Err(ProtocolViolation::IllegalSequence)
    );
}

#[test]
fn incompatible_hello_is_rejected_before_configuration() {
    let edits: [(&str, Value); 4] = [
        ("worker_build_sha256", "f".repeat(64).into()),
        ("adapter_id", "other.adapter".into()),
        ("adapter_revision", "fixture-r1".into()),
        ("features", json!([])),
    ];
    for (field, value) in edits {
        let mut payload = hello_payload();
        payload[field] = value;
        let mut s = session();
        assert_eq!(
            s.accept(inbound(frame("hello", payload, &[]))),
            Err(ProtocolViolation::IncompatibleHello),
            "{field}"
        );
        assert_eq!(
            s.configure("res:1".into()),
            Err(ProtocolViolation::IllegalSequence)
        );
    }
    // A second hello is out of order.
    let mut s = session();
    s.accept(inbound(frame("hello", hello_payload(), &[])))
        .unwrap();
    assert_eq!(
        s.accept(inbound(frame("hello", hello_payload(), &[]))),
        Err(ProtocolViolation::IllegalSequence)
    );
}

#[test]
fn wrong_session_attempt_grant_or_resolution_cannot_update_this_attempt() {
    let mut s = session();
    let other_session = frame("hello", hello_payload(), &[]).replace(SES, &random_id("ses_"));
    assert_eq!(
        s.accept(inbound(other_session)),
        Err(ProtocolViolation::WrongSession)
    );
    s.accept(inbound(frame("hello", hello_payload(), &[])))
        .unwrap();
    let configure = command_id(&s.configure("res:1".into()).unwrap());
    s.accept(inbound(frame(
        "configured",
        json!({"accepted": true}),
        &[("in_reply_to", configure.into())],
    )))
    .unwrap();
    let load = command_id(&s.load("res:1".into()).unwrap());
    let wrong_attempt = frame(
        "loaded",
        json!({"grant_id": GRT, "resolution_sha256": "b".repeat(64)}),
        &[
            ("job_id", JOB.into()),
            ("attempt_id", random_id("att_").into()),
            ("in_reply_to", load.clone().into()),
        ],
    );
    assert_eq!(
        s.accept(inbound(wrong_attempt)),
        Err(ProtocolViolation::WrongAttempt)
    );
    let wrong_grant = frame(
        "loaded",
        json!({"grant_id": random_id("grt_"), "resolution_sha256": "b".repeat(64)}),
        &scoped(Some(&load)),
    );
    assert_eq!(
        s.accept(inbound(wrong_grant)),
        Err(ProtocolViolation::WrongGrant)
    );
    let wrong_resolution = frame(
        "loaded",
        json!({"grant_id": GRT, "resolution_sha256": "e".repeat(64)}),
        &scoped(Some(&load)),
    );
    assert_eq!(
        s.accept(inbound(wrong_resolution)),
        Err(ProtocolViolation::WrongResolution)
    );
    // None of these established loaded evidence.
    assert!(!s.loaded());
    assert_eq!(s.phase(), Phase::Loading);
}

#[test]
fn stale_acknowledgements_and_repeated_execute_never_issue_a_second_execution() {
    let mut s = session();
    let (configure, load) = to_loaded(&mut s);
    // Replayed acknowledgements of completed commands are stale.
    assert_eq!(
        s.accept(inbound(frame(
            "configured",
            json!({"accepted": true}),
            &[("in_reply_to", configure.into())],
        ))),
        Err(ProtocolViolation::StaleAcknowledgement)
    );
    assert_eq!(
        s.accept(loaded(&load)),
        Err(ProtocolViolation::StaleAcknowledgement)
    );
    // An acknowledgement of a command never sent is stale too.
    execute(&mut s).unwrap();
    assert_eq!(execute(&mut s), Err(ProtocolViolation::RepeatedExecute));
    s.accept(candidate()).unwrap();
    // Permission is one-shot in every later state.
    assert_eq!(execute(&mut s), Err(ProtocolViolation::RepeatedExecute));
    let mut fresh = session();
    to_loaded(&mut fresh);
    let foreign = random_id("cmd_");
    let cancel = fresh.cancel(CancelReason::UserCancel).unwrap();
    assert!(!cancel.is_empty());
    assert_eq!(
        fresh.accept(inbound(frame(
            "cancel_ack",
            json!({"observed": true}),
            &scoped(Some(&foreign)),
        ))),
        Err(ProtocolViolation::StaleAcknowledgement)
    );
    assert_eq!(execute(&mut fresh), Err(ProtocolViolation::IllegalSequence));
    assert!(!fresh.execute_issued());
}

#[test]
fn pong_is_responsiveness_only_and_cancel_ack_is_not_termination() {
    let mut s = session();
    to_loaded(&mut s);
    // A pong without an outstanding ping is stale.
    let stray = frame(
        "pong",
        json!({}),
        &[("in_reply_to", random_id("cmd_").into())],
    );
    assert_eq!(
        s.accept(inbound(stray)),
        Err(ProtocolViolation::StaleAcknowledgement)
    );
    let ping = s.ping().unwrap().unwrap();
    // Never more than one ping in flight.
    assert!(s.ping().unwrap().is_none());
    let pong = frame(
        "pong",
        json!({}),
        &[("in_reply_to", command_id(&ping).into())],
    );
    assert_eq!(s.accept(inbound(pong)), Ok(Observation::Pong));
    // The pong changed no phase and no loaded/execute fact.
    assert_eq!(s.phase(), Phase::Loaded);
    assert!(!s.ping_outstanding());
    execute(&mut s).unwrap();
    let cancel = command_id(&s.cancel(CancelReason::Deadline).unwrap());
    assert_eq!(
        s.accept(inbound(frame(
            "cancel_ack",
            json!({"observed": true}),
            &scoped(Some(&cancel)),
        ))),
        Ok(Observation::CancelAcknowledged)
    );
    // Acknowledged, not terminated: the phase stays canceling.
    assert_eq!(s.phase(), Phase::Canceling);
    // A racing candidate is accepted once (the supervisor discards it) ...
    assert!(matches!(
        s.accept(candidate()),
        Ok(Observation::Candidate(_))
    ));
    // ... and a second one is still illegal.
    assert_eq!(
        s.accept(candidate()),
        Err(ProtocolViolation::IllegalSequence)
    );
    // `released` must name this grant.
    let wrong = frame(
        "released",
        json!({"grant_id": random_id("grt_")}),
        &scoped(None),
    );
    assert_eq!(s.accept(inbound(wrong)), Err(ProtocolViolation::WrongGrant));
    let released = frame("released", json!({"grant_id": GRT}), &scoped(None));
    assert_eq!(s.accept(inbound(released)), Ok(Observation::Released));
}
