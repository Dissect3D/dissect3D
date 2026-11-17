//! WE-P04 codec regressions (plan protocol list, WC-001). In-memory only.
use super::*;
use serde_json::{Value, json};

pub(crate) const SES: &str = "ses_0123456789abcdef0123456789abcdef";
pub(crate) const JOB: &str = "job_0123456789abcdef0123456789abcdef";
pub(crate) const ATT: &str = "att_0123456789abcdef0123456789abcdef";
pub(crate) const GRT: &str = "grt_0123456789abcdef0123456789abcdef";

/// A worker frame without its LF.
pub(crate) fn frame(kind: &str, payload: Value, extra: &[(&str, Value)]) -> String {
    let mut object = serde_json::Map::new();
    object.insert("protocol_version".into(), PROTOCOL_VERSION.into());
    object.insert("kind".into(), kind.into());
    object.insert("session_id".into(), SES.into());
    object.insert("message_id".into(), random_id("msg_").into());
    object.insert("payload".into(), payload);
    for (key, value) in extra {
        object.insert((*key).into(), value.clone());
    }
    Value::Object(object).to_string()
}
pub(crate) fn hello_payload() -> Value {
    json!({
        "worker_build_sha256": "a".repeat(64),
        "adapter_id": "test.mesh-copy",
        "adapter_revision": "fixture-r2",
        "features": ["cooperative_cancel"],
    })
}
fn scoped() -> [(&'static str, Value); 2] {
    [("job_id", JOB.into()), ("attempt_id", ATT.into())]
}

fn decode_all(
    decoder: &mut FrameDecoder,
    mut bytes: &[u8],
) -> Result<Vec<String>, ProtocolViolation> {
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let used = decoder.push(bytes)?;
        bytes = &bytes[used..];
        while let Some(f) = decoder.next_frame() {
            frames.push(f);
        }
    }
    Ok(frames)
}

#[test]
fn utf8_split_across_reads_and_multiple_frames_per_read_decode_exactly() {
    let mut payload = hello_payload();
    payload["adapter_id"] = "メッシュ.copy-é".into();
    let line = format!("{}\n", frame("hello", payload, &[]));
    // One byte per read splits every multibyte character.
    let mut decoder = FrameDecoder::default();
    let mut frames = Vec::new();
    for byte in line.as_bytes() {
        frames.extend(decode_all(&mut decoder, std::slice::from_ref(byte)).unwrap());
    }
    assert_eq!(frames.len(), 1);
    match decode_inbound(&frames[0]).unwrap().report {
        WorkerReport::Hello(hello) => assert_eq!(hello.adapter_id, "メッシュ.copy-é"),
        other => panic!("{other:?}"),
    }
    // Three frames in a single read.
    let pong = frame(
        "pong",
        json!({}),
        &[("in_reply_to", random_id("cmd_").into())],
    );
    let three = format!("{pong}\n{pong}\n{pong}\n");
    let frames = decode_all(&mut FrameDecoder::default(), three.as_bytes()).unwrap();
    assert_eq!(frames.len(), 3);
    assert!(frames.iter().all(|f| decode_inbound(f).is_ok()));
}

#[test]
fn the_lf_inclusive_65536_byte_boundary_is_exact_and_rejected_before_allocation() {
    // 65,535 bytes + LF is the largest legal frame.
    let mut decoder = FrameDecoder::default();
    let exact = format!("{}\n", "x".repeat(FRAME_BYTES_MAX - 1));
    assert_eq!(decode_all(&mut decoder, exact.as_bytes()).unwrap().len(), 1);
    // One more byte is oversized, rejected as soon as no LF can fit.
    let mut decoder = FrameDecoder::default();
    let over = vec![b'x'; FRAME_BYTES_MAX];
    assert_eq!(decoder.push(&over), Err(ProtocolViolation::OversizedFrame));
    // A never-terminated stream fails at the bound across many small reads.
    let mut decoder = FrameDecoder::default();
    let mut fed = 0usize;
    let error = loop {
        match decoder.push(&[b'x'; 1000]) {
            Ok(used) => fed += used,
            Err(e) => break e,
        }
    };
    assert_eq!(error, ProtocolViolation::OversizedFrame);
    assert!(fed < FRAME_BYTES_MAX);
    // The decoder stays failed.
    assert_eq!(
        decoder.push(b"{}\n"),
        Err(ProtocolViolation::OversizedFrame)
    );
}

#[test]
fn malformed_incomplete_duplicate_key_non_finite_and_invalid_utf8_frames_are_rejected() {
    assert_eq!(
        decode_inbound("{not json").unwrap_err(),
        ProtocolViolation::MalformedFrame
    );
    let pong = frame(
        "pong",
        json!({}),
        &[("in_reply_to", random_id("cmd_").into())],
    );
    let duplicate = pong.replacen("{", "{\"kind\":\"pong\",", 1);
    assert_eq!(
        decode_inbound(&duplicate).unwrap_err(),
        ProtocolViolation::MalformedFrame
    );
    let progress = frame(
        "progress",
        json!({"stage": "copy", "fraction": 0.5}),
        &scoped(),
    );
    let infinite = progress.replace("0.5", "1e999");
    assert_eq!(
        decode_inbound(&infinite).unwrap_err(),
        ProtocolViolation::MalformedFrame
    );
    assert_eq!(
        decode_inbound(&progress.replace("0.5", "NaN")).unwrap_err(),
        ProtocolViolation::MalformedFrame
    );
    // Incomplete at EOF: bytes without their LF are never a frame.
    let mut decoder = FrameDecoder::default();
    decoder.push(pong.as_bytes()).unwrap();
    assert_eq!(decoder.next_frame(), None);
    assert_eq!(decoder.finish(), Err(ProtocolViolation::IncompleteFrame));
    let mut decoder = FrameDecoder::default();
    assert_eq!(
        decoder.push(b"{\"kind\":\"\xff\"}\n"),
        Err(ProtocolViolation::InvalidUtf8)
    );
    assert_eq!(
        FrameDecoder::default().push(b"\n"),
        Err(ProtocolViolation::MalformedFrame)
    );
}

#[test]
fn unknown_engine_only_and_version_mismatched_kinds_are_rejected() {
    assert_eq!(
        decode_inbound(&frame("teleport", json!({}), &[])).unwrap_err(),
        ProtocolViolation::UnknownKind
    );
    // Engine -> worker kinds are unknown from a worker.
    for kind in ["configure", "load", "execute", "cancel", "shutdown", "ping"] {
        assert_eq!(
            decode_inbound(&frame(kind, json!({}), &[])).unwrap_err(),
            ProtocolViolation::UnknownKind,
            "{kind}"
        );
    }
    let old = frame("hello", hello_payload(), &[]).replace("d3d-worker/1", "d3d-worker/0");
    assert_eq!(
        decode_inbound(&old).unwrap_err(),
        ProtocolViolation::IncompatibleVersion
    );
}

#[test]
fn closed_records_reject_extra_missing_null_and_out_of_range_fields() {
    let reply = || ("in_reply_to", Value::from(random_id("cmd_")));
    let cases = [
        // Extra envelope field.
        frame("pong", json!({}), &[reply(), ("extra", 1.into())]),
        // Extra payload field.
        frame("pong", json!({"x": 1}), &[reply()]),
        // Missing in_reply_to on an acknowledgement.
        frame("pong", json!({}), &[]),
        // null where a correlation field is optional.
        frame("hello", hello_payload(), &[("in_reply_to", Value::Null)]),
        // Assignment fields on a session-scoped kind.
        frame("hello", hello_payload(), &scoped()),
        // Missing assignment on a scoped kind.
        frame("progress", json!({"stage": "copy", "fraction": 0.5}), &[]),
        // Required nullable field absent.
        frame("progress", json!({"stage": "copy"}), &scoped()),
        frame(
            "progress",
            json!({"stage": "copy", "fraction": 1.5}),
            &scoped(),
        ),
        frame("configured", json!({"accepted": false}), &[reply()]),
        frame(
            "candidate",
            json!({"description_handle": "d", "files": []}),
            &scoped(),
        ),
        frame(
            "loaded",
            json!({"grant_id": "grt_bad", "resolution_sha256": "b".repeat(64)}),
            &[reply(), ("job_id", JOB.into()), ("attempt_id", ATT.into())],
        ),
        frame("hello", hello_payload(), &[]).replace(SES, "ses_XYZ"),
    ];
    for case in cases {
        assert_eq!(
            decode_inbound(&case).unwrap_err(),
            ProtocolViolation::InvalidRecord,
            "{case}"
        );
    }
    // A null fraction is legal unknown progress.
    let unknown = frame(
        "progress",
        json!({"stage": "copy", "fraction": null}),
        &scoped(),
    );
    assert_eq!(
        decode_inbound(&unknown).unwrap().report,
        WorkerReport::Progress {
            stage: "copy".into(),
            fraction: None
        }
    );
}

#[test]
fn control_buffering_holds_at_most_32_frames_and_applies_backpressure() {
    let pong = frame(
        "pong",
        json!({}),
        &[("in_reply_to", random_id("cmd_").into())],
    );
    let line = format!("{pong}\n");
    let forty = line.repeat(40);
    let mut decoder = FrameDecoder::default();
    let used = decoder.push(forty.as_bytes()).unwrap();
    assert_eq!(used, line.len() * BUFFERED_FRAMES_MAX);
    assert_eq!(decoder.buffered(), BUFFERED_FRAMES_MAX);
    // Full: nothing more is consumed until the supervisor drains.
    assert_eq!(decoder.push(&forty.as_bytes()[used..]).unwrap(), 0);
    let mut drained = 0;
    while decoder.next_frame().is_some() {
        drained += 1;
    }
    assert_eq!(drained, 32);
    assert_eq!(
        decoder.push(&forty.as_bytes()[used..]).unwrap(),
        line.len() * 8
    );
}

#[test]
fn engine_commands_are_bounded_lf_terminated_and_carry_supervisor_identity() {
    let assignment = Assignment {
        job_id: JOB.into(),
        attempt_id: ATT.into(),
    };
    let command = random_id("cmd_");
    let bytes = encode_command(
        SES,
        &command,
        &assignment,
        &EngineCommand::Load {
            resolution_handle: "res:1".into(),
            grant_id: GRT.into(),
        },
    )
    .unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["kind"], "load");
    assert_eq!(value["session_id"], SES);
    assert_eq!(value["command_id"], command.as_str());
    assert_eq!(value["job_id"], JOB);
    assert_eq!(value["attempt_id"], ATT);
    assert_eq!(value["payload"]["grant_id"], GRT);
    // Session-scoped commands carry no assignment.
    let ping = encode_command(SES, &command, &assignment, &EngineCommand::Ping).unwrap();
    let value: Value = serde_json::from_slice(&ping).unwrap();
    assert!(value.get("job_id").is_none());
    // Never send an oversized frame: schema-legal fields can still exceed the
    // frame bound together (64 x 1,024-byte handles), so encoding refuses.
    let huge = EngineCommand::Execute {
        grant_id: GRT.into(),
        inputs: vec![
            ExecuteInput {
                role: "mesh".into(),
                handle: "h".repeat(1024),
                sha256: "c".repeat(64),
                byte_length: 1,
            };
            64
        ],
        output_staging_handle: "o".repeat(1024),
        effective_parameters_handle: "p".repeat(1024),
    };
    assert_eq!(
        encode_command(SES, &command, &assignment, &huge).unwrap_err(),
        ProtocolViolation::OversizedFrame
    );
    let over = EngineCommand::Configure {
        resolution_handle: "r".repeat(FRAME_BYTES_MAX),
        features: vec![],
    };
    assert_eq!(
        encode_command(SES, &command, &assignment, &over).unwrap_err(),
        ProtocolViolation::OversizedFrame
    );
}

#[test]
fn diagnostic_capture_is_capped_at_one_mib_and_exposes_only_safe_categories() {
    let raw = b"C:\\Users\\secret\\input.obj token=abc\n";
    let mut capture = DiagnosticCapture::default();
    capture.capture(raw);
    capture.capture(&vec![b'x'; DIAGNOSTIC_BYTES_MAX]);
    capture.note(DiagnosticCategory::ProtocolViolation);
    let summary = capture.summary();
    assert_eq!(summary.bytes_retained, DIAGNOSTIC_BYTES_MAX);
    assert_eq!(
        summary.bytes_observed,
        (DIAGNOSTIC_BYTES_MAX + raw.len()) as u64
    );
    assert!(summary.truncated);
    assert_eq!(
        summary.categories,
        vec![
            ("worker_protocol_violation", 1),
            ("diagnostic_output_truncated", 1)
        ]
    );
    // The summary has no field that could carry worker text or paths.
    let rendered = format!("{summary:?}");
    assert!(!rendered.contains("secret") && !rendered.contains("token"));
}
