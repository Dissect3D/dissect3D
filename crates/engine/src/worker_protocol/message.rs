//! Closed private frame variants from `worker.schema.json` (`d3d-worker/1`).
//!
//! Worker reports are untrusted. Decoding applies the shared strict JSON guard
//! (duplicate keys, non-finite numbers, nesting) and then a closed per-kind
//! record with exact field names and bounds. A kind the engine sends, or one the
//! schema does not define, is an unknown kind when it arrives from a worker.
use super::{FRAME_BYTES_MAX, PROTOCOL_VERSION, ProtocolViolation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `<prefix>` + 32 lowercase hex digits, the schema's identifier shape.
fn is_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 32
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max
}
#[expect(
    clippy::expect_used,
    reason = "Deliberate pre-existing fail-closed abort: a failed OS random source must not yield \
              a predictable message or command identity; returning an error instead would turn it \
              into a supervised protocol failure, a behavior change."
)]
pub(crate) fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    // A failed OS source must not produce a predictable correlation identity.
    getrandom::fill(&mut bytes).expect("operating system random source");
    let mut id = String::with_capacity(prefix.len() + 32);
    id.push_str(prefix);
    for b in bytes {
        id.push_str(&format!("{b:02x}"));
    }
    id
}

/// Job/attempt scope carried by assignment frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Assignment {
    pub(crate) job_id: String,
    pub(crate) attempt_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hello {
    pub(crate) worker_build_sha256: String,
    pub(crate) adapter_id: String,
    pub(crate) adapter_revision: String,
    pub(crate) features: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateFile {
    pub(crate) relative_name: String,
    pub(crate) byte_length: u64,
    pub(crate) sha256: String,
}
/// Untrusted candidate description. It names files; it is never a result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CandidateReport {
    pub(crate) description_handle: String,
    pub(crate) files: Vec<CandidateFile>,
}

/// One decoded worker -> engine report.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum WorkerReport {
    Hello(Hello),
    Configured,
    Loaded {
        grant_id: String,
        resolution_sha256: String,
    },
    LoadFailed,
    Progress {
        stage: String,
        fraction: Option<f64>,
    },
    Candidate(CandidateReport),
    Rejected,
    ExecutionFailed,
    CancelAck,
    Released {
        grant_id: String,
    },
    ShutdownAck,
    Pong,
}

/// A decoded inbound frame with its correlation facts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InboundFrame {
    pub(crate) session_id: String,
    pub(crate) message_id: String,
    pub(crate) in_reply_to: Option<String>,
    pub(crate) assignment: Option<Assignment>,
    pub(crate) report: WorkerReport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<P> {
    protocol_version: String,
    #[allow(dead_code, reason = "dispatched before this record is decoded")]
    kind: String,
    session_id: String,
    message_id: String,
    payload: P,
    #[serde(default, deserialize_with = "present")]
    in_reply_to: Option<String>,
    #[serde(default, deserialize_with = "present")]
    job_id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    attempt_id: Option<String>,
}
/// Optional correlation fields may be absent, but never `null`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloPayload {
    worker_build_sha256: String,
    adapter_id: String,
    adapter_revision: String,
    features: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedPayload {
    accepted: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedPayload {
    observed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadedPayload {
    grant_id: String,
    resolution_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodePayload {
    code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressPayload {
    stage: String,
    // Required but nullable: `Option` alone would also accept absence.
    #[serde(deserialize_with = "required_nullable")]
    fraction: Option<f64>,
}
fn required_nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
    Option::deserialize(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidatePayload {
    description_handle: String,
    files: Vec<CandidateFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantPayload {
    grant_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyPayload {}

/// Which correlation fields a kind must carry (`in_reply_to`, assignment).
#[derive(Clone, Copy)]
struct Shape {
    reply: bool,
    assignment: bool,
}
const fn shape(reply: bool, assignment: bool) -> Shape {
    Shape { reply, assignment }
}

/// Decode one complete frame (without its LF). Rejects before trusting any field.
pub(crate) fn decode_inbound(frame: &str) -> Result<InboundFrame, ProtocolViolation> {
    let value: Value = dissect3d_api::decode_json(frame.as_bytes()).map_err(|e| match e {
        dissect3d_api::DecodeError::Json(_) => ProtocolViolation::MalformedFrame,
        dissect3d_api::DecodeError::Record(_) => ProtocolViolation::InvalidRecord,
    })?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(ProtocolViolation::InvalidRecord)?
        .to_owned();
    let decoded = match kind.as_str() {
        "hello" => decode_as::<HelloPayload>(value, shape(false, false)).and_then(|(c, p)| {
            let features_ok = p.features.len() <= 32
                && p.features.iter().all(|f| bounded(f, 128))
                && p.features
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == p.features.len();
            if !is_sha256(&p.worker_build_sha256)
                || !bounded(&p.adapter_id, 128)
                || !bounded(&p.adapter_revision, 128)
                || !features_ok
            {
                return Err(ProtocolViolation::InvalidRecord);
            }
            Ok((
                c,
                WorkerReport::Hello(Hello {
                    worker_build_sha256: p.worker_build_sha256,
                    adapter_id: p.adapter_id,
                    adapter_revision: p.adapter_revision,
                    features: p.features,
                }),
            ))
        }),
        "configured" => {
            decode_as::<AcceptedPayload>(value, shape(true, false)).and_then(|(c, p)| {
                p.accepted
                    .then_some((c, WorkerReport::Configured))
                    .ok_or(ProtocolViolation::InvalidRecord)
            })
        }
        "loaded" => decode_as::<LoadedPayload>(value, shape(true, true)).and_then(|(c, p)| {
            (is_id(&p.grant_id, "grt_") && is_sha256(&p.resolution_sha256))
                .then_some((
                    c,
                    WorkerReport::Loaded {
                        grant_id: p.grant_id,
                        resolution_sha256: p.resolution_sha256,
                    },
                ))
                .ok_or(ProtocolViolation::InvalidRecord)
        }),
        "load_failed" => code(value, shape(true, true), WorkerReport::LoadFailed),
        "progress" => decode_as::<ProgressPayload>(value, shape(false, true)).and_then(|(c, p)| {
            let fraction_ok = p
                .fraction
                .is_none_or(|f| f.is_finite() && (0.0..=1.0).contains(&f));
            (bounded(&p.stage, 128) && fraction_ok)
                .then_some((
                    c,
                    WorkerReport::Progress {
                        stage: p.stage,
                        fraction: p.fraction,
                    },
                ))
                .ok_or(ProtocolViolation::InvalidRecord)
        }),
        "candidate" => {
            decode_as::<CandidatePayload>(value, shape(false, true)).and_then(|(c, p)| {
                let files_ok = (1..=16).contains(&p.files.len())
                    && p.files.iter().all(|f| {
                        bounded(&f.relative_name, 256) && f.byte_length >= 1 && is_sha256(&f.sha256)
                    });
                (bounded(&p.description_handle, 1024) && files_ok)
                    .then_some((
                        c,
                        WorkerReport::Candidate(CandidateReport {
                            description_handle: p.description_handle,
                            files: p.files,
                        }),
                    ))
                    .ok_or(ProtocolViolation::InvalidRecord)
            })
        }
        "rejected" => code(value, shape(false, true), WorkerReport::Rejected),
        "execution_failed" => code(value, shape(false, true), WorkerReport::ExecutionFailed),
        "cancel_ack" => {
            decode_as::<ObservedPayload>(value, shape(true, true)).and_then(|(c, p)| {
                p.observed
                    .then_some((c, WorkerReport::CancelAck))
                    .ok_or(ProtocolViolation::InvalidRecord)
            })
        }
        "released" => decode_as::<GrantPayload>(value, shape(false, true)).and_then(|(c, p)| {
            is_id(&p.grant_id, "grt_")
                .then_some((
                    c,
                    WorkerReport::Released {
                        grant_id: p.grant_id,
                    },
                ))
                .ok_or(ProtocolViolation::InvalidRecord)
        }),
        "shutdown_ack" => {
            decode_as::<ObservedPayload>(value, shape(true, false)).and_then(|(c, p)| {
                p.observed
                    .then_some((c, WorkerReport::ShutdownAck))
                    .ok_or(ProtocolViolation::InvalidRecord)
            })
        }
        "pong" => decode_as::<EmptyPayload>(value, shape(true, false))
            .map(|(c, _)| (c, WorkerReport::Pong)),
        // Engine-only kinds (`configure`, `load`, `execute`, `cancel`,
        // `shutdown`, `ping`) and anything else are unknown from a worker.
        _ => Err(ProtocolViolation::UnknownKind),
    }?;
    let (correlation, report) = decoded;
    Ok(InboundFrame {
        session_id: correlation.session_id,
        message_id: correlation.message_id,
        in_reply_to: correlation.in_reply_to,
        assignment: correlation.assignment,
        report,
    })
}

struct Correlation {
    session_id: String,
    message_id: String,
    in_reply_to: Option<String>,
    assignment: Option<Assignment>,
}

fn decode_as<P: serde::de::DeserializeOwned>(
    value: Value,
    shape: Shape,
) -> Result<(Correlation, P), ProtocolViolation> {
    let envelope: Envelope<P> =
        serde_json::from_value(value).map_err(|_| ProtocolViolation::InvalidRecord)?;
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolViolation::IncompatibleVersion);
    }
    let reply_ok = match (&envelope.in_reply_to, shape.reply) {
        (Some(id), true) => is_id(id, "cmd_"),
        (None, false) => true,
        _ => false,
    };
    let assignment = match (envelope.job_id, envelope.attempt_id, shape.assignment) {
        (Some(job_id), Some(attempt_id), true)
            if is_id(&job_id, "job_") && is_id(&attempt_id, "att_") =>
        {
            Some(Assignment { job_id, attempt_id })
        }
        (None, None, false) => None,
        _ => return Err(ProtocolViolation::InvalidRecord),
    };
    if !reply_ok || !is_id(&envelope.session_id, "ses_") || !is_id(&envelope.message_id, "msg_") {
        return Err(ProtocolViolation::InvalidRecord);
    }
    Ok((
        Correlation {
            session_id: envelope.session_id,
            message_id: envelope.message_id,
            in_reply_to: envelope.in_reply_to,
            assignment,
        },
        envelope.payload,
    ))
}

/// Typed failure reports keep only the fact; the worker's `code` text is
/// untrusted upstream content and never leaves the decoder.
fn code(
    value: Value,
    shape: Shape,
    report: WorkerReport,
) -> Result<(Correlation, WorkerReport), ProtocolViolation> {
    let (c, p) = decode_as::<CodePayload>(value, shape)?;
    bounded(&p.code, 128)
        .then_some((c, report))
        .ok_or(ProtocolViolation::InvalidRecord)
}

/// One scoped input handle for `execute`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ExecuteInput {
    pub(crate) role: String,
    pub(crate) handle: String,
    pub(crate) sha256: String,
    pub(crate) byte_length: u64,
}

/// Engine -> worker commands. Identities come from the supervisor only.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EngineCommand {
    Configure {
        resolution_handle: String,
        features: Vec<String>,
    },
    Load {
        resolution_handle: String,
        grant_id: String,
    },
    Execute {
        grant_id: String,
        inputs: Vec<ExecuteInput>,
        output_staging_handle: String,
        effective_parameters_handle: String,
    },
    Cancel {
        reason: CancelReason,
    },
    Shutdown {
        reason: &'static str,
    },
    Ping,
}

/// The schema's closed `cancel.reason` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CancelReason {
    UserCancel,
    Deadline,
    EngineShutdown,
}
impl CancelReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::UserCancel => "user_cancel",
            Self::Deadline => "deadline",
            Self::EngineShutdown => "engine_shutdown",
        }
    }
}

/// Encode one command as an LF-terminated frame of at most 65,536 bytes.
pub(crate) fn encode_command(
    session_id: &str,
    command_id: &str,
    assignment: &Assignment,
    command: &EngineCommand,
) -> Result<Vec<u8>, ProtocolViolation> {
    use serde_json::json;
    let (kind, payload, scoped) = match command {
        EngineCommand::Configure {
            resolution_handle,
            features,
        } => (
            "configure",
            json!({
                "resolution_handle": resolution_handle,
                "features": features,
                "limits": {
                    "frame_bytes": FRAME_BYTES_MAX,
                    "buffered_frames": super::BUFFERED_FRAMES_MAX,
                },
            }),
            false,
        ),
        EngineCommand::Load {
            resolution_handle,
            grant_id,
        } => (
            "load",
            json!({"resolution_handle": resolution_handle, "grant_id": grant_id}),
            true,
        ),
        EngineCommand::Execute {
            grant_id,
            inputs,
            output_staging_handle,
            effective_parameters_handle,
        } => (
            "execute",
            json!({
                "grant_id": grant_id,
                "inputs": inputs,
                "output_staging_handle": output_staging_handle,
                "effective_parameters_handle": effective_parameters_handle,
            }),
            true,
        ),
        EngineCommand::Cancel { reason } => ("cancel", json!({"reason": reason.as_str()}), true),
        EngineCommand::Shutdown { reason } => ("shutdown", json!({"reason": reason}), false),
        EngineCommand::Ping => ("ping", json!({}), false),
    };
    let mut frame = serde_json::Map::new();
    frame.insert("protocol_version".into(), PROTOCOL_VERSION.into());
    frame.insert("kind".into(), kind.into());
    frame.insert("session_id".into(), session_id.into());
    frame.insert("message_id".into(), random_id("msg_").into());
    frame.insert("payload".into(), payload);
    frame.insert("command_id".into(), command_id.into());
    if scoped {
        frame.insert("job_id".into(), assignment.job_id.clone().into());
        frame.insert("attempt_id".into(), assignment.attempt_id.clone().into());
    }
    let mut bytes =
        serde_json::to_vec(&Value::Object(frame)).map_err(|_| ProtocolViolation::InvalidRecord)?;
    bytes.push(b'\n');
    if bytes.len() > FRAME_BYTES_MAX {
        return Err(ProtocolViolation::OversizedFrame);
    }
    Ok(bytes)
}
