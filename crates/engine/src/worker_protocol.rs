//! WE-P04 private worker protocol (WC-001, WE-004): pure codec, no I/O.
//!
//! `frame` splits finite LF-delimited UTF-8 frames, `message` decodes closed
//! worker reports and encodes engine commands, and `diagnostics` bounds the
//! separate output capture. Sequencing and authority live in
//! `execution::legality`; process ownership and timers in
//! `execution::supervisor`. Worker reports are untrusted throughout.
mod diagnostics;
mod frame;
mod message;

pub(crate) use diagnostics::{DiagnosticCapture, DiagnosticCategory, DiagnosticSummary};
pub(crate) use frame::FrameDecoder;
pub(crate) use message::{
    Assignment, CancelReason, CandidateReport, EngineCommand, ExecuteInput, InboundFrame,
    WorkerReport, decode_inbound, encode_command, random_id,
};

pub(crate) const PROTOCOL_VERSION: &str = "d3d-worker/1";
/// Control frame bound, including its LF.
pub(crate) const FRAME_BYTES_MAX: usize = 65_536;
/// Decoded control frames waiting for the supervisor.
pub(crate) const BUFFERED_FRAMES_MAX: usize = 32;
/// Diagnostic output retained per attempt.
pub(crate) const DIAGNOSTIC_BYTES_MAX: usize = 1_048_576;

/// Why a frame or sequence was rejected. Carries no worker-supplied text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolViolation {
    OversizedFrame,
    IncompleteFrame,
    InvalidUtf8,
    /// Not one strict JSON value: syntax, duplicate key, non-finite number.
    MalformedFrame,
    /// Well-formed JSON that is not the kind's closed record.
    InvalidRecord,
    UnknownKind,
    IncompatibleVersion,
    IncompatibleHello,
    WrongSession,
    WrongAttempt,
    StaleAcknowledgement,
    IllegalSequence,
    RepeatedExecute,
    WrongGrant,
    WrongResolution,
}

#[cfg(test)]
#[path = "worker_protocol_tests.rs"]
pub(crate) mod tests;
