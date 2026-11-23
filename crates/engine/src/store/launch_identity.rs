//! Launch-identity persistence and the release-time identity check (WE-P04;
//! WC-003, ENG-031/035, WE-004/005).
//!
//! Right after a confirmed contained spawn, the supervisor records the
//! worker's native identity (process and guardian creation evidence plus the
//! session nonce) in `job_attempts.native_identity_json`, before any command
//! reaches the worker. Releasing reservations on a native cleanup witness then
//! requires the witness's identity to equal that record. A missing or
//! mismatched identity rejects before any write, and holds stay. Restart keeps
//! the record (it is durable), so recovery (WE-P07) can identify survivors.
use super::cleanup::{AttemptRef, CleanupEvidence, read_attempt};
use super::execution::{ExecutionCommand, LiveAttempts};
use super::*;
use dissect3d_platform::{ProcessIdentity, WorkerIdentity};

/// The 16 bytes of `ses_<32 lowercase hex>`; the platform binds the native
/// identity and its witness to this nonce.
pub(crate) fn session_nonce(session_id: &str) -> Option<[u8; 16]> {
    let hex = session_id.strip_prefix("ses_")?.as_bytes();
    if hex.len() != 32 {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut nonce = [0u8; 16];
    let (pairs, _) = hex.as_chunks::<2>();
    for (byte, [high, low]) in nonce.iter_mut().zip(pairs) {
        *byte = (digit(*high)? << 4) | digit(*low)?;
    }
    Some(nonce)
}

/// Platform start markers are short ASCII (`linux-start-<ticks>`,
/// `macos-start-<s>-<us>`, a Windows creation time); anything else is refused.
const START_MARKER_BYTES_MAX: usize = 128;

fn process_json(process: &ProcessIdentity) -> Option<serde_json::Value> {
    let marker = &process.start_marker;
    if process.pid == 0
        || marker.is_empty()
        || marker.len() > START_MARKER_BYTES_MAX
        || !marker.bytes().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    Some(serde_json::json!({"pid": process.pid, "start_marker": marker}))
}

/// The one canonical encoding, used both to record and to compare. `None` for
/// an identity that cannot be a real launch record.
pub(super) fn encode(identity: &WorkerIdentity) -> Option<String> {
    let guardian = match &identity.guardian {
        Some(guardian) => process_json(guardian)?,
        None => serde_json::Value::Null,
    };
    let nonce: String = identity
        .session_nonce
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Some(
        serde_json::json!({
            "version": 1,
            "process": process_json(&identity.process)?,
            "guardian": guardian,
            "session_nonce": nonce,
        })
        .to_string(),
    )
}

/// The recorded identity back, for restart recovery. Only an exact canonical
/// encoding decodes: anything `encode` would not have written is `None`.
pub(super) fn decode(json: &str) -> Option<WorkerIdentity> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let process = |v: &serde_json::Value| {
        Some(ProcessIdentity {
            pid: u32::try_from(v.get("pid")?.as_u64()?).ok()?,
            start_marker: v.get("start_marker")?.as_str()?.to_owned(),
        })
    };
    let guardian = match value.get("guardian")? {
        serde_json::Value::Null => None,
        other => Some(process(other)?),
    };
    let hex = value.get("session_nonce")?.as_str()?;
    let nonce = session_nonce(&format!("ses_{hex}"))?;
    let identity = WorkerIdentity {
        process: process(value.get("process")?)?,
        guardian,
        session_nonce: nonce,
    };
    (encode(&identity)? == json).then_some(identity)
}

/// One attempt's native worker identity, reported once after its spawn.
#[derive(Clone, Debug)]
pub(crate) struct LaunchRecord {
    pub(crate) attempt: AttemptRef,
    pub(crate) identity: WorkerIdentity,
}
impl LaunchRecord {
    /// Shapes and session binding; the Store checks the attempt itself.
    fn validate(&self) -> Result<String, CoreError> {
        self.attempt.validate()?;
        if session_nonce(&self.attempt.session_id) != Some(self.identity.session_nonce) {
            return Err(CoreError::Conflict);
        }
        encode(&self.identity).ok_or(CoreError::Conflict)
    }
}

impl Store {
    /// Durably record a launched worker's identity. Idempotent for the same
    /// identity; a different identity, a stale or foreign attempt, or an
    /// attempt this instance did not dispatch rejects without writing.
    pub(crate) fn record_launch_identity(&self, record: LaunchRecord) -> Result<(), CoreError> {
        record.validate()?;
        self.request(|reply| Command::Execution(ExecutionCommand::Launch(record, reply)))
    }
}

fn stored(tx: &Transaction<'_>, attempt: &AttemptRef) -> Result<Option<String>, CoreError> {
    sql(tx.query_row(
        "SELECT native_identity_json FROM job_attempts WHERE attempt_id=?1",
        [attempt.attempt_id.as_str()],
        |r| r.get(0),
    ))
}

pub(super) fn record_launch(
    db: &mut Connection,
    live: &LiveAttempts,
    record: LaunchRecord,
) -> Result<(), CoreError> {
    let encoded = record.validate()?;
    let attempt = &record.attempt;
    // Only an attempt this running instance dispatched has a live worker; an
    // attempt interrupted by restart can never gain an identity afterwards.
    if !live.contains(&attempt.attempt_id) {
        return Err(CoreError::Conflict);
    }
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
    let facts = read_attempt(&tx, attempt)?;
    // A user cancellation may commit while the worker is launching.
    if !matches!(facts.state.as_str(), "running" | "cancel_requested") {
        return Err(CoreError::Conflict);
    }
    let cleanup: String = sql(tx.query_row(
        "SELECT cleanup_status FROM job_attempts WHERE attempt_id=?1",
        [attempt.attempt_id.as_str()],
        |r| r.get(0),
    ))?;
    if cleanup != "pending" {
        return Err(CoreError::Conflict);
    }
    match stored(&tx, attempt)? {
        Some(existing) if existing == encoded => Ok(()),
        Some(_) => Err(CoreError::Conflict),
        None => {
            sql(tx.execute(
                "UPDATE job_attempts SET native_identity_json=?2
                 WHERE attempt_id=?1 AND native_identity_json IS NULL",
                rusqlite::params![attempt.attempt_id, encoded],
            ))?;
            // Private ownership metadata: not part of the public snapshot, so
            // no revision or event.
            sql(tx.commit())
        }
    }
}

/// What a cleanup-facts write rests on. Only the confirmed and never-launched
/// bases release reservations, and each must agree with the launch record.
#[derive(Clone, Copy, Debug)]
pub(super) enum CleanupBasis<'a> {
    /// A native witness: its identity must equal the recorded launch identity.
    Confirmed(&'a CleanupEvidence),
    /// No process was created: no launch identity may be recorded.
    NeverLaunched,
    /// Termination uncertain: nothing is released (safe reason code).
    Fault(&'a str),
}
impl CleanupBasis<'_> {
    pub(super) fn status(&self) -> &'static str {
        match self {
            Self::Confirmed(_) | Self::NeverLaunched => "confirmed",
            Self::Fault(_) => "fault",
        }
    }
    pub(super) fn reason(&self) -> Option<&str> {
        match self {
            Self::Fault(reason) => Some(reason),
            Self::Confirmed(evidence) => evidence.reason_code(),
            Self::NeverLaunched => None,
        }
    }
}

/// Reject a release whose basis disagrees with the launch record. Reads only;
/// the caller's transaction has written nothing yet.
pub(super) fn verify_release(
    tx: &Transaction<'_>,
    attempt: &AttemptRef,
    basis: CleanupBasis<'_>,
) -> Result<(), CoreError> {
    let agrees = match basis {
        CleanupBasis::Fault(_) => true,
        CleanupBasis::NeverLaunched => stored(tx, attempt)?.is_none(),
        CleanupBasis::Confirmed(evidence) => match stored(tx, attempt)? {
            Some(recorded) => encode(evidence.identity()).is_some_and(|e| e == recorded),
            None => false,
        },
    };
    if agrees {
        Ok(())
    } else {
        Err(CoreError::Conflict)
    }
}
