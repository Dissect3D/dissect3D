//! WE-P03 cleanup-witness transitions (ENG-030/031/035, WE-002/003/005).
//!
//! This is the only writer of attempt/job `cleanup_status`, `cleanup_reason`
//! and `resource_reservations.released` after dispatch. Supervision (WE-P04),
//! shutdown and restart recovery (WE-P07) report a typed outcome for one
//! attempt; the Store checks identity and legality and commits the cleanup
//! facts, any reservation release, one revision and its event together.
use super::execution::{
    DispatchRecord, ExecutionCommand, LiveAttempts, is_safe_code, record_event,
};
use super::launch_identity::{CleanupBasis, verify_release};
use super::*;
use dissect3d_api::JobId;

/// The exact attempt a report concerns. A stale or mismatched identity rejects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttemptRef {
    pub(crate) job_id: JobId,
    pub(crate) attempt_id: String,
    pub(crate) session_id: String,
    pub(crate) grant_id: String,
}
impl From<&DispatchRecord> for AttemptRef {
    fn from(record: &DispatchRecord) -> Self {
        Self {
            job_id: record.job_id.clone(),
            attempt_id: record.attempt_id.clone(),
            session_id: record.session_id.clone(),
            grant_id: record.grant_id.clone(),
        }
    }
}

/// Established termination of one attempt's whole worker tree.
///
/// Only a native `CleanupConfirmed` witness mints it in production; nothing
/// public, no worker message and no enum tag can. Acknowledgement, EOF, a pong
/// or one PID disappearing is not cleanup. It keeps the witness's native
/// identity; release requires it to equal the identity recorded at launch
/// (`launch_identity`). WE-P07 adds restart-recovery evidence.
#[derive(Debug)]
pub(crate) struct CleanupEvidence {
    identity: dissect3d_platform::WorkerIdentity,
}
impl CleanupEvidence {
    pub(crate) fn from_witness(witness: dissect3d_platform::CleanupConfirmed) -> Self {
        Self {
            identity: witness.identity().clone(),
        }
    }
    /// The native worker identity whose whole tree the witness confirmed.
    pub(crate) fn identity(&self) -> &dissect3d_platform::WorkerIdentity {
        &self.identity
    }
    /// Test-only evidence for a given identity (see `test_identity`).
    #[cfg(test)]
    pub(crate) fn for_test(identity: dissect3d_platform::WorkerIdentity) -> Self {
        Self { identity }
    }
}

/// A well-formed test identity bound to `session_id`, as a launch would
/// report it. `marker` distinguishes otherwise identical identities.
#[cfg(test)]
pub(crate) fn test_identity(session_id: &str, marker: &str) -> dissect3d_platform::WorkerIdentity {
    dissect3d_platform::WorkerIdentity {
        process: dissect3d_platform::ProcessIdentity {
            pid: 4242,
            start_marker: format!("test-start-{marker}"),
        },
        guardian: None,
        session_nonce: super::launch_identity::session_nonce(session_id).unwrap_or([0; 16]),
    }
}

/// Typed cleanup outcome for one attempt.
#[derive(Debug)]
pub(crate) enum CleanupOutcome {
    /// Termination established: release the attempt's reservations.
    Confirmed(CleanupEvidence),
    /// Termination uncertain or escaped: keep every reservation held and
    /// record a safe reason code (at most 128 bytes of `[a-z0-9_.]`).
    Fault { reason: String },
}
/// The safe reason code for a platform cleanup fault (one owner).
pub(crate) fn fault_code(fault: dissect3d_platform::CleanupFault) -> &'static str {
    use dissect3d_platform::CleanupFault::*;
    match fault {
        Deadline => "cleanup_deadline",
        OwnershipLost => "cleanup_ownership_lost",
        NativeFailure => "cleanup_native_failure",
    }
}
impl From<dissect3d_platform::CleanupFault> for CleanupOutcome {
    fn from(fault: dissect3d_platform::CleanupFault) -> Self {
        Self::Fault {
            reason: fault_code(fault).into(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CleanupReport {
    pub(crate) attempt: AttemptRef,
    pub(crate) outcome: CleanupOutcome,
}
impl AttemptRef {
    /// Identifier shapes only; the Store checks the identity itself.
    pub(super) fn validate(&self) -> Result<(), CoreError> {
        let id = |value: &str, prefix: &str| {
            value.len() == 36
                && value.starts_with(prefix)
                && value[4..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !id(&self.attempt_id, "att_")
            || !id(&self.session_id, "ses_")
            || !id(&self.grant_id, "grt_")
        {
            return Err(CoreError::Conflict);
        }
        Ok(())
    }
}
impl CleanupReport {
    fn validate(&self) -> Result<(), CoreError> {
        self.attempt.validate()?;
        match &self.outcome {
            CleanupOutcome::Confirmed(_) => Ok(()),
            CleanupOutcome::Fault { reason } if is_safe_code(reason) => Ok(()),
            CleanupOutcome::Fault { .. } => Err(CoreError::Conflict),
        }
    }
}

/// What the transition committed; `changed` is false for an idempotent repeat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CleanupReceipt {
    pub(crate) snapshot_revision: i64,
    pub(crate) changed: bool,
}

impl Store {
    /// Record one attempt's cleanup outcome. Rejects before any write.
    pub(crate) fn record_attempt_cleanup(
        &self,
        report: CleanupReport,
    ) -> Result<CleanupReceipt, CoreError> {
        report.validate()?;
        self.request(|reply| Command::Execution(ExecutionCommand::Cleanup(report, reply)))
    }
}

const TERMINAL: [&str; 5] = ["succeeded", "partial", "failed", "canceled", "interrupted"];

/// The attempt's current facts, after its exact identity matched.
pub(super) struct AttemptFacts {
    pub(super) state: String,
    pub(super) revision: i64,
    pub(super) cleanup: String,
    pub(super) reason: Option<String>,
    pub(super) outcome: Option<String>,
}

/// Read one attempt; a stale or mismatched identity rejects.
pub(super) fn read_attempt(
    tx: &Transaction<'_>,
    attempt: &AttemptRef,
) -> Result<AttemptFacts, CoreError> {
    type Row = (String, String, AttemptFacts);
    let row: Option<Row> = sql(tx
        .query_row(
            "SELECT a.session_id,a.grant_id,a.cleanup_status,e.state,e.snapshot_revision,
                    e.cleanup_reason,e.outcome_code
             FROM job_attempts a JOIN job_execution e USING(job_id)
             WHERE a.attempt_id=?1 AND a.job_id=?2",
            rusqlite::params![attempt.attempt_id, attempt.job_id.as_str()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    AttemptFacts {
                        cleanup: r.get(2)?,
                        state: r.get(3)?,
                        revision: r.get(4)?,
                        reason: r.get(5)?,
                        outcome: r.get(6)?,
                    },
                ))
            },
        )
        .optional())?;
    // One attempt per job: a row here is the job's current attempt.
    let (session, grant, facts) = row.ok_or(CoreError::Conflict)?;
    if session != attempt.session_id || grant != attempt.grant_id {
        return Err(CoreError::Conflict);
    }
    Ok(facts)
}

/// The only writer of cleanup facts: reservations, attempt and job cleanup
/// columns. Callers add their state change, revision and event in the same
/// transaction. A release whose basis disagrees with the recorded launch
/// identity rejects before the first write.
pub(super) fn write_cleanup_facts(
    tx: &Transaction<'_>,
    attempt: &AttemptRef,
    basis: CleanupBasis<'_>,
) -> Result<(), CoreError> {
    verify_release(tx, attempt, basis)?;
    let (next, reason) = (basis.status(), basis.reason());
    if next == "confirmed" {
        sql(tx.execute(
            "UPDATE resource_reservations SET released=1 WHERE attempt_id=?1 AND released=0",
            [attempt.attempt_id.as_str()],
        ))?;
    }
    sql(tx.execute(
        "UPDATE job_attempts SET cleanup_status=?2 WHERE attempt_id=?1",
        rusqlite::params![attempt.attempt_id, next],
    ))?;
    sql(tx.execute(
        "UPDATE job_execution SET cleanup_status=?2,cleanup_reason=?3 WHERE job_id=?1",
        rusqlite::params![attempt.job_id.as_str(), next, reason],
    ))?;
    Ok(())
}

/// Cleanup transition for `cancel_requested` or terminal work, uncommitted.
/// `changed: false` is an idempotent repeat that wrote nothing.
pub(super) fn cleanup_transition(
    tx: &Transaction<'_>,
    attempt: &AttemptRef,
    facts: &AttemptFacts,
    basis: CleanupBasis<'_>,
) -> Result<CleanupReceipt, CoreError> {
    // Running work is finalized with its outcome (`store::finalize`), never here.
    if facts.state != "cancel_requested" && !TERMINAL.contains(&facts.state.as_str()) {
        return Err(CoreError::Conflict);
    }
    // Even a repeat must agree with the launch record.
    verify_release(tx, attempt, basis)?;
    let (next, reason) = (basis.status(), basis.reason());
    let unchanged = CleanupReceipt {
        snapshot_revision: facts.revision,
        changed: false,
    };
    match (facts.cleanup.as_str(), next) {
        ("confirmed", "confirmed") => return Ok(unchanged),
        // Established termination is final.
        ("confirmed", _) => return Err(CoreError::Conflict),
        ("fault", "fault") if facts.reason.as_deref() == reason => return Ok(unchanged),
        ("pending" | "fault", _) => {}
        _ => return Err(CoreError::InvalidStore),
    }
    write_cleanup_facts(tx, attempt, basis)?;
    // Only an active cancellation completes here, and only with confirmed
    // termination. Terminal outcomes never change.
    let completes_cancel = next == "confirmed" && facts.state == "cancel_requested";
    sql(tx.execute(
        "UPDATE job_execution
         SET state=CASE WHEN ?2 THEN 'canceled' ELSE state END,
             phase=CASE WHEN ?2 THEN 'canceled' ELSE phase END,
             snapshot_revision=snapshot_revision+1,updated_at_ms=?3
         WHERE job_id=?1",
        rusqlite::params![attempt.job_id.as_str(), completes_cancel, now_ms()?],
    ))?;
    record_event(tx, attempt.job_id.as_str())?;
    Ok(CleanupReceipt {
        snapshot_revision: facts.revision + 1,
        changed: true,
    })
}

pub(super) fn record_cleanup(
    db: &mut Connection,
    live: &mut LiveAttempts,
    report: CleanupReport,
) -> Result<CleanupReceipt, CoreError> {
    report.validate()?;
    let attempt = &report.attempt;
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
    let facts = read_attempt(&tx, attempt)?;
    let basis = match &report.outcome {
        CleanupOutcome::Confirmed(evidence) => CleanupBasis::Confirmed(evidence),
        CleanupOutcome::Fault { reason } => CleanupBasis::Fault(reason),
    };
    let receipt = cleanup_transition(&tx, attempt, &facts, basis)?;
    if receipt.changed {
        sql(tx.commit())?;
        if basis.status() == "confirmed" {
            // The attempt is over and no publication follows a terminal job.
            live.forget(&attempt.attempt_id);
        }
    }
    Ok(receipt)
}
