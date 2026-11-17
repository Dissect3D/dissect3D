//! WE-P04 Store writers for supervised attempts (WE-002/003/004/005,
//! ENG-029/030/031).
//!
//! `finalize` owns `running` -> `failed`/`interrupted` with a safe outcome
//! code, applying the supervisor's cleanup facts through the single cleanup
//! writer, with one revision and event in one transaction. Success is owned by
//! publication (RP-P03) and never written here. A committed user cancellation
//! takes the cancellation path instead. `observe` persists coalesced phase and
//! progress for running work only.
use super::cleanup::{
    AttemptRef, CleanupReceipt, cleanup_transition, read_attempt, write_cleanup_facts,
};
use super::execution::{ExecutionCommand, LiveAttempts, is_safe_code, record_event};
use super::*;
use crate::execution::progress::ObservationUpdate;
use crate::execution::types::{AttemptCleanup, AttemptEnd, StopIntent};

/// Typed failure/interruption report for one attempt. Never success.
#[derive(Debug)]
pub(crate) struct AttemptFinalization {
    pub(crate) attempt: AttemptRef,
    pub(crate) end: AttemptEnd,
    pub(crate) cleanup: AttemptCleanup,
}

/// Which transition a finalization took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalizationPath {
    /// `running` became `failed` or `interrupted` (or a repeat of that).
    Finalized,
    /// Durable user cancellation won; only cleanup facts were applied.
    Cancellation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinalizationReceipt {
    pub(crate) receipt: CleanupReceipt,
    pub(crate) path: FinalizationPath,
}

/// Terminal state and safe outcome code for a running attempt's end.
fn terminal_for(end: AttemptEnd) -> Option<(&'static str, &'static str)> {
    Some(match end {
        AttemptEnd::DeadlineExceeded => ("failed", "execution_deadline_exceeded"),
        AttemptEnd::ProtocolError => ("failed", "worker_protocol_error"),
        AttemptEnd::LaunchFailed => ("failed", "worker_launch_failed"),
        AttemptEnd::WorkerFailed => ("failed", "worker_failed"),
        AttemptEnd::CleanupUnconfirmed => ("failed", "cleanup_unconfirmed"),
        // The worker schema's `engine_shutdown` reason (WE-005: interrupted).
        AttemptEnd::Stopped(StopIntent::EngineShutdown) => ("interrupted", "engine_shutdown"),
        // A user stop follows committed cancellation: never a running outcome.
        AttemptEnd::Stopped(StopIntent::UserCancel | StopIntent::Continue) => return None,
    })
}
fn cleanup_change(cleanup: &AttemptCleanup) -> (&'static str, Option<&'static str>) {
    match cleanup {
        // No process ever existed, so nothing can survive.
        AttemptCleanup::Confirmed(_) | AttemptCleanup::NeverLaunched(_) => ("confirmed", None),
        AttemptCleanup::Fault(code) => ("fault", Some(*code)),
    }
}

impl AttemptFinalization {
    fn validate(&self) -> Result<(), CoreError> {
        self.attempt.validate()?;
        match self.cleanup {
            AttemptCleanup::Fault(code) if !is_safe_code(code) => Err(CoreError::Conflict),
            _ => Ok(()),
        }
    }
}

/// Coalesced phase/progress for one running attempt.
#[derive(Clone, Debug)]
pub(crate) struct AttemptObservation {
    pub(crate) attempt: AttemptRef,
    pub(crate) update: ObservationUpdate,
}
impl AttemptObservation {
    fn validate(&self) -> Result<(), CoreError> {
        self.attempt.validate()?;
        let progress_ok = self.update.progress.as_ref().is_none_or(|p| {
            is_safe_code(p.stage) && p.fraction.is_finite() && (0.0..=1.0).contains(&p.fraction)
        });
        if !progress_ok {
            return Err(CoreError::Conflict);
        }
        Ok(())
    }
    fn progress_json(&self) -> Option<String> {
        self.update
            .progress
            .as_ref()
            .map(|p| serde_json::json!({"fraction": p.fraction, "stage": p.stage}).to_string())
    }
}

impl Store {
    /// Finalize a failed or interrupted attempt. Rejects before any write.
    pub(crate) fn finalize_attempt(
        &self,
        finalization: AttemptFinalization,
    ) -> Result<FinalizationReceipt, CoreError> {
        finalization.validate()?;
        self.request(|reply| Command::Execution(ExecutionCommand::Finalize(finalization, reply)))
    }

    /// Persist a coalesced observation for running work.
    pub(crate) fn record_attempt_observation(
        &self,
        observation: AttemptObservation,
    ) -> Result<CleanupReceipt, CoreError> {
        observation.validate()?;
        self.request(|reply| Command::Execution(ExecutionCommand::Observe(observation, reply)))
    }
}

pub(super) fn finalize(
    db: &mut Connection,
    live: &mut LiveAttempts,
    finalization: AttemptFinalization,
) -> Result<FinalizationReceipt, CoreError> {
    finalization.validate()?;
    let attempt = &finalization.attempt;
    let (next, reason) = cleanup_change(&finalization.cleanup);
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
    let facts = read_attempt(&tx, attempt)?;
    let result = match facts.state.as_str() {
        // A committed user cancellation encountered first wins (WE-003).
        "cancel_requested" | "canceled" => FinalizationReceipt {
            receipt: cleanup_transition(&tx, attempt, &facts, next, reason)?,
            path: FinalizationPath::Cancellation,
        },
        "running" => {
            let (state, code) = terminal_for(finalization.end).ok_or(CoreError::Conflict)?;
            if facts.cleanup != "pending" {
                return Err(CoreError::InvalidStore);
            }
            write_cleanup_facts(&tx, attempt, next, reason)?;
            sql(tx.execute(
                "UPDATE job_execution
                 SET state=?2,phase=?2,outcome_code=?3,snapshot_revision=snapshot_revision+1,
                     updated_at_ms=?4
                 WHERE job_id=?1 AND state='running'",
                rusqlite::params![attempt.job_id.as_str(), state, code, now_ms()?],
            ))?;
            record_event(&tx, attempt.job_id.as_str())?;
            FinalizationReceipt {
                receipt: CleanupReceipt {
                    snapshot_revision: facts.revision + 1,
                    changed: true,
                },
                path: FinalizationPath::Finalized,
            }
        }
        terminal => {
            // Only a repeat of the same finalization; cleanup may still advance.
            let (state, code) = terminal_for(finalization.end).ok_or(CoreError::Conflict)?;
            if terminal != state || facts.outcome.as_deref() != Some(code) {
                return Err(CoreError::Conflict);
            }
            FinalizationReceipt {
                receipt: cleanup_transition(&tx, attempt, &facts, next, reason)?,
                path: FinalizationPath::Finalized,
            }
        }
    };
    if result.receipt.changed {
        sql(tx.commit())?;
        if next == "confirmed" {
            // The attempt is over; its live timing record is no longer needed.
            live.forget(&attempt.attempt_id);
        }
    }
    Ok(result)
}

pub(super) fn observe(
    db: &mut Connection,
    observation: AttemptObservation,
) -> Result<CleanupReceipt, CoreError> {
    observation.validate()?;
    let attempt = &observation.attempt;
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
    let facts = read_attempt(&tx, attempt)?;
    // A stopped or finished job's facts are never overwritten by progress.
    if facts.state != "running" {
        return Err(CoreError::Conflict);
    }
    let (phase, progress): (String, Option<String>) = sql(tx.query_row(
        "SELECT phase,progress_json FROM job_execution WHERE job_id=?1",
        [attempt.job_id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ))?;
    let progress_json = observation.progress_json();
    let unchanged = CleanupReceipt {
        snapshot_revision: facts.revision,
        changed: false,
    };
    if phase == observation.update.phase.as_str() && progress == progress_json {
        return Ok(unchanged);
    }
    sql(tx.execute(
        "UPDATE job_execution
         SET phase=?2,progress_json=?3,snapshot_revision=snapshot_revision+1,updated_at_ms=?4
         WHERE job_id=?1",
        rusqlite::params![
            attempt.job_id.as_str(),
            observation.update.phase.as_str(),
            progress_json,
            now_ms()?
        ],
    ))?;
    // Also enforces the 16,384-byte progress bound before COMMIT.
    record_event(&tx, attempt.job_id.as_str())?;
    sql(tx.commit())?;
    Ok(CleanupReceipt {
        snapshot_revision: facts.revision + 1,
        changed: true,
    })
}
