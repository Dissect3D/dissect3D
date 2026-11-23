//! WE-P07/4 restart reconciliation reads (WE-005, ENG-031/035). Startup has
//! already marked formerly running work `interrupted` and kept durable
//! cancellation intent. What remains is ownership: every attempt of an
//! earlier engine instance whose cleanup is not confirmed still holds its
//! reservations. Each is offered with its recorded launch identity, so
//! recovery can establish cleanup (user decision 2026-11-24) and report it
//! through `cleanup::record_cleanup`, the only writer of cleanup facts.
use super::cleanup::AttemptRef;
use super::execution::ExecutionCommand;
use super::*;
use dissect3d_api::JobId;
use dissect3d_platform::WorkerIdentity;

/// Most attempts one recovery pass reads; the rest wait for the next pass.
pub(crate) const RECOVERY_BATCH: usize = 128;

/// One earlier instance's attempt with unconfirmed cleanup.
#[derive(Clone, Debug)]
pub(crate) struct RecoveryCandidate {
    pub(crate) attempt: AttemptRef,
    /// The launch record; `None` when the engine died before writing it
    /// (or before launch): no evidence can be established then.
    pub(crate) identity: Option<WorkerIdentity>,
}

impl Store {
    /// Attempts of earlier engine instances whose cleanup is pending or
    /// faulted, oldest dispatch first, at most `RECOVERY_BATCH`.
    pub(crate) fn recovery_candidates(&self) -> Result<Vec<RecoveryCandidate>, CoreError> {
        self.request(|reply| Command::Execution(ExecutionCommand::Recovery(reply)))
    }
}

pub(super) fn candidates(db: &Connection) -> Result<Vec<RecoveryCandidate>, CoreError> {
    let mut statement = sql(db.prepare(
        "SELECT a.job_id,a.attempt_id,a.session_id,a.grant_id,a.native_identity_json
         FROM job_attempts a
         WHERE a.cleanup_status<>'confirmed'
           AND a.instance_id<>coalesce(
               (SELECT instance_id FROM service_sessions WHERE termination='active'),'')
         ORDER BY a.dispatched_at_ms,a.attempt_id LIMIT ?1",
    ))?;
    let rows = sql(statement.query_map([RECOVERY_BATCH as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    }))?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|_| CoreError::StoreUnavailable)?;
    rows.into_iter()
        .map(|(job, attempt_id, session_id, grant_id, identity)| {
            let identity = match identity {
                // A recorded identity that does not decode is a corrupt record.
                Some(json) => {
                    Some(super::launch_identity::decode(&json).ok_or(CoreError::InvalidStore)?)
                }
                None => None,
            };
            Ok(RecoveryCandidate {
                attempt: AttemptRef {
                    job_id: JobId::parse(job).map_err(|_| CoreError::InvalidStore)?,
                    attempt_id,
                    session_id,
                    grant_id,
                },
                identity,
            })
        })
        .collect()
}
