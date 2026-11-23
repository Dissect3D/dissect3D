//! The authoritative publication transaction (RP-P03/1-/3, /5; RP-003,
//! ENG-030/031/045, WE-002-WE-005).
//!
//! Only this commit makes an attempt succeed. In one IMMEDIATE transaction it
//! verifies the job's current attempt and session, the absence of committed
//! cancellation and of the shutdown barrier, a `prepared` allocation whose
//! file rows equal the caller's durable witnesses, and the native cleanup
//! witness against the recorded launch identity. It then stages the cleanup
//! facts and reservation release, the `results` row, the publication
//! sequence, the `published` allocation, `succeeded` with one revision and
//! its event. Immediately before COMMIT it samples the Store-owned monotonic
//! `AttemptTiming` afresh; at or past the captured deadline every staged
//! change rolls back. No I/O, hashing or queued work separates that check
//! from starting COMMIT. The deadline gates starting COMMIT only: a COMMIT
//! that started in time and completes or is acknowledged later stays
//! committed.
//!
//! A refusal is definite: nothing was written, and the caller finalizes the
//! attempt through its own path (for example `execution_deadline_exceeded`).
//! An error is not a refusal. When COMMIT itself fails, the outcome is
//! uncertain and the caller reconciles with `publication_for_attempt`. It
//! never assumes failure, because success may have committed.
use super::cleanup::{AttemptRef, CleanupEvidence, read_attempt, write_cleanup_facts};
use super::execution::{LiveAttempts, record_event};
use super::launch_identity::CleanupBasis;
use super::results::{FileRole, generated_name};
use super::*;

/// One durably prepared file, as its witness recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommittedFile {
    pub(crate) object_name: String,
    pub(crate) role: FileRole,
    pub(crate) byte_length: u64,
    pub(crate) sha256: [u8; 32],
}

/// Everything one success commit binds. Production builds it only from a
/// sealed `PreparedPublication` and the supervisor's cleanup witness.
#[derive(Clone, Debug)]
pub(crate) struct PublicationCommit {
    pub(crate) attempt: AttemptRef,
    pub(crate) cleanup: CleanupEvidence,
    pub(crate) result_id: String,
    pub(crate) publication_id: String,
    pub(crate) manifest_version: String,
    pub(crate) published_at_ms: u64,
    pub(crate) files: Vec<CommittedFile>,
}

impl PublicationCommit {
    fn validate(&self) -> Result<(), CoreError> {
        self.attempt.validate()?;
        let bounded = generated_name(&self.result_id, "res_")
            && generated_name(&self.publication_id, "pub_")
            && (1..=16).contains(&self.manifest_version.len())
            && i64::try_from(self.published_at_ms).is_ok()
            && (2..=17).contains(&self.files.len())
            && self.files.iter().all(|file| {
                (generated_name(&file.object_name, "art_")
                    || generated_name(&file.object_name, "pub_"))
                    && i64::try_from(file.byte_length).is_ok()
            });
        if bounded {
            Ok(())
        } else {
            Err(CoreError::Conflict)
        }
    }
}

/// The committed identity of one published result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicationReceipt {
    pub(crate) result_id: String,
    pub(crate) publication_id: String,
    pub(crate) job_id: String,
    pub(crate) attempt_id: String,
    /// The job revision that recorded success.
    pub(crate) snapshot_revision: i64,
    pub(crate) publication_sequence: i64,
}

/// Why an eligible-looking commit was definitely not made. Nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitRefusal {
    /// User cancellation committed first (WE-003): it stays authoritative.
    Canceled,
    /// The job is no longer running (already terminal or never dispatched).
    NotRunning,
    /// The attempt belongs to an earlier service session.
    NotCurrentSession,
    /// The shutdown barrier was recorded first; active work is interrupted.
    ShutdownBarrier,
    /// The allocation is not `prepared` (still writing, failed or reclaiming).
    NotPrepared,
    /// The Store-owned monotonic deadline passed before COMMIT could start.
    DeadlineExpired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommitOutcome {
    Committed(PublicationReceipt),
    Refused(CommitRefusal),
}

impl Store {
    /// Commit success for one attempt, or refuse with nothing written.
    pub(crate) fn commit_publication(
        &self,
        commit: PublicationCommit,
    ) -> Result<CommitOutcome, CoreError> {
        commit.validate()?;
        self.request(|reply| {
            Command::Execution(super::execution::ExecutionCommand::CommitPublication(
                Box::new(commit),
                reply,
            ))
        })
    }

    /// The committed result of `attempt_id`, if any: the reconciliation read
    /// after an uncertain COMMIT or a lost acknowledgement.
    pub(crate) fn publication_for_attempt(
        &self,
        attempt_id: String,
    ) -> Result<Option<PublicationReceipt>, CoreError> {
        if !generated_name(&attempt_id, "att_") {
            return Err(CoreError::NotFound);
        }
        self.request(|reply| {
            Command::Results(super::results::ResultCommand::PublicationForAttempt(
                attempt_id, reply,
            ))
        })
    }
}

fn receipt_for(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Option<PublicationReceipt>, CoreError> {
    sql(connection
        .query_row(
            "SELECT r.result_id,a.publication_id,r.job_id,r.attempt_id,
                    (SELECT max(snapshot_revision) FROM job_events v
                      WHERE v.job_id=r.job_id
                        AND json_extract(v.snapshot_json,'$.state')='succeeded'),
                    r.publication_sequence
             FROM results r JOIN publication_allocations a USING(result_id)
             WHERE r.attempt_id=?1",
            [attempt_id],
            |r| {
                Ok(PublicationReceipt {
                    result_id: r.get(0)?,
                    publication_id: r.get(1)?,
                    job_id: r.get(2)?,
                    attempt_id: r.get(3)?,
                    // A committed result always has its success event (the
                    // newest is never pruned); its absence is corruption.
                    snapshot_revision: r.get::<_, Option<i64>>(4)?.unwrap_or(-1),
                    publication_sequence: r.get(5)?,
                })
            },
        )
        .optional())
    .and_then(|receipt| match receipt {
        Some(receipt) if receipt.snapshot_revision < 1 => Err(CoreError::InvalidStore),
        other => Ok(other),
    })
}

pub(super) fn publication_for_attempt(
    connection: &mut Connection,
    attempt_id: &str,
) -> Result<Option<PublicationReceipt>, CoreError> {
    receipt_for(connection, attempt_id)
}

fn stored_files(tx: &Transaction<'_>, result_id: &str) -> Result<Vec<CommittedFile>, CoreError> {
    let mut statement = sql(tx.prepare(
        "SELECT object_name,role,byte_length,sha256 FROM result_files
         WHERE result_id=?1 ORDER BY object_name",
    ))?;
    let rows = sql(statement.query_map([result_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Vec<u8>>(3)?,
        ))
    }))?;
    let mut files = Vec::new();
    for row in rows {
        let (object_name, role, byte_length, sha256) = sql(row)?;
        files.push(CommittedFile {
            object_name,
            role: match role.as_str() {
                "artifact" => FileRole::Artifact,
                "manifest" => FileRole::Manifest,
                _ => return Err(CoreError::InvalidStore),
            },
            byte_length: u64::try_from(byte_length).map_err(|_| CoreError::InvalidStore)?,
            sha256: sha256.try_into().map_err(|_| CoreError::InvalidStore)?,
        });
    }
    Ok(files)
}

pub(super) fn commit_publication(
    db: &mut Connection,
    live: &mut LiveAttempts,
    commit: PublicationCommit,
    stopping: bool,
) -> Result<CommitOutcome, CoreError> {
    commit.validate()?;
    let attempt = &commit.attempt;
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
    // A committed result for this attempt is final: the same publication gets
    // its original identity back; any other candidate is refused.
    if let Some(existing) = receipt_for(&tx, &attempt.attempt_id)? {
        return if existing.result_id == commit.result_id
            && existing.publication_id == commit.publication_id
            && existing.job_id == attempt.job_id.as_str()
        {
            Ok(CommitOutcome::Committed(existing))
        } else {
            Err(CoreError::Conflict)
        };
    }
    // Exact job/attempt/session/grant identity, or Conflict.
    let facts = read_attempt(&tx, attempt)?;
    match facts.state.as_str() {
        "running" => {}
        "cancel_requested" | "canceled" => {
            return Ok(CommitOutcome::Refused(CommitRefusal::Canceled));
        }
        _ => return Ok(CommitOutcome::Refused(CommitRefusal::NotRunning)),
    }
    if stopping {
        return Ok(CommitOutcome::Refused(CommitRefusal::ShutdownBarrier));
    }
    let current: bool = sql(tx.query_row(
        "SELECT instance_id=(SELECT instance_id FROM service_sessions WHERE termination='active')
         FROM job_attempts WHERE attempt_id=?1",
        [attempt.attempt_id.as_str()],
        |r| r.get::<_, Option<bool>>(0),
    ))?
    .unwrap_or(false);
    if !current || !live.contains(&attempt.attempt_id) {
        return Ok(CommitOutcome::Refused(CommitRefusal::NotCurrentSession));
    }
    // Running work's cleanup is still pending: this commit establishes it.
    if facts.cleanup != "pending" {
        return Err(CoreError::InvalidStore);
    }
    let allocation: Option<(String, String)> = sql(tx
        .query_row(
            "SELECT publication_id,state FROM publication_allocations
             WHERE result_id=?1 AND job_id=?2 AND attempt_id=?3",
            rusqlite::params![
                commit.result_id,
                attempt.job_id.as_str(),
                attempt.attempt_id
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional())?;
    let (publication_id, state) = allocation.ok_or(CoreError::Conflict)?;
    if publication_id != commit.publication_id {
        return Err(CoreError::Conflict);
    }
    if state != "prepared" {
        return Ok(CommitOutcome::Refused(CommitRefusal::NotPrepared));
    }
    let mut witnessed = commit.files.clone();
    witnessed.sort_by(|a, b| a.object_name.cmp(&b.object_name));
    if stored_files(&tx, &commit.result_id)? != witnessed {
        return Err(CoreError::Conflict);
    }
    // Stage every change; the native witness must equal the launch record.
    write_cleanup_facts(&tx, attempt, CleanupBasis::Confirmed(&commit.cleanup))?;
    let now = now_ms()?;
    let sequence: i64 = sql(tx.query_row(
        "UPDATE publication_sequence SET value=value+1 WHERE singleton=1 RETURNING value",
        [],
        |r| r.get(0),
    ))?;
    sql(tx.execute(
        "INSERT INTO results(result_id,job_id,attempt_id,publication_sequence,manifest_version,
                             published_at_ms)
         VALUES(?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            commit.result_id,
            attempt.job_id.as_str(),
            attempt.attempt_id,
            sequence,
            commit.manifest_version,
            commit.published_at_ms as i64
        ],
    ))?;
    sql(tx.execute(
        "UPDATE publication_allocations SET state='published',updated_at_ms=max(updated_at_ms,?2)
         WHERE result_id=?1 AND state='prepared'",
        rusqlite::params![commit.result_id, now],
    ))?;
    sql(tx.execute(
        "UPDATE job_execution
         SET state='succeeded',phase='succeeded',outcome_code=NULL,
             snapshot_revision=snapshot_revision+1,updated_at_ms=?2
         WHERE job_id=?1 AND state='running'",
        rusqlite::params![attempt.job_id.as_str(), now],
    ))?;
    record_event(&tx, attempt.job_id.as_str())?;
    // Final eligibility, immediately before COMMIT: the Store's own record,
    // sampled afresh. Dropping `tx` rolls back every staged change.
    let Some(timing) = live.timing(&attempt.attempt_id) else {
        return Ok(CommitOutcome::Refused(CommitRefusal::NotCurrentSession));
    };
    if timing.expired() {
        return Ok(CommitOutcome::Refused(CommitRefusal::DeadlineExpired));
    }
    // A failed COMMIT is uncertain, never a definite refusal.
    tx.commit().map_err(|_| CoreError::StoreUnavailable)?;
    live.forget(&attempt.attempt_id);
    Ok(CommitOutcome::Committed(PublicationReceipt {
        result_id: commit.result_id,
        publication_id: commit.publication_id,
        job_id: attempt.job_id.as_str().to_owned(),
        attempt_id: attempt.attempt_id.clone(),
        snapshot_revision: facts.revision + 1,
        publication_sequence: sequence,
    }))
}
