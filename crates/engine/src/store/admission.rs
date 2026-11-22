//! Shared bounded admission building blocks for fresh queued acceptances.
//!
//! Callers prepare outside the actor; the actor owns every final decision. The
//! helpers here are the parts of that final transaction shared by submission and
//! linked retry: freshness, growth capacity, sequence/free-space and COMMIT.

use super::inputs::read_observed_wall_time_at;
use super::*;
use crate::domain::SubmissionError;
use dissect3d_api::ErrorCode;

pub(super) type Result<T> = std::result::Result<T, SubmissionError>;

pub(super) fn invalid_store() -> SubmissionError {
    ErrorCode::StoreUnavailable.into()
}

/// Fixed product bounds. Tests may lower them only inside their private actor.
#[derive(Clone, Copy)]
pub(crate) struct AcceptanceLimits {
    pub(crate) queued: i64,
    /// Lifetime job bindings: submission and retry bindings share this cap.
    pub(crate) bindings: i64,
    pub(crate) captured_bytes: u64,
    pub(crate) metadata_bytes: usize,
    pub(crate) free_reserve: u64,
}

impl Default for AcceptanceLimits {
    fn default() -> Self {
        Self {
            queued: 128,
            bindings: 65_536,
            captured_bytes: 17_179_869_184,
            metadata_bytes: 262_144,
            free_reserve: STORAGE_FREE_RESERVE_BYTES,
        }
    }
}

/// Engine growth allowed per fresh admission, including metadata and WAL needs.
pub(super) const GROWTH_ALLOWANCE_BYTES: u64 = 4_194_304;
/// Maximum age of a caller-side free-space observation at finish and COMMIT.
const OBSERVATION_WINDOW: Duration = Duration::from_millis(100);

/// Actor-owned facts for one final admission transaction.
pub(super) struct AcceptancePolicy {
    pub(super) stopping: bool,
    pub(super) fail_commit: bool,
    pub(super) response_limit: usize,
    pub(super) limits: AcceptanceLimits,
}

/// Submission and retry admission gate (`Store::bounded_admission`) only.
/// Only the active two callers retain prepared snapshots. Waiting callers are
/// bounded by the existing Store queue capacity and a finite coordination wait.
/// Execution reads never take a slot: they use the bounded actor queue.
pub(super) struct PreparationGate {
    counts: std::sync::Mutex<(usize, usize)>,
    wake: std::sync::Condvar,
    waiting_max: usize,
}
pub(super) struct PreparationPermit<'a>(&'a PreparationGate);
impl PreparationGate {
    pub(super) fn new(waiting_max: usize) -> Self {
        Self {
            counts: std::sync::Mutex::new((0, 0)),
            wake: std::sync::Condvar::new(),
            waiting_max,
        }
    }
    pub(super) fn acquire(&self) -> Result<PreparationPermit<'_>> {
        let mut counts = self.counts.lock().map_err(|_| invalid_store())?;
        if counts.1 >= self.waiting_max {
            return Err(CoreError::Busy.into());
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        counts.1 += 1;
        while counts.0 >= 2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                counts.1 -= 1;
                return Err(CoreError::Busy.into());
            }
            counts = self
                .wake
                .wait_timeout(counts, remaining)
                .map_err(|_| invalid_store())?
                .0;
        }
        counts.1 -= 1;
        counts.0 += 1;
        Ok(PreparationPermit(self))
    }
}
impl Drop for PreparationPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.0.counts.lock() {
            counts.0 -= 1;
            self.0.wake.notify_one();
        }
    }
}

/// Actor-owned counters a caller-side preparation is checked against.
///
/// `generation` moves after a command that may change a fact `finish` cannot
/// recheck in SQL (see `Command::preparation_effect`). `admissions` counts
/// committed fresh acceptances: each one is charged the per-admission growth
/// allowance against an older free-space observation instead of invalidating it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct AdmissionEpoch {
    pub(super) generation: u64,
    pub(super) admissions: u64,
}

/// The actor's view of one fresh preparation: its read epoch, the current
/// epoch and the instant its free-space observation was taken.
pub(super) struct Freshness<'a> {
    /// Locates per-root test hooks; production code does not read it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) root: &'a OwnedRoot,
    pub(super) read: AdmissionEpoch,
    pub(super) current: AdmissionEpoch,
    pub(super) observed_at: Instant,
}
impl Freshness<'_> {
    #[cfg(test)]
    fn hooks(&self) -> Arc<crate::submission::test_support::Hooks> {
        crate::submission::test_support::for_root(self.root.path())
    }
    /// Stale at finish entry: a fact behind the observation may have changed,
    /// or the observation is older than the window.
    pub(super) fn stale_at_entry(&self) -> bool {
        let changed = self.read.generation != self.current.generation;
        let aged = self.observed_at.elapsed() > OBSERVATION_WINDOW;
        #[cfg(test)]
        {
            use crate::submission::test_support::Observation;
            let hooks = self.hooks();
            hooks.observe(Observation::FinishEntry(self.observed_at.elapsed()));
            if changed {
                hooks.observe(Observation::Changed);
            } else if aged {
                hooks.observe(Observation::Aged);
            }
        }
        changed || aged
    }
    /// The observation aged past the window inside the transaction.
    pub(super) fn aged(&self) -> bool {
        let aged = self.observed_at.elapsed() > OBSERVATION_WINDOW;
        #[cfg(test)]
        if aged {
            self.hooks()
                .observe(crate::submission::test_support::Observation::Aged);
        }
        aged
    }
    /// Fresh acceptances committed since this preparation read its epoch.
    fn siblings(&self) -> u64 {
        self.current.admissions.wrapping_sub(self.read.admissions)
    }
}

pub(super) fn input_identity(
    connection: &Connection,
    context: &AuthContext,
    id: &InputId,
    now: i64,
) -> Result<InputIdentity> {
    let row: Option<(String, i64, Vec<u8>)> = sql(connection
        .query_row(
            "SELECT media_type,byte_length,sha256 FROM captured_inputs
             WHERE input_id=?1 AND client_id=?2 AND cleanup_state='complete'
               AND (expires_at_ms>?3 OR EXISTS(SELECT 1 FROM job_inputs
                                               WHERE job_inputs.input_id=captured_inputs.input_id))",
            rusqlite::params![id.as_str(), context.client_id.as_str(), now],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional())?;
    let (media_type, length, digest) =
        row.ok_or_else(|| SubmissionError::from(ErrorCode::InputUnavailable))?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| invalid_store())?;
    Ok(InputIdentity {
        input_id: id.clone(),
        media_type,
        byte_length: u64::try_from(length).map_err(|_| invalid_store())?,
        sha256: ContentDigest::parse(digest_hex(&digest)).map_err(|_| invalid_store())?,
    })
}

/// Read-only current time for snapshots; the authoritative write is in finish.
pub(super) fn read_now(connection: &Connection) -> Result<i64> {
    Ok(read_observed_wall_time_at(connection, now_ms()?)?)
}

/// Check the growth caps that a fresh job consumes and return outstanding
/// upload reservations (declared bytes plus per-upload metadata allowance).
/// `inputs` are the job's distinct inputs; already referenced ones add no bytes.
pub(super) fn check_growth_capacity<'i>(
    transaction: &Transaction<'_>,
    limits: &AcceptanceLimits,
    inputs: impl Iterator<Item = &'i InputIdentity>,
) -> Result<u64> {
    let queued: i64 = sql(transaction.query_row(
        "SELECT count(*) FROM job_execution WHERE state IN ('queued','running','cancel_requested')",
        [],
        |row| row.get(0),
    ))?;
    // Lifetime job bindings: submission and retry bindings share one cap
    // (2026-11-17 user-confirmed E2); neither is ever evicted.
    let bindings: i64 = sql(transaction.query_row(
        "SELECT (SELECT count(*) FROM submission_bindings)+(SELECT count(*) FROM retry_bindings)",
        [],
        |row| row.get(0),
    ))?;
    if queued >= limits.queued {
        return Err(CoreError::CapacityExceeded("queued_jobs_max").into());
    }
    if bindings >= limits.bindings {
        return Err(CoreError::CapacityExceeded("submission_bindings_max").into());
    }
    let captured: i64 = sql(transaction.query_row(
        "SELECT coalesce(sum(byte_length),0) FROM captured_inputs WHERE EXISTS
         (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)",
        [],
        |row| row.get(0),
    ))?;
    let mut additional = 0u64;
    for identity in inputs {
        let referenced: bool = sql(transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM job_inputs WHERE input_id=?1)",
            [identity.input_id.as_str()],
            |row| row.get(0),
        ))?;
        if !referenced {
            additional = additional
                .checked_add(identity.byte_length)
                .ok_or_else(invalid_store)?;
        }
    }
    if (captured as u64)
        .checked_add(additional)
        .is_none_or(|bytes| bytes > limits.captured_bytes)
    {
        return Err(CoreError::CapacityExceeded("captured_input_bytes_max").into());
    }
    let reserved: i64 = sql(transaction.query_row(
        "SELECT coalesce(sum(declared_length),0)+count(*)*4194304 FROM input_upload_reservations",
        [],
        |row| row.get(0),
    ))?;
    Ok(reserved as u64)
}

/// Assign the next acceptance sequence and check free space, after the final
/// freshness check. `None` means the observation aged and the work is stale.
pub(super) fn next_sequence_with_space(
    transaction: &Transaction<'_>,
    freshness: &Freshness<'_>,
    free: u64,
    reserved: u64,
    limits: &AcceptanceLimits,
) -> Result<Option<i64>> {
    if freshness.aged() {
        return Ok(None);
    }
    let sequence = sql(transaction.query_row(
        "SELECT value FROM job_sequence WHERE singleton=1",
        [],
        |r| r.get::<_, i64>(0),
    ))?
    .checked_add(1)
    .ok_or_else(|| SubmissionError::from(ErrorCode::CapacityExceeded))?;
    // Fresh acceptances committed since this observation each used up to one
    // growth allowance of disk that the observation could not see.
    let charged = GROWTH_ALLOWANCE_BYTES.saturating_mul(freshness.siblings().saturating_add(1));
    if free
        < reserved
            .saturating_add(charged)
            .saturating_add(limits.free_reserve)
    {
        return Err(CoreError::CapacityExceeded("storage_free_reserve_bytes").into());
    }
    Ok(Some(sequence))
}

/// Record the new sequence and its acceptance event.
pub(super) fn record_acceptance(
    transaction: &Transaction<'_>,
    job_id: &str,
    sequence: i64,
) -> Result<()> {
    sql(transaction.execute(
        "UPDATE job_sequence SET value=?1 WHERE singleton=1",
        [sequence],
    ))?;
    sql(transaction.execute(
        "INSERT INTO job_acceptance_events VALUES(?1,?2,1)",
        rusqlite::params![job_id, sequence],
    ))?;
    Ok(())
}

/// COMMIT a fresh acceptance unless injected faults or an aged observation
/// require rollback. `None` means stale; a dropped transaction rolls back.
pub(super) fn commit_fresh(
    transaction: Transaction<'_>,
    freshness: &Freshness<'_>,
    fail_commit: bool,
) -> Result<Option<()>> {
    #[cfg(test)]
    if !freshness.hooks().transaction_boundary(false) {
        return Err(ErrorCode::StoreUnavailable.into());
    }
    if fail_commit {
        return Err(ErrorCode::StoreUnavailable.into());
    }
    if freshness.aged() {
        return Ok(None);
    }
    #[cfg(test)]
    freshness
        .hooks()
        .observe(crate::submission::test_support::Observation::CommitStart(
            freshness.observed_at.elapsed(),
        ));
    sql(transaction.commit())?;
    #[cfg(test)]
    {
        // A test-only pause after commit must never manufacture a rejection.
        let _ = freshness.hooks().transaction_boundary(true);
    }
    Ok(Some(()))
}
