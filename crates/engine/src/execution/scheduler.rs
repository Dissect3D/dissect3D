//! One central dispatch turn (WE-P06/1; WE-002).
//!
//! Queue order is acceptance sequence among currently eligible jobs. The turn
//! reads queued jobs oldest first in bounded pages and asks the caller's
//! eligibility check about each:
//! - A blocked job keeps its place and never reaches the reservation
//!   transaction.
//! - A ready job is offered to the Store with its exact captured revision,
//!   resolution and complete resource set. The Store reserves that whole set
//!   atomically or refuses: `Busy` means the resources are held, and the job
//!   waits for a later turn. `Conflict`/`NotFound` mean the job changed (for
//!   example, it was canceled before dispatch); it is skipped, not retried.
//! - An error that may hide a committed dispatch is never guessed. The
//!   identical request is replayed once, and only a returned record settles
//!   it: the Store's duplicate path returns the live attempt, or the replay
//!   dispatches exactly once if nothing committed. Any refusal stays
//!   uncertain, because a COMMIT that landed but reported an error never
//!   reached the Store's live set and its replay answers `Conflict` (or `Busy`
//!   while stopping). The turn then stops and reports the job.
//!
//! The SQLite queue is authoritative; the turn keeps no queue of its own. It
//! is driven by one controller, so a returned record is launched once. Unlike
//! a head-of-line scheduler, a blocked oldest job does not hold back eligible
//! work behind it, and nothing is retried automatically.
use crate::CoreError;
use crate::store::execution::{CANDIDATE_PAGE, DispatchRecord, DispatchRequest, QueuedCandidate};
use dissect3d_api::JobId;

/// The Store operations a dispatch turn needs.
pub(crate) trait DispatchStore {
    fn queued_candidates(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> Result<Vec<QueuedCandidate>, CoreError>;
    fn dispatch(&self, request: DispatchRequest) -> Result<DispatchRecord, CoreError>;
}

impl DispatchStore for crate::Store {
    fn queued_candidates(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> Result<Vec<QueuedCandidate>, CoreError> {
        crate::Store::queued_candidates(self, after_sequence, limit)
    }
    fn dispatch(&self, request: DispatchRequest) -> Result<DispatchRecord, CoreError> {
        self.dispatch_attempt(request)
    }
}

/// The caller's verdict on one queued job, from verified prepared support,
/// readiness and input facts held outside the Store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Eligibility {
    /// Executable now, needing exactly this resource set.
    Ready { resources: Vec<String> },
    /// Not executable now, with a safe blocker code; nothing is reserved.
    Blocked(&'static str),
}

/// What one turn did. Records in `dispatched` are committed attempts that
/// the caller must supervise; none is ever dropped.
#[derive(Debug, Default)]
pub(crate) struct DispatchTurn {
    pub(crate) dispatched: Vec<DispatchRecord>,
    pub(crate) blocked: Vec<(JobId, &'static str)>,
    /// Ready, but its resources are held.
    pub(crate) waiting: Vec<JobId>,
    /// A dispatch whose commit could not be established.
    pub(crate) uncertain: Option<JobId>,
    /// Why the turn ended early, if it did.
    pub(crate) stopped: Option<CoreError>,
}

/// Whether a dispatch error may hide a committed attempt.
fn may_have_committed(error: CoreError) -> bool {
    matches!(error, CoreError::StoreUnavailable)
}

/// Run one turn, dispatching at most `max_dispatch` attempts.
pub(crate) fn dispatch_turn(
    store: &impl DispatchStore,
    eligibility: impl Fn(&QueuedCandidate) -> Eligibility,
    max_dispatch: usize,
) -> DispatchTurn {
    let mut turn = DispatchTurn::default();
    let mut after = 0;
    while turn.dispatched.len() < max_dispatch {
        let page = match store.queued_candidates(after, CANDIDATE_PAGE) {
            Ok(page) => page,
            Err(error) => {
                turn.stopped = Some(error);
                return turn;
            }
        };
        let Some(last) = page.last() else {
            return turn;
        };
        after = last.acceptance_sequence;
        for candidate in page {
            if turn.dispatched.len() >= max_dispatch {
                return turn;
            }
            let resources = if !candidate.storage_verified {
                turn.blocked
                    .push((candidate.job_id, "storage_integrity_fault"));
                continue;
            } else {
                match eligibility(&candidate) {
                    Eligibility::Ready { resources } => resources,
                    Eligibility::Blocked(code) => {
                        turn.blocked.push((candidate.job_id, code));
                        continue;
                    }
                }
            };
            let request = DispatchRequest {
                job_id: candidate.job_id.clone(),
                expected_revision: candidate.snapshot_revision,
                resolved_json: candidate.resolved_json,
                resources,
            };
            let mut outcome = store.dispatch(request.clone());
            if let Err(first) = outcome
                && may_have_committed(first)
            {
                // Only a returned record settles it. A refusal may mean the
                // first COMMIT landed without reaching the live set.
                match store.dispatch(request) {
                    Ok(record) => outcome = Ok(record),
                    Err(_) => {
                        turn.uncertain = Some(candidate.job_id);
                        turn.stopped = Some(first);
                        return turn;
                    }
                }
            }
            match outcome {
                Ok(record) => turn.dispatched.push(record),
                Err(CoreError::Busy) => turn.waiting.push(candidate.job_id),
                Err(CoreError::Conflict | CoreError::NotFound) => {}
                Err(error) => {
                    turn.stopped = Some(error);
                    return turn;
                }
            }
        }
    }
    turn
}
