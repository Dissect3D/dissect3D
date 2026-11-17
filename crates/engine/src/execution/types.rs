//! Supervisor-owned execution types (WE-P04; coordination "Shared internal
//! interface proposal"). Nothing here is serialized or public API.
use crate::store::cleanup::CleanupEvidence;
use crate::worker_protocol::{CandidateReport, DiagnosticSummary, ExecuteInput};
use std::time::Duration;

/// External stop request delivered on a `watch` channel. A deadline is not a
/// stop intent: expiry is the supervisor's own typed failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopIntent {
    Continue,
    /// Durable user cancellation is already committed (`cancel_requested`).
    UserCancel,
    /// The shutdown barrier is committed.
    EngineShutdown,
}

/// Separate finite supervision bounds (WE-004). They are never the attempt
/// deadline, never renewed by a pong, and no bound proves termination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SupervisionLimits {
    pub(crate) launch: Duration,
    pub(crate) handshake: Duration,
    pub(crate) load: Duration,
    pub(crate) cooperative_cancel: Duration,
    pub(crate) termination: Duration,
    pub(crate) shutdown: Duration,
    /// Responsiveness probe interval; an unanswered ping only warns.
    pub(crate) ping_interval: Duration,
    /// A stage silent this long warns; silence alone never fails the job.
    pub(crate) silence_warning: Duration,
    /// Minimum spacing of persisted progress within one phase.
    pub(crate) progress_interval: Duration,
}
impl SupervisionLimits {
    /// The accepted initial ceilings for the CPU fixture profile (WE-004).
    pub(crate) const CONTRACT: Self = Self {
        launch: Duration::from_secs(10),
        handshake: Duration::from_secs(10),
        load: Duration::from_secs(30),
        cooperative_cancel: Duration::from_secs(2),
        termination: Duration::from_secs(5),
        shutdown: Duration::from_secs(5),
        ping_interval: Duration::from_secs(5),
        silence_warning: Duration::from_secs(60),
        progress_interval: Duration::from_secs(1),
    };
    /// Effective values never exceed the accepted ceilings.
    pub(crate) fn within_contract(&self) -> bool {
        let c = Self::CONTRACT;
        self.launch <= c.launch
            && self.handshake <= c.handshake
            && self.load <= c.load
            && self.cooperative_cancel <= c.cooperative_cancel
            && self.termination <= c.termination
            && self.shutdown <= c.shutdown
    }
}

/// Engine-verified inputs for one attempt's private messages (WE-P05 supplies
/// the scoped handles and exact identities from prepared support).
#[derive(Clone, Debug)]
pub(crate) struct AttemptPlan {
    pub(crate) expectation: super::legality::WorkerExpectation,
    pub(crate) resolution_handle: String,
    pub(crate) inputs: Vec<ExecuteInput>,
    pub(crate) output_staging_handle: String,
    pub(crate) effective_parameters_handle: String,
    /// Allowlisted progress stage identifiers for this adapter.
    pub(crate) stages: &'static [&'static str],
    pub(crate) limits: SupervisionLimits,
}

/// Proof that the supervisor never started a process for this attempt.
/// Only the execution module mints it.
#[derive(Debug)]
pub(crate) struct NeverLaunched {
    _private: (),
}
impl NeverLaunched {
    pub(super) fn new() -> Self {
        Self { _private: () }
    }
}

/// Established cleanup facts for a finished attempt.
#[derive(Debug)]
pub(crate) enum AttemptCleanup {
    /// Whole-tree termination established by native evidence.
    Confirmed(CleanupEvidence),
    /// No process was ever started; nothing can survive.
    NeverLaunched(NeverLaunched),
    /// Termination or ownership is uncertain: holds stay (safe code).
    Fault(&'static str),
}

/// Why an attempt ended without a publishable candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptEnd {
    DeadlineExceeded,
    ProtocolError,
    LaunchFailed,
    /// Declared load/execution failure, rejection, crash or early exit.
    WorkerFailed,
    /// A candidate arrived but termination could not be established.
    CleanupUnconfirmed,
    Stopped(StopIntent),
}

/// The supervisor's only result. No callback or worker message publishes.
#[derive(Debug)]
pub(crate) enum AttemptExit {
    /// Untrusted candidate description after confirmed whole-tree cleanup.
    /// RP-P02 capture turns it into a `ClosedCandidate`; it is never success.
    Candidate {
        report: CandidateReport,
        cleanup: CleanupEvidence,
        diagnostics: DiagnosticSummary,
    },
    Ended {
        end: AttemptEnd,
        cleanup: AttemptCleanup,
        diagnostics: DiagnosticSummary,
    },
}
