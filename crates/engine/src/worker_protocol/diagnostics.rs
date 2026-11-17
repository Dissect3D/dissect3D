//! Bounded diagnostic capture, separate from the control channel (WE-004).
//!
//! Worker stdout/stderr bytes are counted and retained locally up to
//! `DIAGNOSTIC_BYTES_MAX` per attempt, then truncated with a marker. They are
//! never parsed as protocol and never reach normal diagnostics: those carry only
//! engine-owned categories and allowlisted stage identifiers.
use super::DIAGNOSTIC_BYTES_MAX;
use std::collections::BTreeMap;

/// Engine-owned safe diagnostic categories. No variant carries worker text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DiagnosticCategory {
    ProtocolViolation,
    UnlistedStage,
    UnknownProgress,
    ControlUnresponsive,
    SilentStage,
    WorkerDeclaredFailure,
    LaunchFailed,
    DeadlineExceeded,
    CleanupFault,
    OutputTruncated,
}
impl DiagnosticCategory {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolViolation => "worker_protocol_violation",
            Self::UnlistedStage => "unlisted_progress_stage",
            Self::UnknownProgress => "unknown_progress",
            Self::ControlUnresponsive => "control_unresponsive",
            Self::SilentStage => "silent_stage",
            Self::WorkerDeclaredFailure => "worker_declared_failure",
            Self::LaunchFailed => "worker_launch_failed",
            Self::DeadlineExceeded => "execution_deadline_exceeded",
            Self::CleanupFault => "cleanup_fault",
            Self::OutputTruncated => "diagnostic_output_truncated",
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct DiagnosticCapture {
    retained: Vec<u8>,
    observed: u64,
    categories: BTreeMap<DiagnosticCategory, u32>,
}

/// What normal diagnostics may show: counts and safe categories only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DiagnosticSummary {
    pub(crate) bytes_observed: u64,
    pub(crate) bytes_retained: usize,
    pub(crate) truncated: bool,
    pub(crate) categories: Vec<(&'static str, u32)>,
}

impl DiagnosticCapture {
    /// Record raw output. Beyond the cap bytes are counted and discarded, so the
    /// caller keeps draining the pipe without growing memory.
    pub(crate) fn capture(&mut self, bytes: &[u8]) {
        self.observed = self.observed.saturating_add(bytes.len() as u64);
        let room = DIAGNOSTIC_BYTES_MAX - self.retained.len();
        let kept = bytes.len().min(room);
        self.retained.extend_from_slice(&bytes[..kept]);
        if kept < bytes.len() {
            self.note(DiagnosticCategory::OutputTruncated);
        }
    }

    pub(crate) fn note(&mut self, category: DiagnosticCategory) {
        let count = self.categories.entry(category).or_default();
        *count = count.saturating_add(1);
    }

    pub(crate) fn count(&self, category: DiagnosticCategory) -> u32 {
        self.categories.get(&category).copied().unwrap_or(0)
    }

    pub(crate) fn summary(&self) -> DiagnosticSummary {
        DiagnosticSummary {
            bytes_observed: self.observed,
            bytes_retained: self.retained.len(),
            truncated: self.observed > self.retained.len() as u64,
            categories: self
                .categories
                .iter()
                .map(|(c, n)| (c.as_str(), *n))
                .collect(),
        }
    }
}
