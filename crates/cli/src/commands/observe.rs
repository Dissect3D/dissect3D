//! Polling observation loop and monotonic `--observe-timeout-ms` bounds for
//! `jobs watch`, `jobs wait`, and foreground `run`.

use crate::commands::execution::{
    ExecutionMode, detect_mode, execution_client_error, operation_unavailable,
    require_execution_ops, usage_error,
};
use crate::commands::{CommandError, CommandErrorContext};
use crate::config::ConfigFile;
use crate::output::write_stderr_line;
use dissect3d_api::{
    CleanupStatus, Client, ClientError, ClientLimits, ErrorCode, ExecutionCapability,
    ExecutionJobSnapshot, ExecutionJobState, JobId,
};
use std::path::Path;
use std::time::Duration;

pub(crate) const MIN_OBSERVE_TIMEOUT_MS: u64 = 1_000;
pub(crate) const MAX_OBSERVE_TIMEOUT_MS: u64 = 86_400_000;
const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(2_000);

/// Validated finite observation deadline (`1,000..=86,400,000` ms, `CR-CS-03`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObserveTimeout(Duration);

impl ObserveTimeout {
    pub(crate) fn from_ms(ms: u64) -> Result<Self, CommandError> {
        if !(MIN_OBSERVE_TIMEOUT_MS..=MAX_OBSERVE_TIMEOUT_MS).contains(&ms) {
            return Err(usage_error(
                "--observe-timeout-ms must be an integer between 1000 and 86400000",
            ));
        }
        Ok(Self(Duration::from_millis(ms)))
    }

    pub(crate) fn parse(raw: &str) -> Result<Self, CommandError> {
        let ms = raw.parse::<u64>().map_err(|_| {
            usage_error("--observe-timeout-ms must be an integer between 1000 and 86400000")
        })?;
        Self::from_ms(ms)
    }

    pub(crate) fn duration(self) -> Duration {
        self.0
    }
}

/// Terminal or non-terminal end of a bounded observation loop.
#[derive(Clone, Debug)]
pub(crate) enum ObserveEnd {
    Terminal(Box<ExecutionJobSnapshot>),
    TimedOut {
        job_id: JobId,
        last: Option<Box<ExecutionJobSnapshot>>,
    },
    Interrupted {
        job_id: JobId,
        last: Option<Box<ExecutionJobSnapshot>>,
    },
    ReadsExhausted {
        job_id: JobId,
        last: Option<Box<ExecutionJobSnapshot>>,
    },
    NotFound(JobId),
}

pub(crate) fn is_terminal(state: ExecutionJobState) -> bool {
    matches!(
        state,
        ExecutionJobState::Succeeded
            | ExecutionJobState::Partial
            | ExecutionJobState::Failed
            | ExecutionJobState::Canceled
            | ExecutionJobState::Interrupted
    )
}

pub(crate) fn run_observe(
    job_id: String,
    observe_timeout_ms: Option<String>,
    config: &ConfigFile,
    path: &Path,
    limits: ClientLimits,
) -> Result<ObserveEnd, CommandError> {
    let id = JobId::parse(job_id).map_err(|_| usage_error("Job ID is invalid"))?;
    let timeout = observe_timeout_ms
        .as_deref()
        .map(ObserveTimeout::parse)
        .transpose()?;
    super::discovery::connected(config, path, limits, |client| {
        let runtime = super::tokio_runtime();
        runtime.block_on(async {
            let mode = detect_mode(&client).await?;
            let ExecutionMode::Negotiated {
                capability,
                granted_operations,
            } = mode
            else {
                return Err(operation_unavailable(
                    "Job observation requires an execution-capable engine",
                ));
            };
            require_execution_ops(&capability, &granted_operations, &["jobs.show"])?;
            poll_job_observation(&client, &capability, id, timeout).await
        })
    })
}

async fn poll_job_observation(
    client: &Client,
    capability: &ExecutionCapability,
    job_id: JobId,
    timeout: Option<ObserveTimeout>,
) -> Result<ObserveEnd, CommandError> {
    // Non-console or detached processes on Windows have no console handle; failure is benign there.
    let _ = dissect3d_platform::enable_console_ctrl_c();
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t.duration());
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut interval = INITIAL_POLL_INTERVAL;
    let mut last: Option<Box<ExecutionJobSnapshot>> = None;
    let mut printer = ObserverPrinter::new();

    loop {
        if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
            return Ok(ObserveEnd::TimedOut { job_id, last });
        }

        let poll_result = tokio::select! {
            biased;
            _ = &mut ctrl_c => {
                return Ok(ObserveEnd::Interrupted { job_id, last });
            }
            _ = sleep_until_optional(deadline) => {
                return Ok(ObserveEnd::TimedOut { job_id, last });
            }
            result = client.execution_job_with(capability, &job_id) => result,
        };

        match poll_result {
            Ok(snapshot) => {
                printer.on_snapshot(&snapshot);
                if is_terminal(snapshot.summary.state) {
                    return Ok(ObserveEnd::Terminal(Box::new(snapshot)));
                }
                let revision_changed = last.as_ref().is_none_or(|prev| {
                    prev.summary.snapshot_revision != snapshot.summary.snapshot_revision
                });
                interval = if revision_changed {
                    INITIAL_POLL_INTERVAL
                } else {
                    (interval * 2).min(MAX_POLL_INTERVAL)
                };
                last = Some(Box::new(snapshot));
            }
            Err(ClientError::Rejected(ErrorCode::NotFound)) => {
                return Ok(ObserveEnd::NotFound(job_id));
            }
            Err(ClientError::Transport) => {
                return Ok(ObserveEnd::ReadsExhausted { job_id, last });
            }
            Err(other) => {
                return Err(attach_last_known(
                    execution_client_error(other),
                    &job_id,
                    last.as_deref(),
                ));
            }
        }

        let sleep_deadline = match deadline {
            Some(d) => (tokio::time::Instant::now() + interval).min(d),
            None => tokio::time::Instant::now() + interval,
        };
        tokio::select! {
            biased;
            _ = &mut ctrl_c => {
                return Ok(ObserveEnd::Interrupted { job_id, last });
            }
            _ = tokio::time::sleep_until(sleep_deadline) => {
                if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
                    return Ok(ObserveEnd::TimedOut { job_id, last });
                }
            }
        }
    }
}

async fn sleep_until_optional(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

fn attach_last_known(
    mut error: CommandError,
    job_id: &JobId,
    last: Option<&ExecutionJobSnapshot>,
) -> CommandError {
    let context = error
        .context
        .get_or_insert_with(|| Box::new(CommandErrorContext::default()));
    if let Some(snapshot) = last
        && let Ok(raw) = serde_json::value::to_raw_value(snapshot)
    {
        context.raw_data = Some(raw);
        return error;
    }
    context.data = Some(serde_json::json!({ "job_id": job_id }));
    error
}

/// Emits one readiness line on the first snapshot and state-change lines only
/// thereafter (no progress display, per `CR-CS-02`).
pub(crate) struct ObserverPrinter {
    foreground: bool,
    announced: bool,
    last_key: Option<(
        ExecutionJobState,
        String,
        bool,
        CleanupStatus,
        Option<String>,
    )>,
}

impl ObserverPrinter {
    pub(crate) fn new() -> Self {
        Self {
            foreground: false,
            announced: false,
            last_key: None,
        }
    }

    pub(crate) fn for_foreground() -> Self {
        Self {
            foreground: true,
            announced: false,
            last_key: None,
        }
    }

    pub(crate) fn readiness_line(&self, snapshot: &ExecutionJobSnapshot) -> String {
        let summary = &snapshot.summary;
        let state = state_label(summary.state);
        let cleanup = cleanup_label(summary.cleanup.status);
        if self.foreground {
            format!(
                "running job {} (state={}, phase={}, cancel_requested={}, cleanup={}); press Ctrl+C to request cancellation (press Ctrl+C again to stop waiting)",
                summary.job_id.as_str(),
                state,
                summary.phase,
                summary.cancellation.requested,
                cleanup
            )
        } else {
            format!(
                "observing job {} (state={}, phase={}, cancel_requested={}, cleanup={}); press Ctrl+C to stop observing (job keeps running)",
                summary.job_id.as_str(),
                state,
                summary.phase,
                summary.cancellation.requested,
                cleanup
            )
        }
    }

    pub(crate) fn on_snapshot(&mut self, snapshot: &ExecutionJobSnapshot) {
        let summary = &snapshot.summary;
        let state = state_label(summary.state);
        let cleanup = cleanup_label(summary.cleanup.status);
        let outcome_code = summary.outcome.as_ref().map(|o| o.code.clone());
        let key = (
            summary.state,
            summary.phase.clone(),
            summary.cancellation.requested,
            summary.cleanup.status,
            outcome_code.clone(),
        );

        if !self.announced {
            self.announced = true;
            write_stderr_line(&self.readiness_line(snapshot));
            self.last_key = Some(key);
            return;
        }

        if self.last_key.as_ref() != Some(&key) {
            let mut line = format!(
                "job {}: state={} phase={} cancel_requested={} cleanup={}",
                summary.job_id.as_str(),
                state,
                summary.phase,
                summary.cancellation.requested,
                cleanup
            );
            if let Some(code) = outcome_code {
                line.push_str(&format!(" outcome={code}"));
            }
            write_stderr_line(&line);
            self.last_key = Some(key);
        }
    }
}

pub(crate) fn state_label(state: ExecutionJobState) -> &'static str {
    match state {
        ExecutionJobState::Queued => "queued",
        ExecutionJobState::Running => "running",
        ExecutionJobState::CancelRequested => "cancel_requested",
        ExecutionJobState::Succeeded => "succeeded",
        ExecutionJobState::Partial => "partial",
        ExecutionJobState::Failed => "failed",
        ExecutionJobState::Canceled => "canceled",
        ExecutionJobState::Interrupted => "interrupted",
    }
}

pub(crate) fn cleanup_label(status: CleanupStatus) -> &'static str {
    match status {
        CleanupStatus::Pending => "pending",
        CleanupStatus::Confirmed => "confirmed",
        CleanupStatus::Fault => "fault",
    }
}
