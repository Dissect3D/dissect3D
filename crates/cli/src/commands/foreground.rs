//! Polling foreground `run` orchestration (`WE-P08.5`, `CR-CS-02`–`CR-CS-04`).
//!
//! Submits through the negotiated `we-0.1` boundary, observes authoritative
//! snapshots with a bounded poll cadence and optional monotonic
//! `--observe-timeout-ms`, wires `--output DIR` through `FEAT-05`'s
//! `download_result`, keeps Esc inert (never reads stdin or changes terminal
//! mode), and drives the two-stage Ctrl+C state machine in `interrupt.rs`.

pub(crate) mod interrupt;

use crate::args::RunArgs;
use crate::commands::execution::request::ExecutionRequest;
use crate::commands::execution::submit::{
    parse_or_generate_key, persist_fresh_execution_record, random_hex,
    save_execution_receipt_or_cr_cs_01,
};
use crate::commands::execution::{
    ExecutionMode, detect_mode, execution_client_error, execution_send_error,
    operation_unavailable, require_execution_ops, usage_error,
};
use crate::commands::foreground::interrupt::{InterruptAction, InterruptStateMachine};
use crate::commands::job_outcome::{Promise, exit_code, render_outcome};
use crate::commands::observe::{ObserveEnd, ObserveTimeout, ObserverPrinter, is_terminal};
use crate::commands::results::{DownloadError, DownloadReport, download_result};
use crate::commands::{CommandError, CommandErrorContext, data_root, tokio_runtime};
use crate::config::ConfigFile;
use crate::connection::Profile;
use crate::output::{CommandOutcome, ErrorInfo, write_stderr_line};
use crate::submissions::execution::PendingExecutionRecord;
use dissect3d_api::{
    Client, ClientError, ClientLimits, ErrorCode, ExecutionCapability, ExecutionJobSnapshot,
    ExecutionJobState, InputRef, JOB_CONTRACT, JobId, ModelLookup, ObservationScope, PageQuery,
    SubmissionId, SubmittedTask, TaskKey, TaskListQuery,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(2_000);

pub(crate) struct ForegroundOutcome {
    pub(crate) exit_code: i32,
    pub(crate) outcome: CommandOutcome,
}

pub(crate) fn run_foreground(
    args: RunArgs,
    config: &ConfigFile,
    config_path: &Path,
    limits: ClientLimits,
) -> Result<ForegroundOutcome, CommandError> {
    let observe_timeout = args
        .observe_timeout_ms
        .as_deref()
        .map(ObserveTimeout::parse)
        .transpose()?;
    if let Some(dir) = &args.output
        && dir.as_os_str().is_empty()
    {
        return Err(usage_error("Output directory path is required"));
    }
    let cwd = std::env::current_dir()
        .map_err(|_| usage_error("Current working directory is unavailable"))?;
    let (definition, policy) = ExecutionRequest::from_args(&args.definition, &cwd)?;
    let key = parse_or_generate_key(args.definition.idempotency_key.as_deref())?;

    let root = data_root(config, config_path).ok_or_else(|| CommandError {
        category: "engine_unavailable",
        message: "Configure an engine connection before running a job",
        exit_code: 3,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(false)),
            ..Default::default()
        })),
    })?;
    let profile = Profile::open(config_path).map_err(CommandError::connection)?;
    let engine = profile
        .connection(&root, limits.connect_timeout, limits)
        .map_err(CommandError::connection)?;
    let credential = profile
        .credential_snapshot(config, &engine)
        .map_err(CommandError::connection)?;
    let installation_id = credential.installation_id.clone();
    let client_id = credential.client_id.clone();
    let client = engine
        .client(credential)
        .map_err(CommandError::connection)?;

    let runtime = tokio_runtime();
    runtime.block_on(async {
        let mode = detect_mode(&client).await?;
        let ExecutionMode::Negotiated {
            capability,
            granted_operations,
        } = mode
        else {
            return Err(operation_unavailable(
                "Foreground run requires an engine advertising job_execution",
            ));
        };
        require_execution_ops(
            &capability,
            &granted_operations,
            &["inputs.create", "jobs.submit", "jobs.show"],
        )?;
        definition.validate_execution_features()?;

        // Non-console or detached processes on Windows have no console handle; failure is benign there.
        let _ = dissect3d_platform::enable_console_ctrl_c();
        let mut ctrl_c = CtrlCListener::install()?;
        let mut state = InterruptStateMachine::new();

        // Phase: BeforeSend — resolve selection, capture inputs, persist record.
        let (task, references, identities) = tokio::select! {
            biased;
            _ = ctrl_c.recv() => {
                let _ = state.on_interrupt();
                return Ok(before_send_interrupted());
            }
            prepared = resolve_and_capture(&client, &capability, &definition) => prepared?,
        };

        let body = definition.to_execution_body(task, references, policy)?;
        let body_utf8 = String::from_utf8(body.as_bytes().to_vec())
            .map_err(|_| usage_error("Execution request body must be valid UTF-8"))?;
        let sub_id = SubmissionId::parse(format!("sub_{}", random_hex()?))
            .map_err(|_| usage_error("Could not generate submission ID"))?;
        let record = PendingExecutionRecord {
            record_version: "1.1".into(),
            sub_id,
            installation_id,
            client_id,
            operation: "jobs.submit".into(),
            key,
            job_contract: JOB_CONTRACT.into(),
            request_body_utf8: Some(body_utf8),
            source_job_id: None,
            input_identities: identities,
            receipt: None,
        };
        let record_lease = persist_fresh_execution_record(&profile, &record)?;

        // Phase: InFlight — send once, racing against first/second Ctrl+C.
        state.enter_in_flight();
        let send_fut = client.submit_execution_job_with(&capability, &record.key, &body);
        tokio::pin!(send_fut);

        let receipt = loop {
            tokio::select! {
                biased;
                _ = ctrl_c.recv() => {
                    match state.on_interrupt() {
                        InterruptAction::AckAndKeepWaiting => {
                            write_stderr_line(
                                "Interrupt received before acceptance receipt; waiting for engine reply (press Ctrl+C again to stop waiting with uncertain status)",
                            );
                        }
                        InterruptAction::ExitUncertain => {
                            return Ok(pre_receipt_uncertain(&record));
                        }
                        _ => {}
                    }
                }
                result = &mut send_fut => {
                    break result.map_err(|error| {
                        execution_send_error(error, &record.sub_id, &record.key, false)
                    })?;
                }
            }
        };

        save_execution_receipt_or_cr_cs_01(&record, &receipt, |rec, acc| {
            record_lease.save_receipt(rec, acc)
        })?;
        drop(record_lease);

        let job_id = receipt.job_id.clone();
        if let Some(InterruptAction::SendCancel(id)) = state.on_accepted(job_id.clone())
            && request_cancel_once(&client, &capability, &id, &mut ctrl_c, &mut state).await
        {
            return Ok(detached_after_cancel(&job_id, None));
        }

        // Phase: Accepted / CancelRequested — bounded poll loop.
        observe_foreground(
            &client,
            &capability,
            job_id,
            observe_timeout,
            args.output,
            &mut ctrl_c,
            &mut state,
        )
        .await
    })
}

async fn resolve_and_capture(
    client: &Client,
    capability: &ExecutionCapability,
    definition: &ExecutionRequest,
) -> Result<
    (
        SubmittedTask,
        BTreeMap<String, Vec<InputRef>>,
        Vec<dissect3d_api::InputIdentity>,
    ),
    CommandError,
> {
    let mut model_selector = definition.model.clone();
    let declared = if definition.task.is_none() {
        let model = client
            .model(ModelLookup {
                selector: definition.model.clone(),
                ..Default::default()
            })
            .await
            .map_err(execution_client_error)?;
        model_selector = model.item.summary.support_ref;
        let tasks = client
            .tasks(TaskListQuery {
                page: PageQuery {
                    limit: Some(2),
                    cursor: None,
                },
                support_ref: Some(model_selector.clone()),
            })
            .await
            .map_err(execution_client_error)?;
        if tasks.next_cursor.is_some() {
            return Err(usage_error("Specify --task and --task-version"));
        }
        tasks
            .items
            .into_iter()
            .map(|task| SubmittedTask {
                id: task.task.id().to_owned(),
                version: task.task.version().to_owned(),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let task = definition.select_task(&declared)?;
    definition.validate_selected_task(task.clone())?;
    let selected = client
        .model(ModelLookup {
            selector: model_selector.clone(),
            task: Some(
                TaskKey::new(&task.id, &task.version)
                    .map_err(|_| usage_error("Task ID or version is invalid"))?,
            ),
            runtime_ref: definition.runtime.clone(),
            variant: definition.variant.clone(),
        })
        .await
        .map_err(execution_client_error)?;
    let summary = selected.item.summary;
    let [observation] = summary.observations.as_slice() else {
        return Err(execution_client_error(ClientError::InvalidResponse));
    };
    let selection = &observation.selection;
    if observation.scope != ObservationScope::Selection
        || (definition.task.is_none() && summary.support_ref != model_selector)
        || selection["support_ref"] != summary.support_ref
        || selection["task"] != serde_json::json!(task)
        || selection["runtime_ref"].as_str().is_none_or(str::is_empty)
        || selection["variant"].as_str().is_none_or(str::is_empty)
        || definition
            .variant
            .as_ref()
            .is_some_and(|variant| selection["variant"] != *variant)
    {
        return Err(execution_client_error(ClientError::InvalidResponse));
    }

    let inputs = definition.open_inputs()?;
    let mut references: BTreeMap<String, Vec<InputRef>> = BTreeMap::new();
    let mut identities = Vec::new();
    for input in inputs {
        let receipt = client
            .create_execution_input_with(
                capability,
                tokio::fs::File::from_std(input.file),
                input.length,
                input.media_type,
            )
            .await
            .map_err(execution_client_error)?;
        references.entry(input.role).or_default().push(InputRef {
            input_id: receipt.identity.input_id.clone(),
        });
        identities.push(receipt.identity);
    }
    Ok((task, references, identities))
}

/// Sends a single cancel request, returning `true` if a second Ctrl+C detached
/// while the cancel request was in flight.
async fn request_cancel_once(
    client: &Client,
    capability: &ExecutionCapability,
    job_id: &JobId,
    ctrl_c: &mut CtrlCListener,
    state: &mut InterruptStateMachine,
) -> bool {
    write_stderr_line(&format!(
        "Cancellation requested for job {}; waiting for terminal outcome (press Ctrl+C again to stop waiting)",
        job_id.as_str()
    ));
    let cancel_fut = client.cancel_execution_job_with(capability, job_id);
    tokio::pin!(cancel_fut);
    let result = tokio::select! {
        biased;
        _ = ctrl_c.recv() => {
            let _ = state.on_interrupt();
            return true;
        }
        res = &mut cancel_fut => res,
    };
    if result.is_err() {
        write_stderr_line(&format!(
            "warning: cancel request for job {} could not be confirmed; continuing to observe (check `dissect3d jobs show {}` or retry `dissect3d jobs cancel {}`)",
            job_id.as_str(),
            job_id.as_str(),
            job_id.as_str(),
        ));
    }
    false
}

async fn observe_foreground(
    client: &Client,
    capability: &ExecutionCapability,
    job_id: JobId,
    timeout: Option<ObserveTimeout>,
    output_dir: Option<PathBuf>,
    ctrl_c: &mut CtrlCListener,
    state: &mut InterruptStateMachine,
) -> Result<ForegroundOutcome, CommandError> {
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t.duration());
    let mut interval = INITIAL_POLL_INTERVAL;
    let mut last: Option<Box<ExecutionJobSnapshot>> = None;
    let mut printer = ObserverPrinter::for_foreground();

    loop {
        if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
            let end = ObserveEnd::TimedOut { job_id, last };
            return Ok(ForegroundOutcome {
                exit_code: exit_code(Promise::Run, &end),
                outcome: render_outcome("run", Promise::Run, &end),
            });
        }

        let poll_result = tokio::select! {
            biased;
            _ = ctrl_c.recv() => {
                match state.on_interrupt() {
                    InterruptAction::SendCancel(id) => {
                        if request_cancel_once(client, capability, &id, ctrl_c, state).await {
                            return Ok(detached_after_cancel(&job_id, last.as_deref()));
                        }
                        continue;
                    }
                    InterruptAction::ExitDetached => {
                        return Ok(detached_after_cancel(&job_id, last.as_deref()));
                    }
                    _ => continue,
                }
            }
            _ = sleep_until_optional(deadline) => {
                let end = ObserveEnd::TimedOut { job_id, last };
                return Ok(ForegroundOutcome {
                    exit_code: exit_code(Promise::Run, &end),
                    outcome: render_outcome("run", Promise::Run, &end),
                });
            }
            result = client.execution_job_with(capability, &job_id) => result,
        };

        match poll_result {
            Ok(snapshot) => {
                printer.on_snapshot(&snapshot);
                if is_terminal(snapshot.summary.state) {
                    return finish_terminal(client, Box::new(snapshot), output_dir).await;
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
                let end = ObserveEnd::NotFound(job_id);
                return Ok(ForegroundOutcome {
                    exit_code: exit_code(Promise::Run, &end),
                    outcome: render_outcome("run", Promise::Run, &end),
                });
            }
            Err(ClientError::Transport) => {
                let end = ObserveEnd::ReadsExhausted { job_id, last };
                return Ok(ForegroundOutcome {
                    exit_code: exit_code(Promise::Run, &end),
                    outcome: render_outcome("run", Promise::Run, &end),
                });
            }
            Err(other) => {
                let mut err = execution_client_error(other);
                let ctx = err
                    .context
                    .get_or_insert_with(|| Box::new(CommandErrorContext::default()));
                ctx.accepted = Some(serde_json::Value::Bool(true));
                if let Some(snap) = last.as_deref()
                    && let Ok(raw) = serde_json::value::to_raw_value(snap)
                {
                    ctx.raw_data = Some(raw);
                } else {
                    ctx.data = Some(serde_json::json!({ "job_id": job_id }));
                }
                return Err(err);
            }
        }

        let sleep_deadline = match deadline {
            Some(d) => (tokio::time::Instant::now() + interval).min(d),
            None => tokio::time::Instant::now() + interval,
        };
        tokio::select! {
            biased;
            _ = ctrl_c.recv() => {
                match state.on_interrupt() {
                    InterruptAction::SendCancel(id) => {
                        if request_cancel_once(client, capability, &id, ctrl_c, state).await {
                            return Ok(detached_after_cancel(&job_id, last.as_deref()));
                        }
                    }
                    InterruptAction::ExitDetached => {
                        return Ok(detached_after_cancel(&job_id, last.as_deref()));
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep_until(sleep_deadline) => {
                if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) {
                    let end = ObserveEnd::TimedOut { job_id, last };
                    return Ok(ForegroundOutcome {
                        exit_code: exit_code(Promise::Run, &end),
                        outcome: render_outcome("run", Promise::Run, &end),
                    });
                }
            }
        }
    }
}

async fn finish_terminal(
    client: &Client,
    snapshot: Box<ExecutionJobSnapshot>,
    output_dir: Option<PathBuf>,
) -> Result<ForegroundOutcome, CommandError> {
    if snapshot.summary.state == ExecutionJobState::Succeeded
        && let Some(dir) = output_dir
    {
        if snapshot.summary.result_ids.is_empty() {
            return Ok(download_failed_with_succeeded_job(
                &snapshot,
                "artifact_unavailable",
                "Job succeeded, but no published result ID was reported for download",
                None,
            ));
        }
        let mut reports: Vec<DownloadReport> = Vec::new();
        for result_id in &snapshot.summary.result_ids {
            match download_result(client, result_id, &dir).await {
                Ok(report) => reports.push(report),
                Err(error) => {
                    return Ok(download_failed_with_succeeded_job(
                        &snapshot,
                        error.category,
                        error.message,
                        Some(&error),
                    ));
                }
            }
        }
        let mut value = serde_json::to_value(&*snapshot)
            .unwrap_or_else(|_| serde_json::json!({ "job_id": snapshot.summary.job_id }));
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "downloads".to_owned(),
                serde_json::to_value(&reports).unwrap_or_else(|_| serde_json::Value::Array(vec![])),
            );
        }
        return Ok(ForegroundOutcome {
            exit_code: 0,
            outcome: CommandOutcome::success("run", value)
                .with_accepted(serde_json::Value::Bool(true)),
        });
    }

    let end = ObserveEnd::Terminal(snapshot);
    Ok(ForegroundOutcome {
        exit_code: exit_code(Promise::Run, &end),
        outcome: render_outcome("run", Promise::Run, &end),
    })
}

fn download_failed_with_succeeded_job(
    snapshot: &ExecutionJobSnapshot,
    category: &'static str,
    message: &'static str,
    download_error: Option<&DownloadError>,
) -> ForegroundOutcome {
    let mut value = serde_json::to_value(snapshot)
        .unwrap_or_else(|_| serde_json::json!({ "job_id": snapshot.summary.job_id }));
    if let (Some(obj), Some(err)) = (value.as_object_mut(), download_error) {
        obj.insert(
            "download".to_owned(),
            serde_json::json!({
                "result_id": err.result_id,
                "complete": false,
                "completed_files": err.completed_files,
            }),
        );
    }
    ForegroundOutcome {
        exit_code: 16,
        outcome: CommandOutcome::failure_with_context(
            "run",
            ErrorInfo::new(category, message),
            Some(serde_json::Value::Bool(true)),
            None,
            Some(value),
        ),
    }
}

fn before_send_interrupted() -> ForegroundOutcome {
    ForegroundOutcome {
        exit_code: 18,
        outcome: CommandOutcome::failure_with_context(
            "run",
            ErrorInfo::new("interrupted", "Interrupted before the submission was sent"),
            Some(serde_json::Value::Bool(false)),
            None,
            None,
        ),
    }
}

fn pre_receipt_uncertain(record: &PendingExecutionRecord) -> ForegroundOutcome {
    let sub_id = record.sub_id.as_str();
    let message = format!(
        "Interrupted before acceptance receipt; if accepted, the job continues running uncancelled. Run `dissect3d jobs recover {sub_id}` to reconcile, then `dissect3d jobs cancel` if needed."
    );
    ForegroundOutcome {
        exit_code: 15,
        outcome: CommandOutcome::failure_with_context(
            "run",
            ErrorInfo::new("submission_uncertain", message),
            Some(serde_json::Value::Null),
            None,
            Some(serde_json::json!({
                "sub_id": record.sub_id,
                "idempotency_key": record.key,
            })),
        ),
    }
}

fn detached_after_cancel(job_id: &JobId, last: Option<&ExecutionJobSnapshot>) -> ForegroundOutcome {
    let error = ErrorInfo::new(
        "foreground_detached",
        "Stopped waiting during cancellation without worker control; cancellation remains engine-owned",
    );
    let outcome = if let Some(snapshot) = last
        && let Ok(raw) = serde_json::value::to_raw_value(snapshot)
    {
        CommandOutcome::failure_with_context(
            "run",
            error,
            Some(serde_json::Value::Bool(true)),
            None,
            None,
        )
        .with_raw_data(Some(raw))
    } else {
        CommandOutcome::failure_with_context(
            "run",
            error,
            Some(serde_json::Value::Bool(true)),
            None,
            Some(serde_json::json!({ "job_id": job_id })),
        )
    };
    ForegroundOutcome {
        exit_code: 17,
        outcome,
    }
}

async fn sleep_until_optional(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// Persistent Ctrl+C signal stream so first and second interrupts are never lost
/// between awaits.
struct CtrlCListener {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
    #[cfg(windows)]
    signal: tokio::signal::windows::CtrlC,
}

impl CtrlCListener {
    fn install() -> Result<Self, CommandError> {
        #[cfg(unix)]
        {
            let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| CommandError {
                    category: "internal_error",
                    message: "Failed to install interrupt signal handler",
                    exit_code: 19,
                    context: None,
                })?;
            Ok(Self { signal })
        }
        #[cfg(windows)]
        {
            let signal = tokio::signal::windows::ctrl_c().map_err(|_| CommandError {
                category: "internal_error",
                message: "Failed to install console interrupt handler",
                exit_code: 19,
                context: None,
            })?;
            Ok(Self { signal })
        }
    }

    async fn recv(&mut self) {
        let _ = self.signal.recv().await;
    }
}
