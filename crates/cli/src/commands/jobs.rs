//! One-page private inspection through the shared engine client.

use super::execution::{ExecutionMode, detect_mode, execution_client_error};
use crate::args::JobsCommand;
use crate::config::ConfigFile;
use dissect3d_api::{ClientLimits, JobId, JobsQuery};
use std::path::Path;

pub(crate) fn inspect(
    command: JobsCommand,
    config: &ConfigFile,
    path: &Path,
    limits: ClientLimits,
) -> Result<Box<serde_json::value::RawValue>, super::CommandError> {
    super::discovery::connected(config, path, limits, |client| {
        let runtime = super::tokio_runtime();
        let mode = runtime.block_on(detect_mode(&client))?;
        let raw = match (mode, command) {
            (
                ExecutionMode::Negotiated {
                    capability,
                    granted_operations,
                },
                JobsCommand::List { limit, cursor },
            ) => {
                super::execution::require_execution_ops(
                    &capability,
                    &granted_operations,
                    &["jobs.list"],
                )?;
                let page = runtime
                    .block_on(client.execution_jobs_with(&capability, JobsQuery { limit, cursor }))
                    .map_err(execution_client_error)?;
                serde_json::value::to_raw_value(&page)
            }
            (
                ExecutionMode::Negotiated {
                    capability,
                    granted_operations,
                },
                JobsCommand::Show { job_id },
            ) => {
                super::execution::require_execution_ops(
                    &capability,
                    &granted_operations,
                    &["jobs.show"],
                )?;
                let id = JobId::parse(job_id)
                    .map_err(|_| super::execution::usage_error("Job ID is invalid"))?;
                let job = runtime
                    .block_on(client.execution_job_with(&capability, &id))
                    .map_err(execution_client_error)?;
                serde_json::value::to_raw_value(&job)
            }
            (ExecutionMode::Stage3, JobsCommand::List { limit, cursor }) => {
                let page = runtime
                    .block_on(client.jobs(JobsQuery { limit, cursor }))
                    .map_err(error)?;
                serde_json::value::to_raw_value(&page)
            }
            (ExecutionMode::Stage3, JobsCommand::Show { job_id }) => {
                let id = JobId::parse(job_id).map_err(|_| super::invalid_error())?;
                let job = runtime.block_on(client.job(&id)).map_err(error)?;
                serde_json::value::to_raw_value(&job)
            }
            _ => return Err(super::invalid_error()),
        };
        raw.map_err(|_| super::invalid_error())
    })
}

fn error(problem: dissect3d_api::ClientError) -> super::CommandError {
    let mut problem = super::submission::before_client_error(problem);
    if let Some(context) = &mut problem.context {
        context.accepted = None;
    }
    problem
}
