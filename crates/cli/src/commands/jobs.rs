//! One-page private inspection through the shared engine client.

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
        let raw = match command {
            JobsCommand::List { limit, cursor } => {
                let page = runtime
                    .block_on(client.jobs(JobsQuery { limit, cursor }))
                    .map_err(error)?;
                serde_json::value::to_raw_value(&page)
            }
            JobsCommand::Show { job_id } => {
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
