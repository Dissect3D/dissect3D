//! Execution-aware local request (`cli_request_version: "1.0"` and `"1.1"`),
//! `--execution-timeout-ms` merge/conflict checks, and canonical revision-2
//! request body construction.

use super::usage_error;
use crate::args::JobDefinitionArgs;
use crate::commands::CommandError;
use dissect3d_api::{
    EXECUTION_FEATURE, ExecutionJobRequest, ExecutionPolicy, ExecutionRecord,
    ExecutionSubmissionBody, InputId, InputRef, JobRequest, SubmissionValue, SubmittedTask,
    decode_submission_json, encode_job_request,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_DEFINITION_BYTES: usize = 65_536;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalInput {
    path: PathBuf,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RawRequestFile {
    cli_request_version: String,
    model: String,
    #[serde(default)]
    task: Option<SubmittedTask>,
    #[serde(default)]
    runtime: Option<String>,
    #[serde(default)]
    variant: Option<String>,
    inputs: BTreeMap<String, Vec<LocalInput>>,
    parameters: BTreeMap<String, SubmissionValue>,
    required_features: Vec<String>,
    evaluation_consent: bool,
    #[serde(default)]
    execution: Option<ExecutionPolicy>,
}

pub(crate) struct ExecutionRequest {
    pub(crate) cli_request_version: String,
    pub(crate) model: String,
    pub(crate) task: Option<SubmittedTask>,
    pub(crate) runtime: Option<String>,
    pub(crate) variant: Option<String>,
    inputs: BTreeMap<String, Vec<LocalInput>>,
    pub(crate) parameters: BTreeMap<String, SubmissionValue>,
    pub(crate) required_features: Vec<String>,
    pub(crate) evaluation_consent: bool,
    pub(crate) execution: Option<ExecutionPolicy>,
}

pub(crate) struct OpenExecutionInput {
    pub(crate) role: String,
    pub(crate) file: std::fs::File,
    pub(crate) length: u64,
    pub(crate) media_type: &'static str,
}

/// Parse `--execution-timeout-ms` as an integer in `1..=86,400,000`.
pub(crate) fn parse_execution_timeout(raw: Option<&str>) -> Result<Option<u64>, CommandError> {
    let Some(text) = raw else {
        return Ok(None);
    };
    let value: u64 = text
        .parse()
        .map_err(|_| usage_error("--execution-timeout-ms must be an integer in 1..=86400000"))?;
    if !(1..=86_400_000).contains(&value) {
        return Err(usage_error(
            "--execution-timeout-ms must be in 1..=86400000",
        ));
    }
    Ok(Some(value))
}

/// Merge request-file `execution` policy with CLI `--execution-timeout-ms`.
/// Supplying both is a mutually exclusive `usage_error` (exit `2`).
pub(crate) fn merge_timeout(
    request_policy: Option<ExecutionPolicy>,
    cli_timeout_ms: Option<u64>,
) -> Result<ExecutionPolicy, CommandError> {
    match (request_policy, cli_timeout_ms) {
        (Some(_), Some(_)) => Err(usage_error(
            "--execution-timeout-ms conflicts with execution policy in the request file",
        )),
        (None, Some(ms)) => {
            if !(1..=86_400_000).contains(&ms) {
                return Err(usage_error(
                    "--execution-timeout-ms must be in 1..=86400000",
                ));
            }
            Ok(ExecutionPolicy {
                timeout_ms: Some(ms),
            })
        }
        (Some(policy), None) => {
            policy
                .validate()
                .map_err(|_| usage_error("execution.timeout_ms must be in 1..=86400000"))?;
            Ok(policy)
        }
        (None, None) => Ok(ExecutionPolicy::default()),
    }
}

/// Pre-config validation run in `stage3_preflight`. Never opens input files.
pub(crate) fn preflight_args(args: &JobDefinitionArgs) -> Result<(), CommandError> {
    let cli_timeout = parse_execution_timeout(args.execution_timeout_ms.as_deref())?;
    if let (Some(request_path), Some(timeout_ms)) = (&args.request, cli_timeout) {
        let cwd = std::env::current_dir()
            .map_err(|_| usage_error("Current working directory is unavailable"))?;
        let full = cwd.join(request_path);
        let file = dissect3d_platform::open_regular_file(&full)
            .map_err(|_| usage_error("Request file could not be opened"))?;
        let mut bytes = Vec::new();
        file.take(MAX_DEFINITION_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| usage_error("Request file could not be read"))?;
        let base = full
            .parent()
            .ok_or_else(|| usage_error("Request file path is invalid"))?;
        let decoded = ExecutionRequest::decode(&bytes, base)?;
        let _ = merge_timeout(decoded.execution, Some(timeout_ms))?;
    }
    Ok(())
}

impl ExecutionRequest {
    pub(crate) fn decode(bytes: &[u8], base: &Path) -> Result<Self, CommandError> {
        let fields: BTreeMap<String, SubmissionValue> =
            decode_submission_json(bytes, MAX_DEFINITION_BYTES)
                .map_err(|_| usage_error("Local job request file is invalid"))?;
        for optional in ["task", "runtime", "variant", "execution"] {
            if matches!(fields.get(optional), Some(SubmissionValue::Null)) {
                return Err(usage_error("Optional request fields cannot be null"));
            }
        }
        let raw: RawRequestFile = decode_submission_json(bytes, MAX_DEFINITION_BYTES)
            .map_err(|_| usage_error("Local job request file is invalid"))?;
        if raw.cli_request_version == "1.0" && raw.execution.is_some() {
            return Err(usage_error(
                "cli_request_version 1.0 does not allow an execution policy; use 1.1",
            ));
        }
        if !matches!(raw.cli_request_version.as_str(), "1.0" | "1.1") {
            return Err(usage_error("Unsupported cli_request_version"));
        }
        if let Some(policy) = &raw.execution {
            policy
                .validate()
                .map_err(|_| usage_error("execution.timeout_ms must be in 1..=86400000"))?;
        }
        let mut req = Self {
            cli_request_version: raw.cli_request_version,
            model: raw.model,
            task: raw.task,
            runtime: raw.runtime,
            variant: raw.variant,
            inputs: raw.inputs,
            parameters: raw.parameters,
            required_features: raw.required_features,
            evaluation_consent: raw.evaluation_consent,
            execution: raw.execution,
        };
        req.validate_and_resolve_paths(base)?;
        Ok(req)
    }

    pub(crate) fn from_args(
        args: &JobDefinitionArgs,
        cwd: &Path,
    ) -> Result<(Self, ExecutionPolicy), CommandError> {
        let cli_timeout = parse_execution_timeout(args.execution_timeout_ms.as_deref())?;
        if let Some(path) = &args.request {
            let full = cwd.join(path);
            let file = dissect3d_platform::open_regular_file(&full)
                .map_err(|_| usage_error("Request file could not be opened"))?;
            let mut bytes = Vec::new();
            file.take(MAX_DEFINITION_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| usage_error("Request file could not be read"))?;
            let base = full
                .parent()
                .ok_or_else(|| usage_error("Request file path is invalid"))?;
            let decoded = Self::decode(&bytes, base)?;
            let policy = merge_timeout(decoded.execution.clone(), cli_timeout)?;
            return Ok((decoded, policy));
        }
        let mut inputs: BTreeMap<String, Vec<LocalInput>> = BTreeMap::new();
        for input in &args.input {
            let (role, path) = input
                .split_once('=')
                .ok_or_else(|| usage_error("Input must be formatted as ROLE=PATH"))?;
            inputs
                .entry(role.into())
                .or_default()
                .push(LocalInput { path: path.into() });
        }
        let task = match (&args.task, &args.task_version) {
            (Some(id), Some(version)) => Some(SubmittedTask {
                id: id.clone(),
                version: version.clone(),
            }),
            (None, None) => None,
            _ => return Err(usage_error("Both --task and --task-version are required")),
        };
        let parameters = match &args.parameters_json {
            Some(text) => decode_submission_json(text.as_bytes(), MAX_DEFINITION_BYTES)
                .map_err(|_| usage_error("--parameters-json must be a valid JSON object"))?,
            None => BTreeMap::new(),
        };
        let mut req = Self {
            cli_request_version: "1.0".into(),
            model: args
                .model
                .clone()
                .ok_or_else(|| usage_error("Either --request or --model is required"))?,
            task,
            runtime: args.runtime.clone(),
            variant: args.variant.clone(),
            inputs,
            parameters,
            required_features: Vec::new(),
            evaluation_consent: false,
            execution: None,
        };
        req.validate_and_resolve_paths(cwd)?;
        let policy = merge_timeout(None, cli_timeout)?;
        Ok((req, policy))
    }

    pub(crate) fn requires_execution_contract(&self, cli_timeout_ms: Option<&str>) -> bool {
        self.cli_request_version == "1.1"
            || self.execution.is_some()
            || cli_timeout_ms.is_some()
            || self
                .required_features
                .iter()
                .any(|feature| feature == EXECUTION_FEATURE)
    }

    pub(crate) fn select_task(
        &self,
        declared: &[SubmittedTask],
    ) -> Result<SubmittedTask, CommandError> {
        if let Some(task) = &self.task {
            return Ok(task.clone());
        }
        match declared {
            [task] => Ok(task.clone()),
            _ => Err(usage_error("Specify --task and --task-version")),
        }
    }

    pub(crate) fn validate_selected_task(&self, task: SubmittedTask) -> Result<(), CommandError> {
        let placeholder = InputId::parse(format!("inp_{}", "0".repeat(32)))
            .map_err(|_| usage_error("Invalid job request"))?;
        let inputs = self
            .inputs
            .iter()
            .map(|(role, list)| {
                (
                    role.clone(),
                    list.iter()
                        .map(|_| InputRef {
                            input_id: placeholder.clone(),
                        })
                        .collect(),
                )
            })
            .collect();
        let request = JobRequest {
            api_version: "1.0".into(),
            support_ref: self.model.clone(),
            task,
            runtime_ref: self.runtime.clone(),
            variant: self.variant.clone(),
            inputs,
            parameters: self.parameters.clone(),
            required_features: self.required_features.clone(),
            evaluation_consent: self.evaluation_consent,
        };
        encode_job_request(&request).map_err(|_| usage_error("Invalid job request"))?;
        Ok(())
    }

    /// Validate that `required_features` is compatible with negotiated `we-0.1`
    /// before opening or uploading any local input files.
    pub(crate) fn validate_execution_features(&self) -> Result<(), CommandError> {
        if self.required_features.is_empty()
            || self.required_features.as_slice() == [EXECUTION_FEATURE]
        {
            Ok(())
        } else {
            Err(usage_error("Unsupported required_features for we-0.1"))
        }
    }

    pub(crate) fn open_inputs(&self) -> Result<Vec<OpenExecutionInput>, CommandError> {
        let mut opened = Vec::new();
        let mut total = 0u64;
        for (role, inputs) in &self.inputs {
            for input in inputs {
                let file = dissect3d_platform::open_regular_file(&input.path)
                    .map_err(|_| usage_error("Input file could not be opened"))?;
                let length = file
                    .metadata()
                    .map_err(|_| usage_error("Input file metadata is unavailable"))?
                    .len();
                total = total
                    .checked_add(length)
                    .ok_or_else(|| usage_error("Input size exceeds limit"))?;
                if !(1..=268_435_456).contains(&length) || total > 1_073_741_824 {
                    return Err(usage_error("Input size is outside allowed bounds"));
                }
                opened.push(OpenExecutionInput {
                    role: role.clone(),
                    file,
                    length,
                    media_type: "application/octet-stream",
                });
            }
        }
        Ok(opened)
    }

    pub(crate) fn to_execution_body(
        &self,
        task: SubmittedTask,
        inputs: BTreeMap<String, Vec<InputRef>>,
        execution: ExecutionPolicy,
    ) -> Result<ExecutionSubmissionBody, CommandError> {
        let mut features = self.required_features.clone();
        if features.is_empty() {
            features.push(EXECUTION_FEATURE.to_owned());
        } else if features.as_slice() != [EXECUTION_FEATURE] {
            return Err(usage_error("Unsupported required_features for we-0.1"));
        }
        let request = ExecutionJobRequest {
            request: JobRequest {
                api_version: "1.0".into(),
                support_ref: self.model.clone(),
                task,
                runtime_ref: self.runtime.clone(),
                variant: self.variant.clone(),
                inputs,
                parameters: self.parameters.clone(),
                required_features: features,
                evaluation_consent: self.evaluation_consent,
            },
            execution,
        };
        ExecutionSubmissionBody::fresh(&request)
            .map_err(|_| usage_error("Execution job request is invalid"))
    }

    fn validate_and_resolve_paths(&mut self, base: &Path) -> Result<(), CommandError> {
        if !base.is_absolute() {
            return Err(usage_error("Base path must be absolute"));
        }
        self.validate_selected_task(self.task.clone().unwrap_or(SubmittedTask {
            id: "omitted".into(),
            version: "1.0".into(),
        }))?;
        for input in self.inputs.values_mut().flatten() {
            let text = input
                .path
                .to_str()
                .ok_or_else(|| usage_error("Input path is invalid"))?;
            if text.is_empty() || text.chars().count() > 32768 || text.contains('\0') {
                return Err(usage_error("Input path is invalid"));
            }
            input.path = base.join(&input.path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_1_1(execution: Option<serde_json::Value>) -> Vec<u8> {
        let mut obj = serde_json::json!({
            "cli_request_version": "1.1",
            "model": "test.mesh-copy@fixture-r2",
            "task": {"id": "dissect3d.test.mesh-copy", "version": "1.0"},
            "runtime": "test.cpu@fixture-r2",
            "variant": "fixture",
            "inputs": {"mesh": [{"path": "tetra.obj"}]},
            "parameters": {},
            "required_features": ["job_execution.we-0.1"],
            "evaluation_consent": false,
        });
        if let Some(exec) = execution {
            obj["execution"] = exec;
        }
        serde_json::to_vec(&obj).expect("encode sample")
    }

    fn base_dir() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn decodes_1_1_request_and_rejects_null_execution() {
        let decoded = ExecutionRequest::decode(
            &sample_1_1(Some(serde_json::json!({"timeout_ms": 5000}))),
            &base_dir(),
        )
        .ok()
        .expect("valid 1.1 request");
        assert_eq!(decoded.cli_request_version, "1.1");
        assert_eq!(
            decoded.execution,
            Some(ExecutionPolicy {
                timeout_ms: Some(5000)
            })
        );

        let err = ExecutionRequest::decode(&sample_1_1(Some(serde_json::Value::Null)), &base_dir())
            .err()
            .expect("null execution must be rejected");
        assert_eq!(err.exit_code, 2);
        assert_eq!(err.category, "usage_error");

        let dup_features = serde_json::to_vec(&serde_json::json!({
            "cli_request_version": "1.0",
            "model": "test.mesh-copy@fixture-r1",
            "inputs": {"mesh": [{"path": "tetra.obj"}]},
            "parameters": {},
            "required_features": ["dup", "dup"],
            "evaluation_consent": false,
        }))
        .expect("encode dup");
        let dup_err = ExecutionRequest::decode(&dup_features, &base_dir())
            .err()
            .expect("duplicate required_features must fail locally");
        assert_eq!(dup_err.exit_code, 2);
        assert_eq!(dup_err.category, "usage_error");
    }

    #[test]
    fn merge_timeout_rejects_conflict_and_out_of_range() {
        let conflict = merge_timeout(
            Some(ExecutionPolicy {
                timeout_ms: Some(5000),
            }),
            Some(10000),
        )
        .expect_err("conflict must fail");
        assert_eq!(conflict.exit_code, 2);
        assert_eq!(conflict.category, "usage_error");

        let empty_conflict = merge_timeout(Some(ExecutionPolicy::default()), Some(10000))
            .expect_err("empty execution object still conflicts with CLI flag");
        assert_eq!(empty_conflict.exit_code, 2);

        for bad in [0, 86_400_001] {
            let err = merge_timeout(None, Some(bad)).expect_err("out-of-range timeout must fail");
            assert_eq!(err.exit_code, 2);
        }
        assert_eq!(
            merge_timeout(None, Some(1)).ok(),
            Some(ExecutionPolicy {
                timeout_ms: Some(1)
            })
        );
        assert_eq!(
            merge_timeout(None, Some(86_400_000)).ok(),
            Some(ExecutionPolicy {
                timeout_ms: Some(86_400_000)
            })
        );
    }

    #[test]
    fn revision_2_body_normalizes_absent_and_empty_execution_identically() {
        let absent = ExecutionRequest::decode(&sample_1_1(None), &base_dir())
            .ok()
            .expect("absent");
        let empty = ExecutionRequest::decode(&sample_1_1(Some(serde_json::json!({}))), &base_dir())
            .ok()
            .expect("empty");
        let task = SubmittedTask {
            id: "dissect3d.test.mesh-copy".into(),
            version: "1.0".into(),
        };
        let input_id = InputId::parse("inp_0123456789abcdef0123456789abcdef").expect("input id");
        let mut inputs = BTreeMap::new();
        inputs.insert("mesh".to_owned(), vec![InputRef { input_id }]);

        let p1 = merge_timeout(absent.execution.clone(), None)
            .ok()
            .expect("p1");
        let p2 = merge_timeout(empty.execution.clone(), None)
            .ok()
            .expect("p2");
        let b1 = absent
            .to_execution_body(task.clone(), inputs.clone(), p1)
            .ok()
            .expect("b1");
        let b2 = empty.to_execution_body(task, inputs, p2).ok().expect("b2");
        assert_eq!(b1.as_bytes(), b2.as_bytes());
    }
}
