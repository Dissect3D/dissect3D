//! Version 1.1 local request types; no source capture or filesystem authority.
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLocalInput {
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLocalRequest {
    pub cli_request_version: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<crate::SubmittedTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub inputs: BTreeMap<String, Vec<ExecutionLocalInput>>,
    pub parameters: BTreeMap<String, SubmissionValue>,
    pub required_features: Vec<String>,
    pub evaluation_consent: bool,
    #[serde(default)]
    pub execution: ExecutionPolicy,
}

pub fn decode_execution_local_request(
    bytes: &[u8],
) -> Result<ExecutionLocalRequest, SubmissionDecodeError> {
    let fields: BTreeMap<String, SubmissionValue> = crate::decode_submission_json(bytes, 65_536)?;
    if ["task", "runtime", "variant"]
        .iter()
        .any(|key| matches!(fields.get(*key), Some(SubmissionValue::Null)))
    {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    let request: ExecutionLocalRequest = crate::decode_submission_json(bytes, 65_536)?;
    if request.cli_request_version != "1.1"
        || request
            .required_features
            .iter()
            .any(|s| s != EXECUTION_FEATURE)
        || request.required_features.len() > 1
    {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    // The constraint check needs only the reference shape, so every local
    // path maps to one canonical placeholder ID (parsed once; it always parses).
    let placeholder = crate::InputId::parse("inp_00000000000000000000000000000000")
        .map_err(|_| SubmissionDecodeError::InvalidRequest)?;
    let mut references = BTreeMap::new();
    for (role, inputs) in &request.inputs {
        if inputs.iter().any(|i| !bounded(&i.path, 32768)) {
            return Err(SubmissionDecodeError::InvalidRequest);
        }
        references.insert(
            role.clone(),
            inputs
                .iter()
                .map(|_| crate::InputRef {
                    input_id: placeholder.clone(),
                })
                .collect(),
        );
    }
    // Apply the shared closed request constraints without opening any paths.
    let wire = ExecutionJobRequest {
        request: JobRequest {
            api_version: "1.0".into(),
            support_ref: request.model.clone(),
            task: request.task.clone().unwrap_or(crate::SubmittedTask {
                id: "unspecified".into(),
                version: "1.0".into(),
            }),
            runtime_ref: request.runtime.clone(),
            variant: request.variant.clone(),
            inputs: references,
            parameters: request.parameters.clone(),
            required_features: vec![EXECUTION_FEATURE.into()],
            evaluation_consent: request.evaluation_consent,
        },
        execution: request.execution.clone(),
    };
    encode_execution_request(&wire)?;
    Ok(request)
}
