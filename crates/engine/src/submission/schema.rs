//! Closed schema semantics implemented by the controlled fixture validator.

use super::admission::AdmissionError;
use dissect3d_api::{JobRequest, SubmissionValue};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn schema_for_binding<'a>(
    binding: &'a crate::support::TaskBindingRecord,
    field: &str,
) -> Result<&'a Value, AdmissionError> {
    let expected_id = match field {
        "input_schema" => "test.mesh",
        "parameter_schema" => "test.parameters",
        "output_schema" => "test.output",
        _ => return Err(AdmissionError::UnsupportedSelection),
    };
    let schema_ref = &binding.binding[field];
    binding
        .schemas
        .iter()
        .find(|schema| {
            schema.document["id"] == expected_id
                && schema.document["version"] == "1.0"
                && schema.document["id"] == schema_ref["id"]
                && schema.document["version"] == schema_ref["version"]
                && schema.sha256 == schema_ref["sha256"]
        })
        .map(|schema| &schema.document["schema"])
        .ok_or(AdmissionError::UnsupportedSelection)
}

pub(super) fn validate_known_schemas(
    input: &Value,
    parameters: &Value,
    output: &Value,
) -> Result<(), AdmissionError> {
    // This validator implements exactly these fixture schemas. Unknown keywords
    // must not silently add constraints that admission does not enforce.
    let expected_input = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": false, "required": ["mesh"],
        "properties": {"mesh": {"type": "array", "items": {"type": "string"},
            "minItems": 1, "maxItems": 1, "x-role": "mesh",
            "x-media-types": ["application/octet-stream"], "x-representations": ["obj"]}}
    });
    let expected_parameters = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": false, "required": [],
        "properties": {
            "hold_before_candidate": {"type": "boolean", "default": false},
            "fail_execution": {"type": "boolean", "default": false}}
    });
    let expected_output = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": false, "required": ["mesh"],
        "properties": {"mesh": {"type": "array", "items": {"type": "string"},
            "minItems": 1, "maxItems": 1,
            "x-output-policy": {"mandatory": true, "partial_allowed": false, "formats": ["obj"]}}}
    });
    if input != &expected_input || parameters != &expected_parameters || output != &expected_output
    {
        return Err(AdmissionError::UnsupportedSelection);
    }
    Ok(())
}

pub(super) fn resolve_parameters(
    request: &JobRequest,
    schema: &Value,
) -> Result<BTreeMap<String, SubmissionValue>, AdmissionError> {
    let properties = schema["properties"]
        .as_object()
        .ok_or(AdmissionError::UnsupportedSelection)?;
    if request
        .parameters
        .keys()
        .any(|name| !properties.contains_key(name))
    {
        return Err(AdmissionError::UnsupportedParameter);
    }
    let mut effective = request.parameters.clone();
    for (name, property) in properties {
        if let Some(value) = effective.get(name) {
            if !matches!(value, SubmissionValue::Bool(_)) {
                return Err(AdmissionError::UnsupportedParameter);
            }
        } else {
            let default = property["default"]
                .as_bool()
                .ok_or(AdmissionError::UnsupportedSelection)?;
            effective.insert(name.clone(), SubmissionValue::Bool(default));
        }
    }
    Ok(effective)
}

pub(super) fn validate_fixture_inputs(request: &JobRequest) -> Result<(), AdmissionError> {
    if request.inputs.len() != 1
        || !request.inputs.contains_key("mesh")
        || request.inputs["mesh"].len() != 1
    {
        return Err(AdmissionError::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unimplemented_constraints_in_otherwise_known_schemas() {
        let input: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/submission/input-schema.json"
        ))
        .unwrap();
        let parameters: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/submission/parameters-schema.json"
        ))
        .unwrap();
        let output: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/submission/output-schema.json"
        ))
        .unwrap();
        let (input, parameters, output) =
            (&input["schema"], &parameters["schema"], &output["schema"]);
        assert_eq!(validate_known_schemas(input, parameters, output), Ok(()));
        let mut constrained = parameters.clone();
        constrained["properties"]["fail_execution"]["const"] = Value::Bool(true);
        assert_eq!(
            validate_known_schemas(input, &constrained, output),
            Err(AdmissionError::UnsupportedSelection)
        );
        let mut constrained = input.clone();
        constrained["properties"]["mesh"]["items"]["pattern"] =
            Value::String("^restricted$".to_owned());
        assert_eq!(
            validate_known_schemas(&constrained, parameters, output),
            Err(AdmissionError::UnsupportedSelection)
        );
        let mut constrained = output.clone();
        constrained["properties"]["mesh"]["maxItems"] = Value::from(2);
        assert_eq!(
            validate_known_schemas(input, parameters, &constrained),
            Err(AdmissionError::UnsupportedSelection)
        );
    }
}
