//! Strict, lossless JSON request handling for Stage 3.

use super::JobRequest;
use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer as _, Serialize};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_JSON_DEPTH: usize = 32;
const MAX_NUMERIC_TOKEN_BYTES: usize = 64;
const MAX_SUBMISSION_VALUE_BYTES: usize = 262_144;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmissionValue {
    Null,
    Bool(bool),
    String(String),
    Integer(i64),
    Decimal(DecimalToken),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecimalToken(String);

impl DecimalToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SubmissionValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <&RawValue>::deserialize(deserializer)?;
        parse_raw_value(raw, 0, MAX_SUBMISSION_VALUE_BYTES).map_err(serde::de::Error::custom)
    }
}

impl Serialize for SubmissionValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::String(value) => serializer.serialize_str(value),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::Decimal(value) => {
                let raw =
                    RawValue::from_string(value.0.clone()).map_err(serde::ser::Error::custom)?;
                raw.serialize(serializer)
            }
            Self::Array(values) => values.serialize(serializer),
            Self::Object(values) => values.serialize(serializer),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SubmissionDecodeError {
    #[error("invalid or unsupported submission JSON")]
    InvalidJson,
    #[error("job request does not match the Stage 3 contract")]
    InvalidRequest,
}

struct ValueSeed {
    depth: usize,
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = SubmissionValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <&RawValue>::deserialize(deserializer)?;
        parse_raw_value(raw, self.depth, self.maximum).map_err(serde::de::Error::custom)
    }
}

fn parse_raw_value(
    raw: &RawValue,
    depth: usize,
    maximum: usize,
) -> Result<SubmissionValue, String> {
    let text = raw.get().trim();
    if text.len() > maximum {
        return Err("JSON value exceeds its byte limit".to_owned());
    }
    let Some(first) = text.as_bytes().first().copied() else {
        return Err("empty JSON value".to_owned());
    };
    match first {
        b'{' => {
            if depth >= MAX_JSON_DEPTH {
                return Err("JSON nesting limit exceeded".to_owned());
            }
            let mut deserializer = serde_json::Deserializer::from_str(text);
            let value = deserializer
                .deserialize_map(ObjectVisitor {
                    depth: depth + 1,
                    maximum,
                })
                .map_err(|_| "invalid JSON object".to_owned())?;
            deserializer
                .end()
                .map_err(|_| "trailing JSON data".to_owned())?;
            Ok(value)
        }
        b'[' => {
            if depth >= MAX_JSON_DEPTH {
                return Err("JSON nesting limit exceeded".to_owned());
            }
            let mut deserializer = serde_json::Deserializer::from_str(text);
            let value = deserializer
                .deserialize_seq(ArrayVisitor {
                    depth: depth + 1,
                    maximum,
                })
                .map_err(|_| "invalid JSON array".to_owned())?;
            deserializer
                .end()
                .map_err(|_| "trailing JSON data".to_owned())?;
            Ok(value)
        }
        b'"' => serde_json::from_str::<String>(text)
            .map(SubmissionValue::String)
            .map_err(|_| "invalid JSON string".to_owned()),
        b'n' if text == "null" => Ok(SubmissionValue::Null),
        b't' if text == "true" => Ok(SubmissionValue::Bool(true)),
        b'f' if text == "false" => Ok(SubmissionValue::Bool(false)),
        b'-' | b'0'..=b'9' => parse_number(text),
        _ => Err("unsupported JSON value".to_owned()),
    }
}

struct ObjectVisitor {
    depth: usize,
    maximum: usize,
}

impl<'de> Visitor<'de> for ObjectVisitor {
    type Value = SubmissionValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object with unique member names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate object member"));
            }
            let value = map.next_value_seed(ValueSeed {
                depth: self.depth,
                maximum: self.maximum,
            })?;
            values.insert(key, value);
        }
        Ok(SubmissionValue::Object(values))
    }
}

struct ArrayVisitor {
    depth: usize,
    maximum: usize,
}

impl<'de> Visitor<'de> for ArrayVisitor {
    type Value = SubmissionValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            depth: self.depth,
            maximum: self.maximum,
        })? {
            values.push(value);
        }
        Ok(SubmissionValue::Array(values))
    }
}

fn parse_number(text: &str) -> Result<SubmissionValue, String> {
    if text.len() > MAX_NUMERIC_TOKEN_BYTES {
        return Err("numeric token exceeds its byte limit".to_owned());
    }
    if text.contains('.') || text.contains('e') || text.contains('E') {
        if let Some(exponent) = text.find(['e', 'E']) {
            let exponent = text[exponent + 1..]
                .parse::<i32>()
                .map_err(|_| "decimal exponent is unsupported".to_owned())?;
            if exponent.unsigned_abs() > 308 {
                return Err("decimal exponent exceeds its limit".to_owned());
            }
        }
        Ok(SubmissionValue::Decimal(DecimalToken(text.to_owned())))
    } else {
        text.parse::<i64>()
            .map(SubmissionValue::Integer)
            .map_err(|_| "integer is outside the signed 64-bit range".to_owned())
    }
}

fn parse_root(bytes: &[u8], maximum: usize) -> Result<SubmissionValue, SubmissionDecodeError> {
    if bytes.len() > maximum {
        return Err(SubmissionDecodeError::InvalidJson);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SubmissionDecodeError::InvalidJson)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let raw = <&RawValue>::deserialize(&mut deserializer)
        .map_err(|_| SubmissionDecodeError::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| SubmissionDecodeError::InvalidJson)?;
    parse_raw_value(raw, 0, maximum).map_err(|_| SubmissionDecodeError::InvalidJson)
}

pub fn decode_job_request(bytes: &[u8]) -> Result<JobRequest, SubmissionDecodeError> {
    let value = parse_root(bytes, MAX_REQUEST_BYTES)?;
    validate_job_request(&value)?;
    serde_json::from_slice(bytes).map_err(|_| SubmissionDecodeError::InvalidRequest)
}

/// Strictly decode a bounded Stage 3 response without converting numeric
/// parameter values through `serde_json::Value` or floating point.
pub fn decode_submission_json<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, SubmissionDecodeError> {
    let strict_value = parse_root(bytes, maximum)?;
    drop(strict_value);
    serde_json::from_slice(bytes).map_err(|_| SubmissionDecodeError::InvalidRequest)
}

pub fn encode_job_request(request: &JobRequest) -> Result<Vec<u8>, SubmissionDecodeError> {
    let bytes = serde_json::to_vec(request).map_err(|_| SubmissionDecodeError::InvalidRequest)?;
    decode_job_request(&bytes)?;
    Ok(bytes)
}

fn validate_job_request(value: &SubmissionValue) -> Result<(), SubmissionDecodeError> {
    let object = as_object(value)?;
    const ALLOWED: &[&str] = &[
        "api_version",
        "support_ref",
        "task",
        "runtime_ref",
        "variant",
        "inputs",
        "parameters",
        "required_features",
        "evaluation_consent",
    ];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    if string_field(object, "api_version")? != "1.0"
        || !bounded_string(string_field(object, "support_ref")?, 1, 1024)
    {
        return Err(SubmissionDecodeError::InvalidRequest);
    }

    let task = as_object(required_field(object, "task")?)?;
    if task.len() != 2
        || !bounded_string(string_field(task, "id")?, 1, 1024)
        || !valid_task_version(string_field(task, "version")?)
    {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    if let Some(runtime) = object.get("runtime_ref")
        && !bounded_string(as_string(runtime)?, 1, 1024)
    {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    if let Some(variant) = object.get("variant")
        && !bounded_string(as_string(variant)?, 1, 128)
    {
        return Err(SubmissionDecodeError::InvalidRequest);
    }

    let inputs = as_object(required_field(object, "inputs")?)?;
    if inputs.is_empty() || inputs.len() > 16 {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    let mut occurrences = 0usize;
    for (role, role_inputs) in inputs {
        if !valid_role(role) {
            return Err(SubmissionDecodeError::InvalidRequest);
        }
        let SubmissionValue::Array(role_inputs) = role_inputs else {
            return Err(SubmissionDecodeError::InvalidRequest);
        };
        if role_inputs.is_empty() || role_inputs.len() > 64 {
            return Err(SubmissionDecodeError::InvalidRequest);
        }
        occurrences = occurrences
            .checked_add(role_inputs.len())
            .ok_or(SubmissionDecodeError::InvalidRequest)?;
        if occurrences > 64 {
            return Err(SubmissionDecodeError::InvalidRequest);
        }
        for input in role_inputs {
            let input = as_object(input)?;
            if input.len() != 1 {
                return Err(SubmissionDecodeError::InvalidRequest);
            }
            let input_id = string_field(input, "input_id")?;
            if super::InputId::parse(input_id).is_err() {
                return Err(SubmissionDecodeError::InvalidRequest);
            }
        }
    }

    as_object(required_field(object, "parameters")?)?;
    let features = required_field(object, "required_features")?;
    let SubmissionValue::Array(features) = features else {
        return Err(SubmissionDecodeError::InvalidRequest);
    };
    if features.len() > 32 {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    let mut unique_features = BTreeSet::new();
    for feature in features {
        let feature = as_string(feature)?;
        if !bounded_string(feature, 1, 128) || !unique_features.insert(feature) {
            return Err(SubmissionDecodeError::InvalidRequest);
        }
    }
    if !matches!(
        required_field(object, "evaluation_consent")?,
        SubmissionValue::Bool(_)
    ) {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    Ok(())
}

fn as_object(
    value: &SubmissionValue,
) -> Result<&BTreeMap<String, SubmissionValue>, SubmissionDecodeError> {
    match value {
        SubmissionValue::Object(object) => Ok(object),
        _ => Err(SubmissionDecodeError::InvalidRequest),
    }
}

fn as_string(value: &SubmissionValue) -> Result<&str, SubmissionDecodeError> {
    match value {
        SubmissionValue::String(value) => Ok(value),
        _ => Err(SubmissionDecodeError::InvalidRequest),
    }
}

fn required_field<'a>(
    object: &'a BTreeMap<String, SubmissionValue>,
    name: &str,
) -> Result<&'a SubmissionValue, SubmissionDecodeError> {
    object
        .get(name)
        .ok_or(SubmissionDecodeError::InvalidRequest)
}

fn string_field<'a>(
    object: &'a BTreeMap<String, SubmissionValue>,
    name: &str,
) -> Result<&'a str, SubmissionDecodeError> {
    as_string(required_field(object, name)?)
}

fn bounded_string(value: &str, minimum: usize, maximum: usize) -> bool {
    let length = value.chars().count();
    (minimum..=maximum).contains(&length)
}

fn valid_task_version(value: &str) -> bool {
    value.len() <= 32
        && value.is_ascii()
        && matches!(value.split_once('.'), Some((major, minor))
            if !major.is_empty()
                && !minor.is_empty()
                && major.bytes().all(|byte| byte.is_ascii_digit())
                && minor.bytes().all(|byte| byte.is_ascii_digit())
                && !minor.contains('.'))
}

fn valid_role(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
