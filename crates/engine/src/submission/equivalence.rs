//! Versioned submitted-request identity, kept separate from resolved defaults.

use dissect3d_api::{InputIdentity, JobRequest, SubmissionValue};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_CANONICAL_BYTES: usize = 262_144;
const FINGERPRINT_PREFIX: &[u8] = b"dissect3d-job-submission-v1\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalizationVersion {
    V1,
}

impl CanonicalizationVersion {
    pub(crate) const fn as_i64(self) -> i64 {
        match self {
            Self::V1 => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalSubmission {
    pub(crate) version: CanonicalizationVersion,
    pub(crate) bytes: Vec<u8>,
    pub(crate) fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalError {
    MissingInput,
    InvalidDecimal,
    TooLarge,
}

/// Verified engine identities replace client input IDs without changing their
/// role or list positions. The map is constructed only after ownership checks.
pub(crate) type VerifiedInputMap = BTreeMap<String, InputIdentity>;

pub(crate) fn canonicalize(
    request: &JobRequest,
    verified_inputs: &VerifiedInputMap,
) -> Result<CanonicalSubmission, CanonicalError> {
    let mut inputs = BTreeMap::new();
    for (role, references) in &request.inputs {
        let mut values = Vec::with_capacity(references.len());
        for reference in references {
            let identity = verified_inputs
                .get(reference.input_id.as_str())
                .ok_or(CanonicalError::MissingInput)?;
            values.push(object([
                (
                    "media_type",
                    string(identity.media_type.to_ascii_lowercase()),
                ),
                (
                    "byte_length",
                    value_number(SubmissionValue::Integer(
                        i64::try_from(identity.byte_length)
                            .map_err(|_| CanonicalError::TooLarge)?,
                    )),
                ),
                ("sha256", string(identity.sha256.as_str().to_owned())),
            ]));
        }
        inputs.insert(role.clone(), typed_array(values));
    }

    let mut envelope = BTreeMap::new();
    envelope.insert(
        "api_version".to_owned(),
        string(request.api_version.clone()),
    );
    envelope.insert(
        "support_ref".to_owned(),
        string(request.support_ref.clone()),
    );
    envelope.insert(
        "task".to_owned(),
        object([
            ("id", string(request.task.id.clone())),
            ("version", string(request.task.version.clone())),
        ]),
    );
    if let Some(runtime_ref) = &request.runtime_ref {
        envelope.insert("runtime_ref".to_owned(), string(runtime_ref.clone()));
    }
    if let Some(variant) = &request.variant {
        envelope.insert("variant".to_owned(), string(variant.clone()));
    }
    envelope.insert("inputs".to_owned(), object(inputs));
    envelope.insert("parameters".to_owned(), value_object(&request.parameters)?);
    envelope.insert(
        "required_features".to_owned(),
        typed_array(
            request
                .required_features
                .iter()
                .cloned()
                .map(string)
                .collect(),
        ),
    );
    envelope.insert(
        "evaluation_consent".to_owned(),
        boolean(request.evaluation_consent),
    );

    let mut bytes = Vec::new();
    encode_value(&object(envelope), &mut bytes)?;
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(CanonicalError::TooLarge);
    }
    let mut digest = Sha256::new();
    digest.update(FINGERPRINT_PREFIX);
    digest.update(&bytes);
    Ok(CanonicalSubmission {
        version: CanonicalizationVersion::V1,
        bytes,
        fingerprint: digest.finalize().into(),
    })
}

#[cfg(test)]
pub(crate) fn canonical_value(value: &SubmissionValue) -> Result<Vec<u8>, CanonicalError> {
    let mut bytes = Vec::new();
    encode_value(&value_tree(value)?, &mut bytes)?;
    Ok(bytes)
}

fn value_object(
    values: &BTreeMap<String, SubmissionValue>,
) -> Result<CanonicalTree, CanonicalError> {
    Ok(object(
        values
            .iter()
            .map(|(key, value)| Ok((key.as_str(), value_tree(value)?)))
            .collect::<Result<Vec<_>, CanonicalError>>()?,
    ))
}

fn value_tree(value: &SubmissionValue) -> Result<CanonicalTree, CanonicalError> {
    Ok(match value {
        SubmissionValue::Null => tagged("null", None),
        SubmissionValue::Bool(value) => tagged("bool", Some(boolean(*value))),
        SubmissionValue::String(value) => tagged("string", Some(string(value.clone()))),
        SubmissionValue::Integer(value) => tagged("integer", Some(string(value.to_string()))),
        SubmissionValue::Decimal(value) => {
            tagged("decimal", Some(string(normalize_decimal(value.as_str())?)))
        }
        SubmissionValue::Array(values) => typed_array(
            values
                .iter()
                .map(value_tree)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        SubmissionValue::Object(values) => value_object(values)?,
    })
}

fn normalize_decimal(token: &str) -> Result<String, CanonicalError> {
    if token.is_empty() || token.len() > 64 || !token.is_ascii() {
        return Err(CanonicalError::InvalidDecimal);
    }
    let (mantissa, exponent) = match token.find(['e', 'E']) {
        Some(index) => {
            let exponent = token[index + 1..]
                .parse::<i32>()
                .map_err(|_| CanonicalError::InvalidDecimal)?;
            (&token[..index], exponent)
        }
        None => (token, 0),
    };
    if exponent.unsigned_abs() > 308 {
        return Err(CanonicalError::InvalidDecimal);
    }
    let (negative, unsigned) = mantissa
        .strip_prefix('-')
        .map_or((false, mantissa), |rest| (true, rest));
    let (whole, fractional) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || (unsigned.contains('.') && fractional.is_empty() && !token.contains(['e', 'E']))
    {
        return Err(CanonicalError::InvalidDecimal);
    }
    let mut digits = String::with_capacity(whole.len() + fractional.len());
    digits.push_str(whole);
    digits.push_str(fractional);
    let first_nonzero = digits.bytes().position(|byte| byte != b'0');
    let Some(first_nonzero) = first_nonzero else {
        return Ok("0e0".to_owned());
    };
    let mut coefficient = digits[first_nonzero..].to_owned();
    let mut normalized_exponent = exponent
        .checked_sub(i32::try_from(fractional.len()).map_err(|_| CanonicalError::InvalidDecimal)?)
        .ok_or(CanonicalError::InvalidDecimal)?;
    while coefficient.ends_with('0') {
        coefficient.pop();
        normalized_exponent = normalized_exponent
            .checked_add(1)
            .ok_or(CanonicalError::InvalidDecimal)?;
    }
    if negative {
        coefficient.insert(0, '-');
    }
    Ok(format!("{coefficient}e{normalized_exponent}"))
}

#[derive(Clone, Debug)]
enum CanonicalTree {
    Bool(bool),
    String(String),
    Array(Vec<CanonicalTree>),
}

fn tagged(tag: &str, value: Option<CanonicalTree>) -> CanonicalTree {
    let mut values = vec![string(tag.to_owned())];
    if let Some(value) = value {
        values.push(value);
    }
    CanonicalTree::Array(values)
}

fn value_number(value: SubmissionValue) -> CanonicalTree {
    match value {
        SubmissionValue::Integer(number) => tagged("integer", Some(string(number.to_string()))),
        _ => unreachable!("internal input length is an integer"),
    }
}

fn string(value: String) -> CanonicalTree {
    CanonicalTree::String(value)
}

fn boolean(value: bool) -> CanonicalTree {
    CanonicalTree::Bool(value)
}

fn array(value: Vec<CanonicalTree>) -> CanonicalTree {
    CanonicalTree::Array(value)
}

fn typed_array(values: Vec<CanonicalTree>) -> CanonicalTree {
    array(vec![string("array".to_owned()), array(values)])
}

fn object<I, K>(pairs: I) -> CanonicalTree
where
    I: IntoIterator<Item = (K, CanonicalTree)>,
    K: Into<String>,
{
    let mut pairs = pairs
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    CanonicalTree::Array(vec![
        string("object".to_owned()),
        raw_array(
            pairs
                .into_iter()
                .map(|(key, value)| raw_array(vec![string(key), value]))
                .collect(),
        ),
    ])
}

fn raw_array(values: Vec<CanonicalTree>) -> CanonicalTree {
    CanonicalTree::Array(values)
}

fn encode_value(value: &CanonicalTree, output: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        CanonicalTree::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" })
        }
        CanonicalTree::String(value) => {
            encode_string(value, output);
        }
        CanonicalTree::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                encode_value(value, output)?;
            }
            output.push(b']');
        }
    }
    Ok(())
}

fn encode_string(value: &str, output: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            character if character <= '\u{1f}' => {
                let byte = character as u8;
                output.extend_from_slice(b"\\u00");
                output.push(HEX[(byte >> 4) as usize]);
                output.push(HEX[(byte & 0x0f) as usize]);
            }
            character => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use dissect3d_api::decode_submission_json;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct VectorCase {
        id: String,
        left: String,
        right: String,
        equivalent: bool,
    }

    #[derive(Deserialize)]
    struct Literal {
        raw: String,
        canonical_utf8: String,
    }

    #[derive(Deserialize)]
    struct Vectors {
        cases: Vec<VectorCase>,
        invalid_json: Vec<String>,
        literal_canonical: Vec<Literal>,
    }

    #[test]
    fn independent_vectors_and_literal_preimages_match_v1() {
        let vectors: Vectors = serde_json::from_str(include_str!(
            "../../../api/tests/fixtures/submission-vectors.json"
        ))
        .expect("protected vectors");
        assert_eq!(vectors.cases.len(), 12);
        for case in vectors.cases {
            let left: SubmissionValue = decode_submission_json(case.left.as_bytes(), 65_536)
                .unwrap_or_else(|_| panic!("valid left side for {}", case.id));
            let right: SubmissionValue = decode_submission_json(case.right.as_bytes(), 65_536)
                .unwrap_or_else(|_| panic!("valid right side for {}", case.id));
            assert_eq!(
                canonical_value(&left).expect("left canonical")
                    == canonical_value(&right).expect("right canonical"),
                case.equivalent,
                "equivalence expectation {}",
                case.id
            );
        }
        for invalid in vectors.invalid_json {
            assert!(decode_submission_json::<SubmissionValue>(invalid.as_bytes(), 65_536).is_err());
        }
        for literal in vectors.literal_canonical {
            let value: SubmissionValue = decode_submission_json(literal.raw.as_bytes(), 65_536)
                .expect("valid literal preimage");
            assert_eq!(
                canonical_value(&value).expect("canonical literal"),
                literal.canonical_utf8.as_bytes()
            );
        }
    }

    fn request(optional: &str, support: &str, ids: &str, parameters: &str) -> JobRequest {
        let input_id = "inp_0123456789abcdef0123456789abcdef";
        let text = format!(
            "{{\"api_version\":\"1.0\",\"support_ref\":{support},\"task\":{{\"id\":\"dissect3d.test.mesh-copy\",\"version\":\"1.0\"}},{optional}\"inputs\":{{\"mesh\":[{}]}},\"parameters\":{parameters},\"required_features\":[\"first\",\"second\"],\"evaluation_consent\":false}}",
            ids.replace("$id", input_id)
                .replace("$other", "inp_1123456789abcdef0123456789abcdef")
        );
        dissect3d_api::decode_job_request(text.as_bytes()).expect("strict request")
    }

    fn identity(input_id: &str, digest: &str) -> InputIdentity {
        InputIdentity {
            input_id: dissect3d_api::InputId::parse(input_id).expect("input ID"),
            media_type: "application/octet-stream".to_owned(),
            byte_length: 4,
            sha256: dissect3d_api::ContentDigest::parse(digest).expect("digest"),
        }
    }

    fn canonical(request: &JobRequest, input_id: &str, digest: &str) -> CanonicalSubmission {
        let mut inputs = VerifiedInputMap::new();
        inputs.insert(input_id.to_owned(), identity(input_id, digest));
        canonicalize(request, &inputs).expect("request canonicalization")
    }

    fn canonical_two(request: &JobRequest) -> CanonicalSubmission {
        let first = "inp_0123456789abcdef0123456789abcdef";
        let second = "inp_1123456789abcdef0123456789abcdef";
        let mut inputs = VerifiedInputMap::new();
        inputs.insert(first.to_owned(), identity(first, &"a".repeat(64)));
        inputs.insert(second.to_owned(), identity(second, &"b".repeat(64)));
        canonicalize(request, &inputs).expect("two-input request canonicalization")
    }

    #[test]
    fn submitted_envelope_preserves_roles_positions_aliases_omissions_and_decimal_identity() {
        let id = "inp_0123456789abcdef0123456789abcdef";
        let digest = "a".repeat(64);
        let reference = "{\"input_id\":\"$id\"}";
        let base = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            reference,
            "{\"n\":1.0}",
        );
        let reordered_parameters = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            reference,
            "{\"n\":1e0}",
        );
        assert_eq!(
            canonical(&base, id, &digest),
            canonical(&reordered_parameters, id, &digest)
        );
        let mut reversed_features = base.clone();
        reversed_features.required_features.reverse();
        assert_ne!(
            canonical(&base, id, &digest),
            canonical(&reversed_features, id, &digest)
        );
        let mut alternate_role = base.clone();
        let role_inputs = alternate_role.inputs.remove("mesh").expect("mesh role");
        alternate_role
            .inputs
            .insert("alternate".to_owned(), role_inputs);
        assert_ne!(
            canonical(&base, id, &digest),
            canonical(&alternate_role, id, &digest)
        );
        let mut consent_changed = base.clone();
        consent_changed.evaluation_consent = true;
        assert_ne!(
            canonical(&base, id, &digest),
            canonical(&consent_changed, id, &digest)
        );

        let alias = request("", "\"test.latest\"", reference, "{\"n\":1.0}");
        let explicit_default = request(
            "\"variant\":\"fixture\",",
            "\"test.mesh-copy@fixture-r1\"",
            reference,
            "{\"n\":1.0}",
        );
        assert_ne!(
            canonical(&base, id, &digest),
            canonical(&alias, id, &digest)
        );
        assert_ne!(
            canonical(&base, id, &digest),
            canonical(&explicit_default, id, &digest)
        );
        let omitted_parameter_default =
            request("", "\"test.mesh-copy@fixture-r1\"", reference, "{}");
        let explicit_parameter_default = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            reference,
            "{\"hold_before_candidate\":false}",
        );
        assert_ne!(
            canonical(&omitted_parameter_default, id, &digest),
            canonical(&explicit_parameter_default, id, &digest)
        );

        let second_occurrence = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            "{\"input_id\":\"$id\"},{\"input_id\":\"$id\"}",
            "{\"n\":1.0}",
        );
        assert_ne!(
            canonical(&base, id, &digest),
            canonical(&second_occurrence, id, &digest)
        );
        let two_ordered = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            "{\"input_id\":\"$id\"},{\"input_id\":\"$other\"}",
            "{\"n\":1.0}",
        );
        let two_reversed = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            "{\"input_id\":\"$other\"},{\"input_id\":\"$id\"}",
            "{\"n\":1.0}",
        );
        assert_ne!(canonical_two(&two_ordered), canonical_two(&two_reversed));

        let decomposed_unicode = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            reference,
            "{\"label\":\"e\\u0301\"}",
        );
        let composed_unicode = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            reference,
            "{\"label\":\"é\"}",
        );
        assert_ne!(
            canonical(&decomposed_unicode, id, &digest),
            canonical(&composed_unicode, id, &digest)
        );
        assert_eq!(CanonicalizationVersion::V1.as_i64(), 1);
    }

    #[test]
    fn canonical_byte_limit_accepts_exact_limit_and_rejects_one_more() {
        let id = "inp_0123456789abcdef0123456789abcdef";
        let digest = "a".repeat(64);
        let empty_value = request(
            "",
            "\"test.mesh-copy@fixture-r1\"",
            "{\"input_id\":\"$id\"}",
            "{\"x\":\"\"}",
        );
        let empty = canonical(&empty_value, id, &digest);
        let padding = MAX_CANONICAL_BYTES - empty.bytes.len();
        let mut exact = empty_value;
        exact
            .parameters
            .insert("x".to_owned(), SubmissionValue::String("x".repeat(padding)));
        let mut inputs = VerifiedInputMap::new();
        inputs.insert(id.to_owned(), identity(id, &digest));
        assert_eq!(
            canonicalize(&exact, &inputs)
                .expect("exact canonical byte budget")
                .bytes
                .len(),
            MAX_CANONICAL_BYTES
        );
        exact.parameters.insert(
            "x".to_owned(),
            SubmissionValue::String("x".repeat(padding + 1)),
        );
        assert_eq!(canonicalize(&exact, &inputs), Err(CanonicalError::TooLarge));
    }

    #[test]
    fn canonical_json_escapes_controls_as_lowercase_u00xx_and_preserves_unicode() {
        let value: SubmissionValue = decode_submission_json(br#""a\nb""#, 1024).expect("string");
        assert_eq!(
            canonical_value(&value).expect("encoded"),
            br#"["string","a\u000ab"]"#
        );
        let unicode: SubmissionValue =
            decode_submission_json("\"รฉ\"".as_bytes(), 1024).expect("unicode string");
        assert_eq!(
            canonical_value(&unicode).unwrap(),
            "[\"string\",\"รฉ\"]".as_bytes()
        );
    }
}
