use dissect3d_api::decode_json;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    options: Options,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    enabled: bool,
}

#[test]
fn nested_duplicate_members_are_rejected_before_typed_decode() {
    assert!(decode_json::<Request>(br#"{"options":{"enabled":true,"enabled":false}}"#).is_err());
    assert!(
        decode_json::<serde_json::Value>(br#"{"options":{"enabled":true,"enabled":false}}"#)
            .is_err()
    );
    assert!(
        decode_json::<serde_json::Value>(
            br#"{"options":{"enabled":true},"options":{"enabled":false}}"#
        )
        .is_err()
    );
}

#[test]
fn valid_request_decodes_to_typed_values() {
    let request =
        decode_json::<Request>(br#"{"options":{"enabled":true}}"#).expect("valid request");
    assert!(request.options.enabled);
}

#[test]
fn trailing_json_is_rejected() {
    assert!(decode_json::<Request>(br#"{"options":{"enabled":true}} {}"#).is_err());
}

#[test]
fn nesting_beyond_thirty_two_levels_is_rejected() {
    let mut input = String::from("{");
    for _ in 0..33 {
        input.push_str("\"x\":{");
    }
    input.push_str("\"enabled\":true");
    for _ in 0..34 {
        input.push('}');
    }
    assert!(decode_json::<serde_json::Value>(input.as_bytes()).is_err());
}
