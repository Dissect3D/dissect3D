use dissect3d_api::{DeclarationValue, SubmissionValue, decode_json, decode_submission_json};

#[test]
fn declaration_decoder_preserves_numeric_lexemes_and_literal_private_maps() {
    let raw = br#"{"n":9007199254740993.0000000000000001,"literal":{"$serde_json::private::Number":"123","other":true},"raw":{"$serde_json::private::RawValue":"123"}}"#;
    let value: DeclarationValue = decode_json(raw).unwrap();
    assert_eq!(
        value["n"].as_number().unwrap().as_str(),
        "9007199254740993.0000000000000001"
    );
    assert!(value["literal"].is_object());
    assert_eq!(value["literal"]["$serde_json::private::Number"], "123");
    assert_eq!(value["raw"]["$serde_json::private::RawValue"], "123");
    let again: DeclarationValue = decode_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(again, value);
    // The existing core Value decoder retains its ordinary object behavior too.
    let core: serde_json::Value = decode_json(raw).unwrap();
    assert!(core["literal"].is_object());
}

#[test]
fn declaration_decoder_keeps_duplicate_depth_and_finite_guards() {
    for raw in [
        r#"{"n":1,"n":2}"#,
        r#"{"nested":{"n":1,"n":2}}"#,
        r#"{"n":1e309}"#,
        r#"{"n":NaN}"#,
        r#"{"n":1} true"#,
        r#"{"n":1e-999999999999999999999999999}"#,
    ] {
        assert!(
            decode_json::<DeclarationValue>(raw.as_bytes()).is_err(),
            "{raw}"
        );
    }
    let nested = |n| format!("{}1{}", "[".repeat(n), "]".repeat(n));
    assert!(decode_json::<DeclarationValue>(nested(32).as_bytes()).is_ok());
    assert!(decode_json::<DeclarationValue>(nested(33).as_bytes()).is_err());
    // Discovery has finite-number/document limits, not submission's exponent limit.
    let small: DeclarationValue = decode_json(b"1e-999").unwrap();
    let zero: DeclarationValue = decode_json(b"0").unwrap();
    assert_eq!(
        small
            .as_number()
            .unwrap()
            .compare(zero.as_number().unwrap()),
        Some(std::cmp::Ordering::Greater)
    );
}

#[test]
fn submission_limits_and_typed_numeric_identity_are_unchanged() {
    for token in [
        "9007199254740993",
        "-9223372036854775808",
        "9223372036854775807",
        "9007199254740993.0000000000000001",
        "1.2300e2",
        "1e308",
        "1e-308",
    ] {
        let value: SubmissionValue = decode_submission_json(token.as_bytes(), 1024).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), token);
    }
    for token in [
        "9223372036854775808",
        "18446744073709551615",
        "-9223372036854775809",
        "1e309",
        "1e-309",
    ] {
        assert!(decode_submission_json::<SubmissionValue>(token.as_bytes(), 1024).is_err());
    }
    let at_limit = format!("0.{}1", "0".repeat(61));
    assert_eq!(at_limit.len(), 64);
    assert!(decode_submission_json::<SubmissionValue>(at_limit.as_bytes(), 1024).is_ok());
    assert!(
        decode_submission_json::<SubmissionValue>(format!("{at_limit}1").as_bytes(), 1024).is_err()
    );
}
