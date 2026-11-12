#[test]
fn exact_numeric_canonicalization_keeps_boundaries_and_decimal_identity() {
    for (token, expected) in [
        ("9007199254740992", r#"["integer","9007199254740992"]"#),
        ("9007199254740993", r#"["integer","9007199254740993"]"#),
        (
            "-9223372036854775808",
            r#"["integer","-9223372036854775808"]"#,
        ),
        (
            "9223372036854775807",
            r#"["integer","9223372036854775807"]"#,
        ),
        (
            "9007199254740993.0000000000000001",
            r#"["decimal","90071992547409930000000000000001e-16"]"#,
        ),
        ("1.2300e2", r#"["decimal","123e0"]"#),
        ("123.0", r#"["decimal","123e0"]"#),
        ("-0.0e308", r#"["decimal","0e0"]"#),
        ("1e-308", r#"["decimal","1e-308"]"#),
    ] {
        let value: SubmissionValue = decode_submission_json(token.as_bytes(), 1024).unwrap();
        assert_eq!(canonical_value(&value).unwrap(), expected.as_bytes());
    }
}
