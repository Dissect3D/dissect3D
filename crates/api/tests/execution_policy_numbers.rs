use dissect3d_api::{ExecutionPolicy, decode_execution_json};

#[test]
fn policy_uses_exact_mathematical_integers_without_float_rounding() {
    for (token, expected) in [
        ("1.0", 1),
        ("1e0", 1),
        ("10e-1", 1),
        ("0.01e2", 1),
        ("86400000.0", 86_400_000),
        ("8.64e7", 86_400_000),
    ] {
        let bytes = format!("{{\"timeout_ms\":{token}}}");
        let policy: ExecutionPolicy = decode_execution_json(bytes.as_bytes(), 65536)
            .unwrap_or_else(|error| panic!("{token}: {error:?}"));
        assert_eq!(policy.timeout_ms, Some(expected));
    }
    for token in [
        "1.0000000000000000001",
        "86399999.99999999999999999",
        "86400000.00000000000000001",
        "1e308",
        "1e-308",
        "0.0",
        "-1.0",
        "true",
        "null",
    ] {
        let bytes = format!("{{\"timeout_ms\":{token}}}");
        assert!(
            decode_execution_json::<ExecutionPolicy>(bytes.as_bytes(), 65536).is_err(),
            "{token}"
        );
    }
}
