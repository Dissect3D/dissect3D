mod numeric_regressions {
    use super::*;

    #[test]
    fn long_decimal_detail_budgets_count_lossless_bytes() {
        let property = |zeros| format!(r#"{{"type":"number","default":0.{}1}}"#, "0".repeat(zeros));
        assert!(catalog(&property(180_000)).is_ok());
        assert_eq!(
            catalog(&property(196_000)).unwrap_err(),
            CatalogError::LimitExceeded
        );
    }

    fn catalog(property: &str) -> Result<Catalog, CatalogError> {
        let mut package = fixture_package();
        let position = document_position(&package, "schema", "test.parameters@1.0");
        let mut document: Value =
            serde_json::from_slice(&package.document_bytes[position]).unwrap();
        document["schema"]["properties"]["hold_before_candidate"] =
            Value::String("NUMERIC_PROPERTY".into());
        let bytes = serde_json::to_string(&document)
            .unwrap()
            .replace("\"NUMERIC_PROPERTY\"", property)
            .into_bytes();
        let hash = digest(&bytes);
        replace_document(&mut package, position, bytes);
        for reference in [
            "test.mesh-copy",
            "test.mask",
            "test.count",
            "test.segment",
            "test.complete",
        ] {
            mutate_document(
                &mut package,
                "support",
                &format!("{reference}@fixture-r1"),
                |doc| {
                    for task in doc["tasks"].as_array_mut().unwrap() {
                        if task["parameter_schema"]["id"] == "test.parameters" {
                            task["parameter_schema"]["sha256"] = Value::String(hash.clone());
                        }
                    }
                },
            );
        }
        Catalog::from_packages(vec![package], DiscoveryLimits::default())
    }

    #[test]
    fn integer_bounds_never_round_adjacent_values() {
        for (below, boundary, above) in [
            ("9007199254740991", "9007199254740992", "9007199254740993"),
            ("9007199254740992", "9007199254740993", "9007199254740994"),
            (
                "-9007199254740994",
                "-9007199254740993",
                "-9007199254740992",
            ),
            (
                "9223372036854775806",
                "9223372036854775807",
                "9223372036854775808",
            ),
            (
                "18446744073709551613",
                "18446744073709551614",
                "18446744073709551615",
            ),
            (
                "-9223372036854775808",
                "-9223372036854775807",
                "-9223372036854775806",
            ),
            ("-1", "0", "1"),
        ] {
            for field in ["default", "const"] {
                assert!(catalog(&format!(r#"{{"type":"integer","minimum":{boundary},"maximum":{boundary},"{field}":{boundary}}}"#)).is_ok());
                for rejected in [below, above] {
                    assert!(catalog(&format!(r#"{{"type":"integer","minimum":{boundary},"maximum":{boundary},"{field}":{rejected}}}"#)).is_err(), "{field}: {rejected} != {boundary}");
                }
            }
        }
    }

    #[test]
    fn inverted_numeric_bounds_are_exact() {
        for (min, max) in [
            ("9007199254740993", "9007199254740992"),
            ("-9007199254740992", "-9007199254740993"),
            ("1.0000000000000001", "1.0"),
            ("9007199254740993e0", "9007199254740992.0"),
        ] {
            assert!(
                catalog(&format!(
                    r#"{{"type":"number","minimum":{min},"maximum":{max}}}"#
                ))
                .is_err(),
                "inverted {min} > {max}"
            );
        }
    }

    #[test]
    fn decimal_bounds_and_equality_retain_exact_meaning() {
        for (boundary, equal, below, above) in [
            (
                "9007199254740993.0",
                "90071992547409930e-1",
                "9007199254740992.0",
                "9007199254740994e0",
            ),
            (
                "1.2300e2",
                "123.0",
                "122.999999999999999999",
                "123.000000000000000001",
            ),
            (
                "-0.0001",
                "-1e-4",
                "-0.00010000000000000001",
                "-0.00009999999999999999",
            ),
            ("1e-308", "10e-309", "0.1e-308", "1.1e-308"),
        ] {
            assert!(catalog(&format!(r#"{{"type":"number","minimum":{boundary},"maximum":{boundary},"const":{equal},"enum":[{equal}],"default":{boundary}}}"#)).is_ok(), "equal {boundary} {equal}");
            for rejected in [below, above] {
                assert!(catalog(&format!(r#"{{"type":"number","minimum":{boundary},"maximum":{boundary},"default":{rejected}}}"#)).is_err(), "unequal {boundary} {rejected}");
                assert!(
                    catalog(&format!(
                        r#"{{"type":"number","const":{boundary},"default":{rejected}}}"#
                    ))
                    .is_err()
                );
                assert!(
                    catalog(&format!(
                        r#"{{"type":"number","enum":[{boundary}],"default":{rejected}}}"#
                    ))
                    .is_err()
                );
            }
        }
        assert!(
            catalog(r#"{"type":"number","enum":[1.0,1e0]}"#).is_err(),
            "duplicate decimal meaning"
        );
        assert!(
            catalog(r#"{"type":"number","const":1,"default":1.0}"#).is_err(),
            "integer/decimal distinction"
        );
        assert!(catalog(r#"{"type":"integer","default":1e0}"#).is_err());
        assert!(catalog(r#"{"type":"number","minimum":-1,"maximum":18446744073709551615,"default":9223372036854775808}"#).is_ok());
    }

    #[test]
    fn discovery_numeric_output_preserves_tokens_and_unknown_objects() {
        let catalog = catalog(r#"{"type":"number","default":9007199254740993.0000000000000001,"x-future":{"$serde_json::private::Number":"123"}}"#).unwrap();
        let model = catalog.model("test.mesh-copy@fixture-r1").unwrap();
        let schema = model
            .schemas
            .iter()
            .find(|schema| schema.document["id"] == "test.parameters")
            .unwrap();
        let encoded = serde_json::to_string(schema).unwrap();
        assert!(
            encoded.contains("9007199254740993.0000000000000001"),
            "{encoded}"
        );
        assert!(encoded.contains(r#""$serde_json::private::Number":"123""#));
        assert!(!model.tasks[0].unresolved_paths.is_empty());
    }
}
