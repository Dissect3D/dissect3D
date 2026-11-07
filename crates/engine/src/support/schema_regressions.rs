// Separate SD-C03 defect regressions; protected fixture bytes remain unchanged.
fn catalog_with_parameter_schema(
    property: Value,
    definitions: Value,
) -> Result<Catalog, CatalogError> {
    let mut package = fixture_package();
    mutate_document(&mut package, "schema", "test.parameters@1.0", |doc| {
        doc["schema"]["properties"]["hold_before_candidate"] = property;
        doc["schema"]["$defs"] = definitions;
    });
    // Isolate the schema so unchanged support records do not retain its old digest.
    let position = document_position(&package, "schema", "test.parameters@1.0");
    let mut index: Value = serde_json::from_slice(&package.index_bytes).unwrap();
    index["documents"] = serde_json::json!([index["documents"][position].clone()]);
    index["aliases"] = serde_json::json!([]);
    package.index_bytes = serde_json::to_vec(&index).unwrap();
    package.document_bytes = vec![package.document_bytes[position].clone()];
    Catalog::from_packages(vec![package], DiscoveryLimits::default())
}

#[test]
fn constants_obey_all_supported_constraints() {
    for schema in [
        serde_json::json!({"type":"integer","minimum":1,"const":0}),
        serde_json::json!({"type":"number","maximum":1,"const":2}),
        serde_json::json!({"type":"string","minLength":2,"const":"a"}),
        serde_json::json!({"type":"string","maxLength":1,"const":"ab"}),
        serde_json::json!({"type":"integer","enum":[1,2],"const":3}),
        serde_json::json!({"type":"array","items":{"type":"integer"},"minItems":1,"const":[]}),
        serde_json::json!({"type":"array","items":{"type":"integer"},"maxItems":0,"const":[1]}),
        serde_json::json!({"type":"array","items":{"type":"integer"},"const":["bad"]}),
        serde_json::json!({"type":"object","properties":{"n":{"type":"integer"}},"additionalProperties":false,"required":["n"],"const":{}}),
        serde_json::json!({"type":"object","properties":{},"additionalProperties":false,"const":{"extra":1}}),
    ] {
        assert!(
            catalog_with_parameter_schema(schema.clone(), serde_json::json!({})).is_err(),
            "accepted contradictory constant: {schema}"
        );
    }
    for schema in [
        serde_json::json!({"type":"number","minimum":1,"maximum":1,"const":1}),
        serde_json::json!({"type":"string","minLength":1,"maxLength":1,"const":"\u{0E01}"}),
        serde_json::json!({"type":"array","items":{"type":"integer"},"minItems":1,"maxItems":1,"const":[1]}),
    ] {
        assert!(catalog_with_parameter_schema(schema, serde_json::json!({})).is_ok());
    }
}

#[test]
fn nested_defaults_follow_local_references() {
    let defs = serde_json::json!({
        "count":{"type":"integer","minimum":1,"maximum":3},
        "alias":{"$ref":"#/$defs/count"}
    });
    for (schema, invalid, valid) in [
        (
            serde_json::json!({"type":"object","properties":{"n":{"$ref":"#/$defs/alias"}},"additionalProperties":false,"required":["n"]}),
            serde_json::json!({"n":0}),
            serde_json::json!({"n":1}),
        ),
        (
            serde_json::json!({"type":"array","items":{"$ref":"#/$defs/alias"}}),
            serde_json::json!([4]),
            serde_json::json!([3]),
        ),
        (
            serde_json::json!({"type":"object","properties":{"n":{"$ref":"#/$defs/alias"}},"additionalProperties":false}),
            serde_json::json!({"n":"bad"}),
            serde_json::json!({"n":2}),
        ),
    ] {
        let mut property = schema.clone();
        property["default"] = invalid;
        assert!(
            catalog_with_parameter_schema(property, defs.clone()).is_err(),
            "accepted invalid referenced default: {schema}"
        );
        let mut property = schema;
        property["default"] = valid;
        assert!(catalog_with_parameter_schema(property, defs.clone()).is_ok());
    }
}

#[test]
fn referenced_value_validation_retains_safety_limits() {
    for target in [
        serde_json::json!({"$ref":"#/$defs/value"}),
        serde_json::json!({"$ref":"#/$defs/missing"}),
        serde_json::json!({"$ref":"https://example.invalid/schema"}),
    ] {
        assert!(
            catalog_with_parameter_schema(
                serde_json::json!({"type":"array","items":{"$ref":"#/$defs/value"},"default":[1]}),
                serde_json::json!({"value":target})
            )
            .is_err()
        );
    }
    for edges in [16, 17] {
        let mut defs = serde_json::Map::new();
        for i in 0..edges {
            defs.insert(
                format!("node{i}"),
                if i + 1 == edges {
                    serde_json::json!({"type":"integer"})
                } else {
                    serde_json::json!({"$ref":format!("#/$defs/node{}", i + 1)})
                },
            );
        }
        let result = catalog_with_parameter_schema(
            serde_json::json!({"type":"array","items":{"$ref":"#/$defs/node0"},"default":[1]}),
            Value::Object(defs),
        );
        assert_eq!(result.is_ok(), edges == 16, "reference edges: {edges}");
    }
}

#[test]
fn expanded_schema_containers_are_bounded_without_defaults() {
    // Root object plus 31 expanded containers is the inclusive limit.
    for mixed in [false, true] {
        for containers in [31, 32, 36] {
            let mut definitions = serde_json::Map::new();
            let chunks = (containers + 2) / 3;
            for index in 0..chunks {
                let mut schema = if index + 1 == chunks {
                    serde_json::json!({"type":"integer"})
                } else {
                    serde_json::json!({"$ref":format!("#/$defs/node{}", index + 1)})
                };
                for offset in 0..3.min(containers - index * 3) {
                    schema = if mixed && (index * 3 + offset) % 2 == 0 {
                        serde_json::json!({"type":"object","properties":{"child":schema},"additionalProperties":false})
                    } else {
                        serde_json::json!({"type":"array","items":schema})
                    };
                }
                definitions.insert(format!("node{index}"), schema);
            }
            let result = catalog_with_parameter_schema(
                serde_json::json!({"$ref":"#/$defs/node0"}),
                Value::Object(definitions),
            );
            assert_eq!(
                result.is_ok(),
                containers == 31,
                "expanded containers including root: {}, references: {chunks}, mixed: {mixed}",
                containers + 1
            );
        }
    }
}
