use dissect3d_api::*;
use serde_json::{Value, json};
fn storage() -> Value {
    json!({"api_version":"1.0","storage_contract":"rp-0.1","usage":{"retained_input_bytes":null,"published_output_bytes":null,"private_staging_bytes":null,"metadata_bytes":null},"limits":{"retained_bytes_max":17179869184u64},"measurement":{"status":"unavailable","measured_at_ms":null}})
}
#[test]
fn storage_preserves_unknowns_and_requires_freshness_and_closed_fields() {
    let mut value = storage();
    let decoded = decode_storage_snapshot(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(decoded.usage.retained_input_bytes, None);
    println!(
        "RP_SCHEMA_VECTOR storage {}",
        serde_json::to_string(&decoded).unwrap()
    );
    value["usage"]["metadata_bytes"] = json!(0);
    assert!(decode_storage_snapshot(&serde_json::to_vec(&value).unwrap()).is_err());
    value["measurement"] = json!({"status":"stale","measured_at_ms":7});
    let decoded = decode_storage_snapshot(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(decoded.measurement.measured_at_ms, Some(7));
    value["measurement"]["measured_at_ms"] = Value::Null;
    assert!(decode_storage_snapshot(&serde_json::to_vec(&value).unwrap()).is_err());
    for field in [
        "retained_input_bytes",
        "published_output_bytes",
        "private_staging_bytes",
        "metadata_bytes",
    ] {
        let mut value = storage();
        value["usage"].as_object_mut().unwrap().remove(field);
        assert!(decode_storage_snapshot(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut value = storage();
    value["usage"]["path"] = json!("private");
    assert!(decode_storage_snapshot(&serde_json::to_vec(&value).unwrap()).is_err());
}
#[test]
fn result_pages_validate_identity_uniqueness_and_required_nullable_cursor() {
    let summary = json!({"result_id":"res_11111111111111111111111111111111","job_id":"job_22222222222222222222222222222222","attempt_id":"att_33333333333333333333333333333333","published_at_ms":1,"availability":"available"});
    let mut value = json!({"api_version":"1.0","result_contract":"rp-0.1","items":[summary],"next_cursor":null,"truncated":false});
    assert!(decode_result_page(&serde_json::to_vec(&value).unwrap()).is_ok());
    let duplicate = value["items"][0].clone();
    println!(
        "RP_SCHEMA_VECTOR result_page {}",
        serde_json::to_string(&decode_result_page(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap()
    );
    value["items"].as_array_mut().unwrap().push(duplicate);
    assert!(decode_result_page(&serde_json::to_vec(&value).unwrap()).is_err());
    value["items"] = json!([]);
    value.as_object_mut().unwrap().remove("next_cursor");
    assert!(decode_result_page(&serde_json::to_vec(&value).unwrap()).is_err());
}
#[test]
fn capability_rejects_unsupported_interpretation_and_duplicate_keys() {
    let mut value = json!({"contract_version":"rp-0.1","operations":["results.list"],"limits":{"result_page_max":100},"required_features":[RESULT_FEATURE]});
    assert!(decode_result_publication_capability(&serde_json::to_vec(&value).unwrap()).is_ok());
    println!(
        "RP_SCHEMA_VECTOR capability {}",
        serde_json::to_string(
            &decode_result_publication_capability(&serde_json::to_vec(&value).unwrap()).unwrap()
        )
        .unwrap()
    );
    value["required_features"] = json!(["future"]);
    assert!(decode_result_publication_capability(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(decode_storage_snapshot(br#"{"api_version":"1.0","api_version":"1.0"}"#).is_err());
}

#[test]
fn result_page_continuation_cannot_silently_drop_remaining_members() {
    for (truncated, cursor) in [
        (true, Value::Null),
        (false, json!("cursor")),
        (true, json!("cursor")),
    ] {
        let value = json!({"api_version":"1.0","result_contract":"rp-0.1","items":[],"next_cursor":cursor,"truncated":truncated});
        assert!(decode_result_page(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn manifest_required_nulls_and_nested_closed_fields_are_interpreted() {
    let example: Value =
        serde_json::from_str(include_str!("fixtures/result_publication.json")).unwrap();
    let example = example["complete_mesh_copy"].clone();
    let manifest = decode_result_manifest(&serde_json::to_vec(&example).unwrap()).unwrap();
    println!(
        "RP_SCHEMA_VECTOR manifest {}",
        serde_json::to_string(&manifest).unwrap()
    );
    for field in [
        "assembly",
        "coordinates",
        "materials",
        "provenance",
        "validation",
    ] {
        let mut bad = example.clone();
        bad[field]["unsupported_interpretation"] = json!(true);
        assert!(decode_result_manifest(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let mut bad = example.clone();
    bad["provenance"]
        .as_object_mut()
        .unwrap()
        .remove("effective_seed");
    assert!(decode_result_manifest(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut bad = example;
    bad["components"][0]
        .as_object_mut()
        .unwrap()
        .remove("parent_id");
    assert!(decode_result_manifest(&serde_json::to_vec(&bad).unwrap()).is_err());
}
