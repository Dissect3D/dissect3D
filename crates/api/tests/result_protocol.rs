use dissect3d_api::{decode_result_manifest, validate_result_filename};
use serde_json::{Value, json};
fn example() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "fixtures/result_publication.json"
    ))
    .unwrap()["complete_mesh_copy"]
        .clone()
}
#[test]
fn accepted_manifest_roundtrips_with_exact_resolution() {
    let value = example();
    let bytes = serde_json::to_vec(&value).unwrap();
    let manifest = decode_result_manifest(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&manifest).unwrap()["provenance"]["resolved"],
        value["provenance"]["resolved"]
    );
    assert_eq!(
        decode_result_manifest(&serde_json::to_vec(&manifest).unwrap()).unwrap(),
        manifest
    );
}
#[test]
fn semantic_misbindings_external_names_and_non_copy_claims_are_rejected() {
    for (pointer, replacement) in [
        ("/required_features", json!(["unknown.feature"])),
        ("/components/0/parent_id", json!("mesh")),
        (
            "/components/0/artifact_ids/0",
            json!("art_00000000000000000000000000000000"),
        ),
        ("/components/0/local_transform/12", json!(2)),
        ("/coordinates/units", json!("meters")),
        ("/validation/copy_fidelity", json!(false)),
        (
            "/validation/findings",
            json!([{"severity":"error","code":"bad"}]),
        ),
        (
            "/materials/artifact_ids",
            json!(["art_55555555555555555555555555555555"]),
        ),
        (
            "/provenance/input_identities/0/sha256",
            json!("0".repeat(64)),
        ),
        ("/files/0/filename", json!("MANIFEST.JSON")),
        ("/files/0/filename", json!("../escape")),
        ("/files/0/byte_length", json!(0)),
        ("/files/0/mandatory", json!(false)),
        ("/components/0/local_transform/0", json!("1")),
        ("/files", json!([])),
    ] {
        let mut value = example();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            decode_result_manifest(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{pointer}"
        );
    }
}
#[test]
fn missing_nullable_unknown_and_ambiguous_json_are_rejected() {
    {
        let field = "parent_id";
        let mut v = example();
        v["components"][0].as_object_mut().unwrap().remove(field);
        assert!(decode_result_manifest(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    let mut v = example();
    v["provenance"]
        .as_object_mut()
        .unwrap()
        .remove("effective_seed");
    assert!(decode_result_manifest(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut v = example();
    v["provenance"]["resolved"]["selection"]["unexpected"] = json!(true);
    assert!(decode_result_manifest(&serde_json::to_vec(&v).unwrap()).is_err());
    for raw in [
        br#"{"job_id":"a","job_id":"b"}"#.as_slice(),
        br#"{"value":1e999}"#.as_slice(),
    ] {
        assert!(decode_result_manifest(raw).is_err());
    }
}
#[test]
fn portable_filenames_exclude_device_aliases_and_manifest_collision() {
    for bad in [
        "CON.obj",
        "lpt1.obj",
        "AUX",
        "COM0.obj",
        "mesh.",
        "manifest.json",
        "MANIFEST.JSON",
        "dir\\mesh.obj",
        "mesh:stream",
        "C:mesh.obj",
        "../x",
    ] {
        assert!(validate_result_filename(bad).is_err(), "{bad}");
    }
    assert!(validate_result_filename("mesh-1.obj").is_ok());
}

#[test]
fn exact_identity_never_rounds_a_nonidentity_matrix_into_a_copy() {
    let bytes = serde_json::to_string(&example()).unwrap();
    for matrix in [
        "[1.00000000000000001,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1]",
        "[1,0.0000000000000000000000000000000000000001e-308,0,0,0,1,0,0,0,0,1,0,0,0,0,1]",
    ] {
        let raw = bytes.replace("[1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1]", matrix);
        assert_ne!(raw, bytes);
        assert!(decode_result_manifest(raw.as_bytes()).is_err(), "{matrix}");
    }
    let raw = bytes.replace(
        "[1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1]",
        "[1.00,0e5,-0,0,0,1e0,0,0,0,0,1.0,0,0,0,0,10e-1]",
    );
    assert!(decode_result_manifest(raw.as_bytes()).is_ok());
}
#[test]
fn closed_copy_interpretation_rejects_unknown_task_and_media_semantics() {
    for field in ["id", "version"] {
        let mut value = example();
        value["provenance"]["resolved"]["selection"]["task"][field] =
            json!(if field == "version" {
                "2.0"
            } else {
                "unsupported"
            });
        assert!(
            decode_result_manifest(&serde_json::to_vec(&value).unwrap()).is_err(),
            "task {field}"
        );
    }
    let mut value = example();
    value["provenance"]["input_identities"][0]["media_type"] = json!("image/png");
    value["provenance"]["resolved"]["inputs"]["mesh"][0]["media_type"] = json!("image/png");
    assert!(decode_result_manifest(&serde_json::to_vec(&value).unwrap()).is_err());
}
