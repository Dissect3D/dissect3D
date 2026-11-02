use dissect3d_api::{EngineInfo, InstallationId, SecretToken, TimestampMs};

#[test]
fn wire_identifiers_are_validated_on_deserialization() {
    assert!(
        serde_json::from_str::<InstallationId>("\"ins_0123456789abcdef0123456789abcdef\"").is_ok()
    );
    assert!(serde_json::from_str::<InstallationId>("\"ins_not-an-id\"").is_err());
}

#[test]
fn timestamp_uses_the_signed_database_range() {
    assert!(TimestampMs::new(i64::MAX as u64).is_ok());
    assert!(TimestampMs::new(i64::MAX as u64 + 1).is_err());
    assert!(serde_json::from_str::<TimestampMs>("-1").is_err());
}

#[test]
fn token_debug_output_redacts_secret_bytes() {
    let token = SecretToken::new(vec![0x5a; 32]).expect("valid token length");
    assert_eq!(token.expose(), &[0x5a; 32]);
    assert!(!format!("{token:?}").contains("5a"));
}

#[test]
fn older_engine_info_without_optional_discovery_still_decodes() {
    let legacy = r#"{
        "api_version":"1.0",
        "engine_version":"0.1.0",
        "installation_id":"ins_0123456789abcdef0123456789abcdef",
        "instance_id":"eng_0123456789abcdef0123456789abcdef",
        "phase":"ready",
        "supported_operations":["engine.info"],
        "granted_operations":["engine.info"],
        "required_features":[],
        "limits":{},
        "platform":{"os":"macos","architecture":"aarch64"}
    }"#;
    let info: EngineInfo = dissect3d_api::decode_json(legacy.as_bytes()).unwrap();
    assert!(info.discovery.is_none());
    let encoded = serde_json::to_value(info).unwrap();
    assert!(encoded.get("discovery").is_none());
}
