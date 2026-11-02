use dissect3d_api::{ErrorCode, InventoryPage, TaskKey};

#[test]
fn task_key_rejects_invalid_names_and_versions() {
    for (id, version) in [
        ("", "1.0"),
        ("..", "1.0"),
        ("tsk_abc", "1.0"),
        ("has space", "1.0"),
        ("mesh", "01.0"),
        ("mesh", "65536.0"),
        ("mesh", "1"),
    ] {
        assert!(TaskKey::new(id, version).is_err(), "{id:?}@{version:?}");
    }
    assert!(TaskKey::new("dissect3d.test.mesh-copy", "1.0").is_ok());
    assert!(TaskKey::new("mesh", "0.65535").is_ok());
}

#[test]
fn inventory_page_rejects_inconsistent_continuation() {
    let valid = r#"{"api_version":"1.0","catalog_revision":"a08d0eebb9c0c86c19a40d5835de4f3c5e587203c9ead10f2a8b511a6212005e","items":[],"next_cursor":null,"truncated":false}"#;
    let page: InventoryPage<serde_json::Value> = serde_json::from_str(valid).unwrap();
    assert!(page.validate().is_ok());
    let invalid = valid.replace("\"truncated\":false", "\"truncated\":true");
    let page: InventoryPage<serde_json::Value> = serde_json::from_str(&invalid).unwrap();
    assert!(page.validate().is_err());
}

#[test]
fn discovery_errors_have_stable_wire_categories() {
    assert_eq!(
        serde_json::to_string(&ErrorCode::AmbiguousSelection).unwrap(),
        "\"ambiguous_selection\""
    );
    assert_eq!(
        serde_json::to_string(&ErrorCode::InventoryCursorExpired).unwrap(),
        "\"inventory_cursor_expired\""
    );
}

#[test]
fn task_key_deserialization_validates_both_fields() {
    assert!(serde_json::from_str::<TaskKey>(r#"{"id":"mesh","version":"1.0"}"#).is_ok());
    assert!(serde_json::from_str::<TaskKey>(r#"{"id":"mesh","version":"01.0"}"#).is_err());
    assert!(serde_json::from_str::<TaskKey>(r#"{"id":"mesh","version":"1.0","extra":1}"#).is_err());
}
