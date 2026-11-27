//! Exercise the production typed JSON/TEXT codec without enabling numeric admission.
#![expect(
    clippy::disallowed_methods,
    reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup; \
              direct SQLite opens inspect engine state from outside the store"
)]
use dissect3d_api::{AcceptanceReceipt, ResolvedJob, decode_submission_json};

#[test]
fn resolved_numeric_parameters_survive_sqlite_text_and_receipt_codec() {
    let mut receipt: AcceptanceReceipt = decode_submission_json(
        include_bytes!("../../cli/tests/fixtures/illustrative-acceptance.json"),
        262_144,
    )
    .unwrap();
    receipt.resolved.effective_parameters = decode_submission_json(
        br#"{"integer":9007199254740993,"decimal":9007199254740993.0000000000000001,"exp":1.2300e2,"negative":-9223372036854775808,"large":1e308,"small":1e-308,"wide_decimal":123456789012345678901234567890123456789012345678901234567891e308}"#,
        262_144,
    ).unwrap();
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute("CREATE TABLE codec (resolved TEXT NOT NULL)", [])
        .unwrap();
    let encoded = serde_json::to_string(&receipt.resolved).unwrap();
    connection
        .execute("INSERT INTO codec VALUES (?1)", [&encoded])
        .unwrap();
    let stored: String = connection
        .query_row("SELECT resolved FROM codec", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, encoded);
    let decoded: ResolvedJob = decode_submission_json(stored.as_bytes(), 262_144).unwrap();
    assert_eq!(decoded, receipt.resolved);
    receipt.resolved = decoded;
    let roundtrip: AcceptanceReceipt =
        decode_submission_json(&serde_json::to_vec(&receipt).unwrap(), 262_144).unwrap();
    assert_eq!(roundtrip, receipt);
}
