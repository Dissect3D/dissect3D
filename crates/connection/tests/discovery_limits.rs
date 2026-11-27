//! 2026-11-13 defect regression (`CS-S20`, `CSC-006`): `verify_engine` read
//! discovery records up to 65,536 bytes although the client contract caps
//! protected discovery at 16,384 bytes (`CT-CLI-SURFACE` §2).
//!
//! Each record carries a non-loopback `base_url`, so a record that is read
//! and decoded fails validation as `InvalidDiscovery` before any process or
//! native probe. A record refused at the read never reaches validation.
#![expect(
    clippy::expect_used,
    reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup"
)]
use dissect3d_api::{
    BootstrapAddress, DiscoveryRecord, InstallationId, InstanceId, MAX_DISCOVERY_BYTES,
    ProcessReference,
};
use dissect3d_connection::{ReadinessError, verify_engine};
use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose};
use std::time::Duration;
use tempfile::TempDir;

/// A rejected-by-validation record whose JSON encoding is exactly `size` bytes.
fn encoded_record(size: usize) -> Vec<u8> {
    let mut record = DiscoveryRecord {
        discovery_version: "1.0".to_owned(),
        installation_id: InstallationId::parse("ins_0123456789abcdef0123456789abcdef")
            .expect("installation id"),
        instance_id: InstanceId::parse("eng_0123456789abcdef0123456789abcdef")
            .expect("instance id"),
        base_url: "http://127.0.0.1:12345/".to_owned(),
        bootstrap_endpoint: BootstrapAddress::Unix {
            path: "/not/used".to_owned(),
        },
        process: ProcessReference {
            pid: 1,
            start_marker: String::new(),
        },
        trust_anchor_der: vec![1],
        trust_anchor_sha256: vec![0; 32],
    };
    let base = serde_json::to_vec(&record).expect("discovery JSON").len();
    record.process.start_marker = "m".repeat(size - base);
    let encoded = serde_json::to_vec(&record).expect("discovery JSON");
    assert_eq!(encoded.len(), size);
    encoded
}

fn verify_record_of(size: usize) -> Option<ReadinessError> {
    let temp = TempDir::new().expect("temporary root");
    let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    root.ensure_private_directory(&RelativePath::parse("run").expect("run path"))
        .expect("private runtime directory");
    root.write_atomic(
        &RelativePath::parse("run/endpoint.json").expect("descriptor path"),
        &encoded_record(size),
    )
    .expect("publish test discovery");
    verify_engine(&root, Duration::from_millis(100)).err()
}

#[test]
fn discovery_at_the_contract_ceiling_is_read_and_validated() {
    assert_eq!(MAX_DISCOVERY_BYTES, 16_384);
    assert_eq!(
        verify_record_of(MAX_DISCOVERY_BYTES),
        Some(ReadinessError::InvalidDiscovery)
    );
}

#[test]
fn discovery_above_the_contract_ceiling_is_refused_before_decoding() {
    // Before the fix this record was read, decoded and reached validation.
    let refused = verify_record_of(MAX_DISCOVERY_BYTES + 1);
    assert_ne!(refused, Some(ReadinessError::InvalidDiscovery));
    assert!(refused.is_some(), "an oversized record is never ready");
}
