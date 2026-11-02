use dissect3d_api::{
    BootstrapAddress, DiscoveryRecord, InstallationId, InstanceId, ProcessReference,
};
use dissect3d_connection::{ReadinessError, verify_engine};
#[cfg(unix)]
use dissect3d_platform::{BootstrapEndpoint, BootstrapListener};
use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose, current_process_identity};
use std::time::Duration;
use tempfile::TempDir;

fn root_with_record(record: &DiscoveryRecord) -> (TempDir, OwnedRoot) {
    let temp = TempDir::new().expect("temporary root");
    let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    root.ensure_private_directory(&RelativePath::parse("run").expect("run path"))
        .expect("private runtime directory");
    root.write_atomic(
        &RelativePath::parse("run/endpoint.json").expect("descriptor path"),
        &serde_json::to_vec(record).expect("discovery JSON"),
    )
    .expect("publish test discovery");
    (temp, root)
}

fn valid_record() -> DiscoveryRecord {
    let process = current_process_identity().expect("test process identity");
    DiscoveryRecord {
        discovery_version: "1.0".to_owned(),
        installation_id: InstallationId::parse("ins_0123456789abcdef0123456789abcdef")
            .expect("installation id"),
        instance_id: InstanceId::parse("eng_0123456789abcdef0123456789abcdef")
            .expect("instance id"),
        base_url: "https://127.0.0.1:12345/".to_owned(),
        bootstrap_endpoint: BootstrapAddress::Unix {
            path: "/not/used/until-probed".to_owned(),
        },
        process: ProcessReference {
            pid: process.pid,
            start_marker: process.start_marker,
        },
        trust_anchor_der: vec![1],
        trust_anchor_sha256: vec![0; 32],
    }
}

#[test]
fn unsafe_discovery_is_rejected_before_native_probe() {
    let mut record = valid_record();
    record.base_url = "http://127.0.0.1:12345/".to_owned();
    let (_temp, root) = root_with_record(&record);
    assert_eq!(
        verify_engine(&root, Duration::from_millis(100)).err(),
        Some(ReadinessError::InvalidDiscovery)
    );
}

#[test]
fn wrong_process_identity_is_unavailable_and_never_ready() {
    let mut record = valid_record();
    record.process.start_marker.push_str("-stale");
    let (_temp, root) = root_with_record(&record);
    assert_eq!(
        verify_engine(&root, Duration::from_millis(100)).err(),
        Some(ReadinessError::Unavailable)
    );
}

#[test]
#[cfg(unix)]
fn wrong_installation_probe_receipt_is_incompatible() {
    use dissect3d_platform::AuthorityLease;

    let temp = TempDir::new().expect("temporary root");
    let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
        .expect("private engine root");
    let _lease = AuthorityLease::acquire(&root).expect("authority");
    let listener = BootstrapListener::bind(&root, "eng_0123456789abcdef0123456789abcdef")
        .expect("private bootstrap endpoint");
    let BootstrapEndpoint::Unix { path } = listener.endpoint() else {
        unreachable!("Unix test endpoint")
    };
    let endpoint = path.to_string_lossy().into_owned();
    let mut record = valid_record();
    record.bootstrap_endpoint = BootstrapAddress::Unix { path: endpoint };
    let descriptor = RelativePath::parse("run/endpoint.json").expect("descriptor path");
    root.write_atomic(
        &descriptor,
        &serde_json::to_vec(&record).expect("discovery JSON"),
    )
    .expect("publish discovery");
    let server = std::thread::spawn(move || {
        let mut channel = listener.accept(Duration::from_secs(1)).expect("probe peer");
        let _request = channel.read_frame().expect("probe request");
        let response = serde_json::json!({
            "bootstrap_version": "1.0",
            "installation_id": "ins_ffffffffffffffffffffffffffffffff",
            "instance_id": "eng_0123456789abcdef0123456789abcdef",
            "ready": true
        });
        channel
            .write_frame(&serde_json::to_vec(&response).expect("probe receipt"))
            .expect("write probe receipt");
    });

    assert_eq!(
        verify_engine(&root, Duration::from_secs(1)).err(),
        Some(ReadinessError::Incompatible)
    );
    server.join().expect("server thread");
}
