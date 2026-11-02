use dissect3d_api::{ClientId, EnrollmentReceipt, TokenDigest, decode_json};
use dissect3d_engine::{CorePolicy, Store, serve_bootstrap_once};
use dissect3d_platform::{
    AuthorityLease, BootstrapListener, OwnedRoot, RootPurpose, connect_bootstrap,
    current_owner_identity,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tempfile::TempDir;

const ENROLLMENT: &str = "enr_0123456789abcdef0123456789abcdef";
const CLIENT: &str = "cli_0123456789abcdef0123456789abcdef";
const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeReceipt {
    bootstrap_version: String,
    installation_id: String,
    instance_id: String,
    ready: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapError {
    bootstrap_version: String,
    error: String,
}

fn request(kind: &str, installation_id: &str, instance_id: &str, secret: &str) -> Vec<u8> {
    format!(
        "{{\"bootstrap_version\":\"1.0\",\"kind\":\"{kind}\",\"installation_id\":\"{installation_id}\",\"instance_id\":\"{instance_id}\",\"enrollment_id\":\"{ENROLLMENT}\",\"client_id\":\"{CLIENT}\",\"client_kind\":\"cli\",\"secret_hex\":\"{secret}\"}}"
    )
    .into_bytes()
}

fn digest_secret(secret: &str) -> TokenDigest {
    let mut bytes = [0_u8; 32];
    for (index, pair) in secret.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(pair).expect("ASCII hex pair");
        bytes[index] = u8::from_str_radix(text, 16).expect("hex secret");
    }
    let hash = Sha256::digest(bytes);
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&hash);
    TokenDigest::new(digest)
}

#[test]
fn probe_reports_the_ready_store_identity_without_enrollment_fields() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("metadata store");
    let expected = store.identity().expect("store identity");
    let listener_root =
        OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("listener root");
    let listener = BootstrapListener::bind(&listener_root, expected.instance_id.as_str())
        .expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("owner identity");
    let server = std::thread::spawn(move || {
        serve_bootstrap_once(&listener, &store, Duration::from_secs(2))
            .expect("serve readiness probe");
        store
    });

    let mut client = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("verified engine owner");
    client
        .write_frame(
            format!(
                "{{\"bootstrap_version\":\"1.0\",\"kind\":\"probe\",\"instance_id\":\"{}\"}}",
                expected.instance_id.as_str()
            )
            .as_bytes(),
        )
        .expect("send probe");
    let receipt: ProbeReceipt =
        decode_json(&client.read_frame().expect("probe response")).expect("strict probe receipt");
    assert_eq!(receipt.bootstrap_version, "1.0");
    assert_eq!(receipt.installation_id, expected.installation_id.as_str());
    assert_eq!(receipt.instance_id, expected.instance_id.as_str());
    assert!(receipt.ready);
    drop(client);
    drop(server.join().expect("server thread"));
}

#[test]
fn lost_enrollment_receipt_can_be_replayed_after_durable_commit() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("metadata store");
    let identity = store.identity().expect("store identity");
    let installation_id = identity.installation_id;
    let instance_id = identity.instance_id;
    let listener_root =
        OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("listener root");
    let listener =
        BootstrapListener::bind(&listener_root, instance_id.as_str()).expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("owner identity");
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            serve_bootstrap_once(&listener, &store, Duration::from_secs(2))
                .expect("serve enrollment attempt");
        }
        store
    });

    let mut first = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("first verified connection");
    first
        .write_frame(&request(
            "enroll",
            installation_id.as_str(),
            instance_id.as_str(),
            SECRET,
        ))
        .expect("submit enrollment");
    // Simulate the CLI losing the receipt before it can save enrollment state.
    // The engine has completed its response, while the caller deliberately
    // discards the bytes and retries with the same durable identity.
    let _discarded_receipt = first.read_frame().expect("committed receipt");
    drop(first);

    let mut retry = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("replay verified connection");
    retry
        .write_frame(&request(
            "enroll",
            installation_id.as_str(),
            instance_id.as_str(),
            SECRET,
        ))
        .expect("replay enrollment");
    let receipt: EnrollmentReceipt = decode_json(&retry.read_frame().expect("replay receipt"))
        .expect("strict enrollment receipt");
    assert!(receipt.replayed);
    assert_eq!(receipt.installation_id, installation_id);
    assert_eq!(receipt.client_id.as_str(), CLIENT);
    assert_eq!(receipt.enrollment_id.as_str(), ENROLLMENT);
    drop(retry);
    drop(server.join().expect("server thread"));
}

#[test]
fn changed_secret_conflicts_without_reflecting_secret_and_revoked_identity_stays_revoked() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("metadata store");
    let identity = store.identity().expect("store identity");
    let installation_id = identity.installation_id;
    let instance_id = identity.instance_id;
    let listener_root =
        OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("listener root");
    let listener =
        BootstrapListener::bind(&listener_root, instance_id.as_str()).expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("owner identity");
    let server = std::thread::spawn(move || {
        // The first caller deliberately closes before reading the receipt.
        let _ = serve_bootstrap_once(&listener, &store, Duration::from_secs(2));
        serve_bootstrap_once(&listener, &store, Duration::from_secs(2))
            .expect("serve changed-secret attempt");
        let context = store
            .authenticate(
                ClientId::parse(CLIENT).expect("client id"),
                digest_secret(SECRET),
            )
            .expect("authenticate enrollment before revocation");
        store.revoke_self(context).expect("durable revocation");
        serve_bootstrap_once(&listener, &store, Duration::from_secs(2))
            .expect("serve revoked replay");
        store
    });

    let mut first = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("first verified connection");
    first
        .write_frame(&request(
            "enroll",
            installation_id.as_str(),
            instance_id.as_str(),
            SECRET,
        ))
        .expect("submit enrollment");
    let receipt: EnrollmentReceipt =
        decode_json(&first.read_frame().expect("receipt")).expect("strict enrollment receipt");
    drop(first);

    let changed_secret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let mut changed = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("changed-secret connection");
    changed
        .write_frame(&request(
            "enroll",
            installation_id.as_str(),
            instance_id.as_str(),
            changed_secret,
        ))
        .expect("submit changed secret");
    let response = changed.read_frame().expect("safe conflict response");
    let error: BootstrapError = decode_json(&response).expect("strict safe error");
    assert_eq!(error.bootstrap_version, "1.0");
    assert_eq!(error.error, "conflict");
    assert!(!String::from_utf8_lossy(&response).contains(changed_secret));
    drop(changed);

    // The server revokes the credential after the conflicting attempt and
    // then processes the final exact replay against the durable tombstone.
    let mut replay =
        connect_bootstrap(&endpoint, &owner, Duration::from_secs(2)).expect("replay connection");
    replay
        .write_frame(&request(
            "enroll",
            installation_id.as_str(),
            instance_id.as_str(),
            SECRET,
        ))
        .expect("replay request");
    let response = replay.read_frame().expect("safe revoked response");
    let error: BootstrapError = decode_json(&response).expect("strict safe error");
    assert_eq!(error.error, "unauthorized");
    assert_eq!(receipt.client_id.as_str(), CLIENT);
    drop(replay);
    drop(server.join().expect("server thread"));
}

#[test]
fn bootstrap_decoder_rejects_duplicate_and_unknown_request_members() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("metadata store");
    let instance_id = store.identity().expect("store identity").instance_id;
    let listener_root =
        OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("listener root");
    let listener =
        BootstrapListener::bind(&listener_root, instance_id.as_str()).expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("owner identity");
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            serve_bootstrap_once(&listener, &store, Duration::from_secs(2))
                .expect("serve invalid request");
        }
        store
    });
    for invalid in [
        format!(
            "{{\"bootstrap_version\":\"1.0\",\"kind\":\"probe\",\"instance_id\":\"{}\",\"kind\":\"probe\"}}",
            instance_id.as_str()
        ),
        format!(
            "{{\"bootstrap_version\":\"1.0\",\"kind\":\"probe\",\"instance_id\":\"{}\",\"extra\":true}}",
            instance_id.as_str()
        ),
        String::from_utf8(request(
            "enroll",
            "ins_0123456789abcdef0123456789abcdef",
            instance_id.as_str(),
            "0123456789abcdef",
        ))
        .expect("ASCII enrollment request"),
    ] {
        let mut client = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
            .expect("verified invalid-request connection");
        client
            .write_frame(invalid.as_bytes())
            .expect("invalid request");
        let response = client.read_frame().expect("safe error response");
        let error: BootstrapError = decode_json(&response).expect("strict error response");
        assert_eq!(error.error, "invalid_request");
        assert_eq!(error.bootstrap_version, "1.0");
    }
    drop(server.join().expect("server thread"));
}
