#![cfg(unix)]

use dissect3d_api::{
    Client, ClientError, ClientId, ClientLimits, ConnectionMaterial, EnrollmentReceipt, ErrorCode,
    IdempotencyKey, InputReceipt, SecretToken, decode_json,
};
use dissect3d_engine::{CorePolicy, HttpServer, Store, serve_bootstrap_once};
use dissect3d_platform::{
    AuthorityLease, BootstrapListener, OwnedRoot, RelativePath, RootPurpose, connect_bootstrap,
    current_owner_identity,
};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};

const CLIENT_ID: &str = "cli_0123456789abcdef0123456789abcdef";
const ENROLLMENT_ID: &str = "enr_0123456789abcdef0123456789abcdef";
const SECRET_HEX: &str = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a";

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_capture_framing_capacity_and_control_are_bounded() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority lease");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("metadata store");
    let identity = store.identity().expect("store identity");
    let listener_root =
        OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("bootstrap listener root");
    let listener = BootstrapListener::bind(&listener_root, identity.instance_id.as_str())
        .expect("bootstrap listener");
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().expect("native owner identity");
    let server = std::thread::spawn(move || {
        serve_bootstrap_once(&listener, &store, Duration::from_secs(2))
            .expect("submission enrollment");
        store
    });
    let mut bootstrap = connect_bootstrap(&endpoint, &owner, Duration::from_secs(2))
        .expect("verified bootstrap connection");
    let body = format!(
        "{{\"bootstrap_version\":\"1.0\",\"kind\":\"enroll_submission\",\"installation_id\":\"{}\",\"instance_id\":\"{}\",\"enrollment_id\":\"{}\",\"client_id\":\"{}\",\"client_kind\":\"cli\",\"secret_hex\":\"{}\"}}",
        identity.installation_id.as_str(),
        identity.instance_id.as_str(),
        ENROLLMENT_ID,
        CLIENT_ID,
        SECRET_HEX,
    );
    bootstrap
        .write_frame(body.as_bytes())
        .expect("send submission enrollment");
    let enrollment: EnrollmentReceipt =
        decode_json(&bootstrap.read_frame().expect("enrollment receipt"))
            .expect("strict enrollment receipt");
    assert!(
        enrollment
            .granted_operations
            .iter()
            .any(|op| op == "inputs.create")
    );
    drop(bootstrap);
    let store = server.join().expect("bootstrap server thread");

    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let http = HttpServer::bind(&tls_root, std::sync::Arc::new(store), CorePolicy::default())
        .await
        .expect("HTTPS engine");
    let endpoint = http.base_url();
    let socket = http.endpoint();
    let (ca_der, ca_sha256) = http.trust_anchor();
    let ca_der = ca_der.to_vec();
    let ca_sha256 = *ca_sha256;
    let connector = trusted_connector(&ca_der);
    let (stop_tx, stop_rx) = oneshot::channel::<std::time::Instant>();
    let server_task = tokio::spawn(http.run_with_ready(stop_rx, None));
    let client = Arc::new(
        Client::new(
            ConnectionMaterial::new(
                endpoint,
                identity.installation_id,
                identity.instance_id,
                ClientId::parse(CLIENT_ID).expect("client identity"),
                ca_der,
                ca_sha256,
                SecretToken::new(vec![42; 32]).expect("client secret"),
            ),
            ClientLimits::default(),
        )
        .expect("trusted engine client"),
    );

    let expected = b"immutable input bytes".to_vec();
    let (mut writer, reader) = tokio::io::duplex(64);
    let write_task = tokio::spawn(async move {
        // Progress remains well within the 30-second idle limit while total
        // upload time exceeds reqwest's former response-header timeout.
        for chunk in expected.chunks(1) {
            writer.write_all(chunk).await.expect("write upload source");
            tokio::time::sleep(Duration::from_millis(1_600)).await;
        }
        expected
    });
    let upload_started = std::time::Instant::now();
    let receipt = client
        .create_input(
            reader,
            b"immutable input bytes".len() as u64,
            "Application/Octet-Stream",
        )
        .await
        .expect("authenticated input capture");
    assert!(upload_started.elapsed() > Duration::from_secs(30));
    assert_eq!(receipt.identity.media_type, "application/octet-stream");
    let expected = write_task.await.expect("source writer");
    assert!(receipt.complete);
    assert_eq!(receipt.identity.byte_length, expected.len() as u64);
    assert_eq!(receipt.identity.media_type, "application/octet-stream");
    let mut expected_digest = String::with_capacity(64);
    for byte in Sha256::digest(&expected) {
        use std::fmt::Write as _;
        write!(expected_digest, "{byte:02x}").expect("writing to String");
    }
    assert_eq!(receipt.identity.sha256.as_str(), expected_digest);
    assert_eq!(
        receipt.expires_at_ms.get() - receipt.completed_at_ms.get(),
        86_400_000
    );

    let root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("reopened root");
    let path = RelativePath::parse(format!(
        "inputs/data/{}.bin",
        receipt.identity.input_id.as_str()
    ))
    .expect("generated immutable input path");
    let mut input = root.open_immutable_input(&path).expect("published input");
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).expect("read captured bytes");
    assert_eq!(bytes, expected);

    let auth = format!("Bearer {CLIENT_ID}.{SECRET_HEX}");
    let missing_auth = raw_request(
        socket,
        &connector,
        format!(
            "POST /v1/inputs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
            socket.port()
        ),
        false,
    )
    .await;
    assert_eq!(response_status(&missing_auth), 401, "{missing_auth}");

    let missing_length = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Type: application/octet-stream\r\n",
        "",
        false,
    )
    .await;
    assert_eq!(response_status(&missing_length), 411, "{missing_length}");

    let duplicate_length = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Length: 1\r\nContent-Length: 1\r\nContent-Type: application/octet-stream\r\n",
        "x",
        false,
    )
    .await;
    assert_eq!(
        response_status(&duplicate_length),
        400,
        "{duplicate_length}"
    );

    let transfer_encoding = raw_upload(
        &connector,
        socket,
        &auth,
        "Transfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n",
        "0\r\n\r\n",
        false,
    )
    .await;
    assert_eq!(
        response_status(&transfer_encoding),
        400,
        "{transfer_encoding}"
    );

    let content_encoding = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Length: 1\r\nContent-Encoding: gzip\r\nContent-Type: application/octet-stream\r\n",
        "x",
        false,
    )
    .await;
    assert_eq!(
        response_status(&content_encoding),
        400,
        "{content_encoding}"
    );

    let duplicate_media_type = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Length: 1\r\nContent-Type: application/octet-stream\r\nContent-Type: application/octet-stream\r\n",
        "x",
        false,
    )
    .await;
    assert_eq!(
        response_status(&duplicate_media_type),
        400,
        "{duplicate_media_type}"
    );

    let unsupported_media_type = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Length: 1\r\nContent-Type: image/png\r\n",
        "x",
        false,
    )
    .await;
    assert_eq!(
        response_status(&unsupported_media_type),
        415,
        "{unsupported_media_type}"
    );

    let idle_timeout = raw_request_with_timeout(
        socket,
        &connector,
        format!(
            "POST /v1/inputs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: {auth}\r\nContent-Length: 1\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            socket.port()
        ),
        false,
        Duration::from_secs(35),
    )
    .await;
    assert_ne!(response_status(&idle_timeout), 201, "{idle_timeout}");
    assert_eq!(
        owned_file_count(&root_path, "inputs/staging"),
        0,
        "an idle timeout leaves no staged input after confirmed cleanup"
    );

    let short_body = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Length: 4\r\nContent-Type: application/octet-stream\r\n",
        "x",
        true,
    )
    .await;
    assert_ne!(response_status(&short_body), 201, "{short_body}");

    let overrun_body = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Length: 1\r\nContent-Type: application/octet-stream\r\n",
        "xy",
        false,
    )
    .await;
    // Bytes after Content-Length are outside this HTTP request's body. The
    // server captures exactly the declared one byte; the typed client separately
    // rejects a source reader that yields bytes beyond its declared length.
    assert_eq!(response_status(&overrun_body), 201, "{overrun_body}");
    let response_body = overrun_body
        .split_once("\r\n\r\n")
        .expect("raw response body")
        .1;
    let raw_receipt: InputReceipt = decode_json(response_body.as_bytes()).expect("strict receipt");
    assert_eq!(raw_receipt.identity.byte_length, 1);
    let root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("reopened root");
    let overrun_path = RelativePath::parse(format!(
        "inputs/data/{}.bin",
        raw_receipt.identity.input_id.as_str()
    ))
    .expect("generated input path");
    let mut captured = root
        .open_immutable_input(&overrun_path)
        .expect("declared request body only");
    let mut captured_bytes = Vec::new();
    captured
        .read_to_end(&mut captured_bytes)
        .expect("read declared body");
    assert_eq!(captured_bytes, b"x");

    let (mut overrun_source, overrun_reader) = tokio::io::duplex(8);
    overrun_source
        .write_all(b"xy")
        .await
        .expect("write overlong client source");
    drop(overrun_source);
    assert_eq!(
        client
            .create_input(overrun_reader, 1, "application/octet-stream")
            .await,
        Err(ClientError::InvalidMaterial),
        "the shared client never returns a receipt for an overlong source"
    );
    assert!(
        (2..=3).contains(&owned_file_count(&root_path, "inputs/data")),
        "the overlong source can leave one unreferenced capture if its declared bytes reached the server before the client detected excess source bytes"
    );

    let stray_link = root_path.join("inputs/data/unrecognized.entry.bin");
    std::os::unix::fs::symlink("missing-target", &stray_link)
        .expect("seed an ambiguous no-follow scan entry");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if std::fs::symlink_metadata(&stray_link).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("bounded recovery quarantines an ambiguous entry");
    let quarantined = std::fs::read_dir(root_path.join("inputs/quarantine"))
        .expect("private quarantine directory")
        .map(|entry| {
            entry
                .expect("quarantine entry")
                .file_type()
                .expect("entry type")
        })
        .any(|kind| kind.is_symlink());
    assert!(
        quarantined,
        "quarantine preserves the link without following it"
    );

    let expired_path = RelativePath::parse(format!(
        "inputs/data/{}.bin",
        receipt.identity.input_id.as_str()
    ))
    .expect("initial captured input path");
    let database = rusqlite::Connection::open(root_path.join("metadata.sqlite3"))
        .expect("open test metadata for expiry injection");
    let changed = database
        .execute(
            "UPDATE captured_inputs SET expires_at_ms=completed_at_ms+1 WHERE input_id=?1",
            [receipt.identity.input_id.as_str()],
        )
        .expect("advance this fixture input to expiry");
    assert_eq!(changed, 1);
    drop(database);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                root.file_metadata(&expired_path),
                Err(dissect3d_platform::PlatformError::NotFound)
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("recovery durably removes an expired unreferenced input");
    let database = rusqlite::Connection::open(root_path.join("metadata.sqlite3"))
        .expect("reopen test metadata after expiry");
    // Unlink becomes visible before its native namespace barriers and the
    // subsequent actor confirmation finish. Wait for confirmation, preserving
    // the assertion that permanent charge leakage still fails this scenario.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pending: i64 = database
                .query_row(
                    "SELECT count(*) FROM captured_inputs WHERE input_id=?1",
                    [receipt.identity.input_id.as_str()],
                    |row| row.get(0),
                )
                .expect("cleanup confirmation metadata count");
            if pending == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("bounded durable cleanup confirmation");
    let remaining: i64 = database
        .query_row(
            "SELECT count(*) FROM captured_inputs WHERE input_id=?1",
            [receipt.identity.input_id.as_str()],
            |row| row.get(0),
        )
        .expect("expired input metadata count");
    assert_eq!(
        remaining, 0,
        "charge release follows confirmed file deletion"
    );

    let (mut first_source, first_reader) = tokio::io::duplex(32);
    let (mut second_source, second_reader) = tokio::io::duplex(32);
    first_source
        .write_all(b"first")
        .await
        .expect("first partial bytes");
    second_source
        .write_all(b"second")
        .await
        .expect("second partial bytes");
    let first_client = client.clone();
    let first_upload = tokio::spawn(async move {
        first_client
            .create_input(first_reader, 1024, "application/octet-stream")
            .await
    });
    let second_client = client.clone();
    let second_upload = tokio::spawn(async move {
        second_client
            .create_input(second_reader, 1024, "application/octet-stream")
            .await
    });
    wait_for_file_count(&root_path, "inputs/staging", 2).await;

    // Authenticated uploads retain their own deadline rather than the core
    // connection's five-second budget. Both sources deliberately remain open.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        !first_upload.is_finished(),
        "first upload survives the core deadline"
    );
    assert!(
        !second_upload.is_finished(),
        "second upload survives the core deadline"
    );

    let (mut third_source, third_reader) = tokio::io::duplex(8);
    third_source
        .write_all(b"third")
        .await
        .expect("third source");
    let third = tokio::time::timeout(
        Duration::from_secs(3),
        client.create_input(third_reader, 1024, "application/octet-stream"),
    )
    .await
    .expect("third upload receives bounded capacity response");
    assert_eq!(
        third,
        Err(ClientError::Rejected(ErrorCode::CapacityExceeded))
    );
    let capacity = raw_upload(
        &connector,
        socket,
        &auth,
        "Content-Length: 1\r\nContent-Type: application/octet-stream\r\n",
        "",
        false,
    )
    .await;
    assert_eq!(response_status(&capacity), 429);
    let body = capacity.split_once("\r\n\r\n").unwrap().1;
    let error: dissect3d_api::ApiError = decode_json(body.as_bytes()).unwrap();
    assert_eq!(
        error.error.details.unwrap()["limit"],
        "upload_concurrency_max"
    );
    let limits = client.info().await.unwrap().submission.unwrap().limits;
    assert_eq!(limits["staged_input_records_max"], 1024);
    assert_eq!(limits["storage_free_reserve_bytes"], 1_073_741_824);
    assert_eq!(limits["upload_metadata_reserve_bytes"], 4_194_304);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.info())
            .await
            .expect("info remains responsive under two uploads")
            .is_ok()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.auth_status())
            .await
            .expect("auth status remains responsive under two uploads")
            .is_ok()
    );

    let stop_receipt = client
        .shutdown(IdempotencyKey::parse("input-capture-stop-test-1").expect("shutdown key"))
        .await
        .expect("shutdown remains responsive under two uploads");
    assert_eq!(stop_receipt.state, dissect3d_api::OperationState::Queued);
    assert_eq!(
        client.info().await.expect("stopping info").phase,
        dissect3d_api::EnginePhase::Stopping
    );
    let _ = stop_tx.send(std::time::Instant::now() + Duration::from_millis(200));
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("stop drains or closes partial uploads within its deadline")
        .expect("HTTP server task")
        .expect("HTTP server");
    drop(first_source);
    drop(second_source);
    drop(third_source);
    let _ = tokio::time::timeout(Duration::from_secs(2), first_upload).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), second_upload).await;
}

fn trusted_connector(ca_der: &[u8]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .expect("trust the engine CA");
    TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

async fn raw_upload(
    connector: &TlsConnector,
    endpoint: SocketAddr,
    auth: &str,
    headers: &str,
    body: &str,
    half_close: bool,
) -> String {
    raw_request(
        endpoint,
        connector,
        format!(
            "POST /v1/inputs HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: {auth}\r\n{headers}Connection: close\r\n\r\n{body}",
            endpoint.port()
        ),
        half_close,
    )
    .await
}

async fn raw_request(
    endpoint: SocketAddr,
    connector: &TlsConnector,
    request: String,
    half_close: bool,
) -> String {
    raw_request_with_timeout(
        endpoint,
        connector,
        request,
        half_close,
        Duration::from_secs(3),
    )
    .await
}

async fn raw_request_with_timeout(
    endpoint: SocketAddr,
    connector: &TlsConnector,
    request: String,
    half_close: bool,
    response_timeout: Duration,
) -> String {
    let stream = tokio::net::TcpStream::connect(endpoint)
        .await
        .expect("raw HTTPS socket");
    let server_name = ServerName::try_from("127.0.0.1".to_owned()).expect("loopback name");
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .expect("trusted raw HTTPS socket");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write raw HTTP request");
    if half_close {
        stream
            .shutdown()
            .await
            .expect("close incomplete request body");
    }
    let mut response = Vec::new();
    tokio::time::timeout(response_timeout, stream.read_to_end(&mut response))
        .await
        .expect("finite raw response")
        .expect("read raw response");
    String::from_utf8_lossy(&response).into_owned()
}

fn response_status(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("HTTP status line")
}

fn owned_file_count(root_path: &std::path::Path, relative: &str) -> usize {
    let root = OwnedRoot::open(root_path, RootPurpose::EngineData).expect("reopen scan root");
    let directory = RelativePath::parse(relative).expect("private scan directory");
    root.scan_owned_inputs(&directory)
        .expect("owned input scan")
        .next_batch(64)
        .expect("bounded input scan")
        .entries
        .len()
}

async fn wait_for_file_count(root_path: &std::path::Path, relative: &str, expected: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if owned_file_count(root_path, relative) == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("uploads reach the bounded staging directory");
}
