#![cfg(unix)]

use dissect3d_api::{
    Client, ClientId, ConnectionMaterial, DiscoveryRecord, EnrollmentReceipt, IdempotencyKey,
    SecretToken, decode_json,
};
use dissect3d_platform::{
    BootstrapEndpoint, ProcessIdentity, ProcessWatcher, connect_bootstrap, current_owner_identity,
};
use rusqlite::Connection;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};

const CLIENT: &str = "cli_0123456789abcdef0123456789abcdef";

struct Engine {
    child: ChildGuard,
    root: PathBuf,
    discovery: DiscoveryRecord,
    client: Client,
}
impl Engine {
    fn start(root: &Path) -> Self {
        let mut child = ChildGuard(
            Command::new(env!("CARGO_BIN_EXE_dissect3d-engine"))
                .arg("--data-root")
                .arg(root)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let discovery = loop {
            if let Ok(bytes) = std::fs::read(root.join("run/endpoint.json"))
                && let Ok(discovery) = decode_json::<DiscoveryRecord>(&bytes)
                && discovery.process.pid == child.0.id()
            {
                break discovery;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "engine exited before readiness"
            );
            if Instant::now() >= deadline {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                panic!("readiness deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let endpoint = match &discovery.bootstrap_endpoint {
            dissect3d_api::BootstrapAddress::Unix { path } => {
                BootstrapEndpoint::Unix { path: path.into() }
            }
            _ => panic!("Unix bootstrap expected"),
        };
        let mut channel = connect_bootstrap(
            &endpoint,
            &current_owner_identity().unwrap(),
            Duration::from_secs(2),
        )
        .unwrap();
        channel.write_frame(&serde_json::to_vec(&serde_json::json!({
            "kind":"enroll", "bootstrap_version":"1.0", "installation_id":discovery.installation_id,
            "instance_id":discovery.instance_id, "enrollment_id":"enr_0123456789abcdef0123456789abcdef",
            "client_id":CLIENT, "client_kind":"cli", "secret_hex":"2a".repeat(32)
        })).unwrap()).unwrap();
        let _: EnrollmentReceipt = decode_json(&channel.read_frame().unwrap()).unwrap();
        let pin = discovery.trust_anchor_sha256.clone().try_into().unwrap();
        let client = Client::new(
            ConnectionMaterial::new(
                discovery.base_url.clone(),
                discovery.installation_id.clone(),
                discovery.instance_id.clone(),
                ClientId::parse(CLIENT).unwrap(),
                discovery.trust_anchor_der.clone(),
                pin,
                SecretToken::new(vec![42; 32]).unwrap(),
            ),
            Default::default(),
        )
        .unwrap();
        Self {
            child,
            root: root.to_owned(),
            discovery,
            client,
        }
    }
    fn watcher(&self) -> ProcessWatcher {
        ProcessWatcher::new(&ProcessIdentity {
            pid: self.child.0.id(),
            start_marker: self.discovery.process.start_marker.clone(),
        })
        .unwrap()
    }
    fn kill(&mut self) {
        self.child.0.kill().unwrap();
        self.child.0.wait().unwrap();
    }
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_bootstrap_frame_does_not_delay_http_shutdown_or_clean_barrier() {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::start(&temp.path().join("engine"));
    let path = match &engine.discovery.bootstrap_endpoint {
        dissect3d_api::BootstrapAddress::Unix { path } => path,
        _ => panic!("Unix endpoint"),
    };
    let mut stalled = std::os::unix::net::UnixStream::connect(path).unwrap();
    stalled.write_all(&[0, 0, 0, 10, b'{']).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let watcher = engine.watcher();
    let started = Instant::now();
    let receipt = engine
        .client
        .shutdown(IdempotencyKey::parse("stalled-bootstrap-shutdown").unwrap())
        .await
        .unwrap();
    assert!(
        watcher.wait(Duration::from_secs(2)).unwrap(),
        "native frame consumed shutdown budget"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let db = Connection::open(engine.root.join("metadata.sqlite3")).unwrap();
    let state: String = db
        .query_row(
            "SELECT state FROM core_operations WHERE operation_id=?1",
            [receipt.operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let termination: String = db
        .query_row(
            "SELECT termination FROM service_sessions WHERE instance_id=?1",
            [engine.discovery.instance_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "succeeded");
    assert_eq!(termination, "clean");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_death_after_receipt_before_final_barrier_recovers_interrupted() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("engine");
    let mut engine = Engine::start(&root);
    let old_instance = engine.discovery.instance_id.clone();
    let installation = engine.discovery.installation_id.clone();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            engine.discovery.trust_anchor_der.clone(),
        ))
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let address = engine.discovery.base_url.strip_prefix("https://").unwrap();
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut stalled = connector
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .unwrap();
    stalled
        .write_all(format!("GET /v1/info HTTP/1.1\r\nHost: {address}\r\nX-Pending: ").as_bytes())
        .await
        .unwrap();
    let receipt = engine
        .client
        .shutdown(IdempotencyKey::parse("crash-after-durable-receipt").unwrap())
        .await
        .unwrap();
    let db = Connection::open(root.join("metadata.sqlite3")).unwrap();
    let phase: String = db
        .query_row(
            "SELECT phase FROM core_operations WHERE operation_id=?1",
            [receipt.operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        phase, "quiescing",
        "test must reach committed intent before final barrier"
    );
    engine.kill();
    drop(db);
    let restarted = Engine::start(&root);
    assert_eq!(restarted.discovery.installation_id, installation);
    assert_ne!(restarted.discovery.instance_id, old_instance);
    let db = Connection::open(root.join("metadata.sqlite3")).unwrap();
    let state: String = db
        .query_row(
            "SELECT state FROM core_operations WHERE operation_id=?1",
            [receipt.operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let termination: String = db
        .query_row(
            "SELECT termination FROM service_sessions WHERE instance_id=?1",
            [old_instance.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "interrupted");
    assert_eq!(termination, "unclean");
}
