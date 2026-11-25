//! Real loopback HTTPS + SQLite Store + OwnedRoot tests for `RP-P04`
//! (`RP-S09`, `RP-S10`, `RP-S11`, `RP-S12`, `RP-S16`, `RP-S18`).

use crate::{CorePolicy, HttpServer, Store, serve_bootstrap_once};
use dissect3d_api::{
    Client, ClientError, ClientId, ClientLimits, ConnectionMaterial, ErrorCode, JobId,
    ResultAvailability, ResultsQuery, SecretToken, StorageMeasurementStatus,
    decode_result_manifest,
};
use dissect3d_platform::{
    AuthorityLease, BootstrapListener, OwnedRoot, RelativePath, RootPurpose, connect_bootstrap,
    current_owner_identity,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

const CLIENT_A: &str = "cli_11111111111111111111111111111111";
const CLIENT_B: &str = "cli_22222222222222222222222222222222";
const SECRET_A: [u8; 32] = [0x31; 32];
const SECRET_B: [u8; 32] = [0x32; 32];

struct TestHost {
    dir: Option<tempfile::TempDir>,
    path: PathBuf,
    root: Option<OwnedRoot>,
    store: Option<Arc<Store>>,
    base_url: String,
    ca_der: Vec<u8>,
    ca_sha256: [u8; 32],
    shutdown: Option<oneshot::Sender<()>>,
    server_task: Option<tokio::task::JoinHandle<()>>,
}

impl TestHost {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).unwrap();
        Self::boot(dir, path, root).await
    }

    async fn boot(dir: tempfile::TempDir, path: PathBuf, root: OwnedRoot) -> Self {
        let lease = AuthorityLease::acquire(&root).unwrap();
        let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).unwrap());
        let http_root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
        let server = HttpServer::bind(&http_root, store.clone(), CorePolicy::default())
            .await
            .unwrap();
        let base_url = server.base_url();
        let (ca_der, ca_sha256) = server.trust_anchor();
        let ca_der = ca_der.to_vec();
        let ca_sha256 = *ca_sha256;
        let (tx, rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let _ = server.run(rx).await;
        });
        Self {
            dir: Some(dir),
            path,
            root: Some(http_root),
            store: Some(store),
            base_url,
            ca_der,
            ca_sha256,
            shutdown: Some(tx),
            server_task: Some(server_task),
        }
    }

    fn root(&self) -> &OwnedRoot {
        self.root.as_ref().unwrap()
    }

    fn store(&self) -> &Arc<Store> {
        self.store.as_ref().unwrap()
    }

    async fn restart(mut self) -> Self {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.server_task.take() {
            let _ = task.await;
        }
        let dir = self.dir.take().unwrap();
        let path = self.path.clone();
        self.root.take();
        self.store.take();
        let root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
        Self::boot(dir, path, root).await
    }

    fn enroll_execution(&self, client_id: &str, enrollment_id: &str, secret: [u8; 32]) {
        let id = self.store().identity().unwrap();
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let message = json!({
            "kind": "enroll_execution",
            "bootstrap_version": "1.0",
            "installation_id": id.installation_id,
            "instance_id": id.instance_id,
            "client_id": client_id,
            "enrollment_id": enrollment_id,
            "client_kind": "cli",
            "secret_hex": secret_hex,
            "execution_contract": "execution-v1",
        });
        let listener = BootstrapListener::bind(self.root(), id.instance_id.as_str()).unwrap();
        let endpoint = listener.endpoint().clone();
        let owner = current_owner_identity().unwrap();
        let store = self.store().clone();
        let thread = std::thread::spawn(move || {
            serve_bootstrap_once(&listener, &store, Duration::from_secs(5)).unwrap();
        });
        let mut channel = connect_bootstrap(&endpoint, &owner, Duration::from_secs(5)).unwrap();
        channel
            .write_frame(&serde_json::to_vec(&message).unwrap())
            .unwrap();
        let reply: Value = serde_json::from_slice(&channel.read_frame().unwrap()).unwrap();
        assert_eq!(reply["client_id"], client_id);
        drop(channel);
        thread.join().unwrap();
    }

    fn client(&self, client_id: &str, secret: [u8; 32]) -> Client {
        let id = self.store().identity().unwrap();
        Client::new(
            ConnectionMaterial::new(
                format!("{}/", self.base_url),
                id.installation_id,
                id.instance_id,
                ClientId::parse(client_id).unwrap(),
                self.ca_der.clone(),
                self.ca_sha256,
                SecretToken::new(secret.to_vec()).unwrap(),
            ),
            ClientLimits::default(),
        )
        .unwrap()
    }

    fn raw_http(&self) -> reqwest::Client {
        let cert = reqwest::Certificate::from_der(&self.ca_der).unwrap();
        reqwest::Client::builder()
            .https_only(true)
            .tls_backend_rustls()
            .tls_certs_only([cert])
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .build()
            .unwrap()
    }

    fn bearer(client_id: &str, secret: [u8; 32]) -> String {
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        format!("Bearer {client_id}.{hex}")
    }
}

impl Drop for TestHost {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
    }
}

struct SeededResult {
    result_id: String,
    publication_id: String,
    artifact_id: String,
    job_id: String,
    attempt_id: String,
    manifest_bytes: Vec<u8>,
}

struct SeedSpec<'a> {
    client_id: &'a str,
    acceptance_seq: i64,
    pub_seq: i64,
    n: u8,
    artifact_bytes: Vec<u8>,
    override_features: Option<Vec<&'a str>>,
    override_version: Option<&'a str>,
}

fn manifest_bytes_for(
    ids: [&str; 6],
    artifact_bytes: &[u8],
    override_features: Option<Vec<&str>>,
    override_version: Option<&str>,
) -> Vec<u8> {
    let [
        result_id,
        publication_id,
        artifact_id,
        job_id,
        attempt_id,
        input_id,
    ] = ids;
    let sha: String = Sha256::digest(artifact_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut value: Value = serde_json::from_str::<Value>(include_str!(
        "../../../api/tests/fixtures/result_publication.json"
    ))
    .unwrap()["complete_mesh_copy"]
        .clone();
    value["result_id"] = json!(result_id);
    value["publication_id"] = json!(publication_id);
    value["job_id"] = json!(job_id);
    value["attempt_id"] = json!(attempt_id);
    value["files"][0]["artifact_id"] = json!(artifact_id);
    value["files"][0]["byte_length"] = json!(artifact_bytes.len());
    value["files"][0]["sha256"] = json!(sha);
    value["components"][0]["artifact_ids"][0] = json!(artifact_id);
    value["provenance"]["resolved"]["inputs"]["mesh"][0]["input_id"] = json!(input_id);
    value["provenance"]["resolved"]["inputs"]["mesh"][0]["byte_length"] =
        json!(artifact_bytes.len());
    value["provenance"]["resolved"]["inputs"]["mesh"][0]["sha256"] = json!(sha);
    value["provenance"]["input_identities"][0]["input_id"] = json!(input_id);
    value["provenance"]["input_identities"][0]["byte_length"] = json!(artifact_bytes.len());
    value["provenance"]["input_identities"][0]["sha256"] = json!(sha);
    if let Some(features) = override_features {
        value["required_features"] = json!(features);
    }
    if let Some(version) = override_version {
        value["manifest_version"] = json!(version);
    }
    serde_json::to_vec(&value).unwrap()
}

fn write_object(root: &OwnedRoot, object_name: &str, bytes: &[u8]) {
    let staging = RelativePath::parse(format!("results/staging/{object_name}")).unwrap();
    let object = RelativePath::parse(format!("results/objects/{object_name}")).unwrap();
    root.prepare_artifact(&staging, &object, bytes).unwrap();
}

/// Seed a job row + committed published result directly in SQLite and `results/objects`,
/// preserving every v8 foreign key and invariant.
fn seed_committed_result(db_path: &Path, root: &OwnedRoot, spec: SeedSpec<'_>) -> SeededResult {
    let SeedSpec {
        client_id,
        acceptance_seq,
        pub_seq,
        n,
        artifact_bytes,
        override_features,
        override_version,
    } = spec;
    let result_id = format!("res_{n:032x}");
    let publication_id = format!("pub_{n:032x}");
    let artifact_id = format!("art_{n:032x}");
    let job_id = format!("job_{n:032x}");
    let attempt_id = format!("att_{n:032x}");
    let input_id = format!("inp_{n:032x}");
    let manifest_bytes = manifest_bytes_for(
        [
            &result_id,
            &publication_id,
            &artifact_id,
            &job_id,
            &attempt_id,
            &input_id,
        ],
        &artifact_bytes,
        override_features,
        override_version,
    );
    let art_sha: [u8; 32] = Sha256::digest(&artifact_bytes).into();
    let man_sha: [u8; 32] = Sha256::digest(&manifest_bytes).into();
    write_object(root, &artifact_id, &artifact_bytes);
    write_object(root, &publication_id, &manifest_bytes);

    let conn = rusqlite::Connection::open(db_path.join("metadata.sqlite3")).unwrap();
    let instance_id: String = conn
        .query_row(
            "SELECT instance_id FROM service_sessions WHERE termination='active'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let resolved_json = serde_json::to_string(
        &serde_json::from_slice::<Value>(&manifest_bytes).unwrap()["provenance"]["resolved"],
    )
    .unwrap();
    let total_bytes = (artifact_bytes.len() + manifest_bytes.len()) as i64;
    conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
    conn.execute(
        "INSERT INTO captured_inputs
         (input_id,client_id,media_type,byte_length,sha256,completed_at_ms,expires_at_ms,cleanup_state)
         VALUES(?1,?2,'application/octet-stream',?3,?4,100,999999999,'complete')",
        rusqlite::params![input_id, client_id, artifact_bytes.len() as i64, art_sha.as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO jobs
         (job_id,client_id,acceptance_sequence,created_at_ms,resolved_json,storage_status)
         VALUES(?1,?2,?3,100,?4,'verified')",
        rusqlite::params![job_id, client_id, acceptance_seq, resolved_json],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO job_inputs(job_id,input_id) VALUES(?1,?2)",
        rusqlite::params![job_id, input_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO job_execution
         (job_id,state,phase,snapshot_revision,cleanup_status,updated_at_ms)
         VALUES(?1,'succeeded','succeeded',2,'confirmed',200)",
        [&job_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO job_attempts
         VALUES(?1,?2,?3,?4,?5,150,200,'confirmed')",
        rusqlite::params![
            attempt_id,
            job_id,
            instance_id,
            format!("ses_{n:032x}"),
            format!("grt_{n:032x}"),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO publication_allocations
         (result_id,publication_id,job_id,attempt_id,instance_id,state,reserved_bytes,created_at_ms,updated_at_ms)
         VALUES(?1,?2,?3,?4,?5,'published',?6,150,200)",
        rusqlite::params![
            result_id,
            publication_id,
            job_id,
            attempt_id,
            instance_id,
            total_bytes,
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO result_files
         (object_name,result_id,role,filename,media_type,byte_length,sha256)
         VALUES(?1,?2,'artifact','mesh.obj','application/octet-stream',?3,?4)",
        rusqlite::params![
            artifact_id,
            result_id,
            artifact_bytes.len() as i64,
            art_sha.as_slice()
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO result_files
         (object_name,result_id,role,filename,media_type,byte_length,sha256)
         VALUES(?1,?2,'manifest','manifest.json','application/json',?3,?4)",
        rusqlite::params![
            publication_id,
            result_id,
            manifest_bytes.len() as i64,
            man_sha.as_slice()
        ],
    )
    .unwrap();
    let manifest_version = override_version.unwrap_or("1.0");
    conn.execute(
        "INSERT INTO results
         (result_id,job_id,attempt_id,publication_sequence,manifest_version,published_at_ms)
         VALUES(?1,?2,?3,?4,?5,200)",
        rusqlite::params![result_id, job_id, attempt_id, pub_seq, manifest_version],
    )
    .unwrap();
    conn.execute(
        "UPDATE publication_sequence SET value=max(value,?1) WHERE singleton=1",
        [pub_seq],
    )
    .unwrap();
    conn.execute_batch("COMMIT;").unwrap();

    SeededResult {
        result_id,
        publication_id,
        artifact_id,
        job_id,
        attempt_id,
        manifest_bytes,
    }
}

/// Seed an uncommitted `prepared` allocation (no `results` row) to verify
/// private staging never leaks via `/v1/artifacts/{id}` and is charged in
/// `private_staging_bytes`.
fn seed_uncommitted_prepared(
    db_path: &Path,
    root: &OwnedRoot,
    client_id: &str,
    acceptance_seq: i64,
    n: u8,
    artifact_bytes: &[u8],
) -> String {
    let result_id = format!("res_{n:032x}");
    let publication_id = format!("pub_{n:032x}");
    let artifact_id = format!("art_{n:032x}");
    let job_id = format!("job_{n:032x}");
    let attempt_id = format!("att_{n:032x}");
    let art_sha: [u8; 32] = Sha256::digest(artifact_bytes).into();
    write_object(root, &artifact_id, artifact_bytes);
    let conn = rusqlite::Connection::open(db_path.join("metadata.sqlite3")).unwrap();
    let instance_id: String = conn
        .query_row(
            "SELECT instance_id FROM service_sessions WHERE termination='active'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
    conn.execute(
        "INSERT INTO jobs
         (job_id,client_id,acceptance_sequence,created_at_ms,resolved_json,storage_status)
         VALUES(?1,?2,?3,100,'{}','verified')",
        rusqlite::params![job_id, client_id, acceptance_seq],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO job_execution
         (job_id,state,phase,snapshot_revision,cleanup_status,updated_at_ms)
         VALUES(?1,'running','running',1,'pending',100)",
        [&job_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO job_attempts
         VALUES(?1,?2,?3,?4,?5,150,NULL,'pending')",
        rusqlite::params![
            attempt_id,
            job_id,
            instance_id,
            format!("ses_{n:032x}"),
            format!("grt_{n:032x}"),
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO publication_allocations
         (result_id,publication_id,job_id,attempt_id,instance_id,state,reserved_bytes,created_at_ms,updated_at_ms)
         VALUES(?1,?2,?3,?4,?5,'prepared',?6,150,200)",
        rusqlite::params![
            result_id,
            publication_id,
            job_id,
            attempt_id,
            instance_id,
            artifact_bytes.len() as i64,
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO result_files
         (object_name,result_id,role,filename,media_type,byte_length,sha256)
         VALUES(?1,?2,'artifact','mesh.obj','application/octet-stream',?3,?4)",
        rusqlite::params![
            artifact_id,
            result_id,
            artifact_bytes.len() as i64,
            art_sha.as_slice()
        ],
    )
    .unwrap();
    conn.execute_batch("COMMIT;").unwrap();
    artifact_id
}

#[tokio::test]
async fn creator_privacy_large_streaming_headers_and_storage_usage() {
    let host = TestHost::start().await;
    host.enroll_execution(CLIENT_A, "enr_11111111111111111111111111111111", SECRET_A);
    host.enroll_execution(CLIENT_B, "enr_22222222222222222222222222222222", SECRET_B);

    // 300 KiB payload > 262 KiB control response cap to prove artifact streaming
    // bypasses the control response buffer and streams in <= 64 KiB chunks.
    let mut large_obj = Vec::with_capacity(310_000);
    while large_obj.len() < 300_000 {
        large_obj.extend_from_slice(b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n");
    }
    let seeded = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 1,
            pub_seq: 1,
            n: 1,
            artifact_bytes: large_obj.clone(),
            override_features: None,
            override_version: None,
        },
    );
    let uncommitted_art =
        seed_uncommitted_prepared(&host.path, host.root(), CLIENT_A, 2, 2, b"private-staging");

    let client_a = host.client(CLIENT_A, SECRET_A);
    let client_b = host.client(CLIENT_B, SECRET_B);

    // Creator reads exact manifest bytes and streamed artifact (> 262 KiB).
    let manifest = client_a.result_manifest(&seeded.result_id).await.unwrap();
    assert_eq!(manifest.raw_bytes, seeded.manifest_bytes);
    assert_eq!(manifest.manifest.result_id, seeded.result_id);
    assert_eq!(
        manifest.manifest.job_id,
        JobId::parse(&seeded.job_id).unwrap()
    );
    assert_eq!(manifest.manifest.attempt_id, seeded.attempt_id);

    let mut stream = client_a
        .artifact(&seeded.artifact_id, 1_048_576)
        .await
        .unwrap();
    assert_eq!(stream.content_length(), large_obj.len() as u64);
    assert_eq!(stream.media_type(), "application/octet-stream");
    assert_eq!(stream.filename(), Some("mesh.obj"));
    let mut received = Vec::new();
    let mut chunks = 0usize;
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        assert!(chunk.len() <= 65_536);
        chunks += 1;
        received.extend_from_slice(&chunk);
    }
    assert!(
        chunks >= 5,
        "expected multi-chunk 64 KiB stream, got {chunks}"
    );
    assert_eq!(received, large_obj);

    // Uncommitted staging artifact is invisible (404) even to its creator.
    assert_eq!(
        client_a.artifact(&uncommitted_art, 1_048_576).await.err(),
        Some(ClientError::Rejected(ErrorCode::NotFound))
    );

    // Other client gets 404 on manifest/artifact and empty list (no existence leak).
    assert_eq!(
        client_b.result_manifest(&seeded.result_id).await.err(),
        Some(ClientError::Rejected(ErrorCode::NotFound))
    );
    assert_eq!(
        client_b
            .artifact(&seeded.artifact_id, 1_048_576)
            .await
            .err(),
        Some(ClientError::Rejected(ErrorCode::NotFound))
    );
    let page_b = client_b.results(ResultsQuery::default()).await.unwrap();
    assert!(page_b.items.is_empty());

    // Storage usage is creator-scoped and includes uncommitted staging bytes.
    let storage_a = client_a.storage().await.unwrap();
    assert_eq!(storage_a.storage_contract, "rp-0.1");
    assert_eq!(
        storage_a.measurement.status,
        StorageMeasurementStatus::Current
    );
    assert!(storage_a.measurement.measured_at_ms.is_some());
    assert_eq!(
        storage_a.usage.retained_input_bytes,
        Some(large_obj.len() as u64)
    );
    assert_eq!(
        storage_a.usage.published_output_bytes,
        Some((large_obj.len() + seeded.manifest_bytes.len()) as u64)
    );
    assert_eq!(
        storage_a.usage.private_staging_bytes,
        Some(b"private-staging".len() as u64)
    );
    assert!(storage_a.usage.metadata_bytes.unwrap_or(0) > 0);
    assert!(storage_a.limits.contains_key("result_published_bytes_max"));

    let storage_b = client_b.storage().await.unwrap();
    assert_eq!(storage_b.usage.retained_input_bytes, Some(0));
    assert_eq!(storage_b.usage.published_output_bytes, Some(0));
    assert_eq!(storage_b.usage.private_staging_bytes, Some(0));

    // Reject Range, non-identity Accept-Encoding, and unknown query params with 400.
    let raw = host.raw_http();
    let auth_a = TestHost::bearer(CLIENT_A, SECRET_A);
    let range_resp = raw
        .get(format!(
            "{}/v1/artifacts/{}",
            host.base_url, seeded.artifact_id
        ))
        .header("Authorization", &auth_a)
        .header("Range", "bytes=0-10")
        .send()
        .await
        .unwrap();
    assert_eq!(range_resp.status(), 400);
    let gzip_resp = raw
        .get(format!(
            "{}/v1/artifacts/{}",
            host.base_url, seeded.artifact_id
        ))
        .header("Authorization", &auth_a)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(gzip_resp.status(), 400);
    let identity_resp = raw
        .get(format!(
            "{}/v1/results/{}/manifest",
            host.base_url, seeded.result_id
        ))
        .header("Authorization", &auth_a)
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .unwrap();
    assert_eq!(identity_resp.status(), 200);
}

#[tokio::test]
async fn high_water_pagination_concurrent_older_publication_and_restart_expiry() {
    let host = TestHost::start().await;
    host.enroll_execution(CLIENT_A, "enr_11111111111111111111111111111111", SECRET_A);
    let obj = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n".to_vec();

    // Publish acceptance_sequence 2 and 3 first (publication_sequence 1 and 2).
    let r2 = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 2,
            pub_seq: 1,
            n: 2,
            artifact_bytes: obj.clone(),
            override_features: None,
            override_version: None,
        },
    );
    let r3 = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 3,
            pub_seq: 2,
            n: 3,
            artifact_bytes: obj.clone(),
            override_features: None,
            override_version: None,
        },
    );

    let client = host.client(CLIENT_A, SECRET_A);
    let page1 = client
        .results(ResultsQuery {
            limit: Some(1),
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(page1.items.len(), 1);
    assert_eq!(page1.items[0].result_id, r2.result_id);
    assert!(page1.truncated);
    let cursor1 = page1.next_cursor.clone().unwrap();

    // Concurrently publish older job (acceptance_sequence 1, publication_sequence 3).
    let r1 = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 1,
            pub_seq: 3,
            n: 1,
            artifact_bytes: obj,
            override_features: None,
            override_version: None,
        },
    );

    // Continuing with cursor1 stays pinned to high-water 2 (returns r3, no duplicates/skips).
    let page2 = client
        .results(ResultsQuery {
            limit: Some(1),
            cursor: Some(cursor1.clone()),
        })
        .await
        .unwrap();
    assert_eq!(page2.items.len(), 1);
    assert_eq!(page2.items[0].result_id, r3.result_id);
    assert!(!page2.truncated);
    assert!(page2.next_cursor.is_none());

    // Fresh traversal sees all three in ascending acceptance_sequence order (r1, r2, r3).
    let fresh = client
        .results(ResultsQuery {
            limit: Some(10),
            cursor: None,
        })
        .await
        .unwrap();
    let ids: Vec<&str> = fresh.items.iter().map(|i| i.result_id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            r1.result_id.as_str(),
            r2.result_id.as_str(),
            r3.result_id.as_str()
        ]
    );

    // Restart engine: old cursor expires explicitly with JobCursorExpired (409),
    // while fresh traversal still returns all retained results.
    let host = host.restart().await;
    let restarted_client = host.client(CLIENT_A, SECRET_A);
    assert_eq!(
        restarted_client
            .results(ResultsQuery {
                limit: Some(1),
                cursor: Some(cursor1),
            })
            .await
            .err(),
        Some(ClientError::Rejected(ErrorCode::JobCursorExpired))
    );
    let after_restart = restarted_client
        .results(ResultsQuery {
            limit: Some(10),
            cursor: None,
        })
        .await
        .unwrap();
    let ids: Vec<&str> = after_restart
        .items
        .iter()
        .map(|i| i.result_id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            r1.result_id.as_str(),
            r2.result_id.as_str(),
            r3.result_id.as_str()
        ]
    );
}

#[tokio::test]
async fn offline_missing_and_corrupt_content_returns_410_and_503_without_regeneration() {
    let host = TestHost::start().await;
    host.enroll_execution(CLIENT_A, "enr_11111111111111111111111111111111", SECRET_A);
    let obj = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n".to_vec();
    let missing = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 1,
            pub_seq: 1,
            n: 1,
            artifact_bytes: obj.clone(),
            override_features: None,
            override_version: None,
        },
    );
    let corrupt = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 2,
            pub_seq: 2,
            n: 2,
            artifact_bytes: obj.clone(),
            override_features: None,
            override_version: None,
        },
    );

    // Offline fault 1: remove committed artifact file.
    let missing_path = host.path.join("results/objects").join(&missing.artifact_id);
    std::fs::remove_file(&missing_path).unwrap();

    // Offline fault 2: flip one byte in committed artifact file (same length, bad SHA-256).
    let corrupt_path = host.path.join("results/objects").join(&corrupt.artifact_id);
    let mut tampered = std::fs::read(&corrupt_path).unwrap();
    tampered[0] ^= 0xff;
    std::fs::write(&corrupt_path, &tampered).unwrap();

    let client = host.client(CLIENT_A, SECRET_A);
    assert_eq!(
        client.artifact(&missing.artifact_id, 1_048_576).await.err(),
        Some(ClientError::Rejected(ErrorCode::ArtifactUnavailable))
    );
    assert_eq!(
        client.artifact(&corrupt.artifact_id, 1_048_576).await.err(),
        Some(ClientError::Rejected(ErrorCode::StorageIntegrityFault))
    );

    // Listing reports accurate availability for both without regenerating bytes.
    let page = client.results(ResultsQuery::default()).await.unwrap();
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].availability, ResultAvailability::Unavailable);
    assert_eq!(
        page.items[1].availability,
        ResultAvailability::IntegrityFault
    );
    assert!(!missing_path.exists());
    assert_eq!(std::fs::read(&corrupt_path).unwrap(), tampered);

    // Remove manifest too -> 410 artifact_unavailable.
    let missing_manifest = host
        .path
        .join("results/objects")
        .join(&missing.publication_id);
    std::fs::remove_file(&missing_manifest).unwrap();
    assert_eq!(
        client.result_manifest(&missing.result_id).await.err(),
        Some(ClientError::Rejected(ErrorCode::ArtifactUnavailable))
    );
}

#[tokio::test]
async fn historical_manifest_bytes_are_served_verbatim_and_unknown_features_fail_closed() {
    let host = TestHost::start().await;
    host.enroll_execution(CLIENT_A, "enr_11111111111111111111111111111111", SECRET_A);
    let obj = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n".to_vec();
    let future = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 1,
            pub_seq: 1,
            n: 1,
            artifact_bytes: obj,
            override_features: Some(vec![
                "result_publication.rp-0.1",
                "result_publication.future",
            ]),
            override_version: Some("1.0"),
        },
    );

    // Engine serves exact retained bytes verbatim (RP-S18).
    let raw = host.raw_http();
    let resp = raw
        .get(format!(
            "{}/v1/results/{}/manifest",
            host.base_url, future.result_id
        ))
        .header("Authorization", TestHost::bearer(CLIENT_A, SECRET_A))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), future.manifest_bytes.as_slice());

    // Client fails closed on unsupported required_features (never claims usable download).
    let client = host.client(CLIENT_A, SECRET_A);
    assert_eq!(
        client.result_manifest(&future.result_id).await.err(),
        Some(ClientError::Incompatible)
    );
    assert!(decode_result_manifest(&future.manifest_bytes).is_err());
}

#[tokio::test]
async fn revocation_blocks_subsequent_requests_and_aborts_active_stream() {
    use futures_util::StreamExt;
    let host = TestHost::start().await;
    host.enroll_execution(CLIENT_A, "enr_11111111111111111111111111111111", SECRET_A);
    let large_obj = vec![b'a'; 196_608];
    let seeded = seed_committed_result(
        &host.path,
        host.root(),
        SeedSpec {
            client_id: CLIENT_A,
            acceptance_seq: 1,
            pub_seq: 1,
            n: 1,
            artifact_bytes: large_obj.clone(),
            override_features: None,
            override_version: None,
        },
    );
    let auth = host
        .store()
        .authenticate(
            ClientId::parse(CLIENT_A).unwrap(),
            dissect3d_api::TokenDigest::new(Sha256::digest(SECRET_A).into()),
        )
        .unwrap();
    // Deterministic mid-stream revocation: pull chunk 1 (64 KiB), revoke
    // credential through HTTP, then pull chunk 2 -> must abort with PermissionDenied.
    let mut stream = Box::pin(super::artifact_body_stream(
        large_obj,
        host.store().clone(),
        auth,
    ));
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(first.len(), 65_536);

    let client = host.client(CLIENT_A, SECRET_A);
    client.revoke_self().await.unwrap();

    let second = stream.next().await.unwrap();
    assert_eq!(
        second.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(stream.next().await.is_none());

    // Subsequent HTTP requests on all 4 routes are blocked with 401 Unauthorized.
    assert_eq!(
        client.results(ResultsQuery::default()).await.err(),
        Some(ClientError::Rejected(ErrorCode::Unauthorized))
    );
    assert_eq!(
        client.result_manifest(&seeded.result_id).await.err(),
        Some(ClientError::Rejected(ErrorCode::Unauthorized))
    );
    assert_eq!(
        client.artifact(&seeded.artifact_id, 1_048_576).await.err(),
        Some(ClientError::Rejected(ErrorCode::Unauthorized))
    );
    assert_eq!(
        client.storage().await.err(),
        Some(ClientError::Rejected(ErrorCode::Unauthorized))
    );
}

#[tokio::test]
async fn reclaim_block_surfaces_stale_storage_and_diagnostic_without_auto_repair() {
    use std::os::unix::fs::symlink;

    let host = TestHost::start().await;
    host.enroll_execution(CLIENT_A, "enr_50000000000000000000000000000001", SECRET_A);
    let client = host.client(CLIENT_A, SECRET_A);

    // Baseline storage is healthy and current.
    let healthy = client.storage().await.unwrap();
    assert_eq!(
        healthy.measurement.status,
        StorageMeasurementStatus::Current
    );
    assert_eq!(healthy.usage.private_staging_bytes, Some(0));

    // Seed a terminal failed job with a reclaiming allocation whose object is
    // replaced by a planted symlink.
    let job_id = "job_a0000000000000000000000000000001";
    let res_id = "res_a0000000000000000000000000000001";
    let pub_id = "pub_a0000000000000000000000000000001";
    let art_id = "art_a0000000000000000000000000000001";
    let att_id = "att_a0000000000000000000000000000001";
    let db = rusqlite::Connection::open(host.path.join("metadata.sqlite3")).unwrap();
    let instance_id: String = db
        .query_row(
            "SELECT instance_id FROM service_sessions WHERE termination='active'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    db.execute(
        "INSERT INTO jobs
         (job_id,client_id,acceptance_sequence,created_at_ms,resolved_json,storage_status)
         VALUES(?1,?2,1,100,'{}','verified')",
        rusqlite::params![job_id, CLIENT_A],
    )
    .unwrap();
    db.execute(
        "INSERT INTO job_execution
         (job_id,state,phase,snapshot_revision,cleanup_status,updated_at_ms)
         VALUES(?1,'failed','failed',2,'confirmed',200)",
        [job_id],
    )
    .unwrap();
    db.execute(
        "INSERT INTO job_attempts
         VALUES(?1,?2,?3,'ses_a0000000000000000000000000000001',1,150,200,'confirmed')",
        rusqlite::params![att_id, job_id, instance_id],
    )
    .unwrap();
    db.execute(
        "INSERT INTO publication_allocations
         VALUES(?1,?2,?3,?4,?5,'reclaiming',4096,1,1)",
        rusqlite::params![res_id, pub_id, job_id, att_id, instance_id],
    )
    .unwrap();
    db.execute(
        "INSERT INTO result_files VALUES(?1,?2,'artifact','mesh.obj','application/octet-stream',4096,zeroblob(32))",
        rusqlite::params![art_id, res_id],
    )
    .unwrap();
    drop(db);

    let objects_dir = host.path.join("results/objects");
    host.root()
        .ensure_private_directory(&RelativePath::parse("results/objects").unwrap())
        .unwrap();
    let outside = host.dir.as_ref().unwrap().path().join("outside-target.txt");
    std::fs::write(&outside, b"must-not-be-deleted").unwrap();
    let planted = objects_dir.join(art_id);
    symlink(&outside, &planted).unwrap();

    // Reclamation must fail closed: stop turn, keep charge, leave planted link
    // and outside target untouched, and record bounded diagnostic.
    let err = crate::publication::storage::reclaim_turn(host.store(), host.root()).unwrap_err();
    assert_eq!(err, crate::publication::PublicationError::Storage);
    assert!(planted.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read(&outside).unwrap(), b"must-not-be-deleted");
    assert!(crate::diagnostics::has_publication_reclaim_failure(
        host.root()
    ));

    // GET /v1/storage surfaces the blocked state as `stale` with charged
    // `private_staging_bytes > 0` and no automatic repair.
    let blocked = client.storage().await.unwrap();
    assert_eq!(blocked.measurement.status, StorageMeasurementStatus::Stale);
    assert_eq!(blocked.usage.private_staging_bytes, Some(4096));
    assert!(planted.symlink_metadata().unwrap().file_type().is_symlink());

    // After manual operator removal of the planted link, a clean reclaim turn
    // releases the charge and restores `current` measurement status.
    std::fs::remove_file(&planted).unwrap();
    let report = crate::publication::storage::reclaim_turn(host.store(), host.root()).unwrap();
    assert_eq!(report.released_bytes, 4096);
    assert!(!crate::diagnostics::has_publication_reclaim_failure(
        host.root()
    ));
    let recovered = client.storage().await.unwrap();
    assert_eq!(
        recovered.measurement.status,
        StorageMeasurementStatus::Current
    );
    assert_eq!(recovered.usage.private_staging_bytes, Some(0));
}
