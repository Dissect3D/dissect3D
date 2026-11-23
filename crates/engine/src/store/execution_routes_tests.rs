//! WE-P06 execution routes over real HTTPS: the explicit execution host
//! (prepared r2 package, controller, contained r2 worker) driven by the real
//! `dissect3d_api` client, plus raw requests for negotiation and body checks.
//!
//! Credentials are enrolled and execution-authorized through the Store with a
//! known secret, so this checks routes and authorization, not native
//! enrollment (the CLI's `auth setup --execution-access` is WE-P08). Evidence
//! is the host it ran on (WSL2/ext4 here), not native acceptance elsewhere.
use super::fixture_attempts_tests::worker_launch;
use super::*;
use crate::execution::controller::{ExecutionDependencies, ExecutionLimits, start};
use crate::execution_fixture::attempts::FixtureAttempts;
use crate::execution_fixture::preparation::{load, prepare};
use crate::http::HttpServer;
use dissect3d_platform::RootPurpose;
use std::path::PathBuf;
use tokio::sync::oneshot;

const MESH: &[u8] = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");
const BOUND: Duration = Duration::from_secs(120);

struct Host {
    /// The root and Store, kept to serve them again.
    prepared: Option<Prepared>,
    base_url: String,
    ca_der: Vec<u8>,
    ca_sha256: [u8; 32],
    identity: StoreIdentity,
    stop: Option<oneshot::Sender<()>>,
    /// Private fault latches this server reads (lost replies, staging expiry).
    hooks: Arc<crate::submission::test_support::Hooks>,
    task: tokio::task::JoinHandle<Result<(), crate::http::HttpError>>,
}

/// One enrolled, execution-authorized client with a known secret.
pub(super) fn enroll(store: &Store, identity: &StoreIdentity, n: u8) -> (ClientId, [u8; 32]) {
    let secret = [n; 32];
    let digest = TokenDigest::new(Sha256::digest(secret).into());
    let hex = format!("{n:02x}").repeat(16);
    let client = ClientId::parse(format!("cli_{hex}")).unwrap();
    store
        .enroll(VerifiedEnrollment::new_submission_access(
            current_owner_identity().unwrap(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse(format!("enr_{hex}")).unwrap(),
            client.clone(),
            digest.clone(),
        ))
        .unwrap();
    store
        .authorize_execution(reauthorization::VerifiedAuthorization {
            owner: current_owner_identity().unwrap(),
            installation_id: identity.installation_id.clone(),
            instance_id: identity.instance_id.clone(),
            client_id: client.clone(),
            token_digest: digest,
            authorization_id: format!("aut_{hex}"),
        })
        .unwrap();
    (client, secret)
}

/// A prepared r2 root with its Store and two enrolled clients.
struct Prepared {
    dir: tempfile::TempDir,
    path: PathBuf,
    store: Arc<Store>,
    identity: StoreIdentity,
    clients: [(ClientId, [u8; 32]); 2],
}
impl Prepared {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine");
        prepare(&path, &worker_launch()).unwrap();
        let root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
        let lease = AuthorityLease::acquire(&root).unwrap();
        let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).unwrap());
        let identity = store.identity().unwrap();
        let clients = [
            enroll(&store, &identity, 0x21),
            enroll(&store, &identity, 0x22),
        ];
        Self {
            dir,
            path,
            store,
            identity,
            clients,
        }
    }
}

impl Host {
    /// The explicit execution host plus two clients.
    async fn start() -> (Self, Client, Client) {
        let host = Self::serve(Prepared::new(), true).await;
        let a = host.0.client(&host.1[0]);
        let b = host.0.client(&host.1[1]);
        (host.0, a, b)
    }

    /// Serve the prepared Store with prepared admission, with or without
    /// the execution controller.
    async fn serve(prepared: Prepared, execution: bool) -> (Self, [(ClientId, [u8; 32]); 2]) {
        let Prepared {
            dir,
            path,
            store,
            identity,
            clients,
        } = prepared;
        let open = || Arc::new(OwnedRoot::open(&path, RootPurpose::EngineData).unwrap());
        let hooks = Arc::new(crate::submission::test_support::Hooks::default());
        crate::submission::test_support::register(open().path(), &hooks);
        let mut fixture = load(&open()).unwrap();
        let catalog = Arc::new(std::mem::replace(
            &mut fixture.catalog,
            crate::support::Catalog::empty(),
        ));
        let readiness = fixture.readiness.clone();
        let server = if execution {
            let attempts_root = open();
            let handle = start(ExecutionDependencies {
                store: store.clone(),
                root: Arc::clone(&attempts_root),
                source: Arc::new(FixtureAttempts::new(fixture, attempts_root)),
                limits: ExecutionLimits::CONTROLLED,
            });
            HttpServer::bind_with_execution(
                &open(),
                store.clone(),
                CorePolicy::default(),
                catalog,
                readiness,
                Arc::new(handle),
            )
            .await
        } else {
            HttpServer::bind_with_prepared_catalog(
                &open(),
                store.clone(),
                CorePolicy::default(),
                catalog,
                readiness,
            )
            .await
        }
        .unwrap();
        let base_url = server.base_url();
        let (ca_der, ca_sha256) = server.trust_anchor();
        let (ca_der, ca_sha256) = (ca_der.to_vec(), *ca_sha256);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.run(stopped));
        let host = Self {
            prepared: Some(Prepared {
                dir,
                path,
                store,
                identity: identity.clone(),
                clients: clients.clone(),
            }),
            base_url,
            ca_der,
            ca_sha256,
            identity,
            stop: Some(stop),
            hooks,
            task,
        };
        (host, clients)
    }

    fn client(&self, (client, secret): &(ClientId, [u8; 32])) -> Client {
        Client::new(
            ConnectionMaterial::new(
                self.base_url.clone(),
                self.identity.installation_id.clone(),
                self.identity.instance_id.clone(),
                client.clone(),
                self.ca_der.clone(),
                self.ca_sha256,
                SecretToken::new(secret.to_vec()).unwrap(),
            ),
            ClientLimits::default(),
        )
        .unwrap()
    }

    /// A raw request with the first client's bearer.
    async fn raw(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> (u16, serde_json::Value) {
        self.raw_as(0x21, method, path, headers, body).await
    }

    /// A raw request with the bearer of the client enrolled with byte `n`.
    async fn raw_as(
        &self,
        n: u8,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> (u16, serde_json::Value) {
        let http = reqwest::Client::builder()
            .https_only(true)
            .tls_certs_only([reqwest::Certificate::from_der(&self.ca_der).unwrap()])
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let hex = format!("{n:02x}");
        let bearer = format!("Bearer cli_{}.{}", hex.repeat(16), hex.repeat(32));
        let mut request = http
            .request(method, format!("{}{path}", self.base_url))
            .header(reqwest::header::AUTHORIZATION, bearer);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_owned());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let body = response.json().await.unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    /// Stop serving; the root and Store stay for another server.
    async fn stop(mut self) -> Prepared {
        let _ = self.stop.take().unwrap().send(());
        let _ = tokio::time::timeout(Duration::from_secs(15), self.task).await;
        self.prepared.take().unwrap()
    }
}

pub(super) fn request(input: &InputId, parameters: serde_json::Value) -> ExecutionJobRequest {
    decode_execution_request(
        &serde_json::to_vec(&serde_json::json!({
            "api_version": "1.0",
            "support_ref": "test.mesh-copy@fixture-r2",
            "task": {"id": "dissect3d.test.mesh-copy", "version": "1.0"},
            "inputs": {"mesh": [{"input_id": input}]},
            "parameters": parameters,
            "required_features": [EXECUTION_FEATURE],
            "evaluation_consent": false,
            "execution": {"timeout_ms": 600000}
        }))
        .unwrap(),
    )
    .unwrap()
}

pub(super) async fn upload(client: &Client) -> InputId {
    client
        .create_execution_input(MESH, MESH.len() as u64, "application/octet-stream")
        .await
        .unwrap()
        .identity
        .input_id
}

pub(super) async fn submit(
    client: &Client,
    key: &str,
    parameters: serde_json::Value,
) -> (ExecutionAcceptance, ExecutionJobRequest) {
    let input = upload(client).await;
    let request = request(&input, parameters);
    let body = ExecutionSubmissionBody::fresh(&request).unwrap();
    let receipt = client
        .submit_execution_job(&IdempotencyKey::parse(key).unwrap(), &body)
        .await
        .unwrap();
    (receipt, request)
}

pub(super) async fn wait(
    client: &Client,
    job: &JobId,
    done: impl Fn(&ExecutionJobSnapshot) -> bool,
) -> ExecutionJobSnapshot {
    let deadline = tokio::time::Instant::now() + BOUND;
    loop {
        let snapshot = client.execution_job(job).await.unwrap();
        if done(&snapshot) {
            return snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out: {:?}",
            snapshot.summary
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) fn terminal(snapshot: &ExecutionJobSnapshot) -> bool {
    use ExecutionJobState as S;
    matches!(
        snapshot.summary.state,
        S::Succeeded | S::Partial | S::Failed | S::Canceled | S::Interrupted
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_execution_host_advertises_and_runs_a_job_to_publication() {
    let (host, client, _) = Host::start().await;
    let capability = client
        .require_execution_capability("jobs.cancel")
        .await
        .unwrap();
    assert!(capability.dispatch_enabled);
    assert_eq!(capability.required_features, vec![EXECUTION_FEATURE]);
    assert_eq!(capability.limits["worker_handshake_ms"], 10_000);
    let info = client.info().await.unwrap();
    assert!(
        info.submission.unwrap().dispatch_enabled,
        "old Stage 3 clients refuse"
    );

    let (receipt, request) = submit(&client, "route-success", serde_json::json!({})).await;
    assert!(!receipt.replayed);
    assert_eq!(receipt.job_contract, JOB_CONTRACT);
    assert_eq!(receipt.retry_of, None);
    let done = wait(&client, &receipt.job_id, terminal).await;
    assert_eq!(done.summary.state, ExecutionJobState::Succeeded);
    assert!(done.summary.snapshot_revision > 1);
    assert!(done.summary.attempt_id.is_some());
    assert_eq!(done.summary.cleanup.status, CleanupStatus::Confirmed);
    assert_eq!(done.summary.result_ids.len(), 1);
    assert_eq!(done.resolved, receipt.resolved);

    // Same key and body replays; a changed execution policy conflicts.
    let body = ExecutionSubmissionBody::fresh(&request).unwrap();
    let key = IdempotencyKey::parse("route-success").unwrap();
    let replay = client.submit_execution_job(&key, &body).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.job_id, receipt.job_id);
    let mut changed = request.clone();
    changed.execution.timeout_ms = Some(20_000);
    let conflict = client
        .submit_execution_job(&key, &ExecutionSubmissionBody::fresh(&changed).unwrap())
        .await;
    assert!(
        matches!(
            conflict,
            Err(SubmissionClientError::Rejected(ref e)) if e.error.code == ErrorCode::IdempotencyConflict
        ),
        "{conflict:?}"
    );
    let page = client.execution_jobs(JobsQuery::default()).await.unwrap();
    assert_eq!(page.items.len(), 1);
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_and_linked_retry_through_the_routes_are_creator_private() {
    let (host, client, other) = Host::start().await;
    let (receipt, _) = submit(
        &client,
        "route-hold",
        serde_json::json!({"hold_before_candidate": true}),
    )
    .await;
    let job = receipt.job_id.clone();
    wait(&client, &job, |s| s.summary.phase == "executing").await;
    // Queued behind it: eligible and waiting, so no blocker is invented.
    let (queued, _) = submit(&client, "route-queued", serde_json::json!({})).await;
    let snapshot = client.execution_job(&queued.job_id).await.unwrap();
    assert_eq!(snapshot.summary.state, ExecutionJobState::Queued);
    assert!(
        snapshot.summary.blockers.is_empty(),
        "{:?}",
        snapshot.summary.blockers
    );
    client.cancel_execution_job(&queued.job_id).await.unwrap();

    // Another creator sees nothing and cancels nothing.
    assert!(matches!(
        other.execution_job(&job).await,
        Err(ClientError::Rejected(ErrorCode::NotFound))
    ));
    assert!(matches!(
        other.cancel_execution_job(&job).await,
        Err(SubmissionClientError::Rejected(ref e)) if e.error.code == ErrorCode::NotFound
    ));

    let response = client.cancel_execution_job(&job).await.unwrap();
    assert_eq!(response.cancel_effect, CancelEffect::Requested);
    let done = wait(&client, &job, terminal).await;
    assert_eq!(done.summary.state, ExecutionJobState::Canceled);
    assert_eq!(done.summary.cleanup.status, CleanupStatus::Confirmed);
    assert!(done.summary.result_ids.is_empty());
    let repeat = client.cancel_execution_job(&job).await.unwrap();
    assert_eq!(repeat.cancel_effect, CancelEffect::AlreadyTerminal);

    // Explicit linked retry: a new job with the exact stored configuration.
    let key = IdempotencyKey::parse("route-retry").unwrap();
    let retried = client.retry_execution_job(&job, &key).await.unwrap();
    assert_eq!(retried.retry_of.as_ref(), Some(&job));
    assert_ne!(retried.job_id, job);
    assert_eq!(retried.resolved, receipt.resolved);
    let replay = client.retry_execution_job(&job, &key).await.unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.job_id, retried.job_id);
    // The retry was woken and runs (it holds again); the source is unchanged.
    wait(&client, &retried.job_id, |s| s.summary.phase == "executing").await;
    assert_eq!(
        client.execution_job(&job).await.unwrap().summary.state,
        ExecutionJobState::Canceled
    );
    client.cancel_execution_job(&retried.job_id).await.unwrap();
    wait(&client, &retried.job_id, terminal).await;
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unnegotiated_or_malformed_execution_requests_are_refused() {
    let (host, client, _) = Host::start().await;
    let input = upload(&client).await;
    let body = serde_json::to_string(&request(&input, serde_json::json!({}))).unwrap();
    let contract = [("Dissect3D-Job-Contract", "we-0.1")];
    let keyed = [
        ("Dissect3D-Job-Contract", "we-0.1"),
        ("Idempotency-Key", "route-raw"),
    ];
    // Fresh unnegotiated mutation on an execution engine.
    let (status, error) = host
        .raw(
            reqwest::Method::POST,
            "/v1/jobs",
            &[("Idempotency-Key", "route-legacy")],
            Some(&body),
        )
        .await;
    assert_eq!(status, 409);
    assert_eq!(error["error"]["code"], "incompatible_contract");
    // Another contract version.
    let (status, error) = host
        .raw(
            reqwest::Method::POST,
            "/v1/jobs",
            &[
                ("Dissect3D-Job-Contract", "we-9.9"),
                ("Idempotency-Key", "route-v9"),
            ],
            Some(&body),
        )
        .await;
    assert_eq!(
        (status, error["error"]["code"].clone()),
        (409, "incompatible_contract".into())
    );
    // An accepted job, then control bodies.
    let (status, receipt) = host
        .raw(reqwest::Method::POST, "/v1/jobs", &keyed, Some(&body))
        .await;
    assert_eq!(status, 201, "{receipt}");
    let job = receipt["job_id"].as_str().unwrap().to_owned();
    let cancel = format!("/v1/jobs/{job}/cancel");
    let (status, _) = host
        .raw(
            reqwest::Method::POST,
            &cancel,
            &[],
            Some(r#"{"api_version":"1.0","required_features":[]}"#),
        )
        .await;
    assert_eq!(status, 409, "cancel needs the negotiated contract");
    for (bad, code) in [
        (r#"{"api_version":"1.0","required_features":[],"x":1}"#, 400),
        (r#"{"api_version":"1.0"}"#, 400),
        (
            r#"{"api_version":"1.0","required_features":["later.feature"]}"#,
            422,
        ),
    ] {
        let (status, _) = host
            .raw(reqwest::Method::POST, &cancel, &contract, Some(bad))
            .await;
        assert_eq!(status, code, "{bad}");
    }
    let retry = format!("/v1/jobs/{job}/retry");
    let (status, _) = host
        .raw(
            reqwest::Method::POST,
            &retry,
            &contract,
            Some(r#"{"api_version":"1.0","required_features":[]}"#),
        )
        .await;
    assert_eq!(status, 400, "retry needs an idempotency key");
    let done = wait(&client, &JobId::parse(job).unwrap(), terminal).await;
    assert_eq!(done.summary.state, ExecutionJobState::Succeeded);
    host.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negotiation_replays_only_existing_stage3_bindings_and_needs_a_controller() {
    let contract = ("Dissect3D-Job-Contract", "we-0.1");
    // A prepared host without a controller: Stage 3 accepts fresh queued work,
    // and negotiated execution requests are refused.
    let (host, clients) = Host::serve(Prepared::new(), false).await;
    let client = host.client(&clients[0]);
    let input = client
        .create_input(MESH, MESH.len() as u64, "application/octet-stream")
        .await
        .unwrap()
        .identity
        .input_id;
    let stage3 = serde_json::json!({
        "api_version": "1.0",
        "support_ref": "test.mesh-copy@fixture-r2",
        "task": {"id": "dissect3d.test.mesh-copy", "version": "1.0"},
        "inputs": {"mesh": [{"input_id": input}]},
        "parameters": {},
        "required_features": [],
        "evaluation_consent": false
    })
    .to_string();
    let (status, legacy) = host
        .raw(
            reqwest::Method::POST,
            "/v1/jobs",
            &[("Idempotency-Key", "stage3-original")],
            Some(&stage3),
        )
        .await;
    assert_eq!(status, 201, "{legacy}");
    let original = legacy["job_id"].as_str().unwrap().to_owned();
    let (status, error) = host
        .raw(
            reqwest::Method::GET,
            &format!("/v1/jobs/{original}"),
            &[contract],
            None,
        )
        .await;
    assert_eq!(
        (status, error["error"]["code"].clone()),
        (409, "incompatible_contract".into()),
        "no controller, no execution routes"
    );
    let prepared = host.stop().await;

    // The same Store behind the execution host.
    let (host, _) = Host::serve(prepared, true).await;
    // Exact original bytes under the header replay the retained binding.
    let (status, replay) = host
        .raw(
            reqwest::Method::POST,
            "/v1/jobs",
            &[contract, ("Idempotency-Key", "stage3-original")],
            Some(&stage3),
        )
        .await;
    assert_eq!(status, 200, "{replay}");
    assert_eq!(replay["job_id"], original.as_str());
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["job_contract"], JOB_CONTRACT);
    // A Stage 3 body without a binding never becomes fresh work.
    let (status, error) = host
        .raw(
            reqwest::Method::POST,
            "/v1/jobs",
            &[contract, ("Idempotency-Key", "stage3-fresh")],
            Some(&stage3),
        )
        .await;
    assert_eq!(
        (status, error["error"]["code"].clone()),
        (409, "incompatible_contract".into())
    );
    // Duplicate contract headers are refused, even with the right value.
    let (status, _) = host
        .raw(
            reqwest::Method::GET,
            &format!("/v1/jobs/{original}"),
            &[contract, contract],
            None,
        )
        .await;
    assert_eq!(status, 409);
    // The replayed job is an ordinary queued job the controller now runs.
    let client = host.client(&clients[0]);
    let done = wait(&client, &JobId::parse(original).unwrap(), terminal).await;
    assert_eq!(done.summary.state, ExecutionJobState::Succeeded);
    host.stop().await;
}

/// A retained r1 job, captured under the older exact profile at the Store
/// (this host serves no r1 catalog), for the first client.
fn accept_r1(prepared: &Prepared, input: &InputId) -> JobId {
    let root = OwnedRoot::open(&prepared.path, RootPurpose::EngineData).unwrap();
    let r1 = crate::submission_fixture::verified_fixture_for_admission(&root);
    let (client, secret) = &prepared.clients[0];
    let auth = prepared
        .store
        .authenticate(
            client.clone(),
            TokenDigest::new(Sha256::digest(secret).into()),
        )
        .unwrap();
    let request = decode_execution_request(
        &serde_json::to_vec(&serde_json::json!({
            "api_version": "1.0",
            "support_ref": "test.mesh-copy@fixture-r1",
            "task": {"id": "dissect3d.test.mesh-copy", "version": "1.0"},
            "inputs": {"mesh": [{"input_id": input}]},
            "parameters": {},
            "required_features": [EXECUTION_FEATURE],
            "evaluation_consent": false,
            "execution": {"timeout_ms": 600000}
        }))
        .unwrap(),
    )
    .unwrap();
    let pins = prepared
        .store
        .pin_verified_inputs(auth.clone(), vec![input.clone()])
        .unwrap();
    let mut readers = BTreeMap::new();
    let path = RelativePath::parse(format!("inputs/data/{}.bin", input.as_str())).unwrap();
    readers.insert(
        input.as_str().to_owned(),
        Box::new(root.open_immutable_input(&path).unwrap()) as Box<dyn Read + Send>,
    );
    let candidate = crate::submission::admission::build_execution_candidate(
        &r1.catalog,
        &crate::submission::admission::PreparedAdmission::from_verified_fixture(&r1.readiness),
        &request,
        encode_execution_request(&request).unwrap().len(),
        pins,
        readers,
    )
    .unwrap();
    prepared
        .store
        .accept_execution_job(
            auth,
            IdempotencyKey::parse("r1-retained").unwrap(),
            request,
            candidate,
        )
        .unwrap()
        .job_id
}

/// (resolved_json, attempt rows, unreleased reservations) of one job.
fn captured(path: &std::path::Path, job: &str) -> (String, i64, i64) {
    Connection::open(path.join(DATABASE_NAME))
        .unwrap()
        .query_row(
            "SELECT j.resolved_json,
                    (SELECT count(*) FROM job_attempts a WHERE a.job_id=j.job_id),
                    (SELECT count(*) FROM resource_reservations r JOIN job_attempts a
                      USING(attempt_id) WHERE a.job_id=j.job_id AND r.released=0)
             FROM jobs j WHERE j.job_id=?1",
            [job],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

/// WE-P06/2: jobs queued while dispatch was disabled keep their IDs,
/// bindings and exact resolutions when the execution host activates; eligible
/// work runs in acceptance order and the older r1 job stays blocked in place,
/// never remapped to r2 and holding no attempt or reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activation_runs_jobs_queued_while_dispatch_was_disabled_in_order() {
    let contract = ("Dissect3D-Job-Contract", "we-0.1");
    let (host, clients) = Host::serve(Prepared::new(), false).await;
    let client = host.client(&clients[0]);
    let mut inputs = Vec::new();
    for _ in 0..3 {
        inputs.push(
            client
                .create_input(MESH, MESH.len() as u64, "application/octet-stream")
                .await
                .unwrap()
                .identity
                .input_id,
        );
    }
    // Oldest first: the r1 job, then two Stage 3 jobs (the first holds).
    let r1 = accept_r1(host.prepared.as_ref().unwrap(), &inputs[0]);
    let stage3 = |input: &InputId, parameters: serde_json::Value| {
        serde_json::json!({
            "api_version": "1.0",
            "support_ref": "test.mesh-copy@fixture-r2",
            "task": {"id": "dissect3d.test.mesh-copy", "version": "1.0"},
            "inputs": {"mesh": [{"input_id": input}]},
            "parameters": parameters,
            "required_features": [],
            "evaluation_consent": false
        })
        .to_string()
    };
    let bodies = [
        (
            "queued-first",
            stage3(
                &inputs[1],
                serde_json::json!({"hold_before_candidate": true}),
            ),
        ),
        ("queued-second", stage3(&inputs[2], serde_json::json!({}))),
    ];
    let mut jobs = Vec::new();
    for (key, body) in &bodies {
        let (status, receipt) = host
            .raw(
                reqwest::Method::POST,
                "/v1/jobs",
                &[("Idempotency-Key", key)],
                Some(body),
            )
            .await;
        assert_eq!(status, 201, "{receipt}");
        jobs.push(receipt["job_id"].as_str().unwrap().to_owned());
    }
    let path = host.prepared.as_ref().unwrap().path.clone();
    let before: Vec<_> = [r1.as_str(), &jobs[0], &jobs[1]]
        .map(|job| captured(&path, job).0)
        .into();
    for job in [r1.as_str(), &jobs[0], &jobs[1]] {
        assert_eq!(
            captured(&path, job).1,
            0,
            "nothing dispatched while disabled"
        );
    }
    let prepared = host.stop().await;

    // Explicit activation over the same Store.
    let (host, _) = Host::serve(prepared, true).await;
    let client = host.client(&clients[0]);
    let first = JobId::parse(jobs[0].clone()).unwrap();
    let second = JobId::parse(jobs[1].clone()).unwrap();
    wait(&client, &first, |s| s.summary.phase == "executing").await;
    // The second waits its turn without a blocker; the r1 job is blocked.
    let snapshot = client.execution_job(&second).await.unwrap();
    assert_eq!(snapshot.summary.state, ExecutionJobState::Queued);
    assert!(
        snapshot.summary.blockers.is_empty(),
        "{:?}",
        snapshot.summary.blockers
    );
    let blocked = wait(&client, &r1, |s| !s.summary.blockers.is_empty()).await;
    assert_eq!(blocked.summary.state, ExecutionJobState::Queued);
    assert_eq!(
        blocked.summary.blockers,
        vec!["profile_not_executable".to_owned()]
    );
    // The same keys and bytes still replay the same jobs.
    for ((key, body), job) in bodies.iter().zip(&jobs) {
        let (status, replay) = host
            .raw(
                reqwest::Method::POST,
                "/v1/jobs",
                &[contract, ("Idempotency-Key", key)],
                Some(body),
            )
            .await;
        assert_eq!(status, 200, "{replay}");
        assert_eq!(replay["job_id"], job.as_str());
    }
    client.cancel_execution_job(&first).await.unwrap();
    assert_eq!(
        wait(&client, &first, terminal).await.summary.state,
        ExecutionJobState::Canceled
    );
    assert_eq!(
        wait(&client, &second, terminal).await.summary.state,
        ExecutionJobState::Succeeded
    );
    // FIFO: the first job's attempt was the only one before the second's.
    let order: Vec<String> = Connection::open(path.join(DATABASE_NAME))
        .unwrap()
        .prepare("SELECT job_id FROM job_attempts ORDER BY dispatched_at_ms, rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(order, jobs);
    // The r1 job is untouched: same resolution, no attempt, no reservation.
    let r1_now = client.execution_job(&r1).await.unwrap();
    assert_eq!(r1_now.summary.state, ExecutionJobState::Queued);
    assert_eq!(captured(&path, r1.as_str()), (before[0].clone(), 0, 0));
    for (job, resolved) in jobs.iter().zip(&before[1..]) {
        assert_eq!(&captured(&path, job).0, resolved, "exact resolution kept");
    }
    host.stop().await;
}

/// WE-P06/5: a lost submission, cancel or retry reply is reconciled by
/// repeating the same request. It finds the committed outcome (the same job,
/// the current cancel effect, the same retry job), never a second job or a
/// fabricated Busy; staging expiry does not stop exact replay of the
/// original input IDs, and nothing is re-uploaded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_replies_reconcile_to_the_same_committed_outcome() {
    use std::sync::atomic::Ordering::Release;
    let (host, client, _) = Host::start().await;
    let input = upload(&client).await;
    let request = request(&input, serde_json::json!({"hold_before_candidate": true}));
    let body = ExecutionSubmissionBody::fresh(&request).unwrap();
    let key = IdempotencyKey::parse("lost-submit").unwrap();
    host.hooks.drop_after.store(true, Release);
    assert!(client.submit_execution_job(&key, &body).await.is_err());
    let replay = client.submit_execution_job(&key, &body).await.unwrap();
    assert!(replay.replayed, "the lost acceptance had committed");
    let job = replay.job_id.clone();
    wait(&client, &job, |s| s.summary.phase == "executing").await;

    host.hooks.drop_after.store(true, Release);
    assert!(client.cancel_execution_job(&job).await.is_err());
    let repeat = client.cancel_execution_job(&job).await.unwrap();
    assert!(
        matches!(
            repeat.cancel_effect,
            CancelEffect::Requested | CancelEffect::AlreadyTerminal
        ),
        "{:?}",
        repeat.cancel_effect
    );
    let done = wait(&client, &job, terminal).await;
    assert_eq!(done.summary.state, ExecutionJobState::Canceled);

    let retry_key = IdempotencyKey::parse("lost-retry").unwrap();
    host.hooks.drop_after.store(true, Release);
    assert!(client.retry_execution_job(&job, &retry_key).await.is_err());
    let retried = client.retry_execution_job(&job, &retry_key).await.unwrap();
    assert!(retried.replayed, "the lost retry had committed");
    assert_eq!(retried.retry_of.as_ref(), Some(&job));

    // Unreferenced staging expires; the original IDs still replay exactly.
    host.hooks.expire_unreferenced.store(true, Release);
    let again = client.submit_execution_job(&key, &body).await.unwrap();
    assert!(
        !host
            .hooks
            .expire_unreferenced
            .load(std::sync::atomic::Ordering::Acquire),
        "the staging cleanup pass ran"
    );
    assert!(again.replayed);
    assert_eq!(again.job_id, job);
    let page = client.execution_jobs(JobsQuery::default()).await.unwrap();
    assert_eq!(page.items.len(), 2, "one job and one retry, nothing more");

    wait(&client, &retried.job_id, |s| s.summary.phase == "executing").await;
    client.cancel_execution_job(&retried.job_id).await.unwrap();
    wait(&client, &retried.job_id, terminal).await;
    let attempts: i64 = Connection::open(host.prepared.as_ref().unwrap().path.join(DATABASE_NAME))
        .unwrap()
        .query_row("SELECT count(*) FROM job_attempts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(attempts, 2, "one attempt per job");
    host.stop().await;
}

/// The prepared selection's discovery observation from model detail.
async fn model_observation(host: &Host) -> serde_json::Value {
    let (status, detail) = host
        .raw(
            reqwest::Method::GET,
            concat!(
                "/v1/models/test.mesh-copy%40fixture-r2?task_id=dissect3d.test.mesh-copy",
                "&task_version=1.0&runtime_ref=test.cpu%40fixture-r2&variant=fixture"
            ),
            &[],
            None,
        )
        .await;
    assert_eq!(status, 200, "{detail}");
    detail["item"]["observations"][0].clone()
}

/// Model ids listed with `loaded=<value>`.
async fn listed(host: &Host, loaded: bool) -> Vec<serde_json::Value> {
    let (status, page) = host
        .raw(
            reqwest::Method::GET,
            &format!("/v1/models?loaded={loaded}"),
            &[],
            None,
        )
        .await;
    assert_eq!(status, 200, "{page}");
    page["items"].as_array().unwrap().clone()
}

/// WE-P06/6: the execution host feeds engine-owned facts into discovery.
/// The prepared selection is installed, ready and eligible but not loaded;
/// a held worker reports loaded with its reserved resource, and only
/// confirmed cleanup clears it. The host without a controller keeps the
/// Phase 2 answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_reports_installed_ready_and_loaded_facts_from_their_owners() {
    let (host, clients) = Host::serve(Prepared::new(), false).await;
    let observation = model_observation(&host).await;
    assert_eq!(observation["installation"]["status"], "absent");
    assert_eq!(observation["eligibility"]["status"], "blocked");
    assert!(
        observation["eligibility"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["code"] == "execution_unavailable"),
        "{observation}"
    );
    let prepared = host.stop().await;

    let (host, _) = Host::serve(prepared, true).await;
    let client = host.client(&clients[0]);
    let observation = model_observation(&host).await;
    assert_eq!(observation["scope"], "selection");
    assert_eq!(observation["installation"]["status"], "present");
    assert!(observation["installation"]["realization"].is_string());
    assert_eq!(observation["readiness"]["status"], "passed");
    assert_eq!(observation["readiness"]["freshness"], "current");
    assert_eq!(observation["execution_authorization"]["status"], "allowed");
    assert_eq!(
        observation["eligibility"]["status"], "eligible",
        "{observation}"
    );
    assert_eq!(observation["loaded"]["status"], "not_loaded");
    assert_eq!(
        observation["loaded"]["allocation_ids"],
        serde_json::json!([])
    );
    assert!(listed(&host, true).await.is_empty());
    assert_eq!(listed(&host, false).await.len(), 1);

    let (receipt, _) = submit(
        &client,
        "loaded-hold",
        serde_json::json!({"hold_before_candidate": true}),
    )
    .await;
    let job = receipt.job_id;
    wait(&client, &job, |s| s.summary.phase == "executing").await;
    let observation = model_observation(&host).await;
    assert_eq!(observation["loaded"]["status"], "loaded", "{observation}");
    assert_eq!(
        observation["loaded"]["allocation_ids"],
        serde_json::json!(["cpu:fixture"])
    );
    assert!(observation["loaded"]["observed_at_ms"].is_u64());
    assert_eq!(listed(&host, true).await.len(), 1);
    assert!(listed(&host, false).await.is_empty());

    client.cancel_execution_job(&job).await.unwrap();
    let done = wait(&client, &job, terminal).await;
    assert_eq!(done.summary.cleanup.status, CleanupStatus::Confirmed);
    let observation = model_observation(&host).await;
    assert_eq!(
        observation["loaded"]["status"], "not_loaded",
        "{observation}"
    );
    assert!(listed(&host, true).await.is_empty());
    host.stop().await;
}

/// WE-P06/6: a credential without the execution grants is refused by every
/// control route, before any job lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_routes_need_their_grants() {
    let prepared = Prepared::new();
    let hex = "23".repeat(16);
    prepared
        .store
        .enroll(VerifiedEnrollment::new_submission_access(
            current_owner_identity().unwrap(),
            prepared.identity.installation_id.clone(),
            prepared.identity.instance_id.clone(),
            EnrollmentId::parse(format!("enr_{hex}")).unwrap(),
            ClientId::parse(format!("cli_{hex}")).unwrap(),
            TokenDigest::new(Sha256::digest([0x23u8; 32]).into()),
        ))
        .unwrap();
    let (host, clients) = Host::serve(prepared, true).await;
    let client = host.client(&clients[0]);
    let (receipt, _) = submit(&client, "grant-job", serde_json::json!({})).await;
    let job = receipt.job_id.as_str().to_owned();
    let contract = [("Dissect3D-Job-Contract", "we-0.1")];
    let keyed = [
        ("Dissect3D-Job-Contract", "we-0.1"),
        ("Idempotency-Key", "grant-retry"),
    ];
    let body = Some(r#"{"api_version":"1.0","required_features":[]}"#);
    for (path, headers) in [
        (format!("/v1/jobs/{job}/cancel"), &contract[..]),
        (format!("/v1/jobs/{job}/retry"), &keyed[..]),
    ] {
        let (status, error) = host
            .raw_as(0x23, reqwest::Method::POST, &path, headers, body)
            .await;
        assert_eq!(
            (status, error["error"]["code"].clone()),
            (403, "forbidden".into()),
            "{path}"
        );
    }
    wait(&client, &receipt.job_id, terminal).await;
    host.stop().await;
}
