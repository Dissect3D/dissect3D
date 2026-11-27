#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "Fault and migration tests open the SQLite file directly to plant or inspect states \
              the store API cannot express; production opens only via store/schema.rs"
)]
use super::*;
use crate::store::DurableInput;
use crate::{AuthContext, CorePolicy, Store, VerifiedEnrollment};
use dissect3d_api::*;
use dissect3d_platform::{
    AuthorityLease, OwnedRoot, RelativePath, RootPurpose, current_owner_identity,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read};
struct Fixture {
    _parent: tempfile::TempDir,
    root: OwnedRoot,
    store: Store,
    auth: AuthContext,
    prepared: crate::submission_fixture::PreparedFixture,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).unwrap();
        let lease = AuthorityLease::acquire(&root).unwrap();
        let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
        let identity = store.identity().unwrap();
        let client = ClientId::parse("cli_11111111111111111111111111111111").unwrap();
        let digest = TokenDigest::new([1; 32]);
        store
            .enroll(VerifiedEnrollment::new_submission_access(
                current_owner_identity().unwrap(),
                identity.installation_id,
                identity.instance_id,
                EnrollmentId::parse("enr_11111111111111111111111111111111").unwrap(),
                client.clone(),
                digest.clone(),
            ))
            .unwrap();
        let auth = store.authenticate(client, digest).unwrap();
        let root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
        let prepared = crate::submission_fixture::verified_fixture_for_admission(&root);
        Self {
            _parent: dir,
            root,
            store,
            auth,
            prepared,
        }
    }
    fn capture(&self) -> InputIdentity {
        let bytes = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");
        let r = self
            .store
            .reserve_upload(
                self.auth.clone(),
                bytes.len() as u64,
                "application/octet-stream".into(),
                self.root.available_space_bytes().unwrap(),
            )
            .unwrap();
        let staged =
            RelativePath::parse(format!("inputs/staging/{}.part", r.input_id.as_str())).unwrap();
        let final_path =
            RelativePath::parse(format!("inputs/data/{}.bin", r.input_id.as_str())).unwrap();
        let mut writer = self.root.begin_input(&staged).unwrap();
        writer.write_chunk(bytes).unwrap();
        let file = writer.finish(&final_path).unwrap();
        self.store
            .complete_upload(
                self.auth.clone(),
                r,
                DurableInput {
                    file,
                    sha256: Sha256::digest(bytes).into(),
                },
            )
            .unwrap()
            .identity
    }
    fn request(&self, input: &InputIdentity) -> ExecutionJobRequest {
        decode_execution_request(&serde_json::to_vec(&serde_json::json!({"api_version":"1.0","support_ref":"test.mesh-copy@fixture-r1","task":{"id":"dissect3d.test.mesh-copy","version":"1.0"},"inputs":{"mesh":[{"input_id":input.input_id}]},"parameters":{},"required_features":[EXECUTION_FEATURE],"evaluation_consent":false,"execution":{"timeout_ms":1200}})).unwrap()).unwrap()
    }
    fn candidate(&self, req: &ExecutionJobRequest) -> admission::AdmissionCandidate {
        let ids = req
            .request
            .inputs
            .values()
            .flatten()
            .map(|i| i.input_id.clone())
            .collect();
        let pins = self
            .store
            .pin_verified_inputs(self.auth.clone(), ids)
            .unwrap();
        let mut readers = BTreeMap::new();
        for input in &pins.identities {
            let path = RelativePath::parse(format!("inputs/data/{}.bin", input.input_id.as_str()))
                .unwrap();
            readers.insert(
                input.input_id.as_str().to_owned(),
                Box::new(self.root.open_immutable_input(&path).unwrap()) as Box<dyn Read + Send>,
            );
        }
        admission::build_execution_candidate(
            &self.prepared.catalog,
            &admission::PreparedAdmission::from_verified_fixture(&self.prepared.readiness),
            req,
            encode_execution_request(req).unwrap().len(),
            pins,
            readers,
        )
        .unwrap()
    }
}
#[test]
fn v2_acceptance_captures_policy_and_recovers_exact_identity_at_capacity() {
    let f = Fixture::new();
    let input = f.capture();
    let req = f.request(&input);
    let key = IdempotencyKey::parse("execution-key").unwrap();
    let receipt = f
        .store
        .accept_execution_job(f.auth.clone(), key.clone(), req.clone(), f.candidate(&req))
        .unwrap();
    let db = rusqlite::Connection::open(f.root.path().join("metadata.sqlite3")).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT canonicalization_version FROM submission_bindings",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT timeout_ms FROM job_execution", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1200
    );
    assert_eq!(
        receipt.resolved.selection.support_ref,
        "test.mesh-copy@fixture-r1"
    );
    f.store
        .set_test_job_limits(crate::store::admission::AcceptanceLimits {
            queued: 0,
            bindings: 0,
            ..Default::default()
        });
    let recovered = f
        .store
        .probe_execution_binding(f.auth.clone(), key.clone(), req.clone())
        .unwrap()
        .unwrap();
    assert_eq!(recovered.job_id, receipt.job_id);
    assert_eq!(recovered.resolved, receipt.resolved);
    assert!(recovered.replayed);
    let mut conflict = req.clone();
    conflict.execution.timeout_ms = Some(1201);
    assert_eq!(
        f.store
            .probe_execution_binding(f.auth.clone(), key, conflict)
            .unwrap_err()
            .code,
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn failed_v2_commit_leaves_no_binding_policy_or_sequence_and_exact_retry_works() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let key = IdempotencyKey::parse("execution-rollback").unwrap();
    f.store.fail_next_job_commit().unwrap();
    assert_eq!(
        f.store
            .accept_execution_job(f.auth.clone(), key.clone(), req.clone(), f.candidate(&req))
            .unwrap_err()
            .code,
        ErrorCode::StoreUnavailable
    );
    let db = rusqlite::Connection::open(f.root.path().join("metadata.sqlite3")).unwrap();
    for table in [
        "jobs",
        "submission_bindings",
        "job_execution",
        "job_inputs",
        "job_acceptance_events",
    ] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(
        db.query_row("SELECT value FROM job_sequence", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        f.store
            .accept_execution_job(f.auth.clone(), key, req.clone(), f.candidate(&req))
            .unwrap()
            .acceptance_sequence,
        1
    );
}
#[test]
fn v1_and_v2_share_one_key_domain_without_reinterpreting_original_requests() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let key = IdempotencyKey::parse("one-domain").unwrap();
    let first = f
        .store
        .accept_execution_job(f.auth.clone(), key.clone(), req.clone(), f.candidate(&req))
        .unwrap();
    let mut old = req.request.clone();
    old.required_features.clear();
    assert_eq!(
        f.store
            .probe_job_binding(f.auth.clone(), key.clone(), old)
            .unwrap_err()
            .code,
        ErrorCode::IncompatibleContract
    );
    let original = f
        .store
        .probe_execution_binding(f.auth.clone(), key, req)
        .unwrap()
        .unwrap();
    assert_eq!(original.job_id, first.job_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versioned_submission_uses_existing_reconciliation_and_binding_first_service() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let auth = f.auth.clone();
    let prepared = admission::PreparedAdmission::from_verified_fixture(&f.prepared.readiness);
    let root = std::sync::Arc::new(f.root);
    let store = std::sync::Arc::new(f.store);
    let inputs = std::sync::Arc::new(crate::inputs::InputService::new(
        store.clone(),
        root.clone(),
    ));
    let jobs = std::sync::Arc::new(crate::jobs::JobsService::new(store.clone(), root.clone()));
    let (input_stop, input_rx) = tokio::sync::oneshot::channel();
    let (job_stop, job_rx) = tokio::sync::oneshot::channel();
    let ir = tokio::spawn(crate::inputs::recovery::run(inputs.clone(), input_rx));
    let jr = tokio::spawn(jobs.clone().run_recovery(job_rx));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !inputs.is_reconciled() || !jobs.is_reconciled() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let service = service::SubmissionService::new(
        store.clone(),
        root.clone(),
        std::sync::Arc::new(f.prepared.catalog),
        Some(prepared),
        inputs.clone(),
        jobs.clone(),
    );
    let key = IdempotencyKey::parse("service-execution").unwrap();
    let first = service
        .submit_execution(auth.clone(), key.clone(), req.clone())
        .await
        .unwrap();
    let recovery = service::SubmissionService::new(
        store,
        root,
        std::sync::Arc::new(crate::support::Catalog::empty()),
        None,
        inputs,
        jobs,
    );
    // Binding-first recovery does not require the captured support to be prepared now.
    let replay = recovery.submit_execution(auth, key, req).await.unwrap();
    assert_eq!(first.job_id, replay.job_id);
    assert!(replay.replayed);
    let _ = input_stop.send(());
    let _ = job_stop.send(());
    ir.await.unwrap();
    jr.await.unwrap();
}
