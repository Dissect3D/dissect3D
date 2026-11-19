//! Deterministic handoff regressions; no protected oracle or assertion is changed.
use super::*;
use crate::submission::equivalence::SubmittedJobRequest;
use dissect3d_api::*;
use dissect3d_platform::RootPurpose;
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
    fn candidate(
        &self,
        req: &ExecutionJobRequest,
    ) -> crate::submission::admission::AdmissionCandidate {
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
        crate::submission::admission::build_execution_candidate(
            &self.prepared.catalog,
            &crate::submission::admission::PreparedAdmission::from_verified_fixture(
                &self.prepared.readiness,
            ),
            req,
            encode_execution_request(req).unwrap().len(),
            pins,
            readers,
        )
        .unwrap()
    }
}

fn snapshot(
    f: &Fixture,
    key: &IdempotencyKey,
    request: &SubmittedJobRequest,
) -> submission::ReadState {
    f.store
        .request(|reply| {
            Command::ReadSubmission(f.auth.clone(), key.clone(), request.clone(), reply)
        })
        .unwrap()
}
fn finish(
    f: &Fixture,
    key: &IdempotencyKey,
    request: &SubmittedJobRequest,
    candidate: Option<Arc<crate::submission::admission::AdmissionCandidate>>,
    prepared: submission::Prepared,
) -> Result<Option<Option<AcceptanceReceipt>>, crate::submission::SubmissionError> {
    f.store.request(|reply| {
        Command::FinishSubmission(
            f.auth.clone(),
            key.clone(),
            request.clone(),
            candidate,
            Box::new(prepared),
            reply,
        )
    })
}
#[test]
fn actor_reads_remain_responsive_and_do_not_invalidate_preparation() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req);
    let key = IdempotencyKey::parse("responsive").unwrap();
    let state = snapshot(&f, &key, &request);
    // Preparation is caller-owned; the SQL thread answers while it is held.
    let prepared = submission::prepare(&f.root, &f.auth, &key, &request, Some(&candidate), state);
    for _ in 0..8 {
        f.store.identity().unwrap();
    }
    assert!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap()
            .unwrap()
            .unwrap()
            .accepted
    );
}
#[test]
fn replay_does_not_allocate_a_fresh_sequence_or_require_fresh_capacity() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let key = IdempotencyKey::parse("last-sequence").unwrap();
    let accepted = f
        .store
        .accept_execution_job(f.auth.clone(), key.clone(), req.clone(), f.candidate(&req))
        .unwrap();
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    db.execute("UPDATE job_sequence SET value=?1", [i64::MAX])
        .unwrap();
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        queued: 0,
        bindings: 0,
        free_reserve: u64::MAX,
        ..Default::default()
    });
    let replay = f
        .store
        .probe_execution_binding(f.auth.clone(), key, req)
        .unwrap()
        .unwrap();
    assert_eq!(replay.job_id, accepted.job_id);
    assert!(replay.replayed);
}
#[test]
fn revocation_during_preparation_wins_over_both_fresh_work_and_replay() {
    for replay in [false, true] {
        let f = Fixture::new();
        let req = f.request(&f.capture());
        let key = IdempotencyKey::parse("revoked-preparation").unwrap();
        let candidate = Arc::new(f.candidate(&req));
        if replay {
            f.store
                .accept_execution_job(f.auth.clone(), key.clone(), req.clone(), f.candidate(&req))
                .unwrap();
        }
        let request = SubmittedJobRequest::Execution(req);
        let prepared = submission::prepare(
            &f.root,
            &f.auth,
            &key,
            &request,
            Some(&candidate),
            snapshot(&f, &key, &request),
        );
        f.store.revoke_self(f.auth.clone()).unwrap();
        assert_eq!(
            finish(&f, &key, &request, Some(candidate), prepared)
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
    }
}
#[test]
fn capacity_mutation_invalidates_preparation_and_is_rechecked() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let key = IdempotencyKey::parse("capacity-preparation").unwrap();
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req.clone());
    let prepared = submission::prepare(
        &f.root,
        &f.auth,
        &key,
        &request,
        Some(&candidate),
        snapshot(&f, &key, &request),
    );
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        free_reserve: u64::MAX,
        ..Default::default()
    });
    assert!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.store
            .accept_execution_job(f.auth.clone(), key, req.clone(), f.candidate(&req))
            .unwrap_err()
            .code,
        ErrorCode::CapacityExceeded
    );
}
#[test]
fn expired_observation_is_explicitly_stale_and_never_commits() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let key = IdempotencyKey::parse("aged-preparation").unwrap();
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req);
    let mut prepared = submission::prepare(
        &f.root,
        &f.auth,
        &key,
        &request,
        Some(&candidate),
        snapshot(&f, &key, &request),
    );
    prepared.observed_at = Instant::now() - Duration::from_secs(1);
    assert!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap()
            .is_none()
    );
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn competing_v1_v2_preparations_share_one_binding_in_both_orders() {
    for v2_first in [false, true] {
        let f = Fixture::new();
        let req = f.request(&f.capture());
        let key = IdempotencyKey::parse("competing-versions").unwrap();
        let v2 = Arc::new(f.candidate(&req));
        let mut legacy = req.request.clone();
        legacy.required_features.clear();
        let input_ids = legacy
            .inputs
            .values()
            .flatten()
            .map(|i| i.input_id.clone())
            .collect();
        let pins = f
            .store
            .pin_verified_inputs(f.auth.clone(), input_ids)
            .unwrap();
        let mut readers = BTreeMap::new();
        for i in &pins.identities {
            readers.insert(
                i.input_id.as_str().to_owned(),
                Box::new(
                    f.root
                        .open_immutable_input(
                            &RelativePath::parse(format!(
                                "inputs/data/{}.bin",
                                i.input_id.as_str()
                            ))
                            .unwrap(),
                        )
                        .unwrap(),
                ) as Box<dyn Read + Send>,
            );
        }
        let v1 = Arc::new(
            crate::submission::admission::build_candidate(
                &f.prepared.catalog,
                &crate::submission::admission::PreparedAdmission::from_verified_fixture(
                    &f.prepared.readiness,
                ),
                &legacy,
                serde_json::to_vec(&legacy).unwrap().len(),
                pins,
                readers,
            )
            .unwrap(),
        );
        let r1 = SubmittedJobRequest::Legacy(legacy.clone());
        let r2 = SubmittedJobRequest::Execution(req.clone());
        let p1 = submission::prepare(
            &f.root,
            &f.auth,
            &key,
            &r1,
            Some(&v1),
            snapshot(&f, &key, &r1),
        );
        let p2 = submission::prepare(
            &f.root,
            &f.auth,
            &key,
            &r2,
            Some(&v2),
            snapshot(&f, &key, &r2),
        );
        let (first, second) = if v2_first {
            ((&r2, v2, p2), (&r1, v1, p1))
        } else {
            ((&r1, v1, p1), (&r2, v2, p2))
        };
        let accepted = finish(&f, &key, first.0, Some(first.1), first.2)
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            finish(&f, &key, second.0, Some(second.1), second.2)
                .unwrap()
                .is_none()
        );
        let error = if v2_first {
            f.store
                .probe_job_binding(f.auth.clone(), key, legacy)
                .unwrap_err()
        } else {
            f.store
                .probe_execution_binding(f.auth.clone(), key, req)
                .unwrap_err()
        };
        assert_eq!(
            error.code,
            if v2_first {
                ErrorCode::IncompatibleContract
            } else {
                ErrorCode::IdempotencyConflict
            }
        );
        assert_eq!(accepted.acceptance_sequence, 1);
        let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[test]
fn changed_or_expired_input_is_rejected_by_the_final_sql_check() {
    for mutation in [
        "UPDATE captured_inputs SET sha256=zeroblob(32)",
        "UPDATE captured_inputs SET completed_at_ms=0,expires_at_ms=1",
    ] {
        let f = Fixture::new();
        let req = f.request(&f.capture());
        let key = IdempotencyKey::parse("changed-input").unwrap();
        let candidate = Arc::new(f.candidate(&req));
        let request = SubmittedJobRequest::Execution(req);
        let prepared = submission::prepare(
            &f.root,
            &f.auth,
            &key,
            &request,
            Some(&candidate),
            snapshot(&f, &key, &request),
        );
        // Isolated offline-fault injection, deliberately bypassing the normal
        // actor mutation generation to prove the final SQL validity check itself.
        let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
        db.execute(mutation, []).unwrap();
        assert_eq!(
            finish(&f, &key, &request, Some(candidate), prepared)
                .unwrap_err()
                .code,
            ErrorCode::InputUnavailable
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
#[test]
fn dropped_final_reply_preserves_the_committed_v2_binding() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let key = IdempotencyKey::parse("dropped-final").unwrap();
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req.clone());
    let prepared = submission::prepare(
        &f.root,
        &f.auth,
        &key,
        &request,
        Some(&candidate),
        snapshot(&f, &key, &request),
    );
    let (reply, rx) = mpsc::sync_channel(1);
    drop(rx);
    f.store
        .sender
        .send(Command::FinishSubmission(
            f.auth.clone(),
            key.clone(),
            request,
            Some(candidate),
            Box::new(prepared),
            reply,
        ))
        .ok()
        .unwrap();
    let a = f
        .store
        .probe_execution_binding(f.auth.clone(), key.clone(), req.clone())
        .unwrap()
        .unwrap();
    let b = f
        .store
        .probe_execution_binding(f.auth.clone(), key, req)
        .unwrap()
        .unwrap();
    assert!(a.replayed);
    assert_eq!(a, b);
    assert_eq!(a.acceptance_sequence, 1);
}
#[test]
fn preparation_gate_bounds_active_work_and_releases_slots_on_drop() {
    let gate = admission::PreparationGate::new(1);
    let a = gate.acquire().unwrap();
    let b = gate.acquire().unwrap();
    std::thread::scope(|scope| {
        let (ready, waiting) = mpsc::sync_channel(1);
        let gate = &gate;
        let c = scope.spawn(move || {
            ready.send(()).unwrap();
            gate.acquire().unwrap()
        });
        waiting.recv().unwrap();
        drop(a);
        let c = c.join().unwrap();
        drop(c);
    });
    drop(b);
    drop(gate.acquire().unwrap());
}

#[test]
fn queued_dispatch_and_abandoned_ack_keep_one_actor_owned_clock() {
    let f = Fixture::new();
    let mut req = f.request(&f.capture());
    req.execution.timeout_ms = Some(1);
    let accepted = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse("timed-dispatch").unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap();
    let (entered, paused) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    f.store
        .sender
        .send(Command::PauseExecutionQueue(entered, resume))
        .ok()
        .unwrap();
    paused.recv_timeout(Duration::from_secs(2)).unwrap();
    let request = execution::DispatchRequest {
        job_id: accepted.job_id.clone(),
        expected_revision: 1,
        resolved_json: serde_json::to_string(&accepted.resolved).unwrap(),
        resources: vec!["cpu:fixture".into()],
    };
    let (reply, rx) = mpsc::sync_channel(1);
    drop(rx);
    f.store
        .sender
        .send(Command::Execution(execution::ExecutionCommand::Dispatch(
            request.clone(),
            reply,
        )))
        .ok()
        .unwrap();
    let before_release = Instant::now();
    release.send(()).unwrap();
    let record = f.store.dispatch_attempt(request).unwrap();
    assert!(record.timing.started() >= before_release);
    assert_eq!(
        record.timing.deadline().unwrap() - record.timing.started(),
        Duration::from_millis(1)
    );
    let original = f.store.attempt_timing(record.attempt_id.clone()).unwrap();
    assert!(Arc::ptr_eq(&original, &record.timing));
    while Instant::now() < original.deadline().unwrap() {
        std::thread::yield_now();
    }
    assert!(f.store.attempt_timing(record.attempt_id).unwrap().expired());
    assert!(Arc::ptr_eq(&original, &record.timing));
}
#[test]
fn restart_keeps_dispatch_holds_and_never_reconstructs_a_live_clock() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let accepted = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse("restart-dispatch").unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap();
    let dispatched = f
        .store
        .dispatch_attempt(execution::DispatchRequest {
            job_id: accepted.job_id.clone(),
            expected_revision: 1,
            resolved_json: serde_json::to_string(&accepted.resolved).unwrap(),
            resources: vec!["cpu:fixture".into()],
        })
        .unwrap();
    drop(f.store);
    let root = OwnedRoot::open(f.root.path(), RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
    assert!(matches!(
        store.attempt_timing(dispatched.attempt_id),
        Err(CoreError::NotFound)
    ));
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT state FROM job_execution WHERE job_id=?1",
            [accepted.job_id.as_str()],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "interrupted"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM resource_reservations WHERE released=0",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn execution_snapshot_reads_current_lifecycle_and_exact_resolution() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let accepted = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse("snapshot-lifecycle").unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap();
    let queued = f
        .store
        .execution_job_snapshot(f.auth.clone(), accepted.job_id.clone())
        .unwrap();
    assert_eq!(queued.summary.state, ExecutionJobState::Queued);
    assert_eq!(queued.summary.snapshot_revision, 1);
    assert_eq!(queued.resolved, accepted.resolved);
    assert_eq!(queued.summary.execution_policy, req.execution);
    let dispatched = f
        .store
        .dispatch_attempt(execution::DispatchRequest {
            job_id: accepted.job_id.clone(),
            expected_revision: 1,
            resolved_json: serde_json::to_string(&accepted.resolved).unwrap(),
            resources: vec!["cpu:fixture".into()],
        })
        .unwrap();
    let running = f
        .store
        .execution_job_snapshot(f.auth.clone(), accepted.job_id)
        .unwrap();
    assert_eq!(running.summary.state, ExecutionJobState::Running);
    assert_eq!(running.summary.snapshot_revision, 2);
    assert_eq!(running.summary.attempt_id, Some(dispatched.attempt_id));
    assert_eq!(running.summary.cleanup.status, CleanupStatus::Pending);
    assert_eq!(running.resolved, queued.resolved);
}
#[test]
fn snapshot_decode_cannot_outlive_revocation_or_a_changed_revision() {
    for revoke in [false, true] {
        let f = Fixture::new();
        let req = f.request(&f.capture());
        let accepted = f
            .store
            .accept_execution_job(
                f.auth.clone(),
                IdempotencyKey::parse("snapshot-final-check").unwrap(),
                req.clone(),
                f.candidate(&req),
            )
            .unwrap();
        let _raw = f
            .store
            .request(|reply| {
                Command::ExecutionRead(execution_reads::ReadCommand::Snapshot(
                    f.auth.clone(),
                    accepted.job_id.clone(),
                    reply,
                ))
            })
            .unwrap();
        if revoke {
            f.store.revoke_self(f.auth.clone()).unwrap();
        } else {
            f.store
                .dispatch_attempt(execution::DispatchRequest {
                    job_id: accepted.job_id.clone(),
                    expected_revision: 1,
                    resolved_json: serde_json::to_string(&accepted.resolved).unwrap(),
                    resources: vec!["cpu:fixture".into()],
                })
                .unwrap();
        }
        let result = f.store.request(|reply| {
            Command::ExecutionRead(execution_reads::ReadCommand::Confirm(
                f.auth.clone(),
                accepted.job_id.clone(),
                1,
                "verified".into(),
                reply,
            ))
        });
        if revoke {
            assert!(matches!(result, Err(CoreError::Unauthorized)));
        } else {
            assert!(!result.unwrap());
        }
    }
}

/// The single execution read uses the page's model: the bounded actor queue,
/// decoding outside the actor and a final confirmation. It never takes a
/// submission/retry preparation slot (2026-11-18 gate split).
#[test]
fn snapshot_reads_neither_wait_for_nor_consume_submission_preparation_slots() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let accepted = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse("snapshot-gate").unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap();
    let read = || {
        f.store
            .execution_job_snapshot(f.auth.clone(), accepted.job_id.clone())
    };
    // Both submission slots are held: reads neither wait nor read Busy.
    let first = f.store.submission_preparation.acquire().unwrap();
    let second = f.store.submission_preparation.acquire().unwrap();
    for _ in 0..8 {
        let started = Instant::now();
        assert_eq!(read().unwrap().summary.state, ExecutionJobState::Queued);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    drop((first, second));
    // Reads parked behind a paused actor hold no slot: submission still gets both.
    let (entered, paused) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    f.store
        .sender
        .send(Command::PauseExecutionQueue(entered, resume))
        .ok()
        .unwrap();
    paused.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::scope(|scope| {
        let readers: Vec<_> = (0..2).map(|_| scope.spawn(read)).collect();
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        let first = f.store.submission_preparation.acquire().unwrap();
        let second = f.store.submission_preparation.acquire().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        drop((first, second));
        release.send(()).unwrap();
        for reader in readers {
            assert_eq!(
                reader.join().unwrap().unwrap().summary.state,
                ExecutionJobState::Queued
            );
        }
    });
}

#[test]
fn observation_that_ages_inside_the_transaction_rolls_back_before_commit() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let key = IdempotencyKey::parse("precommit-freshness").unwrap();
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req.clone());
    let prepared = submission::prepare(
        &f.root,
        &f.auth,
        &key,
        &request,
        Some(&candidate),
        snapshot(&f, &key, &request),
    );
    let hooks = Arc::new(crate::submission::test_support::Hooks::default());
    crate::submission::test_support::register(f.root.path(), &hooks);
    let (entered, release) = hooks.pause_transaction(false);
    std::thread::scope(|scope| {
        let f = &f;
        let key = &key;
        let request = &request;
        let candidate = candidate.clone();
        let worker = scope.spawn(move || finish(f, key, request, Some(candidate), prepared));
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(Duration::from_millis(120));
        release.send(()).unwrap();
        assert!(worker.join().unwrap().unwrap().is_none());
    });
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let accepted = f
        .store
        .accept_execution_job(f.auth.clone(), key, req.clone(), f.candidate(&req))
        .unwrap();
    assert_eq!(accepted.acceptance_sequence, 1);
}

// 2026-11-17 repair slice: invalidation follows committed admission facts only.
fn fixture_credentials() -> (ClientId, TokenDigest) {
    (
        ClientId::parse("cli_11111111111111111111111111111111").unwrap(),
        TokenDigest::new([1; 32]),
    )
}
#[test]
fn authentication_and_snapshot_polling_do_not_invalidate_fresh_preparation() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req);
    let key = IdempotencyKey::parse("polled-preparation").unwrap();
    let prepared = submission::prepare(
        &f.root,
        &f.auth,
        &key,
        &request,
        Some(&candidate),
        snapshot(&f, &key, &request),
    );
    let (client, digest) = fixture_credentials();
    f.store
        .authenticate(client.clone(), digest.clone())
        .unwrap();
    f.store.authorize_snapshot(client, digest).unwrap();
    assert!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap()
            .unwrap()
            .unwrap()
            .accepted
    );
}
#[test]
fn stale_finish_does_not_invalidate_a_competing_fresh_preparation() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req);
    let stale_key = IdempotencyKey::parse("stale-competitor").unwrap();
    let fresh_key = IdempotencyKey::parse("fresh-competitor").unwrap();
    let mut stale = submission::prepare(
        &f.root,
        &f.auth,
        &stale_key,
        &request,
        Some(&candidate),
        snapshot(&f, &stale_key, &request),
    );
    let fresh = submission::prepare(
        &f.root,
        &f.auth,
        &fresh_key,
        &request,
        Some(&candidate),
        snapshot(&f, &fresh_key, &request),
    );
    stale.observed_at = Instant::now() - Duration::from_secs(1);
    assert!(
        finish(&f, &stale_key, &request, Some(candidate.clone()), stale)
            .unwrap()
            .is_none()
    );
    let accepted = finish(&f, &fresh_key, &request, Some(candidate), fresh)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(accepted.acceptance_sequence, 1);
}
#[test]
fn input_capture_between_read_and_finish_still_forces_stale_preparation() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req);
    let key = IdempotencyKey::parse("capture-invalidates").unwrap();
    let prepared = submission::prepare(
        &f.root,
        &f.auth,
        &key,
        &request,
        Some(&candidate),
        snapshot(&f, &key, &request),
    );
    // Reservation and completion change upload accounting and disk usage.
    f.capture();
    assert!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap()
            .is_none()
    );
}
#[test]
fn bounded_pollers_and_submitters_finish_without_spurious_busy() {
    use std::sync::atomic::AtomicU64;
    const SUBMITTERS: usize = 4;
    const POLLERS: usize = 3;
    let f = Fixture::new();
    let input = f.capture();
    let work: Vec<_> = (0..SUBMITTERS)
        .map(|i| {
            let req = f.request(&input);
            let candidate = f.candidate(&req);
            (
                IdempotencyKey::parse(format!("polled-submitter-{i}")).unwrap(),
                req,
                candidate,
            )
        })
        .collect();
    let done = AtomicBool::new(false);
    let polls = AtomicU64::new(0);
    let (client, digest) = fixture_credentials();
    let results: Vec<_> = std::thread::scope(|scope| {
        for _ in 0..POLLERS {
            scope.spawn(|| {
                while !done.load(Ordering::Acquire) {
                    if f.store
                        .authorize_snapshot(client.clone(), digest.clone())
                        .is_ok()
                    {
                        polls.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
        // Let pollers occupy the actor before any submitter starts.
        while polls.load(Ordering::Relaxed) < 16 {
            std::thread::yield_now();
        }
        let submitters: Vec<_> = work
            .into_iter()
            .map(|(key, req, candidate)| {
                let f = &f;
                scope.spawn(move || {
                    f.store
                        .accept_execution_job(f.auth.clone(), key, req, candidate)
                        .map_err(|e| e.code)
                })
            })
            .collect();
        let results = submitters
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        done.store(true, Ordering::Release);
        results
    });
    let accepted: Vec<_> = results
        .into_iter()
        .map(|result| result.expect("no spurious Busy").acceptance_sequence)
        .collect();
    let mut sequences = accepted.clone();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=SUBMITTERS as i64).collect::<Vec<_>>());
}
#[test]
fn submission_read_observes_but_never_persists_the_engine_clock() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let request = SubmittedJobRequest::Execution(req);
    let key = IdempotencyKey::parse("read-only-clock").unwrap();
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    db.execute(
        "UPDATE engine_clock SET last_observed_ms=0 WHERE singleton=1",
        [],
    )
    .unwrap();
    let _state = snapshot(&f, &key, &request);
    assert_eq!(
        db.query_row(
            "SELECT last_observed_ms FROM engine_clock WHERE singleton=1",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}
#[test]
fn backward_wall_clock_cannot_revive_an_expired_input() {
    let f = Fixture::new();
    let input = f.capture();
    let req = f.request(&input);
    let candidate = Arc::new(f.candidate(&req));
    let request = SubmittedJobRequest::Execution(req);
    let key = IdempotencyKey::parse("backward-clock").unwrap();
    let now = now_ms().unwrap();
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    db.execute(
        "UPDATE captured_inputs SET expires_at_ms=?1 WHERE input_id=?2",
        rusqlite::params![now + 3_600_000, input.input_id.as_str()],
    )
    .unwrap();
    // The engine previously observed a later time; the wall clock now reads earlier.
    db.execute(
        "UPDATE engine_clock SET last_observed_ms=?1 WHERE singleton=1",
        [now + 7_200_000],
    )
    .unwrap();
    let prepared = submission::prepare(
        &f.root,
        &f.auth,
        &key,
        &request,
        Some(&candidate),
        snapshot(&f, &key, &request),
    );
    assert_eq!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap_err()
            .code,
        ErrorCode::InputUnavailable
    );
    assert!(
        db.query_row(
            "SELECT last_observed_ms FROM engine_clock WHERE singleton=1",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap()
            >= now + 7_200_000
    );
}

fn percentiles_ms(samples: &mut [Duration]) -> serde_json::Value {
    samples.sort_unstable();
    let at = |q: f64| -> f64 {
        if samples.is_empty() {
            return f64::NAN;
        }
        let index = ((samples.len() as f64 - 1.0) * q).round() as usize;
        samples[index].as_secs_f64() * 1000.0
    };
    serde_json::json!({
        "count": samples.len(),
        "p50_ms": at(0.50),
        "p90_ms": at(0.90),
        "p99_ms": at(0.99),
        "max_ms": at(1.0),
    })
}
/// Opt-in measurement for the 100 ms freshness policy; prints JSON, asserts nothing
/// about timing. Run with `-- --ignored --nocapture --test-threads=1`.
#[test]
#[ignore = "opt-in admission load measurement"]
fn measure_fresh_admission_observation_age_under_load() {
    use std::sync::atomic::AtomicU64;
    const ROUNDS: usize = 8;
    const SUBMITTERS: usize = 4;
    for (scenario, pollers, uploads) in [
        ("serial-submitters-only", 0, false),
        ("pollers-3", 3, false),
        ("pollers-3-plus-uploads", 3, true),
    ] {
        let f = Fixture::new();
        let hooks = Arc::new(crate::submission::test_support::Hooks::default());
        crate::submission::test_support::register(f.root.path(), &hooks);
        let input = f.capture();
        let mut work: Vec<_> = (0..ROUNDS * SUBMITTERS)
            .map(|i| {
                let req = f.request(&input);
                let candidate = f.candidate(&req);
                (
                    IdempotencyKey::parse(format!("measured-{i}")).unwrap(),
                    req,
                    candidate,
                )
            })
            .collect();
        hooks.sample_observations();
        let done = AtomicBool::new(false);
        let polls = AtomicU64::new(0);
        let captured = AtomicU64::new(0);
        let (client, digest) = fixture_credentials();
        let started = Instant::now();
        let outcomes: Vec<Result<i64, ErrorCode>> = std::thread::scope(|scope| {
            for _ in 0..pollers {
                scope.spawn(|| {
                    while !done.load(Ordering::Acquire) {
                        if f.store
                            .authorize_snapshot(client.clone(), digest.clone())
                            .is_ok()
                        {
                            polls.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
            if uploads {
                scope.spawn(|| {
                    while !done.load(Ordering::Acquire) {
                        f.capture();
                        captured.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(5));
                    }
                });
            }
            let mut outcomes = Vec::new();
            for _ in 0..ROUNDS {
                let round: Vec<_> = work.drain(..SUBMITTERS).collect();
                let handles: Vec<_> = round
                    .into_iter()
                    .map(|(key, req, candidate)| {
                        let f = &f;
                        scope.spawn(move || {
                            f.store
                                .accept_execution_job(f.auth.clone(), key, req, candidate)
                                .map(|receipt| receipt.acceptance_sequence)
                                .map_err(|error| error.code)
                        })
                    })
                    .collect();
                outcomes.extend(handles.into_iter().map(|h| h.join().unwrap()));
            }
            done.store(true, Ordering::Release);
            outcomes
        });
        let elapsed = started.elapsed();
        let mut samples = hooks.take_observations().unwrap();
        let accepted = outcomes.iter().filter(|o| o.is_ok()).count();
        let busy = outcomes
            .iter()
            .filter(|o| matches!(o, Err(ErrorCode::Busy)))
            .count();
        println!(
            "{}",
            serde_json::json!({
                "scenario": scenario,
                "submissions": outcomes.len(),
                "accepted": accepted,
                "busy": busy,
                "other_errors": outcomes.len() - accepted - busy,
                "fresh_finish_attempts": samples.finish_entry.len(),
                "stale_changed": samples.changed,
                "stale_aged": samples.aged,
                "polls": polls.load(Ordering::Relaxed),
                "uploads_completed": captured.load(Ordering::Relaxed),
                "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
                "age_at_finish_entry": percentiles_ms(&mut samples.finish_entry),
                "age_at_commit_start": percentiles_ms(&mut samples.commit_start),
            })
        );
    }
}

// 2026-11-17 admission follow-up: sequence assignment and per-command invalidation.
type Work = (
    IdempotencyKey,
    SubmittedJobRequest,
    Arc<crate::submission::admission::AdmissionCandidate>,
);
/// Capture every input first: completing an upload invalidates preparations.
fn captured_work(f: &Fixture, keys: &[&str]) -> Vec<Work> {
    keys.iter()
        .map(|key| {
            let req = f.request(&f.capture());
            let candidate = Arc::new(f.candidate(&req));
            (
                IdempotencyKey::parse(*key).unwrap(),
                SubmittedJobRequest::Execution(req),
                candidate,
            )
        })
        .collect()
}
fn prepare_work(f: &Fixture, (key, request, candidate): &Work) -> submission::Prepared {
    submission::prepare(
        &f.root,
        &f.auth,
        key,
        request,
        Some(candidate),
        snapshot(f, key, request),
    )
}
fn finish_work(
    f: &Fixture,
    (key, request, candidate): &Work,
    prepared: submission::Prepared,
) -> Result<Option<Option<AcceptanceReceipt>>, crate::submission::SubmissionError> {
    finish(f, key, request, Some(candidate.clone()), prepared)
}
fn prepared_for(
    f: &Fixture,
    key: &str,
) -> (
    IdempotencyKey,
    SubmittedJobRequest,
    Arc<crate::submission::admission::AdmissionCandidate>,
    submission::Prepared,
) {
    let work = captured_work(f, &[key]).pop().unwrap();
    let prepared = prepare_work(f, &work);
    (work.0, work.1, work.2, prepared)
}
#[test]
fn sibling_commit_between_read_and_finish_keeps_preparation_and_orders_sequences() {
    let f = Fixture::new();
    let work = captured_work(&f, &["sibling-a", "sibling-b"]);
    let pa = prepare_work(&f, &work[0]);
    let pb = prepare_work(&f, &work[1]);
    let a = finish_work(&f, &work[0], pa).unwrap().unwrap().unwrap();
    // The sibling's committed acceptance no longer forces a stale retry.
    let b = finish_work(&f, &work[1], pb)
        .unwrap()
        .expect("not stale")
        .unwrap();
    assert_eq!((a.acceptance_sequence, b.acceptance_sequence), (1, 2));
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    let stored: Vec<(String, i64)> = db
        .prepare("SELECT job_id,acceptance_sequence FROM jobs ORDER BY acceptance_sequence")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        stored,
        vec![(a.job_id.as_str().into(), 1), (b.job_id.as_str().into(), 2)]
    );
    assert_eq!(
        db.query_row("SELECT value FROM job_sequence", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    // Replay returns the actor-assigned sequence, not a caller placeholder.
    let replay = f
        .store
        .probe_execution_binding(
            f.auth.clone(),
            work[1].0.clone(),
            match work[1].1.clone() {
                SubmittedJobRequest::Execution(r) => r,
                SubmittedJobRequest::Legacy(_) => unreachable!(),
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(replay.acceptance_sequence, 2);
}
#[test]
fn sibling_commits_are_charged_the_growth_allowance_against_an_older_observation() {
    let f = Fixture::new();
    let work = captured_work(&f, &["charged-a", "charged-b"]);
    // Leave room above the reserve for one admission's 4 MiB growth allowance,
    // with 2 MiB slack either side for unrelated disk activity.
    let free = f.root.available_space_bytes().unwrap();
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        free_reserve: free - 4_194_304 - 2_097_152,
        ..Default::default()
    });
    let pa = prepare_work(&f, &work[0]);
    let pb = prepare_work(&f, &work[1]);
    finish_work(&f, &work[0], pa).unwrap().unwrap().unwrap();
    // B observed free space before A committed; A's allowance is deducted.
    assert_eq!(
        finish_work(&f, &work[1], pb).unwrap_err().limit,
        Some("storage_free_reserve_bytes")
    );
}
#[test]
fn pin_reserve_abandon_and_cleanup_no_longer_invalidate_preparation() {
    let mut invalidated = Vec::new();
    for step in ["pin", "reserve", "abandon", "claim", "confirm"] {
        let f = Fixture::new();
        let extra = f.capture();
        let held = (step == "abandon").then(|| {
            f.store
                .reserve_upload(
                    f.auth.clone(),
                    16,
                    "application/octet-stream".into(),
                    f.root.available_space_bytes().unwrap(),
                )
                .unwrap()
        });
        let claimed = (step == "confirm").then(|| {
            let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
            db.execute(
                "UPDATE captured_inputs SET completed_at_ms=0,expires_at_ms=1 WHERE input_id=?1",
                [extra.input_id.as_str()],
            )
            .unwrap();
            let claims = f.store.claim_input_cleanup().unwrap();
            assert_eq!(claims.len(), 1);
            claims
        });
        let (key, request, candidate, prepared) = prepared_for(&f, step);
        match step {
            "pin" => drop(
                f.store
                    .pin_verified_inputs(f.auth.clone(), vec![extra.input_id.clone()])
                    .unwrap(),
            ),
            "reserve" => drop(
                f.store
                    .reserve_upload(
                        f.auth.clone(),
                        16,
                        "application/octet-stream".into(),
                        f.root.available_space_bytes().unwrap(),
                    )
                    .unwrap(),
            ),
            "abandon" => f
                .store
                .abandon_upload(held.unwrap().reservation_id.clone())
                .unwrap(),
            "claim" => drop(f.store.claim_input_cleanup().unwrap()),
            _ => {
                for claim in claimed.unwrap() {
                    f.store.confirm_input_cleanup(claim).unwrap();
                }
            }
        }
        match finish(&f, &key, &request, Some(candidate), prepared).unwrap() {
            Some(accepted) => assert!(accepted.unwrap().accepted, "{step}"),
            None => invalidated.push(step),
        }
    }
    assert!(invalidated.is_empty(), "invalidated by {invalidated:?}");
}
#[test]
fn completing_an_upload_still_invalidates_preparation() {
    let f = Fixture::new();
    let bytes = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");
    let r = f
        .store
        .reserve_upload(
            f.auth.clone(),
            bytes.len() as u64,
            "application/octet-stream".into(),
            f.root.available_space_bytes().unwrap(),
        )
        .unwrap();
    let (key, request, candidate, prepared) = prepared_for(&f, "complete-invalidates");
    let staged =
        RelativePath::parse(format!("inputs/staging/{}.part", r.input_id.as_str())).unwrap();
    let final_path =
        RelativePath::parse(format!("inputs/data/{}.bin", r.input_id.as_str())).unwrap();
    let mut writer = f.root.begin_input(&staged).unwrap();
    writer.write_chunk(bytes).unwrap();
    let file = writer.finish(&final_path).unwrap();
    f.store
        .complete_upload(
            f.auth.clone(),
            r,
            DurableInput {
                file,
                sha256: Sha256::digest(bytes).into(),
            },
        )
        .unwrap();
    assert!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap()
            .is_none()
    );
}
#[test]
fn unclassified_mutating_command_still_invalidates_preparation() {
    let f = Fixture::new();
    let (key, request, candidate, prepared) = prepared_for(&f, "unclassified");
    let identity = f.store.identity().unwrap();
    f.store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().unwrap(),
            identity.installation_id,
            identity.instance_id,
            EnrollmentId::parse("enr_22222222222222222222222222222222").unwrap(),
            ClientId::parse("cli_22222222222222222222222222222222").unwrap(),
            TokenDigest::new([2; 32]),
        ))
        .unwrap();
    assert!(
        finish(&f, &key, &request, Some(candidate), prepared)
            .unwrap()
            .is_none()
    );
}
#[test]
fn unbound_probe_does_not_persist_the_engine_clock() {
    let f = Fixture::new();
    let req = f.request(&f.capture());
    let db = Connection::open(f.root.path().join(DATABASE_NAME)).unwrap();
    db.execute(
        "UPDATE engine_clock SET last_observed_ms=0 WHERE singleton=1",
        [],
    )
    .unwrap();
    assert!(
        f.store
            .probe_execution_binding(
                f.auth.clone(),
                IdempotencyKey::parse("unbound-probe").unwrap(),
                req
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.query_row(
            "SELECT last_observed_ms FROM engine_clock WHERE singleton=1",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}

#[path = "retry_tests.rs"]
mod retry_tests;
// 2026-11-17 execution pages and retained-history accounting.
#[path = "accounting_tests.rs"]
mod accounting_tests;
#[path = "attempt_deadline_tests.rs"]
mod attempt_deadline_tests;
#[path = "execution_page_tests.rs"]
mod execution_page_tests;
// 2026-11-18 cleanup-witness transitions.
#[path = "cleanup_tests.rs"]
mod cleanup_tests;
// 2026-11-18 WE-P04 failure finalization and observation writers.
#[path = "finalize_tests.rs"]
mod finalize_tests;
// 2026-11-19 WE-P04 launch identity and release-time identity check.
#[path = "launch_identity_tests.rs"]
mod launch_identity_tests;
