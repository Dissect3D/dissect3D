//! Real file/store completion past the deadline must not expose a receipt or
//! release resources while the non-cancellable operation is still running.

use super::*;
use crate::CorePolicy;
use crate::credentials::VerifiedEnrollment;
use crate::store::inputs::InputCleanupKind;
use crate::submission::test_support::{Hooks, register};
use dissect3d_api::{ClientId, EnrollmentId, TokenDigest};
use dissect3d_platform::{AuthorityLease, RootPurpose, current_owner_identity};

fn fixture() -> (tempfile::TempDir, Arc<InputService>, AuthContext) {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).unwrap());
    let identity = store.identity().unwrap();
    let client = ClientId::parse("cli_2223456789abcdef0123456789abcdef").unwrap();
    let digest = TokenDigest::new(Sha256::digest([42; 32]).into());
    store
        .enroll(VerifiedEnrollment::new_submission_access(
            current_owner_identity().unwrap(),
            identity.installation_id,
            identity.instance_id,
            EnrollmentId::parse("enr_2223456789abcdef0123456789abcdef").unwrap(),
            client.clone(),
            digest.clone(),
        ))
        .unwrap();
    let context = store.authenticate(client, digest).unwrap();
    let root = Arc::new(OwnedRoot::open(&path, RootPurpose::EngineData).unwrap());
    (parent, Arc::new(InputService::new(store, root)), context)
}

fn counts(service: &InputService) -> (i64, i64, i64) {
    let db = rusqlite::Connection::open_with_flags(
        service.root.path().join("metadata.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    db.query_row(
        "SELECT (SELECT count(*) FROM input_upload_reservations),
        (SELECT count(*) FROM captured_inputs), (SELECT count(*) FROM jobs)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn body_deadline_uses_only_request_slack_for_safe_failure_cleanup() {
    let (_parent, service, context) = fixture();
    let started = tokio::time::Instant::now();
    let result = service
        .capture_until(
            context,
            1,
            "application/octet-stream".into(),
            futures_util::stream::pending::<Result<Vec<u8>, std::io::Error>>(),
            started + Duration::from_millis(500),
        )
        .await;
    assert_eq!(result, Err(InputError::Transfer));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(counts(&service), (0, 0, 0));
    assert_eq!(service.uploads.available_permits(), MAX_UPLOADS as usize);
    assert_eq!(
        std::fs::read_dir(service.root.path().join("inputs/staging"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn finalization_deadline_and_cancellation_retain_ownership_and_reconcile_late_completion() {
    for (metadata, cancel) in [(false, false), (true, false), (false, true), (true, true)] {
        let (_parent, service, context) = fixture();
        let hooks = Arc::new(Hooks::default());
        register(service.root.path(), &hooks);
        let (entered, release) = hooks.pause_upload_finalization(metadata);
        let upload = service.clone();
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            upload
                .capture_until(
                    context,
                    1,
                    "application/octet-stream".into(),
                    futures_util::stream::iter([Ok::<_, std::io::Error>(vec![42])]),
                    started + Duration::from_millis(500),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match entered.try_recv() {
                    Ok(()) => break,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(5)).await
                    }
                    Err(error) => panic!("finalization latch disconnected: {error}"),
                }
            }
        })
        .await
        .expect("capture did not reach finalization before its deadline");
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                result,
                Err(InputError::Transfer),
                "late completion exposed a usable receipt"
            );
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            service.uploads.available_permits(),
            MAX_UPLOADS as usize - 1
        );
        assert_eq!(counts(&service), (1, 0, 0));
        assert!(
            service.store.claim_input_cleanup().unwrap().is_empty(),
            "native work lost its cleanup exclusion"
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while service.uploads.available_permits() != MAX_UPLOADS as usize {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("completed native work retained its slot");
        let claims = if metadata {
            assert_eq!(counts(&service), (0, 1, 0));
            assert!(
                service.store.claim_input_cleanup().unwrap().is_empty(),
                "late capture lost its TTL"
            );
            let future = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
                + policy::UPLOAD_TTL_MS
                + 1000;
            service.store.claim_input_cleanup_at(future).unwrap()
        } else {
            assert_eq!(counts(&service), (1, 0, 0));
            service.store.claim_input_cleanup().unwrap()
        };
        assert_eq!(claims.len(), 1);
        let claim = claims.into_iter().next().unwrap();
        assert_eq!(matches!(claim.kind, InputCleanupKind::Captured), metadata);
        for path in [
            format!("inputs/staging/{}.part", claim.input_id.as_str()),
            format!("inputs/data/{}.bin", claim.input_id.as_str()),
        ] {
            match service
                .root
                .remove_durable(&RelativePath::parse(path).unwrap())
            {
                Ok(()) | Err(PlatformError::NotFound) => {}
                Err(error) => panic!("durable recovery removal failed: {error:?}"),
            }
        }
        assert_eq!(
            counts(&service),
            if metadata { (0, 1, 0) } else { (1, 0, 0) },
            "file deletion released accounting before actor confirmation"
        );
        service.store.confirm_input_cleanup(claim).unwrap();
        assert_eq!(counts(&service), (0, 0, 0));
    }
}
