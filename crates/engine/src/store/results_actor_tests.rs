//! RP-P02/5-/6 through the real Store actor and a genuinely dispatched
//! attempt (the connection-level suite is `results_tests.rs`).
use super::retry_tests::{accept, db, dispatch};
use super::*;
use crate::store::results::{FileRole, PublicationReservation, ReservedFile, ResultUsage};

fn reservation(job: &JobId, attempt: &str) -> PublicationReservation {
    let file = |object_name: String, role, filename: &str, byte_length| ReservedFile {
        object_name,
        role,
        filename: filename.to_owned(),
        media_type: "application/octet-stream".to_owned(),
        byte_length,
        sha256: [3; 32],
    };
    PublicationReservation {
        result_id: format!("res_{}", "a".repeat(32)),
        publication_id: format!("pub_{}", "a".repeat(32)),
        job_id: job.as_str().to_owned(),
        attempt_id: attempt.to_owned(),
        files: vec![
            file(
                format!("art_{}", "a".repeat(32)),
                FileRole::Artifact,
                "mesh.obj",
                64,
            ),
            file(
                format!("pub_{}", "a".repeat(32)),
                FileRole::Manifest,
                "manifest.json",
                8,
            ),
        ],
        available_space_bytes: u64::MAX / 4,
    }
}

#[test]
fn a_dispatched_attempt_reserves_once_and_its_orphan_is_reclaimed_only_after_it_ends() {
    let f = Fixture::new();
    let job = accept(&f, "results-actor").job_id;
    let record = dispatch(&f, &job);
    let request = reservation(&job, &record.attempt_id);
    f.store.reserve_publication(request.clone()).unwrap();
    assert_eq!(
        f.store.reserve_publication(request.clone()),
        Err(CoreError::Conflict)
    );
    f.store
        .mark_publication_prepared(request.result_id.clone())
        .unwrap();
    assert_eq!(
        f.store.result_usage().unwrap(),
        ResultUsage {
            private_bytes: 72,
            published_bytes: 0,
            unwritten_bytes: 0,
            records: 1
        }
    );
    assert_eq!(
        f.store
            .known_result_objects(vec![request.files[0].object_name.clone()])
            .unwrap()
            .len(),
        1
    );
    assert!(
        f.store
            .claim_publication_reclaim()
            .unwrap()
            .objects
            .is_empty()
    );
    // The attempt ends without a result (as restart interruption would mark it).
    db(&f)
        .execute(
            "UPDATE job_execution SET state='interrupted' WHERE job_id=?1",
            [job.as_str()],
        )
        .unwrap();
    let batch = f.store.claim_publication_reclaim().unwrap();
    assert_eq!(batch.objects.len(), 2);
    assert_eq!(
        f.store
            .confirm_publication_reclaimed(batch.objects)
            .unwrap(),
        72
    );
    assert_eq!(f.store.result_usage().unwrap(), ResultUsage::default());
}
