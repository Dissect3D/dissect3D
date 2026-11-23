//! RP-P02/7: native faults, cancellation and caller abort during capture and
//! durable preparation. Faults are injected at the preparation seam (or, for
//! disk-full while writing, in the platform's own test); real-device and
//! physical faults remain separate evidence (RP-P07).
use super::*;
use crate::publication::capture::capture_candidate;
use crate::store::cleanup::{CleanupEvidence, test_identity};
use crate::worker_protocol::{CandidateFile, CandidateReport};

fn failing_at(
    target: fn(&PrepareStep<'_>) -> bool,
) -> impl FnMut(PrepareStep<'_>) -> Result<(), PlatformError> {
    move |step| {
        if target(&step) {
            Err(PlatformError::Io)
        } else {
            Ok(())
        }
    }
}

/// The allocation failed without a witness; its whole charge stays until the
/// job is terminal, and reclamation then removes every name it may have left.
fn assert_failed_then_reclaimed(env: &Env) {
    assert_eq!(env.allocation_state().as_deref(), Some("failed"));
    let charged = env.usage().private_bytes;
    assert!(charged > MESH.len() as u64);
    assert_eq!(
        reclaim_turn(&env.ledger, &env.root).unwrap(),
        ReclaimReport::default(),
        "a running job keeps a failed preparation"
    );
    assert_eq!(env.usage().private_bytes, charged);
    env.set_job_state("failed");
    let report = reclaim_turn(&env.ledger, &env.root).unwrap();
    assert_eq!(report.released_bytes, charged);
    assert!(env.entries("results/objects").is_empty());
    assert!(env.entries("results/staging").is_empty());
    assert_eq!(env.usage(), ResultUsage::default());
}

#[test]
fn a_native_write_or_sync_failure_after_reservation_keeps_the_charge_without_a_witness() {
    // Artifact: nothing durable yet. Manifest: the artifact is already
    // durable when the second file's native write or barrier fails.
    for (role, artifacts_left) in [(FileRole::Artifact, 0), (FileRole::Manifest, 1)] {
        let env = env();
        let mut hook = move |step: PrepareStep<'_>| match step {
            PrepareStep::Write(at) if at == role => Err(PlatformError::Io),
            _ => Ok(()),
        };
        assert!(matches!(
            prepare_publication_with(&env.ledger, &env.root, &env.candidate, soon(), &mut hook),
            Err(PublicationError::Storage)
        ));
        assert_eq!(
            env.entries("results/objects").len(),
            artifacts_left,
            "{role:?}"
        );
        assert_failed_then_reclaimed(&env);
    }
}

#[test]
fn a_read_back_failure_or_digest_mismatch_never_yields_a_witness() {
    type Fault = fn(&mut Vec<u8>) -> Result<(), PlatformError>;
    let faults: [(&str, Fault); 3] = [
        ("read error", |_| Err(PlatformError::Io)),
        ("changed byte", |bytes| {
            bytes[0] ^= 1;
            Ok(())
        }),
        ("short read", |bytes| {
            bytes.pop();
            Ok(())
        }),
    ];
    for (label, fault) in faults {
        let env = env();
        let mut hook = move |step: PrepareStep<'_>| match step {
            PrepareStep::ReadBack(FileRole::Artifact, bytes) => fault(bytes),
            _ => Ok(()),
        };
        assert!(
            matches!(
                prepare_publication_with(&env.ledger, &env.root, &env.candidate, soon(), &mut hook),
                Err(PublicationError::Storage)
            ),
            "{label}"
        );
        assert_failed_then_reclaimed(&env);
    }
}

#[test]
fn a_deadline_passing_during_the_read_back_hash_refuses_the_witness() {
    let env = env();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut hook = move |step: PrepareStep<'_>| {
        if matches!(step, PrepareStep::ReadBack(FileRole::Artifact, _)) {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        }
        Ok(())
    };
    assert!(matches!(
        prepare_publication_with(&env.ledger, &env.root, &env.candidate, deadline, &mut hook),
        Err(PublicationError::Deadline)
    ));
    assert_failed_then_reclaimed(&env);
}

#[test]
fn a_failing_platform_step_maps_to_storage_whatever_the_file() {
    // Both seams, both files: never another error class, never a witness.
    let targets: [fn(&PrepareStep<'_>) -> bool; 2] = [
        |s| matches!(s, PrepareStep::Write(FileRole::Manifest)),
        |s| matches!(s, PrepareStep::ReadBack(FileRole::Manifest, _)),
    ];
    for target in targets {
        let env = env();
        assert!(matches!(
            prepare_publication_with(
                &env.ledger,
                &env.root,
                &env.candidate,
                soon(),
                &mut failing_at(target)
            ),
            Err(PublicationError::Storage)
        ));
        assert_failed_then_reclaimed(&env);
    }
}

#[test]
fn cancellation_recorded_while_capturing_refuses_preparation_and_writes_nothing() {
    use sha2::{Digest, Sha256};
    let env = env();
    let (dispatch, _, inputs) = fixture();
    let staging = env
        .root
        .create_attempt_root(
            &RelativePath::parse(format!(
                "execution/attempts/{}/staging",
                dispatch.attempt_id
            ))
            .unwrap(),
        )
        .unwrap();
    fs::write(staging.worker_path().join("mesh.obj"), MESH).unwrap();
    fs::write(staging.worker_path().join("output.json"), b"{}").unwrap();
    let report = CandidateReport {
        description_handle: "output.json".into(),
        files: vec![CandidateFile {
            relative_name: "mesh.obj".into(),
            byte_length: MESH.len() as u64,
            sha256: Sha256::digest(MESH)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        }],
    };
    let cleanup = CleanupEvidence::for_test(test_identity(&dispatch.session_id, "faults"));
    let closed = capture_candidate(&dispatch, &report, &cleanup, &staging).unwrap();
    // Capture only reads through retained handles and changes no state, so a
    // cancel committed at any moment during it is what the reservation sees.
    env.set_job_state("cancel_requested");
    let candidate = {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        validate_candidate(&dispatch, &closed, &inputs).unwrap()
    };
    assert!(matches!(
        prepare_publication(&env.ledger, &env.root, &candidate, soon()),
        Err(PublicationError::Stale)
    ));
    assert_eq!(env.usage(), ResultUsage::default());
    assert!(!env.root.path().join("results").exists(), "nothing written");
    // The worker's staged output is evidence; capture consumed nothing.
    assert_eq!(
        fs::read(staging.worker_path().join("mesh.obj")).unwrap(),
        MESH
    );
}

#[test]
fn cancellation_during_native_preparation_keeps_its_content_private_and_charged() {
    let env = env();
    let mut hook = |step: PrepareStep<'_>| {
        if matches!(step, PrepareStep::Write(FileRole::Manifest)) {
            env.set_job_state("cancel_requested");
        }
        Ok(())
    };
    // Started native work finishes and records its own outcome; RP-P03's
    // commit, not preparation, refuses publication after cancellation.
    let prepared =
        prepare_publication_with(&env.ledger, &env.root, &env.candidate, soon(), &mut hook)
            .unwrap();
    assert_eq!(env.allocation_state().as_deref(), Some("prepared"));
    let results: i64 = env
        .ledger
        .db()
        .query_row("SELECT count(*) FROM results", [], |r| r.get(0))
        .unwrap();
    assert_eq!(results, 0, "preparation publishes nothing");
    let charged = env.usage().private_bytes;
    drop(prepared);
    assert_eq!(
        reclaim_turn(&env.ledger, &env.root).unwrap(),
        ReclaimReport::default(),
        "cancel requested is not terminal"
    );
    assert_eq!(env.entries("results/objects").len(), 2);
    env.set_job_state("canceled");
    let report = reclaim_turn(&env.ledger, &env.root).unwrap();
    assert_eq!((report.deleted, report.released_bytes), (2, charged));
    assert_eq!(env.usage(), ResultUsage::default());
}

#[test]
fn a_caller_that_stops_waiting_never_frees_space_held_by_running_native_work() {
    let Env {
        parent: _parent,
        root,
        ledger,
        candidate,
        job,
    } = env();
    let ledger = Arc::new(ledger);
    let root = Arc::new(root);
    let state = |ledger: &Ledger| -> Option<String> {
        ledger
            .db()
            .query_row("SELECT state FROM publication_allocations", [], |r| {
                r.get(0)
            })
            .ok()
    };
    let private = |ledger: &Ledger| results::usage(&mut ledger.db()).unwrap().private_bytes;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let (entered, started) = std::sync::mpsc::sync_channel(1);
    let (release, resume) = std::sync::mpsc::sync_channel::<()>(1);
    let hook = move |step: PrepareStep<'_>| {
        if matches!(step, PrepareStep::Write(FileRole::Artifact)) {
            entered.send(()).unwrap();
            // Blocking native work in progress until the test releases it.
            let _ = resume.recv_timeout(Duration::from_secs(10));
        }
        Ok(())
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let abandoned = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(100),
            prepare_blocking_with(ledger.clone(), root.clone(), candidate, deadline, hook),
        )
        .await
    });
    assert!(abandoned.is_err(), "the caller gave up first");
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    // The caller is gone; the blocking task still owns the allocation.
    assert_eq!(state(&ledger).as_deref(), Some("preparing"));
    let charged = private(&ledger);
    assert!(charged > MESH.len() as u64);
    // Even a terminal job cannot reclaim work still running in this session.
    ledger
        .db()
        .execute(
            "UPDATE job_execution SET state='interrupted' WHERE job_id=?1",
            [&job],
        )
        .unwrap();
    assert_eq!(
        reclaim_turn(&ledger, &root).unwrap(),
        ReclaimReport::default()
    );
    assert_eq!(private(&ledger), charged);
    release.send(()).unwrap();
    let finished = Instant::now() + Duration::from_secs(10);
    while state(&ledger).as_deref() == Some("preparing") {
        assert!(Instant::now() < finished, "native work never finished");
        std::thread::sleep(Duration::from_millis(10));
    }
    // It finished and recorded its own outcome; only now can space return.
    assert_eq!(state(&ledger).as_deref(), Some("prepared"));
    let report = reclaim_turn(&ledger, &root).unwrap();
    assert_eq!((report.deleted, report.released_bytes), (2, charged));
    assert_eq!(private(&ledger), 0);
}

#[test]
fn a_completion_after_the_deadline_is_not_a_usable_witness() {
    let Env {
        parent: _parent,
        root,
        ledger,
        candidate,
        ..
    } = env();
    let ledger = Arc::new(ledger);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    // The work outlives the deadline: the caller sees Deadline, not a witness.
    let hook = move |step: PrepareStep<'_>| {
        if matches!(step, PrepareStep::Write(FileRole::Artifact)) {
            std::thread::sleep(Duration::from_millis(2_500));
        }
        Ok(())
    };
    let outcome = runtime.block_on(async {
        prepare_blocking_with(ledger.clone(), Arc::new(root), candidate, deadline, hook).await
    });
    assert!(matches!(outcome, Err(PublicationError::Deadline)));
    // The blocking task refused its next step after expiry and recorded it.
    let finished = Instant::now() + Duration::from_secs(10);
    loop {
        let state: Option<String> = ledger
            .db()
            .query_row("SELECT state FROM publication_allocations", [], |r| {
                r.get(0)
            })
            .ok();
        if state.as_deref() != Some("preparing") {
            assert_eq!(state.as_deref(), Some("failed"));
            break;
        }
        assert!(Instant::now() < finished, "native work never finished");
        std::thread::sleep(Duration::from_millis(10));
    }
}
