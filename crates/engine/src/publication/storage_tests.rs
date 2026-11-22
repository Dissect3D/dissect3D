//! RP-P02/4-/6 on the native filesystem, with the real Store SQL behind a
//! test ledger. Durable paths run on Unix and on Windows (DS-G04 protocol);
//! a root that fails its durable check must refuse before charging or writing.
use super::*;
use crate::publication::tests::MESH;
use crate::publication::tests::{SERIAL, fixture};
use crate::publication::validate_candidate;
use crate::store::results::tests::{seed_running, store_at};
use crate::store::results::{self, ResultUsage};
use dissect3d_platform::RootPurpose;
use rusqlite::Connection;
use std::fs;
use std::sync::Mutex;
use std::time::Duration;

struct Ledger {
    db: Mutex<Connection>,
    fail_lookups: bool,
}

impl Ledger {
    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl ResultLedger for Ledger {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError> {
        results::reserve(&mut self.db(), &request)
    }
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError> {
        results::mark_prepared(&mut self.db(), result_id)
    }
    fn abandon(&self, result_id: &str) -> Result<(), CoreError> {
        results::abandon(&mut self.db(), result_id)
    }
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        results::claim_reclaim(&mut self.db())
    }
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError> {
        results::confirm_reclaimed(&mut self.db(), &objects)
    }
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError> {
        if self.fail_lookups {
            return Err(CoreError::StoreUnavailable);
        }
        results::known_objects(&mut self.db(), &names)
    }
}

struct Env {
    parent: tempfile::TempDir,
    root: OwnedRoot,
    ledger: Ledger,
    candidate: ValidatedCandidate,
    job: String,
}

fn env() -> Env {
    let parent = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData).unwrap();
    let db = store_at(&parent.path().join("metadata.sqlite3"));
    let (dispatch, closed, inputs) = fixture();
    seed_running(&db, dispatch.job_id.as_str(), &dispatch.attempt_id, 1);
    let candidate = {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        validate_candidate(&dispatch, &closed, &inputs).unwrap()
    };
    Env {
        parent,
        root,
        ledger: Ledger {
            db: Mutex::new(db),
            fail_lookups: false,
        },
        candidate,
        job: dispatch.job_id.as_str().to_owned(),
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

impl Env {
    fn usage(&self) -> ResultUsage {
        results::usage(&mut self.ledger.db()).unwrap()
    }
    fn set_job_state(&self, state: &str) {
        self.ledger
            .db()
            .execute(
                "UPDATE job_execution SET state=?2 WHERE job_id=?1",
                [&self.job, state],
            )
            .unwrap();
    }
    fn allocation_state(&self) -> Option<String> {
        self.ledger
            .db()
            .query_row("SELECT state FROM publication_allocations", [], |r| {
                r.get(0)
            })
            .ok()
    }
    fn entries(&self, directory: &str) -> Vec<String> {
        let mut names = match fs::read_dir(self.root.path().join(directory)) {
            Ok(entries) => entries
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }
}

#[test]
fn prepared_files_are_durable_private_and_bound_to_their_recorded_rows() {
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let env = env();
    let prepared = prepare_publication(&env.ledger, &env.root, &env.candidate, soon()).unwrap();
    assert_eq!(env.allocation_state().as_deref(), Some("prepared"));
    let [artifact, manifest] = prepared.files() else {
        panic!("two files")
    };
    assert_eq!(artifact.role(), FileRole::Artifact);
    assert_eq!(manifest.role(), FileRole::Manifest);
    assert_eq!(manifest.object_name(), prepared.publication_id());
    assert_eq!(manifest.filename(), "manifest.json");
    for file in prepared.files() {
        let path = env
            .root
            .path()
            .join(file.durable().relative_path().as_str());
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, file.byte_length());
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), file.sha256());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Windows: the platform's no-follow read validates the private owner
        // ACL and single link; a fresh read-back must succeed.
        assert_eq!(
            env.root
                .read_file(file.durable().relative_path(), 1_048_576)
                .unwrap(),
            bytes
        );
        let recorded: Vec<u8> = env
            .ledger
            .db()
            .query_row(
                "SELECT sha256 FROM result_files WHERE object_name=?1",
                [file.object_name()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(recorded, file.sha256());
    }
    assert_eq!(
        fs::read(
            env.root
                .path()
                .join("results/objects")
                .join(artifact.object_name())
        )
        .unwrap(),
        MESH
    );
    let parsed: dissect3d_api::ResultManifest = serde_json::from_slice(
        &fs::read(
            env.root
                .path()
                .join("results/objects")
                .join(manifest.object_name()),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(parsed.result_id, prepared.result_id());
    assert_eq!(parsed.publication_id, prepared.publication_id());
    assert_eq!(parsed.files[0].artifact_id, artifact.object_name());
    assert_eq!(parsed.published_at_ms, prepared.published_at_ms());
    assert_eq!(parsed.attempt_id, prepared.attempt_id());
    assert_eq!(prepared.manifest_version(), "1.0");
    assert!(
        env.entries("results/staging").is_empty(),
        "no staged leftovers"
    );
    assert_eq!(
        env.usage(),
        ResultUsage {
            private_bytes: artifact.byte_length() + manifest.byte_length(),
            published_bytes: 0,
            unwritten_bytes: 0,
            records: 1
        }
    );
    // One allocation per attempt: a repeat writes nothing.
    assert!(matches!(
        prepare_publication(&env.ledger, &env.root, &env.candidate, soon()),
        Err(PublicationError::Stale)
    ));
    assert_eq!(env.entries("results/objects").len(), 2);
}

#[test]
fn a_failed_barrier_yields_no_witness_and_keeps_its_charge_until_terminal_reclaim() {
    let env = env();
    // Bytes are staged and synced, then the final namespace cannot be opened:
    // `results/objects` is a private regular file, not a directory.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(env.root.path().join("results"))
            .unwrap();
    }
    #[cfg(windows)]
    env.root
        .ensure_private_directory(&dissect3d_platform::RelativePath::parse("results").unwrap())
        .unwrap();
    let objects = env.root.path().join("results/objects");
    fs::write(&objects, b"not a directory").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&objects, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(matches!(
        prepare_publication(&env.ledger, &env.root, &env.candidate, soon()),
        Err(PublicationError::Storage)
    ));
    assert_eq!(env.allocation_state().as_deref(), Some("failed"));
    let charged = env.usage().private_bytes;
    assert!(charged > MESH.len() as u64);
    assert_eq!(env.entries("results/staging").len(), 1, "evidence retained");
    // A running job (a caller that timed out or vanished) keeps everything.
    assert_eq!(
        reclaim_turn(&env.ledger, &env.root).unwrap(),
        ReclaimReport::default()
    );
    assert_eq!(env.usage().private_bytes, charged);
    env.set_job_state("interrupted");
    // Reclamation needs the namespace back to remove the staged name.
    fs::remove_file(&objects).unwrap();
    let report = reclaim_turn(&env.ledger, &env.root).unwrap();
    assert_eq!((report.deleted, report.released_bytes), (2, charged));
    assert!(env.entries("results/staging").is_empty());
    assert_eq!(env.usage(), ResultUsage::default());
}

#[test]
fn stale_attempts_limits_and_expired_deadlines_refuse_before_writing() {
    let env = env();
    env.set_job_state("cancel_requested");
    assert!(matches!(
        prepare_publication(&env.ledger, &env.root, &env.candidate, soon()),
        Err(PublicationError::Stale)
    ));
    env.set_job_state("running");
    {
        let db = env.ledger.db();
        db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
        db.execute(
            "INSERT INTO publication_allocations VALUES('res_ffffffffffffffffffffffffffffffff','pub_ffffffffffffffffffffffffffffffff','job_x','att_x','ins_x','reclaiming',67108000,1,1)",
            [],
        )
        .unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    }
    assert!(matches!(
        prepare_publication(&env.ledger, &env.root, &env.candidate, soon()),
        Err(PublicationError::Capacity("result_private_bytes_max"))
    ));
    assert!(matches!(
        prepare_publication(&env.ledger, &env.root, &env.candidate, Instant::now()),
        Err(PublicationError::Deadline)
    ));
    assert_eq!(env.usage().records, 1, "only the seeded allocation");
    assert!(!env.root.path().join("results").exists(), "nothing written");
}

#[test]
fn a_failed_deletion_keeps_the_charge_and_a_later_turn_finishes_it() {
    let env = env();
    let prepared = prepare_publication(&env.ledger, &env.root, &env.candidate, soon()).unwrap();
    let charged = env.usage().private_bytes;
    let manifest = env
        .root
        .path()
        .join("results/objects")
        .join(prepared.publication_id());
    // `art_` sorts before `pub_`: the artifact goes, the manifest cannot.
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();
    env.set_job_state("failed");
    assert!(matches!(
        reclaim_turn(&env.ledger, &env.root),
        Err(PublicationError::Storage)
    ));
    assert_eq!(env.allocation_state().as_deref(), Some("reclaiming"));
    assert_eq!(
        env.usage().private_bytes,
        charged,
        "no release before deletion"
    );
    assert_eq!(
        env.entries("results/objects"),
        vec![prepared.publication_id().to_owned()]
    );
    fs::remove_dir(&manifest).unwrap();
    let report = reclaim_turn(&env.ledger, &env.root).unwrap();
    assert_eq!((report.deleted, report.released_bytes), (1, charged));
    assert_eq!(env.usage(), ResultUsage::default());
    assert_eq!(env.allocation_state(), None);
}

#[test]
fn audit_quarantines_unreferenced_entries_and_a_failed_lookup_keeps_everything() {
    let mut env = env();
    let prepared = prepare_publication(&env.ledger, &env.root, &env.candidate, soon()).unwrap();
    let objects = env.root.path().join("results/objects");
    let outside = env.parent.path().join("outside.bin");
    fs::write(&outside, b"outside").unwrap();
    fs::write(objects.join("stray.bin"), b"x").unwrap();
    fs::write(objects.join("art_0123456789abcdef0123456789abcdef"), b"y").unwrap();
    fs::create_dir_all(env.root.path().join("results/staging")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, env.root.path().join("results/staging/link")).unwrap();
    #[cfg(windows)]
    {
        // A junction needs no privilege; it must move without being followed.
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(env.root.path().join("results").join("staging").join("link"))
            .arg(env.parent.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "junction creation");
    }
    let planted = (
        env.entries("results/objects"),
        env.entries("results/staging"),
    );

    env.ledger.fail_lookups = true;
    assert!(matches!(
        audit_turn(&env.ledger, &env.root, &mut AuditCursor::default()),
        Err(PublicationError::Storage)
    ));
    assert_eq!(
        (
            env.entries("results/objects"),
            env.entries("results/staging")
        ),
        planted,
        "an unknown lookup is not absence"
    );

    env.ledger.fail_lookups = false;
    let mut cursor = AuditCursor::default();
    let mut quarantined = 0;
    for _ in 0..4 {
        let report = audit_turn(&env.ledger, &env.root, &mut cursor).unwrap();
        quarantined += report.quarantined;
        if report.exhausted {
            break;
        }
    }
    assert_eq!(quarantined, 3);
    let mut kept = prepared
        .files()
        .iter()
        .map(|f| f.object_name().to_owned())
        .collect::<Vec<_>>();
    kept.sort();
    assert_eq!(env.entries("results/objects"), kept);
    assert!(env.entries("results/staging").is_empty());
    assert_eq!(env.entries("results/quarantine").len(), 3);
    assert_eq!(fs::read(&outside).unwrap(), b"outside", "link not followed");
    assert_eq!(env.allocation_state().as_deref(), Some("prepared"));
}

#[test]
fn a_root_failing_its_durable_check_refuses_before_charging_or_writing() {
    let env = env();
    // Rename the selected root away and put a valid private root in its
    // place: the retained root no longer matches a fresh no-follow open.
    let selected = env.root.path().to_path_buf();
    let moved = env.parent.path().join("moved-engine");
    fs::rename(&selected, &moved).unwrap();
    let _replacement = OwnedRoot::create_private(&selected, RootPurpose::EngineData).unwrap();
    assert!(matches!(
        prepare_publication(&env.ledger, &env.root, &env.candidate, soon()),
        Err(PublicationError::Storage)
    ));
    assert!(matches!(
        reclaim_turn(&env.ledger, &env.root),
        Err(PublicationError::Storage)
    ));
    assert!(matches!(
        audit_turn(&env.ledger, &env.root, &mut AuditCursor::default()),
        Err(PublicationError::Storage)
    ));
    assert_eq!(env.usage(), ResultUsage::default());
    assert!(!selected.join("results").exists());
    assert!(!moved.join("results").exists());
}
