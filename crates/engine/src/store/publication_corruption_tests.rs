//! RP-P03/7: offline corruption or removal of committed result bytes.
//!
//! A real publication commits through the Store. Then, with the engine
//! stopped, one test-owned committed object is damaged and the Store is
//! reopened. Historical success and provenance stay exactly as committed.
//! The verified read reports `artifact_unavailable` or
//! `storage_integrity_fault` as found, and nothing is re-hashed into the
//! record, rebuilt, rewritten or run as another attempt. Reclamation and the
//! audit never follow a damaged reference out of the owned root. HTTP
//! status mapping is RP-P04/3.
use super::publication_crash_tests::publication_job;
use super::results::FileRole;
use super::results_commit::CommittedFile;
use super::retry_tests::db;
use super::*;
use crate::publication::service::{PublishOutcome, publish_blocking};
use crate::publication::storage::{
    ArtifactFault, AuditCursor, audit_turn, read_committed, reclaim_turn,
};
use std::path::Path;

/// Everything committed history consists of, as stored.
#[derive(Debug, PartialEq, Eq)]
struct History {
    job: (String, Option<String>, i64, String),
    results: Vec<(String, String, i64, String)>,
    files: Vec<(String, String, i64, Vec<u8>)>,
    attempts: i64,
    events: (i64, i64),
}

fn history(f: &Fixture) -> History {
    let db = db(f);
    let rows = |sql: &str| -> Vec<(String, String, i64, Vec<u8>)> {
        let mut statement = db.prepare(sql).unwrap();
        statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    History {
        job: db
            .query_row(
                "SELECT state,outcome_code,snapshot_revision,cleanup_status FROM job_execution",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap(),
        results: {
            let mut statement = db
                .prepare(
                    "SELECT result_id,attempt_id,publication_sequence,manifest_version
                     FROM results ORDER BY result_id",
                )
                .unwrap();
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        },
        files: rows(
            "SELECT object_name,role,byte_length,sha256 FROM result_files ORDER BY object_name",
        ),
        attempts: db
            .query_row("SELECT count(*) FROM job_attempts", [], |r| r.get(0))
            .unwrap(),
        events: db
            .query_row(
                "SELECT count(*),max(snapshot_revision) FROM job_events",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap(),
    }
}

fn committed_files(f: &Fixture) -> Vec<CommittedFile> {
    history(f)
        .files
        .into_iter()
        .map(|(object_name, role, length, sha256)| CommittedFile {
            object_name,
            role: if role == "artifact" {
                FileRole::Artifact
            } else {
                FileRole::Manifest
            },
            byte_length: length as u64,
            sha256: sha256.try_into().unwrap(),
        })
        .collect()
}

/// Stop the engine, damage storage, start it again.
fn offline(f: Fixture, damage: impl FnOnce(&Path)) -> Fixture {
    let Fixture {
        _parent,
        root,
        store,
        auth,
        prepared,
    } = f;
    drop(store);
    damage(root.path());
    let reopened = OwnedRoot::open(root.path(), RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&reopened).unwrap();
    Fixture {
        _parent,
        root,
        store: Store::open(reopened, lease, &CorePolicy::default()).unwrap(),
        auth,
        prepared,
    }
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    Removed,
    Truncated,
    FlippedByte,
    ReplacedByDirectory,
    LinkedOutside,
}

#[test]
fn damaged_committed_bytes_are_reported_as_found_and_history_is_kept() {
    for damage in [
        Damage::Removed,
        Damage::Truncated,
        Damage::FlippedByte,
        Damage::ReplacedByDirectory,
        Damage::LinkedOutside,
    ] {
        let f = Fixture::new();
        let (_, attempt, request) = publication_job(&f);
        let PublishOutcome::Published(receipt) = publish_blocking(&f.store, &f.root, request)
        else {
            panic!("{damage:?}: the real publication did not commit")
        };
        let committed = history(&f);
        let files = committed_files(&f);
        let artifact = files
            .iter()
            .find(|file| file.role == FileRole::Artifact)
            .unwrap()
            .clone();
        let manifest = files
            .iter()
            .find(|file| file.role == FileRole::Manifest)
            .unwrap()
            .clone();
        let exact = read_committed(&f.root, &artifact).unwrap();
        assert_eq!(exact.len() as u64, artifact.byte_length);
        // A file outside the owned root with exactly the committed bytes.
        let outside = f._parent.path().join("outside.obj");
        std::fs::write(&outside, &exact).unwrap();
        let object = |root: &Path| root.join("results/objects").join(&artifact.object_name);
        let f = offline(f, |root| {
            let path = object(root);
            match damage {
                Damage::Removed => std::fs::remove_file(&path).unwrap(),
                Damage::Truncated => {
                    std::fs::write(&path, &exact[..exact.len() - 1]).unwrap();
                }
                Damage::FlippedByte => {
                    let mut bytes = exact.clone();
                    bytes[0] ^= 0x01;
                    std::fs::write(&path, bytes).unwrap();
                }
                Damage::ReplacedByDirectory => {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::create_dir(&path).unwrap();
                }
                Damage::LinkedOutside => {
                    std::fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink(&outside, &path).unwrap();
                }
            }
        });
        let expected = match damage {
            Damage::Removed => ArtifactFault::Unavailable,
            _ => ArtifactFault::Integrity,
        };
        assert_eq!(
            read_committed(&f.root, &artifact),
            Err(expected),
            "{damage:?}"
        );
        // The undamaged manifest still reads exactly.
        assert_eq!(
            read_committed(&f.root, &manifest).map(|bytes| bytes.len() as u64),
            Ok(manifest.byte_length),
            "{damage:?}"
        );
        // Historical success and provenance are exactly as committed.
        assert_eq!(history(&f), committed, "{damage:?}");
        assert_eq!(
            f.store.publication_for_attempt(attempt.attempt_id.clone()),
            Ok(Some(receipt.clone())),
            "{damage:?}"
        );
        // Neither cleanup turn takes, follows or repairs a committed name.
        let reclaimed = reclaim_turn(&f.store, &f.root).unwrap();
        assert_eq!(reclaimed.deleted, 0, "{damage:?}");
        let mut cursor = AuditCursor::default();
        loop {
            let report = audit_turn(&f.store, &f.root, &mut cursor).unwrap();
            assert_eq!(report.quarantined, 0, "{damage:?}: committed names stay");
            if report.exhausted {
                break;
            }
        }
        assert_eq!(std::fs::read(&outside).unwrap(), exact, "{damage:?}");
        assert_eq!(
            read_committed(&f.root, &artifact),
            Err(expected),
            "{damage:?}: still reported as found, never rebuilt"
        );
        // A second restart changes nothing.
        let f = offline(f, |_| {});
        assert_eq!(history(&f), committed, "{damage:?}");
        assert_eq!(
            read_committed(&f.root, &artifact),
            Err(expected),
            "{damage:?}"
        );
    }
}

/// A file row whose object name is not a generated name is never opened.
#[test]
fn a_reference_that_is_not_a_generated_name_is_an_integrity_fault() {
    let f = Fixture::new();
    std::fs::write(f._parent.path().join("escape"), b"x").unwrap();
    for name in ["../../escape", "results/../escape", "art_short"] {
        let file = CommittedFile {
            object_name: name.into(),
            role: FileRole::Artifact,
            byte_length: 1,
            sha256: Sha256::digest(b"x").into(),
        };
        assert_eq!(
            read_committed(&f.root, &file),
            Err(ArtifactFault::Integrity),
            "{name}"
        );
    }
}

/// Reclamation of an orphan whose object was replaced by a link to a file
/// outside the owned root refuses: it neither follows nor removes the link,
/// the target is untouched and the charge stays (fail closed).
#[test]
fn reclaiming_a_linked_orphan_refuses_without_following_the_link() {
    use super::results_commit_tests::{prepared, running};
    let f = Fixture::new();
    let attempt = running(&f, "linked-orphan");
    let commit = prepared(&f, &attempt, '9');
    // Restart interrupts the attempt, so its prepared allocation is an orphan.
    let f = offline(f, |_| {});
    let outside = f._parent.path().join("outside.bin");
    std::fs::write(&outside, b"outside").unwrap();
    let objects = f.root.path().join("results/objects");
    f.root
        .ensure_private_directory(&RelativePath::parse("results/objects").unwrap())
        .unwrap();
    for file in &commit.files {
        std::os::unix::fs::symlink(&outside, objects.join(&file.object_name)).unwrap();
    }
    let before = f.store.result_usage().unwrap();
    assert!(matches!(
        reclaim_turn(&f.store, &f.root),
        Err(crate::publication::PublicationError::Storage)
    ));
    for file in &commit.files {
        let link = std::fs::symlink_metadata(objects.join(&file.object_name)).unwrap();
        assert!(link.file_type().is_symlink(), "kept as evidence");
    }
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    assert_eq!(f.store.result_usage().unwrap(), before, "still charged");
}
