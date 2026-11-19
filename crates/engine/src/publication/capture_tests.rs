use super::*;
use crate::publication::tests::{MESH, SERIAL, fixture};
use crate::publication::validate_candidate;
use crate::store::cleanup::test_identity;
use crate::worker_protocol::CandidateFile;
use dissect3d_platform::{OwnedRoot, RootPurpose};
use sha2::{Digest, Sha256};
use std::fs;

const DESCRIPTION: &[u8] = br#"{"mesh":["mesh.obj"]}"#;

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Attempt {
    _parent: tempfile::TempDir,
    root: OwnedRoot,
    staging: AttemptRoot,
    dispatch: DispatchRecord,
}

/// A real private root, the attempt's retained staging folder and its dispatch.
fn attempt() -> Attempt {
    let parent = tempfile::TempDir::new().unwrap();
    let root =
        OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData).unwrap();
    let (dispatch, _, _) = fixture();
    let staging = root
        .create_attempt_root(
            &RelativePath::parse(format!(
                "execution/attempts/{}/staging",
                dispatch.attempt_id
            ))
            .unwrap(),
        )
        .unwrap();
    Attempt {
        _parent: parent,
        root,
        staging,
        dispatch,
    }
}

impl Attempt {
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.staging.worker_path().join(name), bytes).unwrap();
    }
    fn cleanup(&self) -> CleanupEvidence {
        CleanupEvidence::for_test(test_identity(&self.dispatch.session_id, "capture"))
    }
}

fn report(files: &[(&str, &[u8])], description: &str) -> CandidateReport {
    CandidateReport {
        description_handle: description.into(),
        files: files
            .iter()
            .map(|(name, bytes)| CandidateFile {
                relative_name: (*name).into(),
                byte_length: bytes.len() as u64,
                sha256: hex(bytes),
            })
            .collect(),
    }
}

#[test]
fn a_candidate_captured_after_confirmed_cleanup_validates_end_to_end() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let a = attempt();
    a.write("mesh.obj", MESH);
    a.write("output.json", DESCRIPTION);
    let candidate = capture_candidate(
        &a.dispatch,
        &report(&[("mesh.obj", MESH)], "output.json"),
        &a.cleanup(),
        &a.staging,
    )
    .unwrap();
    // The captured input snapshot, read through a fresh immutable handle.
    let name = RelativePath::parse("inputs/inp_11111111111111111111111111111111").unwrap();
    a.root.write_atomic(&name, MESH).unwrap();
    let (_, _, fixture_inputs) = fixture();
    let inputs = verified_input(
        fixture_inputs.identities[0].clone(),
        a.root.open_immutable_input(&name).unwrap(),
    )
    .unwrap();
    validate_candidate(&a.dispatch, &candidate, &inputs).unwrap();
    // Changing staging afterwards cannot change what was captured.
    fs::write(a.staging.worker_path().join("mesh.obj"), b"v 9 9 9\n").unwrap();
    validate_candidate(&a.dispatch, &candidate, &inputs).unwrap();
}

#[test]
fn cleanup_evidence_for_another_session_cannot_authorize_capture() {
    let a = attempt();
    a.write("mesh.obj", MESH);
    a.write("output.json", DESCRIPTION);
    let other = CleanupEvidence::for_test(test_identity(
        "ses_00000000000000000000000000000000",
        "other",
    ));
    assert!(matches!(
        capture_candidate(
            &a.dispatch,
            &report(&[("mesh.obj", MESH)], "output.json"),
            &other,
            &a.staging
        ),
        Err(PublicationError::InvalidCandidate)
    ));
}

#[test]
fn a_report_whose_length_or_digest_differs_from_the_bytes_is_refused() {
    let a = attempt();
    a.write("mesh.obj", MESH);
    a.write("output.json", DESCRIPTION);
    let mut wrong_length = report(&[("mesh.obj", MESH)], "output.json");
    wrong_length.files[0].byte_length += 1;
    let mut wrong_digest = report(&[("mesh.obj", MESH)], "output.json");
    wrong_digest.files[0].sha256 = hex(b"other");
    for claim in [wrong_length, wrong_digest] {
        assert!(matches!(
            capture_candidate(&a.dispatch, &claim, &a.cleanup(), &a.staging),
            Err(PublicationError::InvalidCandidate)
        ));
    }
}

#[test]
fn unsafe_colliding_or_unreported_names_refuse_the_candidate() {
    for (files, description) in [
        (vec!["../mesh.obj"], "output.json"),
        (vec!["sub/mesh.obj"], "output.json"),
        (vec!["manifest.json"], "output.json"),
        (vec!["mesh.obj"], "../output.json"),
        (vec!["mesh.obj"], "mesh.obj"),
        (vec!["mesh.obj", "MESH.OBJ"], "output.json"),
        (vec![], "output.json"),
    ] {
        let a = attempt();
        a.write("mesh.obj", MESH);
        a.write("output.json", DESCRIPTION);
        let named = files.iter().map(|n| (*n, MESH)).collect::<Vec<_>>();
        assert!(
            matches!(
                capture_candidate(
                    &a.dispatch,
                    &report(&named, description),
                    &a.cleanup(),
                    &a.staging
                ),
                Err(PublicationError::InvalidCandidate)
            ),
            "{files:?} {description}"
        );
    }
    // A file the worker left without reporting it.
    let a = attempt();
    a.write("mesh.obj", MESH);
    a.write("output.json", DESCRIPTION);
    a.write("leftover.tmp", b"x");
    assert!(matches!(
        capture_candidate(
            &a.dispatch,
            &report(&[("mesh.obj", MESH)], "output.json"),
            &a.cleanup(),
            &a.staging
        ),
        Err(PublicationError::InvalidCandidate)
    ));
}

#[test]
fn oversized_candidate_and_description_are_refused() {
    let big = vec![b' '; MAX_BYTES + 1];
    let a = attempt();
    a.write("mesh.obj", &big);
    a.write("output.json", DESCRIPTION);
    assert!(matches!(
        capture_candidate(
            &a.dispatch,
            &report(&[("mesh.obj", &big)], "output.json"),
            &a.cleanup(),
            &a.staging
        ),
        Err(PublicationError::InvalidCandidate)
    ));
    let a = attempt();
    a.write("mesh.obj", MESH);
    a.write(
        "output.json",
        &vec![b' '; DESCRIPTION_BYTES_MAX as usize + 1],
    );
    assert!(matches!(
        capture_candidate(
            &a.dispatch,
            &report(&[("mesh.obj", MESH)], "output.json"),
            &a.cleanup(),
            &a.staging
        ),
        Err(PublicationError::InvalidCandidate)
    ));
}

#[test]
fn an_input_snapshot_that_disagrees_with_its_identity_is_refused() {
    let a = attempt();
    let (_, _, fixture_inputs) = fixture();
    for (index, bytes) in [
        &MESH[..MESH.len() - 1],
        b"v 0 0 9\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 4\n",
    ]
    .into_iter()
    .enumerate()
    {
        let name = RelativePath::parse(format!("inputs/case-{index}")).unwrap();
        a.root.write_atomic(&name, bytes).unwrap();
        assert!(matches!(
            verified_input(
                fixture_inputs.identities[0].clone(),
                a.root.open_immutable_input(&name).unwrap()
            ),
            Err(PublicationError::InputIntegrity)
        ));
    }
}
