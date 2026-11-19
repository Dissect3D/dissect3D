pub(super) static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
use super::*;
pub(super) const MESH: &[u8] =
    b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 4\n";
pub(super) fn fixture() -> (DispatchRecord, ClosedCandidate, VerifiedInputSet) {
    let example: serde_json::Value = serde_json::from_str(include_str!(
        "../../api/tests/fixtures/result_publication.json"
    ))
    .unwrap();
    let resolved: ResolvedJob = dissect3d_api::decode_submission_json(
        serde_json::to_string(&example["complete_mesh_copy"]["provenance"]["resolved"])
            .unwrap()
            .as_bytes(),
        262_144,
    )
    .unwrap();
    let dispatch = DispatchRecord {
        job_id: dissect3d_api::JobId::parse("job_22222222222222222222222222222222").unwrap(),
        attempt_id: "att_33333333333333333333333333333333".into(),
        session_id: "ses_77777777777777777777777777777777".into(),
        grant_id: "grt_88888888888888888888888888888888".into(),
        resolved_json: serde_json::to_string(&resolved).unwrap(),
        resources: vec!["cpu:controlled".into()],
        timeout_ms: None,
        timing: Arc::new(crate::store::execution::AttemptTiming::for_validation_test()),
    };
    let candidate = ClosedCandidate {
        job_id: dispatch.job_id.clone(),
        attempt_id: dispatch.attempt_id.clone(),
        session_id: dispatch.session_id.clone(),
        files: vec![CandidateFileRef {
            filename: "mesh.obj".into(),
            bytes: Arc::from(MESH),
        }],
    };
    let input = VerifiedInputSet {
        identities: resolved.inputs["mesh"].clone(),
        bytes: Arc::from(MESH),
    };
    (dispatch, candidate, input)
}
#[test]
fn independent_geometry_and_copy_validation_builds_exact_manifest_bytes() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (dispatch, candidate, inputs) = fixture();
    let valid = validate_candidate(&dispatch, &candidate, &inputs).unwrap();
    let bytes = valid
        .manifest(
            "res_11111111111111111111111111111111",
            "pub_44444444444444444444444444444444",
            "art_55555555555555555555555555555555",
            1,
        )
        .unwrap();
    let manifest = dissect3d_api::decode_result_manifest(&bytes.bytes).unwrap();
    assert_eq!(manifest.job_id, dispatch.job_id);
    assert_eq!(manifest.provenance.input_identities, inputs.identities);
    assert_eq!(
        manifest.files[0].sha256.as_str(),
        "b391f08159e507ad3a0fa80558bdb046e150e38868378c9972072d54ad65f858"
    );
    assert_eq!(bytes.sha256, <[u8; 32]>::from(Sha256::digest(&bytes.bytes)));
}
#[test]
fn rejects_missing_invalid_external_and_valid_but_different_output() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    for bad in [
        b"".as_slice(),
        b"v NaN 0 0\n",
        b"v 1e999 0 0\n",
        b"mtllib remote.mtl\n",
        b"f 999999999999999999999 2 3\n",
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 3 2\nf 1 4 3\nf 2 3 4\n",
        b"v 0 0 0\nv 2 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 4\n",
    ] {
        let (d, mut c, i) = fixture();
        c.files[0].bytes = Arc::from(bad);
        assert!(validate_candidate(&d, &c, &i).is_err());
    }
    let (d, mut c, i) = fixture();
    c.files.clear();
    assert!(validate_candidate(&d, &c, &i).is_err());
}
/// Captured input and candidate hold the same `bytes`, with a matching input
/// identity, so copy fidelity holds and only the geometry check can refuse.
fn identical_copy_of(bytes: &[u8]) -> (DispatchRecord, ClosedCandidate, VerifiedInputSet) {
    let (mut d, mut c, mut i) = fixture();
    let mut resolved: serde_json::Value = serde_json::from_str(&d.resolved_json).unwrap();
    resolved["inputs"]["mesh"][0]["byte_length"] = bytes.len().into();
    resolved["inputs"]["mesh"][0]["sha256"] = hex(Sha256::digest(bytes).into()).into();
    let resolved: ResolvedJob = dissect3d_api::decode_submission_json(
        serde_json::to_string(&resolved).unwrap().as_bytes(),
        MANIFEST_BYTES_MAX,
    )
    .unwrap();
    d.resolved_json = serde_json::to_string(&resolved).unwrap();
    i.identities = resolved.inputs["mesh"].clone();
    i.bytes = Arc::from(bytes);
    c.files[0].bytes = Arc::from(bytes);
    (d, c, i)
}
#[test]
fn invalid_geometry_is_refused_even_when_it_is_an_exact_copy() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (d, c, i) = identical_copy_of(MESH);
    assert!(
        validate_candidate(&d, &c, &i).is_ok(),
        "control: a valid copy passes"
    );
    for bad in [
        b"v NaN 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n".as_slice(),
        b"v 1e999 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n",
        b"v 2000000 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n",
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 4\n",
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 999999999999999999999\n",
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 1 2\n",
        b"v 0 0 0\nv 1 0 0\nv 2 0 0\nf 1 2 3\n",
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\nf 1 2 3\n",
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf -1 -2 -3\n",
        b"mtllib remote.mtl\nv 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n",
        b"v 0 0 0\nv 1 0 0\nv 0 1 0\n",
    ] {
        let (d, c, i) = identical_copy_of(bad);
        assert!(
            matches!(
                validate_candidate(&d, &c, &i),
                Err(PublicationError::InvalidGeometry)
            ),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
}
#[test]
fn rejects_wrong_attempt_job_session_and_captured_input_binding() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    for index in 0..4 {
        let (d, mut c, mut i) = fixture();
        match index {
            0 => c.attempt_id = "att_00000000000000000000000000000000".into(),
            1 => {
                c.job_id =
                    dissect3d_api::JobId::parse("job_00000000000000000000000000000000").unwrap()
            }
            2 => c.session_id = "ses_00000000000000000000000000000000".into(),
            _ => {
                i.identities[0].input_id =
                    dissect3d_api::InputId::parse("inp_00000000000000000000000000000000").unwrap()
            }
        }
        assert!(validate_candidate(&d, &c, &i).is_err());
    }
}
#[test]
fn manifest_records_the_exact_stored_resolution_and_explicit_unknowns() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (mut dispatch, candidate, inputs) = fixture();
    // A stored (key-sorted) resolution whose exact numeric text f64 would round.
    let exact = dispatch.resolved_json.replacen(
        "\"hold_before_candidate\":false",
        "\"hold_before_candidate\":false,\"ratio\":0.10000000000000000000000001",
        1,
    );
    assert_ne!(exact, dispatch.resolved_json);
    dispatch.resolved_json = exact;
    let valid = validate_candidate(&dispatch, &candidate, &inputs).unwrap();
    let bytes = valid
        .manifest(
            "res_11111111111111111111111111111111",
            "pub_44444444444444444444444444444444",
            "art_55555555555555555555555555555555",
            1,
        )
        .unwrap();
    assert_eq!(bytes.version, "1.0");
    let text = std::str::from_utf8(&bytes.bytes).unwrap();
    // Independent Draft 2020-12 validation reads this exact engine-built vector.
    println!("RP_SCHEMA_VECTOR manifest {text}");
    let manifest = dissect3d_api::decode_result_manifest(&bytes.bytes).unwrap();
    assert_eq!(manifest.manifest_version, bytes.version);
    assert_eq!(
        serde_json::to_string(&manifest.provenance.resolved).unwrap(),
        dispatch.resolved_json,
        "the manifest must carry the stored resolution exactly"
    );
    assert_eq!(manifest.provenance.effective_seed, None);
    assert!(manifest.provenance.transformations.is_empty());
    assert_eq!(
        manifest.components[0].local_transform,
        copy_identity_transform()
    );
    for unknown in [
        &manifest.coordinates.axes,
        &manifest.coordinates.handedness,
        &manifest.coordinates.units,
        &manifest.coordinates.scale_assumption,
    ] {
        assert_eq!(unknown, "unknown");
    }
    assert_eq!(manifest.validation.validator_id, OUTPUT_VALIDATOR_ID);
    assert_eq!(
        manifest.validation.validator_revision,
        OUTPUT_VALIDATOR_REVISION
    );
}
#[test]
fn a_resolution_naming_another_output_validator_is_refused() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    for (id, revision) in [("dissect3d.test.validator", "2"), ("other.validator", "1")] {
        let (mut d, c, i) = fixture();
        let mut resolved: ResolvedJob =
            dissect3d_api::decode_submission_json(d.resolved_json.as_bytes(), MANIFEST_BYTES_MAX)
                .unwrap();
        resolved.validation[0].validator_id = id.into();
        resolved.validation[0].revision = revision.into();
        d.resolved_json = serde_json::to_string(&resolved).unwrap();
        assert!(matches!(
            validate_candidate(&d, &c, &i),
            Err(PublicationError::InvalidCandidate)
        ));
    }
}
#[test]
fn unsafe_candidate_filenames_are_refused_before_content_checks() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    for name in [
        "",
        "../mesh.obj",
        "a/mesh.obj",
        "a\\mesh.obj",
        "/mesh.obj",
        "C:mesh.obj",
        "mesh.obj:ads",
        "manifest.json",
        "MANIFEST.JSON",
        "CON.obj",
        "lpt1",
        "mesh.",
        ".mesh.obj",
    ] {
        let (d, mut c, i) = fixture();
        c.files[0].filename = name.into();
        assert!(
            matches!(
                validate_candidate(&d, &c, &i),
                Err(PublicationError::InvalidCandidate)
            ),
            "{name:?}"
        );
    }
}
#[test]
fn independent_slot_and_expired_budget_fail_closed() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let (d, c, i) = fixture();
    let slot = ValidationSlot::acquire().unwrap();
    assert!(matches!(
        validate_candidate(&d, &c, &i),
        Err(PublicationError::Busy)
    ));
    drop(slot);
    assert!(matches!(
        validate_candidate_until(&d, &c, &i, Instant::now()),
        Err(PublicationError::Deadline)
    ));
}
