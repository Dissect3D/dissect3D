static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
use super::*;
const MESH: &[u8] = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 4\n";
fn fixture() -> (DispatchRecord, ClosedCandidate, VerifiedInputSet) {
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
    let _serial = SERIAL.lock().unwrap();
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
    let _serial = SERIAL.lock().unwrap();
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
#[test]
fn rejects_wrong_attempt_job_session_and_captured_input_binding() {
    let _serial = SERIAL.lock().unwrap();
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
fn independent_slot_and_expired_budget_fail_closed() {
    let _serial = SERIAL.lock().unwrap();
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
