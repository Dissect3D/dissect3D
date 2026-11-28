//! Real protected files/leases; transport closures establish ordering only.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
use super::*;
fn ids() -> (InstallationId, ClientId) {
    (
        InstallationId::parse("ins_11111111111111111111111111111111").unwrap(),
        ClientId::parse("cli_22222222222222222222222222222222").unwrap(),
    )
}
fn save_credential(profile: &Profile) {
    let (installation, client) = ids();
    profile
        .save(&super::execution_tests::credential(
            &installation,
            &client,
            "active",
        ))
        .unwrap();
}
fn active() -> ProfileCredential {
    let (installation, client) = ids();
    super::execution_tests::credential(&installation, &client, "active")
}
fn receipt(p: &PendingExecutionAuthorization) -> ExecutionAuthorizationReceipt {
    ExecutionAuthorizationReceipt {
        bootstrap_version: "1.0".into(),
        contract_version: "execution-v1".into(),
        installation_id: p.installation_id.clone(),
        client_id: p.client_id.clone(),
        authorization_id: p.authorization_id.clone(),
        grant_policy: "execution-v1".into(),
        granted_operations: EXECUTION_GRANTS.iter().map(|s| (*s).into()).collect(),
        replayed: true,
    }
}
#[test]
fn existing_pending_reestablishes_barriers_before_becoming_sendable() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    let lease = profile.control_lease().unwrap();
    let original = profile
        .begin_execution_authorization(&lease, &active())
        .unwrap();
    let alias = temp.path().join("alias");
    std::fs::hard_link(profile.root.path().join(PENDING_FILE), &alias).unwrap();
    assert!(
        profile
            .begin_execution_authorization(&lease, &active())
            .is_err()
    );
    std::fs::remove_file(&alias).unwrap();
    assert_eq!(
        profile
            .read_execution_authorization()
            .unwrap()
            .unwrap()
            .authorization_id,
        original.authorization_id
    );
}
#[test]
fn lease_and_durable_id_span_send_uncertainty_and_interrupted_completion() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profile.json");
    let profile = Profile::open(&path).unwrap();
    save_credential(&profile);
    let mut original = String::new();
    let result = profile.with_execution_authorization(None, |_credential, pending| {
        original = pending.authorization_id.clone();
        assert_eq!(
            profile
                .read_execution_authorization()
                .map_err(ExchangeFailure::BeforeSend)?
                .unwrap()
                .authorization_id,
            original
        );
        assert!(matches!(
            Profile::open(&path)
                .map_err(ExchangeFailure::BeforeSend)?
                .lock_control(),
            Err(ConnectionError::ProfileBusy)
        ));
        Err(ExchangeFailure::AfterWrite(ConnectionError::Unavailable))
    });
    assert!(matches!(
        result,
        Err(AuthorizationFailure::AfterWrite {
            error: ConnectionError::Unavailable,
            ..
        })
    ));
    let alias = temp.path().join("incomplete-ack");
    // Native replacement refusal simulates interruption before the completion
    // update. The sent ID must remain recoverable even after transport success.
    assert!(matches!(
        profile.with_execution_authorization(None, |_credential, pending| {
            assert_eq!(pending.authorization_id, original);
            std::fs::hard_link(profile.root.path().join(PENDING_FILE), &alias).unwrap();
            Ok(receipt(pending))
        }),
        Err(AuthorizationFailure::ReceiptUnsaved(_))
    ));
    std::fs::remove_file(&alias).unwrap();
    assert_eq!(
        profile
            .read_execution_authorization()
            .unwrap()
            .unwrap()
            .state,
        "pending"
    );
    for expected_state in ["pending", "complete"] {
        profile
            .with_execution_authorization(None, |_credential, pending| {
                assert_eq!(pending.authorization_id, original);
                assert_eq!(pending.state, expected_state);
                Ok(receipt(pending))
            })
            .unwrap();
    }
}

#[test]
fn renamed_profile_namespace_cannot_make_an_old_pending_record_sendable() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    let lease = profile.control_lease().unwrap();
    let original = profile
        .begin_execution_authorization(&lease, &active())
        .unwrap();
    // Reads through the retained directory handle still see the prior record.
    // Reusing it for send additionally requires the original namespace barriers.
    std::fs::rename(profile.root.path(), temp.path().join("detached-profile")).unwrap();
    assert_eq!(
        profile
            .read_execution_authorization()
            .unwrap()
            .unwrap()
            .authorization_id,
        original.authorization_id
    );
    assert!(
        profile
            .begin_execution_authorization(&lease, &active())
            .is_err()
    );
}

#[test]
fn caller_holding_the_lease_completes_without_reacquiring_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profile.json");
    let profile = Profile::open(&path).unwrap();
    save_credential(&profile);
    let lease = profile.control_lease().unwrap();
    // A second acquisition by the same holder is refused, so the proof is passed.
    assert!(matches!(
        profile.lock_control(),
        Err(ConnectionError::ProfileBusy)
    ));
    let mut sent = String::new();
    let receipt = profile
        .with_execution_authorization(Some(&lease), |credential, pending| {
            assert_eq!(credential.client_id, pending.client_id);
            sent = pending.authorization_id.clone();
            Ok(receipt(pending))
        })
        .unwrap();
    assert_eq!(receipt.authorization_id, sent);
    let record = profile.read_execution_authorization().unwrap().unwrap();
    assert_eq!(record.state, "complete");
    assert_eq!(record.authorization_id, sent);
    // The caller's lease still covers the profile after the flow returns.
    assert!(matches!(
        Profile::open(&path).unwrap().lock_control(),
        Err(ConnectionError::ProfileBusy)
    ));
}
#[test]
fn a_lease_for_another_profile_handle_cannot_authorize_this_one() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    save_credential(&profile);
    let other = Profile::open(&temp.path().join("other.json")).unwrap();
    let foreign = other.control_lease().unwrap();
    assert!(matches!(
        profile.begin_execution_authorization(&foreign, &active()),
        Err(AuthorizationFailure::BeforeSend(ConnectionError::Conflict))
    ));
    assert!(matches!(
        profile.with_execution_authorization(Some(&foreign), |_, _| unreachable!()),
        Err(AuthorizationFailure::BeforeSend(ConnectionError::Conflict))
    ));
    assert!(profile.read_execution_authorization().unwrap().is_none());
}
#[test]
fn missing_profile_credential_is_refused_before_any_record_write() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    assert!(matches!(
        profile.with_execution_authorization(None, |_, _| unreachable!()),
        Err(AuthorizationFailure::BeforeSend(
            ConnectionError::Unauthorized
        ))
    ));
    assert!(profile.read_execution_authorization().unwrap().is_none());
}

// 2026-11-17 item 7: the proof is bound to the handle, not the directory.
#[test]
fn a_second_handle_to_the_same_profile_directory_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profile.json");
    let profile = Profile::open(&path).unwrap();
    save_credential(&profile);
    let lease = profile.control_lease().unwrap();
    let same_directory = Profile::open(&path).unwrap();
    assert!(matches!(
        same_directory.with_execution_authorization(Some(&lease), |_, _| unreachable!()),
        Err(AuthorizationFailure::BeforeSend(ConnectionError::Conflict))
    ));
    assert!(matches!(
        same_directory.begin_execution_authorization(&lease, &active()),
        Err(AuthorizationFailure::BeforeSend(ConnectionError::Conflict))
    ));
    assert!(profile.read_execution_authorization().unwrap().is_none());
}

// 2026-11-17 confirmed rule D: supersession on credential change.
fn other_client(state: &str) -> ProfileCredential {
    let (installation, _) = ids();
    super::execution_tests::credential(
        &installation,
        &ClientId::parse("cli_66666666666666666666666666666666").unwrap(),
        state,
    )
}
#[test]
fn active_credential_for_another_client_supersedes_and_never_sends_the_old_id() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profile.json");
    let profile = Profile::open(&path).unwrap();
    save_credential(&profile);
    let mut old = String::new();
    profile
        .with_execution_authorization(None, |_, pending| {
            old = pending.authorization_id.clone();
            Err(ExchangeFailure::AfterWrite(ConnectionError::Unavailable))
        })
        .unwrap_err();
    // The profile now holds a different, active credential.
    let replacement = other_client("active");
    profile.save(&replacement).unwrap();
    let mut sent = String::new();
    profile
        .with_execution_authorization(None, |credential, pending| {
            assert_eq!(credential.client_id, replacement.client_id);
            assert_eq!(pending.client_id, replacement.client_id);
            assert_eq!(pending.state, "pending");
            assert_ne!(pending.authorization_id, old);
            // The replacement is already durable before any send.
            let stored = profile
                .read_execution_authorization()
                .map_err(ExchangeFailure::BeforeSend)?
                .unwrap();
            assert_eq!(stored.authorization_id, pending.authorization_id);
            sent = pending.authorization_id.clone();
            Err(ExchangeFailure::AfterWrite(ConnectionError::Unavailable))
        })
        .unwrap_err();
    // A retry keeps the replacement ID; the old one never comes back.
    profile
        .with_execution_authorization(None, |_, pending| {
            assert_eq!(pending.authorization_id, sent);
            Ok(receipt(pending))
        })
        .unwrap();
    let record = profile.read_execution_authorization().unwrap().unwrap();
    assert_eq!(
        (record.state.as_str(), record.authorization_id),
        ("complete", sent)
    );
}
#[test]
fn another_installation_with_an_active_credential_also_supersedes() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    let lease = profile.control_lease().unwrap();
    let old = profile
        .begin_execution_authorization(&lease, &active())
        .unwrap();
    let (_, client) = ids();
    let moved = super::execution_tests::credential(
        &InstallationId::parse("ins_77777777777777777777777777777777").unwrap(),
        &client,
        "active",
    );
    let new = profile
        .begin_execution_authorization(&lease, &moved)
        .unwrap();
    assert_ne!(new.authorization_id, old.authorization_id);
    assert_eq!(new.installation_id, moved.installation_id);
}
#[test]
fn non_active_credential_for_another_client_never_supersedes() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    let lease = profile.control_lease().unwrap();
    let old = profile
        .begin_execution_authorization(&lease, &active())
        .unwrap();
    for state in ["pending", "revoked"] {
        assert!(matches!(
            profile.begin_execution_authorization(&lease, &other_client(state)),
            Err(AuthorizationFailure::BeforeSend(ConnectionError::Conflict))
        ));
        let kept = profile.read_execution_authorization().unwrap().unwrap();
        assert_eq!(kept.authorization_id, old.authorization_id);
        assert_eq!(kept.client_id, old.client_id);
    }
}
#[test]
fn current_client_record_is_kept_pending_or_complete_even_when_revoked() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    let lease = profile.control_lease().unwrap();
    let pending = profile
        .begin_execution_authorization(&lease, &active())
        .unwrap();
    let (installation, client) = ids();
    let revoked = super::execution_tests::credential(&installation, &client, "revoked");
    let kept = profile
        .begin_execution_authorization(&lease, &revoked)
        .unwrap();
    assert_eq!(kept.authorization_id, pending.authorization_id);
    assert_eq!(kept.state, "pending");
    profile
        .complete_execution_authorization(&lease, &receipt(&pending))
        .unwrap();
    let kept = profile
        .begin_execution_authorization(&lease, &revoked)
        .unwrap();
    assert_eq!(kept.authorization_id, pending.authorization_id);
    assert_eq!(kept.state, "complete");
}
