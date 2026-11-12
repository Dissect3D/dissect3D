#[test]
fn recovery_authorization_denial_does_not_disprove_prior_acceptance() {
    use dissect3d_api::ErrorCode;
    let c = control();
    c.recovering_unknown();
    c.rejected_by(ErrorCode::Unauthorized);
    let error = c.preserve_known(super::super::failure(
        "unauthorized",
        "denied",
        4,
        Some(false),
        None,
    ));
    assert_eq!(
        error.context.unwrap().accepted,
        Some(serde_json::Value::Null)
    );
    assert_eq!(c.interrupt_outcome().err().unwrap().exit_code, 15);
    c.rejected_by(ErrorCode::InputUnavailable);
    let error = c.interrupt_outcome().err().unwrap();
    assert_eq!(error.exit_code, 19);
    assert_eq!(
        error.context.unwrap().accepted,
        Some(serde_json::Value::Bool(false))
    );
}

#[test]
fn recovery_capacity_and_storage_failures_preserve_prior_uncertainty() {
    use dissect3d_api::ErrorCode;
    for code in [
        ErrorCode::CapacityExceeded,
        ErrorCode::StoreUnavailable,
        ErrorCode::PersistenceUnavailable,
        ErrorCode::StorageUnavailable,
        ErrorCode::EngineRecovering,
    ] {
        let c = control();
        c.recovering_unknown();
        c.rejected_by(code);
        let error = c.preserve_known(super::super::rejected_error(code, None));
        assert_eq!(
            error.context.unwrap().accepted,
            Some(serde_json::Value::Null),
            "{code:?}"
        );
        assert_eq!(c.interrupt_outcome().err().unwrap().exit_code, 15);
    }
    let c = control();
    c.recovering_unknown();
    c.rejected_by(ErrorCode::IdempotencyConflict);
    assert_eq!(c.interrupt_outcome().err().unwrap().exit_code, 19);
}
