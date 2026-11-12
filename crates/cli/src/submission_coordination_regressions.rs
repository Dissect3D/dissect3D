#[cfg(unix)]
#[test]
fn record_coordination_is_independent_and_never_allocates_for_missing_records() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    let record = pending();
    let records = SubmissionRecords::lock(&profile).unwrap();
    assert!(matches!(
        records.coordinate(&record),
        Err(RecordError::Missing)
    ));
    assert!(!profile.root().path().join("submission-locks").exists());
    records.save_new(&record).unwrap();
    let first = records.coordinate(&record).unwrap();
    assert!(matches!(
        records.coordinate(&record),
        Err(RecordError::RecordBusy)
    ));
    let mut second = record.clone();
    second.sub_id = SubmissionId::parse(format!("sub_{}", "4".repeat(32))).unwrap();
    records.save_new(&second).unwrap();
    let independent = records.coordinate(&second).unwrap();
    drop(records);
    assert!(
        profile.lock_control().is_ok(),
        "record ownership cannot hold profile coordination"
    );
    let records = SubmissionRecords::lock(&profile).unwrap();
    assert_eq!(records.scan().unwrap().0.len(), 2);
    assert!(records.save_new(&record).is_err());
    let mut altered = record.clone();
    altered.key = IdempotencyKey::parse("replacement-key").unwrap();
    assert!(matches!(
        records.coordinate(&altered),
        Err(RecordError::Invalid)
    ));
    drop(first);
    let recovered = records.coordinate(&record).unwrap();
    let locks = profile.root().path().join("submission-locks");
    assert_eq!(
        std::fs::read_dir(locks).unwrap().count(),
        2,
        "one permanent zero-length lock per published record"
    );
    drop((recovered, independent));
}
