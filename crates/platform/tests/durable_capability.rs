//! Supplementary capability checks do not change the protected recovery tests.
use dissect3d_platform::{OwnedRoot, RootPurpose};

#[test]
fn capability_reports_namespace_support_separately_from_file_availability() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("profile"), RootPurpose::ClientConfig).unwrap();
    // Windows follows the DS-G04 decision (2026-11-23): a private local NTFS
    // root is supported without flushing pre-existing ancestors above it.
    assert_eq!(root.check_durable_mutation_support(), Ok(()));
}

#[cfg(windows)]
#[test]
fn windows_replaced_root_cannot_authorize_a_mutation_through_its_old_handle() {
    // Attribute-only retained handles do not block a rename (observed
    // 2026-11-23); the identity recheck is what refuses the replacement.
    let temp = tempfile::tempdir().unwrap();
    let selected = temp.path().join("profile");
    let root = OwnedRoot::create_private(&selected, RootPurpose::ClientConfig).unwrap();
    let moved = temp.path().join("moved");
    std::fs::rename(&selected, &moved).unwrap();
    let _replacement = OwnedRoot::create_private(&selected, RootPurpose::ClientConfig).unwrap();
    assert_eq!(
        root.check_durable_mutation_support(),
        Err(dissect3d_platform::PlatformError::UnsafeRoot)
    );
    let record = dissect3d_platform::RelativePath::parse("pending.json").unwrap();
    assert!(
        root.write_recovery_record(&record, b"must not publish")
            .is_err()
    );
    assert!(!moved.join("pending.json").exists());
    assert!(!selected.join("pending.json").exists());
}

#[cfg(unix)]
#[test]
fn capability_rechecks_external_namespace_instead_of_trusting_open_root() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("parent");
    let root =
        OwnedRoot::create_private(&parent.join("profile"), RootPurpose::ClientConfig).unwrap();
    assert!(root.check_durable_mutation_support().is_ok());
    let moved = temp.path().join("moved");
    std::fs::rename(&parent, &moved).unwrap();
    symlink(&moved, &parent).unwrap();
    assert!(root.check_durable_mutation_support().is_err());
}

#[cfg(unix)]
#[test]
fn replaced_root_cannot_authorize_a_mutation_through_its_old_handle() {
    let temp = tempfile::tempdir().unwrap();
    let selected = temp.path().join("profile");
    let root = OwnedRoot::create_private(&selected, RootPurpose::ClientConfig).unwrap();
    let moved = temp.path().join("moved");
    std::fs::rename(&selected, &moved).unwrap();
    let _replacement = OwnedRoot::create_private(&selected, RootPurpose::ClientConfig).unwrap();
    assert!(root.check_durable_mutation_support().is_err());
    let record = dissect3d_platform::RelativePath::parse("pending.json").unwrap();
    assert!(
        root.write_recovery_record(&record, b"must not publish")
            .is_err()
    );
    assert!(!moved.join("pending.json").exists());
    assert!(!selected.join("pending.json").exists());
}
