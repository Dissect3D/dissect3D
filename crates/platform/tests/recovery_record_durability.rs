//! Native recovery-record guarantees; process exit is not physical power loss.

use dissect3d_platform::{OwnedRoot, PlatformError, RelativePath, RootPurpose};

#[test]
fn recovery_records_reject_out_of_budget_bytes_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("profile"), RootPurpose::ClientConfig).unwrap();
    let path = RelativePath::parse("submissions/record.json").unwrap();
    for bytes in [Vec::new(), vec![b'x'; 1_048_577]] {
        assert_eq!(
            root.write_recovery_record(&path, &bytes),
            Err(PlatformError::InvalidFile)
        );
        assert_eq!(root.file_metadata(&path), Err(PlatformError::NotFound));
    }
}

#[cfg(windows)]
#[test]
fn unresolved_windows_namespace_barrier_never_publishes_a_recovery_record() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("profile"), RootPurpose::ClientConfig).unwrap();
    let path = RelativePath::parse("submissions/record.json").unwrap();
    assert_eq!(
        root.write_recovery_record(&path, b"pending"),
        Err(PlatformError::UnsupportedRoot)
    );
    assert_eq!(root.file_metadata(&path), Err(PlatformError::NotFound));
}

#[cfg(unix)]
#[test]
fn native_record_publication_survives_writer_process_exit() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().join("profile");
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_recovery_record_writer_helper",
            "--nocapture",
        ])
        .env("DISSECT3D_RECOVERY_TEST_ROOT", &root_path)
        .status()
        .unwrap();
    assert!(status.success());
    let root = OwnedRoot::open(&root_path, RootPurpose::ClientConfig).unwrap();
    let path = RelativePath::parse("submissions/record.json").unwrap();
    assert_eq!(
        root.read_file(&path, 1_048_576).unwrap(),
        vec![b'x'; 1_048_576]
    );
}

#[cfg(unix)]
#[test]
fn native_recovery_record_writer_helper() {
    let Some(path) = std::env::var_os("DISSECT3D_RECOVERY_TEST_ROOT") else {
        return;
    };
    let root =
        OwnedRoot::create_private(std::path::Path::new(&path), RootPurpose::ClientConfig).unwrap();
    root.write_recovery_record(
        &RelativePath::parse("submissions/record.json").unwrap(),
        &vec![b'x'; 1_048_576],
    )
    .unwrap();
    std::process::exit(0);
}

#[cfg(unix)]
#[test]
fn record_links_never_authorize_replacement() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("profile"), RootPurpose::ClientConfig).unwrap();
    let path = RelativePath::parse("submissions/record.json").unwrap();
    root.write_recovery_record(&path, b"original").unwrap();
    let alias = temp.path().join("outside-alias");
    std::fs::hard_link(root.path().join(path.as_str()), &alias).unwrap();
    assert!(root.write_recovery_record(&path, b"replacement").is_err());
    assert_eq!(std::fs::read(&alias).unwrap(), b"original");
    std::fs::remove_file(&alias).unwrap();
    symlink(root.path().join("submissions"), root.path().join("alias")).unwrap();
    assert!(
        root.write_recovery_record(&RelativePath::parse("alias/other.json").unwrap(), b"unsafe")
            .is_err()
    );
}
