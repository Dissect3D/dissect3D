use dissect3d_platform::{OwnedRoot, RootPurpose};
use tempfile::tempdir;

#[test]
fn protected_root_reports_user_available_filesystem_space() {
    let parent = tempdir().expect("temporary parent");
    let root_path = parent.path().join("engine-root");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    assert!(root.available_space_bytes().expect("available space") > 0);
}
