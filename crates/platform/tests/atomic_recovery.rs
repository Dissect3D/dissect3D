use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose};

#[test]
fn staging_recovery_child() {
    let Some(path) = std::env::var_os("DISSECT3D_STAGING_PROBE") else {
        return;
    };
    let root = OwnedRoot::open(path.as_ref(), RootPurpose::ClientConfig).unwrap();
    let leftover = root
        .path()
        .join(format!(".d3d-tmp-{}-0", std::process::id()));
    std::fs::write(&leftover, b"preserve interrupted write").unwrap();
    root.write_atomic(
        &RelativePath::parse("credential.json").unwrap(),
        b"new complete record",
    )
    .unwrap();
    assert_eq!(
        std::fs::read(leftover).unwrap(),
        b"preserve interrupted write"
    );
}

#[test]
fn leftover_staging_files_do_not_block_or_get_deleted_by_a_new_write() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::ClientConfig).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "staging_recovery_child"])
        .env("DISSECT3D_STAGING_PROBE", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
