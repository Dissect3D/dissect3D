use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::fs::symlink_dir;

use dissect3d_platform::{OwnedRoot, PlatformError, RelativePath, RootPurpose};
use tempfile::TempDir;

#[test]
fn creates_private_root_and_round_trips_unicode_relative_files() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("mesh cache 日本語");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private root creation");
    assert_eq!(root.path(), root_path);
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let name = RelativePath::parse("run/endpoint café.json").expect("valid relative path");
    root.write_atomic(&name, b"safe descriptor")
        .expect("atomic write");
    assert_eq!(
        root.read_file(&name, 128).expect("bounded read"),
        b"safe descriptor"
    );
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(root_path.join("run/endpoint café.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn removes_only_a_validated_owned_regular_file() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("private");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::ClientConfig)
        .expect("private profile root");
    let path = RelativePath::parse("pending-stop.json").expect("fixed profile file");
    root.write_atomic(&path, b"{}").expect("write owned file");
    root.remove_file(&path).expect("remove owned file");
    assert_eq!(root.read_file(&path, 16), Err(PlatformError::NotFound));
}

#[test]
#[cfg(unix)]
fn refuses_overbroad_existing_root_without_changing_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("too open");
    fs::create_dir(&root_path).expect("create fixture");
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755))
        .expect("set unsafe permissions");

    assert!(matches!(
        OwnedRoot::open(&root_path, RootPurpose::EngineData),
        Err(PlatformError::UnsafeRoot)
    ));
    assert_eq!(
        fs::metadata(root_path).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
#[cfg(unix)]
fn rejects_symlink_root_and_refuses_to_replace_a_symlink_target() {
    use std::os::unix::fs::symlink;

    let parent = TempDir::new().expect("temporary parent");
    let real = parent.path().join("real");
    let root =
        OwnedRoot::create_private(&real, RootPurpose::EngineData).expect("private root creation");
    let redirected = parent.path().join("redirected");
    symlink(&real, &redirected).expect("root symlink");
    assert!(OwnedRoot::open(&redirected, RootPurpose::EngineData).is_err());

    let outside = parent.path().join("outside.txt");
    fs::write(&outside, b"keep outside bytes").expect("outside content");
    symlink(&outside, real.join("endpoint.json")).expect("file symlink");
    let name = RelativePath::parse("endpoint.json").expect("valid file path");
    assert!(root.write_atomic(&name, b"replacement").is_err());
    assert_eq!(fs::read(outside).unwrap(), b"keep outside bytes");
}

#[cfg(windows)]
#[test]
fn rejects_reparse_root_and_refuses_to_replace_a_reparse_target() {
    let parent = TempDir::new().expect("temporary parent");
    let real = parent.path().join("real");
    let root =
        OwnedRoot::create_private(&real, RootPurpose::EngineData).expect("private root creation");
    let redirected = parent.path().join("redirected");
    if let Err(error) = symlink_dir(&real, &redirected) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("skipping reparse-point test: directory symlink privilege unavailable");
            return;
        }
        panic!("create test symlink: {error}");
    }
    assert!(matches!(
        OwnedRoot::open(&redirected, RootPurpose::EngineData),
        Err(PlatformError::UnsafeRoot)
    ));

    let outside = parent.path().join("outside.txt");
    fs::write(&outside, b"keep outside bytes").expect("outside content");
    let endpoint = real.join("endpoint.json");
    if let Err(error) = std::os::windows::fs::symlink_file(&outside, &endpoint) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("skipping file reparse check: symlink privilege unavailable");
            return;
        }
        panic!("create test file symlink: {error}");
    }
    let name = RelativePath::parse("endpoint.json").expect("valid relative file");
    assert!(root.write_atomic(&name, b"replacement").is_err());
    assert_eq!(fs::read(outside).unwrap(), b"keep outside bytes");
}

#[cfg(windows)]
#[test]
fn refuses_an_inherited_directory_acl_without_replacing_the_directory() {
    let parent = TempDir::new().expect("temporary parent");
    let path = parent.path().join("inherited permissions");
    fs::create_dir(&path).expect("create ordinary inherited directory");

    assert!(matches!(
        OwnedRoot::open(&path, RootPurpose::EngineData),
        Err(PlatformError::UnsafeRoot)
    ));
    assert!(
        path.is_dir(),
        "refusal must leave the selected directory in place"
    );
}

#[test]
fn rejects_relative_alias_components() {
    assert!(RelativePath::parse("run/../metadata.sqlite3").is_err());
    assert!(RelativePath::parse("run//endpoint.json").is_err());
    assert!(RelativePath::parse("C:\\data\\engine").is_err());
    assert!(RelativePath::parse("CON").is_err());
    assert!(RelativePath::parse("assets/nul.txt").is_err());
    assert!(RelativePath::parse("assets/trailing.").is_err());
}

#[cfg(windows)]
#[test]
fn rejects_known_sync_roots_before_creating_them() {
    let Ok(profile) = std::env::var("USERPROFILE") else {
        return;
    };
    let path = std::path::PathBuf::from(profile)
        .join("OneDrive - Dissect3D test")
        .join("new root");
    assert!(matches!(
        OwnedRoot::create_private(&path, RootPurpose::EngineData),
        Err(PlatformError::UnsupportedRoot)
    ));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn rejects_known_sync_roots_before_creating_them() {
    let home = std::env::var_os("HOME").expect("home directory");
    let path = std::path::PathBuf::from(home)
        .join("Dropbox")
        .join("Dissect3D test root");
    assert!(matches!(
        OwnedRoot::create_private(&path, RootPurpose::EngineData),
        Err(PlatformError::UnsupportedRoot)
    ));
    assert!(!path.exists());
}
