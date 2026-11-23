//! Barrier-order tests for the Windows namespace-durability protocol
//! (DS-G04 decision 2026-11-23). Each assertion names the exact barriers so
//! disabling one barrier, or adding an external-ancestor flush, fails a test.
use super::*;
use crate::RootPurpose;
use std::path::{Path, PathBuf};

fn name(value: &str) -> RelativePath {
    RelativePath::parse(value).unwrap()
}

fn root_at(temp: &tempfile::TempDir) -> OwnedRoot {
    OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData).unwrap()
}

fn publish(root: &OwnedRoot, staged: &str, published: &str, bytes: &[u8]) {
    let mut writer = root.begin_input(&name(staged)).unwrap();
    writer.write_chunk(bytes).unwrap();
    writer.finish(&name(published)).unwrap();
}

fn under(root: &OwnedRoot, relative: &str) -> PathBuf {
    let mut path = root.path().to_path_buf();
    path.extend(relative.split('/').filter(|part| !part.is_empty()));
    path
}

fn assert_only_owned(root: &OwnedRoot, barriers: &[Barrier]) {
    for barrier in barriers {
        let path = match barrier {
            Barrier::File(path)
            | Barrier::Directory(path)
            | Barrier::RootIdentity(path)
            | Barrier::Publish(path) => path,
            Barrier::ExternalParent { .. } => panic!("external ancestor touched: {barrier:?}"),
        };
        let path = path.to_string_lossy();
        let path = path.strip_prefix(r"\\?\").unwrap_or(&path);
        assert!(
            Path::new(path).starts_with(root.path()),
            "barrier outside the engine root: {barrier:?}"
        );
    }
}

#[test]
fn preflight_verifies_identity_then_flushes_only_the_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    take_barriers();
    root.check_durable_mutation_support().unwrap();
    assert_eq!(
        take_barriers(),
        vec![
            Barrier::RootIdentity(root.path().to_path_buf()),
            Barrier::Directory(root.path().to_path_buf()),
        ]
    );
}

#[test]
fn publication_flushes_data_before_publish_then_both_owned_chains_and_rechecks_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    // Warm-up creates both directories so only publication barriers remain.
    publish(
        &root,
        "inputs/staging/warm.part",
        "inputs/data/warm.bin",
        b"w",
    );
    let mut writer = root.begin_input(&name("inputs/staging/a.part")).unwrap();
    writer.write_chunk(b"bytes").unwrap();
    take_barriers();
    writer.finish(&name("inputs/data/a.bin")).unwrap();
    let barriers = take_barriers();
    assert_eq!(
        barriers,
        vec![
            Barrier::File(under(&root, "inputs/staging/a.part")),
            Barrier::Publish(under(&root, "inputs/data/a.bin")),
            Barrier::File(under(&root, "inputs/data/a.bin")),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "inputs")),
            Barrier::Directory(under(&root, "inputs/data")),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "inputs")),
            Barrier::Directory(under(&root, "inputs/staging")),
            Barrier::RootIdentity(root.path().to_path_buf()),
        ]
    );
    assert_only_owned(&root, &barriers);
}

#[test]
fn newly_created_directories_and_their_owned_parents_are_flushed_before_use() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    take_barriers();
    let writer = root.begin_input(&name("a/b/c.part")).unwrap();
    let barriers = take_barriers();
    assert_eq!(
        barriers,
        vec![
            Barrier::RootIdentity(root.path().to_path_buf()),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "a")),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "a/b")),
            Barrier::Directory(under(&root, "a")),
        ]
    );
    drop(writer);
}

#[test]
fn root_creation_flushes_its_writable_external_parent_exactly_once() {
    let temp = tempfile::tempdir().unwrap();
    take_barriers();
    let path = temp.path().join("a").join("engine");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).unwrap();
    let barriers = take_barriers();
    assert_eq!(
        barriers,
        vec![
            Barrier::Directory(temp.path().join("a")),
            Barrier::ExternalParent {
                path: temp.path().to_path_buf(),
                flushed: true,
            },
            Barrier::Directory(path.clone()),
            Barrier::Directory(temp.path().join("a")),
        ]
    );
    drop(root);
    OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
    OwnedRoot::create_private(&path, RootPurpose::EngineData).unwrap();
    assert_eq!(take_barriers(), Vec::new(), "reopen flushes nothing");
}

#[test]
fn a_protected_external_parent_is_skipped_rather_than_failing_the_root() {
    // Standard users receive ERROR_ACCESS_DENIED opening `C:\` for writing
    // (the 2026-11-06 full-chain finding). That is not a failed barrier.
    take_barriers();
    assert_eq!(flush_external_parent_if_writable(Path::new(r"C:\")), Ok(()));
    let barriers = take_barriers();
    assert_eq!(barriers.len(), 1);
    assert!(matches!(
        &barriers[0],
        Barrier::ExternalParent { path, .. } if path == Path::new(r"C:\")
    ));
}

#[test]
fn recovery_record_flushes_file_then_owned_chain_then_rechecks_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    root.write_recovery_record(&name("submissions/warm.json"), b"w")
        .unwrap();
    take_barriers();
    root.write_recovery_record(&name("submissions/r.json"), b"record")
        .unwrap();
    let barriers = take_barriers();
    assert_eq!(
        barriers,
        vec![
            Barrier::RootIdentity(root.path().to_path_buf()),
            Barrier::Directory(under(&root, "")),
            Barrier::File(under(&root, "submissions/r.json")),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "submissions")),
            Barrier::RootIdentity(root.path().to_path_buf()),
        ]
    );
    assert_only_owned(&root, &barriers);
}

#[test]
fn durable_removal_flushes_the_owned_chain_after_deleting() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    publish(&root, "inputs/staging/a.part", "inputs/data/a.bin", b"a");
    take_barriers();
    root.remove_durable(&name("inputs/data/a.bin")).unwrap();
    let barriers = take_barriers();
    assert_eq!(
        barriers,
        vec![
            Barrier::RootIdentity(root.path().to_path_buf()),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "inputs")),
            Barrier::Directory(under(&root, "inputs/data")),
            Barrier::RootIdentity(root.path().to_path_buf()),
        ]
    );
}

#[test]
fn quarantine_flushes_source_and_destination_chains() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    publish(&root, "inputs/staging/a.part", "inputs/data/a.bin", b"a");
    root.ensure_private_directory(&name("inputs/quarantine"))
        .unwrap();
    take_barriers();
    root.quarantine_owned_entry(
        &name("inputs/data"),
        std::ffi::OsStr::new("a.bin"),
        &name("inputs/quarantine/q_1"),
    )
    .unwrap();
    let barriers = take_barriers();
    let target = format!(r"\\?\{}", under(&root, "inputs/quarantine/q_1").display());
    assert_eq!(
        barriers,
        vec![
            Barrier::RootIdentity(root.path().to_path_buf()),
            Barrier::Directory(under(&root, "")),
            Barrier::Publish(PathBuf::from(target)),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "inputs")),
            Barrier::Directory(under(&root, "inputs/data")),
            Barrier::Directory(under(&root, "")),
            Barrier::Directory(under(&root, "inputs")),
            Barrier::Directory(under(&root, "inputs/quarantine")),
            Barrier::RootIdentity(root.path().to_path_buf()),
        ]
    );
}

#[test]
fn quarantine_opens_reserved_and_trailing_dot_names_verbatim() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    root.ensure_private_directory(&name("inputs/data")).unwrap();
    let data = verbatim(&under(&root, "inputs/data")).unwrap();
    for entry in ["CON", "trailing."] {
        std::fs::write(data.join(entry), b"planted").unwrap();
        let destination = name(&format!("inputs/quarantine/q_{}", entry.len()));
        root.quarantine_owned_entry(
            &name("inputs/data"),
            std::ffi::OsStr::new(entry),
            &destination,
        )
        .unwrap();
        assert!(!data.join(entry).exists());
        assert_eq!(root.read_file(&destination, 16).unwrap(), b"planted");
    }
}

#[test]
fn a_different_retained_root_is_refused_even_with_a_valid_path() {
    let temp = tempfile::tempdir().unwrap();
    let first =
        OwnedRoot::create_private(&temp.path().join("one"), RootPurpose::EngineData).unwrap();
    let second =
        OwnedRoot::create_private(&temp.path().join("two"), RootPurpose::EngineData).unwrap();
    assert!(verify_root_identity_against(first.path(), first.windows_root_handle()).is_ok());
    assert_eq!(
        verify_root_identity_against(first.path(), second.windows_root_handle()).err(),
        Some(PlatformError::UnsafeRoot)
    );
}

#[test]
fn only_ntfs_is_a_supported_filesystem_name() {
    let wide = |value: &str| value.encode_utf16().chain([0, 0]).collect::<Vec<_>>();
    assert!(supported_filesystem_name(&wide("NTFS")));
    assert!(supported_filesystem_name(&wide("ntfs")));
    for name in ["ReFS", "FAT", "FAT32", "exFAT", "CSVFS", "UDF", "NTFS2", ""] {
        assert!(!supported_filesystem_name(&wide(name)), "{name}");
    }
}

#[test]
fn sync_root_status_fails_closed_except_for_the_recorded_codes() {
    // DS-G04 (2026-11-23) records exactly these "not a sync root" results:
    // ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT and ERROR_INVALID_FUNCTION.
    assert_eq!(NOT_A_SYNC_ROOT, [390, 1]);
    for status in [0x8007_0186_u32 as i32, 0x8007_0001_u32 as i32] {
        assert_eq!(classify_sync_root_status(status), Ok(()), "{status:#x}");
    }
    for status in [
        0,
        1,
        0x8007_0002_u32 as i32,
        0x8007_0005_u32 as i32,
        0x8007_0032_u32 as i32,
        0x8000_4005_u32 as i32,
    ] {
        assert_eq!(
            classify_sync_root_status(status),
            Err(PlatformError::UnsupportedRoot),
            "{status:#x}"
        );
    }
}

#[test]
fn a_root_below_a_registered_sync_root_is_refused_before_creation() {
    let Ok(profile) = std::env::var("USERPROFILE") else {
        return;
    };
    let mut exercised = false;
    for provider in ["Box", "OneDrive"] {
        let folder = Path::new(&profile).join(provider);
        if folder.is_dir() {
            exercised = true;
            let candidate = folder.join("dissect3d-never-created").join("engine");
            assert_eq!(
                validate_filesystem(&candidate),
                Err(PlatformError::UnsupportedRoot),
                "{provider}"
            );
            assert!(!folder.join("dissect3d-never-created").exists());
        }
    }
    if !exercised {
        eprintln!("NOT EXERCISED: no registered sync root folder present");
    }
}

#[test]
fn not_found_means_an_absent_entry_only_while_the_root_is_in_place() {
    let temp = tempfile::tempdir().unwrap();
    let root = root_at(&temp);
    assert_eq!(
        confirm_absent(&root, Err::<(), _>(PlatformError::NotFound)),
        Err(PlatformError::NotFound)
    );
    assert_eq!(confirm_absent(&root, Ok(7)), Ok(7));
    fs::rename(root.path(), temp.path().join("moved")).unwrap();
    assert_eq!(
        confirm_absent(&root, Err::<(), _>(PlatformError::NotFound)),
        Err(PlatformError::UnsafeRoot)
    );
    // Other failures pass through unchanged.
    assert_eq!(
        confirm_absent(&root, Err::<(), _>(PlatformError::Io)),
        Err(PlatformError::Io)
    );
}
