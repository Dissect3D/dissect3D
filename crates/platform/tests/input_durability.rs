use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose};
use std::io::Read;

fn path(value: &str) -> RelativePath {
    RelativePath::parse(value).unwrap()
}

#[cfg(unix)]
#[test]
fn publication_cleanup_rejects_unrelated_files_and_external_hardlinks() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
    let staged = path("inputs/staging/first.part");
    let published = path("inputs/data/first.bin");
    root.write_atomic(&staged, b"staging").unwrap();
    root.write_atomic(&published, b"unrelated").unwrap();
    assert!(root.remove_input_publication(&staged, &published).is_err());
    assert_eq!(root.read_file(&staged, 64).unwrap(), b"staging");
    assert_eq!(root.read_file(&published, 64).unwrap(), b"unrelated");
    root.remove_file(&published).unwrap();
    let external_alias = temp.path().join("alias");
    std::fs::hard_link(root.path_for_native_vfs(&staged), &external_alias).unwrap();
    assert!(root.remove_input_publication(&staged, &published).is_err());
    assert!(external_alias.exists());
    assert!(root.path_for_native_vfs(&staged).exists());
}

#[test]
fn input_writer_exit_child() {
    let Some(root_path) = std::env::var_os("DISSECT3D_INPUT_CRASH_ROOT") else {
        return;
    };
    let root = OwnedRoot::open(std::path::Path::new(&root_path), RootPurpose::EngineData).unwrap();
    let mut writer = root
        .begin_input(&path("inputs/incomplete/crash.part"))
        .unwrap();
    writer.write_chunk(b"process-owned input").unwrap();
    if std::env::var_os("DISSECT3D_INPUT_CRASH_AFTER_PUBLISH").is_some() {
        let _witness = writer.finish(&path("inputs/content/crash.bin")).unwrap();
        std::process::exit(74);
    }
    // Exit without Rust destructors, independently of the parent's handles.
    std::process::exit(73);
}

#[test]
fn process_exit_preserves_incomplete_and_published_orphans_for_reconciliation() {
    for published in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root =
            OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "input_writer_exit_child", "--nocapture"])
            .env("DISSECT3D_INPUT_CRASH_ROOT", root.path())
            .env_remove("DISSECT3D_INPUT_CRASH_AFTER_PUBLISH");
        if published {
            child.env("DISSECT3D_INPUT_CRASH_AFTER_PUBLISH", "1");
        }
        let status = child.status().unwrap();
        assert_eq!(status.code(), Some(if published { 74 } else { 73 }));
        let content = path("inputs/content/crash.bin");
        let incomplete = path("inputs/incomplete/crash.part");
        if published {
            assert_eq!(
                root.read_file(&content, 64).unwrap(),
                b"process-owned input"
            );
            assert!(root.file_metadata(&incomplete).is_err());
        } else {
            assert!(root.file_metadata(&incomplete).is_ok());
            assert!(root.file_metadata(&content).is_err());
        }
    }
}

#[test]
fn streams_and_publishes_without_overwriting_then_reopens_and_deletes() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
    let staged = path("inputs/incomplete/first.part");
    let final_name = path("inputs/content/first.bin");
    let mut writer = root.begin_input(&staged).unwrap();
    writer.write_chunk(b"first ").unwrap();
    writer.write_chunk(b"input").unwrap();
    assert!(root.open_immutable_input(&final_name).is_err());
    assert!(root.begin_input(&staged).is_err());
    let durable = writer.finish(&final_name).unwrap();
    assert_eq!(durable.length(), 11);
    assert!(root.file_metadata(&staged).is_err());
    let mut content = Vec::new();
    root.open_immutable_input(&final_name)
        .unwrap()
        .read_to_end(&mut content)
        .unwrap();
    assert_eq!(content, b"first input");

    let collision = path("inputs/incomplete/second.part");
    let mut writer = root.begin_input(&collision).unwrap();
    writer.write_chunk(b"replacement").unwrap();
    assert!(writer.finish(&final_name).is_err());
    assert_eq!(root.read_file(&final_name, 32).unwrap(), b"first input");
    // Failure keeps uncertain staging for engine-owned accounting and cleanup.
    assert!(root.file_metadata(&collision).is_ok());
    root.remove_durable(&collision).unwrap();
    root.remove_durable(&final_name).unwrap();
    root.remove_durable(&final_name).unwrap();
    assert!(root.open_immutable_input(&final_name).is_err());
}

#[test]
fn abandoned_writer_keeps_its_private_staging_file() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
    let staged = path("inputs/incomplete/abandoned.part");
    let mut writer = root.begin_input(&staged).unwrap();
    writer.write_chunk(b"partial").unwrap();
    drop(writer);
    assert_eq!(root.file_metadata(&staged).unwrap().length, 7);
    root.remove_durable(&staged).unwrap();
}

#[test]
fn scan_retains_a_bounded_cursor_and_names_never_bypass_file_validation() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
    for index in 0..70 {
        drop(
            root.begin_input(&path(&format!("inputs/incomplete/{index}.part")))
                .unwrap(),
        );
    }
    let mut scan = root.scan_owned_inputs(&path("inputs/incomplete")).unwrap();
    assert!(scan.next_batch(65).is_err());
    let mut names = std::collections::BTreeSet::new();
    loop {
        let batch = scan.next_batch(7).unwrap();
        assert!(batch.entries.len() + batch.rejected_entries <= 7);
        assert_eq!(batch.rejected_entries, 0);
        for entry in batch.entries {
            assert!(names.insert(root.path_for_native_vfs(&entry)));
            assert!(root.open_immutable_input(&entry).is_ok());
        }
        if batch.exhausted {
            break;
        }
    }
    assert_eq!(names.len(), 70);
    assert!(scan.next_batch(7).unwrap().exhausted);
}

#[test]
fn hardlink_aliases_cannot_be_read_or_finalized() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
    let staged = path("inputs/incomplete/alias.part");
    let final_name = path("inputs/content/alias.bin");
    let mut writer = root.begin_input(&staged).unwrap();
    writer.write_chunk(b"private").unwrap();
    std::fs::hard_link(
        root.path().join("inputs/incomplete/alias.part"),
        root.path().join("alias"),
    )
    .unwrap();
    assert!(writer.finish(&final_name).is_err());
    assert!(root.open_immutable_input(&staged).is_err());
    assert!(!root.path().join("inputs/content/alias.bin").exists());
}

#[cfg(unix)]
#[test]
fn symlinks_and_fifo_sources_never_grant_file_authority() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
    let outside = temp.path().join("outside");
    std::fs::write(&outside, b"outside").unwrap();
    symlink(&outside, root.path().join("link")).unwrap();
    assert!(root.begin_input(&path("link")).is_err());
    assert!(root.open_immutable_input(&path("link")).is_err());
    assert!(root.remove_durable(&path("link")).is_err());
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        root.path().join("fifo"),
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    assert!(root.open_immutable_input(&path("fifo")).is_err());
    assert_eq!(std::fs::read(outside).unwrap(), b"outside");
}
