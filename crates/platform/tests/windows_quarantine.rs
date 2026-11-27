//! Windows quarantine moves one direct child without following or opening it.
#![cfg_attr(
    windows,
    expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup"
    )
)]
#![cfg(windows)]

use dissect3d_platform::{OwnedRoot, PlatformError, RelativePath, RootPurpose};
use std::ffi::OsStr;
use std::fs;
use tempfile::TempDir;

fn name(value: &str) -> RelativePath {
    RelativePath::parse(value).unwrap()
}

fn engine_root() -> (TempDir, OwnedRoot) {
    let temp = TempDir::new().unwrap();
    let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
        .expect("private NTFS root");
    (temp, root)
}

fn seed(root: &OwnedRoot, relative: &str, bytes: &[u8]) {
    let mut writer = root
        .begin_input(&name(&format!("seed/{}.part", relative.replace('/', "_"))))
        .unwrap();
    writer.write_chunk(bytes).unwrap();
    writer.finish(&name(relative)).unwrap();
}

#[test]
fn quarantine_moves_a_regular_file_into_its_feature_quarantine() {
    let (_temp, root) = engine_root();
    seed(&root, "results/objects/art_orphan", b"orphan");
    root.quarantine_owned_entry(
        &name("results/objects"),
        OsStr::new("art_orphan"),
        &name("results/quarantine/q_1"),
    )
    .unwrap();
    assert_eq!(
        root.file_metadata(&name("results/objects/art_orphan")),
        Err(PlatformError::NotFound)
    );
    assert_eq!(
        root.read_file(&name("results/quarantine/q_1"), 64).unwrap(),
        b"orphan"
    );
}

#[test]
fn quarantine_moves_links_and_directories_without_following_them() {
    let (temp, root) = engine_root();
    seed(&root, "inputs/data/keep.bin", b"keep");
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("victim.txt"), b"victim").unwrap();
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.path().join("inputs").join("data").join("planted"))
        .arg(&outside)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "junction creation: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::create_dir(root.path().join("inputs/data/folder")).unwrap();
    for (entry, destination) in [
        ("planted", "inputs/quarantine/q_link"),
        ("folder", "inputs/quarantine/q_dir"),
    ] {
        root.quarantine_owned_entry(&name("inputs/data"), OsStr::new(entry), &name(destination))
            .unwrap();
        assert!(!root.path().join("inputs/data").join(entry).exists());
    }
    // The junction itself moved; its target and contents are untouched.
    let moved = root.path().join("inputs/quarantine/q_link");
    assert!(
        fs::symlink_metadata(&moved)
            .unwrap()
            .file_type()
            .is_symlink()
            || fs::symlink_metadata(&moved).unwrap().is_dir()
    );
    assert_eq!(fs::read(outside.join("victim.txt")).unwrap(), b"victim");
    assert!(outside.join("victim.txt").exists());
    assert_eq!(
        root.read_file(&name("inputs/data/keep.bin"), 64).unwrap(),
        b"keep"
    );
}

#[test]
fn quarantine_refuses_existing_destinations_and_foreign_targets() {
    let (_temp, root) = engine_root();
    seed(&root, "inputs/staging/a.part", b"a");
    seed(&root, "inputs/quarantine/q_taken", b"taken");
    assert_eq!(
        root.quarantine_owned_entry(
            &name("inputs/staging"),
            OsStr::new("a.part"),
            &name("inputs/quarantine/q_taken"),
        ),
        Err(PlatformError::Busy)
    );
    assert_eq!(
        root.read_file(&name("inputs/quarantine/q_taken"), 64)
            .unwrap(),
        b"taken"
    );
    for (source, entry, destination) in [
        ("inputs/staging", "a.part", "results/quarantine/q_x"),
        ("results/objects", "a.part", "inputs/quarantine/q_x"),
        ("seed", "a.part", "inputs/quarantine/q_x"),
        ("inputs/staging", "..", "inputs/quarantine/q_x"),
        ("inputs/staging", "a\\b", "inputs/quarantine/q_x"),
        ("inputs/staging", "a.part:stream", "inputs/quarantine/q_x"),
        ("inputs/staging", "", "inputs/quarantine/q_x"),
    ] {
        assert_eq!(
            root.quarantine_owned_entry(&name(source), OsStr::new(entry), &name(destination)),
            Err(PlatformError::InvalidPath),
            "{source} {entry} {destination}"
        );
    }
    assert_eq!(
        root.read_file(&name("inputs/staging/a.part"), 64).unwrap(),
        b"a"
    );
    assert_eq!(
        root.quarantine_owned_entry(
            &name("inputs/staging"),
            OsStr::new("missing"),
            &name("inputs/quarantine/q_m"),
        ),
        Err(PlatformError::NotFound)
    );
}
