//! Windows namespace-durability protocol (DS-G04 decision 2026-11-23).
//!
//! Process exit and handle reopen are exercised here; physical power loss is a
//! separate open gate and is never implied by these tests.
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
use std::fs;
use std::io::Read;
use std::path::Path;
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

fn junction(link: &Path, target: &Path) {
    // Junctions need no privilege, so these refusals always run.
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "junction creation: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn staged_names(directory: &Path) -> Vec<String> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|entry| entry.starts_with(".d3d-tmp-"))
        .collect()
}

#[test]
fn private_ntfs_root_supports_durable_mutation() {
    let (_temp, root) = engine_root();
    assert_eq!(root.check_durable_mutation_support(), Ok(()));
}

#[test]
fn recovery_record_is_published_reopened_and_leaves_no_staged_name() {
    let temp = TempDir::new().unwrap();
    let root_path = temp.path().join("profile");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "windows_recovery_record_writer_helper",
            "--nocapture",
        ])
        .env("DISSECT3D_WINDOWS_RECORD_ROOT", &root_path)
        .status()
        .unwrap();
    assert!(status.success());
    let root = OwnedRoot::open(&root_path, RootPurpose::ClientConfig).unwrap();
    let path = name("submissions/record.json");
    assert_eq!(
        root.read_file(&path, 1_048_576).unwrap(),
        vec![b'x'; 1_048_576]
    );
    assert!(staged_names(&root_path.join("submissions")).is_empty());
}

#[test]
fn windows_recovery_record_writer_helper() {
    let Some(path) = std::env::var_os("DISSECT3D_WINDOWS_RECORD_ROOT") else {
        return;
    };
    let root = OwnedRoot::create_private(Path::new(&path), RootPurpose::ClientConfig).unwrap();
    root.write_recovery_record(&name("submissions/record.json"), &vec![b'x'; 1_048_576])
        .unwrap();
    std::process::exit(0);
}

#[test]
fn recovery_record_update_replaces_only_a_private_single_link_record() {
    let (temp, root) = engine_root();
    let path = name("submissions/record.json");
    root.write_recovery_record(&path, b"original").unwrap();
    root.write_recovery_record(&path, b"updated").unwrap();
    assert_eq!(root.read_file(&path, 64).unwrap(), b"updated");
    let alias = temp.path().join("outside-alias");
    fs::hard_link(root.path().join("submissions/record.json"), &alias).unwrap();
    assert!(root.write_recovery_record(&path, b"replacement").is_err());
    assert_eq!(fs::read(&alias).unwrap(), b"updated");
    assert!(staged_names(&root.path().join("submissions")).is_empty());
}

#[test]
fn input_begin_finish_reopen_and_durable_removal() {
    let (_temp, root) = engine_root();
    let staged = name("inputs/staging/one.part");
    let published = name("inputs/data/one.bin");
    let mut writer = root.begin_input(&staged).unwrap();
    writer.write_chunk(b"captured input bytes").unwrap();
    let durable = writer.finish(&published).unwrap();
    assert_eq!(durable.length(), 20);
    assert_eq!(root.file_metadata(&staged), Err(PlatformError::NotFound));
    drop(root);
    let root = OwnedRoot::open(&_temp.path().join("engine"), RootPurpose::EngineData).unwrap();
    let mut bytes = Vec::new();
    root.open_immutable_input(&published)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"captured input bytes");
    root.remove_durable(&published).unwrap();
    assert_eq!(root.file_metadata(&published), Err(PlatformError::NotFound));
    // Repeated removal of an absent name still completes its barriers.
    root.remove_durable(&published).unwrap();
}

#[test]
fn input_publication_never_overwrites_an_existing_name() {
    let (_temp, root) = engine_root();
    let published = name("inputs/data/taken.bin");
    let mut first = root.begin_input(&name("inputs/staging/a.part")).unwrap();
    first.write_chunk(b"first").unwrap();
    first.finish(&published).unwrap();
    let staged = name("inputs/staging/b.part");
    let mut second = root.begin_input(&staged).unwrap();
    second.write_chunk(b"second").unwrap();
    assert!(second.finish(&published).is_err());
    assert_eq!(root.read_file(&published, 64).unwrap(), b"first");
    assert_eq!(root.read_file(&staged, 64).unwrap(), b"second");
}

#[test]
fn prepared_artifact_reads_back_through_a_fresh_no_follow_handle() {
    let (_temp, root) = engine_root();
    let bytes = (0..200_000_u32).map(|i| i as u8).collect::<Vec<_>>();
    let staging = name("results/staging/art_one.part");
    let published = name("results/objects/art_one");
    let artifact = root.prepare_artifact(&staging, &published, &bytes).unwrap();
    assert_eq!(artifact.length(), bytes.len() as u64);
    assert_eq!(artifact.relative_path(), &published);
    assert_eq!(root.file_metadata(&staging), Err(PlatformError::NotFound));
    let mut read = Vec::new();
    root.open_immutable_input(&published)
        .unwrap()
        .read_to_end(&mut read)
        .unwrap();
    assert_eq!(read, bytes);
}

#[test]
fn prepared_artifact_collision_keeps_existing_bytes_and_issues_no_witness() {
    let (_temp, root) = engine_root();
    let published = name("results/objects/art_taken");
    root.prepare_artifact(&name("results/staging/a.part"), &published, b"kept")
        .unwrap();
    let staging = name("results/staging/b.part");
    assert!(
        root.prepare_artifact(&staging, &published, b"other")
            .is_err()
    );
    assert_eq!(root.read_file(&published, 64).unwrap(), b"kept");
    // The losing staged name stays for reference-aware reclamation.
    assert_eq!(root.read_file(&staging, 64).unwrap(), b"other");
}

fn assert_every_mutation_refused(root: &OwnedRoot, places: &[&Path]) {
    assert_eq!(
        root.check_durable_mutation_support(),
        Err(PlatformError::UnsafeRoot)
    );
    assert!(root.write_recovery_record(&name("r.json"), b"no").is_err());
    assert!(
        root.prepare_artifact(&name("s/a.part"), &name("o/a"), b"no")
            .is_err()
    );
    assert!(root.begin_input(&name("s/b.part")).is_err());
    assert!(root.remove_durable(&name("o/a")).is_err());
    for place in places {
        for leaf in ["r.json", "s", "o"] {
            assert!(!place.join(leaf).exists(), "{} {leaf}", place.display());
        }
    }
}

#[test]
fn a_root_renamed_and_replaced_after_open_refuses_every_mutation() {
    // Retained attribute-only handles do not prevent the rename; the
    // volume-serial/file-index recheck against a fresh open refuses it.
    let temp = TempDir::new().unwrap();
    let selected = temp.path().join("engine");
    let root = OwnedRoot::create_private(&selected, RootPurpose::EngineData).unwrap();
    let moved = temp.path().join("moved");
    fs::rename(&selected, &moved).unwrap();
    let _replacement = OwnedRoot::create_private(&selected, RootPurpose::EngineData).unwrap();
    assert_every_mutation_refused(&root, &[&selected, &moved]);
}

#[test]
fn a_renamed_ancestor_with_a_replacement_chain_refuses_every_mutation() {
    let temp = TempDir::new().unwrap();
    let parent = temp.path().join("parent");
    let selected = parent.join("engine");
    let root = OwnedRoot::create_private(&selected, RootPurpose::EngineData).unwrap();
    let moved = temp.path().join("moved-parent");
    match fs::rename(&parent, &moved) {
        // Observed 2026-11-23: NTFS refuses to rename a directory while a
        // descendant (the root) has an open handle. Mutations stay bound.
        Err(error) => {
            assert_eq!(error.raw_os_error(), Some(5), "{error}");
            root.write_recovery_record(&name("r.json"), b"bound")
                .unwrap();
            assert_eq!(fs::read(selected.join("r.json")).unwrap(), b"bound");
        }
        Ok(()) => {
            let _replacement =
                OwnedRoot::create_private(&selected, RootPurpose::EngineData).unwrap();
            assert_every_mutation_refused(&root, &[&selected, &moved.join("engine")]);
        }
    }
}

#[test]
fn a_renamed_root_without_replacement_refuses_every_mutation() {
    let temp = TempDir::new().unwrap();
    let selected = temp.path().join("engine");
    let root = OwnedRoot::create_private(&selected, RootPurpose::EngineData).unwrap();
    let moved = temp.path().join("moved");
    fs::rename(&selected, &moved).unwrap();
    // A missing root is never reported as NotFound: callers read NotFound
    // as "this entry is absent" and may release its storage charge.
    assert_eq!(
        root.check_durable_mutation_support(),
        Err(PlatformError::UnsafeRoot)
    );
    assert_eq!(
        root.remove_durable(&name("r.json")),
        Err(PlatformError::UnsafeRoot)
    );
    assert!(root.write_recovery_record(&name("r.json"), b"no").is_err());
    assert!(!moved.join("r.json").exists());
}

#[test]
fn junction_ancestor_above_the_root_is_refused() {
    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = temp.path().join("link");
    junction(&link, &real);
    assert_eq!(
        OwnedRoot::create_private(&link.join("engine"), RootPurpose::EngineData).err(),
        Some(PlatformError::UnsafeRoot)
    );
    assert!(!real.join("engine").exists());
}

#[test]
fn junction_inside_the_root_never_receives_published_bytes() {
    let (temp, root) = engine_root();
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    junction(&root.path().join("results"), &outside);
    assert!(
        root.prepare_artifact(
            &name("results/staging/x.part"),
            &name("results/objects/x"),
            b"escape"
        )
        .is_err()
    );
    assert!(root.begin_input(&name("results/x.part")).is_err());
    assert!(
        root.write_recovery_record(&name("results/r.json"), b"escape")
            .is_err()
    );
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn symlink_ancestor_is_refused_when_symlinks_can_be_created() {
    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = temp.path().join("link");
    if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
        eprintln!("NOT EXERCISED: directory symlink creation not permitted for this user");
        return;
    }
    assert_eq!(
        OwnedRoot::create_private(&link.join("engine"), RootPurpose::EngineData).err(),
        Some(PlatformError::UnsafeRoot)
    );
    assert!(!real.join("engine").exists());
}

#[test]
fn network_share_roots_are_unsupported() {
    let local = TempDir::new().unwrap();
    let remainder = local
        .path()
        .to_str()
        .unwrap()
        .strip_prefix("C:\\")
        .expect("temporary directory on C:");
    let unc = std::path::PathBuf::from(format!("\\\\localhost\\C$\\{remainder}\\engine"));
    assert_eq!(
        OwnedRoot::create_private(&unc, RootPurpose::EngineData).err(),
        Some(PlatformError::UnsupportedRoot)
    );
    assert!(!local.path().join("engine").exists());
}

#[test]
fn registered_cloud_sync_roots_are_unsupported() {
    // Read-only: open an existing registered sync root folder, never create in it.
    let Ok(profile) = std::env::var("USERPROFILE") else {
        eprintln!("NOT EXERCISED: no user profile");
        return;
    };
    let mut exercised = false;
    for candidate in ["Box", "Dropbox", "iCloudDrive"] {
        let path = Path::new(&profile).join(candidate);
        if path.is_dir() {
            exercised = true;
            assert_eq!(
                OwnedRoot::open(&path, RootPurpose::EngineData).err(),
                Some(PlatformError::UnsupportedRoot),
                "{candidate}"
            );
        }
    }
    if !exercised {
        eprintln!("NOT EXERCISED: no non-heuristic sync root folder present");
    }
}
