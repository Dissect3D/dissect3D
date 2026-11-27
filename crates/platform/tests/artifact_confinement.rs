//! RP-P02/2: capture from a real per-attempt staging folder on the native
//! filesystem. Every refusal must leave the outside world unread.
#![expect(
    clippy::unwrap_used,
    reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup"
)]
use dissect3d_platform::{
    ATTEMPT_ENTRIES_MAX, AttemptRoot, OwnedRoot, PlatformError, RelativePath, RootPurpose,
};
use std::fs;
use tempfile::TempDir;

const MESH: &[u8] = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n";

fn name(value: &str) -> RelativePath {
    RelativePath::parse(value).unwrap()
}

/// A fresh private root with one attempt folder, as the engine lays it out.
fn attempt() -> (TempDir, OwnedRoot, AttemptRoot) {
    let parent = TempDir::new().unwrap();
    let root =
        OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData).unwrap();
    let staging = root
        .create_attempt_root(&name(
            "execution/attempts/att_33333333333333333333333333333333/staging",
        ))
        .unwrap();
    (parent, root, staging)
}

/// What a worker does: plain create-new writes by path into its folder.
fn worker_writes(staging: &AttemptRoot, files: &[(&str, &[u8])]) {
    for (file, bytes) in files {
        fs::write(staging.worker_path().join(file), bytes).unwrap();
    }
}

fn capture(staging: &AttemptRoot, names: &[&str], max: u64) -> Result<Vec<Vec<u8>>, PlatformError> {
    let expected = names.iter().map(|n| name(n)).collect::<Vec<_>>();
    let closed = staging.close_entries(&expected)?;
    expected
        .iter()
        .map(|n| closed.capture_candidate(n, max).map(|a| a.into_bytes()))
        .collect()
}

#[test]
fn captures_exactly_the_declared_files_written_by_path() {
    let (_parent, _root, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH), ("output.json", b"{}")]);
    let captured = capture(&staging, &["mesh.obj", "output.json"], 1_048_576).unwrap();
    assert_eq!(captured, vec![MESH.to_vec(), b"{}".to_vec()]);
    // Bound is inclusive.
    assert!(capture(&staging, &["mesh.obj", "output.json"], MESH.len() as u64).is_ok());
}

#[test]
fn an_existing_attempt_folder_is_never_reused() {
    let (_parent, root, _staging) = attempt();
    assert_eq!(
        root.create_attempt_root(&name(
            "execution/attempts/att_33333333333333333333333333333333/staging"
        ))
        .unwrap_err(),
        PlatformError::Busy
    );
}

#[test]
fn traversal_absolute_unc_drive_stream_and_device_names_never_become_references() {
    for bad in [
        "..",
        "../mesh.obj",
        "/mesh.obj",
        "\\\\server\\share\\mesh.obj",
        "C:mesh.obj",
        "C:\\mesh.obj",
        "mesh.obj:stream",
        "CON",
        "nul.obj",
        "COM1.obj",
        "mesh.obj.",
        "mesh.obj ",
        "",
        "a//b",
    ] {
        assert!(RelativePath::parse(bad).is_err(), "{bad:?}");
    }
    // A parseable multi-component name is still not a staging entry.
    let (_parent, _root, staging) = attempt();
    fs::create_dir(staging.worker_path().join("sub")).unwrap();
    fs::write(staging.worker_path().join("sub").join("mesh.obj"), MESH).unwrap();
    assert_eq!(
        capture(&staging, &["sub/mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidPath
    );
}

#[test]
fn unexpected_missing_directory_and_case_alias_entries_refuse_the_candidate() {
    // An extra file.
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH), ("extra.bin", b"x")]);
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidFile
    );
    // A declared file that is absent.
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH)]);
    assert_eq!(
        capture(&staging, &["mesh.obj", "output.json"], 1_048_576).unwrap_err(),
        PlatformError::NotFound
    );
    // A directory where a file is declared.
    let (_p, _r, staging) = attempt();
    fs::create_dir(staging.worker_path().join("mesh.obj")).unwrap();
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidFile
    );
    // The listing must contain the declared name verbatim, not a case alias.
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("MESH.OBJ", MESH)]);
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidFile
    );
    // Declared names that alias each other ignoring case.
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH)]);
    assert_eq!(
        capture(&staging, &["mesh.obj", "MESH.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidPath
    );
}

#[test]
fn entry_count_and_byte_bounds_are_finite() {
    let (_p, _r, staging) = attempt();
    let names = (0..=ATTEMPT_ENTRIES_MAX)
        .map(|i| format!("f{i}.bin"))
        .collect::<Vec<_>>();
    for file in &names {
        fs::write(staging.worker_path().join(file), b"x").unwrap();
    }
    let all = names.iter().map(|n| name(n)).collect::<Vec<_>>();
    assert_eq!(
        staging.close_entries(&all).unwrap_err(),
        PlatformError::InvalidPath
    );
    assert_eq!(
        staging
            .close_entries(&all[..ATTEMPT_ENTRIES_MAX])
            .unwrap_err(),
        PlatformError::InvalidFile,
        "a folder holding more than the maximum is refused"
    );
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH)]);
    assert_eq!(
        capture(&staging, &["mesh.obj"], MESH.len() as u64 - 1).unwrap_err(),
        PlatformError::InvalidFile
    );
}

#[test]
fn a_hard_link_alias_to_an_engine_file_is_refused_and_unread() {
    let (parent, root, staging) = attempt();
    root.write_atomic(&name("secret.json"), b"engine-private")
        .unwrap();
    let _ = parent;
    fs::hard_link(
        root.path().join("secret.json"),
        staging.worker_path().join("mesh.obj"),
    )
    .unwrap();
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidFile
    );
}

#[test]
fn a_file_renamed_and_replaced_after_listing_is_refused() {
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH)]);
    let expected = [name("mesh.obj")];
    let closed = staging.close_entries(&expected).unwrap();
    // Race: the listed file moves away and another takes its name.
    fs::rename(
        staging.worker_path().join("mesh.obj"),
        staging.worker_path().join("moved.obj"),
    )
    .unwrap();
    fs::write(staging.worker_path().join("mesh.obj"), b"v 9 9 9\n").unwrap();
    assert_eq!(
        closed.capture_candidate(&expected[0], 1_048_576).err(),
        Some(PlatformError::InvalidFile)
    );
}

#[test]
fn a_replaced_staging_folder_is_never_read() {
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH)]);
    let path = staging.worker_path().to_path_buf();
    let aside = path.with_file_name("aside");
    let renamed = fs::rename(&path, &aside);
    // Windows: the retained handle (no DELETE sharing) denies the rename.
    #[cfg(windows)]
    assert!(renamed.is_err(), "the retained folder cannot be renamed");
    // Unix: a replacement folder appears at the old path; capture still reads
    // the retained original, never the replacement.
    #[cfg(unix)]
    {
        renamed.unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("mesh.obj"), b"v 9 9 9\n").unwrap();
    }
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap(),
        vec![MESH.to_vec()]
    );
}

#[cfg(unix)]
#[test]
fn symlinks_and_fifos_are_refused_without_following_or_blocking() {
    use std::os::unix::fs::symlink;
    let (parent, _r, staging) = attempt();
    let outside = parent.path().join("outside.obj");
    fs::write(&outside, MESH).unwrap();
    symlink(&outside, staging.worker_path().join("mesh.obj")).unwrap();
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidFile
    );

    let (_p, _r, staging) = attempt();
    let fifo = std::ffi::CString::new(
        staging
            .worker_path()
            .join("mesh.obj")
            .into_os_string()
            .into_encoded_bytes(),
    )
    .unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc_mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidFile
    );
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "mkfifo"]
    fn libc_mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
}

#[cfg(windows)]
#[test]
fn windows_reparse_points_are_refused_without_following() {
    use std::os::windows::fs::symlink_file;
    let (parent, _r, staging) = attempt();
    let outside = parent.path().join("outside.obj");
    fs::write(&outside, MESH).unwrap();
    // File symlinks need Developer Mode or the symlink privilege. A junction
    // (directory reparse point) needs neither, so it always runs.
    let junction = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(staging.worker_path().join("mesh.obj"))
        .arg(parent.path())
        .output()
        .unwrap();
    assert!(
        junction.status.success(),
        "junction creation: {}{}",
        String::from_utf8_lossy(&junction.stdout),
        String::from_utf8_lossy(&junction.stderr)
    );
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
        PlatformError::InvalidFile
    );
    let (_p, _r, staging) = attempt();
    match symlink_file(&outside, staging.worker_path().join("mesh.obj")) {
        Ok(()) => assert_eq!(
            capture(&staging, &["mesh.obj"], 1_048_576).unwrap_err(),
            PlatformError::InvalidFile
        ),
        Err(_) => eprintln!("NOT EXERCISED: file symlink creation not permitted for this user"),
    }
}

#[cfg(windows)]
#[test]
fn windows_alternate_streams_are_not_entries() {
    let (_p, _r, staging) = attempt();
    worker_writes(&staging, &[("mesh.obj", MESH)]);
    fs::write(staging.worker_path().join("mesh.obj:hidden"), b"stream").unwrap();
    // The stream neither appears as an entry nor changes the captured bytes.
    assert_eq!(
        capture(&staging, &["mesh.obj"], 1_048_576).unwrap(),
        vec![MESH.to_vec()]
    );
}
