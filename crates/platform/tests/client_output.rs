//! Native confinement, private staging, and atomic no-replace installation
//! tests for `ClientOutputDirectory` (`RP-P05`, `RP-S13`, `RP-S14`).

use dissect3d_platform::{ClientOutputDirectory, ClientOutputError, OutputFilename};
use std::fs;
use tempfile::TempDir;

const SAMPLE: &[u8] = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n";

#[test]
fn output_filename_accepts_portable_names_and_rejects_traversal_ads_reserved_and_aliases() {
    for valid in ["mesh.obj", "manifest.json", "part_01-a.glb", "A1.obj"] {
        assert_eq!(
            OutputFilename::parse(valid).expect(valid).as_str(),
            valid,
            "expected valid filename: {valid}"
        );
    }
    for invalid in [
        "",
        ".",
        "..",
        "../mesh.obj",
        "sub/mesh.obj",
        "sub\\mesh.obj",
        "/mesh.obj",
        "C:mesh.obj",
        "mesh.obj:stream",
        "mesh.obj.",
        "mesh.obj ",
        " mesh.obj",
        ".hidden.obj",
        "CON",
        "con.obj",
        "PRN.txt",
        "AUX",
        "NUL.obj",
        "CLOCK$",
        "COM1",
        "com9.obj",
        "LPT0.obj",
        "lpt3",
        "mesh\0.obj",
        "mesh\n.obj",
        "caf\u{00E9}.obj",
        "cafe\u{0301}.obj",
        "mesh\u{202E}jbo.exe",
    ] {
        assert_eq!(
            OutputFilename::parse(invalid),
            Err(ClientOutputError::InvalidFilename),
            "expected invalid filename: {invalid:?}"
        );
    }
    let long = format!("{}.obj", "a".repeat(126));
    assert_eq!(
        OutputFilename::parse(&long),
        Err(ClientOutputError::InvalidFilename)
    );
}

#[test]
fn creates_missing_destination_stages_privately_and_installs_without_temp_leftovers() {
    let root = TempDir::new().unwrap();
    let destination = root.path().join("nested").join("result");
    let dir = ClientOutputDirectory::open(&destination).unwrap();
    let name = OutputFilename::parse("mesh.obj").unwrap();

    let mut staged = dir.begin_staged_file().unwrap();
    staged.write_chunk(&SAMPLE[..10]).unwrap();
    staged.write_chunk(&SAMPLE[10..]).unwrap();
    assert_eq!(staged.bytes_written(), SAMPLE.len() as u64);
    staged.install_no_replace(&name).unwrap();

    assert_eq!(fs::read(destination.join("mesh.obj")).unwrap(), SAMPLE);
    let entries: Vec<_> = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1, "staging file must be cleaned up");
}

#[test]
fn existing_file_and_case_alias_are_refused_without_modifying_sentinel() {
    let root = TempDir::new().unwrap();
    let destination = root.path().join("out");
    let dir = ClientOutputDirectory::open(&destination).unwrap();
    let sentinel = b"existing client data";
    fs::write(destination.join("mesh.obj"), sentinel).unwrap();

    // Exact match refusal.
    let mut staged = dir.begin_staged_file().unwrap();
    staged.write_chunk(SAMPLE).unwrap();
    let error = staged
        .install_no_replace(&OutputFilename::parse("mesh.obj").unwrap())
        .unwrap_err();
    assert_eq!(error, ClientOutputError::AlreadyExists);
    assert_eq!(fs::read(destination.join("mesh.obj")).unwrap(), sentinel);

    // Case-insensitive collision refusal (even on case-sensitive Linux ext4).
    let mut staged = dir.begin_staged_file().unwrap();
    staged.write_chunk(SAMPLE).unwrap();
    let error = staged
        .install_no_replace(&OutputFilename::parse("MESH.OBJ").unwrap())
        .unwrap_err();
    assert_eq!(error, ClientOutputError::AlreadyExists);
    assert_eq!(fs::read(destination.join("mesh.obj")).unwrap(), sentinel);

    // Ensure no partial staging files remain after refused installs.
    let entries: Vec<_> = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn dropping_uninstalled_staged_file_cleans_up_only_owned_staging() {
    let root = TempDir::new().unwrap();
    let destination = root.path().join("out");
    let dir = ClientOutputDirectory::open(&destination).unwrap();
    fs::write(destination.join("keep.txt"), b"keep").unwrap();

    {
        let mut staged = dir.begin_staged_file().unwrap();
        staged.write_chunk(b"partial").unwrap();
        // Dropped without install_no_replace.
    }

    assert_eq!(fs::read(destination.join("keep.txt")).unwrap(), b"keep");
    let entries: Vec<_> = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn rejects_destination_with_parent_traversal_or_regular_file_target() {
    let root = TempDir::new().unwrap();
    let traversed = root.path().join("sub").join("..").join("out");
    assert_eq!(
        ClientOutputDirectory::open(&traversed).unwrap_err(),
        ClientOutputError::InvalidPath
    );

    let file_target = root.path().join("not-a-dir");
    fs::write(&file_target, b"file").unwrap();
    assert_eq!(
        ClientOutputDirectory::open(&file_target).unwrap_err(),
        ClientOutputError::UnsafeDestination
    );
}

#[cfg(unix)]
#[test]
fn unix_rejects_symlink_destination_symlink_ancestor_and_symlink_target() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().unwrap();
    let real_outside = root.path().join("outside");
    fs::create_dir(&real_outside).unwrap();

    // Symlink as destination leaf.
    let link_dest = root.path().join("link-dest");
    symlink(&real_outside, &link_dest).unwrap();
    assert_eq!(
        ClientOutputDirectory::open(&link_dest).unwrap_err(),
        ClientOutputError::UnsafeDestination
    );

    // Symlink as ancestor of destination.
    let through_link = link_dest.join("child");
    assert_eq!(
        ClientOutputDirectory::open(&through_link).unwrap_err(),
        ClientOutputError::UnsafeDestination
    );

    // Pre-existing symlink at target filename inside real destination.
    let dest = root.path().join("real-dest");
    let dir = ClientOutputDirectory::open(&dest).unwrap();
    let victim = real_outside.join("victim.obj");
    fs::write(&victim, b"victim").unwrap();
    symlink(&victim, dest.join("mesh.obj")).unwrap();

    let mut staged = dir.begin_staged_file().unwrap();
    staged.write_chunk(SAMPLE).unwrap();
    let error = staged
        .install_no_replace(&OutputFilename::parse("mesh.obj").unwrap())
        .unwrap_err();
    assert_eq!(error, ClientOutputError::AlreadyExists);
    assert_eq!(fs::read(&victim).unwrap(), b"victim");
}

#[cfg(unix)]
#[test]
fn unix_retained_dirfd_confines_install_even_if_destination_path_is_swapped() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().unwrap();
    let dest = root.path().join("dest");
    let moved = root.path().join("moved");
    let decoy = root.path().join("decoy");
    fs::create_dir(&decoy).unwrap();

    let dir = ClientOutputDirectory::open(&dest).unwrap();
    let mut staged = dir.begin_staged_file().unwrap();
    staged.write_chunk(SAMPLE).unwrap();

    // Attacker swaps `dest` with a symlink to `decoy` before install.
    fs::rename(&dest, &moved).unwrap();
    symlink(&decoy, &dest).unwrap();

    staged
        .install_no_replace(&OutputFilename::parse("mesh.obj").unwrap())
        .unwrap();

    // The file landed in the originally opened directory inode (`moved`),
    // never following the swapped symlink into `decoy`.
    assert!(!decoy.join("mesh.obj").exists());
    assert_eq!(fs::read(moved.join("mesh.obj")).unwrap(), SAMPLE);
}
