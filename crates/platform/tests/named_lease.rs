use dissect3d_platform::{AuthorityLease, OwnedRoot, PlatformError, RelativePath, RootPurpose};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn named_lease_child() {
    let Some(path) = std::env::var_os("D3_NAMED_LEASE_ROOT") else {
        return;
    };
    let root = OwnedRoot::open(std::path::Path::new(&path), RootPurpose::ClientConfig).unwrap();
    let _lease = AuthorityLease::acquire_at(
        &root,
        &RelativePath::parse("record-locks/one.lock").unwrap(),
    )
    .unwrap();
    std::fs::write(root.path().join("ready"), b"ready").unwrap();
    loop {
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn named_locks_are_independent_and_process_death_releases_the_same_inode() {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("profile"), RootPurpose::ClientConfig).unwrap();
    let one = RelativePath::parse("record-locks/one.lock").unwrap();
    let two = RelativePath::parse("record-locks/two.lock").unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "named_lease_child", "--nocapture"])
        .env("D3_NAMED_LEASE_ROOT", root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.path().join("ready").exists() {
        if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("named lease child did not become ready");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let busy = AuthorityLease::acquire_at(&root, &one);
    let independent = AuthorityLease::acquire_at(&root, &two);
    let profile = AuthorityLease::acquire(&root);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(matches!(busy, Err(PlatformError::Busy)));
    assert!(independent.is_ok() && profile.is_ok());
    assert!(AuthorityLease::acquire_at(&root, &one).is_ok());
    assert!(
        root.path().join(one.as_str()).is_file(),
        "never unlink permanent lock paths"
    );
}

#[cfg(unix)]
#[test]
fn named_locks_reject_links_in_parent_and_final_components() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("profile"), RootPurpose::ClientConfig).unwrap();
    let path = RelativePath::parse("locks/real.lock").unwrap();
    let lease = AuthorityLease::acquire_at(&root, &path).unwrap();
    symlink(root.path().join("locks"), root.path().join("alias")).unwrap();
    symlink(
        root.path().join(path.as_str()),
        root.path().join("locks/alias.lock"),
    )
    .unwrap();
    assert!(
        AuthorityLease::acquire_at(&root, &RelativePath::parse("alias/real.lock").unwrap())
            .is_err()
    );
    assert!(
        AuthorityLease::acquire_at(&root, &RelativePath::parse("locks/alias.lock").unwrap())
            .is_err()
    );
    drop(lease);
}
