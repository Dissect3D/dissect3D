//! 2026-11-24 regression (found by WE-P07/4 engine-death tests on WSL2):
//! restart reconciliation reopened a guardian that had just exited while init
//! reaped it. Reading `/proc/PID/stat` then fails with ESRCH, which was
//! reported as a native I/O failure, so a cleanly exited worker tree became a
//! spurious `cleanup_native_failure` that kept its reservations.
use super::*;

#[test]
fn a_reaped_process_reads_as_absent_not_as_an_io_failure() {
    let errno = |code: rustix::io::Errno| std::io::Error::from_raw_os_error(code.raw_os_error());
    assert_eq!(
        proc_stat_error(&errno(rustix::io::Errno::SRCH)),
        PlatformError::NotFound
    );
    assert_eq!(
        proc_stat_error(&errno(rustix::io::Errno::NOENT)),
        PlatformError::NotFound
    );
    // Anything else stays a failure the caller reports as unconfirmed.
    assert_eq!(
        proc_stat_error(&errno(rustix::io::Errno::ACCESS)),
        PlatformError::Io
    );
    assert_eq!(
        proc_stat_error(&errno(rustix::io::Errno::IO)),
        PlatformError::Io
    );
}

/// 2026-11-25 regression (WE-P07 deferred MAJOR, residual spurious
/// `cleanup_native_failure` on restart): `pidfd_open` reports EINVAL, not
/// ESRCH, when the PID number is still allocated but no thread-group leader
/// holds it. When the number now names another task (reuse, here by a
/// thread), the recorded process is gone and was misreported as `Io`, so
/// restart kept the holds of a tree that had exited. A live thread's TID
/// gives the same EINVAL deterministically.
#[test]
fn a_pid_number_without_a_leader_is_rechecked_before_it_is_called_a_failure() {
    use std::sync::mpsc;
    let (tid_sender, tid) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        // SAFETY: gettid has no arguments and cannot fail.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        tid_sender.send(tid as u32).unwrap();
        let _ = released.recv();
    });
    let tid = tid.recv().unwrap();

    // The recorded process is gone and its number now names another task.
    let reused = ProcessIdentity {
        pid: tid,
        start_marker: "linux-start-0".to_owned(),
    };
    assert_eq!(
        open_linux_process(&reused).err(),
        Some(PlatformError::NotFound)
    );
    // If `/proc` still names the recorded identity, EINVAL proves nothing.
    let unproven = ProcessIdentity {
        pid: tid,
        start_marker: process_start_marker(tid).unwrap(),
    };
    assert_eq!(open_linux_process(&unproven).err(), Some(PlatformError::Io));

    release.send(()).unwrap();
    thread.join().unwrap();
}

/// Companion to the regression above (QA 2026-11-25): EINVAL also arrives
/// when the recorded process-group leader was reaped but members of its
/// group still run and pin the number. That is a possible survivor, never
/// absence, so it must stay a failure and keep the holds.
#[test]
fn a_reaped_leader_pinned_by_live_group_members_stays_a_failure() {
    use std::os::unix::process::CommandExt;
    let mut leader = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 30 & exit 0"])
        .process_group(0)
        .spawn()
        .unwrap();
    let identity = ProcessIdentity {
        pid: leader.id(),
        start_marker: process_start_marker(leader.id()).unwrap(),
    };
    leader.wait().unwrap();

    let pinned = open_linux_process(&identity).err();
    // SAFETY: signals only the test-created process group named by the
    // reaped leader's pid; ESRCH is harmless.
    unsafe {
        libc::kill(-(identity.pid as libc::pid_t), libc::SIGKILL);
    }
    assert_eq!(pinned, Some(PlatformError::Io));
}
