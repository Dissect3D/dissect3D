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
