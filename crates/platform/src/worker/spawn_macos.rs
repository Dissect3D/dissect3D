//! Shared exact Darwin spawn: explicit descriptor set and optional suspended start.
use crate::{PlatformError, ProcessIdentity};
use std::ffi::{CString, OsString};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn check(code: i32) -> Result<(), PlatformError> {
    if code == 0 {
        Ok(())
    } else {
        Err(PlatformError::LaunchRestricted)
    }
}

pub(super) fn spawn(
    program: &Path,
    args: &[OsString],
    environment: &[(OsString, OsString)],
    descriptors: &[(RawFd, i32)],
    suspended: bool,
) -> Result<i32, PlatformError> {
    let string = |value: &std::ffi::OsStr| {
        CString::new(value.as_bytes()).map_err(|_| PlatformError::InvalidPath)
    };
    let binary = string(program.as_os_str())?;
    let arguments = std::iter::once(program.as_os_str())
        .chain(args.iter().map(|v| v.as_os_str()))
        .map(string)
        .collect::<Result<Vec<_>, _>>()?;
    let env = environment
        .iter()
        .map(|(key, value)| {
            let mut pair = key.clone();
            pair.push("=");
            pair.push(value);
            string(&pair)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let argv: Vec<_> = arguments
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(Some(std::ptr::null_mut()))
        .collect();
    let envp: Vec<_> = env
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(Some(std::ptr::null_mut()))
        .collect();
    struct Attributes(libc::posix_spawnattr_t);
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                libc::posix_spawnattr_destroy(&mut self.0);
            }
        }
    }
    struct Files(libc::posix_spawn_file_actions_t);
    impl Drop for Files {
        fn drop(&mut self) {
            unsafe {
                libc::posix_spawn_file_actions_destroy(&mut self.0);
            }
        }
    }
    let mut attributes = std::mem::MaybeUninit::uninit();
    let mut files = std::mem::MaybeUninit::uninit();
    // SAFETY: native initializers write their complete opaque objects.
    check(unsafe { libc::posix_spawnattr_init(attributes.as_mut_ptr()) })?;
    let mut attributes = Attributes(unsafe { attributes.assume_init() });
    check(unsafe { libc::posix_spawn_file_actions_init(files.as_mut_ptr()) })?;
    let mut files = Files(unsafe { files.assume_init() });
    let mut defaults: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut defaults);
        libc::sigaddset(&mut defaults, libc::SIGCHLD);
        libc::sigemptyset(&mut mask);
    }
    check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attributes.0, &defaults) })?;
    check(unsafe { libc::posix_spawnattr_setsigmask(&mut attributes.0, &mask) })?;
    let flags = libc::POSIX_SPAWN_SETPGROUP
        | libc::POSIX_SPAWN_SETSIGDEF
        | libc::POSIX_SPAWN_SETSIGMASK
        | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
        | if suspended {
            libc::POSIX_SPAWN_START_SUSPENDED
        } else {
            0
        };
    check(unsafe { libc::posix_spawnattr_setflags(&mut attributes.0, flags as i16) })?;
    check(unsafe { libc::posix_spawnattr_setpgroup(&mut attributes.0, 0) })?;
    // Actions run in order: a source must not be an earlier destination.
    // Callers pass sources relocated above every destination.
    for &(source, destination) in descriptors {
        if descriptors.iter().any(|&(_, target)| target == source) {
            return Err(PlatformError::InvalidPath);
        }
        check(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut files.0, source, destination)
        })?;
    }
    let mut pid = 0;
    // CLOEXEC_DEFAULT closes everything except explicit file actions. Exact
    // posix_spawn has no PATH search or ENOEXEC shell fallback.
    check(unsafe {
        libc::posix_spawn(
            &mut pid,
            binary.as_ptr(),
            &files.0,
            &attributes.0,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    })?;
    Ok(pid)
}

pub(super) fn observe(pid: i32) -> Result<ProcessIdentity, PlatformError> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            std::mem::size_of_val(&info) as i32,
        )
    };
    if size != std::mem::size_of_val(&info) as i32 || info.pbi_pid != pid as u32 {
        return Err(PlatformError::Io);
    }
    // Same creation marker as platform/process.rs; PID alone is not authority.
    Ok(ProcessIdentity {
        pid: pid as u32,
        start_marker: format!(
            "macos-start-{}-{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ),
    })
}

/// A CLOEXEC copy of `fd` at or above 64, clear of every mapped destination
/// (stdio, control and up to `MAX_WORKER_INPUTS` inputs).
pub(super) fn relocate(fd: RawFd) -> Result<std::os::fd::OwnedFd, PlatformError> {
    use std::os::fd::FromRawFd;
    // SAFETY: F_DUPFD_CLOEXEC creates a new descriptor or fails.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
    if copy < 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: the new descriptor is owned only here.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(copy) })
}
