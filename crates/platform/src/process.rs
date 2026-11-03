//! Detached engine launch and process-start identity checks.
//!
//! A PID is only a lookup hint. This module pairs it with the OS creation/start
//! marker and observes that same identity until exit, so a reused PID cannot
//! be mistaken for the engine that the CLI started.

use crate::PlatformError;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

/// Native PID plus the OS creation marker that guards against PID reuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_marker: String,
}

/// A process-exit watcher registered against one verified process identity.
pub struct ProcessWatcher {
    #[cfg(target_os = "macos")]
    identity: ProcessIdentity,
    #[cfg(target_os = "linux")]
    handle: std::os::fd::OwnedFd,
    #[cfg(target_os = "macos")]
    handle: std::os::fd::OwnedFd,
    #[cfg(windows)]
    handle: std::os::windows::io::OwnedHandle,
}

impl ProcessWatcher {
    /// Register the native observer before submitting a shutdown mutation.
    /// Rechecking the birth marker after registration prevents PID reuse from
    /// binding the observer to a later process.
    pub fn new(identity: &ProcessIdentity) -> Result<Self, PlatformError> {
        if !process_matches(identity)? {
            return Err(PlatformError::NotFound);
        }
        #[cfg(target_os = "linux")]
        {
            let raw_pid = i32::try_from(identity.pid).map_err(|_| PlatformError::InvalidPath)?;
            let pid = rustix::process::Pid::from_raw(raw_pid).ok_or(PlatformError::InvalidPath)?;
            let handle = open_linux_process(pid)?;
            if !process_matches(identity)? {
                return Err(PlatformError::NotFound);
            }
            Ok(Self {
                #[cfg(target_os = "macos")]
                identity: identity.clone(),
                handle,
            })
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::FromRawFd;
            let raw = unsafe { libc::kqueue() };
            if raw < 0 {
                return Err(PlatformError::Io);
            }
            // SAFETY: kqueue returned a unique descriptor owned by this value.
            let handle = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            event.ident = identity.pid as libc::uintptr_t;
            event.filter = libc::EVFILT_PROC;
            event.flags = libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT;
            event.fflags = libc::NOTE_EXIT;
            // SAFETY: the queue and one-event registration are valid.
            if unsafe {
                libc::kevent(
                    std::os::fd::AsRawFd::as_raw_fd(&handle),
                    &event,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            } < 0
            {
                return Err(PlatformError::Io);
            }
            if !process_matches(identity)? {
                return Err(PlatformError::NotFound);
            }
            Ok(Self {
                #[cfg(target_os = "macos")]
                identity: identity.clone(),
                handle,
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::FromRawHandle;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            };
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    identity.pid,
                )
            };
            if raw.is_null() {
                return Err(crate::windows::process_query_error());
            }
            // SAFETY: OpenProcess returned a unique owned process handle.
            let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
            if !process_matches(identity)? {
                return Err(PlatformError::NotFound);
            }
            Ok(Self {
                #[cfg(target_os = "macos")]
                identity: identity.clone(),
                handle,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = identity;
            Err(PlatformError::UnsupportedRoot)
        }
    }

    /// Return true only when the native watcher observes this process exit.
    pub fn wait(&self, timeout: Duration) -> Result<bool, PlatformError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let deadline = Instant::now() + timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let millis = remaining.as_millis().min(i32::MAX as u128) as i32;
                let mut descriptor = libc::pollfd {
                    fd: self.handle.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
                if result > 0 {
                    return Ok(true);
                }
                if result == 0 {
                    return Ok(false);
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    return Err(PlatformError::Io);
                }
                if Instant::now() >= deadline {
                    return Ok(false);
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            let deadline = Instant::now() + timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let timespec = libc::timespec {
                    tv_sec: remaining.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
                    tv_nsec: remaining.subsec_nanos() as libc::c_long,
                };
                let mut event: libc::kevent = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::kevent(
                        self.handle.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        &mut event,
                        1,
                        &timespec,
                    )
                };
                if result > 0 {
                    return Ok(event.filter == libc::EVFILT_PROC);
                }
                if result == 0 {
                    return match process_matches(&self.identity) {
                        Ok(false) => Ok(true),
                        Ok(true) => Ok(false),
                        Err(error) => Err(error),
                    };
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    return Err(PlatformError::Io);
                }
                if Instant::now() >= deadline {
                    return Ok(false);
                }
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            let millis = timeout.as_millis().min(u32::MAX as u128) as u32;
            match unsafe { WaitForSingleObject(self.handle.as_raw_handle().cast(), millis) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                WAIT_FAILED => Err(PlatformError::Io),
                _ => Err(PlatformError::Io),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = timeout;
            Err(PlatformError::UnsupportedRoot)
        }
    }
}

#[cfg(target_os = "linux")]
fn open_linux_process(pid: rustix::process::Pid) -> Result<std::os::fd::OwnedFd, PlatformError> {
    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).map_err(|error| {
        if error == rustix::io::Errno::SRCH {
            PlatformError::NotFound
        } else {
            PlatformError::Io
        }
    })
}

/// Return a start marker for the running engine or CLI process.
pub fn current_process_identity() -> Result<ProcessIdentity, PlatformError> {
    let pid = std::process::id();
    Ok(ProcessIdentity {
        pid,
        start_marker: process_start_marker(pid)?,
    })
}

/// Launch one explicitly selected engine binary without inheriting terminal I/O.
pub fn launch_engine(binary: &Path, data_root: &Path) -> Result<ProcessIdentity, PlatformError> {
    if !binary.is_absolute() || !data_root.is_absolute() || !binary.is_file() {
        return Err(PlatformError::InvalidPath);
    }
    crate::root::validate_storage_path(data_root)?;
    let mut command = Command::new(binary);
    command
        .arg("--data-root")
        .arg(data_root)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Storage admission needs the same home context in the detached engine.
    // Do not inherit proxies, loader overrides, or arbitrary client settings.
    for name in ["HOME", "USERPROFILE", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the child-only hook performs one async-signal-safe setsid
        // call before exec and does not access shared runtime state.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(unix)]
    let child = command.spawn().map_err(|error| {
        let _ = error;
        PlatformError::Io
    })?;
    #[cfg(windows)]
    let (child, pid) = {
        use std::os::windows::io::AsRawHandle;
        let (child, pid) = crate::windows::spawn_detached_engine(&command)?;
        ensure_no_job(child.as_raw_handle().cast())?;
        (child, pid)
    };
    #[cfg(unix)]
    let pid = child.id();
    drop(child);
    Ok(ProcessIdentity {
        pid,
        start_marker: process_start_marker(pid)?,
    })
}

/// Refuse a Windows engine still constrained by a launcher Job Object.
/// Call before opening storage so a failed detached launch cannot mutate it.
pub fn ensure_independent_engine() -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle for this call.
        ensure_no_job(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() })?;
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_no_job(process: windows_sys::Win32::Foundation::HANDLE) -> Result<(), PlatformError> {
    let mut in_job = 0;
    // SAFETY: process is a live owned or current-process pseudo-handle; null
    // asks about any job, and in_job is writable for the duration of the call.
    let success = unsafe {
        windows_sys::Win32::System::JobObjects::IsProcessInJob(
            process,
            std::ptr::null_mut(),
            &mut in_job,
        )
    };
    if success == 0 || in_job != 0 {
        return Err(PlatformError::LaunchRestricted);
    }
    Ok(())
}

/// Verify that `pid` still names the process with this OS start marker.
pub fn process_matches(reference: &ProcessIdentity) -> Result<bool, PlatformError> {
    compare_start_marker(process_start_marker(reference.pid), &reference.start_marker)
}

/// Wait for the exact process identity to disappear or change, within a bound.
pub fn wait_for_process_exit(
    reference: &ProcessIdentity,
    timeout: Duration,
) -> Result<bool, PlatformError> {
    match ProcessWatcher::new(reference) {
        Ok(watcher) => watcher.wait(timeout),
        Err(PlatformError::NotFound) => Ok(true),
        Err(error) => Err(error),
    }
}

fn compare_start_marker(
    observed: Result<String, PlatformError>,
    expected: &str,
) -> Result<bool, PlatformError> {
    match observed {
        Ok(marker) => Ok(marker == expected),
        // A definitive no-such-process result establishes exit. Permission and
        // query failures remain errors so callers report an unconfirmed outcome.
        Err(PlatformError::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

fn process_start_marker(pid: u32) -> Result<String, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PlatformError::NotFound
            } else {
                PlatformError::Io
            }
        })?;
        let end_of_name = stat.rfind(')').ok_or(PlatformError::InvalidFile)?;
        let fields = stat[end_of_name + 1..]
            .split_whitespace()
            .collect::<Vec<_>>();
        let start_ticks = fields.get(19).ok_or(PlatformError::InvalidFile)?;
        if start_ticks.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(PlatformError::InvalidFile);
        }
        Ok(format!("linux-start-{start_ticks}"))
    }
    #[cfg(target_os = "macos")]
    {
        // proc_pidinfo fills the stable kernel start-time fields for this PID;
        // the returned byte count must cover the entire native record.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a writable native proc_bsdinfo record and pid is
        // passed only to the read-only process query API.
        let size = unsafe {
            libc::proc_pidinfo(
                pid as libc::pid_t,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                std::mem::size_of::<libc::proc_bsdinfo>() as i32,
            )
        };
        if size != std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                Err(PlatformError::NotFound)
            } else {
                Err(PlatformError::Io)
            };
        }
        if info.pbi_pid != pid {
            return Err(PlatformError::NotFound);
        }
        Ok(format!(
            "macos-start-{}-{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        ))
    }
    #[cfg(windows)]
    {
        crate::windows::process_start_marker(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        Err(PlatformError::UnsupportedRoot)
    }
}

#[cfg(test)]
mod tests {
    use super::compare_start_marker;
    use crate::PlatformError;

    #[cfg(target_os = "linux")]
    #[test]
    fn process_disappearance_during_registration_establishes_exit() {
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        child.wait().unwrap();
        assert!(matches!(
            super::open_linux_process(pid),
            Err(PlatformError::NotFound)
        ));
    }

    #[test]
    fn failed_process_queries_do_not_establish_exit() {
        assert_eq!(
            compare_start_marker(Err(PlatformError::Io), "marker"),
            Err(PlatformError::Io)
        );
        assert_eq!(
            compare_start_marker(Err(PlatformError::NotFound), "marker"),
            Ok(false)
        );
        assert_eq!(
            compare_start_marker(Ok("different".to_owned()), "marker"),
            Ok(false)
        );
    }
}
