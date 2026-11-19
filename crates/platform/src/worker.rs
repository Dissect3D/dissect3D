//! Native ownership for a single controlled worker. Never uses engine breakaway.
use crate::{PlatformError, ProcessIdentity};
use std::ffi::OsString;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[cfg(windows)]
#[path = "worker/windows.rs"]
mod native;
#[cfg(target_os = "linux")]
#[path = "worker/linux.rs"]
mod native;
#[cfg(target_os = "macos")]
#[path = "worker/macos.rs"]
mod native;

/// Names the worker's two inherited private control endpoints (WC-001) as
/// `<engine-to-worker>:<worker-to-engine>` native handle or descriptor values.
/// The platform sets it; a caller-supplied value is rejected.
pub const WORKER_CONTROL_ENV: &str = "DISSECT3D_WORKER_CONTROL";

/// Engine ends of one worker's private pipes. Control frames use only the two
/// control pipes; the worker's stdout and stderr share the separate
/// diagnostics pipe, so upstream output can never be parsed as protocol.
pub struct WorkerChannels {
    /// Engine writes commands; the worker reads them.
    pub to_worker: File,
    /// The worker writes reports; the engine reads them.
    pub from_worker: File,
    /// Worker stdout and stderr, for bounded diagnostic capture only.
    pub diagnostics: File,
}

/// Engine-verified executable and finite launch inputs. No shell interpretation.
/// No public credentials or ambient environment are inherited.
pub struct WorkerCommand {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    /// Explicit packaged guardian on Unix; never searched through PATH.
    pub guardian: Option<PathBuf>,
}

impl WorkerCommand {
    pub fn new(executable: PathBuf) -> Self {
        Self {
            executable,
            args: Vec::new(),
            environment: Vec::new(),
            guardian: None,
        }
    }

    fn validate(&self) -> Result<(), PlatformError> {
        if !self.executable.is_absolute()
            || !self.executable.is_file()
            || self.args.len() > 256
            || self.environment.len() > 128
        {
            return Err(PlatformError::InvalidPath);
        }
        let mut length = 0usize;
        for value in std::iter::once(self.executable.as_os_str())
            .chain(self.args.iter().map(|v| v.as_os_str()))
            .chain(
                self.environment
                    .iter()
                    .flat_map(|(k, v)| [k.as_os_str(), v.as_os_str()]),
            )
        {
            if value.as_encoded_bytes().contains(&0) {
                return Err(PlatformError::InvalidPath);
            }
            length = length
                .checked_add(value.len())
                .ok_or(PlatformError::InvalidPath)?;
        }
        if length > 65_536 {
            return Err(PlatformError::InvalidPath);
        }
        let mut keys = std::collections::HashSet::new();
        for (key, _) in &self.environment {
            let upper = key.to_string_lossy().to_uppercase();
            if key.is_empty()
                || key.as_encoded_bytes().contains(&b'=')
                || upper == WORKER_CONTROL_ENV
                || !keys.insert(upper)
            {
                return Err(PlatformError::InvalidPath);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerIdentity {
    pub process: ProcessIdentity,
    pub guardian: Option<ProcessIdentity>,
    pub session_nonce: [u8; 16],
}

/// Only native closure evidence can construct this witness. Drop is not evidence.
#[derive(Clone, Debug)]
pub struct CleanupConfirmed {
    identity: WorkerIdentity,
}
impl CleanupConfirmed {
    pub fn identity(&self) -> &WorkerIdentity {
        &self.identity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupFault {
    Deadline,
    OwnershipLost,
    NativeFailure,
}

pub struct WorkerProcess {
    identity: WorkerIdentity,
    confirmed: bool,
    channels: Option<WorkerChannels>,
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    native: native::Worker,
}

impl WorkerProcess {
    pub fn launch(command: WorkerCommand, session_nonce: [u8; 16]) -> Result<Self, PlatformError> {
        command.validate()?;
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            let (native, process, guardian, channels) = native::Worker::launch(command)?;
            Ok(Self {
                native,
                identity: WorkerIdentity {
                    process,
                    guardian,
                    session_nonce,
                },
                confirmed: false,
                channels: Some(channels),
            })
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = session_nonce;
            Err(PlatformError::UnsupportedRoot)
        }
    }

    pub fn identity(&self) -> WorkerIdentity {
        self.identity.clone()
    }

    /// The engine ends of the private pipes, exactly once. Dropping them only
    /// closes the channel; it is never cleanup evidence.
    pub fn take_channels(&mut self) -> Option<WorkerChannels> {
        self.channels.take()
    }

    pub fn terminate_tree(&mut self, deadline: Instant) -> Result<CleanupConfirmed, CleanupFault> {
        if !self.confirmed {
            #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
            {
                self.native.terminate(deadline)?;
                self.confirmed = true;
            }
            #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
            {
                let _ = deadline;
                return Err(CleanupFault::OwnershipLost);
            }
        }
        Ok(CleanupConfirmed {
            identity: self.identity.clone(),
        })
    }
}

static CONTROL_TAKEN: AtomicBool = AtomicBool::new(false);

/// Worker side: take ownership of the inherited control endpoints named by
/// [`WORKER_CONTROL_ENV`], returning `(commands, reports)`. Callable once per
/// process. The endpoints are made non-inheritable (CLOEXEC on Unix) first,
/// so descendants the worker launches never hold the control channel open. A
/// Unix child forked without exec keeps copies; cleanup never relies on EOF.
pub fn worker_control_channels() -> Result<(File, File), PlatformError> {
    let value = std::env::var(WORKER_CONTROL_ENV).map_err(|_| PlatformError::NotFound)?;
    let (commands, reports) = value.split_once(':').ok_or(PlatformError::InvalidFile)?;
    let parse = |text: &str| {
        if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PlatformError::InvalidFile);
        }
        text.parse::<u64>().map_err(|_| PlatformError::InvalidFile)
    };
    let (commands, reports) = (parse(commands)?, parse(reports)?);
    if commands == reports || CONTROL_TAKEN.swap(true, Ordering::SeqCst) {
        return Err(PlatformError::Busy);
    }
    Ok((adopt(commands)?, adopt(reports)?))
}

/// Own one inherited pipe end and stop further inheritance.
#[cfg(unix)]
fn adopt(value: u64) -> Result<File, PlatformError> {
    use std::os::fd::FromRawFd;
    let fd = i32::try_from(value).map_err(|_| PlatformError::InvalidFile)?;
    // Only stdio is reserved below 3; the platform passes control at 3 and 4.
    if fd < 3 {
        return Err(PlatformError::InvalidFile);
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes only the provided struct; an invalid fd fails.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(PlatformError::InvalidFile);
    }
    // Linux passes pipes; the Darwin launcher passes socket pairs.
    let kind = stat.st_mode & libc::S_IFMT;
    if kind != libc::S_IFIFO && kind != libc::S_IFSOCK {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: fcntl on a descriptor validated above; no memory is passed.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: the launch contract transfers this inherited descriptor to the
    // worker, and CONTROL_TAKEN prevents a second owner in this process.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(windows)]
fn adopt(value: u64) -> Result<File, PlatformError> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
    let handle = usize::try_from(value).map_err(|_| PlatformError::InvalidFile)?
        as windows_sys::Win32::Foundation::HANDLE;
    if handle.is_null() {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: both calls only query/update the handle table entry; an
    // invalid value fails without touching memory.
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE
        || unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0
    {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: the launch contract transfers this inherited handle to the
    // worker, and CONTROL_TAKEN prevents a second owner in this process.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

#[cfg(not(any(unix, windows)))]
fn adopt(_value: u64) -> Result<File, PlatformError> {
    Err(PlatformError::UnsupportedRoot)
}
