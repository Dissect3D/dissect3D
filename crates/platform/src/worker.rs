//! Native ownership for a single controlled worker. Never uses engine breakaway.
use crate::{PlatformError, ProcessIdentity};
use std::ffi::OsString;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

/// Names the worker's inherited read-only inputs as comma-separated native
/// handle or descriptor values, in the order they were added. The platform
/// sets it; a caller-supplied value is rejected.
pub const WORKER_INPUTS_ENV: &str = "DISSECT3D_WORKER_INPUTS";

/// Inherited read-only handles per worker, counting every engine document
/// (resolution, effective parameters) and every captured input. More are
/// refused before any process exists.
pub const MAX_WORKER_INPUTS: usize = 16;

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
    /// Read-only files the worker inherits, in order; only through
    /// [`WorkerCommand::inherit_read_only`].
    inputs: Vec<File>,
}

impl WorkerCommand {
    pub fn new(executable: PathBuf) -> Self {
        Self {
            executable,
            args: Vec::new(),
            environment: Vec::new(),
            guardian: None,
            inputs: Vec::new(),
        }
    }

    /// Pass a read-only view of `file` to the worker (WE-004 scoped input).
    /// Returns the native value the worker sees in [`WORKER_INPUTS_ENV`] and
    /// adopts with [`worker_inherited_input`]. The worker can never write
    /// through it: Windows reopens the file with read access only; Unix
    /// accepts only a descriptor opened read-only. Only regular files.
    /// Exactly these handles (plus the private pipes) are inherited.
    pub fn inherit_read_only(&mut self, file: &File) -> Result<u64, PlatformError> {
        if self.inputs.len() >= MAX_WORKER_INPUTS {
            return Err(PlatformError::InvalidPath);
        }
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            let (view, value) = native::read_only_view(file, self.inputs.len())?;
            self.inputs.push(view);
            Ok(value)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = file;
            Err(PlatformError::UnsupportedRoot)
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
                || upper == WORKER_INPUTS_ENV
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

/// Restart evidence about a previous engine's worker (WE-P07/4; user decision
/// 2026-11-24): no recorded member of its tree (guardian, worker) still
/// matches its pid and start marker. A member found alive was ended through a
/// handle bound to the verified process. The rest of the tree relies on the
/// tested owner-death containment (Linux guardian lifeline, Windows
/// kill-on-close Job); this is that evidence kind, distinct from a
/// [`CleanupConfirmed`] live witness. Only [`reconcile_survivors`] mints it.
#[derive(Clone, Debug)]
pub struct SurvivorsAbsent {
    identity: WorkerIdentity,
    terminated: bool,
}
impl SurvivorsAbsent {
    pub fn identity(&self) -> &WorkerIdentity {
        &self.identity
    }
    /// A recorded member was still alive and had to be ended.
    pub fn terminated(&self) -> bool {
        self.terminated
    }
}

/// Reconcile a previous engine's worker tree at restart. A live guardian is
/// first given half the time to finish the cleanup it starts when it loses
/// its lifeline; then any recorded member that still matches is killed
/// through a verified handle and awaited. Never signals a PID whose start
/// marker differs. A query failure or a member that outlives `timeout` is a
/// fault: holds stay.
pub fn reconcile_survivors(
    identity: &WorkerIdentity,
    timeout: Duration,
) -> Result<SurvivorsAbsent, CleanupFault> {
    use crate::process::{ProcessWatcher, wait_for_process_exit};
    let native = |_| CleanupFault::NativeFailure;
    let deadline = Instant::now() + timeout;
    if let Some(guardian) = &identity.guardian {
        wait_for_process_exit(guardian, timeout / 2).map_err(native)?;
    }
    let members = std::iter::once(&identity.process).chain(identity.guardian.as_ref());
    let mut terminated = false;
    for member in members {
        // A verified handle, or proof that no process has this identity.
        let watcher = match ProcessWatcher::new_terminable(member) {
            Ok(watcher) => watcher,
            Err(PlatformError::NotFound) => continue,
            Err(_) => return Err(CleanupFault::NativeFailure),
        };
        // Exited, but still open elsewhere (Windows): already absent.
        if watcher.wait(Duration::ZERO).map_err(native)? {
            continue;
        }
        watcher.kill().map_err(native)?;
        terminated = true;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !watcher.wait(remaining).map_err(native)? {
            return Err(CleanupFault::Deadline);
        }
    }
    Ok(SurvivorsAbsent {
        identity: identity.clone(),
        terminated,
    })
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

/// Whether this process leaves child-exit reaping to direct `waitpid` callers:
/// SIGCHLD at its default action and without `SA_NOCLDWAIT`. A process-wide
/// SIGCHLD reaper (for example tokio's process driver) could reap the Darwin
/// guardian and let its PID be reused, so the macOS worker launch refuses
/// with [`PlatformError::LaunchRestricted`] whenever this is false.
#[cfg(unix)]
pub fn child_exit_reaping_unclaimed() -> Result<bool, PlatformError> {
    // SAFETY: a null new action only reads the current disposition into the
    // zeroed, writable `current` record.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current) } != 0 {
        return Err(PlatformError::Io);
    }
    Ok(current.sa_sigaction == libc::SIG_DFL && current.sa_flags & libc::SA_NOCLDWAIT == 0)
}

static CONTROL_TAKEN: AtomicBool = AtomicBool::new(false);
static INPUTS_TAKEN: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

/// Parse a platform-set list of native handle or descriptor values.
fn native_values(value: &str, limit: usize) -> Result<Vec<u64>, PlatformError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for text in value.split(',') {
        if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PlatformError::InvalidFile);
        }
        let parsed = text
            .parse::<u64>()
            .map_err(|_| PlatformError::InvalidFile)?;
        if values.contains(&parsed) || values.len() >= limit {
            return Err(PlatformError::InvalidFile);
        }
        values.push(parsed);
    }
    Ok(values)
}

/// Worker side: take ownership of one inherited read-only input named in
/// [`WORKER_INPUTS_ENV`] (the value `execute` names). Each value is adopted at
/// most once per process; an unlisted value, a non-regular file or (Unix) a
/// writable descriptor is refused. Inheritance stops at adoption. The file
/// position may be shared with the engine's copy: read from offset 0.
pub fn worker_inherited_input(value: u64) -> Result<File, PlatformError> {
    let listed = std::env::var(WORKER_INPUTS_ENV).map_err(|_| PlatformError::NotFound)?;
    if !native_values(&listed, MAX_WORKER_INPUTS)?.contains(&value) {
        return Err(PlatformError::NotFound);
    }
    let mut taken = INPUTS_TAKEN.lock().map_err(|_| PlatformError::Busy)?;
    if taken.contains(&value) {
        return Err(PlatformError::Busy);
    }
    let file = adopt_input(value)?;
    taken.push(value);
    Ok(file)
}

#[cfg(unix)]
fn adopt_input(value: u64) -> Result<File, PlatformError> {
    use std::os::fd::FromRawFd;
    let fd = i32::try_from(value).map_err(|_| PlatformError::InvalidFile)?;
    // 0-2 are stdio and 3-4 the control channel.
    if fd < 5 {
        return Err(PlatformError::InvalidFile);
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes only the provided struct; an invalid fd fails.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 || stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: fcntl on a validated descriptor; no memory is passed.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: the launch contract transfers this listed descriptor to the
    // worker, and INPUTS_TAKEN prevents a second owner in this process.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(windows)]
fn adopt_input(value: u64) -> Result<File, PlatformError> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};
    let handle = usize::try_from(value).map_err(|_| PlatformError::InvalidFile)?
        as windows_sys::Win32::Foundation::HANDLE;
    if handle.is_null() {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: both calls only query/update the handle table entry; an
    // invalid value fails without touching memory.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK
        || !is_regular_file(handle)
        || unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0
    {
        return Err(PlatformError::InvalidFile);
    }
    // SAFETY: the launch contract transfers this listed handle to the worker,
    // and INPUTS_TAKEN prevents a second owner in this process.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

/// A disk handle that is not a directory (a backup-semantics directory
/// handle is also `FILE_TYPE_DISK`).
#[cfg(windows)]
fn is_regular_file(handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: writes only the provided struct; an invalid handle fails.
    let queried = unsafe { GetFileInformationByHandle(handle, &mut info) };
    queried != 0 && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
}

#[cfg(not(any(unix, windows)))]
fn adopt_input(_value: u64) -> Result<File, PlatformError> {
    Err(PlatformError::UnsupportedRoot)
}

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
