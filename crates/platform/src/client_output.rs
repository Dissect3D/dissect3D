//! Safe client-side local output confinement, private staging, and atomic
//! no-replace file installation (`RP-005`, `RP-P05`, `RP-S13`, `RP-S14`).
//!
//! Unlike `OwnedRoot` (which enforces `0700` engine-owned storage roots),
//! [`ClientOutputDirectory`] operates with the caller's normal user permissions
//! on an explicit `--output DIR` destination while confining every staging and
//! installation step to a retained OS directory handle.
//!
//! - Every component of the destination path is walked without following
//!   symlinks or Windows reparse points.
//! - Untrusted filenames are validated as strict single-component ASCII names,
//!   rejecting traversal, separators, Windows reserved device names, ADS,
//!   trailing dots/spaces, control characters, and case/normalization aliases.
//! - Each file is staged privately with exclusive creation, synced, and
//!   installed atomically with no-replace semantics (`linkat` + `unlinkat` on
//!   Unix; `MoveFileExW(MOVEFILE_WRITE_THROUGH)` without replace on Windows).
//! - Dropping an uninstalled [`StagedOutputFile`] removes only its own private
//!   staging entry and never touches existing user files.

use std::fs::File;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);
const MAX_FILENAME_BYTES: usize = 128;

/// Safe local output error without exposing raw OS error strings or full paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientOutputError {
    InvalidPath,
    InvalidFilename,
    UnsafeDestination,
    AlreadyExists,
    PermissionDenied,
    Io,
    UnsupportedPlatform,
}

/// Validated single-component output filename safe across Windows, Linux, and macOS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputFilename(String);

impl OutputFilename {
    /// Validate an untrusted filename (such as a manifest entry or `manifest.json`).
    pub fn parse(name: &str) -> Result<Self, ClientOutputError> {
        if name.is_empty()
            || name.len() > MAX_FILENAME_BYTES
            || !name.is_ascii()
            || !name.as_bytes()[0].is_ascii_alphanumeric()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || name.ends_with(['.', ' '])
            || is_windows_reserved_device_name(name)
        {
            return Err(ClientOutputError::InvalidFilename);
        }
        Ok(Self(name.to_owned()))
    }

    /// Return the validated filename string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Case-insensitive comparison used to reject cross-platform case aliases.
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

fn is_windows_reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit())
}

/// An OS-handle-confined local output directory for safe artifact downloads.
pub struct ClientOutputDirectory {
    #[cfg(unix)]
    directory: File,
    #[cfg(windows)]
    directory: File,
    #[cfg(windows)]
    identity: crate::windows::FileIdentity,
    path: PathBuf,
}

impl std::fmt::Debug for ClientOutputDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOutputDirectory")
            .finish_non_exhaustive()
    }
}

impl ClientOutputDirectory {
    /// Open or create `path` component-by-component without following symlinks
    /// or reparse points, retaining a handle to the verified directory.
    pub fn open(path: &Path) -> Result<Self, ClientOutputError> {
        if path.as_os_str().is_empty() {
            return Err(ClientOutputError::InvalidPath);
        }
        let resolved = resolve_destination_path(path)?;
        #[cfg(unix)]
        {
            let normalized = normalize_unix_system_alias(&resolved);
            let directory = open_unix_directory_chain(&normalized)?;
            Ok(Self {
                directory,
                path: normalized,
            })
        }
        #[cfg(windows)]
        {
            let (directory, identity) = open_windows_directory_chain(&resolved)?;
            Ok(Self {
                directory,
                identity,
                path: resolved,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = resolved;
            Err(ClientOutputError::UnsupportedPlatform)
        }
    }

    /// Return whether an existing directory entry collides with `target`
    /// ignoring ASCII case.
    pub fn contains_case_insensitive_conflict(
        &self,
        target: &OutputFilename,
    ) -> Result<bool, ClientOutputError> {
        #[cfg(unix)]
        {
            let mut dir = rustix::fs::Dir::read_from(&self.directory).map_err(map_unix_errno)?;
            while let Some(entry) = dir.read() {
                let entry = entry.map_err(map_unix_errno)?;
                let raw = entry.file_name().to_bytes();
                if raw == b"." || raw == b".." {
                    continue;
                }
                if let Ok(existing) = std::str::from_utf8(raw)
                    && existing.eq_ignore_ascii_case(target.as_str())
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        #[cfg(windows)]
        {
            self.verify_windows_identity()?;
            let entries = std::fs::read_dir(&self.path).map_err(map_std_io)?;
            for entry in entries {
                let entry = entry.map_err(map_std_io)?;
                if let Some(existing) = entry.file_name().to_str()
                    && existing.eq_ignore_ascii_case(target.as_str())
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = target;
            Err(ClientOutputError::UnsupportedPlatform)
        }
    }

    /// Create a new private staging file inside this directory.
    ///
    /// Dropping the returned handle before [`StagedOutputFile::install_no_replace`]
    /// succeeds removes only this staging file and never touches existing files.
    pub fn begin_staged_file(&self) -> Result<StagedOutputFile<'_>, ClientOutputError> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            let pid = rustix::process::getpid().as_raw_pid();
            for _ in 0..64 {
                let name = format!(
                    ".d3d-stage-{pid}-{}",
                    STAGE_COUNTER.fetch_add(1, Ordering::Relaxed)
                );
                match openat(
                    &self.directory,
                    name.as_str(),
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                ) {
                    Ok(descriptor) => {
                        let file = File::from(descriptor);
                        validate_unix_staged_file(&file)?;
                        return Ok(StagedOutputFile {
                            directory: self,
                            staged_name: name,
                            file: Some(file),
                            written: 0,
                            failed: false,
                            installed: false,
                        });
                    }
                    Err(rustix::io::Errno::EXIST) => continue,
                    Err(error) => return Err(map_unix_errno(error)),
                }
            }
            Err(ClientOutputError::Io)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            self.verify_windows_identity()?;
            let pid = std::process::id();
            for _ in 0..64 {
                let name = format!(
                    ".d3d-stage-{pid}-{}",
                    STAGE_COUNTER.fetch_add(1, Ordering::Relaxed)
                );
                let staged_path = self.path.join(&name);
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&staged_path)
                {
                    Ok(file) => {
                        validate_windows_staged_file(&file)?;
                        return Ok(StagedOutputFile {
                            directory: self,
                            staged_name: name,
                            file: Some(file),
                            written: 0,
                            failed: false,
                            installed: false,
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(map_std_io(error)),
                }
            }
            Err(ClientOutputError::Io)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(ClientOutputError::UnsupportedPlatform)
        }
    }

    /// Return the resolved path of the confined directory (for diagnostics/tests).
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(windows)]
    fn verify_windows_identity(&self) -> Result<(), ClientOutputError> {
        let (_, fresh_identity) = open_windows_directory_chain(&self.path)?;
        if fresh_identity != self.identity {
            return Err(ClientOutputError::UnsafeDestination);
        }
        let retained = crate::windows::file_identity(&self.directory)
            .map_err(|_| ClientOutputError::UnsafeDestination)?;
        if retained != self.identity {
            return Err(ClientOutputError::UnsafeDestination);
        }
        Ok(())
    }
}

/// One privately staged file bound to a [`ClientOutputDirectory`].
pub struct StagedOutputFile<'a> {
    directory: &'a ClientOutputDirectory,
    staged_name: String,
    file: Option<File>,
    written: u64,
    failed: bool,
    installed: bool,
}

impl std::fmt::Debug for StagedOutputFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedOutputFile")
            .field("written", &self.written)
            .field("installed", &self.installed)
            .finish_non_exhaustive()
    }
}

impl StagedOutputFile<'_> {
    /// Append one verified chunk to the private staging file.
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), ClientOutputError> {
        if self.failed || self.installed {
            return Err(ClientOutputError::Io);
        }
        let Some(next) = self.written.checked_add(bytes.len() as u64) else {
            self.failed = true;
            return Err(ClientOutputError::Io);
        };
        let Some(file) = self.file.as_mut() else {
            self.failed = true;
            return Err(ClientOutputError::Io);
        };
        if let Err(error) = file.write_all(bytes) {
            self.failed = true;
            return Err(map_std_io(error));
        }
        self.written = next;
        Ok(())
    }

    /// Return the exact number of bytes written to this staging file so far.
    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    /// Sync the staged file and atomically install it at `target` without
    /// replacing any existing file, link, or case-insensitive alias.
    pub fn install_no_replace(mut self, target: &OutputFilename) -> Result<(), ClientOutputError> {
        if self.failed || self.installed {
            return Err(ClientOutputError::Io);
        }
        let file = self.file.as_ref().ok_or(ClientOutputError::Io)?;
        let metadata = file.metadata().map_err(map_std_io)?;
        if metadata.len() != self.written {
            self.failed = true;
            return Err(ClientOutputError::Io);
        }
        file.sync_all().map_err(map_std_io)?;
        if self.directory.contains_case_insensitive_conflict(target)? {
            return Err(ClientOutputError::AlreadyExists);
        }

        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, linkat, unlinkat};
            validate_unix_staged_file(file)?;
            // `linkat` atomically fails with `EEXIST` if `target` already exists
            // (including symlinks, directories, or case aliases on APFS).
            match linkat(
                &self.directory.directory,
                self.staged_name.as_str(),
                &self.directory.directory,
                target.as_str(),
                AtFlags::empty(),
            ) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => return Err(ClientOutputError::AlreadyExists),
                Err(error) => return Err(map_unix_errno(error)),
            }
            // Drop the file handle, unlink the temporary staging name, and sync
            // the directory namespace.
            let _ = self.file.take();
            unlinkat(
                &self.directory.directory,
                self.staged_name.as_str(),
                AtFlags::empty(),
            )
            .map_err(map_unix_errno)?;
            rustix::fs::fsync(&self.directory.directory).map_err(map_unix_errno)?;
            self.installed = true;
            Ok(())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
            use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
            validate_windows_staged_file(file)?;
            self.directory.verify_windows_identity()?;
            let _ = self.file.take();
            let from_path = self.directory.path.join(&self.staged_name);
            let to_path = self.directory.path.join(target.as_str());
            let from: Vec<u16> = from_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let to: Vec<u16> = to_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: both UTF-16 paths are NUL-terminated and live for the call.
            // Omitting MOVEFILE_REPLACE_EXISTING and MOVEFILE_COPY_ALLOWED
            // guarantees atomic same-volume no-replace semantics.
            if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS)
                ) {
                    return Err(ClientOutputError::AlreadyExists);
                }
                return Err(map_std_io(error));
            }
            self.directory.verify_windows_identity()?;
            self.installed = true;
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = target;
            Err(ClientOutputError::UnsupportedPlatform)
        }
    }
}

impl Drop for StagedOutputFile<'_> {
    fn drop(&mut self) {
        if self.installed {
            return;
        }
        let _ = self.file.take();
        #[cfg(unix)]
        {
            let _ = rustix::fs::unlinkat(
                &self.directory.directory,
                self.staged_name.as_str(),
                rustix::fs::AtFlags::empty(),
            );
        }
        #[cfg(windows)]
        {
            if self.directory.verify_windows_identity().is_ok() {
                let staged_path = self.directory.path.join(&self.staged_name);
                let _ = std::fs::remove_file(&staged_path);
            }
        }
    }
}

fn resolve_destination_path(path: &Path) -> Result<PathBuf, ClientOutputError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().contains(&0) {
            return Err(ClientOutputError::InvalidPath);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        if path.as_os_str().encode_wide().any(|unit| unit == 0) {
            return Err(ClientOutputError::InvalidPath);
        }
    }
    for component in path.components() {
        match component {
            Component::ParentDir => return Err(ClientOutputError::InvalidPath),
            Component::Normal(part) => {
                if let Some(text) = part.to_str()
                    && text.contains(':')
                {
                    return Err(ClientOutputError::InvalidPath);
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
        }
    }
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ClientOutputError::InvalidPath)?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => return Err(ClientOutputError::InvalidPath),
            other => normalized.push(other.as_os_str()),
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(ClientOutputError::InvalidPath);
    }
    Ok(normalized)
}

#[cfg(all(unix, target_os = "macos"))]
fn normalize_unix_system_alias(path: &Path) -> PathBuf {
    if let Ok(remainder) = path.strip_prefix("/var")
        && std::fs::read_link("/var").is_ok_and(|target| target == Path::new("private/var"))
    {
        return Path::new("/private/var").join(remainder);
    }
    if let Ok(remainder) = path.strip_prefix("/tmp")
        && std::fs::read_link("/tmp").is_ok_and(|target| target == Path::new("private/tmp"))
    {
        return Path::new("/private/tmp").join(remainder);
    }
    path.to_path_buf()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn normalize_unix_system_alias(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(unix)]
fn open_unix_directory_chain(path: &Path) -> Result<File, ClientOutputError> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};
    if !path.is_absolute() {
        return Err(ClientOutputError::InvalidPath);
    }
    let mut directory = File::open("/").map_err(map_std_io)?;
    let components: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return Err(ClientOutputError::UnsafeDestination);
    }
    for component in components {
        let next = match openat(
            &directory,
            &component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => File::from(descriptor),
            Err(rustix::io::Errno::NOENT) => {
                match mkdirat(&directory, &component, Mode::from_bits_truncate(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(map_unix_errno(error)),
                }
                rustix::fs::fsync(&directory).map_err(map_unix_errno)?;
                let descriptor = openat(
                    &directory,
                    &component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(map_unix_errno)?;
                File::from(descriptor)
            }
            Err(error) => return Err(map_unix_errno(error)),
        };
        let metadata = next.metadata().map_err(map_std_io)?;
        if !metadata.is_dir() {
            return Err(ClientOutputError::UnsafeDestination);
        }
        directory = next;
    }
    Ok(directory)
}

#[cfg(unix)]
fn validate_unix_staged_file(file: &File) -> Result<(), ClientOutputError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(map_std_io)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(ClientOutputError::UnsafeDestination);
    }
    Ok(())
}

#[cfg(unix)]
fn map_unix_errno(error: rustix::io::Errno) -> ClientOutputError {
    if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::NOTDIR {
        ClientOutputError::UnsafeDestination
    } else if error == rustix::io::Errno::ACCESS || error == rustix::io::Errno::PERM {
        ClientOutputError::PermissionDenied
    } else if error == rustix::io::Errno::EXIST {
        ClientOutputError::AlreadyExists
    } else {
        ClientOutputError::Io
    }
}

#[cfg(windows)]
fn open_windows_directory_chain(
    path: &Path,
) -> Result<(File, crate::windows::FileIdentity), ClientOutputError> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Prefix;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle,
    };

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(ClientOutputError::InvalidPath);
    };
    if !matches!(prefix.kind(), Prefix::Disk(_)) {
        return Err(ClientOutputError::InvalidPath);
    }
    let Some(Component::RootDir) = components.next() else {
        return Err(ClientOutputError::InvalidPath);
    };
    let mut current = PathBuf::new();
    current.push(prefix.as_os_str());
    current.push(std::path::MAIN_SEPARATOR_STR);
    let mut normal_count = 0_usize;
    let mut last_dir: Option<File> = None;

    for component in components {
        let Component::Normal(name) = component else {
            return Err(ClientOutputError::InvalidPath);
        };
        if let Some(text) = name.to_str()
            && (text.contains(':') || is_windows_reserved_device_name(text))
        {
            return Err(ClientOutputError::InvalidPath);
        }
        normal_count += 1;
        current.push(name);
        let opened = match std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)
        {
            Ok(dir) => dir,
            Err(error)
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
                ) =>
            {
                match std::fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_err) => return Err(map_std_io(create_err)),
                }
                std::fs::OpenOptions::new()
                    .access_mode(0)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&current)
                    .map_err(map_std_io)?
            }
            Err(error) => return Err(map_std_io(error)),
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `opened` is a live directory handle and `info` is a writable output.
        if unsafe { GetFileInformationByHandle(opened.as_raw_handle(), &mut info) } == 0 {
            return Err(ClientOutputError::Io);
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        {
            return Err(ClientOutputError::UnsafeDestination);
        }
        last_dir = Some(opened);
    }

    if normal_count == 0 {
        return Err(ClientOutputError::UnsafeDestination);
    }
    let directory = last_dir.ok_or(ClientOutputError::UnsafeDestination)?;
    let identity = crate::windows::file_identity(&directory)
        .map_err(|_| ClientOutputError::UnsafeDestination)?;
    Ok((directory, identity))
}

#[cfg(windows)]
fn validate_windows_staged_file(file: &File) -> Result<(), ClientOutputError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` is a live handle and `info` is a writable output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(ClientOutputError::Io);
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(ClientOutputError::UnsafeDestination);
    }
    Ok(())
}

fn map_std_io(error: std::io::Error) -> ClientOutputError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => ClientOutputError::PermissionDenied,
        std::io::ErrorKind::AlreadyExists => ClientOutputError::AlreadyExists,
        _ => ClientOutputError::Io,
    }
}
