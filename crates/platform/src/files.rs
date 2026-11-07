//! Validated relative paths and protected atomic file operations.
//!
//! Each operation opens parents and files without following links, then checks
//! metadata and owner permissions on the resulting handle. Unix uses descriptor-
//! relative opens; Windows also relies on a private root and retained directory
//! handles to protect path-based Win32 operations from other-user replacement.

use crate::{OwnedRoot, PlatformError};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags, openat};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(unix)]
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Open a user-selected configuration file without waiting on Unix FIFOs.
/// Unlike protected credentials, configuration may live in a shared parent;
/// require a regular file but do not grant it engine-storage authority.
pub fn open_regular_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    let file = std::fs::File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    Ok(file)
}

/// Open a persistent configuration lock without following links or waiting on FIFOs.
pub fn open_config_lock(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    let file = std::fs::File::from(rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )?);
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected a regular lock file",
        ));
    }
    Ok(file)
}

/// A safe slash-separated sequence of ordinary path components.
///
/// Windows aliases and separators are rejected even on Unix so a stored path
/// cannot acquire a different meaning when it crosses platforms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelativePath(String);

/// Metadata from a no-follow, owner-validated file opened beneath `OwnedRoot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafeFileMetadata {
    pub length: u64,
}

impl RelativePath {
    /// Validate a nonempty relative path with no aliases or parent traversal.
    pub fn parse(value: impl Into<String>) -> Result<Self, PlatformError> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('/')
            || value.contains('\\')
            || value.contains(':')
            || value.split('/').any(|component| {
                component.is_empty()
                    || component == "."
                    || component == ".."
                    || component.ends_with([' ', '.'])
                    || is_windows_device_name(component)
            })
        {
            return Err(PlatformError::InvalidPath);
        }
        Ok(Self(value))
    }
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches([' ', '.']);
    ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|name| stem.eq_ignore_ascii_case(name))
        || (1..=9).any(|number| {
            stem.eq_ignore_ascii_case(&format!("COM{number}"))
                || stem.eq_ignore_ascii_case(&format!("LPT{number}"))
        })
}

impl OwnedRoot {
    /// Report free bytes available to this user on the root's filesystem.
    ///
    /// A failed or unsupported query is an error; callers that reserve durable
    /// storage must not treat unknown capacity as available space.
    pub fn available_space_bytes(&self) -> Result<u64, PlatformError> {
        #[cfg(unix)]
        {
            let mut statistics = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
            // SAFETY: `fstatvfs` writes the platform-defined statvfs structure
            // to this correctly aligned output buffer for a live root handle.
            if unsafe { libc::fstatvfs(self.directory().as_raw_fd(), statistics.as_mut_ptr()) } != 0
            {
                return Err(PlatformError::Io);
            }
            // SAFETY: success means the complete statvfs structure was written.
            let statistics = unsafe { statistics.assume_init() };
            // Native field widths vary by Unix target. Widen before multiplying
            // and check the resulting byte count at the public u64 boundary.
            let blocks = u128::from(statistics.f_bavail);
            let block_size = u128::from(statistics.f_frsize);
            if block_size == 0 {
                return Err(PlatformError::Io);
            }
            u64::try_from(blocks * block_size).map_err(|_| PlatformError::Io)
        }
        #[cfg(windows)]
        {
            crate::windows::available_space_bytes(self)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(PlatformError::UnsupportedRoot)
        }
    }

    /// Remove one owner-validated regular file beneath this root.
    pub fn remove_file(&self, path: &RelativePath) -> Result<(), PlatformError> {
        #[cfg(unix)]
        {
            let (parent, final_name) = self.open_parent(path, false)?;
            let descriptor = openat(
                &parent,
                final_name.as_str(),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(crate::root::map_errno)?;
            let file = File::from(descriptor);
            validate_private_file(&file)?;
            drop(file);
            rustix::fs::unlinkat(&parent, final_name.as_str(), AtFlags::empty())
                .map_err(crate::root::map_errno)
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                crate::windows::remove_file(self, path)
            }
            #[cfg(not(windows))]
            {
                let _ = (self, path);
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }

    /// Inspect a private regular file without allocating its contents.
    pub fn file_metadata(&self, path: &RelativePath) -> Result<SafeFileMetadata, PlatformError> {
        #[cfg(unix)]
        {
            let (parent, final_name) = self.open_parent(path, false)?;
            let descriptor = openat(
                &parent,
                final_name.as_str(),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(crate::root::map_errno)?;
            let file = File::from(descriptor);
            validate_private_file(&file)?;
            let metadata = file.metadata().map_err(|_| PlatformError::Io)?;
            Ok(SafeFileMetadata {
                length: metadata.len(),
            })
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                crate::windows::file_metadata(self, path)
            }
            #[cfg(not(windows))]
            {
                let _ = (self, path);
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }

    /// Replace one owned file atomically without following an existing link.
    pub fn write_atomic(&self, path: &RelativePath, contents: &[u8]) -> Result<(), PlatformError> {
        #[cfg(unix)]
        {
            let mut components = path.components().peekable();
            let mut parent = self
                .directory()
                .try_clone()
                .map_err(|_| PlatformError::Io)?;
            let mut final_name = None;
            while let Some(component) = components.next() {
                if components.peek().is_none() {
                    final_name = Some(component.to_owned());
                    break;
                }
                parent = open_subdirectory(&parent, component, true)?;
            }
            let final_name = final_name.ok_or(PlatformError::InvalidPath)?;
            validate_replace_target(&parent, &final_name)?;
            // Write and sync a private sibling first. Rename then publishes the
            // complete file atomically; syncing the directory makes that name
            // replacement durable across a crash.
            let mut staged = None;
            for _ in 0..64 {
                let temporary = format!(
                    ".d3d-tmp-{}-{}",
                    rustix::process::getpid().as_raw_pid(),
                    TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
                );
                match openat(
                    &parent,
                    temporary.as_str(),
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o600),
                ) {
                    Ok(descriptor) => {
                        staged = Some((temporary, File::from(descriptor)));
                        break;
                    }
                    Err(error) if error == rustix::io::Errno::EXIST => continue,
                    Err(error) => return Err(crate::root::map_errno(error)),
                }
            }
            let (temporary, mut file) = staged.ok_or(PlatformError::Busy)?;
            let result = (|| {
                file.write_all(contents).map_err(|_| PlatformError::Io)?;
                file.sync_all().map_err(|_| PlatformError::Io)?;
                drop(file);
                validate_replace_target(&parent, &final_name)?;
                rustix::fs::renameat(&parent, temporary.as_str(), &parent, final_name.as_str())
                    .map_err(crate::root::map_errno)?;
                rustix::fs::fsync(&parent).map_err(crate::root::map_errno)?;
                Ok(())
            })();
            if result.is_err() {
                // A failed write must not leave a reusable temporary name that
                // could collide with a later attempt or be mistaken for data.
                match rustix::fs::unlinkat(&parent, temporary.as_str(), AtFlags::empty()) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                    Err(_) => return Err(PlatformError::Io),
                }
            }
            result
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                crate::windows::write_atomic(self, path, contents)
            }
            #[cfg(not(windows))]
            {
                let _ = (self, path, contents);
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }

    /// Read a bounded owned file through the held root.
    pub fn read_file(
        &self,
        path: &RelativePath,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, PlatformError> {
        #[cfg(unix)]
        {
            let (parent, final_name) = self.open_parent(path, false)?;
            let descriptor = openat(
                &parent,
                final_name.as_str(),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(crate::root::map_errno)?;
            let mut file = File::from(descriptor);
            validate_private_file(&file)?;
            let metadata = file.metadata().map_err(|_| PlatformError::Io)?;
            if metadata.len() > maximum_bytes as u64 {
                return Err(PlatformError::InvalidFile);
            }
            // Metadata can become stale while a file is being read, so cap the
            // actual stream as well as checking its advertised length.
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(maximum_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| PlatformError::Io)?;
            if bytes.len() > maximum_bytes {
                return Err(PlatformError::InvalidFile);
            }
            Ok(bytes)
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                crate::windows::read_file(self, path, maximum_bytes)
            }
            #[cfg(not(windows))]
            {
                let _ = (self, path, maximum_bytes);
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }
}

impl RelativePath {
    /// Return the validated slash-separated relative path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn as_path(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }

    pub(crate) fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

#[cfg(unix)]
impl OwnedRoot {
    pub(crate) fn open_parent(
        &self,
        path: &RelativePath,
        create: bool,
    ) -> Result<(File, String), PlatformError> {
        let mut components = path.components().peekable();
        let mut parent = self
            .directory()
            .try_clone()
            .map_err(|_| PlatformError::Io)?;
        let mut final_name = None;
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                final_name = Some(component.to_owned());
                break;
            }
            parent = open_subdirectory(&parent, component, create)?;
        }
        Ok((parent, final_name.ok_or(PlatformError::InvalidPath)?))
    }
}

#[cfg(unix)]
pub(crate) fn open_subdirectory(
    parent: &File,
    name: &str,
    create: bool,
) -> Result<File, PlatformError> {
    let descriptor = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if create && error == rustix::io::Errno::NOENT => {
            match rustix::fs::mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => return Err(crate::root::map_errno(error)),
            }
            rustix::fs::fsync(parent).map_err(crate::root::map_errno)?;
            openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(crate::root::map_errno)?
        }
        Err(error) => return Err(crate::root::map_errno(error)),
    };
    let directory = File::from(descriptor);
    let metadata = directory.metadata().map_err(|_| PlatformError::Io)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(PlatformError::UnsafeRoot);
    }
    Ok(directory)
}

#[cfg(unix)]
pub(crate) fn validate_private_file(file: &File) -> Result<(), PlatformError> {
    let metadata = file.metadata().map_err(|_| PlatformError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(PlatformError::InvalidFile);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_replace_target(parent: &File, name: &str) -> Result<(), PlatformError> {
    match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => {
            if rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_symlink() {
                return Err(PlatformError::InvalidFile);
            }
            let descriptor = openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(crate::root::map_errno)?;
            validate_private_file(&File::from(descriptor))
        }
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(crate::root::map_errno(error)),
    }
}
