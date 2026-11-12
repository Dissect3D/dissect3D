//! Cross-process exclusive leases for protected authorities and records.
//!
//! The lock file is persistent. Removing and recreating a locked inode could
//! let two processes each hold a lock on a different file with the same name.

use crate::{OwnedRoot, PlatformError, RelativePath};
use std::fs::File;

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, openat};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// A permanent lock file handle that represents the single writer authority.
/// The file descriptor remains alive for the lease lifetime; dropping it
/// releases ownership without unlinking the shared lock pathname.
pub struct AuthorityLease {
    #[cfg(any(unix, windows))]
    _file: File,
}

impl AuthorityLease {
    /// Acquire the permanent lock file without replacing or unlinking it.
    pub fn acquire(root: &OwnedRoot) -> Result<Self, PlatformError> {
        Self::acquire_at(root, &RelativePath::parse("authority.lock")?)
    }

    /// Acquire a permanent named lease under an owner-validated root.
    /// Callers bound the namespace and must never unlink a published lock file.
    pub fn acquire_at(root: &OwnedRoot, path: &RelativePath) -> Result<Self, PlatformError> {
        #[cfg(unix)]
        {
            let (parent, name) = root.open_parent(path, true)?;
            let descriptor = openat(
                &parent,
                name.as_str(),
                OFlags::RDWR
                    | OFlags::NONBLOCK
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(crate::root::map_errno)?;
            let file = File::from(descriptor);
            let metadata = file.metadata().map_err(|_| PlatformError::Io)?;
            if !metadata.is_file()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(PlatformError::UnsafeRoot);
            }
            match file.try_lock() {
                Ok(()) => Ok(Self { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => Err(PlatformError::Busy),
                Err(std::fs::TryLockError::Error(_)) => Err(PlatformError::Io),
            }
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                let file = crate::windows::open_lease_file_at(root, path)?;
                match file.try_lock() {
                    Ok(()) => Ok(Self { _file: file }),
                    Err(std::fs::TryLockError::WouldBlock) => Err(PlatformError::Busy),
                    Err(std::fs::TryLockError::Error(_)) => Err(PlatformError::Io),
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (root, path);
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }
}
