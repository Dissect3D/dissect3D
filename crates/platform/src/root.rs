//! Protected root identity and handle ownership.
//!
//! Unix file operations are resolved relative to opened directory handles.
//! Windows retains no-delete-sharing directory handles and opens every path
//! component without following reparse points before checking its ACL.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, openat};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Caller-declared use for a protected root.
///
/// The value is retained at call sites to make ownership intent explicit.
/// Current Unix implementations apply the same permission and filesystem
/// checks to both purposes; the purpose does not yet select a different policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootPurpose {
    EngineData,
    ClientConfig,
}

/// Safe platform failure without leaking path or OS diagnostic strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformError {
    InvalidPath,
    UnsupportedRoot,
    UnsafeRoot,
    Io,
    Busy,
    NotFound,
    InvalidFile,
    LaunchRestricted,
}

/// An owner-validated root held through a directory handle.
///
/// On supported Unix targets the final directory must be owned by the current
/// effective user and private (`0700`). Windows roots require a protected DACL
/// for the current SID. Both target families restrict roots to selected local
/// filesystems.
pub struct OwnedRoot {
    #[cfg(unix)]
    directory: File,
    #[cfg(windows)]
    _directories: Vec<File>,
    path: PathBuf,
}

impl OwnedRoot {
    /// Open an existing root after checking owner, directory type and permissions.
    pub fn open(path: &Path, _purpose: RootPurpose) -> Result<Self, PlatformError> {
        #[cfg(unix)]
        {
            validate_storage_path(path)?;
            // Keep the pathname used by standard-VFS consumers aligned with
            // the system alias normalized by the descriptor-relative opener.
            // On macOS `/var` is a symlink to `/private/var`, which SQLite's
            // NOFOLLOW open flag correctly refuses in any path component.
            let normalized_path = normalize_system_alias(path);
            let directory = open_directory_chain(&normalized_path, false)?;
            validate_owned_directory(&directory)?;
            validate_storage_filesystem(&directory, &normalized_path)?;
            Ok(Self {
                directory,
                path: path.to_path_buf(),
            })
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                validate_storage_path(path)?;
                crate::windows::validate_filesystem(path)?;
                let directories = crate::windows::open_directory_chain(path, false)?;
                crate::windows::validate_directory(
                    directories.last().ok_or(PlatformError::UnsafeRoot)?,
                    true,
                )?;
                Ok(Self {
                    _directories: directories,
                    path: path.to_path_buf(),
                })
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }

    /// Create a new private root for an explicit start/configuration operation.
    pub fn create_private(path: &Path, _purpose: RootPurpose) -> Result<Self, PlatformError> {
        #[cfg(unix)]
        {
            validate_storage_path(path)?;
            let normalized_path = normalize_system_alias(path);
            let directory = open_directory_chain(&normalized_path, true)?;
            validate_owned_directory(&directory)?;
            validate_storage_filesystem(&directory, &normalized_path)?;
            Ok(Self {
                directory,
                path: path.to_path_buf(),
            })
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                validate_storage_path(path)?;
                crate::windows::validate_filesystem(path)?;
                let directories = crate::windows::open_directory_chain(path, true)?;
                crate::windows::validate_directory(
                    directories.last().ok_or(PlatformError::UnsafeRoot)?,
                    true,
                )?;
                Ok(Self {
                    _directories: directories,
                    path: path.to_path_buf(),
                })
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }

    /// Return the selected path for diagnostics and process launch composition.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Build a pathname for a fixed internal file opened by a native pathname
    /// API such as SQLite's stock VFS.
    ///
    /// Unix platform operations remain descriptor-relative. On macOS this
    /// normalizes the system `/var` alias so SQLite's no-follow open does not
    /// reject a trusted system path component. The returned path does not bind
    /// later native file operations to this root handle; callers must use only
    /// trusted names beneath the protected root and honor that limitation.
    pub fn path_for_native_vfs(&self, name: &crate::RelativePath) -> PathBuf {
        #[cfg(unix)]
        let root = normalize_system_alias(&self.path);
        #[cfg(not(unix))]
        let root = self.path.clone();
        root.join(name.as_path())
    }

    /// Create or validate a private directory beneath this root for an
    /// engine-owned native endpoint or metadata subtree.
    pub fn ensure_private_directory(
        &self,
        path: &crate::RelativePath,
    ) -> Result<(), PlatformError> {
        #[cfg(unix)]
        {
            let mut parent = self.directory.try_clone().map_err(|_| PlatformError::Io)?;
            for component in path.components() {
                parent = crate::files::open_subdirectory(&parent, component, true)?;
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            {
                crate::windows::ensure_private_directory(self, path)
            }
            #[cfg(not(windows))]
            {
                let _ = path;
                Err(PlatformError::UnsupportedRoot)
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn directory(&self) -> &File {
        &self.directory
    }
}

#[cfg(windows)]
pub(crate) fn validate_storage_path(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(_)))
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(PlatformError::InvalidPath);
    }
    if let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from)
        && path.strip_prefix(profile).is_ok_and(|remainder| {
            remainder.components().any(|component| {
                let component = component.as_os_str().to_string_lossy().to_ascii_lowercase();
                component.starts_with("onedrive")
                    || matches!(
                        component.as_str(),
                        "dropbox" | "google drive" | "googledrive" | "nextcloud" | "drivefs"
                    )
            })
        })
    {
        return Err(PlatformError::UnsupportedRoot);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_storage_path(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute() {
        return Err(PlatformError::InvalidPath);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let sync_locations = [
        "Library/CloudStorage",
        "Library/Mobile Documents",
        "Dropbox",
        "OneDrive",
        "Google Drive",
        "GoogleDrive",
        "Nextcloud",
    ];
    if home.is_some_and(|home| {
        sync_locations
            .iter()
            .any(|suffix| path.starts_with(home.join(suffix)))
    }) {
        return Err(PlatformError::UnsupportedRoot);
    }
    #[cfg(target_os = "macos")]
    if path.starts_with("/Volumes") {
        return Err(PlatformError::UnsupportedRoot);
    }
    Ok(())
}

#[cfg(all(unix, target_os = "macos"))]
fn validate_storage_filesystem(directory: &File, _path: &Path) -> Result<(), PlatformError> {
    let filesystem = rustix::fs::fstatfs(directory).map_err(|_| PlatformError::Io)?;
    let name = filesystem
        .f_fstypename
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8 as char)
        .collect::<String>();
    if name == "apfs" {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedRoot)
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn validate_storage_filesystem(directory: &File, _path: &Path) -> Result<(), PlatformError> {
    const EXT4_SUPER_MAGIC: i64 = 0xef53;
    let filesystem = rustix::fs::fstatfs(directory).map_err(|_| PlatformError::Io)?;
    if filesystem.f_type == EXT4_SUPER_MAGIC {
        Ok(())
    } else {
        Err(PlatformError::UnsupportedRoot)
    }
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn validate_storage_filesystem(_directory: &File, _path: &Path) -> Result<(), PlatformError> {
    Err(PlatformError::UnsupportedRoot)
}

#[cfg(unix)]
fn open_directory_chain(path: &Path, create: bool) -> Result<File, PlatformError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(PlatformError::InvalidPath);
    }
    let path = normalize_system_alias(path);
    let mut directory = File::open("/").map_err(|_| PlatformError::Io)?;
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::RootDir => None,
            _ => None,
        })
        .collect::<Vec<_>>();
    if components.is_empty() {
        return Err(PlatformError::UnsafeRoot);
    }
    let component_count = components.len();
    // Opening each component relative to the preceding descriptor and refusing
    // symlinks prevents an attacker-controlled ancestor from redirecting the
    // eventual root between validation and use.
    for (index, component) in components.into_iter().enumerate() {
        let next = match openat(
            &directory,
            &component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => File::from(descriptor),
            Err(error) if create && error == rustix::io::Errno::NOENT => {
                match rustix::fs::mkdirat(&directory, &component, Mode::from_bits_truncate(0o700)) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(map_errno(error)),
                }
                rustix::fs::fsync(&directory).map_err(map_errno)?;
                let descriptor = openat(
                    &directory,
                    &component,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(map_errno)?;
                File::from(descriptor)
            }
            Err(error) => return Err(map_errno(error)),
        };
        if index + 1 < component_count {
            validate_trusted_ancestor(&next)?;
        }
        directory = next;
    }
    Ok(directory)
}

#[cfg(all(unix, target_os = "macos"))]
fn normalize_system_alias(path: &Path) -> PathBuf {
    if let Ok(remainder) = path.strip_prefix("/var")
        && std::fs::read_link("/var").is_ok_and(|target| target == Path::new("private/var"))
    {
        return Path::new("/private/var").join(remainder);
    }
    path.to_path_buf()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn normalize_system_alias(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(unix)]
fn validate_owned_directory(directory: &File) -> Result<(), PlatformError> {
    let metadata = directory.metadata().map_err(|_| PlatformError::Io)?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(PlatformError::UnsafeRoot);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_ancestor(directory: &File) -> Result<(), PlatformError> {
    let metadata = directory.metadata().map_err(|_| PlatformError::Io)?;
    let mode = metadata.mode();
    let uid = rustix::process::geteuid().as_raw();
    let owned_and_private = metadata.uid() == uid && mode & 0o022 == 0;
    // Root-owned sticky directories such as /tmp allow shared placement only
    // when the sticky bit prevents one user replacing another user's entry.
    let protected_system_directory = metadata.uid() == 0
        && (mode & 0o022 == 0 || (mode & 0o020 == 0 && mode & 0o1002 == 0o1002));
    if !metadata.is_dir() || !(owned_and_private || protected_system_directory) {
        return Err(PlatformError::UnsafeRoot);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn map_errno(error: rustix::io::Errno) -> PlatformError {
    if error == rustix::io::Errno::NOENT {
        PlatformError::NotFound
    } else if error == rustix::io::Errno::EXIST {
        PlatformError::UnsafeRoot
    } else {
        PlatformError::Io
    }
}
