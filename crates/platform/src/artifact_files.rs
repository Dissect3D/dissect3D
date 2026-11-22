//! Engine capture of worker output from one per-attempt staging folder
//! (RP-P02/2-3; ENG-045, ENG-048).
//!
//! The engine creates the folder (never reusing one) and keeps a handle on it
//! for the attempt's life. After confirmed worker cleanup it lists the folder
//! through that handle and requires exactly the expected entries, all regular
//! files. Each file is then opened without following links, checked to be the
//! very entry the listing saw (device and inode, or volume serial and file
//! index on Windows), single-linked and owned by this user, and read once into
//! bounded engine memory. No checked path is reopened, and a worker-reported
//! name grants nothing by itself: it must be one component that the retained
//! folder's listing contains verbatim.
//!
//! Digests are computed by the caller from the captured bytes, so this crate
//! needs no hash dependency. Same-user processes other than the (terminated)
//! worker are outside the threat model; process isolation is not a sandbox.

use crate::{OwnedRoot, PlatformError, RelativePath};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Entries one staging folder may hold: the worker schema's 16 candidate files
/// plus the output description.
pub const ATTEMPT_ENTRIES_MAX: usize = 17;

/// A private staging folder created for one attempt, held by handle.
///
/// The worker receives only `worker_path()`. Capture never trusts that path:
/// it lists and opens through the retained handle (Unix) or binds every opened
/// file to the retained handle's listing (Windows).
pub struct AttemptRoot {
    directory: File,
    path: PathBuf,
}

impl std::fmt::Debug for AttemptRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No path in diagnostics.
        f.debug_struct("AttemptRoot").finish_non_exhaustive()
    }
}

/// Native identity of one directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileKey {
    device: u64,
    file: u64,
}

/// The folder's complete, verified listing: exactly the expected regular files.
pub struct ClosedEntries<'a> {
    root: &'a AttemptRoot,
    entries: Vec<(String, FileKey)>,
}

impl std::fmt::Debug for ClosedEntries<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClosedEntries")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Bytes read once through a verified handle. Only this module constructs it.
pub struct PrivateArtifact {
    name: RelativePath,
    bytes: Vec<u8>,
}

impl PrivateArtifact {
    pub fn name(&self) -> &RelativePath {
        &self.name
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Evidence that one prepared artifact's bytes and final private name passed
/// every native data/namespace/root-chain barrier. Only `prepare_artifact`
/// constructs it; like `DurableFile` it is not proof against a lying device.
pub struct DurableArtifact {
    file: crate::DurableFile,
}

impl std::fmt::Debug for DurableArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableArtifact")
            .field("length", &self.length())
            .finish_non_exhaustive()
    }
}

impl DurableArtifact {
    pub fn relative_path(&self) -> &RelativePath {
        self.file.relative_path()
    }
    pub fn length(&self) -> u64 {
        self.file.length()
    }
}

/// Write unit for preparation, the input writer's chunk bound.
const PREPARE_CHUNK_BYTES: usize = 65_536;

impl OwnedRoot {
    /// Durably prepare `bytes` at the engine-generated private name
    /// `published`, writing through `staging` with the same verified barriers
    /// as input capture: exclusive create, data sync, no-replace publication,
    /// namespace syncs and the root check (Unix: every ancestor; Windows: the
    /// DS-G04 owned-directory flushes and root identity recheck). Refused
    /// before any write where the root's durable mutation protocol is
    /// unsupported. A failure never yields a witness and leaves the staged or
    /// final name for the engine's reference-aware reclamation: nothing here
    /// deletes on error.
    pub fn prepare_artifact(
        &self,
        staging: &RelativePath,
        published: &RelativePath,
        bytes: &[u8],
    ) -> Result<DurableArtifact, PlatformError> {
        self.prepare_artifact_with_checkpoint(staging, published, bytes, |_| Ok(()))
    }

    fn prepare_artifact_with_checkpoint(
        &self,
        staging: &RelativePath,
        published: &RelativePath,
        bytes: &[u8],
        checkpoint: impl FnMut(crate::input_files::PublicationStep) -> Result<(), PlatformError>,
    ) -> Result<DurableArtifact, PlatformError> {
        self.check_durable_mutation_support()?;
        if bytes.is_empty() || staging == published {
            return Err(PlatformError::InvalidFile);
        }
        let mut writer = self.begin_input(staging)?;
        for chunk in bytes.chunks(PREPARE_CHUNK_BYTES) {
            writer.write_chunk(chunk)?;
        }
        Ok(DurableArtifact {
            file: writer.finish_with_checkpoint(published, checkpoint)?,
        })
    }

    /// Create a new private staging folder at `relative` and retain it.
    /// An existing folder is refused (`Busy`), so staging is never reused.
    pub fn create_attempt_root(
        &self,
        relative: &RelativePath,
    ) -> Result<AttemptRoot, PlatformError> {
        // Native separators: the worker receives this path verbatim.
        #[cfg(unix)]
        let path = self.path_for_native_vfs(relative);
        #[cfg(not(unix))]
        let path = {
            let mut path = self.path().to_path_buf();
            path.extend(relative.components());
            path
        };
        #[cfg(unix)]
        {
            let (parent, name) = self.open_parent(relative, true)?;
            match rustix::fs::mkdirat(
                &parent,
                name.as_str(),
                rustix::fs::Mode::from_bits_truncate(0o700),
            ) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => return Err(PlatformError::Busy),
                Err(error) => return Err(crate::root::map_errno(error)),
            }
            rustix::fs::fsync(&parent).map_err(crate::root::map_errno)?;
            let directory = crate::files::open_subdirectory(&parent, &name, false)?;
            Ok(AttemptRoot { directory, path })
        }
        #[cfg(windows)]
        {
            let directory = crate::windows::create_attempt_directory(self, relative)?;
            Ok(AttemptRoot { directory, path })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(PlatformError::UnsupportedRoot)
        }
    }
}

impl AttemptRoot {
    /// The native folder path handed to the worker as its output location.
    pub fn worker_path(&self) -> &Path {
        &self.path
    }

    /// List the retained folder and require exactly `expected`: each a single
    /// component, unique ignoring ASCII case, present verbatim as a regular
    /// file. Anything else in the folder (extra or non-UTF-8 names, links,
    /// directories, devices, case aliases) refuses the whole candidate.
    pub fn close_entries(
        &self,
        expected: &[RelativePath],
    ) -> Result<ClosedEntries<'_>, PlatformError> {
        if expected.is_empty() || expected.len() > ATTEMPT_ENTRIES_MAX {
            return Err(PlatformError::InvalidPath);
        }
        for (index, name) in expected.iter().enumerate() {
            if name.as_str().contains('/')
                || expected[..index]
                    .iter()
                    .any(|other| other.as_str().eq_ignore_ascii_case(name.as_str()))
            {
                return Err(PlatformError::InvalidPath);
            }
        }
        let listed = self.list()?;
        let mut entries = Vec::with_capacity(expected.len());
        for entry in listed {
            let Listed::Regular(name, key) = entry else {
                return Err(PlatformError::InvalidFile);
            };
            if !expected.iter().any(|e| e.as_str() == name) {
                return Err(PlatformError::InvalidFile);
            }
            entries.push((name, key));
        }
        if entries.len() != expected.len() {
            return Err(PlatformError::NotFound);
        }
        Ok(ClosedEntries {
            root: self,
            entries,
        })
    }

    #[cfg(unix)]
    fn list(&self) -> Result<Vec<Listed>, PlatformError> {
        use rustix::fs::{AtFlags, FileType, statat};
        let mut directory =
            rustix::fs::Dir::read_from(&self.directory).map_err(crate::root::map_errno)?;
        let mut listed = Vec::new();
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(crate::root::map_errno)?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            if listed.len() == ATTEMPT_ENTRIES_MAX {
                return Err(PlatformError::InvalidFile);
            }
            let Ok(name) = std::str::from_utf8(raw) else {
                listed.push(Listed::Other);
                continue;
            };
            let stat = statat(
                &self.directory,
                entry.file_name(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(crate::root::map_errno)?;
            listed.push(
                if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
                    Listed::Regular(
                        name.to_owned(),
                        FileKey {
                            device: stat.st_dev as u64,
                            file: stat.st_ino as u64,
                        },
                    )
                } else {
                    Listed::Other
                },
            );
        }
        Ok(listed)
    }

    #[cfg(windows)]
    fn list(&self) -> Result<Vec<Listed>, PlatformError> {
        Ok(
            crate::windows::list_attempt_directory(&self.directory, ATTEMPT_ENTRIES_MAX)?
                .into_iter()
                .map(|entry| match entry.name {
                    Some(name) if entry.regular => Listed::Regular(
                        name,
                        FileKey {
                            device: entry.volume_serial,
                            file: entry.file_index,
                        },
                    ),
                    _ => Listed::Other,
                })
                .collect(),
        )
    }

    #[cfg(not(any(unix, windows)))]
    fn list(&self) -> Result<Vec<Listed>, PlatformError> {
        Err(PlatformError::UnsupportedRoot)
    }
}

enum Listed {
    Regular(String, FileKey),
    Other,
}

impl ClosedEntries<'_> {
    /// Read the listed regular file `name` once, at most `max_bytes`, through a
    /// no-follow handle bound to the listed identity. A changed, replaced,
    /// multiply linked, foreign-owned or oversized file is refused.
    pub fn capture_candidate(
        &self,
        name: &RelativePath,
        max_bytes: u64,
    ) -> Result<PrivateArtifact, PlatformError> {
        let key = self
            .entries
            .iter()
            .find(|(listed, _)| listed == name.as_str())
            .map(|(_, key)| *key)
            .ok_or(PlatformError::InvalidPath)?;
        let (file, length) = self.root.open_listed(name.as_str(), key)?;
        if length > max_bytes {
            return Err(PlatformError::InvalidFile);
        }
        let mut bytes = Vec::with_capacity(length as usize);
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| PlatformError::Io)?;
        if bytes.len() as u64 != length {
            return Err(PlatformError::InvalidFile);
        }
        Ok(PrivateArtifact {
            name: name.clone(),
            bytes,
        })
    }
}

impl AttemptRoot {
    #[cfg(unix)]
    fn open_listed(&self, name: &str, key: FileKey) -> Result<(File, u64), PlatformError> {
        use rustix::fs::{FileType, Mode, OFlags, fstat, openat};
        // NONBLOCK: a planted FIFO cannot stall capture (reference: codex
        // exec-server regular_file.rs opens untrusted regular files this way).
        let descriptor = openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(crate::root::map_errno)?;
        let stat = fstat(&descriptor).map_err(crate::root::map_errno)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_nlink != 1
            || (FileKey {
                device: stat.st_dev as u64,
                file: stat.st_ino as u64,
            }) != key
        {
            return Err(PlatformError::InvalidFile);
        }
        Ok((File::from(descriptor), stat.st_size as u64))
    }

    #[cfg(windows)]
    fn open_listed(&self, name: &str, key: FileKey) -> Result<(File, u64), PlatformError> {
        let (file, device, index, length) =
            crate::windows::open_attempt_file(&self.path.join(name))?;
        if (FileKey {
            device,
            file: index,
        }) != key
        {
            return Err(PlatformError::InvalidFile);
        }
        Ok((file, length))
    }

    #[cfg(not(any(unix, windows)))]
    fn open_listed(&self, _name: &str, _key: FileKey) -> Result<(File, u64), PlatformError> {
        Err(PlatformError::UnsupportedRoot)
    }
}

#[cfg(test)]
mod tests {
    use crate::input_files::PublicationStep;
    use crate::{OwnedRoot, PlatformError, RelativePath, RootPurpose};

    #[test]
    fn injected_failure_at_each_step_issues_no_witness_and_publishes_only_after_the_move() {
        for fault in [
            PublicationStep::DataSync,
            PublicationStep::Publish,
            PublicationStep::NamespaceSync,
            PublicationStep::FinalSync,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root =
                OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
                    .unwrap();
            let staging = RelativePath::parse("results/staging/art_x.part").unwrap();
            let published = RelativePath::parse("results/objects/art_x").unwrap();
            let mut reached = false;
            let result =
                root.prepare_artifact_with_checkpoint(&staging, &published, b"bytes", |step| {
                    if step == fault {
                        reached = true;
                        Err(PlatformError::Io)
                    } else {
                        Ok(())
                    }
                });
            assert!(reached, "{fault:?} not reached");
            assert!(matches!(result, Err(PlatformError::Io)), "{fault:?}");
            let staged_exists = root.path().join(staging.as_path()).exists();
            let published_exists = root.path().join(published.as_path()).exists();
            match fault {
                PublicationStep::DataSync | PublicationStep::Publish => {
                    assert!(staged_exists, "{fault:?}: staging lost");
                    assert!(!published_exists, "{fault:?}: name published early");
                }
                PublicationStep::NamespaceSync | PublicationStep::FinalSync => {
                    // Moved but unwitnessed: retained for reclamation.
                    assert!(published_exists, "{fault:?}");
                    #[cfg(windows)]
                    assert!(!staged_exists, "{fault:?}: staged name remains");
                }
            }
        }
    }
}
