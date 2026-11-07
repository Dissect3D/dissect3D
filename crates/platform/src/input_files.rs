//! Private streamed files. A witness is issued only after all native barriers.
//!
//! Failed or abandoned writers retain their names: only the engine can reconcile
//! their storage reservations. Drop must never imply durable deletion.

use crate::{OwnedRoot, PlatformError, RelativePath, RootPurpose};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};

const MAX_INPUT_BYTES: u64 = 268_435_456;
const MAX_CHUNK_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationStep {
    DataSync,
    Publish,
    NamespaceSync,
    FinalSync,
}

/// Exclusive private staging handle, retained independently of its caller's root.
pub struct PrivateInputWriter {
    root: OwnedRoot,
    staged: RelativePath,
    file: File,
    length: u64,
    failed: bool,
}

/// Evidence that bytes and their final namespace passed the native protocol.
/// This is not a promise against a lying device or proof of physical power loss.
pub struct DurableFile {
    relative: RelativePath,
    length: u64,
}

impl DurableFile {
    pub fn relative_path(&self) -> &RelativePath {
        &self.relative
    }

    pub fn length(&self) -> u64 {
        self.length
    }
}

/// A no-follow validated regular-file reader with a finite byte budget.
pub struct PrivateInputReader {
    file: std::io::Take<File>,
}

/// Retained enumeration state: each turn consumes at most 64 native entries.
/// Names grant no file authority; lookup must still use the no-follow APIs.
pub struct OwnedInputScan {
    _directory: OwnedRoot,
    entries: std::fs::ReadDir,
    relative: RelativePath,
    exhausted: bool,
}

pub struct OwnedFileBatch {
    pub entries: Vec<RelativePath>,
    pub rejected_entries: usize,
    pub rejected_names: Vec<OsString>,
    pub exhausted: bool,
}

impl OwnedInputScan {
    pub fn next_batch(&mut self, limit: usize) -> Result<OwnedFileBatch, PlatformError> {
        if !(1..=64).contains(&limit) {
            return Err(PlatformError::InvalidPath);
        }
        let mut entries = Vec::with_capacity(limit);
        let mut rejected_entries = 0;
        let mut rejected_names = Vec::new();
        if !self.exhausted {
            for _ in 0..limit {
                let Some(entry) = self.entries.next() else {
                    self.exhausted = true;
                    break;
                };
                let entry = entry.map_err(|_| PlatformError::Io)?;
                let name = entry.file_name();
                let checked = name.to_str().and_then(|name| {
                    RelativePath::parse(format!("{}/{}", self.relative.as_str(), name)).ok()
                });
                match checked {
                    Some(relative) => entries.push(relative),
                    None => {
                        rejected_entries += 1;
                        rejected_names.push(entry.file_name());
                    }
                }
            }
        }
        Ok(OwnedFileBatch {
            entries,
            rejected_entries,
            rejected_names,
            exhausted: self.exhausted,
        })
    }
}

impl Read for PrivateInputReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

impl OwnedRoot {
    /// Persist client recovery metadata before a mutation can be sent. The
    /// ordinary atomic writer alone does not prove the entire namespace chain.
    pub fn write_recovery_record(
        &self,
        relative: &RelativePath,
        bytes: &[u8],
    ) -> Result<(), PlatformError> {
        if bytes.is_empty() || bytes.len() > 1_048_576 {
            return Err(PlatformError::InvalidFile);
        }
        #[cfg(unix)]
        {
            sync_root_ancestors(self)?;
            self.write_atomic(relative, bytes)?;
            let (parent, name) = self.open_parent(relative, false)?;
            let file = File::from(
                rustix::fs::openat(
                    &parent,
                    name.as_str(),
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(crate::root::map_errno)?,
            );
            crate::files::validate_private_file(&file)?;
            file.sync_all().map_err(|_| PlatformError::Io)?;
            sync_ancestors(self, relative)?;
            sync_root_ancestors(self)?;
            full_sync(&file)
        }
        #[cfg(not(unix))]
        {
            // Windows' external-root-chain barrier remains an explicit gate.
            // Do not publish a pending record or authorize a POST without it.
            let _ = relative;
            Err(PlatformError::UnsupportedRoot)
        }
    }

    /// Remove an abandoned publication, including the protocol's temporary
    /// two-link state. Only the exact same private inode at both names permits
    /// the extra link; ordinary readers/removers continue rejecting aliases.
    #[cfg(unix)]
    pub fn remove_input_publication(
        &self,
        staged: &RelativePath,
        published: &RelativePath,
    ) -> Result<(), PlatformError> {
        use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};
        use std::os::unix::fs::MetadataExt;
        if staged == published {
            return Err(PlatformError::InvalidPath);
        }
        let inspect = |path: &RelativePath| -> Result<Option<File>, PlatformError> {
            let (parent, name) = match self.open_parent(path, false) {
                Ok(value) => value,
                Err(PlatformError::NotFound) => return Ok(None),
                Err(error) => return Err(error),
            };
            match openat(
                &parent,
                name.as_str(),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => Ok(Some(File::from(fd))),
                Err(rustix::io::Errno::NOENT) => Ok(None),
                Err(error) => Err(crate::root::map_errno(error)),
            }
        };
        let first = inspect(staged)?;
        let second = inspect(published)?;
        if let (Some(first), Some(second)) = (&first, &second) {
            let a = first.metadata().map_err(|_| PlatformError::Io)?;
            let b = second.metadata().map_err(|_| PlatformError::Io)?;
            let private = |m: &std::fs::Metadata| {
                m.is_file()
                    && m.uid() == rustix::process::geteuid().as_raw()
                    && m.mode() & 0o077 == 0
                    && m.nlink() == 2
            };
            if !private(&a) || !private(&b) || a.dev() != b.dev() || a.ino() != b.ino() {
                return Err(PlatformError::InvalidFile);
            }
            let (parent, name) = self.open_parent(staged, false)?;
            unlinkat(&parent, name.as_str(), AtFlags::empty()).map_err(crate::root::map_errno)?;
            sync_directory(&parent)?;
            crate::files::validate_private_file(second)?;
        }
        for path in [staged, published] {
            match self.remove_durable(path) {
                Ok(()) | Err(PlatformError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub fn scan_owned_inputs(
        &self,
        relative: &RelativePath,
    ) -> Result<OwnedInputScan, PlatformError> {
        let directory =
            OwnedRoot::open(&self.path_for_native_vfs(relative), RootPurpose::EngineData)?;
        let entries = std::fs::read_dir(directory.path()).map_err(|_| PlatformError::Io)?;
        Ok(OwnedInputScan {
            _directory: directory,
            entries,
            relative: relative.clone(),
            exhausted: false,
        })
    }
    pub fn begin_input(
        &self,
        relative: &RelativePath,
    ) -> Result<PrivateInputWriter, PlatformError> {
        let root = OwnedRoot::open(self.path(), RootPurpose::EngineData)?;
        #[cfg(unix)]
        sync_root_ancestors(&root)?;
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags, openat};
            let (parent, name) = root.open_parent(relative, true)?;
            let descriptor = openat(
                &parent,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(crate::root::map_errno)?;
            let file = File::from(descriptor);
            crate::files::validate_private_file(&file)?;
            file
        };
        #[cfg(windows)]
        let file = crate::windows::begin_input(&root, relative)?;
        #[cfg(not(any(unix, windows)))]
        return Err(PlatformError::UnsupportedRoot);
        #[cfg(any(unix, windows))]
        Ok(PrivateInputWriter {
            root,
            staged: relative.clone(),
            file,
            length: 0,
            failed: false,
        })
    }

    pub fn open_immutable_input(
        &self,
        relative: &RelativePath,
    ) -> Result<PrivateInputReader, PlatformError> {
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags, openat};
            let (parent, name) = self.open_parent(relative, false)?;
            let descriptor = openat(
                &parent,
                name.as_str(),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(crate::root::map_errno)?;
            let file = File::from(descriptor);
            crate::files::validate_private_file(&file)?;
            file
        };
        #[cfg(windows)]
        let file = crate::windows::open_input(self, relative)?;
        #[cfg(not(any(unix, windows)))]
        return Err(PlatformError::UnsupportedRoot);
        #[cfg(any(unix, windows))]
        {
            if file.metadata().map_err(|_| PlatformError::Io)?.len() > MAX_INPUT_BYTES {
                return Err(PlatformError::InvalidFile);
            }
            Ok(PrivateInputReader {
                file: file.take(MAX_INPUT_BYTES + 1),
            })
        }
    }

    /// A failed removal/barrier never authorizes releasing a storage charge.
    pub fn remove_durable(&self, relative: &RelativePath) -> Result<(), PlatformError> {
        #[cfg(unix)]
        {
            let (parent, _) = self.open_parent(relative, false)?;
            match self.remove_file(relative) {
                Ok(()) | Err(PlatformError::NotFound) => {}
                Err(error) => return Err(error),
            }
            sync_directory(&parent)?;
            sync_ancestors(self, relative)?;
            sync_deletion_cache(self)
        }
        #[cfg(windows)]
        {
            crate::windows::remove_input_durable(self, relative)
        }
        #[cfg(not(any(unix, windows)))]
        Err(PlatformError::UnsupportedRoot)
    }

    /// Move one direct child of a private input directory into quarantine.
    /// The source is renamed without following it, so links and malformed file
    /// types are preserved as evidence instead of being opened or deleted.
    #[cfg(unix)]
    pub fn quarantine_owned_entry(
        &self,
        source_directory: &RelativePath,
        entry_name: &std::ffi::OsStr,
        destination: &RelativePath,
    ) -> Result<(), PlatformError> {
        use rustix::fs::renameat;
        use std::os::unix::ffi::OsStrExt;

        if !matches!(source_directory.as_str(), "inputs/staging" | "inputs/data")
            || !destination.as_str().starts_with("inputs/quarantine/")
            || entry_name.is_empty()
            || entry_name.as_bytes().contains(&b'/')
            || entry_name == std::ffi::OsStr::new(".")
            || entry_name == std::ffi::OsStr::new("..")
        {
            return Err(PlatformError::InvalidPath);
        }
        let source_relative = source_directory.clone();
        let source_directory = OwnedRoot::open(
            &self.path_for_native_vfs(source_directory),
            RootPurpose::EngineData,
        )?;
        let (destination_parent, destination_name) = self.open_parent(destination, true)?;
        match self.file_metadata(destination) {
            Err(PlatformError::NotFound) => {}
            Ok(_) | Err(_) => return Err(PlatformError::Busy),
        }

        renameat(
            source_directory.directory(),
            entry_name,
            &destination_parent,
            destination_name.as_str(),
        )
        .map_err(crate::root::map_errno)?;
        sync_directory(source_directory.directory())?;
        sync_directory(&destination_parent)?;
        sync_ancestors(self, &source_relative)?;
        sync_ancestors(self, destination)?;
        sync_root_ancestors(self)?;
        sync_deletion_cache(self)
    }
}

impl PrivateInputWriter {
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), PlatformError> {
        self.write_chunk_using(bytes, |file, bytes| file.write_all(bytes))
    }

    fn write_chunk_using(
        &mut self,
        bytes: &[u8],
        write: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    ) -> Result<(), PlatformError> {
        let next = self
            .length
            .checked_add(bytes.len() as u64)
            .ok_or(PlatformError::InvalidFile)?;
        if self.failed || bytes.len() > MAX_CHUNK_BYTES || next > MAX_INPUT_BYTES {
            return Err(PlatformError::InvalidFile);
        }
        if write(&mut self.file, bytes).is_err() {
            // write_all may already have written a prefix. Never publish after
            // losing the exact correspondence between streamed bytes and length.
            self.failed = true;
            return Err(PlatformError::Io);
        }
        self.length = next;
        Ok(())
    }

    pub fn finish(self, final_name: &RelativePath) -> Result<DurableFile, PlatformError> {
        self.finish_with_checkpoint(final_name, |_| Ok(()))
    }

    fn finish_with_checkpoint(
        self,
        final_name: &RelativePath,
        mut checkpoint: impl FnMut(PublicationStep) -> Result<(), PlatformError>,
    ) -> Result<DurableFile, PlatformError> {
        if self.failed || self.length == 0 || self.staged == *final_name {
            return Err(PlatformError::InvalidFile);
        }
        if self.file.metadata().map_err(|_| PlatformError::Io)?.len() != self.length {
            return Err(PlatformError::InvalidFile);
        }
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, linkat, unlinkat};
            crate::files::validate_private_file(&self.file)?;
            checkpoint(PublicationStep::DataSync)?;
            self.file.sync_all().map_err(|_| PlatformError::Io)?;
            full_sync(&self.file)?;
            let (from, staged) = self.root.open_parent(&self.staged, false)?;
            let (to, name) = self.root.open_parent(final_name, true)?;
            checkpoint(PublicationStep::Publish)?;
            // linkat has atomic exclusive-destination semantics on Linux and macOS.
            // The temporary two-link state cannot produce a witness.
            linkat(&from, staged.as_str(), &to, name.as_str(), AtFlags::empty())
                .map_err(crate::root::map_errno)?;
            checkpoint(PublicationStep::NamespaceSync)?;
            sync_directory(&to)?;
            unlinkat(&from, staged.as_str(), AtFlags::empty()).map_err(crate::root::map_errno)?;
            sync_directory(&from)?;
            crate::files::validate_private_file(&self.file)?;
            self.file.sync_all().map_err(|_| PlatformError::Io)?;
            // Re-sync existing ancestors too: an earlier failed barrier may have
            // left a directory present without proving durable reachability.
            sync_ancestors(&self.root, final_name)?;
            sync_ancestors(&self.root, &self.staged)?;
            sync_root_ancestors(&self.root)?;
            checkpoint(PublicationStep::FinalSync)?;
            full_sync(&self.file)?;
        }
        #[cfg(windows)]
        crate::windows::finish_input(
            &self.root,
            self.file,
            &self.staged,
            final_name,
            &mut checkpoint,
        )?;
        #[cfg(not(any(unix, windows)))]
        return Err(PlatformError::UnsupportedRoot);
        #[cfg(any(unix, windows))]
        Ok(DurableFile {
            relative: final_name.clone(),
            length: self.length,
        })
    }
}

#[cfg(unix)]
pub(crate) fn sync_root_ancestors(root: &OwnedRoot) -> Result<(), PlatformError> {
    sync_root_ancestors_with(root, |path, private| {
        let directory = if private {
            root.directory()
                .try_clone()
                .map_err(|_| PlatformError::Io)?
        } else if path == std::path::Path::new("/") {
            File::open(path).map_err(|_| PlatformError::Io)?
        } else {
            crate::root::open_directory_chain(path, false)?
        };
        directory.sync_all().map_err(|_| PlatformError::Io)
    })
}

#[cfg(any(unix, test))]
fn sync_root_ancestors_with(
    root: &OwnedRoot,
    mut sync: impl FnMut(&std::path::Path, bool) -> Result<(), PlatformError>,
) -> Result<(), PlatformError> {
    let mut ancestors = root.path().ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for directory in ancestors {
        sync(directory, directory == root.path())?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &File) -> Result<(), PlatformError> {
    directory.sync_all().map_err(|_| PlatformError::Io)
}

#[cfg(unix)]
fn sync_ancestors(root: &OwnedRoot, relative: &RelativePath) -> Result<(), PlatformError> {
    let mut parent = root
        .directory()
        .try_clone()
        .map_err(|_| PlatformError::Io)?;
    sync_directory(&parent)?;
    let components = relative.components().collect::<Vec<_>>();
    for name in &components[..components.len() - 1] {
        parent = crate::files::open_subdirectory(&parent, name, false)?;
        sync_directory(&parent)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn full_sync(file: &File) -> Result<(), PlatformError> {
    use std::os::fd::AsRawFd;
    // SAFETY: the live owned descriptor accepts the argument-free F_FULLFSYNC.
    // No fallback: an unsupported drive-cache barrier must not issue a witness.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
        return Err(PlatformError::Io);
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn full_sync(_: &File) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn sync_deletion_cache(root: &OwnedRoot) -> Result<(), PlatformError> {
    use rustix::fs::{Mode, OFlags, openat};
    // F_FULLFSYNC operates on a regular file; do not assume directories accept it.
    // This fixed private sentinel carries no input identity or user content.
    let descriptor = openat(
        root.directory(),
        ".d3d-input-sync",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(crate::root::map_errno)?;
    let file = File::from(descriptor);
    crate::files::validate_private_file(&file)?;
    file.sync_all().map_err(|_| PlatformError::Io)?;
    sync_directory(root.directory())?;
    full_sync(&file)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn sync_deletion_cache(_: &OwnedRoot) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reopened_root_rechecks_every_namespace_ancestor_before_accepting_a_barrier() {
        let temp = tempfile::tempdir().unwrap();
        let root =
            OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
        let expected = root
            .path()
            .ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(std::path::Path::to_path_buf)
            .collect::<Vec<_>>();
        let root_index = expected.len() - 1;
        let mut observed = Vec::new();
        sync_root_ancestors_with(&root, |directory, private| {
            observed.push((directory.to_path_buf(), private));
            Ok(())
        })
        .unwrap();

        assert_eq!(
            observed,
            expected
                .into_iter()
                .enumerate()
                .map(|(index, path)| (path, index == root_index))
                .collect::<Vec<_>>()
        );
        #[cfg(unix)]
        sync_root_ancestors(&root).unwrap();
    }

    #[test]
    fn interrupted_root_ancestor_barrier_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root =
            OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
        let mut barriers = 0;
        let result = sync_root_ancestors_with(&root, |_, _| {
            barriers += 1;
            if barriers == 2 {
                Err(PlatformError::Io)
            } else {
                Ok(())
            }
        });

        assert_eq!(result, Err(PlatformError::Io));
        assert_eq!(barriers, 2);
    }

    #[test]
    fn input_publication_crash_child() {
        let (Some(root_path), Some(checkpoint)) = (
            std::env::var_os("DISSECT3D_INPUT_CRASH_ROOT"),
            std::env::var_os("DISSECT3D_INPUT_CRASH_CHECKPOINT"),
        ) else {
            return;
        };
        let root =
            OwnedRoot::open(std::path::Path::new(&root_path), RootPurpose::EngineData).unwrap();
        let mut writer = root
            .begin_input(&RelativePath::parse("inputs/incomplete/crash.part").unwrap())
            .unwrap();
        writer.write_chunk(b"checkpoint-owned input").unwrap();
        let checkpoint = match checkpoint.to_string_lossy().as_ref() {
            "data-sync" => PublicationStep::DataSync,
            "publish" => PublicationStep::Publish,
            "namespace-sync" => PublicationStep::NamespaceSync,
            "final-sync" => PublicationStep::FinalSync,
            _ => panic!("unknown publication checkpoint"),
        };
        let _ = writer.finish_with_checkpoint(
            &RelativePath::parse("inputs/content/crash.bin").unwrap(),
            |step| {
                if step == checkpoint {
                    std::process::exit(75);
                }
                Ok(())
            },
        );
        panic!("child unexpectedly returned from publication");
    }

    #[test]
    fn process_exit_at_each_publication_checkpoint_keeps_reconcilable_files() {
        for checkpoint in ["data-sync", "publish", "namespace-sync", "final-sync"] {
            let temp = tempfile::tempdir().unwrap();
            let root_path = temp.path().join("root");
            let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "input_files::tests::input_publication_crash_child",
                    "--nocapture",
                ])
                .env("DISSECT3D_INPUT_CRASH_ROOT", &root_path)
                .env("DISSECT3D_INPUT_CRASH_CHECKPOINT", checkpoint)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(75), "checkpoint {checkpoint}");
            drop(root);
            let reopened = OwnedRoot::open(&root_path, RootPurpose::EngineData).unwrap();
            let staged = RelativePath::parse("inputs/incomplete/crash.part").unwrap();
            let published = RelativePath::parse("inputs/content/crash.bin").unwrap();
            let staged_path = reopened.path_for_native_vfs(&staged);
            let published_path = reopened.path_for_native_vfs(&published);
            let staged_exists = staged_path.exists();
            let published_exists = published_path.exists();

            match checkpoint {
                "data-sync" | "publish" => {
                    assert!(staged_exists, "staging lost at {checkpoint}");
                    assert!(!published_exists, "premature publication at {checkpoint}");
                }
                "namespace-sync" => {
                    assert!(published_exists, "published name missing at {checkpoint}");
                    #[cfg(unix)]
                    assert!(staged_exists, "staging link missing at {checkpoint}");
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        assert_eq!(std::fs::metadata(&published_path).unwrap().nlink(), 2);
                    }
                    #[cfg(windows)]
                    assert!(!staged_exists, "moved staging name remains at {checkpoint}");
                    #[cfg(windows)]
                    assert_eq!(
                        reopened.read_file(&published, 64).unwrap(),
                        b"checkpoint-owned input"
                    );
                }
                "final-sync" => {
                    assert!(!staged_exists, "staging name remains at {checkpoint}");
                    assert!(published_exists, "published name missing at {checkpoint}");
                    assert_eq!(
                        reopened.read_file(&published, 64).unwrap(),
                        b"checkpoint-owned input"
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn publication_barrier_failures_never_issue_a_witness_or_remove_all_evidence() {
        for fault in [
            PublicationStep::DataSync,
            PublicationStep::Publish,
            PublicationStep::NamespaceSync,
            PublicationStep::FinalSync,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root =
                OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData)
                    .unwrap();
            let staged = RelativePath::parse("incomplete/fault.part").unwrap();
            let final_name = RelativePath::parse("content/fault.bin").unwrap();
            let mut writer = root.begin_input(&staged).unwrap();
            writer.write_chunk(b"retained evidence").unwrap();
            let mut reached = false;
            let result = writer.finish_with_checkpoint(&final_name, |step| {
                if step == fault {
                    reached = true;
                    Err(PlatformError::Io)
                } else {
                    Ok(())
                }
            });
            assert!(reached, "fault seam not reached: {fault:?}");
            assert!(matches!(result, Err(PlatformError::Io)));
            // An orphan (possibly with two Unix names) stays conservatively charged.
            assert!(
                root.path().join(staged.as_path()).exists()
                    || root.path().join(final_name.as_path()).exists()
            );
        }
    }

    #[test]
    fn partial_write_failure_poisons_writer_and_prevents_a_witness() {
        let temp = tempfile::tempdir().unwrap();
        let root =
            OwnedRoot::create_private(&temp.path().join("root"), RootPurpose::EngineData).unwrap();
        let staged = RelativePath::parse("incomplete/failed.part").unwrap();
        let final_name = RelativePath::parse("content/failed.bin").unwrap();
        let mut writer = root.begin_input(&staged).unwrap();
        writer.write_chunk(b"first").unwrap();
        assert_eq!(
            writer.write_chunk_using(b"second", |file, bytes| {
                file.write_all(&bytes[..2])?;
                Err(std::io::Error::other("injected short write"))
            }),
            Err(PlatformError::Io)
        );
        assert!(writer.write_chunk(b"retry").is_err());
        assert!(writer.finish(&final_name).is_err());
        assert!(root.file_metadata(&final_name).is_err());
        assert_eq!(root.read_file(&staged, 32).unwrap(), b"firstse");
    }
}
