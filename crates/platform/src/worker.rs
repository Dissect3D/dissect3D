//! Native ownership for a single controlled worker. Never uses engine breakaway.
use crate::{PlatformError, ProcessIdentity};
use std::ffi::OsString;
use std::path::PathBuf;
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
            if key.is_empty()
                || key.as_encoded_bytes().contains(&b'=')
                || !keys.insert(key.to_string_lossy().to_uppercase())
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
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    native: native::Worker,
}

impl WorkerProcess {
    pub fn launch(command: WorkerCommand, session_nonce: [u8; 16]) -> Result<Self, PlatformError> {
        command.validate()?;
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            let (native, process, guardian) = native::Worker::launch(command)?;
            Ok(Self {
                native,
                identity: WorkerIdentity {
                    process,
                    guardian,
                    session_nonce,
                },
                confirmed: false,
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
