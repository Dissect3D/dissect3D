//! Native process owner identity values.
//!
//! Enrollment binds to the operating-system identity observed by the engine,
//! not a client-provided username or a value inferred from configuration.

use crate::PlatformError;

/// Opaque operating-system owner identity used by native enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerIdentity {
    UnixUid(u32),
    WindowsSid(Vec<u8>),
}

/// Return the effective native owner identity for this process.
pub fn current_owner_identity() -> Result<OwnerIdentity, PlatformError> {
    #[cfg(unix)]
    {
        let uid = rustix::process::geteuid().as_raw();
        Ok(OwnerIdentity::UnixUid(uid))
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            crate::windows::current_owner_identity()
        }
        #[cfg(not(windows))]
        {
            Err(PlatformError::UnsupportedRoot)
        }
    }
}
