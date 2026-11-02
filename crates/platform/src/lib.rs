//! Native owner identity, protected roots, atomic files and authority lifetime.
//!
//! This crate centralizes operating-system checks so higher layers can request
//! protected operations without duplicating path, permission, or lock rules.

mod files;
mod identity;
mod ipc;
mod lease;
mod process;
mod root;
#[cfg(windows)]
mod windows;

pub use files::{RelativePath, SafeFileMetadata, open_regular_file};
pub use identity::{OwnerIdentity, current_owner_identity};
pub use ipc::connect as connect_bootstrap;
pub use ipc::{BootstrapEndpoint, BootstrapListener, MAX_BOOTSTRAP_FRAME_BYTES, PeerChannel};
pub use lease::AuthorityLease;
pub use process::{
    ProcessIdentity, ProcessWatcher, current_process_identity, ensure_independent_engine,
    launch_engine, process_matches, wait_for_process_exit,
};
pub use root::{OwnedRoot, PlatformError, RootPurpose};
