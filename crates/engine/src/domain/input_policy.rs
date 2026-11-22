//! Enforced input-capture capacity limits shared by the store and input capture.
//! `inputs::policy` re-exports them and advertises them in the capability.

pub(crate) const MAX_INPUT_BYTES: u64 = 268_435_456;
pub(crate) const MAX_UPLOADS: i64 = 2;
pub(crate) const MAX_STAGING_BYTES: u64 = 2_147_483_648;
pub(crate) const MAX_INPUT_ROWS: i64 = 1_024;
pub(crate) const UPLOAD_TTL_MS: i64 = 86_400_000;
pub(crate) const UPLOAD_METADATA_RESERVE_BYTES: u64 = 4_194_304;
pub(crate) const STORAGE_FREE_RESERVE_BYTES: u64 = 1_073_741_824;
