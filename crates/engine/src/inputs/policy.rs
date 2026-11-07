//! One source for enforced and advertised input-capture policy.

use dissect3d_api::SubmissionCapability;
use std::collections::BTreeMap;
use std::time::Duration;

pub(crate) const MAX_INPUT_BYTES: u64 = 268_435_456;
pub(crate) const MAX_UPLOADS: i64 = 2;
pub(crate) const MAX_STAGING_BYTES: u64 = 2_147_483_648;
pub(crate) const MAX_INPUT_ROWS: i64 = 1_024;
pub(crate) const UPLOAD_TTL_MS: i64 = 86_400_000;
pub(crate) const UPLOAD_METADATA_RESERVE_BYTES: u64 = 4_194_304;
pub(crate) const STORAGE_FREE_RESERVE_BYTES: u64 = 1_073_741_824;
pub(super) const MAX_CHUNK_BYTES: usize = 65_536;
pub(super) const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
// Error cleanup may use the existing outer request slack. This never extends
// the deadline for producing an input receipt.
pub(crate) const UPLOAD_CLEANUP_GRACE: Duration = Duration::from_secs(2);
pub(crate) const UPLOAD_REQUEST_TIMEOUT: Duration =
    UPLOAD_TOTAL_TIMEOUT.saturating_add(UPLOAD_CLEANUP_GRACE);

pub(crate) fn capability() -> SubmissionCapability {
    SubmissionCapability {
        version: "1.0".to_owned(),
        dispatch_enabled: false,
        operations: vec!["inputs.create".to_owned()],
        limits: BTreeMap::from([
            ("input_bytes_max".to_owned(), MAX_INPUT_BYTES),
            ("upload_concurrency_max".to_owned(), MAX_UPLOADS as u64),
            ("staging_reserved_bytes_max".to_owned(), MAX_STAGING_BYTES),
            ("staged_input_ttl_ms".to_owned(), UPLOAD_TTL_MS as u64),
            (
                "upload_idle_timeout_ms".to_owned(),
                UPLOAD_IDLE_TIMEOUT.as_millis() as u64,
            ),
            (
                "upload_total_timeout_ms".to_owned(),
                UPLOAD_TOTAL_TIMEOUT.as_millis() as u64,
            ),
            ("staged_input_records_max".to_owned(), MAX_INPUT_ROWS as u64),
            (
                "storage_free_reserve_bytes".to_owned(),
                STORAGE_FREE_RESERVE_BYTES,
            ),
            (
                "upload_metadata_reserve_bytes".to_owned(),
                UPLOAD_METADATA_RESERVE_BYTES,
            ),
        ]),
        limits_source: "built_in".to_owned(),
    }
}
