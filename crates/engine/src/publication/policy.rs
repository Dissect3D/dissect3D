//! One source for enforced (and later advertised) publication storage policy
//! (RP-P02/5). Finite engineering defaults for plan review, not measured
//! capacity or performance claims, and not user retention settings. Original
//! input caps are unchanged and retained work is never evicted to make room.

/// Artifact bytes one attempt may prepare: one 1-MiB OBJ for mesh-copy.
pub(crate) const ARTIFACT_BYTES_PER_ATTEMPT_MAX: u64 = 1_048_576;
/// Artifact files one attempt may prepare (the worker schema's candidate bound).
pub(crate) const ARTIFACT_FILES_PER_ATTEMPT_MAX: usize = 16;
/// The canonical manifest's bound (`dissect3d_api::MANIFEST_BYTES_MAX`).
pub(crate) const MANIFEST_BYTES_PER_ATTEMPT_MAX: u64 = dissect3d_api::MANIFEST_BYTES_MAX as u64;
/// Private candidate/preparation/orphan bytes charged at once.
pub(crate) const PRIVATE_BYTES_MAX: u64 = 67_108_864;
/// Retained published bytes, counting every charged private byte as future
/// published content.
pub(crate) const PUBLISHED_BYTES_MAX: u64 = 17_179_869_184;
/// Allocations of every state: published results plus private ones.
pub(crate) const RESULT_RECORDS_MAX: u64 = 65_536;
/// The free-space floor shared with input capture
/// (`inputs::policy::STORAGE_FREE_RESERVE_BYTES`, Unix-only module).
pub(crate) const STORAGE_FREE_RESERVE_BYTES: u64 = 1_073_741_824;
/// Reclamation and reconciliation turn bounds.
pub(crate) const RECLAIM_ENTRIES_PER_TURN: usize = 64;
pub(crate) const RECLAIM_BYTES_PER_TURN: u64 = 1_048_576;

#[cfg(all(test, unix))]
#[test]
fn free_space_floor_matches_input_capture() {
    assert_eq!(
        STORAGE_FREE_RESERVE_BYTES,
        crate::inputs::policy::STORAGE_FREE_RESERVE_BYTES
    );
}
