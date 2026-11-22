//! Publication storage policy. The constants live in
//! `crate::domain::publication_policy`; this module keeps their cross-check test.

#[cfg(all(test, unix))]
use crate::domain::publication_policy::STORAGE_FREE_RESERVE_BYTES;

#[cfg(all(test, unix))]
#[test]
fn free_space_floor_matches_input_capture() {
    assert_eq!(
        STORAGE_FREE_RESERVE_BYTES,
        crate::inputs::policy::STORAGE_FREE_RESERVE_BYTES
    );
}
