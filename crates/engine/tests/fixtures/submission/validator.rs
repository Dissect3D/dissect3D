//! Registered test-only OBJ validator contract for the prepared CPU fixture.

pub const VALIDATOR_ID: &str = "dissect3d.test.validator";
pub const VALIDATOR_REVISION: &str = "1";

/// The admitted fixture grammar is a bounded positive-index triangular OBJ.
/// The engine implementation performs the full parse; this source records the
/// exact controlled validator identity shipped with the test package.
pub const VALIDATOR_SCOPE: &str = "positive-index-triangular-obj-v1";
