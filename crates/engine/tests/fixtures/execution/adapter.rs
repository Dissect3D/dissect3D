//! Recorded adapter for `test.mesh-copy@fixture-r2`, compiled into the
//! controlled CPU worker (`execution_fixture`). It copies the scoped input
//! mesh bytes unchanged; the engine validates the output independently.

/// The adapter identity the worker announces in `hello`.
pub const ADAPTER_ID: &str = "dissect3d.fixture.adapter";
pub const ADAPTER_REVISION: &str = "fixture-r2";

/// Copy the captured mesh bytes into the candidate output.
pub fn copy_mesh(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}
