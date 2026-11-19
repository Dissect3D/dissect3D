//! Controlled CPU worker for `test.mesh-copy@fixture-r2` (test-only). The
//! engine launches it contained, with private control pipes and inherited
//! read-only inputs; it has no public listener and is never run by hand.
fn main() {
    dissect3d_engine::run_execution_fixture_worker()
}
