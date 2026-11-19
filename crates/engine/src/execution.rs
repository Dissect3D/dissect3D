//! Supervised worker execution (WE-P04). Dispatch and public routes stay
//! inactive: no service composes this yet (WE-P06 owns activation).
//!
//! `legality` is the pure session state machine, `progress` the pure
//! coalescer, `supervisor` owns one process and its timers, `launcher` is the
//! native contained launch, and `types` holds the supervisor's results. Store
//! finalization lives in `store::finalize`.
pub(crate) mod launcher;
pub(crate) mod legality;
pub(crate) mod progress;
pub(crate) mod supervisor;
pub(crate) mod types;

#[cfg(test)]
#[path = "execution/fake_worker.rs"]
mod fake_worker;
#[cfg(test)]
#[path = "execution/legality_tests.rs"]
mod legality_tests;
#[cfg(test)]
#[path = "execution/process_fixture_tests.rs"]
mod process_fixture_tests;
#[cfg(test)]
#[path = "execution/supervisor_tests.rs"]
mod supervisor_tests;
