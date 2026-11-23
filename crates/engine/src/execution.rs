//! Supervised worker execution (WE-P04, WE-P06). Only the explicit
//! `test-support` execution host composes the controller and its routes; the
//! normal engine keeps dispatch inactive.
//!
//! `legality` is the pure session state machine, `progress` the pure
//! coalescer, `supervisor` owns one process and its timers, `launcher` is the
//! native contained launch, and `types` holds the supervisor's results.
//! `scheduler` is one dispatch turn, `controller` the single owner of
//! turns, attempt launch and outcome routing, `loaded` the workers it holds
//! loaded, `shutdown` the shared shutdown deadline, and `control` job
//! cancellation. Store finalization lives in
//! `store::finalize`.
pub(crate) mod attempt_files;
// The submission services it uses are Unix-only until B-WINDOWS wiring.
#[cfg(unix)]
pub(crate) mod control;
pub(crate) mod controller;
pub(crate) mod launcher;
pub(crate) mod legality;
pub(crate) mod loaded;
pub(crate) mod progress;
// Restart reconciliation; only the Unix execution host composes it.
#[cfg(all(unix, feature = "test-support"))]
pub(crate) mod recovery;
pub(crate) mod scheduler;
pub(crate) mod shutdown;
pub(crate) mod supervisor;
pub(crate) mod types;

#[cfg(test)]
#[path = "execution/fake_worker.rs"]
pub(crate) mod fake_worker;
#[cfg(test)]
#[path = "execution/legality_tests.rs"]
mod legality_tests;
#[cfg(test)]
#[path = "execution/process_fixture_tests.rs"]
mod process_fixture_tests;
#[cfg(test)]
#[path = "execution/r2_worker_tests.rs"]
mod r2_worker_tests;
#[cfg(test)]
#[path = "execution/scheduler_tests.rs"]
mod scheduler_tests;
#[cfg(test)]
#[path = "execution/supervisor_tests.rs"]
pub(crate) mod supervisor_tests;
