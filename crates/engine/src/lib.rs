//! Core engine authority and durable metadata.
//!
//! The public surface exposes validated authorization records and the bounded
//! store handle; the SQLite schema and actor protocol remain implementation
//! details of this crate.

mod bootstrap;
mod credentials;
mod diagnostics;
mod domain;
#[allow(
    dead_code,
    reason = "WE-P06 composes supervision; dispatch and public routes stay inactive"
)]
mod execution;
#[cfg(any(test, feature = "test-support"))]
#[allow(
    dead_code,
    reason = "WE-P09 composes the explicit r2 test host; dispatch stays inactive"
)]
mod execution_fixture;
mod http;
#[cfg(unix)]
mod inputs;
#[cfg(unix)]
mod jobs;
mod policy;
#[allow(
    dead_code,
    reason = "RP-P02/03 integrate private candidate capture and publication"
)]
mod publication;
mod startup;
mod store;
mod submission;
#[cfg(feature = "test-support")]
mod submission_fixture;
pub(crate) mod support;
mod tls;
#[allow(
    dead_code,
    reason = "WE-P04 supervisor consumes the codec; dispatch stays inactive"
)]
mod worker_protocol;

pub use bootstrap::{BootstrapServeError, serve_bootstrap_once};
pub use credentials::{AuthContext, VerifiedEnrollment};
#[cfg(feature = "test-support")]
pub use execution_fixture::preparation::prepare_execution_fixture;
#[cfg(feature = "test-support")]
pub use execution_fixture::run_execution_fixture_worker;
pub use http::{HttpError, HttpServer};
pub use policy::CorePolicy;
#[cfg(feature = "test-support")]
pub use startup::run_discovery_test_engine;
#[cfg(feature = "test-support")]
pub use startup::run_selection_test_engine;
#[cfg(feature = "test-support")]
pub use startup::run_submission_test_engine;
pub use startup::{StartupError, run_engine};
pub use store::{CoreError, Store, StoreIdentity};
#[cfg(feature = "test-support")]
pub use submission_fixture::{
    FixtureError, prepare_submission_fixture, probe_submission_fixture,
    write_submission_provider_manifest,
};
