//! Core engine authority and durable metadata.
//!
//! The public surface exposes validated authorization records and the bounded
//! store handle; the SQLite schema and actor protocol remain implementation
//! details of this crate.

mod bootstrap;
mod credentials;
mod diagnostics;
mod http;
#[cfg(unix)]
mod inputs;
#[cfg(unix)]
mod jobs;
mod policy;
mod startup;
mod store;
#[cfg(any(unix, test, feature = "test-support"))]
mod submission;
#[cfg(feature = "test-support")]
mod submission_fixture;
pub(crate) mod support;
mod tls;

pub use bootstrap::{BootstrapServeError, serve_bootstrap_once};
pub use credentials::{AuthContext, VerifiedEnrollment};
pub use http::{HttpError, HttpServer};
pub use policy::CorePolicy;
#[cfg(feature = "test-support")]
pub use startup::run_discovery_test_engine;
#[cfg(feature = "test-support")]
pub use startup::run_submission_test_engine;
pub use startup::{StartupError, run_engine};
pub use store::{CoreError, Store, StoreIdentity};
#[cfg(feature = "test-support")]
pub use submission_fixture::{
    FixtureError, prepare_submission_fixture, probe_submission_fixture,
    write_submission_provider_manifest,
};
