//! Core engine authority and durable metadata.
//!
//! The public surface exposes validated authorization records and the bounded
//! store handle; the SQLite schema and actor protocol remain implementation
//! details of this crate.

mod bootstrap;
mod credentials;
mod diagnostics;
mod http;
mod policy;
mod startup;
mod store;
pub(crate) mod support;
mod tls;

pub use bootstrap::{BootstrapServeError, serve_bootstrap_once};
pub use credentials::{AuthContext, VerifiedEnrollment};
pub use http::{HttpError, HttpServer};
pub use policy::CorePolicy;
#[cfg(feature = "test-support")]
pub use startup::run_discovery_test_engine;
pub use startup::{StartupError, run_engine};
pub use store::{CoreError, Store, StoreIdentity};
