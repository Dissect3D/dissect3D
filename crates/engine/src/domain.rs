//! Shared engine vocabulary below the store.
//!
//! Items here are used by both the store and the services above it, so neither
//! owns them. This module depends only on `dissect3d-api` and the standard
//! library; it must not import the store or any service module.
//! `submission::SubmissionError` and `inputs::policy` re-export their items;
//! publication callers import `domain::publication_policy` directly.

#[cfg(unix)]
pub(crate) mod input_policy;
#[allow(
    dead_code,
    reason = "RP-P02/03 integrate private candidate capture and publication"
)]
pub(crate) mod publication_policy;
mod submission_error;

#[cfg(unix)]
pub(crate) use submission_error::SubmissionError;
