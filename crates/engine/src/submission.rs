//! Engine-owned bounded admission, equivalence and durable submission orchestration.

#[cfg(unix)]
pub(crate) mod admission;
#[cfg(all(unix, test, feature = "test-support"))]
mod cli_fault_tests;
#[cfg(all(unix, test, feature = "test-support"))]
mod crash_tests;
#[cfg(any(unix, test))]
pub(crate) mod equivalence;
#[cfg_attr(
    windows,
    allow(dead_code, reason = "input admission remains unavailable on Windows")
)]
pub(crate) mod obj;
#[cfg(unix)]
pub(crate) mod service;
#[cfg(all(unix, test))]
pub(crate) mod test_support;

#[cfg(unix)]
mod schema;

#[cfg(unix)]
pub(crate) use crate::domain::SubmissionError;

#[cfg(unix)]
impl From<crate::CoreError> for SubmissionError {
    fn from(error: crate::CoreError) -> Self {
        use dissect3d_api::ErrorCode;
        match error {
            crate::CoreError::Unauthorized => ErrorCode::Unauthorized.into(),
            crate::CoreError::NotFound => ErrorCode::InputUnavailable.into(),
            crate::CoreError::Busy => ErrorCode::Busy.into(),
            crate::CoreError::CapacityExceeded(limit) => Self {
                code: ErrorCode::CapacityExceeded,
                limit: Some(limit),
            },
            _ => ErrorCode::StoreUnavailable.into(),
        }
    }
}

#[cfg(all(unix, test, feature = "test-support"))]
mod execution_submission_tests;
