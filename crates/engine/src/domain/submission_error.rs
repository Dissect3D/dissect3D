//! The safe submission-path error shared by the store and submission services.

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SubmissionError {
    pub(crate) code: dissect3d_api::ErrorCode,
    pub(crate) limit: Option<&'static str>,
}

#[cfg(unix)]
impl From<dissect3d_api::ErrorCode> for SubmissionError {
    fn from(code: dissect3d_api::ErrorCode) -> Self {
        Self { code, limit: None }
    }
}
