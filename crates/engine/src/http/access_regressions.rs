//! 2026-11-24 regression (found during WE-P07): only `POST /v1/jobs` was
//! treated as commit-capable. A linked retry or a cancellation can commit
//! durably before its reply, so a slow one was answered with a fabricated
//! retryable `busy` (WE-P06/5: never fabricate after a possibly committed
//! mutation), and every `/v1/jobs*` diagnostic was labeled `other`.
use super::*;

#[test]
fn every_committing_job_mutation_is_commit_capable() {
    for path in [
        "/v1/jobs",
        "/v1/jobs/job_0123456789abcdef0123456789abcdef/cancel",
        "/v1/jobs/job_0123456789abcdef0123456789abcdef/retry",
    ] {
        assert!(commit_capable(&Method::POST, path), "{path}");
    }
    for (method, path) in [
        (Method::GET, "/v1/jobs"),
        (Method::GET, "/v1/jobs/job_0123456789abcdef0123456789abcdef"),
        (
            Method::GET,
            "/v1/jobs/job_0123456789abcdef0123456789abcdef/retry",
        ),
        (
            Method::POST,
            "/v1/jobs/job_0123456789abcdef0123456789abcdef/other",
        ),
        (
            Method::POST,
            "/v1/jobs/job_0123456789abcdef0123456789abcdef/retry/extra",
        ),
        (Method::POST, "/v1/jobs//retry"),
        (Method::POST, "/v1/inputs"),
    ] {
        assert!(!commit_capable(&method, path), "{method} {path}");
    }
}

#[test]
fn job_routes_have_their_own_diagnostic_labels() {
    let id = "job_0123456789abcdef0123456789abcdef";
    let labels = [
        route_label("/v1/jobs"),
        route_label(&format!("/v1/jobs/{id}")),
        route_label(&format!("/v1/jobs/{id}/cancel")),
        route_label(&format!("/v1/jobs/{id}/retry")),
    ];
    assert_eq!(labels, ["jobs", "job_show", "job_cancel", "job_retry"]);
    assert_eq!(route_label(&format!("/v1/jobs/{id}/other")), "other");
    assert_eq!(route_label("/v1/unknown"), "other");
}
