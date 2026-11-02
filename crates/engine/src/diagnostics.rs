//! Bounded safe startup diagnostics stored beneath the protected engine root.
//!
//! Records intentionally contain only fixed phase/code values and a timestamp;
//! paths, OS error text, request data, and credentials never enter this file.

use dissect3d_api::{CorrelationId, decode_json};
use dissect3d_platform::{OwnedRoot, PlatformError, RelativePath};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

const DIAGNOSTICS_FILE: &str = "run/diagnostics.json";
const MAX_DIAGNOSTICS_BYTES: usize = 16_384;
const MAX_DIAGNOSTICS_RECORDS: usize = 64;
const REQUEST_LOG_FILE: &str = "run/requests.json";
const MAX_REQUEST_LOG_BYTES: usize = 1_048_576;
const MAX_REQUEST_LOG_FILES: usize = 3;
static REQUEST_LOG_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StartupPhase {
    Root,
    Authority,
    Store,
    Bootstrap,
    Https,
    Discovery,
    Runtime,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
enum StartupCode {
    #[serde(rename = "protected_storage_unavailable")]
    ProtectedStorage,
    #[serde(rename = "authority_unavailable")]
    Authority,
    #[serde(rename = "persistence_unavailable")]
    Persistence,
    #[serde(rename = "bootstrap_unavailable")]
    Bootstrap,
    #[serde(rename = "https_unavailable")]
    Https,
    #[serde(rename = "discovery_unavailable")]
    Discovery,
    #[serde(rename = "runtime_unavailable")]
    Runtime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticRecord {
    timestamp_ms: u64,
    phase: StartupPhase,
    code: StartupCode,
    correlation_id: Option<CorrelationId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestRecord {
    timestamp_ms: u64,
    correlation_id: CorrelationId,
    method: String,
    route: String,
    status: u16,
    error_code: Option<String>,
}

pub(crate) fn record_http_request(
    root: &OwnedRoot,
    correlation_id: CorrelationId,
    method: &'static str,
    route: &'static str,
    status: u16,
    error_code: Option<String>,
) {
    let Ok(_lock) = REQUEST_LOG_LOCK.lock() else {
        return;
    };
    let Some(path) = request_log_path(0) else {
        return;
    };
    let previous = match read_request_records(root, &path) {
        Ok(records) => records,
        Err(()) => return,
    };
    let record = RequestRecord {
        timestamp_ms: timestamp_ms(),
        correlation_id,
        method: method.to_owned(),
        route: route.to_owned(),
        status,
        error_code,
    };
    let mut records = previous.clone();
    records.push_back(record.clone());
    let Ok(encoded) = serde_json::to_vec(&records) else {
        return;
    };
    if encoded.len() <= MAX_REQUEST_LOG_BYTES {
        let _ = root.write_atomic(&path, &encoded);
    } else {
        rotate_request_logs(root, &previous);
        if let Ok(encoded) = serde_json::to_vec(&VecDeque::from([record])) {
            let _ = root.write_atomic(&path, &encoded);
        }
    }
}

fn rotate_request_logs(root: &OwnedRoot, active: &VecDeque<RequestRecord>) {
    for index in (1..MAX_REQUEST_LOG_FILES).rev() {
        let Some(source) = request_log_path(index - 1) else {
            continue;
        };
        let Some(destination) = request_log_path(index) else {
            continue;
        };
        match root.read_file(&source, MAX_REQUEST_LOG_BYTES) {
            Ok(bytes) => {
                let _ = root.write_atomic(&destination, &bytes);
            }
            Err(PlatformError::NotFound) => {
                let _ = root.remove_file(&destination);
            }
            Err(_) => return,
        }
    }
    if let Some(previous) = request_log_path(1)
        && let Ok(bytes) = serde_json::to_vec(active)
    {
        let _ = root.write_atomic(&previous, &bytes);
    }
}

fn request_log_path(index: usize) -> Option<RelativePath> {
    let file = match index {
        0 => REQUEST_LOG_FILE.to_owned(),
        1..=2 => format!("run/requests.{index}.json"),
        _ => return None,
    };
    RelativePath::parse(file).ok()
}

fn read_request_records(
    root: &OwnedRoot,
    path: &RelativePath,
) -> Result<VecDeque<RequestRecord>, ()> {
    match root.read_file(path, MAX_REQUEST_LOG_BYTES) {
        Ok(bytes) => decode_json::<VecDeque<RequestRecord>>(&bytes).map_err(|_| ()),
        Err(PlatformError::NotFound) => Ok(VecDeque::new()),
        Err(_) => Err(()),
    }
}

fn timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

pub(crate) fn record_startup_failure(root: &OwnedRoot, error: crate::StartupError) {
    let (phase, code) = match error {
        crate::StartupError::Root => (StartupPhase::Root, StartupCode::ProtectedStorage),
        crate::StartupError::Authority => (StartupPhase::Authority, StartupCode::Authority),
        crate::StartupError::Store => (StartupPhase::Store, StartupCode::Persistence),
        crate::StartupError::Bootstrap => (StartupPhase::Bootstrap, StartupCode::Bootstrap),
        crate::StartupError::Https => (StartupPhase::Https, StartupCode::Https),
        crate::StartupError::Discovery => (StartupPhase::Discovery, StartupCode::Discovery),
        crate::StartupError::Runtime | crate::StartupError::ShutdownDeadline => {
            (StartupPhase::Runtime, StartupCode::Runtime)
        }
    };
    let record = DiagnosticRecord {
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                duration.as_millis().min(u64::MAX as u128) as u64
            }),
        phase,
        code,
        correlation_id: None,
    };
    let path = match RelativePath::parse(DIAGNOSTICS_FILE) {
        Ok(path) => path,
        Err(_) => return,
    };
    let mut records = match root.read_file(&path, MAX_DIAGNOSTICS_BYTES) {
        Ok(bytes) => match decode_json::<VecDeque<DiagnosticRecord>>(&bytes) {
            Ok(records) => records,
            Err(_) => return,
        },
        Err(PlatformError::NotFound) => VecDeque::new(),
        Err(_) => return,
    };
    records.push_back(record);
    while records.len() > MAX_DIAGNOSTICS_RECORDS {
        records.pop_front();
    }
    while serde_json::to_vec(&records).is_ok_and(|encoded| encoded.len() > MAX_DIAGNOSTICS_BYTES)
        && records.len() > 1
    {
        records.pop_front();
    }
    let Ok(encoded) = serde_json::to_vec(&records) else {
        return;
    };
    if encoded.len() <= MAX_DIAGNOSTICS_BYTES {
        let _ = root.write_atomic(&path, &encoded);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_DIAGNOSTICS_BYTES, MAX_DIAGNOSTICS_RECORDS, MAX_REQUEST_LOG_BYTES, RequestRecord,
        record_http_request, record_startup_failure, request_log_path,
    };
    use crate::StartupError;
    use dissect3d_api::{CorrelationId, decode_json};
    use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose};
    use std::collections::VecDeque;

    #[test]
    fn startup_records_are_bounded_and_contain_only_allowlisted_context() {
        let directory = tempfile::tempdir().expect("temporary root");
        let root =
            OwnedRoot::create_private(&directory.path().join("engine"), RootPurpose::EngineData)
                .expect("protected root");
        for _ in 0..MAX_DIAGNOSTICS_RECORDS + 8 {
            record_startup_failure(&root, StartupError::Https);
        }
        let path = RelativePath::parse("run/diagnostics.json").expect("diagnostic path");
        let bytes = root
            .read_file(&path, MAX_DIAGNOSTICS_BYTES)
            .expect("bounded diagnostics file");
        assert!(bytes.len() <= MAX_DIAGNOSTICS_BYTES);
        let records: VecDeque<serde_json::Value> =
            decode_json(&bytes).expect("strict diagnostics records");
        assert_eq!(records.len(), MAX_DIAGNOSTICS_RECORDS);
        let first = &records[0];
        assert_eq!(first["phase"], "https");
        assert_eq!(first["code"], "https_unavailable");
        assert!(first["correlation_id"].is_null());
        let marker = CorrelationId::parse("corr_ffffffffffffffffffffffffffffffff")
            .expect("secret-like marker");
        assert!(!String::from_utf8_lossy(&bytes).contains(marker.as_str()));
    }

    #[test]
    fn request_records_are_correlated_bounded_and_exclude_request_contents() {
        let directory = tempfile::tempdir().expect("temporary root");
        let root =
            OwnedRoot::create_private(&directory.path().join("engine"), RootPurpose::EngineData)
                .expect("protected root");
        let correlation =
            CorrelationId::parse("corr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("correlation");
        for _ in 0..128 {
            record_http_request(&root, correlation.clone(), "post", "auth_revoke", 200, None);
        }
        let path = RelativePath::parse("run/requests.json").expect("request log path");
        let bytes = root
            .read_file(&path, MAX_REQUEST_LOG_BYTES)
            .expect("request log");
        assert!(bytes.len() <= MAX_REQUEST_LOG_BYTES);
        let records: VecDeque<serde_json::Value> = decode_json(&bytes).expect("strict records");
        assert_eq!(records.len(), 128);
        assert_eq!(records[0]["correlation_id"], correlation.as_str());
        assert_eq!(records[0]["method"], "post");
        assert_eq!(records[0]["route"], "auth_revoke");
        assert_eq!(records[0]["status"], 200);
        let contents = String::from_utf8_lossy(&bytes);
        assert!(!contents.contains("Authorization"));
        assert!(!contents.contains("secret_hex"));
        assert!(!contents.contains("personal/path"));
    }

    #[test]
    fn request_log_rotation_keeps_each_file_within_the_accepted_bound() {
        let directory = tempfile::tempdir().expect("temporary root");
        let root =
            OwnedRoot::create_private(&directory.path().join("engine"), RootPurpose::EngineData)
                .expect("protected root");
        let correlation =
            CorrelationId::parse("corr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").expect("correlation");
        let sample = RequestRecord {
            timestamp_ms: 1,
            correlation_id: correlation.clone(),
            method: "get".to_owned(),
            route: "info".to_owned(),
            status: 200,
            error_code: None,
        };
        let sample_bytes = serde_json::to_vec(&sample).expect("encoded record").len();
        let count = (MAX_REQUEST_LOG_BYTES - 2) / (sample_bytes + 1);
        let existing: VecDeque<RequestRecord> = (0..count).map(|_| sample.clone()).collect();
        let encoded = serde_json::to_vec(&existing).expect("encoded log");
        assert!(encoded.len() <= MAX_REQUEST_LOG_BYTES);
        let active = request_log_path(0).expect("active log path");
        root.write_atomic(&active, &encoded)
            .expect("write full active log");
        record_http_request(&root, correlation, "post", "auth_revoke", 200, None);
        let rotated = root
            .read_file(
                &request_log_path(1).expect("first rotated path"),
                MAX_REQUEST_LOG_BYTES,
            )
            .expect("rotated request history");
        let active = root
            .read_file(
                &request_log_path(0).expect("active log path"),
                MAX_REQUEST_LOG_BYTES,
            )
            .expect("new active log");
        assert!(rotated.len() <= MAX_REQUEST_LOG_BYTES);
        assert!(active.len() <= MAX_REQUEST_LOG_BYTES);
        let latest: VecDeque<serde_json::Value> =
            decode_json(&active).expect("strict active records");
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0]["route"], "auth_revoke");
    }
}
