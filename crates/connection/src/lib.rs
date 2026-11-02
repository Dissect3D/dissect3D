//! Shared discovery and readiness orchestration for local engine clients.
//!
//! This crate owns neither profiles nor API credentials. It validates protected
//! discovery, verifies process identity, and probes the platform bootstrap
//! channel before returning an authority. API transport remains in `dissect3d-api`.

use dissect3d_api::{BootstrapAddress, DiscoveryRecord, decode_json};
use dissect3d_platform::{
    BootstrapEndpoint, OwnedRoot, PlatformError, RelativePath, connect_bootstrap,
    current_owner_identity, process_matches,
};
use serde::Deserialize;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const DESCRIPTOR: &str = "run/endpoint.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadinessError {
    Unavailable,
    InvalidDiscovery,
    Incompatible,
    Deadline,
}

/// Discovery that has passed owner, descriptor, process and native probe checks.
pub struct VerifiedEngine {
    pub discovery: DiscoveryRecord,
}

/// Validate protected discovery and prove that the described core service is ready.
///
/// `root` must already be opened using the platform's owner and permission checks.
/// The supplied timeout bounds native channel connection and frame I/O.
pub fn verify_engine(
    root: &OwnedRoot,
    timeout: Duration,
) -> Result<VerifiedEngine, ReadinessError> {
    let path = RelativePath::parse(DESCRIPTOR).map_err(|_| ReadinessError::InvalidDiscovery)?;
    let bytes = root
        .read_file(&path, 65_536)
        .map_err(|_| ReadinessError::Unavailable)?;
    let discovery: DiscoveryRecord =
        decode_json(&bytes).map_err(|_| ReadinessError::InvalidDiscovery)?;
    if discovery.discovery_version != "1.0"
        || discovery.trust_anchor_der.is_empty()
        || discovery.trust_anchor_der.len() > 65_536
        || discovery.trust_anchor_sha256.len() != 32
        || !valid_base_url(&discovery.base_url)
    {
        return Err(ReadinessError::InvalidDiscovery);
    }
    if discovery.process.pid == 0 || discovery.process.start_marker.is_empty() {
        return Err(ReadinessError::InvalidDiscovery);
    }
    let process = dissect3d_platform::ProcessIdentity {
        pid: discovery.process.pid,
        start_marker: discovery.process.start_marker.clone(),
    };
    if !process_matches(&process).map_err(|_| ReadinessError::Unavailable)? {
        return Err(ReadinessError::Unavailable);
    }

    let endpoint = match &discovery.bootstrap_endpoint {
        BootstrapAddress::Unix { path } => {
            let expected = root.path_for_native_vfs(
                &RelativePath::parse("run/bootstrap.sock")
                    .map_err(|_| ReadinessError::InvalidDiscovery)?,
            );
            if Path::new(path) != expected {
                return Err(ReadinessError::InvalidDiscovery);
            }
            BootstrapEndpoint::Unix { path: expected }
        }
        BootstrapAddress::WindowsPipe { name } => {
            let suffix = discovery
                .instance_id
                .as_str()
                .strip_prefix("eng_")
                .ok_or(ReadinessError::InvalidDiscovery)?;
            if name != &format!("\\\\.\\pipe\\dissect3d-bootstrap-{suffix}") {
                return Err(ReadinessError::InvalidDiscovery);
            }
            BootstrapEndpoint::WindowsPipe { name: name.clone() }
        }
    };
    let owner = current_owner_identity().map_err(|_| ReadinessError::Unavailable)?;
    let mut channel =
        connect_bootstrap(&endpoint, &owner, timeout).map_err(|_| ReadinessError::Unavailable)?;
    let request = serde_json::json!({
        "kind": "probe",
        "bootstrap_version": "1.0",
        "instance_id": discovery.instance_id,
    });
    let encoded = serde_json::to_vec(&request).map_err(|_| ReadinessError::InvalidDiscovery)?;
    channel
        .write_frame(&encoded)
        .map_err(|_| ReadinessError::Unavailable)?;
    let response = channel
        .read_frame()
        .map_err(|_| ReadinessError::Unavailable)?;
    let receipt: ProbeReceipt = decode_json(&response).map_err(|_| ReadinessError::Incompatible)?;
    if receipt.bootstrap_version != "1.0"
        || !receipt.ready
        || receipt.installation_id != discovery.installation_id
        || receipt.instance_id != discovery.instance_id
    {
        return Err(ReadinessError::Incompatible);
    }
    Ok(VerifiedEngine { discovery })
}

/// Observe readiness with a single monotonic deadline and bounded probe calls.
///
/// Each probe receives no more time than remains in the total budget. Poll delay
/// is also clamped, and no result other than a successful verified probe is ready.
pub fn observe_readiness<T>(
    timeout: Duration,
    poll_interval: Duration,
    mut probe: impl FnMut(Duration) -> Result<T, ReadinessError>,
) -> Result<T, ReadinessError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReadinessError::Deadline);
        }
        match probe(remaining) {
            Ok(ready) => return Ok(ready),
            Err(ReadinessError::Unavailable) => {}
            Err(error) => return Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReadinessError::Deadline);
        }
        thread::sleep(poll_interval.min(remaining));
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeReceipt {
    bootstrap_version: String,
    installation_id: dissect3d_api::InstallationId,
    instance_id: dissect3d_api::InstanceId,
    ready: bool,
}

fn valid_base_url(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some_and(|port| port != 0)
        && url.path() == "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

impl From<PlatformError> for ReadinessError {
    fn from(_: PlatformError) -> Self {
        Self::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::{ReadinessError, observe_readiness};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[test]
    fn readiness_requires_a_successful_probe() {
        let attempts = AtomicUsize::new(0);
        let ready = observe_readiness(Duration::from_secs(1), Duration::from_millis(1), |_| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(ReadinessError::Unavailable)
            } else {
                Ok("verified")
            }
        })
        .expect("successful probe");
        assert_eq!(ready, "verified");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn observation_clamps_slow_probe_and_poll_delay_to_one_deadline() {
        let started = Instant::now();
        let result = observe_readiness(
            Duration::from_millis(80),
            Duration::from_secs(1),
            |budget| {
                std::thread::sleep(budget.min(Duration::from_millis(25)));
                Err::<(), _>(ReadinessError::Unavailable)
            },
        );
        let elapsed = started.elapsed();
        assert_eq!(result, Err(ReadinessError::Deadline));
        assert!(elapsed >= Duration::from_millis(70), "elapsed: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(300), "elapsed: {elapsed:?}");
    }
}
