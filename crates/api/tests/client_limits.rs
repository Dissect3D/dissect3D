//! 2026-11-13 policy regression (`CS-01`, `CS-05`): the shared client's default
//! connect timeout was 2,000 ms while the governing client preference default
//! (`CT-CLI-SURFACE` §2 `connect_timeout_ms`) is 1,000 ms.
#![cfg(feature = "client")]

use dissect3d_api::{ClientLimits, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS};
use std::time::Duration;

#[test]
fn shared_client_defaults_follow_the_cli_surface_contract() {
    assert_eq!(DEFAULT_CONNECT_TIMEOUT_MS, 1_000);
    assert_eq!(DEFAULT_READ_TIMEOUT_MS, 5_000);
    let limits = ClientLimits::default();
    assert_eq!(limits.connect_timeout, Duration::from_millis(1_000));
    assert_eq!(limits.request_timeout, Duration::from_millis(5_000));
    assert_eq!(limits.read_attempts, 1);
}
