use super::*;
use std::path::Path;

#[test]
fn build_fixture_manifest_includes_hold_keys_when_present() {
    let out_dir = Path::new("/tmp/dissect3d-out");
    let cli_cfg = Path::new("/tmp/dissect3d-out/client-a.json");
    let cli_bin = Path::new("/tmp/bin/dissect3d");
    let pre_hold = Path::new("/tmp/dissect3d-out/pre-receipt-hold.json");
    let cancel_hold = Path::new("/tmp/dissect3d-out/client-a.json");

    let base = build_fixture_manifest(
        "https://127.0.0.1:49152",
        out_dir,
        cli_cfg,
        cli_bin,
        None,
        None,
    );
    assert_eq!(base["fixture_revision"], "execution-fixture-r1");
    assert_eq!(base["isolated_test_engine"], true);
    assert!(base.get("pre_receipt_hold_cli_config_file").is_none());
    assert!(base.get("cancel_wait_hold_cli_config_file").is_none());

    let full = build_fixture_manifest(
        "https://127.0.0.1:49152",
        out_dir,
        cli_cfg,
        cli_bin,
        Some(pre_hold),
        Some(cancel_hold),
    );
    assert_eq!(
        full["pre_receipt_hold_cli_config_file"],
        "/tmp/dissect3d-out/pre-receipt-hold.json"
    );
    assert_eq!(
        full["cancel_wait_hold_cli_config_file"],
        "/tmp/dissect3d-out/client-a.json"
    );
}

#[test]
fn enroll_and_export_rejects_relative_paths() {
    let rel = Path::new("relative/path");
    let abs = Path::new("/tmp/does-not-exist-d3d");
    assert_eq!(
        enroll_and_export_execution_fixture(rel, abs, None, abs, abs),
        Err(FixtureError::InvalidRoot)
    );
    assert_eq!(
        enroll_and_export_execution_fixture(abs, rel, None, abs, abs),
        Err(FixtureError::InvalidRoot)
    );
    assert_eq!(
        enroll_and_export_execution_fixture(abs, abs, Some(rel), abs, abs),
        Err(FixtureError::InvalidRoot)
    );
    assert_eq!(
        enroll_and_export_execution_fixture(abs, abs, None, rel, abs),
        Err(FixtureError::InvalidRoot)
    );
    assert_eq!(
        enroll_and_export_execution_fixture(abs, abs, None, abs, rel),
        Err(FixtureError::InvalidRoot)
    );
}
