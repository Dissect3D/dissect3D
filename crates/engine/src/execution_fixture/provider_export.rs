//! Test-support export of `DISSECT3D_EXECUTION_FIXTURE` (`D1`, `WE-P08.1`,
//! `WE-P09`).
//!
//! Supports both `write-provider-fixture` (base keys from two pre-enrolled
//! profiles) and `enroll-and-export` (real CLI native-bootstrap enrollment and
//! full `execution-fixture-r1` export including `pre_receipt_hold_cli_config_file`
//! and `cancel_wait_hold_cli_config_file` with owner-only `0600`/`0700`
//! permissions). Never depends on `dissect3d-cli` and never edits SQLite.

#[cfg(test)]
#[path = "provider_export_tests.rs"]
mod tests;

use crate::submission_fixture::FixtureError;
use dissect3d_api::{ClientId, EnrollmentId, InstallationId, InstanceId};
use dissect3d_platform::{OwnedRoot, PlatformError, RelativePath, RootPurpose};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SUPPORT_REF: &str = "test.mesh-copy@fixture-r2";
const RUNTIME_REF: &str = "test.cpu@fixture-r2";
const CA_FILE: &str = "installation-ca.pem";
const CLIENT_A_TOKEN_FILE: &str = "client-a.token";
const CLIENT_B_TOKEN_FILE: &str = "client-b.token";
const CLIENT_A_CONFIG_FILE: &str = "client-a.json";
const CLIENT_B_CONFIG_FILE: &str = "client-b.json";
const PRE_RECEIPT_HOLD_CONFIG_FILE: &str = "pre-receipt-hold.json";
const CANCEL_WAIT_HOLD_CONFIG_FILE: &str = "cancel-wait-hold.json";
const REPORT_LIMIT: usize = 65_536;
const ENROLL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CliConfig {
    #[serde(default)]
    preferences: Option<Value>,
    #[serde(default)]
    connection: Option<ConnectionConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionConfig {
    #[serde(default)]
    data_root: Option<String>,
    #[serde(default)]
    engine_binary: Option<String>,
    #[serde(default)]
    credential_file: Option<String>,
    #[serde(default)]
    installation_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileCredential {
    installation_id: InstallationId,
    instance_id: InstanceId,
    client_id: ClientId,
    enrollment_id: EnrollmentId,
    secret_hex: String,
    state: String,
    #[serde(default)]
    submission_access: bool,
    #[serde(default)]
    execution_access: bool,
}

impl Drop for ProfileCredential {
    fn drop(&mut self) {
        let mut secret = std::mem::take(&mut self.secret_hex).into_bytes();
        secret.fill(0);
    }
}

/// Export a base `execution-fixture-r1` JSON file and its owner-only token/CA
/// files from a live `execution_test_host` and two already-enrolled profiles.
pub fn write_execution_provider_fixture(
    data_root: &Path,
    config_a: &Path,
    config_b: &Path,
    cli_binary: &Path,
    output: &Path,
) -> Result<(), FixtureError> {
    if !data_root.is_absolute()
        || !config_a.is_absolute()
        || !config_b.is_absolute()
        || !cli_binary.is_absolute()
        || !output.is_absolute()
    {
        return Err(FixtureError::InvalidRoot);
    }
    let engine_root = OwnedRoot::open(data_root, RootPurpose::EngineData)
        .map_err(|_| FixtureError::InvalidRoot)?;
    let canonical_data_root =
        std::fs::canonicalize(data_root).map_err(|_| FixtureError::InvalidRoot)?;
    let verified = dissect3d_connection::verify_engine(&engine_root, Duration::from_secs(5))
        .map_err(|_| FixtureError::Provider)?;
    let discovery = verified.discovery;

    let canonical_config_a = canonical_regular_file(config_a)?;
    let canonical_config_b = canonical_regular_file(config_b)?;
    let canonical_cli = canonical_regular_file(cli_binary)?;

    let cred_a = load_profile_credential(&canonical_data_root, &canonical_config_a)?;
    let cred_b = load_profile_credential(&canonical_data_root, &canonical_config_b)?;
    validate_credentials(&discovery, &cred_a, &cred_b)?;

    let output_parent = output.parent().ok_or(FixtureError::InvalidRoot)?;
    let output_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(FixtureError::InvalidRoot)?;
    if matches!(
        output_name,
        CA_FILE | CLIENT_A_TOKEN_FILE | CLIENT_B_TOKEN_FILE
    ) {
        return Err(FixtureError::InvalidRoot);
    }
    let output_rel =
        RelativePath::parse(output_name.to_owned()).map_err(|_| FixtureError::InvalidRoot)?;
    let output_root = if output_parent.exists() {
        OwnedRoot::open(output_parent, RootPurpose::ClientConfig)
    } else {
        OwnedRoot::create_private(output_parent, RootPurpose::ClientConfig)
    }
    .map_err(|_| FixtureError::Storage)?;
    let canonical_out_dir =
        std::fs::canonicalize(output_parent).map_err(|_| FixtureError::Storage)?;

    let paths = [
        output_name,
        CA_FILE,
        CLIENT_A_TOKEN_FILE,
        CLIENT_B_TOKEN_FILE,
    ];
    for name in paths {
        let rel = RelativePath::parse(name.to_owned()).map_err(|_| FixtureError::InvalidRoot)?;
        match output_root.file_metadata(&rel) {
            Err(PlatformError::NotFound) => {}
            Ok(_) => return Err(FixtureError::AlreadyExported),
            Err(_) => return Err(FixtureError::Storage),
        }
    }

    let ca_bytes = encode_certificate_pem(&discovery.trust_anchor_der)?;
    let manifest = json!({
        "fixture_revision": "execution-fixture-r1",
        "isolated_test_engine": true,
        "base_url": discovery.base_url,
        "ca_file": canonical_out_dir.join(CA_FILE),
        "credential_file": canonical_out_dir.join(CLIENT_A_TOKEN_FILE),
        "other_credential_file": canonical_out_dir.join(CLIENT_B_TOKEN_FILE),
        "cli_config_file": canonical_config_a,
        "cli_binary": canonical_cli,
        "support_ref": SUPPORT_REF,
        "runtime_ref": RUNTIME_REF,
        "request_timeout_seconds": 5,
        "completion_timeout_seconds": 30,
    });
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|_| FixtureError::Provider)?;
    if manifest_bytes.len() > REPORT_LIMIT {
        manifest_bytes.fill(0);
        return Err(FixtureError::Provider);
    }

    let export_result = (|| {
        output_root
            .write_atomic(
                &RelativePath::parse(CA_FILE.to_owned()).map_err(|_| FixtureError::Storage)?,
                &ca_bytes,
            )
            .map_err(|_| FixtureError::Storage)?;
        write_token_file(&output_root, CLIENT_A_TOKEN_FILE, &cred_a)?;
        write_token_file(&output_root, CLIENT_B_TOKEN_FILE, &cred_b)?;
        output_root
            .write_atomic(&output_rel, &manifest_bytes)
            .map_err(|_| FixtureError::Storage)?;
        Ok(())
    })();
    manifest_bytes.fill(0);
    if let Err(error) = export_result {
        for name in paths.into_iter().rev() {
            if let Ok(rel) = RelativePath::parse(name.to_owned()) {
                let _ = output_root.remove_file(&rel);
            }
        }
        return Err(error);
    }
    Ok(())
}

/// Enroll real execution-policy CLI profiles against live `execution_test_host`
/// instances and export a complete `execution-fixture-r1` JSON file including
/// `pre_receipt_hold_cli_config_file` and `cancel_wait_hold_cli_config_file`
/// (`WE-P09`, `fixture-contract.md`).
///
/// When `cancel_wait_hold_data_root` is `None`, `cancel_wait_hold_cli_config_file`
/// points to client A's config on `data_root` (which must be started with
/// `--cancel-wait-hold-ms`) so provider-side polling on `base_url` observes the
/// running and `cancel_requested` states as required by `WE-S17`.
pub fn enroll_and_export_execution_fixture(
    data_root: &Path,
    pre_receipt_hold_data_root: &Path,
    cancel_wait_hold_data_root: Option<&Path>,
    cli_binary: &Path,
    output: &Path,
) -> Result<(), FixtureError> {
    if !data_root.is_absolute()
        || !pre_receipt_hold_data_root.is_absolute()
        || cancel_wait_hold_data_root.is_some_and(|root| !root.is_absolute())
        || !cli_binary.is_absolute()
        || !output.is_absolute()
    {
        return Err(FixtureError::InvalidRoot);
    }

    let engine_root = OwnedRoot::open(data_root, RootPurpose::EngineData)
        .map_err(|_| FixtureError::InvalidRoot)?;
    let canonical_data_root =
        std::fs::canonicalize(data_root).map_err(|_| FixtureError::InvalidRoot)?;
    let primary_discovery =
        dissect3d_connection::verify_engine(&engine_root, Duration::from_secs(5))
            .map_err(|_| FixtureError::Provider)?
            .discovery;

    let pre_receipt_root = OwnedRoot::open(pre_receipt_hold_data_root, RootPurpose::EngineData)
        .map_err(|_| FixtureError::InvalidRoot)?;
    let canonical_pre_receipt_root =
        std::fs::canonicalize(pre_receipt_hold_data_root).map_err(|_| FixtureError::InvalidRoot)?;
    if canonical_pre_receipt_root == canonical_data_root {
        return Err(FixtureError::InvalidRoot);
    }
    let pre_receipt_discovery =
        dissect3d_connection::verify_engine(&pre_receipt_root, Duration::from_secs(5))
            .map_err(|_| FixtureError::Provider)?
            .discovery;

    let separate_cancel_wait = match cancel_wait_hold_data_root {
        Some(cancel_root_path) => {
            let cancel_root = OwnedRoot::open(cancel_root_path, RootPurpose::EngineData)
                .map_err(|_| FixtureError::InvalidRoot)?;
            let canonical_cancel_root =
                std::fs::canonicalize(cancel_root_path).map_err(|_| FixtureError::InvalidRoot)?;
            let discovery =
                dissect3d_connection::verify_engine(&cancel_root, Duration::from_secs(5))
                    .map_err(|_| FixtureError::Provider)?
                    .discovery;
            Some((canonical_cancel_root, discovery))
        }
        None => None,
    };

    let canonical_cli = canonical_regular_file(cli_binary)?;

    let output_parent = output.parent().ok_or(FixtureError::InvalidRoot)?;
    let output_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(FixtureError::InvalidRoot)?;
    if matches!(
        output_name,
        CA_FILE
            | CLIENT_A_TOKEN_FILE
            | CLIENT_B_TOKEN_FILE
            | CLIENT_A_CONFIG_FILE
            | CLIENT_B_CONFIG_FILE
            | PRE_RECEIPT_HOLD_CONFIG_FILE
            | CANCEL_WAIT_HOLD_CONFIG_FILE
    ) {
        return Err(FixtureError::InvalidRoot);
    }
    let output_rel =
        RelativePath::parse(output_name.to_owned()).map_err(|_| FixtureError::InvalidRoot)?;
    let output_root = if output_parent.exists() {
        OwnedRoot::open(output_parent, RootPurpose::ClientConfig)
    } else {
        OwnedRoot::create_private(output_parent, RootPurpose::ClientConfig)
    }
    .map_err(|_| FixtureError::Storage)?;
    let canonical_out_dir =
        std::fs::canonicalize(output_parent).map_err(|_| FixtureError::Storage)?;

    let mut reserved_files = vec![
        output_name,
        CA_FILE,
        CLIENT_A_TOKEN_FILE,
        CLIENT_B_TOKEN_FILE,
        CLIENT_A_CONFIG_FILE,
        CLIENT_B_CONFIG_FILE,
        PRE_RECEIPT_HOLD_CONFIG_FILE,
    ];
    if separate_cancel_wait.is_some() {
        reserved_files.push(CANCEL_WAIT_HOLD_CONFIG_FILE);
    }
    for name in &reserved_files {
        let rel = RelativePath::parse((*name).to_owned()).map_err(|_| FixtureError::InvalidRoot)?;
        match output_root.file_metadata(&rel) {
            Err(PlatformError::NotFound) => {}
            Ok(_) => return Err(FixtureError::AlreadyExported),
            Err(_) => return Err(FixtureError::Storage),
        }
    }

    let export_result = (|| {
        write_profile_config(&output_root, CLIENT_A_CONFIG_FILE, &canonical_data_root)?;
        write_profile_config(&output_root, CLIENT_B_CONFIG_FILE, &canonical_data_root)?;
        write_profile_config(
            &output_root,
            PRE_RECEIPT_HOLD_CONFIG_FILE,
            &canonical_pre_receipt_root,
        )?;
        if let Some((canonical_cancel_root, _)) = &separate_cancel_wait {
            write_profile_config(
                &output_root,
                CANCEL_WAIT_HOLD_CONFIG_FILE,
                canonical_cancel_root,
            )?;
        }

        let config_a = canonical_out_dir.join(CLIENT_A_CONFIG_FILE);
        let config_b = canonical_out_dir.join(CLIENT_B_CONFIG_FILE);
        let pre_receipt_config = canonical_out_dir.join(PRE_RECEIPT_HOLD_CONFIG_FILE);
        let cancel_wait_config = if separate_cancel_wait.is_some() {
            canonical_out_dir.join(CANCEL_WAIT_HOLD_CONFIG_FILE)
        } else {
            config_a.clone()
        };

        enroll_profile_via_cli(&canonical_cli, &config_a)?;
        enroll_profile_via_cli(&canonical_cli, &config_b)?;
        enroll_profile_via_cli(&canonical_cli, &pre_receipt_config)?;
        if separate_cancel_wait.is_some() {
            enroll_profile_via_cli(&canonical_cli, &cancel_wait_config)?;
        }

        let cred_a = load_profile_credential(&canonical_data_root, &config_a)?;
        let cred_b = load_profile_credential(&canonical_data_root, &config_b)?;
        validate_credentials(&primary_discovery, &cred_a, &cred_b)?;

        let cred_pre_receipt =
            load_profile_credential(&canonical_pre_receipt_root, &pre_receipt_config)?;
        validate_single_credential(&pre_receipt_discovery, &cred_pre_receipt)?;

        if let Some((canonical_cancel_root, cancel_discovery)) = &separate_cancel_wait {
            let cred_cancel = load_profile_credential(canonical_cancel_root, &cancel_wait_config)?;
            validate_single_credential(cancel_discovery, &cred_cancel)?;
        }

        let ca_bytes = encode_certificate_pem(&primary_discovery.trust_anchor_der)?;
        let manifest = build_fixture_manifest(
            &primary_discovery.base_url,
            &canonical_out_dir,
            &config_a,
            &canonical_cli,
            Some(&pre_receipt_config),
            Some(&cancel_wait_config),
        );
        let mut manifest_bytes =
            serde_json::to_vec_pretty(&manifest).map_err(|_| FixtureError::Provider)?;
        if manifest_bytes.len() > REPORT_LIMIT {
            manifest_bytes.fill(0);
            return Err(FixtureError::Provider);
        }

        let write_result = (|| {
            output_root
                .write_atomic(
                    &RelativePath::parse(CA_FILE.to_owned()).map_err(|_| FixtureError::Storage)?,
                    &ca_bytes,
                )
                .map_err(|_| FixtureError::Storage)?;
            write_token_file(&output_root, CLIENT_A_TOKEN_FILE, &cred_a)?;
            write_token_file(&output_root, CLIENT_B_TOKEN_FILE, &cred_b)?;
            output_root
                .write_atomic(&output_rel, &manifest_bytes)
                .map_err(|_| FixtureError::Storage)?;
            Ok(())
        })();
        manifest_bytes.fill(0);
        write_result
    })();

    if let Err(error) = export_result {
        for name in reserved_files.into_iter().rev() {
            if let Ok(rel) = RelativePath::parse(name.to_owned()) {
                let _ = output_root.remove_file(&rel);
            }
        }
        return Err(error);
    }
    Ok(())
}

fn build_fixture_manifest(
    base_url: &str,
    out_dir: &Path,
    cli_config: &Path,
    cli_binary: &Path,
    pre_receipt_hold_config: Option<&Path>,
    cancel_wait_hold_config: Option<&Path>,
) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("fixture_revision".into(), json!("execution-fixture-r1"));
    map.insert("isolated_test_engine".into(), json!(true));
    map.insert("base_url".into(), json!(base_url));
    map.insert("ca_file".into(), json!(out_dir.join(CA_FILE)));
    map.insert(
        "credential_file".into(),
        json!(out_dir.join(CLIENT_A_TOKEN_FILE)),
    );
    map.insert(
        "other_credential_file".into(),
        json!(out_dir.join(CLIENT_B_TOKEN_FILE)),
    );
    map.insert("cli_config_file".into(), json!(cli_config));
    map.insert("cli_binary".into(), json!(cli_binary));
    map.insert("support_ref".into(), json!(SUPPORT_REF));
    map.insert("runtime_ref".into(), json!(RUNTIME_REF));
    map.insert("request_timeout_seconds".into(), json!(5));
    map.insert("completion_timeout_seconds".into(), json!(30));
    if let Some(path) = pre_receipt_hold_config {
        map.insert("pre_receipt_hold_cli_config_file".into(), json!(path));
    }
    if let Some(path) = cancel_wait_hold_config {
        map.insert("cancel_wait_hold_cli_config_file".into(), json!(path));
    }
    Value::Object(map)
}

fn write_profile_config(
    output_root: &OwnedRoot,
    name: &str,
    canonical_data_root: &Path,
) -> Result<(), FixtureError> {
    let data_root_str = canonical_data_root
        .to_str()
        .ok_or(FixtureError::InvalidRoot)?;
    let bytes = serde_json::to_vec_pretty(&json!({
        "connection": {
            "data_root": data_root_str,
        }
    }))
    .map_err(|_| FixtureError::Provider)?;
    let rel = RelativePath::parse(name.to_owned()).map_err(|_| FixtureError::Storage)?;
    output_root
        .write_atomic(&rel, &bytes)
        .map_err(|_| FixtureError::Storage)
}

fn enroll_profile_via_cli(cli_binary: &Path, config_path: &Path) -> Result<(), FixtureError> {
    let mut command = Command::new(cli_binary);
    command
        .args(["--json", "auth", "setup", "--execution-access"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("DISSECT3D_") {
            command.env_remove(key);
        }
    }
    command.env("DISSECT3D_CONFIG_FILE", config_path);
    let mut child = command.spawn().map_err(|_| FixtureError::Provider)?;
    let deadline = Instant::now() + ENROLL_TIMEOUT;
    loop {
        match child.try_wait().map_err(|_| FixtureError::Provider)? {
            Some(status) if status.success() => return Ok(()),
            Some(_) => return Err(FixtureError::Credential),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(FixtureError::Provider);
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

fn validate_single_credential(
    discovery: &dissect3d_api::DiscoveryRecord,
    cred: &ProfileCredential,
) -> Result<(), FixtureError> {
    let _ = cred.submission_access;
    if cred.state != "active"
        || !cred.execution_access
        || cred.installation_id != discovery.installation_id
        || cred.instance_id != discovery.instance_id
        || !valid_secret_hex(&cred.secret_hex)
    {
        return Err(FixtureError::Credential);
    }
    Ok(())
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, FixtureError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| FixtureError::Credential)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(FixtureError::Credential);
    }
    std::fs::canonicalize(path).map_err(|_| FixtureError::Credential)
}

fn load_profile_credential(
    canonical_data_root: &Path,
    config_path: &Path,
) -> Result<ProfileCredential, FixtureError> {
    use std::io::Read as _;
    let mut config_bytes = Vec::new();
    std::fs::File::open(config_path)
        .map_err(|_| FixtureError::Credential)?
        .take(65_537)
        .read_to_end(&mut config_bytes)
        .map_err(|_| FixtureError::Credential)?;
    if config_bytes.len() > 65_536 {
        return Err(FixtureError::Credential);
    }
    let config: CliConfig =
        dissect3d_api::decode_json(&config_bytes).map_err(|_| FixtureError::Credential)?;
    let _ = config.preferences;
    let connection = config.connection.ok_or(FixtureError::Credential)?;
    let configured_root = connection.data_root.ok_or(FixtureError::Credential)?;
    if connection.credential_file.is_some() || connection.installation_id.is_some() {
        return Err(FixtureError::Credential);
    }
    let _ = connection.engine_binary;
    let configured_root =
        std::fs::canonicalize(configured_root).map_err(|_| FixtureError::Credential)?;
    if configured_root != canonical_data_root {
        return Err(FixtureError::Credential);
    }

    let mut state_path = config_path.as_os_str().to_os_string();
    state_path.push(".state");
    let state_root = OwnedRoot::open(Path::new(&state_path), RootPurpose::ClientConfig)
        .map_err(|_| FixtureError::Credential)?;
    let cred_rel =
        RelativePath::parse("credential.json".to_owned()).map_err(|_| FixtureError::Credential)?;
    let mut bytes = state_root
        .read_file(&cred_rel, 16_384)
        .map_err(|_| FixtureError::Credential)?;
    let parsed: Result<ProfileCredential, _> = dissect3d_api::decode_json(&bytes);
    bytes.fill(0);
    parsed.map_err(|_| FixtureError::Credential)
}

fn validate_credentials(
    discovery: &dissect3d_api::DiscoveryRecord,
    cred_a: &ProfileCredential,
    cred_b: &ProfileCredential,
) -> Result<(), FixtureError> {
    let _ = (cred_a.submission_access, cred_b.submission_access);
    if cred_a.state != "active"
        || cred_b.state != "active"
        || !cred_a.execution_access
        || !cred_b.execution_access
        || cred_a.installation_id != discovery.installation_id
        || cred_b.installation_id != discovery.installation_id
        || cred_a.instance_id != discovery.instance_id
        || cred_b.instance_id != discovery.instance_id
        || cred_a.client_id == cred_b.client_id
        || cred_a.enrollment_id == cred_b.enrollment_id
        || cred_a.secret_hex == cred_b.secret_hex
        || !valid_secret_hex(&cred_a.secret_hex)
        || !valid_secret_hex(&cred_b.secret_hex)
    {
        return Err(FixtureError::Credential);
    }
    Ok(())
}

fn write_token_file(
    root: &OwnedRoot,
    name: &str,
    credential: &ProfileCredential,
) -> Result<(), FixtureError> {
    let mut token = format!(
        "{}.{}\n",
        credential.client_id.as_str(),
        credential.secret_hex
    )
    .into_bytes();
    let result = root
        .write_atomic(
            &RelativePath::parse(name.to_owned()).map_err(|_| FixtureError::Storage)?,
            &token,
        )
        .map_err(|_| FixtureError::Storage);
    token.fill(0);
    result
}

fn valid_secret_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_certificate_pem(der: &[u8]) -> Result<Vec<u8>, FixtureError> {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        let line = std::str::from_utf8(line).map_err(|_| FixtureError::Provider)?;
        pem.push_str(line);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem.into_bytes())
}
