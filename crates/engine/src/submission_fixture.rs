//! Explicit test-only preparation and integrity checks for the CPU fixture.

use crate::support::{Catalog, ControlledPackage, DiscoveryLimits, ResolvedSelection, Selection};
use dissect3d_api::{
    ClientId, ContentDigest, EnrollmentId, InstallationId, InstanceId,
    PreparedReadiness as PreparedReadinessDto, TaskKey,
};
use dissect3d_platform::{AuthorityLease, OwnedRoot, PlatformError, RelativePath, RootPurpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

const PACKAGE_DIR: &str = "submission-fixture/package";
const SOURCE_DIR: &str = "submission-fixture/sources";
const REALIZATION_DIR: &str = "submission-fixture/realization";
const PENDING_MANIFEST: &str = "submission-fixture/prepared.pending.json";
const ACTIVE_MANIFEST: &str = "submission-fixture/prepared.json";
const PROBE_BINARY: &str = "submission-fixture/realization/probe.bin";
const REPORT_LIMIT: usize = 1_048_576;
const FIXTURE_FILE_LIMIT: usize = 134_217_728;

const SUPPORT_REF: &str = "test.mesh-copy@fixture-r1";
const RUNTIME_REF: &str = "test.cpu@fixture-r1";
const TASK_ID: &str = "dissect3d.test.mesh-copy";
const TASK_VERSION: &str = "1.0";
const VARIANT: &str = "fixture";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureError {
    InvalidRoot,
    NonEmptyRoot,
    AlreadyPrepared,
    AuthorityUnavailable,
    NotPrepared,
    Integrity,
    Package,
    Probe,
    Storage,
    Credential,
    Provider,
    AlreadyExported,
}

impl FixtureError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::InvalidRoot => "fixture_invalid_root",
            Self::NonEmptyRoot => "fixture_nonempty_root",
            Self::AlreadyPrepared => "fixture_already_prepared",
            Self::AuthorityUnavailable => "fixture_authority_unavailable",
            Self::NotPrepared => "fixture_not_prepared",
            Self::Integrity => "fixture_integrity_failed",
            Self::Package => "fixture_package_invalid",
            Self::Probe => "fixture_probe_failed",
            Self::Storage => "fixture_storage_unavailable",
            Self::Credential => "fixture_credential_invalid",
            Self::Provider => "fixture_provider_unavailable",
            Self::AlreadyExported => "fixture_provider_already_exported",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedFixtureReport {
    schema_version: String,
    status: String,
    evidence_scope: String,
    check_id: String,
    prepared_at_ms: u64,
    target_os: String,
    target_architecture: String,
    support_ref: String,
    support_id: String,
    task_id: String,
    task_version: String,
    task_binding_id: String,
    runtime_ref: String,
    runtime_id: String,
    variant: String,
    catalog_revision: String,
    package_files: Vec<ArtifactIdentity>,
    source_files: Vec<ArtifactIdentity>,
    probe_binary_sha256: String,
    probe_source_sha256: String,
    validator_id: String,
    validator_revision: String,
    readiness_fingerprint: String,
    integrity_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    path: String,
    sha256: String,
    byte_length: u64,
    kind: String,
    reference: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedReadiness {
    pub(crate) resolved: ResolvedSelection,
    pub(crate) snapshot: PreparedReadinessDto,
}

#[derive(Debug)]
pub(crate) struct PreparedFixture {
    pub(crate) catalog: Catalog,
    pub(crate) readiness: PreparedReadiness,
}

struct PackageMaterial {
    index: Vec<u8>,
    documents: Vec<(String, String, String, Vec<u8>)>,
    sources: Vec<(String, Vec<u8>)>,
    catalog: Catalog,
    resolved: ResolvedSelection,
}

/// Called only by the feature-gated maintainer example.
pub fn prepare_submission_fixture(data_root: &Path) -> Result<(), FixtureError> {
    if !data_root.is_absolute() {
        return Err(FixtureError::InvalidRoot);
    }
    let root = open_or_create_private_root(data_root)?;
    ensure_fresh_fixture_root(data_root)?;
    let lease = AuthorityLease::acquire(&root).map_err(|_| FixtureError::AuthorityUnavailable)?;

    root.ensure_private_directory(&relative(PACKAGE_DIR)?)
        .map_err(|_| FixtureError::Storage)?;
    root.ensure_private_directory(&relative(SOURCE_DIR)?)
        .map_err(|_| FixtureError::Storage)?;
    root.ensure_private_directory(&relative(REALIZATION_DIR)?)
        .map_err(|_| FixtureError::Storage)?;
    let material = package_material()?;
    let package_files = write_package(&root, &material)?;
    let source_files = write_sources(&root, &material)?;
    let probe_bytes = current_probe_bytes()?;
    root.write_atomic(&relative(PROBE_BINARY)?, &probe_bytes)
        .map_err(|_| FixtureError::Storage)?;

    let mut report = report_from_material(
        &material,
        package_files,
        source_files,
        digest(&probe_bytes),
        "preparing",
    )?;
    seal_report(&mut report)?;
    root.write_atomic(&relative(PENDING_MANIFEST)?, &encode_report(&report)?)
        .map_err(|_| FixtureError::Storage)?;

    let executable = std::env::current_exe().map_err(|_| FixtureError::Probe)?;
    let status = Command::new(executable)
        .arg("probe-cpu")
        .arg("--data-root")
        .arg(data_root)
        .status()
        .map_err(|_| FixtureError::Probe)?;
    if !status.success() {
        return Err(FixtureError::Probe);
    }

    report.status = "prepared".to_owned();
    report.readiness_fingerprint = readiness_fingerprint(&report);
    seal_report(&mut report)?;
    root.write_atomic(&relative(ACTIVE_MANIFEST)?, &encode_report(&report)?)
        .map_err(|_| FixtureError::Storage)?;
    drop(lease);
    Ok(())
}

/// Probe mode is invoked by the maintainer tool itself after staged bytes exist.
pub fn probe_submission_fixture(data_root: &Path) -> Result<(), FixtureError> {
    if !data_root.is_absolute() {
        return Err(FixtureError::InvalidRoot);
    }
    let root = OwnedRoot::open(data_root, RootPurpose::EngineData)
        .map_err(|_| FixtureError::InvalidRoot)?;
    let bytes = root
        .read_file(&relative(PENDING_MANIFEST)?, REPORT_LIMIT)
        .map_err(|_| FixtureError::NotPrepared)?;
    let report = decode_report(&bytes)?;
    if report.status != "preparing" {
        return Err(FixtureError::Integrity);
    }
    validate_report(&root, &report, &current_probe_bytes()?)?;
    probe_self_checks(&root, &report)?;
    Ok(())
}

/// Export independent provider expectations and two already enrolled clients.
/// This command never enrolls a client or derives expectations from a job.
pub fn write_submission_provider_manifest(
    data_root: &Path,
    config_a: &Path,
    config_b: &Path,
    output: &Path,
) -> Result<(), FixtureError> {
    if !data_root.is_absolute()
        || !config_a.is_absolute()
        || !config_b.is_absolute()
        || !output.is_absolute()
        || config_a == config_b
    {
        return Err(FixtureError::InvalidRoot);
    }
    let canonical_root = std::fs::canonicalize(data_root).map_err(|_| FixtureError::InvalidRoot)?;
    let root = OwnedRoot::open(&canonical_root, RootPurpose::EngineData)
        .map_err(|_| FixtureError::InvalidRoot)?;
    let executable = std::env::current_exe().map_err(|_| FixtureError::Probe)?;
    let fixture = load_prepared_fixture(&root, &executable)?;
    let verified = dissect3d_connection::verify_engine(&root, std::time::Duration::from_secs(2))
        .map_err(|_| FixtureError::Provider)?;
    let discovery = verified.discovery;

    let canonical_config_a = validate_profile_config_path(&canonical_root, config_a)?;
    let canonical_config_b = validate_profile_config_path(&canonical_root, config_b)?;
    if canonical_config_a == canonical_config_b {
        return Err(FixtureError::Credential);
    }
    let credential_a = load_provider_credential(&root, &canonical_root, &canonical_config_a)?;
    let credential_b = load_provider_credential(&root, &canonical_root, &canonical_config_b)?;
    if credential_a.state != "active"
        || credential_b.state != "active"
        || !credential_a.submission_access
        || !credential_b.submission_access
        || credential_a.installation_id != discovery.installation_id
        || credential_b.installation_id != discovery.installation_id
        || credential_a.instance_id != discovery.instance_id
        || credential_b.instance_id != discovery.instance_id
        || credential_a.client_id == credential_b.client_id
        || credential_a.enrollment_id == credential_b.enrollment_id
        || credential_a.secret_hex == credential_b.secret_hex
        || !valid_secret_hex(&credential_a.secret_hex)
        || !valid_secret_hex(&credential_b.secret_hex)
    {
        return Err(FixtureError::Credential);
    }

    let output_path = relative_under_root(&canonical_root, output)?;
    let output_name = output_path.as_str();
    let ca_path = "submission-fixture/ca.pem";
    let credential_a_path = "submission-fixture/client-a.json";
    let credential_b_path = "submission-fixture/client-b.json";
    let marker_path = "durable-submission-test-root";
    if [ca_path, credential_a_path, credential_b_path, marker_path].contains(&output_name) {
        return Err(FixtureError::InvalidRoot);
    }
    let paths = [
        output_name,
        ca_path,
        credential_a_path,
        credential_b_path,
        marker_path,
    ];
    for path in paths {
        match root.file_metadata(&relative(path)?) {
            Err(PlatformError::NotFound) => {}
            Ok(_) => return Err(FixtureError::AlreadyExported),
            Err(_) => return Err(FixtureError::Storage),
        }
    }

    let ca_bytes = encode_certificate_pem(&discovery.trust_anchor_der)?;
    let ca_path_absolute = canonical_root.join("submission-fixture/ca.pem");
    let credential_a_absolute = canonical_root.join("submission-fixture/client-a.json");
    let credential_b_absolute = canonical_root.join("submission-fixture/client-b.json");
    let manifest = json!({
        "isolated_test_engine": true,
        "test_root": canonical_root,
        "base_url": discovery.base_url,
        "ca_file": ca_path_absolute,
        "credential_files": [credential_a_absolute, credential_b_absolute],
        "expected_selection": selection_snapshot_value(&fixture.readiness.resolved),
        "expected_readiness": serde_json::to_value(&fixture.readiness.snapshot)
            .map_err(|_| FixtureError::Provider)?,
    });
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|_| FixtureError::Provider)?;
    if manifest_bytes.len() > REPORT_LIMIT {
        return Err(FixtureError::Provider);
    }

    let export_result = (|| {
        root.write_atomic(&relative(ca_path)?, &ca_bytes)
            .map_err(|_| FixtureError::Storage)?;
        write_provider_credential(&root, credential_a_path, &credential_a)?;
        write_provider_credential(&root, credential_b_path, &credential_b)?;
        root.write_atomic(&relative(marker_path)?, b"durable-submission-test-root\n")
            .map_err(|_| FixtureError::Storage)?;
        root.write_atomic(&output_path, &manifest_bytes)
            .map_err(|_| FixtureError::Storage)?;
        Ok(())
    })();
    manifest_bytes.fill(0);
    if let Err(error) = export_result {
        for path in paths.into_iter().rev() {
            match root.remove_file(&relative(path)?) {
                Ok(()) | Err(PlatformError::NotFound) => {}
                Err(_) => return Err(FixtureError::Storage),
            }
        }
        return Err(error);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCliConfig {
    #[serde(default)]
    preferences: Option<Value>,
    #[serde(default)]
    connection: Option<ProviderConnectionConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderConnectionConfig {
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
struct ProviderProfileCredential {
    installation_id: InstallationId,
    instance_id: InstanceId,
    client_id: ClientId,
    enrollment_id: EnrollmentId,
    secret_hex: String,
    state: String,
    #[serde(default)]
    submission_access: bool,
}

impl Drop for ProviderProfileCredential {
    fn drop(&mut self) {
        let mut secret = std::mem::take(&mut self.secret_hex).into_bytes();
        secret.fill(0);
    }
}

#[derive(Serialize)]
struct ProviderCredentialExport<'a> {
    client_id: &'a ClientId,
    secret_hex: &'a str,
}

fn validate_profile_config_path(root: &Path, config_path: &Path) -> Result<PathBuf, FixtureError> {
    let canonical = std::fs::canonicalize(config_path).map_err(|_| FixtureError::Credential)?;
    if !canonical.starts_with(root)
        || std::fs::symlink_metadata(config_path)
            .map_err(|_| FixtureError::Credential)?
            .file_type()
            .is_symlink()
    {
        return Err(FixtureError::Credential);
    }
    Ok(canonical)
}

fn load_provider_credential(
    root: &OwnedRoot,
    data_root: &Path,
    config_path: &Path,
) -> Result<ProviderProfileCredential, FixtureError> {
    let config_bytes = root
        .read_file(&relative_under_root(data_root, config_path)?, 65_536)
        .map_err(|_| FixtureError::Credential)?;
    let config_result: Result<ProviderCliConfig, _> = serde_json::from_slice(&config_bytes);
    let config = match config_result {
        Ok(config) => config,
        Err(_) => return Err(FixtureError::Credential),
    };
    let _ = config.preferences;
    let connection = config.connection.ok_or(FixtureError::Credential)?;
    let configured_root = connection.data_root.ok_or(FixtureError::Credential)?;
    if connection.credential_file.is_some() || connection.installation_id.is_some() {
        return Err(FixtureError::Credential);
    }
    let configured_root =
        std::fs::canonicalize(configured_root).map_err(|_| FixtureError::Credential)?;
    if configured_root != data_root {
        return Err(FixtureError::Credential);
    }
    let _ = connection.engine_binary;

    let mut state_path = config_path.as_os_str().to_os_string();
    state_path.push(".state");
    let credential_path = PathBuf::from(state_path).join("credential.json");
    let mut credential_bytes = root
        .read_file(&relative_under_root(data_root, &credential_path)?, 16_384)
        .map_err(|_| FixtureError::Credential)?;
    let credential_result: Result<ProviderProfileCredential, _> =
        serde_json::from_slice(&credential_bytes);
    credential_bytes.fill(0);
    credential_result.map_err(|_| FixtureError::Credential)
}

fn write_provider_credential(
    root: &OwnedRoot,
    path: &str,
    credential: &ProviderProfileCredential,
) -> Result<(), FixtureError> {
    let mut bytes = serde_json::to_vec(&ProviderCredentialExport {
        client_id: &credential.client_id,
        secret_hex: &credential.secret_hex,
    })
    .map_err(|_| FixtureError::Credential)?;
    let result = root
        .write_atomic(&relative(path)?, &bytes)
        .map_err(|_| FixtureError::Storage);
    bytes.fill(0);
    result
}

fn relative_under_root(root: &Path, path: &Path) -> Result<RelativePath, FixtureError> {
    if !path.is_absolute() {
        return Err(FixtureError::InvalidRoot);
    }
    let remainder = path
        .strip_prefix(root)
        .map_err(|_| FixtureError::InvalidRoot)?;
    if remainder.as_os_str().is_empty() {
        return Err(FixtureError::InvalidRoot);
    }
    let value = remainder.to_string_lossy().replace('\\', "/");
    relative(&value)
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

pub(crate) fn load_prepared_fixture(
    root: &OwnedRoot,
    probe_executable: &Path,
) -> Result<PreparedFixture, FixtureError> {
    let bytes = root
        .read_file(&relative(ACTIVE_MANIFEST)?, REPORT_LIMIT)
        .map_err(|_| FixtureError::NotPrepared)?;
    let report = decode_report(&bytes)?;
    if report.status != "prepared" || report.evidence_scope != "controlled-test-only" {
        return Err(FixtureError::NotPrepared);
    }
    let current_probe = std::fs::read(probe_executable).map_err(|_| FixtureError::Integrity)?;
    validate_report(root, &report, &current_probe)?;
    let material = catalog_from_installed(root, &report)?;
    let selection = fixture_selection()?;
    let resolved = material
        .resolve(&selection)
        .map_err(|_| FixtureError::Package)?;
    if material.revision != report.catalog_revision
        || resolved.support_id != report.support_id
        || resolved.task_binding_id != report.task_binding_id
        || resolved.runtime_id != report.runtime_id
    {
        return Err(FixtureError::Integrity);
    }
    Ok(PreparedFixture {
        catalog: material,
        readiness: PreparedReadiness {
            snapshot: readiness_snapshot(&report)?,
            resolved,
        },
    })
}

/// Install and re-verify the exact controlled package for internal admission
/// tests without exposing fixture package composition to production callers.
#[cfg(all(unix, test, feature = "test-support"))]
pub(crate) fn verified_fixture_for_admission(root: &OwnedRoot) -> PreparedFixture {
    root.ensure_private_directory(&relative(PACKAGE_DIR).expect("fixture package path"))
        .expect("create fixture package directory");
    root.ensure_private_directory(&relative(SOURCE_DIR).expect("fixture source path"))
        .expect("create fixture source directory");
    root.ensure_private_directory(&relative(REALIZATION_DIR).expect("fixture realization path"))
        .expect("create fixture realization directory");
    let material = package_material().expect("controlled package material");
    let package_files = write_package(root, &material).expect("install controlled package");
    let source_files = write_sources(root, &material).expect("install controlled sources");
    let probe = b"controlled fixture probe bytes for admission regression";
    root.write_atomic(&relative(PROBE_BINARY).expect("probe path"), probe)
        .expect("install probe executable bytes");
    let mut report = report_from_material(
        &material,
        package_files,
        source_files,
        digest(probe),
        "prepared",
    )
    .expect("prepared report");
    report.readiness_fingerprint = readiness_fingerprint(&report);
    seal_report(&mut report).expect("seal prepared report");
    root.write_atomic(
        &relative(ACTIVE_MANIFEST).expect("active manifest path"),
        &encode_report(&report).expect("encode report"),
    )
    .expect("install prepared manifest");
    validate_report(root, &report, probe).expect("verify installed prepared fixture integrity");
    PreparedFixture {
        catalog: material.catalog,
        readiness: PreparedReadiness {
            resolved: material.resolved,
            snapshot: readiness_snapshot(&report).expect("prepared readiness snapshot"),
        },
    }
}

pub(crate) fn fixture_probe_sibling() -> Result<PathBuf, FixtureError> {
    let mut path = std::env::current_exe().map_err(|_| FixtureError::Probe)?;
    let extension = path.extension().map(|value| value.to_os_string());
    path.set_file_name("submission_fixture_tool");
    if let Some(extension) = extension {
        path.set_extension(extension);
    }
    Ok(path)
}

fn package_material() -> Result<PackageMaterial, FixtureError> {
    let input = include_bytes!("../tests/fixtures/submission/input-schema.json").to_vec();
    let parameters = include_bytes!("../tests/fixtures/submission/parameters-schema.json").to_vec();
    let output = include_bytes!("../tests/fixtures/submission/output-schema.json").to_vec();
    let runtime = include_bytes!("../tests/fixtures/submission/runtime.json").to_vec();
    let adapter = include_bytes!("../tests/fixtures/submission/adapter.rs").to_vec();
    let validator = include_bytes!("../tests/fixtures/submission/validator.rs").to_vec();
    let probe_source = include_bytes!("../tests/fixtures/submission/probe-source.md").to_vec();
    let tetrahedron = include_bytes!("../tests/fixtures/submission/tetrahedron.obj").to_vec();
    let module_source = include_bytes!("submission_fixture.rs").to_vec();

    let mut support: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/submission/support-template.json"
    ))
    .map_err(|_| FixtureError::Package)?;
    let schema_files = [
        ("input_schema", &input),
        ("parameter_schema", &parameters),
        ("output_schema", &output),
    ];
    for (field, bytes) in schema_files {
        let schema: Value = serde_json::from_slice(bytes).map_err(|_| FixtureError::Package)?;
        let binding = support["tasks"]
            .as_array_mut()
            .and_then(|tasks| tasks.first_mut())
            .ok_or(FixtureError::Package)?;
        binding[field]["sha256"] = Value::String(digest(bytes));
        if binding[field]["id"] != schema["id"] || binding[field]["version"] != schema["version"] {
            return Err(FixtureError::Package);
        }
    }
    support["adapter"]["sha256"] = Value::String(digest(&adapter));
    support["code"]["executed_revision"] =
        Value::String(format!("sha256:{}", digest(&module_source)));
    let support_bytes = serde_json::to_vec(&support).map_err(|_| FixtureError::Package)?;

    let documents = vec![
        (
            "schema".to_owned(),
            schema_reference(&input)?,
            "submission-fixture/package/input-schema.json".to_owned(),
            input,
        ),
        (
            "schema".to_owned(),
            schema_reference(&parameters)?,
            "submission-fixture/package/parameters-schema.json".to_owned(),
            parameters,
        ),
        (
            "schema".to_owned(),
            schema_reference(&output)?,
            "submission-fixture/package/output-schema.json".to_owned(),
            output,
        ),
        (
            "runtime".to_owned(),
            RUNTIME_REF.to_owned(),
            "submission-fixture/package/runtime.json".to_owned(),
            runtime,
        ),
        (
            "support".to_owned(),
            SUPPORT_REF.to_owned(),
            "submission-fixture/package/support.json".to_owned(),
            support_bytes,
        ),
    ];
    let index_documents = documents
        .iter()
        .map(|(kind, reference, _, bytes)| {
            json!({
                "kind": kind,
                "ref": reference,
                "sha256": digest(bytes),
                "byte_length": bytes.len(),
            })
        })
        .collect::<Vec<_>>();
    let index = serde_json::to_vec(&json!({
        "schema_version": "1.0",
        "required_features": [],
        "documents": index_documents,
        "aliases": [],
    }))
    .map_err(|_| FixtureError::Package)?;
    let controlled = ControlledPackage {
        index_bytes: index.clone(),
        document_bytes: documents
            .iter()
            .map(|(_, _, _, bytes)| bytes.clone())
            .collect(),
    };
    let catalog = Catalog::from_packages(vec![controlled], DiscoveryLimits::default())
        .map_err(|_| FixtureError::Package)?;
    let resolved = catalog
        .resolve(&fixture_selection()?)
        .map_err(|_| FixtureError::Package)?;
    let sources = vec![
        ("submission-fixture/sources/adapter.rs".to_owned(), adapter),
        (
            "submission-fixture/sources/validator.rs".to_owned(),
            validator,
        ),
        (
            "submission-fixture/sources/engine-obj.rs".to_owned(),
            include_bytes!("submission/obj.rs").to_vec(),
        ),
        (
            "submission-fixture/sources/probe-source.md".to_owned(),
            probe_source,
        ),
        (
            "submission-fixture/sources/tetrahedron.obj".to_owned(),
            tetrahedron,
        ),
        (
            "submission-fixture/sources/submission_fixture.rs".to_owned(),
            module_source,
        ),
    ];
    Ok(PackageMaterial {
        index,
        documents,
        sources,
        catalog,
        resolved,
    })
}

fn schema_reference(bytes: &[u8]) -> Result<String, FixtureError> {
    let schema: Value = serde_json::from_slice(bytes).map_err(|_| FixtureError::Package)?;
    let id = schema["id"].as_str().ok_or(FixtureError::Package)?;
    let version = schema["version"].as_str().ok_or(FixtureError::Package)?;
    Ok(format!("{id}@{version}"))
}

fn fixture_selection() -> Result<Selection, FixtureError> {
    Ok(Selection {
        support_ref: SUPPORT_REF.to_owned(),
        task: TaskKey::new(TASK_ID, TASK_VERSION).map_err(|_| FixtureError::Package)?,
        runtime_ref: Some(RUNTIME_REF.to_owned()),
        variant: Some(VARIANT.to_owned()),
    })
}

fn write_package(
    root: &OwnedRoot,
    material: &PackageMaterial,
) -> Result<Vec<ArtifactIdentity>, FixtureError> {
    let mut identities = Vec::with_capacity(material.documents.len() + 1);
    write_artifact(
        root,
        "submission-fixture/package/index.json",
        "index",
        "catalog-v1",
        &material.index,
        &mut identities,
    )?;
    for (kind, reference, path, bytes) in &material.documents {
        write_artifact(root, path, kind, reference, bytes, &mut identities)?;
    }
    Ok(identities)
}

fn write_sources(
    root: &OwnedRoot,
    material: &PackageMaterial,
) -> Result<Vec<ArtifactIdentity>, FixtureError> {
    let mut identities = Vec::with_capacity(material.sources.len());
    for (path, bytes) in &material.sources {
        write_artifact(root, path, "source", path, bytes, &mut identities)?;
    }
    Ok(identities)
}

fn write_artifact(
    root: &OwnedRoot,
    path: &str,
    kind: &str,
    reference: &str,
    bytes: &[u8],
    identities: &mut Vec<ArtifactIdentity>,
) -> Result<(), FixtureError> {
    root.write_atomic(&relative(path)?, bytes)
        .map_err(|_| FixtureError::Storage)?;
    identities.push(ArtifactIdentity {
        path: path.to_owned(),
        sha256: digest(bytes),
        byte_length: bytes.len() as u64,
        kind: kind.to_owned(),
        reference: reference.to_owned(),
    });
    Ok(())
}

fn report_from_material(
    material: &PackageMaterial,
    package_files: Vec<ArtifactIdentity>,
    source_files: Vec<ArtifactIdentity>,
    probe_binary_sha256: String,
    status: &str,
) -> Result<PreparedFixtureReport, FixtureError> {
    let prepared_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| FixtureError::Storage)?
        .as_millis();
    let prepared_at_ms = u64::try_from(prepared_at_ms).map_err(|_| FixtureError::Storage)?;
    Ok(PreparedFixtureReport {
        schema_version: "1.0".to_owned(),
        status: status.to_owned(),
        evidence_scope: "controlled-test-only".to_owned(),
        check_id: "fixture.cpu.probe@1".to_owned(),
        prepared_at_ms,
        target_os: std::env::consts::OS.to_owned(),
        target_architecture: std::env::consts::ARCH.to_owned(),
        support_ref: material.resolved.support_ref.clone(),
        support_id: material.resolved.support_id.clone(),
        task_id: material.resolved.task.id().to_owned(),
        task_version: material.resolved.task.version().to_owned(),
        task_binding_id: material.resolved.task_binding_id.clone(),
        runtime_ref: material.resolved.runtime_ref.clone(),
        runtime_id: material.resolved.runtime_id.clone(),
        variant: material.resolved.variant.clone(),
        catalog_revision: material.catalog.revision.clone(),
        package_files,
        source_files,
        probe_binary_sha256,
        probe_source_sha256: material
            .sources
            .iter()
            .find(|(path, _)| path.ends_with("probe-source.md"))
            .map(|(_, bytes)| digest(bytes))
            .ok_or(FixtureError::Package)?,
        validator_id: "dissect3d.test.validator".to_owned(),
        validator_revision: "1".to_owned(),
        readiness_fingerprint: String::new(),
        integrity_sha256: String::new(),
    })
}

fn catalog_from_installed(
    root: &OwnedRoot,
    report: &PreparedFixtureReport,
) -> Result<Catalog, FixtureError> {
    let expected = package_material()?;
    let index_identity = report
        .package_files
        .iter()
        .find(|identity| identity.kind == "index")
        .ok_or(FixtureError::Integrity)?;
    let index_bytes = read_identity(root, index_identity)?;
    let mut document_bytes = Vec::with_capacity(expected.documents.len());
    for (kind, reference, path, bytes) in &expected.documents {
        let identity = report
            .package_files
            .iter()
            .find(|identity| identity.kind == *kind && identity.reference == *reference)
            .ok_or(FixtureError::Integrity)?;
        if identity.path != *path {
            return Err(FixtureError::Integrity);
        }
        let installed = read_identity(root, identity)?;
        if installed != *bytes {
            return Err(FixtureError::Integrity);
        }
        document_bytes.push(installed);
    }
    if index_bytes != expected.index || report.package_files.len() != expected.documents.len() + 1 {
        return Err(FixtureError::Integrity);
    }
    Catalog::from_packages(
        vec![ControlledPackage {
            index_bytes,
            document_bytes,
        }],
        DiscoveryLimits::default(),
    )
    .map_err(|_| FixtureError::Package)
}

fn validate_report(
    root: &OwnedRoot,
    report: &PreparedFixtureReport,
    current_probe: &[u8],
) -> Result<(), FixtureError> {
    if report.schema_version != "1.0"
        || !matches!(report.status.as_str(), "preparing" | "prepared")
        || report.evidence_scope != "controlled-test-only"
        || report.check_id != "fixture.cpu.probe@1"
        || report.target_os != std::env::consts::OS
        || report.target_architecture != std::env::consts::ARCH
        || report.support_ref != SUPPORT_REF
        || report.task_id != TASK_ID
        || report.task_version != TASK_VERSION
        || report.runtime_ref != RUNTIME_REF
        || report.variant != VARIANT
        || report.validator_id != "dissect3d.test.validator"
        || report.validator_revision != "1"
        || current_probe.is_empty()
        || current_probe.len() > FIXTURE_FILE_LIMIT
        || digest(current_probe) != report.probe_binary_sha256
        || !valid_digest(&report.probe_source_sha256)
        || !valid_digest(&report.integrity_sha256)
    {
        return Err(FixtureError::Integrity);
    }
    let mut unsigned = report.clone();
    let integrity = std::mem::take(&mut unsigned.integrity_sha256);
    if digest(&serde_json::to_vec(&unsigned).map_err(|_| FixtureError::Integrity)?) != integrity {
        return Err(FixtureError::Integrity);
    }

    let expected = package_material()?;
    if report.package_files.len() != expected.documents.len() + 1
        || report.source_files.len() != expected.sources.len()
        || report.catalog_revision != expected.catalog.revision
        || report.support_id != expected.resolved.support_id
        || report.task_binding_id != expected.resolved.task_binding_id
        || report.runtime_id != expected.resolved.runtime_id
        || report.probe_source_sha256
            != expected
                .sources
                .iter()
                .find(|(path, _)| path.ends_with("probe-source.md"))
                .map(|(_, bytes)| digest(bytes))
                .ok_or(FixtureError::Package)?
    {
        return Err(FixtureError::Integrity);
    }
    for identity in &report.package_files {
        let installed = read_identity(root, identity)?;
        let expected_bytes = expected_artifact_bytes(&expected, identity)?;
        if installed != expected_bytes {
            return Err(FixtureError::Integrity);
        }
    }
    for identity in &report.source_files {
        let installed = read_identity(root, identity)?;
        let (_, expected_bytes) = expected
            .sources
            .iter()
            .find(|(path, _)| path == &identity.path)
            .ok_or(FixtureError::Integrity)?;
        if identity.kind != "source"
            || identity.reference != identity.path
            || installed != *expected_bytes
        {
            return Err(FixtureError::Integrity);
        }
    }
    let installed_probe = root
        .read_file(&relative(PROBE_BINARY)?, FIXTURE_FILE_LIMIT)
        .map_err(|_| FixtureError::Integrity)?;
    if installed_probe != current_probe {
        return Err(FixtureError::Integrity);
    }
    if report.status == "prepared"
        && (report.readiness_fingerprint.is_empty()
            || report.readiness_fingerprint != readiness_fingerprint(report))
    {
        return Err(FixtureError::Integrity);
    }
    if report.status == "preparing" && !report.readiness_fingerprint.is_empty() {
        return Err(FixtureError::Integrity);
    }
    Ok(())
}

fn expected_artifact_bytes<'a>(
    material: &'a PackageMaterial,
    identity: &ArtifactIdentity,
) -> Result<&'a [u8], FixtureError> {
    if identity.kind == "index"
        && identity.path == "submission-fixture/package/index.json"
        && identity.reference == "catalog-v1"
    {
        return Ok(&material.index);
    }
    material
        .documents
        .iter()
        .find(|(kind, reference, path, _)| {
            kind == &identity.kind && reference == &identity.reference && path == &identity.path
        })
        .map(|(_, _, _, bytes)| bytes.as_slice())
        .ok_or(FixtureError::Integrity)
}

fn read_identity(root: &OwnedRoot, identity: &ArtifactIdentity) -> Result<Vec<u8>, FixtureError> {
    let path = RelativePath::parse(identity.path.clone()).map_err(|_| FixtureError::Integrity)?;
    let bytes = root
        .read_file(&path, FIXTURE_FILE_LIMIT)
        .map_err(|_| FixtureError::Integrity)?;
    if bytes.len() as u64 != identity.byte_length || digest(&bytes) != identity.sha256 {
        return Err(FixtureError::Integrity);
    }
    Ok(bytes)
}

fn probe_self_checks(root: &OwnedRoot, report: &PreparedFixtureReport) -> Result<(), FixtureError> {
    let mesh = root
        .read_file(
            &relative("submission-fixture/sources/tetrahedron.obj")?,
            FIXTURE_FILE_LIMIT,
        )
        .map_err(|_| FixtureError::Integrity)?;
    validate_fixture_obj(&mesh)?;
    let check_dir = relative("submission-fixture/realization/probe-check")?;
    root.ensure_private_directory(&check_dir)
        .map_err(|_| FixtureError::Storage)?;
    let probe = root
        .read_file(&relative(PROBE_BINARY)?, FIXTURE_FILE_LIMIT)
        .map_err(|_| FixtureError::Integrity)?;
    if digest(&probe) != report.probe_binary_sha256 {
        return Err(FixtureError::Integrity);
    }
    let roundtrip = relative("submission-fixture/realization/probe-check/roundtrip.bin")?;
    root.write_atomic(&roundtrip, &probe)
        .map_err(|_| FixtureError::Storage)?;
    let observed = root
        .read_file(&roundtrip, FIXTURE_FILE_LIMIT)
        .map_err(|_| FixtureError::Storage)?;
    if digest(&observed) != report.probe_binary_sha256 {
        return Err(FixtureError::Integrity);
    }
    root.remove_file(&roundtrip)
        .map_err(|_| FixtureError::Storage)?;
    let copied = relative("submission-fixture/realization/probe-check/candidate.obj")?;
    root.write_atomic(&copied, &mesh)
        .map_err(|_| FixtureError::Storage)?;
    let observed = root
        .read_file(&copied, FIXTURE_FILE_LIMIT)
        .map_err(|_| FixtureError::Storage)?;
    if observed != mesh {
        return Err(FixtureError::Integrity);
    }
    validate_fixture_obj(&observed)?;
    let invalid = b"v NaN 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\n";
    if validate_fixture_obj(invalid).is_ok() {
        return Err(FixtureError::Probe);
    }
    root.remove_file(&copied)
        .map_err(|_| FixtureError::Storage)?;
    Ok(())
}

fn validate_fixture_obj(bytes: &[u8]) -> Result<(), FixtureError> {
    crate::submission::obj::validate_obj(bytes)
        .map(|_| ())
        .map_err(|_| FixtureError::Probe)
}

fn readiness_fingerprint(report: &PreparedFixtureReport) -> String {
    let mut source_hashes = report
        .source_files
        .iter()
        .map(|identity| format!("{}\t{}\n", identity.path, identity.sha256))
        .collect::<Vec<_>>();
    source_hashes.sort();
    let mut package_hashes = report
        .package_files
        .iter()
        .map(|identity| format!("{}\t{}\n", identity.path, identity.sha256))
        .collect::<Vec<_>>();
    package_hashes.sort();
    let mut preimage = format!(
        "dissect3d-submission-fixture-readiness-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        report.target_os,
        report.target_architecture,
        report.catalog_revision,
        report.support_id,
        report.task_binding_id,
        report.runtime_id,
        report.probe_binary_sha256,
        report.probe_source_sha256,
        report.validator_id,
        report.validator_revision,
    );
    preimage.push_str(&report.check_id);
    preimage.push('\n');
    for row in package_hashes.iter().chain(source_hashes.iter()) {
        preimage.push_str(row);
    }
    digest(preimage.as_bytes())
}

fn readiness_snapshot(
    report: &PreparedFixtureReport,
) -> Result<PreparedReadinessDto, FixtureError> {
    let runtime_sha256 = report
        .package_files
        .iter()
        .find(|identity| identity.kind == "runtime" && identity.reference == report.runtime_ref)
        .map(|identity| identity.sha256.as_str())
        .ok_or(FixtureError::Integrity)?;
    Ok(PreparedReadinessDto {
        check_id: report.check_id.clone(),
        fingerprint: ContentDigest::parse(report.readiness_fingerprint.clone())
            .map_err(|_| FixtureError::Integrity)?,
        runtime_realization: format!(
            "native-test:{}:{}:probe-sha256:{}:runtime-sha256:{}:manifest-sha256:{}",
            report.target_os,
            report.target_architecture,
            report.probe_binary_sha256,
            runtime_sha256,
            report.integrity_sha256,
        ),
        integrity_sha256: ContentDigest::parse(report.integrity_sha256.clone())
            .map_err(|_| FixtureError::Integrity)?,
    })
}

fn selection_snapshot_value(selection: &ResolvedSelection) -> Value {
    json!({
        "support_id": selection.support_id,
        "support_ref": selection.support_ref,
        "support_sha256": selection.support_sha256,
        "code": {
            "upstream_repository": selection.code.upstream_repository,
            "upstream_revision": selection.code.upstream_revision,
            "executed_repository": selection.code.executed_repository,
            "executed_revision": selection.code.executed_revision,
            "patches": selection.code.patches.iter().map(|patch| json!({
                "id": patch.id,
                "sha256": patch.sha256,
            })).collect::<Vec<_>>(),
            "build_provenance": selection.code.build_provenance,
        },
        "adapter": {
            "id": selection.adapter.id,
            "revision": selection.adapter.revision,
            "sha256": selection.adapter.sha256,
            "interface_version": selection.adapter.interface_version,
            "required_worker_features": selection.adapter.required_worker_features,
        },
        "assets": selection.assets.iter().map(|asset| json!({
            "id": asset.id,
            "kind": asset.kind,
            "source": asset.source,
            "revision": asset.revision,
            "sha256": asset.sha256,
            "byte_length": asset.byte_length,
            "prerequisites": asset.prerequisites,
            "rights_id": asset.rights_id,
        })).collect::<Vec<_>>(),
        "task_binding_id": selection.task_binding_id,
        "task": {
            "id": selection.task.id(),
            "version": selection.task.version(),
        },
        "schemas": selection.schemas.iter().map(|schema| json!({
            "id": schema.id,
            "version": schema.version,
            "sha256": schema.sha256,
        })).collect::<Vec<_>>(),
        "runtime_id": selection.runtime_id,
        "runtime_ref": selection.runtime_ref,
        "runtime_sha256": selection.runtime_sha256,
        "variant": selection.variant,
    })
}

fn seal_report(report: &mut PreparedFixtureReport) -> Result<(), FixtureError> {
    report.integrity_sha256.clear();
    report.integrity_sha256 =
        digest(&serde_json::to_vec(report).map_err(|_| FixtureError::Storage)?);
    Ok(())
}

fn encode_report(report: &PreparedFixtureReport) -> Result<Vec<u8>, FixtureError> {
    serde_json::to_vec(report).map_err(|_| FixtureError::Storage)
}

fn decode_report(bytes: &[u8]) -> Result<PreparedFixtureReport, FixtureError> {
    serde_json::from_slice(bytes).map_err(|_| FixtureError::Integrity)
}

fn current_probe_bytes() -> Result<Vec<u8>, FixtureError> {
    let executable = std::env::current_exe().map_err(|_| FixtureError::Probe)?;
    let metadata = std::fs::metadata(&executable).map_err(|_| FixtureError::Probe)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > FIXTURE_FILE_LIMIT as u64 {
        return Err(FixtureError::Probe);
    }
    let bytes = std::fs::read(executable).map_err(|_| FixtureError::Probe)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() > FIXTURE_FILE_LIMIT {
        return Err(FixtureError::Probe);
    }
    Ok(bytes)
}

fn open_or_create_private_root(data_root: &Path) -> Result<OwnedRoot, FixtureError> {
    if let Ok(metadata) = std::fs::symlink_metadata(data_root)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(FixtureError::InvalidRoot);
    }
    let result = if data_root.exists() {
        OwnedRoot::open(data_root, RootPurpose::EngineData)
    } else {
        OwnedRoot::create_private(data_root, RootPurpose::EngineData)
    };
    result.map_err(|_| FixtureError::InvalidRoot)
}

fn ensure_fresh_fixture_root(data_root: &Path) -> Result<(), FixtureError> {
    let mut entries = std::fs::read_dir(data_root).map_err(|_| FixtureError::InvalidRoot)?;
    if let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| FixtureError::InvalidRoot)?;
        let metadata = entry.file_type().map_err(|_| FixtureError::InvalidRoot)?;
        if metadata.is_symlink() || entry.file_name().is_empty() {
            return Err(FixtureError::InvalidRoot);
        }
        return Err(FixtureError::NonEmptyRoot);
    }
    Ok(())
}

fn relative(path: &str) -> Result<RelativePath, FixtureError> {
    RelativePath::parse(path.to_owned()).map_err(|_| FixtureError::Storage)
}

fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dissect3d_platform::RootPurpose;
    use serde_json::Value;
    use tempfile::TempDir;

    #[test]
    fn fixture_package_is_strict_test_only_and_resolves_exactly() {
        let material = package_material().expect("controlled fixture package");
        let model = material
            .catalog
            .model(SUPPORT_REF)
            .expect("fixture support");
        let runtime = material
            .catalog
            .runtime(RUNTIME_REF)
            .expect("fixture runtime");
        assert!(model.test_only);
        assert!(runtime.test_only);
        assert_eq!(model.tasks.len(), 1);
        assert_eq!(model.tasks[0].task.id(), TASK_ID);
        assert_eq!(model.tasks[0].task.version(), TASK_VERSION);
        assert!(model.unresolved_paths.is_empty());
        assert!(model.tasks[0].unresolved_paths.is_empty());
        assert_eq!(material.resolved.variant, VARIANT);
        assert_eq!(material.resolved.runtime_ref, RUNTIME_REF);

        let parameter_schema = &model.tasks[0]
            .schemas
            .iter()
            .find(|schema| schema.document["id"] == "test.parameters")
            .expect("closed parameter schema")
            .document["schema"];
        assert_eq!(parameter_schema["additionalProperties"], false);
        assert_eq!(
            parameter_schema["properties"]["hold_before_candidate"]["default"],
            false
        );
        assert_eq!(
            parameter_schema["properties"]["fail_execution"]["default"],
            false
        );

        let runtime_doc = &runtime.declaration;
        assert_eq!(runtime_doc["execution_kind"], "native_test");
        assert!(runtime_doc["interpreter"].is_null());
        assert!(material.documents.iter().all(|(_, _, _, bytes)| {
            !bytes
                .windows(64)
                .any(|window| window.iter().all(|byte| *byte == b'0'))
        }));
        let _: Value = serde_json::from_slice(&material.index).expect("valid exact index");
    }

    #[test]
    fn normal_discovery_and_prepared_compositions_are_separate() {
        let normal = Catalog::empty();
        let discovery = crate::support::test_support::catalog()
            .expect("existing discovery-only test declarations");
        let prepared = package_material().expect("prepared fixture package");
        assert!(normal.models.is_empty());
        assert!(normal.runtimes.is_empty());
        let discovery_model = discovery.model(SUPPORT_REF).expect("Phase 2 declaration");
        let prepared_model = prepared
            .catalog
            .model(SUPPORT_REF)
            .expect("prepared Stage 3 declaration");
        assert_ne!(discovery_model.id, prepared_model.id);
        assert_ne!(
            discovery_model.document_sha256,
            prepared_model.document_sha256
        );
        assert!(prepared_model.test_only);
        assert!(prepared_model.tasks[0].unresolved_paths.is_empty());
        assert!(
            prepared
                .catalog
                .runtime(RUNTIME_REF)
                .is_some_and(|runtime| runtime.test_only)
        );
    }

    #[test]
    fn missing_preparation_is_rejected_before_catalog_publication() {
        let isolated = TempDir::new().expect("temporary parent");
        let root_path = isolated.path().join("engine");
        let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
            .expect("private empty root");
        assert_eq!(
            load_prepared_fixture(&root, Path::new("unused-probe"))
                .expect_err("missing manifest is not prepared"),
            FixtureError::NotPrepared
        );
    }

    #[test]
    fn preparation_report_binds_installed_package_sources_and_probe_bytes() {
        let isolated = TempDir::new().expect("temporary parent");
        let root_path = isolated.path().join("engine");
        let root =
            OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
        root.ensure_private_directory(&relative(PACKAGE_DIR).unwrap())
            .expect("package directory");
        root.ensure_private_directory(&relative(SOURCE_DIR).unwrap())
            .expect("source directory");
        root.ensure_private_directory(&relative(REALIZATION_DIR).unwrap())
            .expect("realization directory");
        let material = package_material().expect("controlled package");
        let package_files = write_package(&root, &material).expect("install package");
        let source_files = write_sources(&root, &material).expect("install sources");
        let probe = b"controlled native probe executable bytes";
        root.write_atomic(&relative(PROBE_BINARY).unwrap(), probe)
            .expect("install probe bytes");
        let mut report = report_from_material(
            &material,
            package_files,
            source_files,
            digest(probe),
            "prepared",
        )
        .expect("preparation report");
        report.readiness_fingerprint = readiness_fingerprint(&report);
        seal_report(&mut report).expect("seal report");
        validate_report(&root, &report, probe).expect("exact prepared bytes validate");

        let mut rebuilt_probe = probe.to_vec();
        rebuilt_probe.push(b'!');
        assert_eq!(
            validate_report(&root, &report, &rebuilt_probe),
            Err(FixtureError::Integrity),
            "a different probe build invalidates readiness"
        );

        root.write_atomic(&relative(PROBE_BINARY).unwrap(), b"tampered probe")
            .expect("tamper installed runtime realization");
        assert_eq!(
            validate_report(&root, &report, probe),
            Err(FixtureError::Integrity),
            "tampered installed probe bytes invalidate readiness"
        );
        root.write_atomic(&relative(PROBE_BINARY).unwrap(), probe)
            .expect("restore probe fixture for package check");

        root.write_atomic(
            &relative("submission-fixture/package/runtime.json").unwrap(),
            b"tampered runtime",
        )
        .expect("tamper fixture package");
        assert_eq!(
            validate_report(&root, &report, probe),
            Err(FixtureError::Integrity),
            "tampered installed package bytes fail rehash"
        );
    }

    #[test]
    fn failed_prepare_refuses_a_nonempty_root_without_activating_partial_state() {
        let isolated = TempDir::new().expect("temporary parent");
        let root_path = isolated.path().join("engine");
        let root =
            OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
        let marker = relative("keep.txt").unwrap();
        root.write_atomic(&marker, b"pre-existing user state")
            .expect("pre-existing file");
        assert_eq!(
            prepare_submission_fixture(&root_path),
            Err(FixtureError::NonEmptyRoot)
        );
        assert_eq!(
            root.read_file(&marker, 128).unwrap(),
            b"pre-existing user state"
        );
        assert!(
            root.read_file(&relative(ACTIVE_MANIFEST).unwrap(), REPORT_LIMIT)
                .is_err()
        );
    }
}
