//! WE-P05/3 explicit test-only preparation of the r2 controlled CPU package:
//! `test.mesh-copy@fixture-r2` on `test.cpu@fixture-r2`.
//!
//! Installs the declared package documents (resolved by the real catalog),
//! the recorded sources, the worker executable and (Linux) the guardian into
//! a fresh private root, each recorded by hash with the exact worker launch
//! arguments. A contained probe launches the installed worker and requires its
//! `hello` to report exactly the recorded build and adapter identity; that is
//! integrity and launchability, never loaded execution (loading is proven only
//! by `loaded` during an attempt). The report is sealed, written pending,
//! then activated once; a prepared root is never replaced. Loading re-verifies
//! every byte before handing out a launch command. No downloads, system
//! Python, GPU runtime or global installation.
use super::{
    ADAPTER_ID, ADAPTER_REVISION, CLOSURE_MANIFEST, CLOSURE_SHA256, SOURCE_FILES, expected_marker,
    sha256_hex,
};
use crate::submission_fixture::{FixtureError, PreparedReadiness, selection_snapshot_value};
use crate::support::{Catalog, ControlledPackage, DiscoveryLimits, ResolvedSelection, Selection};
use crate::worker_protocol::{WorkerReport, decode_inbound, random_id};
use dissect3d_api::{ContentDigest, PreparedReadiness as PreparedReadinessDto, TaskKey};
use dissect3d_platform::{
    AuthorityLease, OwnedRoot, RelativePath, RootPurpose, WorkerCommand, WorkerProcess,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) const SUPPORT_REF: &str = "test.mesh-copy@fixture-r2";
pub(crate) const RUNTIME_REF: &str = "test.cpu@fixture-r2";
const TASK_ID: &str = "dissect3d.test.mesh-copy";
const TASK_VERSION: &str = "1.0";
const VARIANT: &str = "fixture";
const CHECK_ID: &str = "fixture.cpu.worker-probe@2";
/// The output validator the task binding names (RP-P01 owns its behavior).
const VALIDATOR_ID: &str = dissect3d_api::TEST_OUTPUT_VALIDATOR_ID;
const VALIDATOR_REVISION: &str = dissect3d_api::TEST_OUTPUT_VALIDATOR_REVISION;

const BASE: &str = "execution-fixture";
const PENDING: &str = "execution-fixture/prepared.pending.json";
const ACTIVE: &str = "execution-fixture/prepared.json";
const WORKER_FILE: &str = "execution-fixture/realization/worker";
const GUARDIAN_FILE: &str = "execution-fixture/realization/guardian";
const REPORT_LIMIT: usize = 1_048_576;
const FILE_LIMIT: usize = 268_435_456;
/// Bounded recorded launch inputs (WorkerCommand validates again).
const LAUNCH_VALUES_MAX: usize = 16;
const PROBE_BOUND: Duration = Duration::from_secs(20);

/// The exact worker launch the preparation records: an executable plus
/// finite arguments and environment (the example needs none; a test binary
/// re-executed as the worker does).
pub(crate) struct WorkerLaunch {
    pub(crate) executable: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) environment: Vec<(String, String)>,
    pub(crate) guardian: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    sha256: String,
    byte_length: u64,
    kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: String,
    status: String,
    evidence_scope: String,
    check_id: String,
    target_os: String,
    target_architecture: String,
    support_ref: String,
    support_id: String,
    task_binding_id: String,
    runtime_ref: String,
    runtime_id: String,
    variant: String,
    catalog_revision: String,
    adapter_id: String,
    adapter_revision: String,
    artifacts: Vec<Artifact>,
    worker_sha256: String,
    /// The worker's build closure (`build.rs` manifest lines: every file of
    /// the engine and its workspace path dependencies, workspace manifest,
    /// `Cargo.lock`, toolchain configuration, rustc release, target) and its
    /// digest. The installed worker must embed the matching marker.
    worker_closure: Vec<String>,
    worker_closure_sha256: String,
    validator_id: String,
    validator_revision: String,
    worker_args: Vec<String>,
    worker_environment: Vec<(String, String)>,
    guardian_sha256: Option<String>,
    readiness_fingerprint: String,
    integrity_sha256: String,
}

/// Verified prepared r2 support: resolution plus a launchable worker.
pub(crate) struct PreparedExecutionFixture {
    pub(crate) catalog: Catalog,
    pub(crate) resolved: ResolvedSelection,
    /// The exact resolution document handed to the worker.
    pub(crate) resolution_document: Vec<u8>,
    pub(crate) readiness_fingerprint: String,
    /// The readiness facts admission captures and dispatch compares; built
    /// once from the verified report, never re-derived per job.
    pub(crate) readiness: PreparedReadiness,
    /// The worker build identity `hello` must report.
    pub(crate) worker_sha256: String,
    worker: PathBuf,
    guardian: Option<PathBuf>,
    args: Vec<String>,
    environment: Vec<(String, String)>,
}

impl PreparedExecutionFixture {
    /// A launch command for the installed worker, after re-verifying the
    /// installed worker and guardian bytes against the prepared report.
    pub(crate) fn command(&self, report_root: &OwnedRoot) -> Result<WorkerCommand, FixtureError> {
        let fresh = load(report_root)?;
        if fresh.worker_sha256 != self.worker_sha256
            || fresh.readiness.snapshot != self.readiness.snapshot
        {
            return Err(FixtureError::Integrity);
        }
        let mut command = WorkerCommand::new(self.worker.clone());
        command.args = self.args.iter().map(OsString::from).collect();
        command.environment = self
            .environment
            .iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        command.guardian = self.guardian.clone();
        Ok(command)
    }
}

struct Material {
    documents: Vec<(String, String, Vec<u8>)>,
    index: Vec<u8>,
    sources: Vec<(String, Vec<u8>)>,
    catalog: Catalog,
    resolved: ResolvedSelection,
}

fn relative(path: &str) -> Result<RelativePath, FixtureError> {
    RelativePath::parse(path.to_owned()).map_err(|_| FixtureError::Package)
}

fn selection() -> Result<Selection, FixtureError> {
    Ok(Selection {
        support_ref: SUPPORT_REF.to_owned(),
        task: TaskKey::new(TASK_ID, TASK_VERSION).map_err(|_| FixtureError::Package)?,
        runtime_ref: Some(RUNTIME_REF.to_owned()),
        variant: Some(VARIANT.to_owned()),
    })
}

fn schema_ref(bytes: &[u8]) -> Result<String, FixtureError> {
    let schema: Value = serde_json::from_slice(bytes).map_err(|_| FixtureError::Package)?;
    match (schema["id"].as_str(), schema["version"].as_str()) {
        (Some(id), Some(version)) => Ok(format!("{id}@{version}")),
        _ => Err(FixtureError::Package),
    }
}

/// The exact package and sources compiled into this build.
fn material() -> Result<Material, FixtureError> {
    // The task 1.0 schemas are the same declared documents as r1 (unchanged bytes).
    let input = include_bytes!("../../tests/fixtures/submission/input-schema.json").to_vec();
    let parameters =
        include_bytes!("../../tests/fixtures/submission/parameters-schema.json").to_vec();
    let output = include_bytes!("../../tests/fixtures/submission/output-schema.json").to_vec();
    let runtime = include_bytes!("../../tests/fixtures/execution/runtime.json").to_vec();
    let adapter = include_bytes!("../../tests/fixtures/execution/adapter.rs").to_vec();
    let worker_source = include_bytes!("../execution_fixture.rs").to_vec();
    let mut support: Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/execution/support-template.json"
    ))
    .map_err(|_| FixtureError::Package)?;
    let binding = support["tasks"]
        .as_array_mut()
        .and_then(|tasks| tasks.first_mut())
        .ok_or(FixtureError::Package)?;
    for (field, bytes) in [
        ("input_schema", &input),
        ("parameter_schema", &parameters),
        ("output_schema", &output),
    ] {
        if schema_ref(bytes)?
            != format!(
                "{}@{}",
                binding[field]["id"].as_str().unwrap_or_default(),
                binding[field]["version"].as_str().unwrap_or_default()
            )
        {
            return Err(FixtureError::Package);
        }
        binding[field]["sha256"] = Value::String(sha256_hex(bytes));
    }
    if binding["validator"]["id"] != VALIDATOR_ID
        || binding["validator"]["revision"] != VALIDATOR_REVISION
    {
        return Err(FixtureError::Package);
    }
    if support["adapter"]["id"] != ADAPTER_ID || support["adapter"]["revision"] != ADAPTER_REVISION
    {
        return Err(FixtureError::Package);
    }
    support["adapter"]["sha256"] = Value::String(sha256_hex(&adapter));
    support["code"]["executed_revision"] =
        Value::String(format!("sha256:{}", sha256_hex(&worker_source)));
    let support = serde_json::to_vec(&support).map_err(|_| FixtureError::Package)?;
    let documents = vec![
        ("schema".to_owned(), schema_ref(&input)?, input),
        ("schema".to_owned(), schema_ref(&parameters)?, parameters),
        ("schema".to_owned(), schema_ref(&output)?, output),
        ("runtime".to_owned(), RUNTIME_REF.to_owned(), runtime),
        ("support".to_owned(), SUPPORT_REF.to_owned(), support),
    ];
    let index = serde_json::to_vec(&json!({
        "schema_version": "1.0",
        "required_features": [],
        "documents": documents.iter().map(|(kind, reference, bytes)| json!({
            "kind": kind,
            "ref": reference,
            "sha256": sha256_hex(bytes),
            "byte_length": bytes.len(),
        })).collect::<Vec<_>>(),
        "aliases": [],
    }))
    .map_err(|_| FixtureError::Package)?;
    let catalog = Catalog::from_packages(
        vec![ControlledPackage {
            index_bytes: index.clone(),
            document_bytes: documents.iter().map(|(_, _, b)| b.clone()).collect(),
        }],
        DiscoveryLimits::default(),
    )
    .map_err(|_| FixtureError::Package)?;
    let resolved = catalog
        .resolve(&selection()?)
        .map_err(|_| FixtureError::Package)?;
    // The worker's own sources first; each must be the file of the same
    // workspace path in this build's closure.
    let mut sources: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, path, bytes) in SOURCE_FILES {
        if closure_entry(path) != Some(sha256_hex(bytes)) {
            return Err(FixtureError::Package);
        }
        sources.push((name.to_owned(), bytes.to_vec()));
    }
    if sources[0].1 != worker_source || sources[1].1 != adapter {
        return Err(FixtureError::Package);
    }
    sources.extend([
        (
            "validator.rs".to_owned(),
            include_bytes!("../../tests/fixtures/submission/validator.rs").to_vec(),
        ),
        (
            "engine-obj.rs".to_owned(),
            include_bytes!("../submission/obj.rs").to_vec(),
        ),
        (
            "tetrahedron.obj".to_owned(),
            include_bytes!("../../tests/fixtures/submission/tetrahedron.obj").to_vec(),
        ),
    ]);
    Ok(Material {
        documents,
        index,
        sources,
        catalog,
        resolved,
    })
}

/// The readiness snapshot an r2 acceptance captures: the probe check, the
/// sealed report and the exact worker build and closure it verified.
fn readiness_snapshot(report: &Report) -> Result<PreparedReadinessDto, FixtureError> {
    let digest =
        |value: &str| ContentDigest::parse(value.to_owned()).map_err(|_| FixtureError::Integrity);
    Ok(PreparedReadinessDto {
        check_id: report.check_id.clone(),
        fingerprint: digest(&report.readiness_fingerprint)?,
        runtime_realization: format!(
            "native-test:{}:{}:worker-sha256:{}:closure-sha256:{}:manifest-sha256:{}",
            report.target_os,
            report.target_architecture,
            report.worker_sha256,
            report.worker_closure_sha256,
            report.integrity_sha256,
        ),
        integrity_sha256: digest(&report.integrity_sha256)?,
    })
}

/// The exact resolution document handed to the worker (canonical selection).
fn resolution_document(resolved: &ResolvedSelection) -> Result<Vec<u8>, FixtureError> {
    serde_json::to_vec(&selection_snapshot_value(resolved)).map_err(|_| FixtureError::Package)
}

fn bounded_launch(launch: &WorkerLaunch) -> Result<(), FixtureError> {
    let paths = std::iter::once(&launch.executable).chain(launch.guardian.as_ref());
    for path in paths {
        if !path.is_absolute() || !path.is_file() {
            return Err(FixtureError::InvalidRoot);
        }
    }
    let values = launch
        .args
        .iter()
        .chain(launch.environment.iter().flat_map(|(k, v)| [k, v]));
    if launch.args.len() > LAUNCH_VALUES_MAX
        || launch.environment.len() > LAUNCH_VALUES_MAX
        || values.clone().any(|v| v.len() > 1_024 || v.contains('\0'))
    {
        return Err(FixtureError::Package);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if launch.guardian.is_none() {
        return Err(FixtureError::Package);
    }
    Ok(())
}

fn fingerprint(report: &Report) -> String {
    let mut rows: Vec<_> = report
        .artifacts
        .iter()
        .map(|a| format!("{}\t{}\t{}\n", a.kind, a.path, a.sha256))
        .collect();
    rows.sort();
    let mut preimage = format!(
        "dissect3d-execution-fixture-readiness-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        report.target_os,
        report.target_architecture,
        report.catalog_revision,
        report.support_id,
        report.task_binding_id,
        report.runtime_id,
        report.adapter_id,
        report.adapter_revision,
        report.worker_sha256,
        report.guardian_sha256.as_deref().unwrap_or("-"),
        report.check_id,
    );
    preimage.push_str(&format!(
        "validator\t{}\t{}\nclosure\t{}\n",
        report.validator_id, report.validator_revision, report.worker_closure_sha256
    ));
    for (key, value) in &report.worker_environment {
        preimage.push_str(&format!("env\t{key}\t{value}\n"));
    }
    for arg in &report.worker_args {
        preimage.push_str(&format!("arg\t{arg}\n"));
    }
    for row in rows {
        preimage.push_str(&row);
    }
    sha256_hex(preimage.as_bytes())
}

fn seal(report: &mut Report) -> Result<Vec<u8>, FixtureError> {
    report.integrity_sha256.clear();
    report.integrity_sha256 =
        sha256_hex(&serde_json::to_vec(report).map_err(|_| FixtureError::Storage)?);
    serde_json::to_vec(report).map_err(|_| FixtureError::Storage)
}

fn install(
    root: &OwnedRoot,
    path: &str,
    kind: &str,
    bytes: &[u8],
    artifacts: &mut Vec<Artifact>,
) -> Result<(), FixtureError> {
    root.write_atomic(&relative(path)?, bytes)
        .map_err(|_| FixtureError::Storage)?;
    artifacts.push(Artifact {
        path: path.to_owned(),
        sha256: sha256_hex(bytes),
        byte_length: bytes.len() as u64,
        kind: kind.to_owned(),
    });
    Ok(())
}

/// Prepare a fresh, empty private root. Refuses a non-empty or prepared root.
pub(crate) fn prepare(data_root: &Path, launch: &WorkerLaunch) -> Result<(), FixtureError> {
    if !data_root.is_absolute() {
        return Err(FixtureError::InvalidRoot);
    }
    bounded_launch(launch)?;
    let root = if data_root.exists() {
        if std::fs::read_dir(data_root)
            .map_err(|_| FixtureError::InvalidRoot)?
            .next()
            .is_some()
        {
            return Err(FixtureError::NonEmptyRoot);
        }
        OwnedRoot::open(data_root, RootPurpose::EngineData)
    } else {
        OwnedRoot::create_private(data_root, RootPurpose::EngineData)
    }
    .map_err(|_| FixtureError::InvalidRoot)?;
    let lease = AuthorityLease::acquire(&root).map_err(|_| FixtureError::AuthorityUnavailable)?;
    for directory in ["package", "sources", "realization"] {
        root.ensure_private_directory(&relative(&format!("{BASE}/{directory}"))?)
            .map_err(|_| FixtureError::Storage)?;
    }
    let material = material()?;
    let mut artifacts = Vec::new();
    install(
        &root,
        &format!("{BASE}/package/index.json"),
        "index",
        &material.index,
        &mut artifacts,
    )?;
    for (number, (kind, _, bytes)) in material.documents.iter().enumerate() {
        let path = format!("{BASE}/package/{number}-{kind}.json");
        install(&root, &path, kind, bytes, &mut artifacts)?;
    }
    for (name, bytes) in &material.sources {
        install(
            &root,
            &format!("{BASE}/sources/{name}"),
            "source",
            bytes,
            &mut artifacts,
        )?;
    }
    let worker = std::fs::read(&launch.executable).map_err(|_| FixtureError::Package)?;
    install(&root, WORKER_FILE, "worker", &worker, &mut artifacts)?;
    let guardian_sha256 = match &launch.guardian {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|_| FixtureError::Package)?;
            install(&root, GUARDIAN_FILE, "guardian", &bytes, &mut artifacts)?;
            Some(sha256_hex(&bytes))
        }
        None => None,
    };
    executable_permissions(&root)?;
    let mut report = Report {
        schema_version: "2.0".to_owned(),
        status: "preparing".to_owned(),
        evidence_scope: "controlled-test-only".to_owned(),
        check_id: CHECK_ID.to_owned(),
        target_os: std::env::consts::OS.to_owned(),
        target_architecture: std::env::consts::ARCH.to_owned(),
        support_ref: material.resolved.support_ref.clone(),
        support_id: material.resolved.support_id.clone(),
        task_binding_id: material.resolved.task_binding_id.clone(),
        runtime_ref: material.resolved.runtime_ref.clone(),
        runtime_id: material.resolved.runtime_id.clone(),
        variant: material.resolved.variant.clone(),
        catalog_revision: material.catalog.revision.clone(),
        adapter_id: ADAPTER_ID.to_owned(),
        adapter_revision: ADAPTER_REVISION.to_owned(),
        artifacts,
        worker_sha256: sha256_hex(&worker),
        worker_closure: closure_lines(),
        worker_closure_sha256: CLOSURE_SHA256.to_owned(),
        validator_id: VALIDATOR_ID.to_owned(),
        validator_revision: VALIDATOR_REVISION.to_owned(),
        worker_args: launch.args.clone(),
        worker_environment: launch.environment.clone(),
        guardian_sha256,
        readiness_fingerprint: String::new(),
        integrity_sha256: String::new(),
    };
    root.write_atomic(&relative(PENDING)?, &seal(&mut report)?)
        .map_err(|_| FixtureError::Storage)?;
    // Verify the installed bytes, then probe the installed worker.
    verify(&root, &report)?;
    probe(&root, &report)?;
    report.status = "prepared".to_owned();
    report.readiness_fingerprint = fingerprint(&report);
    root.write_atomic(&relative(ACTIVE)?, &seal(&mut report)?)
        .map_err(|_| FixtureError::Storage)?;
    root.remove_file(&relative(PENDING)?)
        .map_err(|_| FixtureError::Storage)?;
    drop(lease);
    Ok(())
}

fn closure_lines() -> Vec<String> {
    CLOSURE_MANIFEST.lines().map(str::to_owned).collect()
}

/// The closure digest of one workspace file, if the closure lists it.
fn closure_entry(path: &str) -> Option<String> {
    CLOSURE_MANIFEST.lines().find_map(|line| {
        let (digest, listed) = line.strip_prefix("file ")?.split_once(' ')?;
        (listed == path).then(|| digest.to_owned())
    })
}

/// The recorded closure is this build's, self-consistent, and its digest is
/// the one the worker must embed.
fn closure_recorded(report: &Report) -> bool {
    let mut manifest = report.worker_closure.join("\n");
    manifest.push('\n');
    report.worker_closure == closure_lines()
        && report.worker_closure_sha256 == CLOSURE_SHA256
        && sha256_hex(manifest.as_bytes()) == report.worker_closure_sha256
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Installed executables must be runnable by their owner only.
fn executable_permissions(root: &OwnedRoot) -> Result<(), FixtureError> {
    #[cfg(unix)]
    for path in [WORKER_FILE, GUARDIAN_FILE] {
        use std::os::unix::fs::PermissionsExt;
        let native = root.path_for_native_vfs(&relative(path)?);
        if native.exists() {
            std::fs::set_permissions(&native, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| FixtureError::Storage)?;
        }
    }
    let _ = root;
    Ok(())
}

/// Every recorded artifact matches its bytes, and the package and sources
/// equal exactly what this build compiles in.
fn verify(root: &OwnedRoot, report: &Report) -> Result<(), FixtureError> {
    if report.schema_version != "2.0"
        || report.evidence_scope != "controlled-test-only"
        || report.check_id != CHECK_ID
        || report.target_os != std::env::consts::OS
        || report.target_architecture != std::env::consts::ARCH
        || report.support_ref != SUPPORT_REF
        || report.runtime_ref != RUNTIME_REF
        || report.variant != VARIANT
        || report.adapter_id != ADAPTER_ID
        || report.adapter_revision != ADAPTER_REVISION
        || report.validator_id != VALIDATOR_ID
        || report.validator_revision != VALIDATOR_REVISION
    {
        return Err(FixtureError::Integrity);
    }
    let mut unsealed = report.clone();
    let integrity = std::mem::take(&mut unsealed.integrity_sha256);
    if sha256_hex(&serde_json::to_vec(&unsealed).map_err(|_| FixtureError::Integrity)?) != integrity
    {
        return Err(FixtureError::Integrity);
    }
    let material = material()?;
    let mut expected: Vec<(String, String, String)> = vec![(
        format!("{BASE}/package/index.json"),
        "index".to_owned(),
        sha256_hex(&material.index),
    )];
    for (number, (kind, _, bytes)) in material.documents.iter().enumerate() {
        expected.push((
            format!("{BASE}/package/{number}-{kind}.json"),
            kind.clone(),
            sha256_hex(bytes),
        ));
    }
    for (name, bytes) in &material.sources {
        expected.push((
            format!("{BASE}/sources/{name}"),
            "source".to_owned(),
            sha256_hex(bytes),
        ));
    }
    expected.push((
        WORKER_FILE.to_owned(),
        "worker".to_owned(),
        report.worker_sha256.clone(),
    ));
    if let Some(guardian) = &report.guardian_sha256 {
        expected.push((
            GUARDIAN_FILE.to_owned(),
            "guardian".to_owned(),
            guardian.clone(),
        ));
    }
    let recorded: Vec<_> = report
        .artifacts
        .iter()
        .map(|a| (a.path.clone(), a.kind.clone(), a.sha256.clone()))
        .collect();
    if recorded != expected
        || report.catalog_revision != material.catalog.revision
        || report.support_id != material.resolved.support_id
        || report.task_binding_id != material.resolved.task_binding_id
        || report.runtime_id != material.resolved.runtime_id
        || !closure_recorded(report)
    {
        return Err(FixtureError::Integrity);
    }
    let marker = expected_marker(&report.worker_closure_sha256);
    for artifact in &report.artifacts {
        let bytes = root
            .read_file(&relative(&artifact.path)?, FILE_LIMIT)
            .map_err(|_| FixtureError::Integrity)?;
        if bytes.len() as u64 != artifact.byte_length || sha256_hex(&bytes) != artifact.sha256 {
            return Err(FixtureError::Integrity);
        }
        // The worker must have been built from exactly the recorded closure.
        if artifact.kind == "worker" && !contains(&bytes, &marker) {
            return Err(FixtureError::Integrity);
        }
    }
    Ok(())
}

fn launch_command(root: &OwnedRoot, report: &Report) -> Result<WorkerCommand, FixtureError> {
    let mut command = WorkerCommand::new(root.path_for_native_vfs(&relative(WORKER_FILE)?));
    command.args = report.worker_args.iter().map(OsString::from).collect();
    command.environment = report
        .worker_environment
        .iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    if report.guardian_sha256.is_some() {
        command.guardian = Some(root.path_for_native_vfs(&relative(GUARDIAN_FILE)?));
    }
    Ok(command)
}

/// Launch the installed worker contained and require its `hello` to report
/// exactly the recorded build and adapter identity; then end it and confirm
/// whole-tree cleanup. Launchability and identity only, not load evidence.
fn probe(root: &OwnedRoot, report: &Report) -> Result<(), FixtureError> {
    let session = random_id("ses_");
    let mut command = launch_command(root, report)?;
    command.environment.push((
        crate::execution::launcher::WORKER_SESSION_ENV.into(),
        session.clone().into(),
    ));
    let nonce =
        crate::store::launch_identity::session_nonce(&session).ok_or(FixtureError::Probe)?;
    let mut worker = WorkerProcess::launch(command, nonce).map_err(|_| FixtureError::Probe)?;
    let channels = worker.take_channels().ok_or(FixtureError::Probe)?;
    let (send, receive) = std::sync::mpsc::channel();
    let reports = channels.from_worker;
    std::thread::spawn(move || {
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(std::io::Read::take(reports, 65_536));
        let _ = reader.read_line(&mut line);
        let _ = send.send(line);
    });
    let hello = receive.recv_timeout(PROBE_BOUND).ok();
    // End the worker: close control, then establish termination.
    drop(channels.to_worker);
    drop(channels.diagnostics);
    let cleanup = worker.terminate_tree(Instant::now() + Duration::from_secs(5));
    let line = hello.ok_or(FixtureError::Probe)?;
    let frame = decode_inbound(line.trim_end_matches('\n')).map_err(|_| FixtureError::Probe)?;
    let WorkerReport::Hello(hello) = frame.report else {
        return Err(FixtureError::Probe);
    };
    if cleanup.is_err()
        || frame.session_id != session
        || hello.worker_build_sha256 != report.worker_sha256
        || hello.adapter_id != ADAPTER_ID
        || hello.adapter_revision != ADAPTER_REVISION
        || !super::FEATURES
            .iter()
            .all(|f| hello.features.iter().any(|h| h == f))
    {
        return Err(FixtureError::Probe);
    }
    Ok(())
}

/// Maintainer entry (feature-gated example only): prepare `data_root` with the
/// built `execution_fixture_worker` (no arguments or environment) and, on
/// Linux, the packaged guardian.
pub fn prepare_execution_fixture(
    data_root: &Path,
    worker: &Path,
    guardian: Option<&Path>,
) -> Result<(), FixtureError> {
    prepare(
        data_root,
        &WorkerLaunch {
            executable: worker.to_owned(),
            args: Vec::new(),
            environment: Vec::new(),
            guardian: guardian.map(Path::to_owned),
        },
    )
}

/// Load and re-verify a prepared root.
pub(crate) fn load(root: &OwnedRoot) -> Result<PreparedExecutionFixture, FixtureError> {
    let bytes = root
        .read_file(&relative(ACTIVE)?, REPORT_LIMIT)
        .map_err(|_| FixtureError::NotPrepared)?;
    let report: Report = serde_json::from_slice(&bytes).map_err(|_| FixtureError::Integrity)?;
    if report.status != "prepared" || report.readiness_fingerprint != fingerprint(&report) {
        return Err(FixtureError::Integrity);
    }
    verify(root, &report)?;
    let material = material()?;
    let command = launch_command(root, &report)?;
    let readiness = PreparedReadiness {
        resolved: material.resolved.clone(),
        snapshot: readiness_snapshot(&report)?,
    };
    Ok(PreparedExecutionFixture {
        readiness,
        resolution_document: resolution_document(&material.resolved)?,
        catalog: material.catalog,
        resolved: material.resolved,
        readiness_fingerprint: report.readiness_fingerprint.clone(),
        worker_sha256: report.worker_sha256.clone(),
        worker: command.executable,
        guardian: command.guardian,
        args: report.worker_args,
        environment: report.worker_environment,
    })
}
