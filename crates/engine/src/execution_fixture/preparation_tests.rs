//! WE-P05/3 preparation of the r2 package: install, contained probe,
//! activation, re-verification on load, refusal of tampering and reuse, and a
//! real supervised attempt by the installed worker (copy into staging).
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
use super::preparation::{PreparedExecutionFixture, WorkerLaunch, load, prepare};
use super::{
    ADAPTER_ID, ADAPTER_REVISION, FEATURES, FixtureParameters, OUTPUT_NAME, STAGES, sha256_hex,
};
use super::{CLOSURE_MANIFEST, CLOSURE_SHA256, SOURCE_FILES, SOURCE_MARKER, expected_marker};
use crate::execution::attempt_files::{AttemptInput, prepare_attempt_files};
use crate::execution::fake_worker::{LedgerMode, TestLedger};
use crate::execution::launcher::PlatformLauncher;
use crate::execution::legality::WorkerExpectation;
use crate::execution::supervisor::WorkerSupervisor;
use crate::execution::supervisor_tests::{bounded, dispatch, process_limits};
use crate::execution::types::{AttemptExit, AttemptPlan, StopIntent, SupervisionLimits};
use crate::submission_fixture::FixtureError;
use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose};
use std::path::{Path, PathBuf};
use tokio::sync::watch;

const ENTRY: &str = "execution::r2_worker_tests::r2_worker_entry";
const MESH: &[u8] = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");

fn guardian() -> Option<PathBuf> {
    if cfg!(unix) {
        let path = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("dissect3d-worker-guardian");
        assert!(
            path.is_file(),
            "build the guardian first: cargo build -p dissect3d-platform --bins"
        );
        Some(path)
    } else {
        None
    }
}

/// This test binary re-executed as the r2 worker.
fn worker_launch(entry: &str) -> WorkerLaunch {
    WorkerLaunch {
        executable: std::env::current_exe().unwrap(),
        args: ["--exact", entry, "--nocapture", "--test-threads=1"]
            .map(str::to_owned)
            .to_vec(),
        environment: vec![("D3D_R2_WORKER".to_owned(), "1".to_owned())],
        guardian: guardian(),
    }
}

fn prepared() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("engine");
    prepare(&root, &worker_launch(ENTRY)).unwrap();
    (temp, root)
}

fn open(root: &Path) -> OwnedRoot {
    OwnedRoot::open(root, RootPurpose::EngineData).unwrap()
}

fn tamper(root: &Path, relative: &str) {
    let path = root.join(relative);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn prepared_r2_package_resolves_and_records_the_exact_worker() {
    let (_temp, root) = prepared();
    let fixture = load(&open(&root)).unwrap();
    assert_eq!(fixture.resolved.support_ref, "test.mesh-copy@fixture-r2");
    assert_eq!(fixture.resolved.runtime_ref, "test.cpu@fixture-r2");
    assert_eq!(fixture.resolved.variant, "fixture");
    assert_eq!(fixture.resolved.adapter.id, ADAPTER_ID);
    assert_eq!(fixture.resolved.adapter.revision, ADAPTER_REVISION);
    assert_eq!(
        fixture.worker_sha256,
        sha256_hex(&std::fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    assert_eq!(fixture.readiness_fingerprint.len(), 64);
    // No pending report remains after activation.
    assert!(
        !root
            .join("execution-fixture/prepared.pending.json")
            .exists()
    );
}

#[test]
fn a_prepared_root_is_never_prepared_again() {
    let (_temp, root) = prepared();
    assert_eq!(
        prepare(&root, &worker_launch(ENTRY)).unwrap_err(),
        FixtureError::NonEmptyRoot
    );
}

#[test]
fn tampered_worker_package_or_report_fails_verification() {
    for target in [
        "execution-fixture/realization/worker",
        "execution-fixture/package/4-support.json",
        "execution-fixture/sources/adapter.rs",
        "execution-fixture/prepared.json",
    ] {
        let (_temp, root) = prepared();
        tamper(&root, target);
        assert_eq!(
            load(&open(&root)).err(),
            Some(FixtureError::Integrity),
            "{target}"
        );
    }
}

#[test]
fn a_probe_that_does_not_see_the_exact_worker_never_activates() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("engine");
    // Launchable, but not a worker: it exits without a hello.
    let launch =
        worker_launch("execution::r2_worker_tests::declared_parameters_are_closed_booleans");
    assert_eq!(prepare(&root, &launch).unwrap_err(), FixtureError::Probe);
    assert_eq!(load(&open(&root)).err(), Some(FixtureError::NotPrepared));
}

#[test]
fn relative_or_missing_launch_paths_are_refused_before_anything_is_written() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("engine");
    let mut launch = worker_launch(ENTRY);
    launch.executable = PathBuf::from("worker");
    assert_eq!(
        prepare(&root, &launch).unwrap_err(),
        FixtureError::InvalidRoot
    );
    assert!(!root.exists());
}

#[tokio::test]
async fn the_installed_worker_runs_a_supervised_copy_attempt() {
    let (_temp, root_path) = prepared();
    let root = open(&root_path);
    let fixture: PreparedExecutionFixture = load(&root).unwrap();
    let mut command = fixture.command(&root).unwrap();
    root.ensure_private_directory(&RelativePath::parse("inputs".to_owned()).unwrap())
        .unwrap();
    let mesh = RelativePath::parse("inputs/mesh.obj".to_owned()).unwrap();
    root.write_atomic(&mesh, MESH).unwrap();
    let reader = root.open_immutable_input(&mesh).unwrap();
    let record = dispatch(None);
    let handles = prepare_attempt_files(
        &root,
        &record.attempt_id,
        &fixture.resolution_document,
        &FixtureParameters::default().to_document(),
        &[AttemptInput {
            role: "mesh",
            reader: &reader,
            sha256: &sha256_hex(MESH),
            byte_length: MESH.len() as u64,
        }],
        &mut command,
    )
    .unwrap();
    let plan = AttemptPlan {
        expectation: WorkerExpectation {
            worker_build_sha256: fixture.worker_sha256.clone(),
            adapter_id: ADAPTER_ID.into(),
            adapter_revision: ADAPTER_REVISION.into(),
            required_features: FEATURES.iter().map(|f| (*f).to_owned()).collect(),
            resolution_sha256: sha256_hex(&fixture.resolution_document),
        },
        resolution_handle: handles.resolution_handle.clone(),
        inputs: handles.inputs.clone(),
        output_staging_handle: handles.output_staging_handle.clone(),
        effective_parameters_handle: handles.effective_parameters_handle.clone(),
        stages: STAGES,
        limits: SupervisionLimits {
            handshake: SupervisionLimits::CONTRACT.handshake,
            load: SupervisionLimits::CONTRACT.load,
            ..process_limits()
        },
    };
    let (_stop_tx, stop_rx) = watch::channel(StopIntent::Continue);
    let (obs_tx, _obs_rx) = watch::channel(None);
    let exit = bounded(WorkerSupervisor::run(
        &record,
        plan,
        PlatformLauncher::new(command),
        TestLedger::new(LedgerMode::Accept),
        stop_rx,
        &obs_tx,
    ))
    .await;
    let AttemptExit::Candidate { report, .. } = &exit else {
        panic!("expected a candidate, got {exit:?}");
    };
    assert_eq!(report.files[0].sha256, sha256_hex(MESH));
    let staged = handles.staging.worker_path().join(OUTPUT_NAME);
    assert_eq!(std::fs::read(staged).unwrap(), MESH);
}

#[test]
fn the_embedded_marker_names_exactly_the_recorded_closure() {
    assert_eq!(sha256_hex(CLOSURE_MANIFEST.as_bytes()), CLOSURE_SHA256);
    assert_eq!(
        SOURCE_MARKER.as_slice(),
        expected_marker(CLOSURE_SHA256).as_slice()
    );
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, files);
        } else {
            files.push(path);
        }
    }
}

/// Independent of `build.rs`: the closure lists exactly every file of the
/// workspace crates the worker links (engine, api, platform, connection) plus
/// the workspace manifest, lockfile and toolchain file, each with its current
/// digest, then the rustc release, target, profile, features and rustflags.
#[test]
fn the_recorded_closure_is_every_file_the_worker_is_built_from() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    let mut files = Vec::new();
    for name in ["engine", "api", "platform", "connection"] {
        walk(&workspace.join("crates").join(name), &mut files);
    }
    for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        files.push(workspace.join(name));
    }
    let mut expected: Vec<String> = files
        .iter()
        .map(|path| {
            let relative = path
                .strip_prefix(workspace)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_str().unwrap())
                .collect::<Vec<_>>()
                .join("/");
            format!(
                "file {} {relative}",
                sha256_hex(&std::fs::read(path).unwrap())
            )
        })
        .collect();
    expected.sort_by(|a, b| a[70..].cmp(&b[70..]));
    let lines: Vec<&str> = CLOSURE_MANIFEST.lines().collect();
    let (files_listed, rest) = lines.split_at(lines.len() - 5);
    assert_eq!(files_listed, expected.as_slice());
    assert!(rest[0].starts_with("rustc ") && rest[0].split(' ').count() == 3);
    assert!(rest[1].starts_with("target ") && rest[1].len() > 7);
    assert!(rest[2].starts_with("profile ") && rest[2].contains(" opt-level "));
    // This build has test-support on, as the prepared worker's must (Cargo
    // exposes feature names to build scripts with `-` mapped to `_`).
    assert_eq!(rest[3], "features test_support");
    assert!(rest[4].starts_with("rustflags ") && rest[4].len() == 10 + 64);
    for (name, path, bytes) in SOURCE_FILES {
        let line = format!("file {} {path}", sha256_hex(bytes));
        assert!(lines.contains(&line.as_str()), "{name}");
    }
}

/// A sealed report whose recorded closure differs from this build's (a line
/// edited, the seal recomputed) is refused on load.
#[test]
fn a_report_recording_another_closure_is_refused() {
    let (_temp, root) = prepared();
    let path = root.join("execution-fixture/prepared.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let digest = &CLOSURE_MANIFEST[5..69];
    let other = format!(
        "{}{}",
        &digest[..63],
        if digest.ends_with('0') { '1' } else { '0' }
    );
    let edited = text.replacen(&format!("\"file {digest} "), &format!("\"file {other} "), 1);
    assert_ne!(edited, text);
    let (head, tail) = edited.split_once("\"integrity_sha256\":\"").unwrap();
    let unsealed = format!("{head}\"integrity_sha256\":\"{}", &tail[64..]);
    let resealed = format!(
        "{head}\"integrity_sha256\":\"{}{}",
        sha256_hex(unsealed.as_bytes()),
        &tail[64..]
    );
    std::fs::write(&path, resealed).unwrap();
    assert_eq!(load(&open(&root)).err(), Some(FixtureError::Integrity));
}

#[test]
fn a_worker_built_from_other_sources_is_refused_before_activation() {
    let temp = tempfile::tempdir().unwrap();
    // A copy of the worker whose embedded closure marker differs by one digit,
    // as a build from different sources, lockfile or toolchain would.
    let mut bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let at = bytes
        .windows(SOURCE_MARKER.len())
        .position(|w| w == SOURCE_MARKER.as_slice())
        .expect("the worker embeds its closure marker");
    let digit = at + SOURCE_MARKER.len() - 2;
    bytes[digit] = if bytes[digit] == b'0' { b'1' } else { b'0' };
    let other = temp
        .path()
        .join(if cfg!(windows) { "other.exe" } else { "other" });
    std::fs::write(&other, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut launch = worker_launch(ENTRY);
    launch.executable = other;
    let root = temp.path().join("engine");
    assert_eq!(
        prepare(&root, &launch).unwrap_err(),
        FixtureError::Integrity
    );
    assert_eq!(load(&open(&root)).err(), Some(FixtureError::NotPrepared));
}
