//! WE-P05/4 real supervisor tests with the r2 controlled CPU worker
//! (`execution_fixture`): the test binary re-executes itself as that worker
//! through `PlatformLauncher`, with the resolution, effective parameters and
//! input passed as inherited read-only handles and one private staging folder
//! (`attempt_files`). Normal copy, hold with cooperative cancel, declared
//! failure, input mismatch and malformed private messages.
//!
//! This exercises supervision and the worker only: no dispatch, validation,
//! capture or publication. On Unix the guardian must already be built
//! (`cargo build -p dissect3d-platform --bins`).
use super::attempt_files::{AttemptHandles, AttemptInput, prepare_attempt_files};
use super::fake_worker::{LedgerMode, TestLedger};
use super::launcher::PlatformLauncher;
use super::legality::WorkerExpectation;
use super::progress::{AttemptPhase, ObservationUpdate};
use super::supervisor::WorkerSupervisor;
use super::supervisor_tests::{bounded, dispatch, process_limits};
use super::types::*;
use crate::execution_fixture::{
    ADAPTER_ID, ADAPTER_REVISION, DESCRIPTION_NAME, FAULT_ENV, FEATURES, FixtureParameters,
    OUTPUT_NAME, STAGES, sha256_hex,
};
use crate::store::execution::DispatchRecord;
use dissect3d_platform::{OwnedRoot, RelativePath, RootPurpose, WorkerCommand};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::watch;

const ENTRY: &str = "execution::r2_worker_tests::r2_worker_entry";
const WORKER_ENV: &str = "D3D_R2_WORKER";
const MESH: &[u8] = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");

/// Worker entry; a no-op in a normal test run.
#[test]
fn r2_worker_entry() {
    if std::env::var_os(WORKER_ENV).is_some() {
        crate::execution_fixture::run_execution_fixture_worker();
    }
}

/// The worker build identity: this test binary's bytes.
fn build_sha256() -> &'static str {
    static BUILD: OnceLock<String> = OnceLock::new();
    BUILD.get_or_init(|| sha256_hex(&std::fs::read(std::env::current_exe().unwrap()).unwrap()))
}

struct Attempt {
    _temp: tempfile::TempDir,
    root: OwnedRoot,
    handles: AttemptHandles,
    command: Option<WorkerCommand>,
    record: DispatchRecord,
}

fn command(fault: Option<&str>) -> WorkerCommand {
    let mut command = WorkerCommand::new(std::env::current_exe().unwrap());
    command.args = ["--exact", ENTRY, "--nocapture", "--test-threads=1"]
        .map(Into::into)
        .to_vec();
    command.environment = vec![(WORKER_ENV.into(), "1".into())];
    if let Some(fault) = fault {
        command.environment.push((FAULT_ENV.into(), fault.into()));
    }
    #[cfg(unix)]
    {
        let guardian = std::env::current_exe()
            .unwrap()
            .parent()
            .and_then(std::path::Path::parent)
            .unwrap()
            .join("dissect3d-worker-guardian");
        assert!(
            guardian.is_file(),
            "build the guardian first: cargo build -p dissect3d-platform --bins"
        );
        command.guardian = Some(guardian);
    }
    command
}

/// A private root with one captured mesh, and the attempt's files.
fn attempt(
    parameters: FixtureParameters,
    declared_sha256: Option<&str>,
    fault: Option<&str>,
) -> Attempt {
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData).unwrap();
    root.ensure_private_directory(&RelativePath::parse("inputs".to_owned()).unwrap())
        .unwrap();
    let mesh = RelativePath::parse("inputs/mesh.obj".to_owned()).unwrap();
    root.write_atomic(&mesh, MESH).unwrap();
    let reader = root.open_immutable_input(&mesh).unwrap();
    let record = dispatch(None);
    let sha256 = sha256_hex(MESH);
    let mut command = command(fault);
    let handles = prepare_attempt_files(
        &root,
        &record.attempt_id,
        br#"{"support_ref":"test.mesh-copy@fixture-r2"}"#,
        &parameters.to_document(),
        &[AttemptInput {
            role: "mesh",
            reader: &reader,
            sha256: declared_sha256.unwrap_or(&sha256),
            byte_length: MESH.len() as u64,
        }],
        &mut command,
    )
    .unwrap();
    Attempt {
        _temp: temp,
        root,
        handles,
        command: Some(command),
        record,
    }
}

impl Attempt {
    fn plan(&self) -> AttemptPlan {
        AttemptPlan {
            expectation: WorkerExpectation {
                worker_build_sha256: build_sha256().to_owned(),
                adapter_id: ADAPTER_ID.into(),
                adapter_revision: ADAPTER_REVISION.into(),
                required_features: FEATURES.iter().map(|f| (*f).to_owned()).collect(),
                resolution_sha256: self.handles.resolution_sha256.clone(),
            },
            resolution_handle: self.handles.resolution_handle.clone(),
            inputs: self.handles.inputs.clone(),
            output_staging_handle: self.handles.output_staging_handle.clone(),
            effective_parameters_handle: self.handles.effective_parameters_handle.clone(),
            stages: STAGES,
            limits: SupervisionLimits {
                // The worker hashes its own executable before `hello`; a large
                // unoptimized test binary needs the contract's handshake bound.
                handshake: SupervisionLimits::CONTRACT.handshake,
                load: SupervisionLimits::CONTRACT.load,
                ..process_limits()
            },
        }
    }
    fn staging(&self) -> std::path::PathBuf {
        self.handles.staging.worker_path().to_path_buf()
    }
    fn staged_names(&self) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(self.staging())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
    /// Run the attempt; `cancel_when_executing` sends a user cancel once the
    /// worker is executing (and holding).
    async fn run(&mut self, cancel_when_executing: bool) -> AttemptExit {
        let (stop_tx, stop_rx) = watch::channel(StopIntent::Continue);
        let (obs_tx, mut obs_rx) = watch::channel::<Option<ObservationUpdate>>(None);
        let stop_tx = Arc::new(stop_tx);
        let stopper = cancel_when_executing.then(|| {
            let stop_tx = Arc::clone(&stop_tx);
            tokio::spawn(async move {
                while obs_rx.changed().await.is_ok() {
                    let executing = obs_rx
                        .borrow_and_update()
                        .as_ref()
                        .is_some_and(|o| o.phase == AttemptPhase::Executing);
                    if executing {
                        // Give the worker time to read inputs and start holding.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        let _ = stop_tx.send(StopIntent::UserCancel);
                        return;
                    }
                }
            })
        });
        let launcher = PlatformLauncher::new(self.command.take().unwrap());
        let exit = bounded(WorkerSupervisor::run(
            &self.record,
            self.plan(),
            launcher,
            TestLedger::new(LedgerMode::Accept),
            stop_rx,
            &obs_tx,
        ))
        .await;
        if let Some(stopper) = stopper {
            stopper.abort();
        }
        exit
    }
}

fn ended(exit: &AttemptExit) -> (AttemptEnd, &AttemptCleanup) {
    match exit {
        AttemptExit::Ended { end, cleanup, .. } => (*end, cleanup),
        other => panic!("expected an ended attempt, got {other:?}"),
    }
}

#[tokio::test]
async fn r2_worker_copies_the_scoped_input_into_staging_and_reports_a_candidate() {
    let mut attempt = attempt(FixtureParameters::default(), None, None);
    let exit = attempt.run(false).await;
    let AttemptExit::Candidate {
        report, cleanup, ..
    } = &exit
    else {
        panic!("expected a candidate, got {exit:?}");
    };
    // Only after confirmed whole-tree cleanup bound to this session.
    assert_eq!(
        cleanup
            .identity()
            .session_nonce
            .map(|b| format!("{b:02x}"))
            .concat(),
        attempt.record.session_id["ses_".len()..]
    );
    assert_eq!(report.description_handle, DESCRIPTION_NAME);
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.files[0].relative_name, OUTPUT_NAME);
    assert_eq!(report.files[0].byte_length, MESH.len() as u64);
    assert_eq!(report.files[0].sha256, sha256_hex(MESH));
    // The staged bytes are an exact copy; the snapshot is unchanged.
    // Sorted: exactly the mesh and its description.
    assert_eq!(attempt.staged_names(), [OUTPUT_NAME, DESCRIPTION_NAME]);
    assert_eq!(
        std::fs::read(attempt.staging().join(OUTPUT_NAME)).unwrap(),
        MESH
    );
    let mesh = RelativePath::parse("inputs/mesh.obj".to_owned()).unwrap();
    assert_eq!(
        std::fs::read(attempt.root.path_for_native_vfs(&mesh)).unwrap(),
        MESH
    );
}

#[tokio::test]
async fn r2_worker_holds_until_cooperative_cancel_and_writes_nothing() {
    let parameters = FixtureParameters {
        hold_before_candidate: true,
        fail_execution: false,
    };
    let mut attempt = attempt(parameters, None, None);
    let exit = attempt.run(true).await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::Stopped(StopIntent::UserCancel), "{exit:?}");
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
    assert!(attempt.staged_names().is_empty());
}

#[tokio::test]
async fn r2_worker_declared_failure_is_a_typed_failure_with_nothing_staged() {
    let parameters = FixtureParameters {
        hold_before_candidate: false,
        fail_execution: true,
    };
    let mut attempt = attempt(parameters, None, None);
    let exit = attempt.run(false).await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::WorkerFailed);
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
    assert!(attempt.staged_names().is_empty());
}

#[tokio::test]
async fn r2_worker_rejects_an_input_that_does_not_match_its_captured_digest() {
    let wrong = "0".repeat(64);
    let mut attempt = attempt(FixtureParameters::default(), Some(&wrong), None);
    let exit = attempt.run(false).await;
    let (end, cleanup) = ended(&exit);
    assert_eq!(end, AttemptEnd::WorkerFailed);
    assert!(
        matches!(cleanup, AttemptCleanup::Confirmed(_)),
        "{cleanup:?}"
    );
    assert!(attempt.staged_names().is_empty());
}

#[tokio::test]
async fn malformed_private_messages_end_as_protocol_errors_never_candidates() {
    for fault in ["malformed_candidate", "garbage_loaded"] {
        let mut attempt = attempt(FixtureParameters::default(), None, Some(fault));
        let exit = attempt.run(false).await;
        let (end, cleanup) = ended(&exit);
        assert_eq!(end, AttemptEnd::ProtocolError, "{fault}: {exit:?}");
        assert!(
            matches!(cleanup, AttemptCleanup::Confirmed(_)),
            "{fault}: {cleanup:?}"
        );
    }
}

#[test]
fn a_reused_attempt_folder_is_refused() {
    let attempt = attempt(FixtureParameters::default(), None, None);
    let mut command = command(None);
    assert!(
        prepare_attempt_files(
            &attempt.root,
            &attempt.record.attempt_id,
            b"{}",
            &FixtureParameters::default().to_document(),
            &[],
            &mut command,
        )
        .is_err()
    );
}

#[test]
fn declared_parameters_are_closed_booleans() {
    assert_eq!(
        FixtureParameters::parse(br#"{}"#),
        Some(FixtureParameters::default())
    );
    assert_eq!(
        FixtureParameters::parse(br#"{"hold_before_candidate":true}"#),
        Some(FixtureParameters {
            hold_before_candidate: true,
            fail_execution: false
        })
    );
    for bad in [
        &br#"{"hold_before_candidate":1}"#[..],
        br#"{"other":true}"#,
        br#"[]"#,
        b"not json",
    ] {
        assert_eq!(FixtureParameters::parse(bad), None);
    }
    let round = FixtureParameters {
        hold_before_candidate: true,
        fail_execution: true,
    };
    assert_eq!(FixtureParameters::parse(&round.to_document()), Some(round));
}
