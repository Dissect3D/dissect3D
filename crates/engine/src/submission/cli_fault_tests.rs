//! Real CLI/native discovery/HTTPS against the normal engine composition.
//! Faults are private per-root Rust-test latches, never public API operations.

use super::test_support::{Hooks, register};
use crate::submission_fixture;
use dissect3d_api::{
    Client, ClientId, ClientLimits, ConnectionMaterial, IdempotencyKey, JobsQuery, SecretToken,
};
use dissect3d_platform::{AuthorityLease, OwnedRoot, RelativePath, RootPurpose};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
use tokio::process::{Child, Command};

struct Host {
    _parent: tempfile::TempDir,
    config: PathBuf,
    cli: PathBuf,
    mesh: PathBuf,
    hooks: Arc<Hooks>,
    api: Client,
    task: tokio::task::JoinHandle<Result<(), crate::StartupError>>,
}

fn binary(name: &str, fallback: &str) -> PathBuf {
    let debug = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| debug.join(fallback));
    assert!(
        path.is_absolute() && path.is_file(),
        "BLOCKED: build workspace and examples; missing {name}"
    );
    path
}

impl Host {
    async fn new() -> Self {
        let cli = binary("DISSECT3D_TEST_CLI", "dissect3d");
        let tool = binary(
            "DISSECT3D_TEST_SUBMISSION_TOOL",
            "examples/submission_fixture_tool",
        );
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("engine");
        let prepared = Command::new(&tool)
            .args(["prepare", "--data-root"])
            .arg(&root)
            .output()
            .await
            .unwrap();
        assert!(prepared.status.success(), "real fixture preparation failed");
        let owned = OwnedRoot::open(&root, RootPurpose::EngineData).unwrap();
        let material = submission_fixture::load_prepared_fixture(&owned, &tool).unwrap();
        let lease = AuthorityLease::acquire(&owned).unwrap();
        let hooks = Arc::new(Hooks::default());
        register(owned.path(), &hooks);
        let data_root = root.clone();
        let task = tokio::spawn(async move {
            crate::startup::run_engine_with_lease(
                &data_root,
                owned,
                lease,
                Arc::new(material.catalog),
                Some(material.readiness),
            )
            .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if root.join("run/endpoint.json").is_file() {
                break;
            }
            assert!(!task.is_finished(), "test engine failed startup");
            assert!(
                tokio::time::Instant::now() < deadline,
                "test engine readiness timed out"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let config = root.join("profile.json");
        for args in [
            vec![
                "config",
                "set",
                "connection.data_root",
                root.to_str().unwrap(),
            ],
            vec![
                "config",
                "set",
                "connection.engine_binary",
                std::env::current_exe().unwrap().to_str().unwrap(),
            ],
            vec!["auth", "setup", "--submission-access"],
        ] {
            let output = command(&cli, &config, &args).output().await.unwrap();
            assert_eq!(output.status.code(), Some(0), "fixture CLI setup failed");
        }
        let profile = OwnedRoot::open(&state_path(&config), RootPurpose::ClientConfig).unwrap();
        let credential: Value = serde_json::from_slice(
            &profile
                .read_file(&RelativePath::parse("credential.json").unwrap(), 16_384)
                .unwrap(),
        )
        .unwrap();
        let hex = credential["secret_hex"].as_str().unwrap();
        let secret = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect();
        let discovery_root = OwnedRoot::open(&root, RootPurpose::EngineData).unwrap();
        let verified =
            dissect3d_connection::verify_engine(&discovery_root, Duration::from_secs(2)).unwrap();
        let discovery = verified.discovery;
        let api = Client::new(
            ConnectionMaterial::new(
                discovery.base_url,
                discovery.installation_id,
                discovery.instance_id,
                ClientId::parse(credential["client_id"].as_str().unwrap()).unwrap(),
                discovery.trust_anchor_der,
                discovery.trust_anchor_sha256.try_into().unwrap(),
                SecretToken::new(secret).unwrap(),
            ),
            ClientLimits::default(),
        )
        .unwrap();
        let mesh = root.join("source.obj");
        std::fs::write(
            &mesh,
            include_bytes!("../../tests/fixtures/submission/tetrahedron.obj"),
        )
        .unwrap();
        Self {
            _parent: parent,
            config,
            cli,
            mesh,
            hooks,
            api,
            task,
        }
    }
    fn submit(&self, key: &str) -> Command {
        command(
            &self.cli,
            &self.config,
            &[
                "jobs",
                "submit",
                "--model",
                "test.mesh-copy@fixture-r1",
                "--task",
                "dissect3d.test.mesh-copy",
                "--task-version",
                "1.0",
                "--input",
                &format!("mesh={}", self.mesh.display()),
                "--idempotency-key",
                key,
            ],
        )
    }
    async fn recover(&self, id: &str) -> Value {
        let output = command(&self.cli, &self.config, &["jobs", "recover", id])
            .output()
            .await
            .unwrap();
        envelope(output, 0)
    }
    async fn jobs(&self) -> usize {
        self.api
            .jobs(JobsQuery::default())
            .await
            .unwrap()
            .items
            .len()
    }
    async fn finish(self) {
        self.api
            .shutdown(IdempotencyKey::parse("test-finish").unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    fn profile(&self) -> OwnedRoot {
        OwnedRoot::open(&state_path(&self.config), RootPurpose::ClientConfig).unwrap()
    }
}

fn command(cli: &Path, config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(cli);
    command.args(args).args(["--json", "--non-interactive"]);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("DISSECT3D_") {
            command.env_remove(key);
        }
    }
    command.env("DISSECT3D_CONFIG_FILE", config);
    command
}
fn state_path(config: &Path) -> PathBuf {
    let mut path = config.as_os_str().to_owned();
    path.push(".state");
    path.into()
}
fn envelope(output: std::process::Output, code: i32) -> Value {
    let data: Value = serde_json::from_slice(&output.stdout).expect("one CLI envelope");
    assert_eq!(
        output.status.code(),
        Some(code),
        "category={:?}",
        data["error"]["category"]
    );
    data
}
async fn signal(child: &Child) {
    let status = Command::new("/bin/kill")
        .args(["-INT", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap();
    assert!(status.success());
}
fn piped(mut command: Command) -> Child {
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_responses_recover_the_same_record_before_or_after_commit() {
    let host = Host::new().await;
    host.hooks.drop_before.store(true, Ordering::Release);
    let first = envelope(host.submit("lost-before").output().await.unwrap(), 15);
    assert!(first["accepted"].is_null());
    assert_eq!(host.jobs().await, 0);
    std::fs::remove_file(&host.mesh).unwrap();
    let recovered = host
        .recover(first["data"]["sub_id"].as_str().unwrap())
        .await;
    assert_eq!(recovered["accepted"], true);
    assert_eq!(recovered["data"]["replayed"], false);
    assert_eq!(host.jobs().await, 1);
    std::fs::write(
        &host.mesh,
        include_bytes!("../../tests/fixtures/submission/tetrahedron.obj"),
    )
    .unwrap();
    host.hooks.drop_after.store(true, Ordering::Release);
    let second = envelope(host.submit("lost-after").output().await.unwrap(), 15);
    assert!(second["accepted"].is_null());
    assert_eq!(host.jobs().await, 2);
    std::fs::remove_file(&host.mesh).unwrap();
    let recovered = host
        .recover(second["data"]["sub_id"].as_str().unwrap())
        .await;
    assert_eq!(recovered["data"]["replayed"], true);
    assert_eq!(host.jobs().await, 2);
    host.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupts_before_upload_or_post_never_submit_and_after_send_is_uncertain() {
    let host = Host::new().await;
    let (entered, release) = host.hooks.pause_upload();
    let child = piped(host.submit("interrupt-upload"));
    tokio::time::timeout(Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    signal(&child).await;
    let output = envelope(child.wait_with_output().await.unwrap(), 18);
    assert_eq!(output["accepted"], false);
    let _ = release.send(());
    assert_eq!(host.hooks.submit_seen.load(Ordering::Acquire), 0);
    let (entered, release) = host.hooks.pause_info(3);
    let child = piped(host.submit("interrupt-before-post"));
    tokio::time::timeout(Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    signal(&child).await;
    let output = envelope(child.wait_with_output().await.unwrap(), 18);
    assert_eq!(output["accepted"], false);
    let _ = release.send(());
    assert_eq!(host.hooks.submit_seen.load(Ordering::Acquire), 0);
    let id = output["data"]["sub_id"].as_str().unwrap();
    assert_eq!(host.recover(id).await["data"]["replayed"], false);
    let (entered, release) = host.hooks.pause_commit();
    let child = piped(host.submit("interrupt-after-send"));
    tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
    signal(&child).await;
    let output = envelope(child.wait_with_output().await.unwrap(), 15);
    assert!(output["accepted"].is_null());
    release.send(()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while host.jobs().await != 2 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        host.recover(output["data"]["sub_id"].as_str().unwrap())
            .await["data"]["replayed"],
        true
    );
    assert_eq!(host.jobs().await, 2);
    host.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_deadline_cannot_report_definitive_rejection_while_commit_survives() {
    let host = Host::new().await;
    let (entered, release) = host.hooks.pause_commit();
    let child = piped(host.submit("deadline-commit"));
    tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .unwrap();
    let output = envelope(child.wait_with_output().await.unwrap(), 15);
    assert!(output["accepted"].is_null());
    release.send(()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while host.jobs().await != 1 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        host.recover(output["data"]["sub_id"].as_str().unwrap())
            .await["data"]["replayed"],
        true
    );
    host.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsafe_pending_storage_prevents_post_and_receipt_failure_preserves_acceptance() {
    let host = Host::new().await;
    let profile = host.profile();
    let quota = RelativePath::parse("submissions/.d3d-tmp-local-quota").unwrap();
    profile
        .write_atomic(&quota, &vec![b'x'; 1_048_577])
        .unwrap();
    let output = envelope(host.submit("pending-quota").output().await.unwrap(), 2);
    assert_eq!(output["accepted"], false);
    assert_eq!(host.hooks.submit_seen.load(Ordering::Acquire), 0);
    profile.remove_file(&quota).unwrap();
    let (entered, release) = host.hooks.pause_info(3);
    let child = piped(host.submit("receipt-quota"));
    tokio::time::timeout(Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    profile
        .write_atomic(&quota, &vec![b'x'; 1_048_577])
        .unwrap();
    release.send(()).unwrap();
    let output = envelope(child.wait_with_output().await.unwrap(), 19);
    assert_eq!(output["accepted"], true);
    assert_eq!(output["error"]["category"], "recovery_storage_failed");
    assert_eq!(host.jobs().await, 1);
    let id = output["data"]["sub_id"].as_str().unwrap();
    let path = RelativePath::parse(format!("submissions/{id}.json")).unwrap();
    let pending: Value =
        serde_json::from_slice(&profile.read_file(&path, 1_048_576).unwrap()).unwrap();
    assert!(pending["receipt"].is_null());
    profile.remove_file(&quota).unwrap();
    let recovered = host.recover(id).await;
    assert_eq!(recovered["data"]["job_id"], output["data"]["job_id"]);
    assert_eq!(host.jobs().await, 1);
    host.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_stdout_preserves_durable_receipt_and_known_job() {
    let host = Host::new().await;
    let mut child = piped(host.submit("closed-stdout"));
    drop(child.stdout.take().unwrap());
    let output = child.wait_with_output().await.unwrap();
    assert_eq!(output.status.code(), Some(19));
    assert_eq!(host.jobs().await, 1);
    let directory = state_path(&host.config).join("submissions");
    let records: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    assert_eq!(records.len(), 1);
    let record: Value = serde_json::from_slice(&std::fs::read(&records[0]).unwrap()).unwrap();
    assert!(record["receipt"]["accepted"].as_bool().unwrap());
    let recovered = host.recover(record["sub_id"].as_str().unwrap()).await;
    assert_eq!(recovered["data"]["job_id"], record["receipt"]["job_id"]);
    assert_eq!(host.jobs().await, 1);
    host.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn never_accepted_expired_record_cannot_create_a_job_or_reread_sources() {
    let host = Host::new().await;
    host.hooks.drop_before.store(true, Ordering::Release);
    let output = envelope(host.submit("expired-pending").output().await.unwrap(), 15);
    assert!(output["accepted"].is_null());
    std::fs::remove_file(&host.mesh).unwrap();
    host.hooks
        .expire_unreferenced
        .store(true, Ordering::Release);
    let rejected = envelope(
        command(
            &host.cli,
            &host.config,
            &[
                "jobs",
                "recover",
                output["data"]["sub_id"].as_str().unwrap(),
            ],
        )
        .output()
        .await
        .unwrap(),
        19,
    );
    assert_eq!(rejected["accepted"], false);
    assert_eq!(rejected["error"]["category"], "input_unavailable");
    assert_eq!(host.jobs().await, 0);
    host.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_installation_rejects_pending_recovery_before_post() {
    let original = Host::new().await;
    original.hooks.drop_before.store(true, Ordering::Release);
    let pending = envelope(
        original
            .submit("installation-identity")
            .output()
            .await
            .unwrap(),
        15,
    );
    let id = pending["data"]["sub_id"].as_str().unwrap();
    let path = RelativePath::parse(format!("submissions/{id}.json")).unwrap();
    let bytes = original.profile().read_file(&path, 1_048_576).unwrap();
    let replacement = Host::new().await;
    replacement
        .profile()
        .write_recovery_record(&path, &bytes)
        .unwrap();
    let rejected = envelope(
        command(
            &replacement.cli,
            &replacement.config,
            &["jobs", "recover", id],
        )
        .output()
        .await
        .unwrap(),
        5,
    );
    assert_eq!(rejected["accepted"], false);
    assert_eq!(rejected["error"]["category"], "recovery_identity_mismatch");
    assert_eq!(replacement.hooks.submit_seen.load(Ordering::Acquire), 0);
    assert_eq!(original.jobs().await, 0);
    assert_eq!(replacement.jobs().await, 0);
    original.finish().await;
    replacement.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_directory_permission_denial_prevents_post() {
    use std::os::unix::fs::PermissionsExt;
    let host = Host::new().await;
    let profile = host.profile();
    let directory = RelativePath::parse("submissions").unwrap();
    profile.ensure_private_directory(&directory).unwrap();
    let path = state_path(&host.config).join("submissions");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let output = host.submit("permission-denial").output().await.unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let rejected = envelope(output, 2);
    assert_eq!(rejected["accepted"], false);
    assert_eq!(host.hooks.submit_seen.load(Ordering::Acquire), 0);
    assert_eq!(host.jobs().await, 0);
    host.finish().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_pending_and_receipt_sync_errors_preserve_send_truth() {
    let host = Host::new().await;
    let source = host._parent.path().join("native_sync_fault.c");
    std::fs::write(
        &source,
        include_bytes!("../../tests/fixtures/submission/native_sync_fault.c"),
    )
    .unwrap();
    let pending = host._parent.path().join("pending-sync.so");
    let receipt = host._parent.path().join("receipt-sync.so");
    for (destination, receipt_only) in [(&pending, false), (&receipt, true)] {
        let mut compiler = Command::new("cc");
        compiler.args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"]);
        if receipt_only {
            compiler.arg("-DRECEIPT_ONLY");
        }
        let compiled = compiler
            .arg(&source)
            .arg("-ldl")
            .arg("-o")
            .arg(destination)
            .output()
            .await
            .unwrap();
        assert!(
            compiled.status.success(),
            "native sync fixture compiler failed"
        );
    }
    let rejected = envelope(
        host.submit("pending-sync-error")
            .env("LD_PRELOAD", &pending)
            .output()
            .await
            .unwrap(),
        2,
    );
    assert_eq!(rejected["accepted"], false);
    assert_eq!(host.hooks.submit_seen.load(Ordering::Acquire), 0);
    let accepted = envelope(
        host.submit("receipt-sync-error")
            .env("LD_PRELOAD", &receipt)
            .output()
            .await
            .unwrap(),
        19,
    );
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["error"]["category"], "recovery_storage_failed");
    assert_eq!(host.jobs().await, 1);
    let id = accepted["data"]["sub_id"].as_str().unwrap();
    let record: Value = serde_json::from_slice(
        &host
            .profile()
            .read_file(
                &RelativePath::parse(format!("submissions/{id}.json")).unwrap(),
                1_048_576,
            )
            .unwrap(),
    )
    .unwrap();
    assert!(record["receipt"].is_null());
    let recovered = host.recover(id).await;
    assert_eq!(recovered["data"]["job_id"], accepted["data"]["job_id"]);
    assert_eq!(host.jobs().await, 1);
    host.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_original_recovery_survives_staging_expiry_without_upload() {
    let host = Host::new().await;
    let first = envelope(host.submit("retained-expiry").output().await.unwrap(), 0);
    let id = first["data"]["sub_id"].as_str().unwrap();
    let path = RelativePath::parse(format!("submissions/{id}.json")).unwrap();
    let before: Value =
        serde_json::from_slice(&host.profile().read_file(&path, 1_048_576).unwrap()).unwrap();
    std::fs::remove_file(&host.mesh).unwrap();
    host.hooks
        .expire_unreferenced
        .store(true, Ordering::Release);
    let replay = host.recover(id).await;
    assert_eq!(replay["accepted"], true);
    assert_eq!(replay["data"]["replayed"], true);
    assert_eq!(replay["data"]["job_id"], first["data"]["job_id"]);
    assert_eq!(host.hooks.submit_seen.load(Ordering::Acquire), 2);
    assert_eq!(host.jobs().await, 1);
    assert_eq!(
        std::fs::read_dir(host.config.parent().unwrap().join("inputs/data"))
            .unwrap()
            .count(),
        1
    );
    let after: Value =
        serde_json::from_slice(&host.profile().read_file(&path, 1_048_576).unwrap()).unwrap();
    for field in [
        "sub_id",
        "installation_id",
        "client_id",
        "operation",
        "key",
        "request_body_utf8",
        "input_identities",
    ] {
        assert_eq!(after[field], before[field], "{field}");
    }
    host.finish().await;
}
