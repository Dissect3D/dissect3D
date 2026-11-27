//! Connected CLI coordination regressions; existing fault assertions are unchanged.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
use super::*;

async fn observer(host: &Host) -> (PathBuf, Client) {
    let config = host.config.with_file_name("observer.json");
    std::fs::copy(&host.config, &config).unwrap();
    envelope(
        bounded_output(command(
            &host.cli,
            &config,
            &["auth", "setup", "--submission-access"],
        ))
        .await,
        0,
    );
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
    let root = OwnedRoot::open(host.config.parent().unwrap(), RootPurpose::EngineData).unwrap();
    let discovery = dissect3d_connection::verify_engine(&root, Duration::from_secs(2))
        .unwrap()
        .discovery;
    let client = Client::new(
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
    (config, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_during_upload_preserves_known_and_unknown_acceptance() {
    use dissect3d_api::{ClientError, ErrorCode, JobId};
    let host = Host::new().await;
    let (observer_config, observer) = observer(&host).await;
    let mut own = host.submit("observer-owned-job");
    own.env("DISSECT3D_CONFIG_FILE", &observer_config);
    let own = envelope(bounded_output(own).await, 0);
    let known = envelope(bounded_output(host.submit("known-before-revoke")).await, 0);
    host.hooks.drop_after.store(true, Ordering::Release);
    let unknown = envelope(
        bounded_output(host.submit("unknown-before-revoke")).await,
        15,
    );
    let id = unknown["data"]["sub_id"].as_str().unwrap();
    let path = RelativePath::parse(format!("submissions/{id}.json")).unwrap();
    let before = host.profile().read_file(&path, 1_048_576).unwrap();
    let (entered, release) = host.hooks.pause_upload();
    let mut slow = host.submit("revoked-during-upload");
    slow.kill_on_drop(true);
    let slow = piped(slow);
    tokio::time::timeout(Duration::from_secs(10), entered)
        .await
        .unwrap()
        .unwrap();
    let revoked = bounded_output(command(&host.cli, &host.config, &["auth", "revoke"])).await;
    let _ = release.send(());
    let slow = slow.wait_with_output().await.unwrap();
    std::fs::remove_file(&host.mesh).unwrap();
    let denied_unknown =
        bounded_output(command(&host.cli, &host.config, &["jobs", "recover", id])).await;
    let denied_known = bounded_output(command(
        &host.cli,
        &host.config,
        &["jobs", "recover", known["data"]["sub_id"].as_str().unwrap()],
    ))
    .await;
    let after = host.profile().read_file(&path, 1_048_576).unwrap();
    let credential: Value = serde_json::from_slice(
        &host
            .profile()
            .read_file(&RelativePath::parse("credential.json").unwrap(), 16_384)
            .unwrap(),
    )
    .unwrap();
    let denied_read = host.api.jobs(JobsQuery::default()).await;
    let foreign = observer
        .job(&JobId::parse(known["data"]["job_id"].as_str().unwrap()).unwrap())
        .await;
    let own_read = observer
        .job(&JobId::parse(own["data"]["job_id"].as_str().unwrap()).unwrap())
        .await;
    let info = observer.info().await;
    let seen = host.hooks.submit_seen.load(Ordering::Acquire);
    observer
        .shutdown(IdempotencyKey::parse("observer-finish").unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), host.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    envelope(revoked, 0);
    let slow = envelope(slow, 4);
    assert_eq!(slow["accepted"], false, "new job was never submitted");
    let unknown = envelope(denied_unknown, 4);
    assert_eq!(unknown["error"]["category"], "unauthorized");
    assert!(
        unknown["accepted"].is_null(),
        "revocation hides a potentially committed earlier acceptance"
    );
    let denied_known = envelope(denied_known, 19);
    assert_eq!(denied_known["accepted"], true);
    assert_eq!(denied_known["data"]["job_id"], known["data"]["job_id"]);
    assert_eq!(
        before, after,
        "denied recovery preserves the exact pending record"
    );
    assert_eq!(credential["state"], "revoked");
    assert_eq!(credential["secret_hex"], "");
    assert!(matches!(
        denied_read,
        Err(ClientError::Rejected(ErrorCode::Unauthorized))
    ));
    assert!(matches!(
        foreign,
        Err(ClientError::Rejected(ErrorCode::NotFound))
    ));
    assert!(own_read.is_ok() && info.is_ok());
    assert_eq!(
        seen, 3,
        "revoked work cannot send a new acceptance mutation"
    );
}

async fn bounded_output(mut command: Command) -> std::process::Output {
    command.kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_upload_keeps_monitoring_usable_and_duplicate_keys_accept_once() {
    let host = Host::new().await;
    let baseline = envelope(
        host.submit("coordination-baseline").output().await.unwrap(),
        0,
    );
    let job = baseline["data"]["job_id"].as_str().unwrap();
    let (entered, release) = host.hooks.pause_upload();
    let mut slow = host.submit("shared-coordination-key");
    slow.kill_on_drop(true);
    let slow = piped(slow);
    tokio::time::timeout(Duration::from_secs(10), entered)
        .await
        .unwrap()
        .unwrap();
    let mut outputs = Vec::new();
    for args in [
        vec!["engine", "status"],
        vec!["engine", "info"],
        vec!["jobs", "list"],
        vec!["jobs", "show", job],
    ] {
        outputs.push(bounded_output(command(&host.cli, &host.config, &args)).await);
    }
    let duplicate = bounded_output(host.submit("shared-coordination-key")).await;
    let _ = release.send(());
    let slow = slow.wait_with_output().await.unwrap();
    // Finish the owned host before asserting the original-defect Red observations.
    let mut conflict = host.submit("shared-coordination-key");
    conflict.args(["--parameters-json", r#"{"fail_execution":true}"#]);
    let conflict = bounded_output(conflict).await;
    let jobs = host.jobs().await;
    host.finish().await;
    for output in outputs {
        envelope(output, 0);
    }
    let first = envelope(duplicate, 0);
    let replay = envelope(slow, 0);
    assert_eq!(first["data"]["job_id"], replay["data"]["job_id"]);
    assert_eq!(replay["data"]["replayed"], true);
    assert_eq!(jobs, 2, "baseline and exactly one duplicate acceptance");
    let conflict = envelope(conflict, 19);
    assert_eq!(conflict["error"]["category"], "idempotency_conflict");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_recovery_and_process_death_keep_one_immutable_record() {
    let host = Host::new().await;
    host.hooks.drop_before.store(true, Ordering::Release);
    let pending = envelope(
        host.submit("recover-one-immutable-request")
            .output()
            .await
            .unwrap(),
        15,
    );
    let id = pending["data"]["sub_id"].as_str().unwrap();
    let path = RelativePath::parse(format!("submissions/{id}.json")).unwrap();
    let before = host.profile().read_file(&path, 1_048_576).unwrap();
    std::fs::remove_file(&host.mesh).unwrap();
    let (entered, release) = host.hooks.pause_commit();
    let mut recovering = command(&host.cli, &host.config, &["jobs", "recover", id]);
    recovering.kill_on_drop(true);
    let mut recovering = piped(recovering);
    tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(15)).unwrap())
        .await
        .unwrap();
    let contender =
        bounded_output(command(&host.cli, &host.config, &["jobs", "recover", id])).await;
    let during = host.profile().read_file(&path, 1_048_576).unwrap();
    recovering.kill().await.unwrap();
    let _ = release.send(());
    let recovered = host.recover(id).await;
    let after = host.profile().read_file(&path, 1_048_576).unwrap();
    let jobs = host.jobs().await;
    let seen = host.hooks.submit_seen.load(Ordering::Acquire);
    host.finish().await;
    assert_eq!(during, before, "busy recovery must not mutate the record");
    let contender = envelope(contender, 2);
    assert_eq!(contender["error"]["category"], "profile_busy");
    assert!(
        contender["accepted"].is_null(),
        "prior acceptance remains unknown"
    );
    assert_eq!(recovered["data"]["sub_id"], id);
    assert_eq!(recovered["data"]["replayed"], true);
    assert_eq!(jobs, 1);
    assert_eq!(
        seen, 3,
        "original attempt, killed recovery and same-key replay only"
    );
    let before: Value = serde_json::from_slice(&before).unwrap();
    let after: Value = serde_json::from_slice(&after).unwrap();
    for field in [
        "sub_id",
        "installation_id",
        "client_id",
        "operation",
        "key",
        "request_body_utf8",
        "input_identities",
    ] {
        assert_eq!(before[field], after[field], "{field}");
    }
    assert_eq!(after["receipt"]["job_id"], recovered["data"]["job_id"]);
}
