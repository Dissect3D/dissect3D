use dissect3d_api::{DiscoveryRecord, decode_json};
#[cfg(unix)]
use dissect3d_platform::{ProcessIdentity, wait_for_process_exit};
use serde_json::Value;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output};
#[cfg(unix)]
use std::time::{Duration, Instant};
use tempfile::TempDir;

const CLI: &str = env!("CARGO_BIN_EXE_dissect3d");

#[test]
#[cfg(unix)]
fn isolated_profiles_enroll_revoke_restart_and_retain_identity() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE to its absolute path");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile_a = isolated.path().join("profile-a.json");
    let profile_b = isolated.path().join("profile-b.json");

    configure(&profile_a, &data_root, &engine_path);
    configure(&profile_b, &data_root, &engine_path);

    let concurrent_a = profile_a.clone();
    let concurrent_b = profile_b.clone();
    let first_start = std::thread::spawn(move || run(&concurrent_a, &["engine", "start"]));
    let second_start = std::thread::spawn(move || run(&concurrent_b, &["engine", "start"]));
    let first_start = first_start.join().expect("first start process");
    let second_start = second_start.join().expect("second start process");
    assert_success(&first_start);
    assert_success(&second_start);
    let started: Value = serde_json::from_slice(&first_start.stdout).expect("start response");
    let converged: Value =
        serde_json::from_slice(&second_start.stdout).expect("converged response");
    let first_installation = started["data"]["installation_id"]
        .as_str()
        .expect("installation id")
        .to_owned();
    let first_instance = started["data"]["instance_id"]
        .as_str()
        .expect("instance id")
        .to_owned();
    assert_eq!(converged["data"]["installation_id"], first_installation);
    assert_eq!(converged["data"]["instance_id"], first_instance);
    let missing_engine = isolated.path().join("missing-engine-binary");
    assert_success(&run(
        &profile_a,
        &[
            "config",
            "set",
            "connection.engine_binary",
            path_arg(&missing_engine),
        ],
    ));
    assert!(
        dissect3d_platform::process_matches(&process_reference(&data_root))
            .expect("observe running test engine"),
        "the test-owned engine exited before reuse"
    );
    let reused = run(&profile_a, &["engine", "start"]);
    assert_success(&reused);
    let reused: Value = serde_json::from_slice(&reused.stdout).expect("reuse response");
    assert_eq!(reused["data"]["already_running"], true);
    assert_eq!(reused["data"]["instance_id"], first_instance);
    let mut first_engine = ManagedEngine(process_reference(&data_root));

    let setup_a = run(&profile_a, &["auth", "setup"]);
    assert_success(&setup_a);
    let secret = stored_secret(&profile_a);
    assert_redacted(&setup_a, &secret);
    let info_a = run(&profile_a, &["engine", "info"]);
    assert_success(&info_a);
    assert_redacted(&info_a, &secret);
    let info: Value = serde_json::from_slice(&info_a.stdout).expect("info response");
    assert_eq!(info["data"]["installation_id"], first_installation);

    // Explicit automation credentials must take precedence over the profile
    // record; failure to resolve either reference cannot fall back silently.
    let external_root = isolated.path().join("external-credential-root");
    dissect3d_platform::OwnedRoot::create_private(
        &external_root,
        dissect3d_platform::RootPurpose::ClientConfig,
    )
    .expect("create protected external credential root");
    let external_credential = external_root.join("external-token.txt");
    let credential_json: Value = serde_json::from_slice(
        &std::fs::read(std::path::PathBuf::from(format!(
            "{}.state/credential.json",
            profile_a.display()
        )))
        .expect("active profile credential"),
    )
    .expect("credential JSON");
    let client_id = credential_json["client_id"].as_str().expect("client id");
    std::fs::write(&external_credential, format!("{client_id}.{}\n", secret))
        .expect("write explicit token file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&external_credential, std::fs::Permissions::from_mode(0o600))
            .expect("protect explicit token file");
    }
    let credential_root = dissect3d_platform::OwnedRoot::open(
        &external_root,
        dissect3d_platform::RootPurpose::ClientConfig,
    )
    .expect("open external credential root");
    credential_root
        .read_file(
            &dissect3d_platform::RelativePath::parse("external-token.txt")
                .expect("relative token path"),
            512,
        )
        .expect("read protected external token file");
    assert_success(&run(
        &profile_a,
        &[
            "config",
            "set",
            "connection.credential_file",
            path_arg(&external_credential),
        ],
    ));
    assert_success(&run(
        &profile_a,
        &[
            "config",
            "set",
            "connection.installation_id",
            &first_installation,
        ],
    ));
    assert_success(&run(&profile_a, &["engine", "info"]));
    let missing_external = isolated.path().join("missing-token.txt");
    assert_success(&run(
        &profile_a,
        &[
            "config",
            "set",
            "connection.credential_file",
            path_arg(&missing_external),
        ],
    ));
    let missing_selected = run(&profile_a, &["engine", "info"]);
    assert_eq!(missing_selected.status.code(), Some(6));
    let wrong_installation = "ins_00000000000000000000000000000000";
    assert_success(&run(
        &profile_a,
        &[
            "config",
            "set",
            "connection.credential_file",
            path_arg(&external_credential),
        ],
    ));
    assert_success(&run(
        &profile_a,
        &[
            "config",
            "set",
            "connection.installation_id",
            wrong_installation,
        ],
    ));
    assert_eq!(run(&profile_a, &["engine", "info"]).status.code(), Some(5));
    assert_success(&run(
        &profile_a,
        &["config", "unset", "connection.installation_id"],
    ));

    let setup_b = run(&profile_b, &["auth", "setup"]);
    assert_success(&setup_b);
    let secret_b = stored_secret(&profile_b);
    assert_redacted(&setup_b, &secret_b);
    assert_not_in_database(&data_root, &secret);
    assert_not_in_database(&data_root, &secret_b);
    let client_a =
        serde_json::from_slice::<Value>(&setup_a.stdout).expect("setup A")["data"]["client_id"]
            .as_str()
            .expect("A client id")
            .to_owned();
    let client_b =
        serde_json::from_slice::<Value>(&setup_b.stdout).expect("setup B")["data"]["client_id"]
            .as_str()
            .expect("B client id")
            .to_owned();
    assert_ne!(client_a, client_b);

    let revoked = run(&profile_a, &["auth", "revoke"]);
    assert_success(&revoked);
    let status_b = run(&profile_b, &["auth", "status"]);
    assert_success(&status_b);
    assert_redacted(&status_b, &stored_secret(&profile_b));
    let status_a = run(&profile_a, &["auth", "status"]);
    assert_eq!(status_a.status.code(), Some(4));
    let rejected_stop = run(&profile_a, &["engine", "stop"]);
    assert_eq!(rejected_stop.status.code(), Some(4));
    let rejected_stop_json: Value =
        serde_json::from_slice(&rejected_stop.stdout).expect("rejected stop response");
    assert_eq!(rejected_stop_json["error"]["category"], "unauthorized");
    assert_success(&run(&profile_b, &["engine", "status"]));

    let stopped = run(&profile_b, &["engine", "stop"]);
    assert_success(&stopped);
    let stopped: Value = serde_json::from_slice(&stopped.stdout).expect("stop response");
    assert_eq!(stopped["data"]["process_exit_confirmed"], true);
    assert_eq!(stopped["data"]["receipt_confirmed"], true);
    let pending_path =
        std::path::PathBuf::from(format!("{}.state/pending-stop.json", profile_b.display()));
    let mut pending: Value =
        serde_json::from_slice(&std::fs::read(&pending_path).expect("pending stop record"))
            .expect("pending stop JSON");
    assert_eq!(
        pending["operation_id"],
        stopped["data"]["operation"]["operation_id"]
    );
    assert_eq!(
        pending["receipt"]["operation_id"],
        stopped["data"]["operation"]["operation_id"]
    );
    pending["state"] = Value::String("pending".to_owned());
    std::fs::write(
        &pending_path,
        serde_json::to_vec(&pending).expect("interrupted local completion state"),
    )
    .expect("preserve receipt while restoring pending state");
    let recovered_stop = run(&profile_b, &["engine", "stop"]);
    assert_success(&recovered_stop);
    let recovered_stop: Value =
        serde_json::from_slice(&recovered_stop.stdout).expect("recovered stop response");
    assert_eq!(recovered_stop["accepted"], true);
    assert_eq!(
        recovered_stop["operation_id"],
        stopped["data"]["operation"]["operation_id"]
    );
    assert_eq!(recovered_stop["data"]["receipt_confirmed"], true);
    assert_eq!(
        recovered_stop["data"]["operation_id"],
        stopped["data"]["operation"]["operation_id"]
    );
    first_engine.disarm();
    let unavailable = run(&profile_b, &["engine", "status"]);
    assert_eq!(unavailable.status.code(), Some(3));
    let restarted = run(&profile_b, &["engine", "start"]);
    assert_success(&restarted);
    let restarted: Value = serde_json::from_slice(&restarted.stdout).expect("restart response");
    assert_eq!(restarted["data"]["installation_id"], first_installation);
    assert_ne!(restarted["data"]["instance_id"], first_instance);
    let mut restarted_engine = ManagedEngine(process_reference(&data_root));

    let info_after_restart = run(&profile_b, &["engine", "info"]);
    assert_success(&info_after_restart);
    let info_after_restart: Value =
        serde_json::from_slice(&info_after_restart.stdout).expect("post-restart info response");
    assert_eq!(
        info_after_restart["data"]["instance_id"],
        restarted["data"]["instance_id"]
    );
    assert_success(&run(&profile_b, &["auth", "status"]));
    let revoked_after_restart = run(&profile_a, &["auth", "status"]);
    assert_eq!(revoked_after_restart.status.code(), Some(4));
    let final_stop = run(&profile_b, &["engine", "stop"]);
    assert_success(&final_stop);
    restarted_engine.disarm();
}

#[test]
#[cfg(unix)]
fn retained_stop_receipt_cannot_satisfy_a_different_selected_engine() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root_a = isolated.path().join("engine-a");
    let data_root_b = isolated.path().join("engine-b");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &data_root_a, &engine_path);

    assert_success(&run(&profile, &["engine", "start"]));
    let mut engine_a = ManagedEngine(process_reference(&data_root_a));
    assert_success(&run(&profile, &["auth", "setup"]));
    let first_stop = run(&profile, &["engine", "stop"]);
    assert_success(&first_stop);
    let first_stop: Value = serde_json::from_slice(&first_stop.stdout).expect("engine A stop");
    let operation_id = first_stop["operation_id"].clone();
    engine_a.disarm();

    assert_success(&run(
        &profile,
        &[
            "config",
            "set",
            "connection.data_root",
            path_arg(&data_root_b),
        ],
    ));
    let unavailable_status = run(&profile, &["engine", "status"]);
    assert_eq!(unavailable_status.status.code(), Some(3));
    let unavailable_status: Value =
        serde_json::from_slice(&unavailable_status.stdout).expect("engine B status");
    assert_eq!(
        unavailable_status["error"]["category"],
        "engine_unavailable"
    );

    let unavailable_stop = run(&profile, &["engine", "stop"]);
    assert_eq!(unavailable_stop.status.code(), Some(3));
    let unavailable_stop: Value =
        serde_json::from_slice(&unavailable_stop.stdout).expect("engine B stop");
    assert_eq!(unavailable_stop["error"]["category"], "engine_unavailable");
    assert!(unavailable_stop["operation_id"].is_null());
    assert!(
        !data_root_b.exists(),
        "unavailable stop created engine B root"
    );

    assert_success(&run(
        &profile,
        &[
            "config",
            "set",
            "connection.data_root",
            path_arg(&data_root_a),
        ],
    ));
    let recovered = run(&profile, &["engine", "stop"]);
    assert_success(&recovered);
    let recovered: Value = serde_json::from_slice(&recovered.stdout).expect("recovered A stop");
    assert_eq!(recovered["operation_id"], operation_id);
    assert_eq!(recovered["data"]["receipt_confirmed"], true);
}

#[test]
#[cfg(unix)]
fn engine_status_does_not_launch_or_create_store_when_unavailable() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE to its absolute path");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &data_root, &engine_path);

    let status = run(&profile, &["engine", "status"]);
    assert_eq!(status.status.code(), Some(3));
    let response: Value = serde_json::from_slice(&status.stdout).expect("status response");
    assert_eq!(response["error"]["category"], "engine_unavailable");
    assert_eq!(response["data"]["status"], "unavailable");
    assert_eq!(response["data"]["detail"], "engine_unavailable");
    assert!(!data_root.exists(), "read-only status created engine data");
}

#[test]
#[cfg(unix)]
fn profile_identity_and_secret_mismatches_fail_closed_without_implicit_enrollment() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &data_root, &engine_path);
    let _guard = TestEngineGuard(profile.clone());
    assert_success(&run(&profile, &["engine", "start"]));

    let missing = run(&profile, &["auth", "status"]);
    assert_eq!(missing.status.code(), Some(4));
    assert!(
        missing
            .stdout
            .windows(b"unauthorized".len())
            .any(|window| window == b"unauthorized")
    );
    let state = Path::new(&format!("{}.state", profile.display())).join("credential.json");
    assert!(!state.exists(), "status must not enroll a missing profile");

    assert_success(&run(&profile, &["auth", "setup"]));
    let original = std::fs::read(&state).expect("protected profile record");
    let mut changed_installation: Value = serde_json::from_slice(&original).expect("profile JSON");
    changed_installation["installation_id"] =
        Value::String("ins_ffffffffffffffffffffffffffffffff".to_owned());
    std::fs::write(
        &state,
        serde_json::to_vec(&changed_installation).expect("changed installation JSON"),
    )
    .expect("wrong-installation profile fixture");
    let stale = run(&profile, &["auth", "status"]);
    assert_eq!(stale.status.code(), Some(4));

    let mut wrong_secret: Value = serde_json::from_slice(&original).expect("profile JSON");
    wrong_secret["secret_hex"] = Value::String("ff".repeat(32));
    std::fs::write(
        &state,
        serde_json::to_vec(&wrong_secret).expect("wrong secret JSON"),
    )
    .expect("wrong-secret profile fixture");
    let rejected = run(&profile, &["auth", "status"]);
    assert_eq!(rejected.status.code(), Some(4));
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains(&"ff".repeat(32)));

    std::fs::write(&state, original).expect("restore isolated profile fixture");
    assert_success(&run(&profile, &["auth", "status"]));
    assert_success(&run(&profile, &["engine", "stop"]));
}

#[test]
#[cfg(unix)]
fn pending_enrollment_recovers_before_or_after_engine_commit_with_exact_identity() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &data_root, &engine_path);
    let _guard = TestEngineGuard(profile.clone());
    assert_success(&run(&profile, &["engine", "start"]));

    // Opening the CLI profile creates its protected directory without
    // enrolling or synthesizing credentials.
    let absent = run(&profile, &["auth", "status"]);
    assert_eq!(absent.status.code(), Some(4));
    let discovery = read_discovery(&data_root);
    let state_root = std::path::PathBuf::from(format!("{}.state", profile.display()));
    let credential_path = state_root.join("credential.json");
    let pending = serde_json::json!({
        "installation_id": discovery.installation_id,
        "instance_id": discovery.instance_id,
        "client_id": "cli_0123456789abcdef0123456789abcdef",
        "enrollment_id": "enr_0123456789abcdef0123456789abcdef",
        "secret_hex": "42".repeat(32),
        "state": "pending"
    });
    std::fs::write(
        &credential_path,
        serde_json::to_vec(&pending).expect("pending JSON"),
    )
    .expect("test-owned pending profile");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect test-owned pending profile");
    }

    let first = run(&profile, &["auth", "setup"]);
    assert_success(&first);
    let first: Value = serde_json::from_slice(&first.stdout).expect("first receipt");
    assert_eq!(first["data"]["replayed"], false);

    let mut interrupted: Value =
        serde_json::from_slice(&std::fs::read(&credential_path).expect("active credential"))
            .expect("active profile JSON");
    interrupted["state"] = Value::String("pending".to_owned());
    std::fs::write(
        &credential_path,
        serde_json::to_vec(&interrupted).expect("pending replay JSON"),
    )
    .expect("simulate interruption after durable engine commit");
    let replay = run(&profile, &["auth", "setup"]);
    assert_success(&replay);
    let replay: Value = serde_json::from_slice(&replay.stdout).expect("replay receipt");
    assert_eq!(replay["data"]["replayed"], true);
    assert_success(&run(&profile, &["auth", "status"]));
    assert_success(&run(&profile, &["engine", "stop"]));
}

#[test]
#[cfg(unix)]
fn abrupt_test_owned_engine_death_recovers_store_and_preserves_enrollment() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &data_root, &engine_path);
    assert_success(&run(&profile, &["engine", "start"]));
    let first_process = process_reference(&data_root);
    let first_discovery = read_discovery(&data_root);
    assert_success(&run(&profile, &["auth", "setup"]));

    assert!(
        dissect3d_platform::process_matches(&first_process)
            .expect("observe test-owned engine process")
    );
    let killed = Command::new("kill")
        .arg("-KILL")
        .arg(first_process.pid.to_string())
        .status()
        .expect("kill only the verified test-owned engine process");
    assert!(killed.success());
    assert!(
        wait_for_process_exit(&first_process, Duration::from_secs(5))
            .expect("observe abrupt child exit"),
        "SIGKILL'd engine must exit within the bounded observation"
    );

    let restarted = run(&profile, &["engine", "start"]);
    assert_success(&restarted);
    let restarted: Value = serde_json::from_slice(&restarted.stdout).expect("restart response");
    assert_eq!(
        restarted["data"]["installation_id"].as_str(),
        Some(first_discovery.installation_id.as_str())
    );
    assert_ne!(
        restarted["data"]["instance_id"].as_str(),
        Some(first_discovery.instance_id.as_str())
    );
    let mut engine = ManagedEngine(process_reference(&data_root));
    assert_success(&run(&profile, &["auth", "status"]));
    assert_success(&run(
        &profile,
        &["--stop-timeout-ms", "1000", "engine", "stop"],
    ));
    engine.disarm();
}

#[test]
fn api_client_never_sends_a_credential_through_an_ambient_proxy() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &data_root, &engine_path);
    let _guard = TestEngineGuard(profile.clone());

    assert_success(&run(&profile, &["engine", "start"]));
    assert_success(&run(&profile, &["auth", "setup"]));
    let trap =
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("test-owned proxy trap");
    trap.set_nonblocking(true)
        .expect("nonblocking trap listener");
    let proxy = format!("http://{}", trap.local_addr().expect("trap address"));
    let request = Command::new(CLI)
        .args(["engine", "info", "--json"])
        .env("DISSECT3D_CONFIG_FILE", &profile)
        .env("HTTPS_PROXY", &proxy)
        .env("https_proxy", &proxy)
        .env("HTTP_PROXY", &proxy)
        .env("http_proxy", &proxy)
        .env("ALL_PROXY", &proxy)
        .env("all_proxy", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("isolated CLI request with proxy trap configured");
    assert_success(&request);
    assert!(
        matches!(trap.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "ambient proxy accepted an API connection"
    );
    assert_success(&run(&profile, &["engine", "stop"]));
}

#[test]
#[cfg(unix)]
fn explicit_start_reports_missing_binary_and_early_exit_without_claiming_ready() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("built test engine path");
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    let missing_binary = isolated.path().join("missing-engine");
    assert_success(&run(
        &profile,
        &[
            "config",
            "set",
            "connection.data_root",
            path_arg(&data_root),
        ],
    ));
    assert_success(&run(
        &profile,
        &[
            "config",
            "set",
            "connection.engine_binary",
            path_arg(&missing_binary),
        ],
    ));
    let missing = run(&profile, &["engine", "start"]);
    assert_eq!(missing.status.code(), Some(2));
    let missing: Value = serde_json::from_slice(&missing.stdout).expect("start error");
    assert_eq!(missing["error"]["category"], "engine_unavailable");

    std::fs::write(&data_root, b"not a directory").expect("store root obstruction");
    assert_success(&run(
        &profile,
        &[
            "config",
            "set",
            "connection.engine_binary",
            path_arg(&engine_path),
        ],
    ));
    let failed_store = run(&profile, &["--start-timeout-ms", "1000", "engine", "start"]);
    let failed_store: Value = serde_json::from_slice(&failed_store.stdout).expect("start error");
    assert_eq!(
        failed_store["error"]["category"],
        "engine_start_unconfirmed"
    );
    std::fs::remove_file(&data_root).expect("remove test-owned obstruction");

    assert_success(&run(
        &profile,
        &[
            "config",
            "set",
            "connection.engine_binary",
            "/usr/bin/false",
        ],
    ));
    let started = Instant::now();
    let early_exit = run(&profile, &["--start-timeout-ms", "1000", "engine", "start"]);
    let elapsed = started.elapsed();
    assert_eq!(early_exit.status.code(), Some(3));
    let early_exit: Value = serde_json::from_slice(&early_exit.stdout).expect("start error");
    assert_eq!(early_exit["error"]["category"], "engine_start_unconfirmed");
    assert!(
        elapsed >= Duration::from_millis(900),
        "elapsed: {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(2), "elapsed: {elapsed:?}");
    assert!(!data_root.join("run/endpoint.json").exists());
}

#[test]
#[cfg(unix)]
fn readiness_observation_timeout_does_not_stop_test_owned_engine() {
    let engine_path = std::env::var_os("DISSECT3D_TEST_ENGINE")
        .map(std::path::PathBuf::from)
        .expect("build dissect3d-engine and set DISSECT3D_TEST_ENGINE");
    assert!(engine_path.is_absolute() && engine_path.is_file());
    let isolated = TempDir::new().expect("isolated acceptance root");
    let data_root = isolated.path().join("engine");
    let identity = dissect3d_platform::launch_engine(&engine_path, &data_root)
        .expect("launch test-owned engine");
    let _engine = ManagedEngine(identity);

    let timed_out = dissect3d_connection::observe_readiness(
        Duration::from_millis(100),
        Duration::from_millis(20),
        |_| Err::<(), _>(dissect3d_connection::ReadinessError::Unavailable),
    );
    assert_eq!(
        timed_out,
        Err(dissect3d_connection::ReadinessError::Deadline)
    );

    let ready = dissect3d_connection::observe_readiness(
        Duration::from_secs(5),
        Duration::from_millis(50),
        |budget| {
            let root = dissect3d_platform::OwnedRoot::open(
                &data_root,
                dissect3d_platform::RootPurpose::EngineData,
            )
            .map_err(|_| dissect3d_connection::ReadinessError::Unavailable)?;
            dissect3d_connection::verify_engine(&root, budget)
        },
    )
    .expect("later verified probe succeeds");
    assert!(
        dissect3d_platform::process_matches(&dissect3d_platform::ProcessIdentity {
            pid: ready.discovery.process.pid,
            start_marker: ready.discovery.process.start_marker.clone(),
        })
        .expect("observe verified engine process")
    );
}

fn configure(profile: &Path, data_root: &Path, engine: &Path) {
    assert_success(&run(
        profile,
        &["config", "set", "connection.data_root", path_arg(data_root)],
    ));
    assert_success(&run(
        profile,
        &[
            "config",
            "set",
            "connection.engine_binary",
            path_arg(engine),
        ],
    ));
}

struct TestEngineGuard(std::path::PathBuf);

impl Drop for TestEngineGuard {
    fn drop(&mut self) {
        let _ = run(&self.0, &["engine", "stop"]);
    }
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("temporary path is UTF-8")
}

fn stored_secret(profile: &Path) -> String {
    let mut state = profile.as_os_str().to_os_string();
    state.push(".state/credential.json");
    let bytes = std::fs::read(std::path::PathBuf::from(state)).expect("protected profile record");
    let record: Value = serde_json::from_slice(&bytes).expect("profile credential JSON");
    record["secret_hex"]
        .as_str()
        .expect("encoded secret")
        .to_owned()
}

fn assert_redacted(output: &Output, secret: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(secret));
    assert!(!stderr.contains(secret));
}

fn assert_not_in_database(data_root: &Path, secret_hex: &str) {
    let mut candidates = vec![data_root.join("metadata.sqlite3")];
    let wal = data_root.join("metadata.sqlite3-wal");
    if wal.exists() {
        candidates.push(wal);
    }
    for file in candidates {
        let bytes = std::fs::read(file).expect("SQLite store bytes");
        assert!(
            !bytes
                .windows(secret_hex.len())
                .any(|window| window == secret_hex.as_bytes())
        );
        let raw_secret = secret_hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("stored secret alphabet was validated"),
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect::<Vec<_>>();
        assert!(
            !bytes
                .windows(raw_secret.len())
                .any(|window| window == raw_secret)
        );
    }
}

fn run(profile: &Path, args: &[&str]) -> Output {
    Command::new(CLI)
        .args(args)
        .arg("--json")
        .env("DISSECT3D_CONFIG_FILE", profile)
        .env_remove("DISSECT3D_OUTPUT")
        .output()
        .expect("CLI process")
}

fn assert_success(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("one JSON response");
    assert_eq!(response["ok"], true);
}

#[cfg(unix)]
fn process_reference(root: &Path) -> ProcessIdentity {
    let discovery = read_discovery(root);
    ProcessIdentity {
        pid: discovery.process.pid,
        start_marker: discovery.process.start_marker,
    }
}

#[cfg(unix)]
fn read_discovery(root: &Path) -> DiscoveryRecord {
    let root =
        dissect3d_platform::OwnedRoot::open(root, dissect3d_platform::RootPurpose::EngineData)
            .expect("private engine root");
    let path =
        dissect3d_platform::RelativePath::parse("run/endpoint.json").expect("descriptor path");
    let bytes = root.read_file(&path, 65_536).expect("published descriptor");
    decode_json(&bytes).expect("valid descriptor")
}

#[cfg(unix)]
struct ManagedEngine(ProcessIdentity);

#[cfg(unix)]
impl ManagedEngine {
    fn disarm(&mut self) {
        self.0.pid = 0;
    }
}

#[cfg(unix)]
impl Drop for ManagedEngine {
    fn drop(&mut self) {
        if self.0.pid != 0 {
            let _ = signal_and_wait(&self.0);
        }
    }
}

#[cfg(unix)]
fn signal_and_wait(process: &ProcessIdentity) -> bool {
    if process.pid == 0 {
        return true;
    }
    if !dissect3d_platform::process_matches(process).expect("observe test-owned process") {
        return true;
    }
    let signal = Command::new("kill")
        .arg("-INT")
        .arg(process.pid.to_string())
        .status()
        .expect("send engine interrupt");
    if !signal.success() {
        return !dissect3d_platform::process_matches(process).expect("observe test-owned process");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if wait_for_process_exit(process, Duration::from_millis(100)).expect("observe engine exit")
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
    }
}

#[test]
#[cfg(unix)]
fn status_requires_live_authorization_after_native_readiness() {
    let engine = std::env::var_os("DISSECT3D_TEST_ENGINE").unwrap();
    let isolated = TempDir::new().unwrap();
    let root = isolated.path().join("engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &root, Path::new(&engine));
    assert_success(&run(&profile, &["engine", "start"]));
    let _guard = ManagedEngine(process_reference(&root));
    assert_eq!(run(&profile, &["engine", "status"]).status.code(), Some(4));
    assert_success(&run(&profile, &["auth", "setup"]));
    assert_success(&run(&profile, &["engine", "status"]));
    assert_success(&run(&profile, &["auth", "revoke"]));
    assert_eq!(run(&profile, &["engine", "status"]).status.code(), Some(4));
    assert_success(&run(&profile, &["auth", "setup"]));
    assert_success(&run(&profile, &["engine", "stop"]));
}

#[test]
#[cfg(unix)]
fn detached_start_rejects_synchronized_storage_before_creating_it() {
    let engine = std::env::var_os("DISSECT3D_TEST_ENGINE").unwrap();
    let isolated = TempDir::new().unwrap();
    let root = isolated.path().join("Dropbox/engine");
    let profile = isolated.path().join("profile.json");
    configure(&profile, &root, Path::new(&engine));
    let output = Command::new(CLI)
        .args(["--json", "engine", "start"])
        .env("DISSECT3D_CONFIG_FILE", &profile)
        .env("HOME", isolated.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !root.exists(),
        "unsupported storage was modified by the detached engine"
    );
}

#[test]
#[cfg(unix)]
fn fifo_configuration_fails_without_waiting_for_a_writer() {
    let isolated = TempDir::new().unwrap();
    let profile = isolated.path().join("config.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&profile)
            .status()
            .unwrap()
            .success()
    );
    let mut child = Command::new(CLI)
        .args(["--json", "config", "show"])
        .env("DISSECT3D_CONFIG_FILE", &profile)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(2));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("config FIFO blocked startup");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[cfg(unix)]
fn live_other_engine_errors_never_inherit_a_previous_stop_receipt() {
    let binary = std::env::var_os("DISSECT3D_TEST_ENGINE").unwrap();
    let temp = TempDir::new().unwrap();
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let profile = temp.path().join("profile.json");
    configure(&profile, &a, Path::new(&binary));
    assert_success(&run(&profile, &["engine", "start"]));
    let mut guard_a = ManagedEngine(process_reference(&a));
    assert_success(&run(&profile, &["auth", "setup"]));
    assert_success(&run(&profile, &["engine", "stop"]));
    guard_a.disarm();
    let pending_path =
        std::path::PathBuf::from(format!("{}.state/pending-stop.json", profile.display()));
    let saved = std::fs::read(&pending_path).unwrap();
    assert_success(&run(
        &profile,
        &["config", "set", "connection.data_root", path_arg(&b)],
    ));
    assert_success(&run(&profile, &["engine", "start"]));
    let _guard_b = ManagedEngine(process_reference(&b));
    let output = run(&profile, &["engine", "stop"]);
    assert_eq!(output.status.code(), Some(4));
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output["operation_id"].is_null());
    assert!(output["accepted"].is_null());
    assert_eq!(std::fs::read(&pending_path).unwrap(), saved);
    assert_success(&run(&profile, &["auth", "setup"]));
    assert_success(&run(&profile, &["engine", "stop"]));
}

#[test]
#[cfg(unix)]
fn profile_control_lease_rejects_concurrent_mutation_before_transport() {
    let binary = std::env::var_os("DISSECT3D_TEST_ENGINE").unwrap();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("engine");
    let profile = temp.path().join("profile.json");
    configure(&profile, &root, Path::new(&binary));
    assert_success(&run(&profile, &["engine", "start"]));
    let _guard = ManagedEngine(process_reference(&root));
    assert_success(&run(&profile, &["auth", "setup"]));
    let state = std::path::PathBuf::from(format!("{}.state", profile.display()));
    let state =
        dissect3d_platform::OwnedRoot::open(&state, dissect3d_platform::RootPurpose::ClientConfig)
            .unwrap();
    let lease = dissect3d_platform::AuthorityLease::acquire(&state).unwrap();
    let rejected = run(&profile, &["auth", "revoke"]);
    assert_eq!(rejected.status.code(), Some(7));
    let rejected: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejected["error"]["category"], "profile_busy");
    drop(lease);
    assert_success(&run(&profile, &["auth", "status"]));
    assert_success(&run(&profile, &["engine", "stop"]));
}
