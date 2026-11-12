//! CLI regression for the installation boundary on an already-revoked profile.
//!
//! The native probe fixture supplies readiness only. No HTTPS service is needed:
//! an old installation's local receipt must be rejected before any API call.

use dissect3d_api::{
    BootstrapAddress, DiscoveryRecord, InstallationId, InstanceId, ProcessReference,
};
use dissect3d_platform::{
    AuthorityLease, BootstrapEndpoint, BootstrapListener, OwnedRoot, RelativePath, RootPurpose,
    current_process_identity,
};
use std::process::Command;
use std::time::Duration;

#[test]
fn revoked_profile_receipt_is_bound_to_the_selected_installation() {
    for same_installation in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let data_path = directory.path().join("engine");
        let root = OwnedRoot::create_private(&data_path, RootPurpose::EngineData).unwrap();
        let _lease = AuthorityLease::acquire(&root).unwrap();
        let installation = InstallationId::parse("ins_11111111111111111111111111111111").unwrap();
        let mut entropy = [0_u8; 16];
        getrandom::fill(&mut entropy).unwrap();
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let instance = InstanceId::parse(format!("eng_{suffix}")).unwrap();
        let listener = BootstrapListener::bind(&root, instance.as_str()).unwrap();
        let endpoint = match listener.endpoint() {
            BootstrapEndpoint::Unix { path } => BootstrapAddress::Unix {
                path: path.to_str().unwrap().to_owned(),
            },
            BootstrapEndpoint::WindowsPipe { name } => {
                BootstrapAddress::WindowsPipe { name: name.clone() }
            }
        };
        let process = current_process_identity().unwrap();
        let discovery = DiscoveryRecord {
            discovery_version: "1.0".to_owned(),
            installation_id: installation.clone(),
            instance_id: instance.clone(),
            base_url: "https://127.0.0.1:1/".to_owned(),
            bootstrap_endpoint: endpoint,
            process: ProcessReference {
                pid: process.pid,
                start_marker: process.start_marker,
            },
            // The probe uses only the shape of these fields. Neither case
            // constructs an authenticated HTTPS client from this fixture.
            trust_anchor_der: vec![1],
            trust_anchor_sha256: vec![0; 32],
        };
        root.write_atomic(
            &RelativePath::parse("run/endpoint.json").unwrap(),
            &serde_json::to_vec(&discovery).unwrap(),
        )
        .unwrap();

        let config_path = directory.path().join("profile.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&serde_json::json!({"connection":{"data_root":data_path}})).unwrap(),
        )
        .unwrap();
        let profile = OwnedRoot::create_private(
            &directory.path().join("profile.json.state"),
            RootPurpose::ClientConfig,
        )
        .unwrap();
        let credential_path = RelativePath::parse("credential.json").unwrap();
        let credential = serde_json::to_vec(&serde_json::json!({
            "installation_id": if same_installation {
                installation.as_str()
            } else {
                "ins_22222222222222222222222222222222"
            },
            "instance_id": instance,
            "client_id":"cli_33333333333333333333333333333333",
            "enrollment_id":"enr_44444444444444444444444444444444",
            "secret_hex":"",
            "state":"revoked"
        }))
        .unwrap();
        profile.write_atomic(&credential_path, &credential).unwrap();

        let probe = std::thread::spawn(move || {
            let mut channel = listener.accept(Duration::from_secs(5)).unwrap();
            let request: serde_json::Value =
                serde_json::from_slice(&channel.read_frame().unwrap()).unwrap();
            assert_eq!(request["kind"], "probe");
            assert_eq!(request["instance_id"], instance.as_str());
            channel
                .write_frame(
                    &serde_json::to_vec(&serde_json::json!({
                        "bootstrap_version":"1.0",
                        "installation_id":installation,
                        "instance_id":instance,
                        "ready":true
                    }))
                    .unwrap(),
                )
                .unwrap();
        });
        let output = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
            .env("DISSECT3D_CONFIG_FILE", &config_path)
            .args(["--json", "auth", "revoke"])
            .output()
            .unwrap();
        probe.join().unwrap();
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            profile.read_file(&credential_path, 16_384).unwrap(),
            credential,
            "neither local receipt observation nor refusal changes the credential"
        );
        if same_installation {
            assert!(output.status.success(), "{response}");
            assert_eq!(response["data"]["revoked"], true);
        } else {
            assert_eq!(output.status.code(), Some(4), "{response}");
            assert_eq!(response["ok"], false);
            assert_eq!(response["error"]["category"], "unauthorized");
        }
    }
}
