use std::process::Command;

#[test]
fn numeric_arguments_obey_the_same_bounds_as_environment_and_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.json");
    std::fs::write(&config, "{}").unwrap();
    for (flag, key, minimum, maximum) in [
        (
            "--connect-timeout-ms",
            "connect_timeout_ms",
            100_u64,
            30_000_u64,
        ),
        ("--read-timeout-ms", "read_timeout_ms", 100, 60_000),
        ("--read-attempts", "read_attempts", 1, 3),
        ("--start-timeout-ms", "start_timeout_ms", 1_000, 60_000),
        ("--stop-timeout-ms", "stop_timeout_ms", 1_000, 60_000),
    ] {
        for value in [minimum - 1, maximum + 1, u64::MAX] {
            let output = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
                .args(["--json", flag, &value.to_string(), "config", "show"])
                .env("DISSECT3D_CONFIG_FILE", &config)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{flag} {value}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        for value in [minimum, maximum] {
            let output = Command::new(env!("CARGO_BIN_EXE_dissect3d"))
                .args(["--json", flag, &value.to_string(), "config", "show"])
                .env("DISSECT3D_CONFIG_FILE", &config)
                .output()
                .unwrap();
            assert!(output.status.success());
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["data"]["effective"][key]["value"], value);
            assert_eq!(result["data"]["effective"][key]["source"], "arguments");
        }
    }
}
