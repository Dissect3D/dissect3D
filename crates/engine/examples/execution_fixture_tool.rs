//! Maintainer tool: explicit test-only preparation of the r2 controlled CPU
//! package in a fresh private root. It installs the built worker (and, on
//! Linux, the guardian) by hash and probes it; it downloads nothing.
use std::path::PathBuf;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "--help") {
        usage();
        return;
    }
    let mut rest = args.iter();
    match rest.next().and_then(|c| c.to_str()) {
        Some("prepare") => run_prepare(rest),
        Some("write-provider-fixture") => run_write_provider_fixture(rest),
        _ => {
            usage();
            std::process::exit(2);
        }
    }
}

fn run_prepare(mut rest: std::slice::Iter<'_, std::ffi::OsString>) {
    let mut values = std::collections::BTreeMap::new();
    while let Some(flag) = rest.next() {
        let (Some(flag), Some(value)) = (flag.to_str(), rest.next()) else {
            usage();
            std::process::exit(2);
        };
        let value = PathBuf::from(value);
        if !matches!(flag, "--data-root" | "--worker" | "--guardian")
            || !value.is_absolute()
            || values.insert(flag.to_owned(), value).is_some()
        {
            usage();
            std::process::exit(2);
        }
    }
    let (Some(root), Some(worker)) = (values.get("--data-root"), values.get("--worker")) else {
        usage();
        std::process::exit(2);
    };
    let guardian = values.get("--guardian").map(PathBuf::as_path);
    if let Err(error) = dissect3d_engine::prepare_execution_fixture(root, worker, guardian) {
        eprintln!("execution fixture tool failed: {}", error.safe_code());
        std::process::exit(1);
    }
}

fn run_write_provider_fixture(mut rest: std::slice::Iter<'_, std::ffi::OsString>) {
    let mut values = std::collections::BTreeMap::new();
    while let Some(flag) = rest.next() {
        let (Some(flag), Some(value)) = (flag.to_str(), rest.next()) else {
            usage();
            std::process::exit(2);
        };
        let value = PathBuf::from(value);
        if !matches!(
            flag,
            "--data-root" | "--config-a" | "--config-b" | "--cli" | "--output"
        ) || !value.is_absolute()
            || values.insert(flag.to_owned(), value).is_some()
        {
            usage();
            std::process::exit(2);
        }
    }
    let (Some(root), Some(config_a), Some(config_b), Some(cli), Some(output)) = (
        values.get("--data-root"),
        values.get("--config-a"),
        values.get("--config-b"),
        values.get("--cli"),
        values.get("--output"),
    ) else {
        usage();
        std::process::exit(2);
    };
    #[cfg(unix)]
    if let Err(error) =
        dissect3d_engine::write_execution_provider_fixture(root, config_a, config_b, cli, output)
    {
        eprintln!("execution fixture tool failed: {}", error.safe_code());
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        let _ = (root, config_a, config_b, cli, output);
        eprintln!("write-provider-fixture is supported only on Unix/WSL2");
        std::process::exit(2);
    }
}

fn usage() {
    println!(
        "Usage:\n  execution_fixture_tool prepare --data-root ABS_ROOT --worker ABS_WORKER [--guardian ABS_GUARDIAN]\n  execution_fixture_tool write-provider-fixture --data-root ABS_ROOT --config-a ABS_CONFIG --config-b ABS_CONFIG --cli ABS_DISSECT3D --output ABS_JSON"
    );
}
