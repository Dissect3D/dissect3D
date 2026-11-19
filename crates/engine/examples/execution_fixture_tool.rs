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
    let mut values = std::collections::BTreeMap::new();
    let mut rest = args.iter();
    if rest.next().and_then(|c| c.to_str()) != Some("prepare") {
        usage();
        std::process::exit(2);
    }
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

fn usage() {
    println!(
        "Usage: execution_fixture_tool prepare --data-root ABS_ROOT --worker ABS_WORKER [--guardian ABS_GUARDIAN]"
    );
}
