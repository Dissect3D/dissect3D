//! Isolated execution host for the explicitly prepared r2 package (WE-P06,
//! WE-P09). Prepare its data root first with `execution_fixture_tool`.
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(flag) = args.next() else {
        usage();
        std::process::exit(2);
    };
    if flag == "--help" {
        usage();
        return;
    }
    let Some(path) = args.next() else {
        eprintln!("execution test host requires an absolute data root");
        std::process::exit(2);
    };
    if flag != "--data-root" || args.next().is_some() {
        eprintln!("execution test host accepts only --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    }
    run(PathBuf::from(path)).await;
}

#[cfg(unix)]
async fn run(path: PathBuf) {
    if let Err(error) = dissect3d_engine::run_execution_test_engine(&path).await {
        eprintln!(
            "execution test host startup or service failure: {}",
            error.safe_code()
        );
        std::process::exit(1);
    }
}

/// Windows execution services are not wired yet (B-WINDOWS); refuse plainly.
#[cfg(not(unix))]
async fn run(_path: PathBuf) {
    eprintln!("execution test host is not available on this platform yet");
    std::process::exit(1);
}

fn usage() {
    println!("Usage: execution_test_host --data-root ABSOLUTE_PATH");
}
