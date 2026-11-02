use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(flag) = args.next() else {
        eprintln!("discovery test host requires --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    };
    if flag == "--help" {
        println!("Usage: discovery_test_host --data-root ABSOLUTE_PATH");
        return;
    }
    let Some(path) = args.next() else {
        eprintln!("discovery test host requires an absolute data root");
        std::process::exit(2);
    };
    if flag != "--data-root" || args.next().is_some() {
        eprintln!("discovery test host accepts only --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    }
    if let Err(error) = dissect3d_engine::run_discovery_test_engine(&PathBuf::from(path)).await {
        eprintln!(
            "discovery test host startup or service failure: {}",
            error.safe_code()
        );
        std::process::exit(1);
    }
}
