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
        eprintln!("submission test host requires an absolute data root");
        std::process::exit(2);
    };
    if flag != "--data-root" || args.next().is_some() {
        eprintln!("submission test host accepts only --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    }
    if let Err(error) = dissect3d_engine::run_submission_test_engine(&PathBuf::from(path)).await {
        eprintln!(
            "submission test host startup or service failure: {}",
            error.safe_code()
        );
        std::process::exit(1);
    }
}

fn usage() {
    println!("Usage: submission_test_host --data-root ABSOLUTE_PATH");
}
