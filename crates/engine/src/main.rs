use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(flag) = args.next() else {
        eprintln!("engine requires --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    };
    if flag == "--help" {
        println!("Usage: dissect3d-engine --data-root ABSOLUTE_PATH");
        return;
    }
    if flag != "--data-root" {
        eprintln!("engine accepts only --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    }
    let Some(path) = args.next() else {
        eprintln!("engine requires an absolute data root");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("engine accepts only --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    }
    let data_root = PathBuf::from(path);
    if let Err(error) = dissect3d_engine::run_engine(&data_root).await {
        eprintln!("engine startup or service failure: {}", error.safe_code());
        std::process::exit(1);
    }
}
