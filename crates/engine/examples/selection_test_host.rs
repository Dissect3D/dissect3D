//! Supplementary native host for connected task-ambiguity regressions.

#[cfg(feature = "test-support")]
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--data-root" {
        eprintln!("Usage: selection_test_host --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    }
    if let Err(error) =
        dissect3d_engine::run_selection_test_engine(std::path::Path::new(&args[1])).await
    {
        eprintln!("selection test host failed: {}", error.safe_code());
        std::process::exit(1);
    }
}

#[cfg(not(feature = "test-support"))]
fn main() {
    eprintln!("selection test host requires test-support");
    std::process::exit(2);
}
