//! Isolated execution host for the explicitly prepared r2 package (WE-P06,
//! WE-P09). Prepare its data root first with `execution_fixture_tool`.
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
const PRE_RECEIPT_HOLD_MAX_MS: u64 = 4_500;
#[cfg(unix)]
const CANCEL_WAIT_HOLD_MAX_MS: u64 = 10_000;

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        usage();
        std::process::exit(2);
    }
    if args.len() == 1 && args[0] == "--help" {
        usage();
        return;
    }
    let mut data_root: Option<PathBuf> = None;
    let mut pre_receipt_hold_ms: Option<u64> = None;
    let mut cancel_wait_hold_ms: Option<u64> = None;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let (Some(flag), Some(value)) = (flag.to_str(), iter.next()) else {
            usage();
            std::process::exit(2);
        };
        match flag {
            "--data-root" => {
                let path = PathBuf::from(value);
                if !path.is_absolute() || data_root.replace(path).is_some() {
                    eprintln!("execution test host requires one absolute --data-root");
                    std::process::exit(2);
                }
            }
            "--pre-receipt-hold-ms" => {
                let Some(ms) = parse_bound_ms(value, 4_500) else {
                    eprintln!("--pre-receipt-hold-ms must be an integer in 1..=4500");
                    std::process::exit(2);
                };
                if pre_receipt_hold_ms.replace(ms).is_some() {
                    usage();
                    std::process::exit(2);
                }
            }
            "--cancel-wait-hold-ms" => {
                let Some(ms) = parse_bound_ms(value, 10_000) else {
                    eprintln!("--cancel-wait-hold-ms must be an integer in 1..=10000");
                    std::process::exit(2);
                };
                if cancel_wait_hold_ms.replace(ms).is_some() {
                    usage();
                    std::process::exit(2);
                }
            }
            _ => {
                usage();
                std::process::exit(2);
            }
        }
    }
    let Some(path) = data_root else {
        eprintln!("execution test host requires --data-root ABSOLUTE_PATH");
        std::process::exit(2);
    };
    run(path, pre_receipt_hold_ms, cancel_wait_hold_ms).await;
}

fn parse_bound_ms(value: &std::ffi::OsStr, max: u64) -> Option<u64> {
    let ms = value.to_str()?.parse::<u64>().ok()?;
    (1..=max).contains(&ms).then_some(ms)
}

#[cfg(unix)]
async fn run(path: PathBuf, pre_receipt_hold_ms: Option<u64>, cancel_wait_hold_ms: Option<u64>) {
    let holds = dissect3d_engine::ExecutionTestHolds {
        pre_receipt_hold: pre_receipt_hold_ms
            .map(|ms| Duration::from_millis(ms.min(PRE_RECEIPT_HOLD_MAX_MS))),
        cancel_wait_hold: cancel_wait_hold_ms
            .map(|ms| Duration::from_millis(ms.min(CANCEL_WAIT_HOLD_MAX_MS))),
    };
    if let Err(error) = dissect3d_engine::run_execution_test_engine_with_holds(&path, holds).await {
        eprintln!(
            "execution test host startup or service failure: {}",
            error.safe_code()
        );
        std::process::exit(1);
    }
}

/// Windows execution services are not wired yet (B-WINDOWS); refuse plainly.
#[cfg(not(unix))]
async fn run(_path: PathBuf, _pre_receipt_hold_ms: Option<u64>, _cancel_wait_hold_ms: Option<u64>) {
    eprintln!("execution test host is not available on this platform yet");
    std::process::exit(1);
}

fn usage() {
    println!(
        "Usage: execution_test_host --data-root ABSOLUTE_PATH [--pre-receipt-hold-ms 1..=4500] [--cancel-wait-hold-ms 1..=10000]"
    );
}
