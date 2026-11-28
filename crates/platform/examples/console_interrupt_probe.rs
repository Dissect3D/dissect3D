//! Helper binary for `windows_console_interrupt` testing `enable_console_ctrl_c`.

use std::io::Write;
use std::time::{Duration, Instant};

fn main() {
    let skip_enable = std::env::args().any(|arg| arg == "--no-enable");
    if !skip_enable && let Err(error) = dissect3d_platform::enable_console_ctrl_c() {
        eprintln!("enable_console_ctrl_c failed: {error:?}");
        std::process::exit(2);
    }
    let _ = writeln!(std::io::stdout(), "ready");
    let _ = std::io::stdout().flush();

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
}
