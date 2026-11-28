//! Console interrupt delivery setup (`WE-P08.5`).
//!
//! On Windows, a child process started with `CREATE_NEW_PROCESS_GROUP` inherits
//! the `ENABLE_IGNORE_CTRL_C` console flag. Calling `SetConsoleCtrlHandler(None, FALSE)`
//! clears that flag before a Ctrl+C listener is installed so `CTRL_C_EVENT` is
//! delivered to the process. On non-Windows platforms this is a no-op.

use crate::PlatformError;

/// Re-enable `CTRL_C_EVENT` delivery for the current process on Windows.
///
/// Must be called before installing the CLI's Ctrl+C signal listener for
/// `run`, `jobs watch`, and `jobs wait`.
#[cfg(windows)]
pub fn enable_console_ctrl_c() -> Result<(), PlatformError> {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    // SAFETY: Passing `None` with `Add = 0` (`FALSE`) only clears the
    // process-local ignore-Ctrl+C attribute inherited from
    // `CREATE_NEW_PROCESS_GROUP`; no callback pointer is registered.
    let ok = unsafe { SetConsoleCtrlHandler(None, 0) };
    if ok == 0 {
        return Err(PlatformError::Io);
    }
    Ok(())
}

/// Re-enable `CTRL_C_EVENT` delivery for the current process (no-op on non-Windows).
#[cfg(not(windows))]
pub fn enable_console_ctrl_c() -> Result<(), PlatformError> {
    Ok(())
}
