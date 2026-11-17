//! Exact execve, without execvp's implicit /bin/sh fallback on ENOEXEC.
use std::ffi::{CString, OsString};
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::process::Command;

struct Image {
    binary: CString,
    _arguments: Vec<CString>,
    _environment: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
}

// SAFETY: pointers refer only to immutable CString heap buffers owned by Image.
// Moving Image does not move those buffers; it remains alive throughout execve.
unsafe impl Send for Image {}
// SAFETY: no buffer or pointer is mutated after construction.
unsafe impl Sync for Image {}

impl Image {
    fn execute(&self) -> std::io::Result<()> {
        // CLOEXEC retains Command's exec-error pipe until successful exec, while
        // sealing all engine/helper descriptors outside the explicit stdio set.
        if unsafe { libc::close_range(3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC as i32) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: all arrays are terminated and their owned CString storage is
        // live. Only async-signal-safe calls execute in this post-fork path.
        unsafe {
            libc::execve(self.binary.as_ptr(), self.argv.as_ptr(), self.envp.as_ptr());
        }
        Err(std::io::Error::last_os_error())
    }
}

pub(super) fn configure(
    command: &mut Command,
    environment: Vec<(OsString, OsString)>,
) -> std::io::Result<()> {
    let string = |value: &std::ffi::OsStr| {
        CString::new(value.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
    };
    let binary = string(command.get_program())?;
    let arguments = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(string)
        .collect::<Result<Vec<_>, _>>()?;
    let environment = environment
        .into_iter()
        .map(|(key, value)| {
            let mut pair = key;
            pair.push("=");
            pair.push(value);
            string(&pair)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let argv = arguments
        .iter()
        .map(|value| value.as_ptr())
        .chain(Some(std::ptr::null()))
        .collect();
    let envp = environment
        .iter()
        .map(|value| value.as_ptr())
        .chain(Some(std::ptr::null()))
        .collect();
    let image = Image {
        binary,
        _arguments: arguments,
        _environment: environment,
        argv,
        envp,
    };
    // SAFETY: all allocation and environment access happened before fork. The
    // closure borrows only the captured immutable image and uses native syscalls.
    unsafe {
        command.pre_exec(move || image.execute());
    }
    Ok(())
}
