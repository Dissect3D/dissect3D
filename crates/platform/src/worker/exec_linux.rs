//! Exact execve, without execvp's implicit /bin/sh fallback on ENOEXEC.
use std::ffi::{CString, OsString};
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::process::Command;

struct Image {
    first_sealed: u32,
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
        // sealing all engine/helper descriptors outside the explicit set below
        // `first_sealed` (stdio plus any private channels mapped by the caller).
        if unsafe {
            libc::close_range(
                self.first_sealed,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC as i32,
            )
        } != 0
        {
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

/// Register the exact-exec hook. Register any descriptor-mapping hook first:
/// this one seals every descriptor from `first_sealed` (minimum 3) and execs.
pub(super) fn configure(
    command: &mut Command,
    environment: Vec<(OsString, OsString)>,
    first_sealed: u32,
) -> std::io::Result<()> {
    if first_sealed < 3 {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
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
        first_sealed,
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

/// Most descriptors one [`map_descriptor_list`] call places.
pub(super) const MAX_MAPPED: usize = 32;

/// Child-only hook: place `sources[i]` at descriptor `first + i`, without
/// CLOEXEC, for at most [`MAX_MAPPED`] sources. Sources are first copied above
/// every target, so a source that already occupies another target cannot be
/// clobbered. The list is copied into a fixed array before fork; only
/// async-signal-safe fcntl/dup2 run after fork.
pub(super) fn map_descriptor_list(
    command: &mut Command,
    sources: &[std::os::fd::RawFd],
    first: std::os::fd::RawFd,
) -> std::io::Result<()> {
    if sources.len() > MAX_MAPPED {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let count = sources.len();
    let mut fixed = [0; MAX_MAPPED];
    fixed[..count].copy_from_slice(sources);
    // SAFETY: the closure performs only fcntl/dup2 on captured integers.
    unsafe {
        command.pre_exec(move || {
            let mut copies = [0; MAX_MAPPED];
            for index in 0..count {
                copies[index] =
                    libc::fcntl(fixed[index], libc::F_DUPFD_CLOEXEC, first + count as i32);
                if copies[index] < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (offset, copy) in copies[..count].iter().enumerate() {
                if libc::dup2(*copy, first + offset as i32) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}
