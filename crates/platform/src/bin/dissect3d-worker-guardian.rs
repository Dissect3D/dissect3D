//! Private controlled-profile helper. EOF on stdin revokes execution ownership.
#[cfg(target_os = "macos")]
use dissect3d_platform::{PlatformError, ProcessIdentity};
#[cfg(target_os = "macos")]
#[path = "../worker/guardian_macos.rs"]
mod guardian_macos;
#[cfg(target_os = "macos")]
#[path = "../worker/spawn_macos.rs"]
mod spawn_macos;
#[cfg(target_os = "macos")]
fn main() {
    guardian_macos::main();
}
#[cfg(target_os = "linux")]
#[path = "../worker/exec_linux.rs"]
mod exec_linux;
#[cfg(target_os = "linux")]
fn main() {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    // Ignored SIGCHLD/SA_NOCLDWAIT would auto-reap the leader and destroy the
    // group identity pin. Establish waitable children before the first spawn.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0 {
        std::process::exit(1);
    }
    // A subreaper observes orphaned grandchildren, including group escape.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        std::process::exit(1);
    }
    // The worker's private pipe ends arrive at 3, 4 and 5 and its read-only
    // inputs at 6.. (listed for the worker as 5..). Move them above every
    // target as CLOEXEC copies before anything else opens.
    let Some(input_count) = input_count() else {
        std::process::exit(1);
    };
    let Some((channels, inputs)) = relocate_channels(input_count) else {
        std::process::exit(1);
    };
    let mut args = std::env::args_os().skip(1);
    let Some(binary) = args.next() else {
        std::process::exit(1);
    };
    if !std::path::Path::new(&binary).is_absolute() {
        std::process::exit(1);
    }
    if !checkpoint("before_worker") {
        return;
    }
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The worker never inherits the engine lifeline or the helper report pipe.
    // stdio replacement happens before exec; setpgid happens before user code.
    let guardian_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            // Protect the direct leader if the guardian dies during launch.
            // This is not descendant-tree proof after arbitrary user code runs.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != guardian_pid {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    if !install_preexec_checkpoint(&mut command) {
        std::process::exit(1);
    }
    {
        use std::os::fd::AsRawFd;
        // After the checkpoint hook (its bridge may occupy 3 or 4): commands
        // at 3, reports at 4, then diagnostics over stdout and stderr.
        let [commands, reports, diagnostics] = &channels;
        let mapped = [
            ([commands.as_raw_fd(), reports.as_raw_fd()], 3),
            ([diagnostics.as_raw_fd(), diagnostics.as_raw_fd()], 1),
        ];
        for (sources, first) in mapped {
            if exec_linux::map_descriptor_list(&mut command, &sources, first).is_err() {
                std::process::exit(1);
            }
        }
        // Last, so no earlier target can clobber a relocated input.
        let sources: Vec<_> = inputs.iter().map(|input| input.as_raw_fd()).collect();
        if exec_linux::map_descriptor_list(&mut command, &sources, 5).is_err() {
            std::process::exit(1);
        }
    }
    let sealed = 5 + input_count as u32;
    if exec_linux::configure(&mut command, std::env::vars_os().collect(), sealed).is_err() {
        std::process::exit(1);
    }
    let spawned = command.spawn();
    // Only the worker keeps the channel and inputs open; worker exit becomes engine EOF.
    drop((channels, inputs));
    let Ok(child) = spawned else {
        std::process::exit(1);
    };
    let pid = child.id() as i32;
    // Keep the leader unreaped until after the group signal. Its PID cannot be
    // reused, even if it exits before the engine closes the lifeline.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let marker = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19));
    let checkpoint_ready =
        marker.is_some_and(|marker| checkpoint(&format!("created {pid} linux-start-{marker}")));
    let ready = checkpoint_ready
        && marker.is_some_and(|marker| report(&format!("READY {pid} linux-start-{marker}")));
    if ready {
        let mut byte = [0u8; 1];
        // Any byte, EOF or broken lifeline requests cleanup; there is no worker
        // control-loop dependency and no execute permission after ownership loss.
        let _ = std::io::stdin().read(&mut byte);
    }
    // Failed READY delivery can mean the engine died during launch. It must
    // enter cleanup too; stdout convenience macros would panic and orphan it.
    let killed = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if killed != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        report("FAULT");
        std::process::exit(1);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if waited > 0 {
            continue;
        }
        if waited < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                report("CLEAN");
                return;
            }
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            report("FAULT");
            std::process::exit(1);
        }
        if Instant::now() >= deadline {
            // Escaped or uninterruptible descendants are never called clean.
            report("FAULT");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The number of inherited inputs, from the platform-set list, which must be
/// exactly the contiguous worker descriptors 5.. in order. Absent means none:
/// nothing past descriptor 5 is then relocated, and the seal closes the rest.
#[cfg(target_os = "linux")]
fn input_count() -> Option<usize> {
    let Some(listed) = std::env::var_os(dissect3d_platform::WORKER_INPUTS_ENV) else {
        return Some(0);
    };
    let listed = listed.into_string().ok()?;
    if listed.is_empty() {
        return Some(0);
    }
    let values: Vec<&str> = listed.split(',').collect();
    if values.len() > dissect3d_platform::MAX_WORKER_INPUTS {
        return None;
    }
    let contiguous = values
        .iter()
        .enumerate()
        .all(|(index, value)| *value == (5 + index).to_string());
    contiguous.then_some(values.len())
}

/// Move the three channel ends (3, 4, 5) and `inputs` input descriptors
/// (6..) clear of every worker target.
#[cfg(target_os = "linux")]
fn relocate_channels(
    inputs: usize,
) -> Option<([std::os::fd::OwnedFd; 3], Vec<std::os::fd::OwnedFd>)> {
    use std::os::fd::FromRawFd;
    let mut moved = Vec::with_capacity(3 + inputs);
    for fd in 3..6 + inputs as i32 {
        // SAFETY: fcntl/close on fixed descriptor numbers this process was
        // launched with; an absent descriptor fails F_DUPFD_CLOEXEC.
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
        if copy < 0 || unsafe { libc::close(fd) } != 0 {
            return None;
        }
        // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned here.
        moved.push(unsafe { std::os::fd::OwnedFd::from_raw_fd(copy) });
    }
    let inputs = moved.split_off(3);
    Some((moved.try_into().ok()?, inputs))
}

#[cfg(target_os = "linux")]
fn report(message: &str) -> bool {
    use std::io::Write;
    let mut output = std::io::stdout().lock();
    writeln!(output, "{message}")
        .and_then(|_| output.flush())
        .is_ok()
}

#[cfg(target_os = "linux")]
fn checkpoint(stage: &str) -> bool {
    checkpoint_exchange(stage)
}

#[cfg(target_os = "linux")]
fn checkpoint_exchange(stage: &str) -> bool {
    use std::io::Read;
    use std::time::{Duration, Instant};
    if !report(&format!("OWNERSHIP {stage}")) {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut fd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut fd, 1, timeout) };
        if result > 0 {
            let mut byte = [0];
            return std::io::stdin().read(&mut byte).ok() == Some(1) && byte[0] == 1;
        }
        if result == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return false;
        }
    }
}

#[cfg(target_os = "linux")]
fn install_preexec_checkpoint(command: &mut std::process::Command) -> bool {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::{net::UnixStream, process::CommandExt};
    let Ok((mut bridge, child_gate)) = UnixStream::pair() else {
        return false;
    };
    std::thread::spawn(move || {
        let mut bytes = [0; 4];
        if bridge.read_exact(&mut bytes).is_err() {
            return;
        }
        let pid = i32::from_ne_bytes(bytes);
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let marker = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19));
        let allowed = marker.is_some_and(|marker| {
            checkpoint_exchange(&format!("before_exec {pid} linux-start-{marker}"))
        });
        let _ = bridge.write_all(&[u8::from(allowed)]);
    });
    // The parent bridge performs allocation/reporting. The fork child uses only
    // native write/poll/read and errno; exact exec later closes this extra fd.
    unsafe {
        command.pre_exec(move || {
            let bytes = libc::getpid().to_ne_bytes();
            if libc::write(child_gate.as_raw_fd(), bytes.as_ptr().cast(), bytes.len())
                != bytes.len() as isize
            {
                return Err(std::io::Error::last_os_error());
            }
            let mut fd = libc::pollfd {
                fd: child_gate.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let mut byte = [0u8];
            if libc::poll(&mut fd, 1, 10_000) <= 0
                || libc::read(child_gate.as_raw_fd(), byte.as_mut_ptr().cast(), 1) != 1
                || byte[0] != 1
            {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            Ok(())
        });
    }
    true
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    std::process::exit(1);
}
