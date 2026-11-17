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
    if exec_linux::configure(&mut command, std::env::vars_os().collect()).is_err() {
        std::process::exit(1);
    }
    let Ok(child) = command.spawn() else {
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
