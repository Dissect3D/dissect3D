//! Conservative Darwin guardian. Any observed fork prevents a closure witness.
use super::spawn_macos;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

fn report(value: &str) -> bool {
    let mut output = std::io::stdout().lock();
    writeln!(output, "{value}")
        .and_then(|_| output.flush())
        .is_ok()
}

struct Group {
    pid: i32,
    unreaped: bool,
}
impl Drop for Group {
    fn drop(&mut self) {
        // Before reaping, this owned direct child pins the numeric group identity.
        if self.unreaped {
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
        }
    }
}

fn event(ident: usize, filter: i16, flags: u32) -> libc::kevent {
    let mut value: libc::kevent = unsafe { std::mem::zeroed() };
    value.ident = ident;
    value.filter = filter;
    value.flags = libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR;
    value.fflags = flags;
    value
}

fn drain(queue: &OwnedFd, wait: Option<Duration>, forked: &mut bool) -> Result<bool, ()> {
    let time = wait.map(|duration| libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    });
    let mut events: [libc::kevent; 4] = unsafe { std::mem::zeroed() };
    let count = unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            std::ptr::null(),
            0,
            events.as_mut_ptr(),
            events.len() as i32,
            time.as_ref().map_or(std::ptr::null(), |v| v),
        )
    };
    if count < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            return Ok(false);
        }
        return Err(());
    }
    let mut stop = false;
    for event in &events[..count as usize] {
        if event.flags & libc::EV_ERROR != 0 {
            return Err(());
        }
        if event.filter == libc::EVFILT_PROC && event.fflags & libc::NOTE_FORK != 0 {
            *forked = true;
        }
        if event.filter == libc::EVFILT_READ && event.ident == 0 {
            stop = true;
        }
    }
    Ok(stop)
}

fn run() -> Result<bool, ()> {
    // Explicitly clear inherited SIG_IGN and SA_NOCLDWAIT before any child can
    // exit. Spawn flags alone are not our evidence of the guardian invariant.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0 {
        return Err(());
    }
    // The worker's private ends arrive at 3, 4 and 5 and its read-only inputs
    // at 6.. (listed for the worker as 5.., contiguous): move them clear of
    // every destination before opening anything else.
    // Absent means none, as on Linux.
    let listed = match std::env::var_os(dissect3d_platform::WORKER_INPUTS_ENV) {
        Some(listed) => listed.into_string().map_err(|_| ())?,
        None => String::new(),
    };
    let names: Vec<&str> = if listed.is_empty() {
        Vec::new()
    } else {
        listed.split(',').collect()
    };
    if names.len() > dissect3d_platform::MAX_WORKER_INPUTS
        || names
            .iter()
            .enumerate()
            .any(|(index, value)| *value != (5 + index).to_string())
    {
        return Err(());
    }
    let mut channels = Vec::with_capacity(3 + names.len());
    for fd in 3..6 + names.len() as i32 {
        channels.push(spawn_macos::relocate(fd).map_err(|_| ())?);
        if unsafe { libc::close(fd) } != 0 {
            return Err(());
        }
    }
    let inputs = channels.split_off(3);
    let mut args = std::env::args_os().skip(1);
    let binary = std::path::PathBuf::from(args.next().ok_or(())?);
    if !binary.is_absolute() {
        return Err(());
    }
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|_| ())?;
    let null = spawn_macos::relocate(null.as_raw_fd()).map_err(|_| ())?;
    // Commands at 3, reports at 4, diagnostics as stdout and stderr, inputs
    // at 5.. in order.
    let mut mapping = vec![
        (null.as_raw_fd(), 0),
        (channels[2].as_raw_fd(), 1),
        (channels[2].as_raw_fd(), 2),
        (channels[0].as_raw_fd(), 3),
        (channels[1].as_raw_fd(), 4),
    ];
    mapping.extend(
        inputs
            .iter()
            .enumerate()
            .map(|(index, input)| (input.as_raw_fd(), 5 + index as i32)),
    );
    let pid = spawn_macos::spawn(
        &binary,
        &args.collect::<Vec<_>>(),
        &std::env::vars_os().collect::<Vec<_>>(),
        &mapping,
        true,
    )
    .map_err(|_| ())?;
    // Only the worker keeps the channel and inputs open; worker exit becomes engine EOF.
    drop((channels, inputs));
    let mut group = Group {
        pid,
        unreaped: true,
    };
    let identity = spawn_macos::observe(pid).map_err(|_| ())?;
    let raw_queue = unsafe { libc::kqueue() };
    if raw_queue < 0 {
        return Err(());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(raw_queue) };
    let changes = [
        event(
            pid as usize,
            libc::EVFILT_PROC,
            libc::NOTE_EXIT | libc::NOTE_FORK,
        ),
        event(0, libc::EVFILT_READ, 0),
    ];
    // Observation precedes all user instructions. NOTE_TRACK is unsupported by
    // Darwin: no descendant-success claim may be inferred from direct waitpid.
    if unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            changes.as_ptr(),
            changes.len() as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(());
    }
    let mut forked = false;
    let stopped = drain(&queue, Some(Duration::ZERO), &mut forked)?;
    let mut ready = false;
    if !stopped {
        // The direct child is still unreaped and suspended; its PID cannot have
        // been reused. SIGCONT is sent only after the fork observer is armed.
        if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
            return Err(());
        }
        ready = report(&format!("READY {} {}", identity.pid, identity.start_marker));
    }
    if ready {
        while !drain(&queue, None, &mut forked)? {}
    }
    if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err(());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        drain(&queue, Some(Duration::ZERO), &mut forked)?;
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            group.unreaped = false;
            // Drain coalesced exit/fork observations before considering CLEAN.
            drain(&queue, Some(Duration::ZERO), &mut forked)?;
            return Ok(!forked);
        }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            // Ownership loss must also disable Drop's numeric group signal.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                group.unreaped = false;
            }
            return Err(());
        }
        if Instant::now() >= deadline {
            return Err(());
        }
        // This timeout bounds observation only; it is never cleanup evidence.
        drain(&queue, Some(Duration::from_millis(5)), &mut forked)?;
    }
}

pub(super) fn main() {
    let clean = run() == Ok(true);
    report(if clean { "CLEAN" } else { "FAULT" });
    if !clean {
        std::process::exit(1);
    }
}
