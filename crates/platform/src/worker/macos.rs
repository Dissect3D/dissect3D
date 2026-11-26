//! Darwin guardian client. Forked-descendant closure remains fail-closed.
use super::{CleanupFault, WORKER_CONTROL_ENV, WORKER_INPUTS_ENV, WorkerChannels, WorkerCommand};
use crate::{PlatformError, ProcessIdentity};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
#[path = "spawn_macos.rs"]
mod spawn_macos;

/// First worker-side descriptor for inherited inputs (3 and 4 are control).
const FIRST_INPUT_FD: u64 = 5;

/// A read-only duplicate of `file` for input `index`, and the descriptor the
/// worker will see. A writable or non-regular descriptor is refused.
pub(super) fn read_only_view(
    file: &std::fs::File,
    index: usize,
) -> Result<(std::fs::File, u64), PlatformError> {
    let fd = file.as_raw_fd();
    // SAFETY: fcntl/fstat on a live descriptor borrowed from `file`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return Err(PlatformError::InvalidFile);
    }
    let view = file.try_clone().map_err(|_| PlatformError::Io)?;
    Ok((view, FIRST_INPUT_FD + index as u64))
}

pub(super) struct Worker {
    guardian: i32,
    lifeline: Option<UnixStream>,
    reports: Receiver<String>,
}

impl Worker {
    pub(super) fn launch(
        command: WorkerCommand,
    ) -> Result<
        (
            Self,
            ProcessIdentity,
            Option<ProcessIdentity>,
            WorkerChannels,
        ),
        PlatformError,
    > {
        // This client owns raw waitpid state. A competing SIGCHLD reaper could
        // consume the guardian and allow PID reuse before our reaper runs.
        if !super::child_exit_reaping_unclaimed().map_err(|_| PlatformError::LaunchRestricted)? {
            return Err(PlatformError::LaunchRestricted);
        }
        let helper = command.guardian.ok_or(PlatformError::InvalidPath)?;
        if !helper.is_absolute() || !helper.is_file() {
            return Err(PlatformError::InvalidPath);
        }
        let (lifeline, input) = UnixStream::pair().map_err(|_| PlatformError::Io)?;
        let (output, report) = UnixStream::pair().map_err(|_| PlatformError::Io)?;
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|_| PlatformError::Io)?;
        let args = std::iter::once(command.executable.into_os_string())
            .chain(command.args)
            .collect::<Vec<_>>();
        // Worker pipe ends reach the guardian at 3, 4 and 5 (see the guardian).
        let (to_worker, worker_commands) = UnixStream::pair().map_err(|_| PlatformError::Io)?;
        let (from_worker, worker_reports) = UnixStream::pair().map_err(|_| PlatformError::Io)?;
        let (diagnostics, worker_diagnostics) =
            UnixStream::pair().map_err(|_| PlatformError::Io)?;
        let mut environment = command.environment;
        environment.push((WORKER_CONTROL_ENV.into(), "3:4".into()));
        // Inputs reach the guardian at 6.. and the worker at 5.. in order.
        let inputs = command.inputs;
        let names = (0..inputs.len() as u64)
            .map(|index| (FIRST_INPUT_FD + index).to_string())
            .collect::<Vec<_>>()
            .join(",");
        environment.push((WORKER_INPUTS_ENV.into(), names.into()));
        let sources = [
            input.as_raw_fd(),
            report.as_raw_fd(),
            null.as_raw_fd(),
            worker_commands.as_raw_fd(),
            worker_reports.as_raw_fd(),
            worker_diagnostics.as_raw_fd(),
        ]
        .into_iter()
        .chain(inputs.iter().map(|file| file.as_raw_fd()))
        .map(spawn_macos::relocate)
        .collect::<Result<Vec<_>, _>>()?;
        let mapping: Vec<_> = sources
            .iter()
            .enumerate()
            .map(|(target, fd)| (fd.as_raw_fd(), target as i32))
            .collect();
        let pid = spawn_macos::spawn(&helper, &args, &environment, &mapping, false)?;
        drop(sources);
        drop((
            input,
            report,
            worker_commands,
            worker_reports,
            worker_diagnostics,
            inputs,
        ));
        let (send, reports) = mpsc::sync_channel(2);
        // Construct the ownership guard before any fallible identity/readiness work.
        let worker = Self {
            guardian: pid,
            lifeline: Some(lifeline),
            reports,
        };
        std::thread::spawn(move || {
            use std::io::Read;
            let mut reader = BufReader::new(output);
            for _ in 0..2 {
                let mut bytes = Vec::new();
                if reader
                    .by_ref()
                    .take(256)
                    .read_until(b'\n', &mut bytes)
                    .is_err()
                    || bytes.last() != Some(&b'\n')
                {
                    break;
                }
                if send
                    .send(String::from_utf8_lossy(&bytes).trim().to_owned())
                    .is_err()
                {
                    break;
                }
            }
        });
        let guardian = spawn_macos::observe(pid)?;
        let ready = worker
            .reports
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| PlatformError::Io)?;
        let fields: Vec<_> = ready.split_whitespace().collect();
        let ["READY", pid, marker] = fields.as_slice() else {
            return Err(PlatformError::Io);
        };
        let process = ProcessIdentity {
            pid: pid.parse().map_err(|_| PlatformError::Io)?,
            start_marker: (*marker).into(),
        };
        if !crate::process_matches(&guardian)? || !crate::process_matches(&process)? {
            return Err(PlatformError::Io);
        }
        let channels = WorkerChannels {
            to_worker: std::fs::File::from(std::os::fd::OwnedFd::from(to_worker)),
            from_worker: std::fs::File::from(std::os::fd::OwnedFd::from(from_worker)),
            diagnostics: std::fs::File::from(std::os::fd::OwnedFd::from(diagnostics)),
        };
        Ok((worker, process, Some(guardian), channels))
    }

    pub(super) fn terminate(&mut self, deadline: Instant) -> Result<(), CleanupFault> {
        self.lifeline.take();
        match self
            .reports
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(line) if line == "CLEAN" => Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CleanupFault::Deadline),
            _ => Err(CleanupFault::OwnershipLost),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.lifeline.take();
        let pid = self.guardian;
        // Only reap this direct child; never signal a numeric PID after ownership
        // may have been lost. The guardian must survive engine Drop to clean up.
        std::thread::spawn(move || {
            loop {
                let status = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                if status >= 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        });
    }
}
