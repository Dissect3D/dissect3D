//! Darwin guardian client. Forked-descendant closure remains fail-closed.
use super::{CleanupFault, WORKER_CONTROL_ENV, WorkerChannels, WorkerCommand};
use crate::{PlatformError, ProcessIdentity};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
#[path = "spawn_macos.rs"]
mod spawn_macos;

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
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0
            || disposition.sa_sigaction != libc::SIG_DFL
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
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
        let sources = [
            input.as_raw_fd(),
            report.as_raw_fd(),
            null.as_raw_fd(),
            worker_commands.as_raw_fd(),
            worker_reports.as_raw_fd(),
            worker_diagnostics.as_raw_fd(),
        ]
        .map(spawn_macos::relocate)
        .into_iter()
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
