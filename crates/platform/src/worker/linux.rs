use super::{CleanupFault, WORKER_CONTROL_ENV, WorkerChannels, WorkerCommand};
#[cfg(feature = "native-test-hooks")]
use crate::native_test_hooks::{self as hooks, Action, Stage};
use crate::{PlatformError, ProcessIdentity};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
#[path = "exec_linux.rs"]
mod exec_linux;

/// One CLOEXEC pipe: `(read end, write end)`.
fn pipe() -> Result<(OwnedFd, OwnedFd), PlatformError> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two new descriptors into the array on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(PlatformError::Io);
    }
    // SAFETY: successful pipe2 transfers both unique descriptors to us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub(super) struct Worker {
    guardian: Option<Child>,
    lifeline: Option<ChildStdin>,
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
        let helper = command.guardian.ok_or(PlatformError::InvalidPath)?;
        if !helper.is_absolute() || !helper.is_file() {
            return Err(PlatformError::InvalidPath);
        }
        let mut launch = Command::new(helper);
        let mut environment = command.environment;
        // The guardian receives the worker's pipe ends at 3, 4 and 5 and gives
        // the worker commands at 3, reports at 4 and diagnostics as stdout/stderr.
        environment.push((WORKER_CONTROL_ENV.into(), "3:4".into()));
        let (worker_commands, to_worker) = pipe()?;
        let (from_worker, worker_reports) = pipe()?;
        let (diagnostics, worker_diagnostics) = pipe()?;
        launch
            .arg(&command.executable)
            .args(&command.args)
            .env_clear()
            .envs(environment.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        exec_linux::map_descriptors(
            &mut launch,
            [
                worker_commands.as_raw_fd(),
                worker_reports.as_raw_fd(),
                worker_diagnostics.as_raw_fd(),
            ],
            3,
        );
        exec_linux::configure(&mut launch, environment, 6)
            .map_err(|_| PlatformError::InvalidPath)?;
        #[cfg(feature = "native-test-hooks")]
        hooks::hit(Stage::GuardianSpawn, None, None)?;
        let spawned = launch.spawn();
        // The guardian (if any) holds its copies; ours close now so worker exit
        // is observable as end-of-file on the engine ends.
        drop((worker_commands, worker_reports, worker_diagnostics));
        let mut guardian = spawned.map_err(|_| PlatformError::Io)?;
        let lifeline = guardian.stdin.take();
        let output = guardian.stdout.take().ok_or(PlatformError::Io)?;
        let (send, reports) = mpsc::sync_channel(2);
        std::thread::spawn(move || {
            // Three ownership handoffs, READY and CLEAN; never worker output.
            let mut reader = BufReader::new(output);
            for _ in 0..5 {
                let mut line = Vec::new();
                use std::io::Read;
                if reader
                    .by_ref()
                    .take(256)
                    .read_until(b'\n', &mut line)
                    .is_err()
                    || line.last() != Some(&b'\n')
                {
                    break;
                }
                if send
                    .send(String::from_utf8_lossy(&line).trim().to_owned())
                    .is_err()
                {
                    break;
                }
            }
        });
        let mut worker = Self {
            guardian: Some(guardian),
            lifeline,
            reports,
        };
        let pid = worker.guardian.as_ref().ok_or(PlatformError::Io)?.id();
        let guardian = ProcessIdentity {
            pid,
            start_marker: crate::process::process_start_marker(pid)?,
        };
        #[cfg(feature = "native-test-hooks")]
        if hooks::hit(Stage::GuardianSpawned, None, Some(guardian.clone()))? == Action::KillGuardian
        {
            worker
                .guardian
                .as_mut()
                .ok_or(PlatformError::Io)?
                .kill()
                .map_err(|_| PlatformError::Io)?;
            return Err(PlatformError::LaunchRestricted);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut handoff = 0;
        let ready = loop {
            let line = worker
                .reports
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| PlatformError::Io)?;
            if line.starts_with("OWNERSHIP ") {
                use std::io::Write;
                let fields: Vec<_> = line.split_whitespace().collect();
                let process = match (handoff, fields.as_slice()) {
                    (0, ["OWNERSHIP", "before_worker"]) => None,
                    (1, ["OWNERSHIP", "before_exec", pid, marker])
                    | (2, ["OWNERSHIP", "created", pid, marker]) => Some(ProcessIdentity {
                        pid: pid.parse().map_err(|_| PlatformError::Io)?,
                        start_marker: (*marker).to_owned(),
                    }),
                    _ => return Err(PlatformError::Io),
                };
                if let Some(identity) = &process
                    && !crate::process_matches(identity)?
                {
                    return Err(PlatformError::Io);
                }
                #[cfg(feature = "native-test-hooks")]
                if hooks::hit(
                    match handoff {
                        0 => Stage::GuardianBeforeWorker,
                        1 => Stage::GuardianBeforeExec,
                        _ => Stage::GuardianWorkerCreated,
                    },
                    process,
                    Some(guardian.clone()),
                )? == Action::KillGuardian
                {
                    worker
                        .guardian
                        .as_mut()
                        .ok_or(PlatformError::Io)?
                        .kill()
                        .map_err(|_| PlatformError::Io)?;
                    return Err(PlatformError::LaunchRestricted);
                }
                // The same owner permission is required in normal builds. EOF,
                // rejection or owner death prevents permission at the exec gate.
                worker
                    .lifeline
                    .as_mut()
                    .ok_or(PlatformError::Io)?
                    .write_all(&[1])
                    .map_err(|_| PlatformError::Io)?;
                handoff += 1;
                continue;
            }
            break line;
        };
        let fields: Vec<_> = ready.split_whitespace().collect();
        if handoff != 3 || fields.len() != 3 || fields[0] != "READY" {
            return Err(PlatformError::Io);
        }
        let pid = fields[1].parse().map_err(|_| PlatformError::Io)?;
        let identity = ProcessIdentity {
            pid,
            start_marker: fields[2].to_owned(),
        };
        if worker
            .guardian
            .as_mut()
            .ok_or(PlatformError::Io)?
            .try_wait()
            .map_err(|_| PlatformError::Io)?
            .is_some()
        {
            return Err(PlatformError::Io);
        }
        // The guardian owns an unreaped leader and does not trust a caller PID.
        if !crate::process_matches(&identity)? {
            return Err(PlatformError::Io);
        }
        let channels = WorkerChannels {
            to_worker: File::from(to_worker),
            from_worker: File::from(from_worker),
            diagnostics: File::from(diagnostics),
        };
        Ok((worker, identity, Some(guardian), channels))
    }

    pub(super) fn terminate(&mut self, deadline: Instant) -> Result<(), CleanupFault> {
        self.lifeline.take();
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.reports.recv_timeout(remaining) {
            Ok(line) if line == "CLEAN" => {
                // CLEAN is sent only after the guardian has reaped every child.
                Ok(())
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => Err(CleanupFault::OwnershipLost),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CleanupFault::Deadline),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.lifeline.take();
        // Do not kill the guardian: it must outlive engine ownership to clean up.
        if let Some(mut guardian) = self.guardian.take() {
            std::thread::spawn(move || {
                let _ = guardian.wait();
            });
        }
    }
}
