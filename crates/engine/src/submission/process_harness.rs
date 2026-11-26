//! Async child processes for the submission harnesses, on `std::process`.
//!
//! These harnesses share one test binary with the real-worker launch tests.
//! tokio's process driver installs a process-wide SIGCHLD handler on macOS,
//! after which the Darwin guardian launch correctly refuses
//! (`LaunchRestricted`). `std::process` reaps its own pid with no handler, so
//! this module mirrors only the tokio API subset the harnesses use.
use std::ffi::OsStr;
use std::io::{self, Read};
use std::process::{ChildStdout, ExitStatus, Output, Stdio};
use std::time::Duration;

/// Exit-polling cadence. It paces an awaited condition and is never a bound.
const POLL: Duration = Duration::from_millis(10);

pub(super) struct Command {
    inner: std::process::Command,
    kill_on_drop: bool,
    stdout_set: bool,
    stderr_set: bool,
}

impl Command {
    pub(super) fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            inner: std::process::Command::new(program),
            kill_on_drop: false,
            stdout_set: false,
            stderr_set: false,
        }
    }

    pub(super) fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.inner.arg(arg);
        self
    }

    pub(super) fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    pub(super) fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.inner.env(key, value);
        self
    }

    pub(super) fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.inner.env_remove(key);
        self
    }

    pub(super) fn stdout(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        self.inner.stdout(stdio);
        self.stdout_set = true;
        self
    }

    pub(super) fn stderr(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        self.inner.stderr(stdio);
        self.stderr_set = true;
        self
    }

    /// SIGKILL and reap the child if its handle is dropped before it is
    /// reaped (for example when a bounding timeout drops the awaiting future).
    pub(super) fn kill_on_drop(&mut self, kill: bool) -> &mut Self {
        self.kill_on_drop = kill;
        self
    }

    pub(super) fn spawn(&mut self) -> io::Result<Child> {
        let mut inner = self.inner.spawn()?;
        Ok(Child {
            stdout: inner.stdout.take(),
            stderr: inner.stderr.take(),
            inner,
            reaped: false,
            kill_on_drop: self.kill_on_drop,
        })
    }

    /// Like tokio: stdout and stderr are captured unless configured, and stdin
    /// is closed.
    pub(super) async fn output(&mut self) -> io::Result<Output> {
        if !self.stdout_set {
            self.inner.stdout(Stdio::piped());
        }
        if !self.stderr_set {
            self.inner.stderr(Stdio::piped());
        }
        self.inner.stdin(Stdio::null());
        self.spawn()?.wait_with_output().await
    }

    pub(super) async fn status(&mut self) -> io::Result<ExitStatus> {
        self.spawn()?.wait().await
    }
}

pub(super) struct Child {
    inner: std::process::Child,
    pub(super) stdout: Option<ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    reaped: bool,
    kill_on_drop: bool,
}

impl Child {
    /// The pid until the child is reaped, as tokio reports it.
    pub(super) fn id(&self) -> Option<u32> {
        (!self.reaped).then(|| self.inner.id())
    }

    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.inner.try_wait()?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    pub(super) async fn wait(&mut self) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// SIGKILL, then reap.
    pub(super) async fn kill(&mut self) -> io::Result<()> {
        if !self.reaped {
            self.inner.kill()?;
            self.wait().await?;
        }
        Ok(())
    }

    /// Reads both captured pipes while awaiting exit, like tokio.
    pub(super) async fn wait_with_output(mut self) -> io::Result<Output> {
        let stdout = self.stdout.take().map(drain);
        let stderr = self.stderr.take().map(drain);
        let status = self.wait().await?;
        Ok(Output {
            status,
            stdout: collect(stdout).await?,
            stderr: collect(stderr).await?,
        })
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.kill_on_drop && !self.reaped {
            let _ = self.inner.kill();
            // The killed child exits promptly; reaping it avoids a zombie.
            let _ = self.inner.wait();
        }
    }
}

fn drain(mut pipe: impl Read + Send + 'static) -> tokio::task::JoinHandle<io::Result<Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).map(|_| bytes)
    })
}

async fn collect(
    reader: Option<tokio::task::JoinHandle<io::Result<Vec<u8>>>>,
) -> io::Result<Vec<u8>> {
    match reader {
        Some(reader) => reader.await.map_err(io::Error::other)?,
        None => Ok(Vec::new()),
    }
}
