//! The native `WorkerLauncher` (WE-P04, WC-001/WC-003): one contained worker
//! process per attempt through `dissect3d_platform::WorkerProcess`, with its
//! inherited private control pipes and separate diagnostics pipe.
//!
//! The launch environment is exactly the verified command's finite list plus
//! the supervisor-created session identity; the platform adds the control
//! endpoint variable. No ambient environment, public credential or database
//! authority reaches the worker. Inactive until WE-P06 composes it.
use super::legality::SessionIdentity;
use super::supervisor::{LaunchFailure, Launched, SupervisedProcess, WorkerLauncher};
use crate::store::cleanup::CleanupEvidence;
use dissect3d_platform::{CleanupFault, PlatformError, WorkerCommand, WorkerProcess};
use std::time::Instant;

/// Carries the supervisor-created session ID for the worker's `hello`. It is
/// an engine-private correlation ID, not a credential.
pub(crate) const WORKER_SESSION_ENV: &str = "DISSECT3D_WORKER_SESSION";

/// Launches one verified `WorkerCommand` (WE-P05 supplies it from prepared
/// support; never a shell or a public parameter).
pub(crate) struct PlatformLauncher {
    command: WorkerCommand,
}
impl PlatformLauncher {
    pub(crate) fn new(command: WorkerCommand) -> Self {
        Self { command }
    }
}

/// The contained native tree. Only the platform's `CleanupConfirmed` witness
/// becomes `CleanupEvidence`; dropping this is the platform's kill-on-close or
/// lifeline fallback, never evidence.
pub(crate) struct PlatformProcess(WorkerProcess);
impl SupervisedProcess for PlatformProcess {
    fn terminate_tree(&mut self, deadline: Instant) -> Result<CleanupEvidence, CleanupFault> {
        self.0
            .terminate_tree(deadline)
            .map(CleanupEvidence::from_witness)
    }
}

/// The platform nonce binds the native identity and witness to this session:
/// the 32 hex digits of `ses_<hex>` as 16 bytes.
fn session_nonce(session_id: &str) -> Option<[u8; 16]> {
    let hex = session_id.strip_prefix("ses_")?.as_bytes();
    if hex.len() != 32 {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut nonce = [0u8; 16];
    let (pairs, _) = hex.as_chunks::<2>();
    for (byte, [high, low]) in nonce.iter_mut().zip(pairs) {
        *byte = (digit(*high)? << 4) | digit(*low)?;
    }
    Some(nonce)
}

impl WorkerLauncher for PlatformLauncher {
    type Process = PlatformProcess;
    type Reader = tokio::fs::File;
    type Writer = tokio::fs::File;
    type Diagnostics = tokio::fs::File;

    fn launch(
        mut self,
        session: &SessionIdentity,
    ) -> Result<
        Launched<PlatformProcess, tokio::fs::File, tokio::fs::File, tokio::fs::File>,
        LaunchFailure,
    > {
        let nonce = session_nonce(&session.session_id).ok_or(LaunchFailure::NotStarted)?;
        if self
            .command
            .environment
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case(WORKER_SESSION_ENV))
        {
            return Err(LaunchFailure::NotStarted);
        }
        self.command
            .environment
            .push((WORKER_SESSION_ENV.into(), session.session_id.clone().into()));
        let mut process =
            WorkerProcess::launch(self.command, nonce).map_err(|error| match error {
                // Command validation precedes any native process creation.
                PlatformError::InvalidPath => LaunchFailure::NotStarted,
                // Anything later may have created a process without established
                // ownership; the platform's drop fallback runs, holds stay.
                _ => LaunchFailure::Uncertain,
            })?;
        let channels = process.take_channels().ok_or(LaunchFailure::Uncertain)?;
        Ok(Launched {
            process: PlatformProcess(process),
            control_from_worker: tokio::fs::File::from_std(channels.from_worker),
            control_to_worker: tokio::fs::File::from_std(channels.to_worker),
            diagnostics: tokio::fs::File::from_std(channels.diagnostics),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::session_nonce;

    #[test]
    fn session_nonce_is_the_exact_session_digits() {
        let id = format!("ses_{}", "0123456789abcdef".repeat(2));
        let nonce = session_nonce(&id).unwrap();
        assert_eq!(nonce[0], 0x01);
        assert_eq!(nonce[7], 0xef);
        assert_eq!(nonce[15], 0xef);
        for bad in [
            "ses_0123".to_owned(),
            format!("att_{}", "0".repeat(32)),
            format!("ses_{}", "A".repeat(32)),
            format!("ses_{}", "0".repeat(33)),
        ] {
            assert!(session_nonce(&bad).is_none(), "{bad}");
        }
    }
}
