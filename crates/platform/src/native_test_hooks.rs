//! Explicit developer-only launch controls. Never compiled into normal builds.
use crate::ProcessIdentity;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    WindowsAttributes,
    WindowsJobList,
    WindowsCreate,
    WindowsCreated,
    WindowsResume,
    WindowsAttributeRejected,
    WindowsCreateRejected,
    WindowsResumeRejected,
    GuardianSpawn,
    GuardianSpawned,
    GuardianBeforeWorker,
    GuardianBeforeExec,
    GuardianWorkerCreated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Continue,
    FailAttribute,
    FailAssignment,
    FailResume,
    KillGuardian,
    Abort,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub stage: Stage,
    pub process: Option<ProcessIdentity>,
    pub guardian: Option<ProcessIdentity>,
    pub native_error: Option<u32>,
}

type Hook = fn(Event) -> Action;
thread_local! { static HOOK: Cell<Option<Hook>> = const { Cell::new(None) }; }

pub fn with_hook<T>(hook: Hook, operation: impl FnOnce() -> T) -> T {
    struct Restore(Option<Hook>);
    impl Drop for Restore {
        fn drop(&mut self) {
            HOOK.set(self.0);
        }
    }
    let restore = Restore(HOOK.replace(Some(hook)));
    let result = operation();
    drop(restore);
    result
}

#[cfg(any(windows, target_os = "linux"))]
pub(crate) fn hit(
    stage: Stage,
    process: Option<ProcessIdentity>,
    guardian: Option<ProcessIdentity>,
) -> Result<Action, crate::PlatformError> {
    let action = HOOK.get().map_or(Action::Continue, |hook| {
        hook(Event {
            stage,
            process,
            guardian,
            native_error: None,
        })
    });
    if action == Action::Abort {
        Err(crate::PlatformError::LaunchRestricted)
    } else {
        Ok(action)
    }
}

#[cfg(windows)]
pub(crate) fn native_failure(stage: Stage, error: u32) {
    if let Some(hook) = HOOK.get() {
        hook(Event {
            stage,
            process: None,
            guardian: None,
            native_error: Some(error),
        });
    }
}
