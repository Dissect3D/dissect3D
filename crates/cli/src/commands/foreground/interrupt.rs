//! Two-stage interrupt state machine for foreground `run` (`WE-P08.5`, `CR-CS-03`).

use dissect3d_api::JobId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForegroundPhase {
    BeforeSend,
    InFlight { cancel_pending: bool },
    Accepted(JobId),
    CancelRequested(JobId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InterruptAction {
    StopNotSent,
    AckAndKeepWaiting,
    SendCancel(JobId),
    ExitUncertain,
    ExitDetached,
}

pub(crate) struct InterruptStateMachine {
    phase: ForegroundPhase,
    cancel_sent: bool,
}

impl InterruptStateMachine {
    pub(crate) fn new() -> Self {
        Self {
            phase: ForegroundPhase::BeforeSend,
            cancel_sent: false,
        }
    }

    pub(crate) fn enter_in_flight(&mut self) {
        self.phase = ForegroundPhase::InFlight {
            cancel_pending: false,
        };
    }

    pub(crate) fn on_accepted(&mut self, job_id: JobId) -> Option<InterruptAction> {
        match &self.phase {
            ForegroundPhase::InFlight {
                cancel_pending: true,
            } if !self.cancel_sent => {
                self.phase = ForegroundPhase::CancelRequested(job_id.clone());
                self.cancel_sent = true;
                Some(InterruptAction::SendCancel(job_id))
            }
            _ => {
                self.phase = ForegroundPhase::Accepted(job_id);
                None
            }
        }
    }

    pub(crate) fn on_interrupt(&mut self) -> InterruptAction {
        match &self.phase {
            ForegroundPhase::BeforeSend => InterruptAction::StopNotSent,
            ForegroundPhase::InFlight {
                cancel_pending: false,
            } => {
                self.phase = ForegroundPhase::InFlight {
                    cancel_pending: true,
                };
                InterruptAction::AckAndKeepWaiting
            }
            ForegroundPhase::InFlight {
                cancel_pending: true,
            } => InterruptAction::ExitUncertain,
            ForegroundPhase::Accepted(job_id) => {
                let id = job_id.clone();
                self.phase = ForegroundPhase::CancelRequested(id.clone());
                self.cancel_sent = true;
                InterruptAction::SendCancel(id)
            }
            ForegroundPhase::CancelRequested(_) => InterruptAction::ExitDetached,
        }
    }
}

#[cfg(test)]
#[path = "interrupt_tests.rs"]
mod tests;
