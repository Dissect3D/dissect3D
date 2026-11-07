//! Submission certainty belongs to the client operation, not a transport task.

use dissect3d_api::{AcceptanceReceipt, SubmissionId};
use std::cell::RefCell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

enum SubmissionSendState {
    NotSent,
    MayHaveBeenSent,
    Rejected,
    Accepted(Box<AcceptanceReceipt>),
}

pub(super) struct SubmissionControl {
    interrupted: Arc<AtomicBool>,
    state: RefCell<SubmissionSendState>,
    local_id: RefCell<Option<SubmissionId>>,
    signal_task: Option<tokio::task::JoinHandle<()>>,
}

impl SubmissionControl {
    pub(super) fn new(
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(Self, tokio::sync::oneshot::Receiver<()>), super::super::CommandError> {
        let _entered = runtime.enter();
        #[cfg(unix)]
        let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt());
        #[cfg(windows)]
        let signal = tokio::signal::windows::ctrl_c();
        let mut signal = signal.map_err(|_| {
            super::failure(
                "local_signal_unavailable",
                "Could not install submission interruption handling",
                2,
                Some(false),
                None,
            )
        })?;
        let interrupted = Arc::new(AtomicBool::new(false));
        let flag = interrupted.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let signal_task = runtime.spawn(async move {
            signal.recv().await;
            flag.store(true, Ordering::Release);
            let _ = tx.send(());
        });
        Ok((
            Self {
                interrupted,
                state: RefCell::new(SubmissionSendState::NotSent),
                local_id: RefCell::new(None),
                signal_task: Some(signal_task),
            },
            rx,
        ))
    }

    pub(super) async fn run(
        &self,
        mut signal: tokio::sync::oneshot::Receiver<()>,
        work: impl std::future::Future<Output = Result<serde_json::Value, super::super::CommandError>>,
    ) -> Result<serde_json::Value, super::super::CommandError> {
        tokio::task::yield_now().await;
        let result =
            tokio::select! {biased;result=work=>result,_=&mut signal=>self.interrupt_outcome()};
        result.map_err(|error| self.preserve_known(error))
    }

    pub(super) fn local_id(&self, id: SubmissionId) {
        *self.local_id.borrow_mut() = Some(id);
    }
    pub(super) fn accepted(&self, receipt: AcceptanceReceipt) {
        *self.state.borrow_mut() = SubmissionSendState::Accepted(Box::new(receipt));
    }
    pub(super) fn rejected(&self) {
        if !matches!(*self.state.borrow(), SubmissionSendState::Accepted(_)) {
            *self.state.borrow_mut() = SubmissionSendState::Rejected;
        }
    }
    pub(super) fn begin_send(&self) -> bool {
        if self.interrupted.load(Ordering::Acquire) {
            return false;
        }
        if !matches!(*self.state.borrow(), SubmissionSendState::Accepted(_)) {
            *self.state.borrow_mut() = SubmissionSendState::MayHaveBeenSent;
        }
        true
    }
    pub(super) async fn checkpoint(&self) -> Result<(), super::super::CommandError> {
        tokio::task::yield_now().await;
        if self.interrupted.load(Ordering::Acquire) {
            return Err(super::failure(
                "interrupted_not_submitted",
                "Interrupted before submitting a job",
                18,
                Some(false),
                self.recovery_data(),
            ));
        }
        Ok(())
    }
    fn recovery_data(&self) -> Option<serde_json::Value> {
        self.local_id
            .borrow()
            .as_ref()
            .map(|id| serde_json::json!({"sub_id":id}))
    }
    fn accepted_data(&self) -> Option<serde_json::Value> {
        match &*self.state.borrow() {
            SubmissionSendState::Accepted(receipt) => Some(
                serde_json::json!({"accepted":true,"job_id":receipt.job_id,"sub_id":*self.local_id.borrow(),"replayed":receipt.replayed}),
            ),
            _ => None,
        }
    }
    pub(super) fn interrupt_outcome(
        &self,
    ) -> Result<serde_json::Value, super::super::CommandError> {
        if let Some(data) = self.accepted_data() {
            return Ok(data);
        }
        let (category, message, exit, accepted) = match *self.state.borrow() {
            SubmissionSendState::MayHaveBeenSent => (
                "submission_uncertain",
                "Interrupted after submission may have reached the engine; use explicit jobs recover",
                15,
                None,
            ),
            SubmissionSendState::Rejected => (
                "submission_rejected",
                "The engine rejected this submission before interruption",
                19,
                Some(false),
            ),
            _ => (
                "interrupted_not_submitted",
                "Interrupted before submitting a job",
                18,
                Some(false),
            ),
        };
        Err(super::failure(
            category,
            message,
            exit,
            accepted,
            self.recovery_data(),
        ))
    }
    fn preserve_known(&self, mut error: super::super::CommandError) -> super::super::CommandError {
        if let Some(data) = self.accepted_data() {
            if error.category == "submission_uncertain" {
                error.category = "recovery_confirmation_failed";
                error.message =
                    "Job acceptance is known; the confirmation response was unavailable";
            }
            error.exit_code = 19;
            let context = error.context.get_or_insert_with(Default::default);
            context.accepted = Some(serde_json::Value::Bool(true));
            context.data = Some(data);
        }
        error
    }
}

impl Drop for SubmissionControl {
    fn drop(&mut self) {
        if let Some(task) = self.signal_task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn control() -> SubmissionControl {
        SubmissionControl {
            interrupted: Arc::new(AtomicBool::new(false)),
            state: RefCell::new(SubmissionSendState::NotSent),
            local_id: RefCell::new(None),
            signal_task: None,
        }
    }
    #[test]
    fn interruption_preserves_distinct_send_certainty_and_known_acceptance() {
        let c = control();
        assert_eq!(c.interrupt_outcome().err().unwrap().exit_code, 18);
        assert!(c.begin_send());
        assert_eq!(c.interrupt_outcome().err().unwrap().exit_code, 15);
        c.rejected();
        assert_eq!(c.interrupt_outcome().err().unwrap().exit_code, 19);
        let receipt: AcceptanceReceipt = dissect3d_api::decode_submission_json(
            include_bytes!("../../../tests/fixtures/illustrative-acceptance.json"),
            262_144,
        )
        .unwrap();
        c.accepted(receipt);
        c.interrupted.store(true, Ordering::Release);
        assert!(!c.begin_send());
        assert!(c.interrupt_outcome().is_ok());
        c.rejected();
        assert!(
            c.interrupt_outcome().is_ok(),
            "known acceptance cannot be demoted by later events"
        );
    }
}
