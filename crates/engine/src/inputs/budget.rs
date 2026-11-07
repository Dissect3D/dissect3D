//! One monotonic capture deadline and ownership of non-cancellable native work.

use super::InputError;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, timeout_at};

#[derive(Clone)]
pub(super) struct UploadBudget {
    pub(super) deadline: Instant,
    permit: Arc<OwnedSemaphorePermit>,
}

impl UploadBudget {
    pub(super) fn new(deadline: Instant, permit: OwnedSemaphorePermit) -> Self {
        Self {
            deadline,
            permit: Arc::new(permit),
        }
    }

    pub(super) fn check(&self) -> Result<(), InputError> {
        if Instant::now() >= self.deadline {
            Err(InputError::Transfer)
        } else {
            Ok(())
        }
    }

    pub(super) fn for_cleanup(&self) -> Self {
        Self {
            deadline: self.deadline + super::policy::UPLOAD_CLEANUP_GRACE,
            permit: self.permit.clone(),
        }
    }

    pub(super) async fn blocking<T, F>(
        &self,
        join_error: InputError,
        work: F,
    ) -> Result<T, InputError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        self.check()?;
        let owner = self.clone();
        let task = tokio::task::spawn_blocking(move || {
            // Queued work must not start a new step after expiry. Once a native
            // call starts it cannot be forcibly cancelled: retain its slot until
            // it returns, independently of the request or JoinHandle lifetime.
            owner.check()?;
            let _permit = owner.permit;
            Ok(work())
        });
        let value = timeout_at(self.deadline, task)
            .await
            .map_err(|_| InputError::Transfer)?
            .map_err(|_| join_error)??;
        // Tokio may poll a ready operation before its timer. A late completion
        // must never become a usable receipt, even when both are ready.
        self.check()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::sync::Semaphore;

    #[test]
    fn queued_native_work_keeps_its_slot_and_never_starts_after_expiry() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (entered, started) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let blocker = runtime.spawn_blocking(move || {
            entered.send(()).unwrap();
            let _ = resume.recv_timeout(Duration::from_secs(5));
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        runtime.block_on(async {
            let slots = Arc::new(Semaphore::new(1));
            let budget = UploadBudget::new(
                Instant::now() + Duration::from_millis(25),
                slots.clone().try_acquire_owned().unwrap(),
            );
            let ran = Arc::new(AtomicBool::new(false));
            let work = ran.clone();
            let result = budget
                .blocking(InputError::Storage, move || {
                    work.store(true, Ordering::Release)
                })
                .await;
            assert_eq!(result, Err(InputError::Transfer));
            drop(budget);
            assert_eq!(
                slots.available_permits(),
                0,
                "queued work lost its capacity ownership"
            );
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while slots.available_permits() == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            assert!(
                !ran.load(Ordering::Acquire),
                "expired queued work started a new native step"
            );
        });
    }
}
