//! Private per-root fault latches, compiled only into Rust test binaries.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock, Weak,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

type AsyncPause = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);
type CommitPause = (
    std::sync::mpsc::SyncSender<()>,
    std::sync::mpsc::Receiver<()>,
);

#[derive(Default)]
pub(crate) struct Hooks {
    pub(crate) submit_seen: AtomicUsize,
    pub(crate) drop_before: AtomicBool,
    pub(crate) drop_after: AtomicBool,
    pub(crate) expire_unreferenced: AtomicBool,
    info_countdown: AtomicUsize,
    info: Mutex<Option<AsyncPause>>,
    upload: Mutex<Option<AsyncPause>>,
    commit: Mutex<Option<CommitPause>>,
    transaction_before: Mutex<Option<CommitPause>>,
    transaction_after: Mutex<Option<CommitPause>>,
    failure: Mutex<Option<AsyncPause>>,
    audit: Mutex<Option<CommitPause>>,
    upload_finish: Mutex<Option<CommitPause>>,
    upload_complete: Mutex<Option<CommitPause>>,
}

impl Hooks {
    #[cfg(feature = "test-support")]
    pub(crate) fn pause_upload_finalization(
        &self,
        metadata: bool,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered, receiver) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let boundary = if metadata {
            &self.upload_complete
        } else {
            &self.upload_finish
        };
        *boundary.lock().unwrap() = Some((entered, resume));
        (receiver, release)
    }

    pub(crate) fn upload_finalization(&self, metadata: bool) {
        let boundary = if metadata {
            &self.upload_complete
        } else {
            &self.upload_finish
        };
        let pause = boundary.lock().unwrap().take();
        if let Some((entered, resume)) = pause {
            let _ = entered.send(());
            let _ = resume.recv_timeout(std::time::Duration::from_secs(5));
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause_failure(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered, receiver) = tokio::sync::oneshot::channel();
        let (release, resume) = tokio::sync::oneshot::channel();
        *self.failure.lock().unwrap() = Some((entered, resume));
        (receiver, release)
    }

    pub(crate) async fn failure(&self) {
        let pause = self.failure.lock().unwrap().take();
        if let Some((entered, resume)) = pause {
            let _ = entered.send(());
            let _ = resume.await;
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause_audit(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered, receiver) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        *self.audit.lock().unwrap() = Some((entered, resume));
        (receiver, release)
    }

    pub(crate) fn audit(&self) {
        let pause = self.audit.lock().unwrap().take();
        if let Some((entered, resume)) = pause {
            let _ = entered.send(());
            let _ = resume.recv_timeout(std::time::Duration::from_secs(15));
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause_transaction(
        &self,
        after: bool,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered, receiver) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let boundary = if after {
            &self.transaction_after
        } else {
            &self.transaction_before
        };
        *boundary.lock().unwrap() = Some((entered, resume));
        (receiver, release)
    }

    pub(crate) fn transaction_boundary(&self, after: bool) -> bool {
        let boundary = if after {
            &self.transaction_after
        } else {
            &self.transaction_before
        };
        let pause = boundary.lock().unwrap().take();
        if let Some((entered, resume)) = pause {
            let _ = entered.send(());
            return resume
                .recv_timeout(std::time::Duration::from_secs(60))
                .is_ok();
        }
        true
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn pause_info(
        &self,
        count: usize,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (release, resume) = tokio::sync::oneshot::channel();
        *self.info.lock().unwrap() = Some((tx, resume));
        self.info_countdown.store(count, Ordering::Release);
        (rx, release)
    }
    #[cfg(feature = "test-support")]
    pub(crate) fn pause_upload(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (release, resume) = tokio::sync::oneshot::channel();
        *self.upload.lock().unwrap() = Some((tx, resume));
        (rx, release)
    }
    #[cfg(feature = "test-support")]
    pub(crate) fn pause_commit(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        *self.commit.lock().unwrap() = Some((tx, resume));
        (rx, release)
    }
    pub(crate) async fn info(&self) {
        if self
            .info_countdown
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_sub(1)
            })
            == Ok(1)
        {
            let pause = { self.info.lock().unwrap().take() };
            if let Some((entered, resume)) = pause {
                let _ = entered.send(());
                let _ = resume.await;
            }
        }
    }
    pub(crate) async fn upload(&self) {
        let pause = { self.upload.lock().unwrap().take() };
        if let Some((entered, resume)) = pause {
            let _ = entered.send(());
            let _ = resume.await;
        }
    }
    pub(crate) fn before_commit(&self) -> bool {
        let pause = { self.commit.lock().unwrap().take() };
        if let Some((entered, resume)) = pause {
            let _ = entered.send(());
            return resume
                .recv_timeout(std::time::Duration::from_secs(15))
                .is_ok();
        }
        true
    }
}

static ROOTS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Hooks>>>> = OnceLock::new();

#[cfg(feature = "test-support")]
pub(crate) fn register(path: &Path, hooks: &Arc<Hooks>) {
    let mut roots = ROOTS.get_or_init(Default::default).lock().unwrap();
    roots.retain(|_, hooks| hooks.strong_count() != 0);
    roots.insert(path.to_owned(), Arc::downgrade(hooks));
}

pub(crate) fn for_root(path: &Path) -> Arc<Hooks> {
    ROOTS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get(path)
        .and_then(Weak::upgrade)
        .unwrap_or_default()
}
