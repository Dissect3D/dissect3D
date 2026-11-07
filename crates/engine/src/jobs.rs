//! Engine-owned private job inspection. Polling reads retained snapshots only.

use crate::{AuthContext, Store, submission::SubmissionError};
use dissect3d_api::{ErrorCode, JobId, JobPage, JobSnapshot, JobsQuery};
use dissect3d_platform::{OwnedRoot, RelativePath};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) struct JobsService {
    store: Arc<Store>,
    root: Arc<OwnedRoot>,
    reconciled: AtomicBool,
}

impl JobsService {
    pub(crate) fn new(store: Arc<Store>, root: Arc<OwnedRoot>) -> Self {
        Self {
            store,
            root,
            reconciled: AtomicBool::new(false),
        }
    }
    pub(crate) fn is_reconciled(&self) -> bool {
        self.reconciled.load(Ordering::Acquire)
    }
    pub(crate) async fn show(
        &self,
        auth: AuthContext,
        id: JobId,
    ) -> Result<JobSnapshot, SubmissionError> {
        let store = self.store.clone();
        let snapshot = tokio::task::spawn_blocking(move || store.show_job(auth, id))
            .await
            .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))??;
        if !self.is_reconciled()
            && snapshot.storage_status == dissect3d_api::StorageStatus::Verified
        {
            return Err(ErrorCode::StorageUnavailable.into());
        }
        Ok(snapshot)
    }
    pub(crate) async fn list(
        &self,
        auth: AuthContext,
        query: JobsQuery,
    ) -> Result<JobPage, SubmissionError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.list_jobs(auth, query))
            .await
            .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?
    }

    pub(crate) async fn run_recovery(
        self: Arc<Self>,
        mut stop: tokio::sync::oneshot::Receiver<()>,
    ) {
        loop {
            let result = tokio::select! {_=&mut stop=>return,result=self.audit()=>result};
            if result.is_ok() {
                self.reconciled.store(true, Ordering::Release);
                let _ = stop.await;
                return;
            }
            let root = self.root.clone();
            let _ = tokio::task::spawn_blocking(move || {
                crate::diagnostics::record_job_recovery_failure(&root)
            })
            .await;
            tokio::select! {_=&mut stop=>return,_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
        }
    }

    async fn audit(&self) -> Result<(), SubmissionError> {
        let mut after = String::new();
        loop {
            let store = self.store.clone();
            let cursor = after.clone();
            let entries = tokio::task::spawn_blocking(move || store.job_audit_batch(cursor))
                .await
                .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))??;
            if entries.is_empty() {
                return Ok(());
            }
            after = entries.last().unwrap().id.as_str().to_owned();
            let mut entries = entries.into_iter();
            let a = entries.next().unwrap();
            let b = entries.next();
            let (first, second) = tokio::join!(verify_input(self.root.clone(), a), async {
                match b {
                    Some(entry) => Some(verify_input(self.root.clone(), entry).await),
                    None => None,
                }
            });
            for (id, valid) in std::iter::once(first).chain(second) {
                if !valid {
                    let store = self.store.clone();
                    tokio::task::spawn_blocking(move || store.mark_job_input_fault(id))
                        .await
                        .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))??;
                }
            }
        }
    }
}

async fn verify_input(
    root: Arc<OwnedRoot>,
    entry: crate::store::jobs::AuditEntry,
) -> (dissect3d_api::InputId, bool) {
    let id = entry.id;
    let Some(identity) = entry.identity else {
        return (id, false);
    };
    let path = RelativePath::parse(format!("inputs/data/{}.bin", id.as_str())).unwrap();
    let opened = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        crate::submission::test_support::for_root(root.path()).audit();
        root.open_immutable_input(&path)
    })
    .await;
    let Ok(Ok(reader)) = opened else {
        return (id, false);
    };
    let mut state = (reader, Sha256::new(), 0u64);
    loop {
        let turn = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
            let (mut reader, mut hasher, mut bytes) = state;
            let mut buffer = [0u8; 65_536];
            let mut done = false;
            for _ in 0..16 {
                let length = reader.read(&mut buffer)?;
                if length == 0 {
                    done = true;
                    break;
                }
                bytes = bytes
                    .checked_add(length as u64)
                    .ok_or_else(|| std::io::Error::other("input size overflow"))?;
                hasher.update(&buffer[..length]);
            }
            Ok((reader, hasher, bytes, done))
        })
        .await;
        let Ok(Ok((reader, hasher, bytes, done))) = turn else {
            return (id, false);
        };
        if bytes > identity.byte_length {
            return (id, false);
        }
        if done {
            let digest = hasher.finalize();
            let expected = identity.sha256.as_str();
            let actual = digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            return (id, bytes == identity.byte_length && actual == expected);
        }
        state = (reader, hasher, bytes);
        tokio::task::yield_now().await;
    }
}
