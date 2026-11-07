//! Engine-owned input capture, publication and conservative recovery.
//! Transport framing stops at HTTP; this service consumes a bounded byte stream.

mod budget;
#[cfg(all(test, feature = "test-support"))]
mod capture_deadline_tests;
pub(crate) mod policy;
pub(crate) mod recovery;

use crate::store::{DurableInput, UploadReservation};
use crate::{AuthContext, CoreError, Store};
use budget::UploadBudget;
use dissect3d_api::InputReceipt;
use dissect3d_platform::{OwnedRoot, PlatformError, PrivateInputWriter, RelativePath};
use futures_util::{Stream, StreamExt};
use policy::{MAX_CHUNK_BYTES, MAX_UPLOADS, UPLOAD_IDLE_TIMEOUT, UPLOAD_TOTAL_TIMEOUT};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputError {
    Transfer,
    Storage,
    Capacity(&'static str),
    Store(CoreError),
}

pub(crate) struct InputService {
    store: Arc<Store>,
    root: Arc<OwnedRoot>,
    uploads: Arc<Semaphore>,
    reconciled: std::sync::atomic::AtomicBool,
}

impl InputService {
    pub(crate) fn new(store: Arc<Store>, root: Arc<OwnedRoot>) -> Self {
        Self {
            store,
            root,
            uploads: Arc::new(Semaphore::new(MAX_UPLOADS as usize)),
            reconciled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn is_reconciled(&self) -> bool {
        self.reconciled.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) async fn capture<S, B, E>(
        &self,
        context: AuthContext,
        length: u64,
        media_type: String,
        body: S,
    ) -> Result<InputReceipt, InputError>
    where
        S: Stream<Item = Result<B, E>> + Unpin,
        B: AsRef<[u8]>,
    {
        self.capture_until(
            context,
            length,
            media_type,
            body,
            tokio::time::Instant::now() + UPLOAD_TOTAL_TIMEOUT,
        )
        .await
    }

    async fn capture_until<S, B, E>(
        &self,
        context: AuthContext,
        length: u64,
        media_type: String,
        body: S,
        deadline: tokio::time::Instant,
    ) -> Result<InputReceipt, InputError>
    where
        S: Stream<Item = Result<B, E>> + Unpin,
        B: AsRef<[u8]>,
    {
        let permit = self
            .uploads
            .clone()
            .try_acquire_owned()
            .map_err(|_| InputError::Capacity("upload_concurrency_max"))?;
        let budget = UploadBudget::new(deadline, permit);
        budget.check()?;
        let result = tokio::time::timeout_at(
            deadline + policy::UPLOAD_CLEANUP_GRACE,
            self.capture_in_budget(context, length, media_type, body, &budget),
        )
        .await
        .map_err(|_| InputError::Transfer)?;
        budget.check()?;
        result
    }

    async fn capture_in_budget<S, B, E>(
        &self,
        context: AuthContext,
        length: u64,
        media_type: String,
        body: S,
        budget: &UploadBudget,
    ) -> Result<InputReceipt, InputError>
    where
        S: Stream<Item = Result<B, E>> + Unpin,
        B: AsRef<[u8]>,
    {
        let root = self.root.clone();
        let available = budget
            .blocking(InputError::Storage, move || root.available_space_bytes())
            .await?
            .map_err(|_| InputError::Storage)?;
        let store = self.store.clone();
        let auth = context.clone();
        let reservation = budget
            .blocking(InputError::Store(CoreError::StoreUnavailable), move || {
                store.reserve_upload(auth, length, media_type, available)
            })
            .await?
            .map_err(InputError::Store)?;
        let staged = stage_path(&reservation);
        let published = final_path(&reservation);
        let root = self.root.clone();
        let path = staged.clone();
        let lease = reservation.lease.clone();
        let writer = match budget
            .blocking(InputError::Storage, move || {
                let _lease = lease;
                root.begin_input(&path)
            })
            .await
        {
            Ok(Ok(writer)) => writer,
            Err(InputError::Transfer) => return Err(InputError::Transfer),
            _ => {
                self.cleanup_incomplete(&reservation, &staged, budget).await;
                return Err(InputError::Storage);
            }
        };
        let (writer, digest) = match stream_to_file_in_budget(
            body,
            writer,
            length,
            budget,
            reservation.lease.clone(),
            PrivateInputWriter::write_chunk,
        )
        .await
        {
            Ok(value) => value,
            Err((error, writer)) => {
                // A timed-out blocking write still owns the file and lease.
                // Only a returned writer establishes that direct removal is safe.
                if let Some(writer) = writer {
                    drop(writer);
                    self.cleanup_incomplete(&reservation, &staged, budget).await;
                }
                return Err(error);
            }
        };
        let lease = reservation.lease.clone();
        #[cfg(test)]
        let hooks = crate::submission::test_support::for_root(self.root.path());
        // A failed or timed-out barrier leaves the reservation and file evidence
        // for recovery. Native work keeps both its slot and reservation lease.
        let durable = budget
            .blocking(InputError::Storage, move || {
                let _lease = lease;
                #[cfg(test)]
                hooks.upload_finalization(false);
                writer.finish(&published)
            })
            .await?
            .map_err(|_| InputError::Storage)?;
        let store = self.store.clone();
        #[cfg(test)]
        let hooks = crate::submission::test_support::for_root(self.root.path());
        budget
            .blocking(InputError::Store(CoreError::StoreUnavailable), move || {
                #[cfg(test)]
                hooks.upload_finalization(true);
                store.complete_upload(
                    context,
                    reservation,
                    DurableInput {
                        file: durable,
                        sha256: digest,
                    },
                )
            })
            .await?
            .map_err(InputError::Store)
    }

    async fn cleanup_incomplete(
        &self,
        reservation: &UploadReservation,
        staged: &RelativePath,
        budget: &UploadBudget,
    ) {
        // Failure cleanup may use the pre-existing two-second request slack.
        // Success/publication/metadata waits always use the original deadline.
        let budget = budget.for_cleanup();
        let root = self.root.clone();
        let path = staged.clone();
        let lease = reservation.lease.clone();
        let result = budget
            .blocking(InputError::Storage, move || {
                let _lease = lease;
                root.remove_durable(&path)
            })
            .await;
        let code = match result {
            Err(InputError::Transfer) => return,
            Ok(Ok(()) | Err(PlatformError::NotFound)) => {
                let store = self.store.clone();
                let id = reservation.reservation_id.clone();
                match budget
                    .blocking(InputError::Store(CoreError::StoreUnavailable), move || {
                        store.abandon_upload(id)
                    })
                    .await
                {
                    Ok(Ok(())) | Err(InputError::Transfer) => return,
                    _ => "store_unavailable",
                }
            }
            _ => "storage_unavailable",
        };
        let root = self.root.clone();
        let _ = budget
            .blocking(InputError::Storage, move || {
                crate::diagnostics::record_input_recovery_failure(&root, code)
            })
            .await;
    }

    async fn record_recovery_failure(&self, code: &'static str) {
        let root = self.root.clone();
        let _ = tokio::task::spawn_blocking(move || {
            crate::diagnostics::record_input_recovery_failure(&root, code)
        })
        .await;
    }
}

#[cfg(test)]
async fn stream_to_file<S, B, E>(
    body: S,
    writer: PrivateInputWriter,
    declared_length: u64,
    total_deadline: tokio::time::Instant,
    reservation_lease: Arc<()>,
) -> Result<(PrivateInputWriter, [u8; 32]), (InputError, Option<PrivateInputWriter>)>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
{
    stream_to_file_with_write(
        body,
        writer,
        declared_length,
        total_deadline,
        reservation_lease,
        PrivateInputWriter::write_chunk,
    )
    .await
}

#[cfg(test)]
async fn stream_to_file_with_write<S, B, E>(
    body: S,
    writer: PrivateInputWriter,
    declared_length: u64,
    total_deadline: tokio::time::Instant,
    reservation_lease: Arc<()>,
    write: fn(&mut PrivateInputWriter, &[u8]) -> Result<(), PlatformError>,
) -> Result<(PrivateInputWriter, [u8; 32]), (InputError, Option<PrivateInputWriter>)>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
{
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let budget = UploadBudget::new(total_deadline, permit);
    stream_to_file_in_budget(
        body,
        writer,
        declared_length,
        &budget,
        reservation_lease,
        write,
    )
    .await
}

async fn stream_to_file_in_budget<S, B, E>(
    mut body: S,
    mut writer: PrivateInputWriter,
    declared_length: u64,
    budget: &UploadBudget,
    reservation_lease: Arc<()>,
    write: fn(&mut PrivateInputWriter, &[u8]) -> Result<(), PlatformError>,
) -> Result<(PrivateInputWriter, [u8; 32]), (InputError, Option<PrivateInputWriter>)>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
{
    let mut received = 0_u64;
    let mut digest = Sha256::new();
    loop {
        if let Err(error) = budget.check() {
            return Err((error, Some(writer)));
        }
        let frame = tokio::time::timeout_at(
            budget.deadline,
            tokio::time::timeout(UPLOAD_IDLE_TIMEOUT, body.next()),
        )
        .await;
        let frame = match frame {
            Ok(Ok(Some(Ok(frame)))) => frame,
            Ok(Ok(None)) if received == declared_length => break,
            _ => return Err((InputError::Transfer, Some(writer))),
        };
        let bytes = frame.as_ref();
        if received
            .checked_add(bytes.len() as u64)
            .is_none_or(|n| n > declared_length)
        {
            return Err((InputError::Transfer, Some(writer)));
        }
        for chunk in bytes.chunks(MAX_CHUNK_BYTES) {
            let owned = chunk.to_vec();
            let lease = reservation_lease.clone();
            let result = budget
                .blocking(InputError::Storage, move || {
                    let _lease = lease;
                    let result = write(&mut writer, &owned);
                    (writer, result)
                })
                .await;
            let (next_writer, write_result) = match result {
                Ok(value) => value,
                Err(error) => return Err((error, None)),
            };
            writer = next_writer;
            if write_result.is_err() {
                return Err((InputError::Storage, Some(writer)));
            }
            digest.update(chunk);
        }
        received += bytes.len() as u64;
    }
    Ok((writer, digest.finalize().into()))
}

fn stage_path(reservation: &UploadReservation) -> RelativePath {
    RelativePath::parse(format!(
        "inputs/staging/{}.part",
        reservation.input_id.as_str()
    ))
    .expect("generated input ID is a safe path component")
}
fn final_path(reservation: &UploadReservation) -> RelativePath {
    RelativePath::parse(format!("inputs/data/{}.bin", reservation.input_id.as_str()))
        .expect("generated input ID is a safe path component")
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use dissect3d_platform::{OwnedRoot, RootPurpose};
    use futures_util::stream;

    #[tokio::test]
    async fn total_deadline_bounds_a_blocking_write_and_retains_its_lease() {
        let temp = tempfile::tempdir().unwrap();
        let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
            .unwrap();
        let writer = root
            .begin_input(&RelativePath::parse("inputs/staging/slow.part").unwrap())
            .unwrap();
        let lease = Arc::new(());
        let started = tokio::time::Instant::now();
        let result = stream_to_file_with_write(
            stream::iter([Ok::<_, std::io::Error>(vec![1])]),
            writer,
            1,
            started + Duration::from_millis(25),
            lease.clone(),
            |writer, bytes| {
                std::thread::sleep(Duration::from_millis(250));
                writer.write_chunk(bytes)
            },
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "blocking write escaped the total deadline"
        );
        assert!(matches!(result, Err((InputError::Transfer, None))));
        assert!(
            Arc::strong_count(&lease) > 1,
            "timed-out native work lost its reservation lease"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&lease) > 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn total_deadline_ends_a_stalled_upload_before_the_idle_limit() {
        let temp = tempfile::tempdir().expect("private test root parent");
        let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
            .expect("private engine root");
        let staged =
            RelativePath::parse("inputs/staging/deadline.part").expect("safe staging path");
        let writer = root.begin_input(&staged).expect("staging writer");
        let started = tokio::time::Instant::now();
        let result = stream_to_file(
            stream::pending::<Result<Vec<u8>, std::io::Error>>(),
            writer,
            1,
            started + Duration::from_millis(25),
            Arc::new(()),
        )
        .await;

        assert!(
            result.is_err(),
            "a never-ending body must hit its total deadline"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(root.path_for_native_vfs(&staged).exists());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dissect3d_platform::{OwnedRoot, RootPurpose};

    #[tokio::test]
    async fn partial_file_write_error_retains_storage_failure_and_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
            .unwrap();
        let path = RelativePath::parse("inputs/staging/write-fault.part").unwrap();
        let writer = root.begin_input(&path).unwrap();
        let body = futures_util::stream::iter([Ok::<_, std::io::Error>(b"snapshot".to_vec())]);
        let result = stream_to_file_with_write(
            body,
            writer,
            8,
            tokio::time::Instant::now() + Duration::from_secs(1),
            Arc::new(()),
            |writer, bytes| {
                writer.write_chunk(&bytes[..1])?;
                Err(PlatformError::Io)
            },
        )
        .await;
        assert!(matches!(result, Err((InputError::Storage, Some(_)))));
        assert_eq!(root.read_file(&path, 64).unwrap(), b"s");
    }

    #[tokio::test]
    async fn transport_frames_are_split_into_bounded_file_writes() {
        let parent = tempfile::tempdir().unwrap();
        let root =
            OwnedRoot::create_private(&parent.path().join("engine"), RootPurpose::EngineData)
                .unwrap();
        let writer = root
            .begin_input(&RelativePath::parse("inputs/staging/frame.part").unwrap())
            .unwrap();
        let bytes = vec![42; MAX_CHUNK_BYTES * 2 + 1];
        let expected_digest: [u8; 32] = Sha256::digest(&bytes).into();
        let length = bytes.len() as u64;
        let body = futures_util::stream::iter([Ok::<_, std::io::Error>(bytes)]);
        let Ok((writer, digest)) = stream_to_file(
            body,
            writer,
            length,
            tokio::time::Instant::now() + Duration::from_secs(5),
            Arc::new(()),
        )
        .await
        else {
            panic!("a transport frame larger than a file-write chunk is valid");
        };
        assert_eq!(digest, expected_digest);
        let file = writer
            .finish(&RelativePath::parse("inputs/data/frame.bin").unwrap())
            .unwrap();
        assert_eq!(file.length(), length);
    }
}
