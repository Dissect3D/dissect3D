//! Bounded startup and periodic reconciliation for reserved and expired inputs.

use super::InputService;
use crate::store::inputs::{InputCleanupClaim, InputCleanupKind};
use dissect3d_api::InputId;
use dissect3d_platform::{OwnedInputScan, OwnedRoot, PlatformError, RelativePath};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

const MAX_FILES_PER_TICK: usize = 64;

struct RecoveryScans {
    staging: Option<OwnedInputScan>,
    data: Option<OwnedInputScan>,
    staging_done: bool,
    data_done: bool,
}

impl RecoveryScans {
    fn new() -> Self {
        Self {
            staging: None,
            data: None,
            staging_done: false,
            data_done: false,
        }
    }

    fn begin_cycle(&mut self) {
        self.staging = None;
        self.data = None;
        self.staging_done = false;
        self.data_done = false;
    }
}

pub(crate) async fn run(state: Arc<InputService>, mut shutdown: oneshot::Receiver<()>) {
    let mut scans = RecoveryScans::new();
    let mut last_failure = None;
    loop {
        match reconcile(&state, &mut scans).await {
            Ok(()) => last_failure = None,
            Err(error) => {
                state
                    .reconciled
                    .store(false, std::sync::atomic::Ordering::Release);
                if last_failure != Some(error) {
                    let code = if matches!(error, crate::CoreError::Platform(_)) {
                        "storage_unavailable"
                    } else {
                        "store_unavailable"
                    };
                    state.record_recovery_failure(code).await;
                }
                last_failure = Some(error);
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            _ = &mut shutdown => break,
        }
    }
}

async fn reconcile(
    state: &InputService,
    scans: &mut RecoveryScans,
) -> Result<(), crate::CoreError> {
    let store = state.store.clone();
    let claims = tokio::task::spawn_blocking(move || store.claim_input_cleanup())
        .await
        .map_err(|_| crate::CoreError::StoreUnavailable)??;
    let mut file_entries = 0usize;
    let mut failure = None;
    for claim in claims {
        file_entries = file_entries.saturating_add(match &claim.kind {
            InputCleanupKind::Reservation { .. } => 2,
            InputCleanupKind::Captured => 1,
        });
        let root = state.root.clone();
        let cleanup = claim.clone();
        let removed = tokio::task::spawn_blocking(move || remove_claimed_files(&root, &cleanup))
            .await
            .map_err(|_| crate::CoreError::StoreUnavailable)?;
        if let Err(error) = removed {
            failure = Some(crate::CoreError::Platform(error));
            continue;
        }
        let store = state.store.clone();
        tokio::task::spawn_blocking(move || store.confirm_input_cleanup(claim))
            .await
            .map_err(|_| crate::CoreError::StoreUnavailable)??;
    }
    let remaining = MAX_FILES_PER_TICK.saturating_sub(file_entries);
    let audit = audit_owned_files(state, scans, remaining).await;
    if let Some(error) = failure {
        return Err(error);
    }
    audit
}

async fn audit_owned_files(
    state: &InputService,
    scans: &mut RecoveryScans,
    budget: usize,
) -> Result<(), crate::CoreError> {
    if budget == 0 {
        return Ok(());
    }
    let root = state.root.clone();
    let mut remaining = budget;
    for (directory, is_staging) in [("inputs/staging", true), ("inputs/data", false)] {
        if remaining == 0 {
            break;
        }
        let (scan, done) = if is_staging {
            (&mut scans.staging, &mut scans.staging_done)
        } else {
            (&mut scans.data, &mut scans.data_done)
        };
        if *done {
            continue;
        }
        if scan.is_none() {
            let path = match RelativePath::parse(directory) {
                Ok(path) => path,
                Err(error) => return Err(crate::CoreError::Platform(error)),
            };
            match root.scan_owned_inputs(&path) {
                Ok(opened) => *scan = Some(opened),
                Err(PlatformError::NotFound) => {
                    *done = true;
                    continue;
                }
                Err(error) => return Err(crate::CoreError::Platform(error)),
            }
        }
        let batch = match scan
            .as_mut()
            .expect("scan initialized")
            .next_batch(remaining)
        {
            Ok(batch) => batch,
            Err(error) => return Err(crate::CoreError::Platform(error)),
        };
        remaining = remaining.saturating_sub(batch.entries.len() + batch.rejected_entries);
        if batch.exhausted {
            *done = true;
        }
        for path in batch.entries {
            let source_directory = match RelativePath::parse(directory) {
                Ok(path) => path,
                Err(error) => return Err(crate::CoreError::Platform(error)),
            };
            quarantine_if_ambiguous(state, &root, &source_directory, &path, is_staging).await?;
        }
        for entry_name in batch.rejected_names {
            let source_directory = match RelativePath::parse(directory) {
                Ok(path) => path,
                Err(error) => return Err(crate::CoreError::Platform(error)),
            };
            quarantine_entry(state, &root, &source_directory, &entry_name).await?;
        }
    }
    if scans.staging_done && scans.data_done {
        state
            .reconciled
            .store(true, std::sync::atomic::Ordering::Release);
        scans.begin_cycle();
    }
    Ok(())
}

async fn quarantine_if_ambiguous(
    state: &InputService,
    root: &Arc<OwnedRoot>,
    source_directory: &RelativePath,
    path: &RelativePath,
    is_staging: bool,
) -> Result<(), crate::CoreError> {
    let suffix = if is_staging { ".part" } else { ".bin" };
    let Some(name) = path.as_str().rsplit('/').next() else {
        return Ok(());
    };
    let Some(id_text) = name.strip_suffix(suffix) else {
        return quarantine_entry(state, root, source_directory, std::ffi::OsStr::new(name)).await;
    };
    let Ok(input_id) = InputId::parse(id_text.to_owned()) else {
        return quarantine_entry(state, root, source_directory, std::ffi::OsStr::new(name)).await;
    };
    let store = state.store.clone();
    // A busy or unavailable actor is not proof that a file is orphaned.
    let known = tokio::task::spawn_blocking(move || store.input_file_known(input_id))
        .await
        .map_err(|_| crate::CoreError::StoreUnavailable)??;
    if !known {
        quarantine_entry(state, root, source_directory, std::ffi::OsStr::new(name)).await?;
    }
    Ok(())
}

async fn quarantine_entry(
    _state: &InputService,
    root: &Arc<OwnedRoot>,
    source_directory: &RelativePath,
    entry_name: &std::ffi::OsStr,
) -> Result<(), crate::CoreError> {
    let id = crate::store::random_id("q_")?;
    let destination = RelativePath::parse(format!("inputs/quarantine/{id}.entry"))
        .map_err(crate::CoreError::Platform)?;
    let root = root.clone();
    let source_directory = source_directory.clone();
    let entry_name = entry_name.to_os_string();
    tokio::task::spawn_blocking(move || {
        root.quarantine_owned_entry(&source_directory, &entry_name, &destination)
    })
    .await
    .map_err(|_| crate::CoreError::StoreUnavailable)?
    .map_err(crate::CoreError::Platform)
}

fn remove_claimed_files(root: &OwnedRoot, claim: &InputCleanupClaim) -> Result<(), PlatformError> {
    let input_id = claim.input_id.as_str();
    let paths = match &claim.kind {
        InputCleanupKind::Reservation { .. } => {
            return root.remove_input_publication(
                &RelativePath::parse(format!("inputs/staging/{input_id}.part"))?,
                &RelativePath::parse(format!("inputs/data/{input_id}.bin"))?,
            );
        }
        InputCleanupKind::Captured => vec![format!("inputs/data/{input_id}.bin")],
    };
    for value in paths {
        let path = RelativePath::parse(value)?;
        match root.remove_durable(&path) {
            Ok(()) | Err(PlatformError::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CorePolicy, Store};
    use dissect3d_platform::{AuthorityLease, RootPurpose};

    pub(super) fn fixture() -> (tempfile::TempDir, std::path::PathBuf, InputService) {
        let parent = tempfile::tempdir().expect("private test parent");
        let root_path = parent.path().join("engine");
        let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
            .expect("private engine root");
        let lease = AuthorityLease::acquire(&root).expect("authority lease");
        let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
        let file_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("file root");
        let state = InputService::new(store, Arc::new(file_root));
        (parent, root_path, state)
    }

    #[tokio::test]
    async fn quarantines_at_most_64_scan_entries_per_tick_and_resumes_cursor() {
        let (_parent, root_path, state) = fixture();
        let data_path = root_path.join("inputs/data");
        state
            .root
            .ensure_private_directory(&RelativePath::parse("inputs/data").expect("data path"))
            .expect("private input data directory");
        for index in 0..65 {
            std::fs::write(data_path.join(format!("orphan-{index:03}.bin")), b"orphan")
                .expect("orphan test file");
        }

        let mut scans = RecoveryScans::new();
        audit_owned_files(&state, &mut scans, MAX_FILES_PER_TICK)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_dir(&data_path)
                .expect("remaining data files")
                .count(),
            1,
            "one tick quarantines no more than its 64-entry allowance"
        );
        let quarantine_path = root_path.join("inputs/quarantine");
        assert_eq!(
            std::fs::read_dir(&quarantine_path)
                .expect("quarantine directory")
                .count(),
            64
        );

        audit_owned_files(&state, &mut scans, MAX_FILES_PER_TICK)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_dir(&data_path)
                .expect("empty data directory")
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(&quarantine_path)
                .expect("quarantine directory")
                .count(),
            65
        );
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;

    #[tokio::test]
    async fn recovery_errors_leave_a_bounded_safe_diagnostic() {
        let (_parent, root_path, state) = super::tests::fixture();
        let db = rusqlite::Connection::open(root_path.join("metadata.sqlite3")).unwrap();
        db.execute_batch("ALTER TABLE captured_inputs RENAME TO unavailable_inputs;")
            .unwrap();
        let state = Arc::new(state);
        let root = state.root.clone();
        let (stop, shutdown) = oneshot::channel();
        let task = tokio::spawn(run(state, shutdown));
        let path = RelativePath::parse("run/input-recovery.json").unwrap();
        let bytes = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(bytes) = root.read_file(&path, 1024) {
                    break bytes;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        task.await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["code"], "store_unavailable");
        assert_eq!(value["phase"], "input_recovery");
        assert!(bytes.len() < 256);
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("metadata.sqlite3")
        );
    }

    #[tokio::test]
    async fn metadata_lookup_failure_never_quarantines_an_input() {
        let (_parent, root_path, state) = super::tests::fixture();
        let path =
            RelativePath::parse("inputs/data/inp_0123456789abcdef0123456789abcdef.bin").unwrap();
        state.root.write_atomic(&path, b"retained bytes").unwrap();
        // A real schema/read failure exercises the actor error path, rather than
        // treating a mock's false result as evidence that an input is absent.
        let database = rusqlite::Connection::open(root_path.join("metadata.sqlite3")).unwrap();
        database
            .execute_batch("ALTER TABLE captured_inputs RENAME TO unavailable_inputs;")
            .unwrap();
        quarantine_if_ambiguous(
            &state,
            &state.root,
            &RelativePath::parse("inputs/data").unwrap(),
            &path,
            false,
        )
        .await
        .expect_err("lookup failure is visible and never grants orphan authority");
        assert_eq!(state.root.read_file(&path, 64).unwrap(), b"retained bytes");
    }
}

#[cfg(test)]
mod publication_recovery_tests {
    use super::*;
    use crate::VerifiedEnrollment;
    use dissect3d_api::{ClientId, EnrollmentId, TokenDigest};
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn interrupted_two_link_publication_must_release_reservation_after_recovery() {
        let (_parent, root_path, state) = super::tests::fixture();
        let identity = state.store.identity().unwrap();
        let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap();
        let digest = TokenDigest::new(Sha256::digest([42; 32]).into());
        state
            .store
            .enroll(VerifiedEnrollment::new_submission_access(
                dissect3d_platform::current_owner_identity().unwrap(),
                identity.installation_id,
                identity.instance_id,
                EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").unwrap(),
                client_id.clone(),
                digest.clone(),
            ))
            .unwrap();
        let context = state.store.authenticate(client_id, digest).unwrap();
        let reservation = state
            .store
            .reserve_upload(
                context.clone(),
                8,
                "application/octet-stream".to_owned(),
                state.root.available_space_bytes().unwrap(),
            )
            .unwrap();
        let stage = RelativePath::parse(format!(
            "inputs/staging/{}.part",
            reservation.input_id.as_str()
        ))
        .unwrap();
        let data =
            RelativePath::parse(format!("inputs/data/{}.bin", reservation.input_id.as_str()))
                .unwrap();
        let mut writer = state.root.begin_input(&stage).unwrap();
        writer.write_chunk(b"snapshot").unwrap();
        drop(writer);
        state
            .root
            .ensure_private_directory(&RelativePath::parse("inputs/data").unwrap())
            .unwrap();
        // The actual publication protocol's crash state after linkat, before unlinkat.
        std::fs::hard_link(
            state.root.path_for_native_vfs(&stage),
            state.root.path_for_native_vfs(&data),
        )
        .unwrap();
        drop(reservation);
        let mut scans = RecoveryScans::new();
        reconcile(&state, &mut scans).await.unwrap();
        reconcile(&state, &mut scans).await.unwrap();
        let db = rusqlite::Connection::open(root_path.join("metadata.sqlite3")).unwrap();
        let remaining: i64 = db
            .query_row("SELECT count(*) FROM input_upload_reservations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            remaining, 0,
            "publication's own two-link crash state must not consume an upload slot forever"
        );
        assert!(!state.root.path_for_native_vfs(&stage).exists());
        assert!(!state.root.path_for_native_vfs(&data).exists());
        let mut live = Vec::new();
        for _ in 0..2 {
            live.push(
                state
                    .store
                    .reserve_upload(
                        context.clone(),
                        8,
                        "application/octet-stream".to_owned(),
                        state.root.available_space_bytes().unwrap(),
                    )
                    .unwrap(),
            );
        }
        assert!(matches!(
            state.store.reserve_upload(
                context,
                8,
                "application/octet-stream".to_owned(),
                state.root.available_space_bytes().unwrap()
            ),
            Err(crate::CoreError::CapacityExceeded("upload_concurrency_max"))
        ));
    }
}
