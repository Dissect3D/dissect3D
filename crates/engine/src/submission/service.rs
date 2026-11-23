//! Engine-owned submission orchestration; files never cross into the actor.

use super::SubmissionError;
use super::admission::{AdmissionError, PreparedAdmission, build_candidate};
use super::equivalence::SubmittedJobRequest;
use crate::{AuthContext, Store, support::Catalog};
use dissect3d_api::{AcceptanceReceipt, ErrorCode, IdempotencyKey, JobRequest};
use dissect3d_platform::{OwnedRoot, RelativePath};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::sync::{Mutex, Weak};
use std::time::Duration;
use tokio::sync::Semaphore;

type KeyGates = BTreeMap<(String, String), Weak<tokio::sync::Mutex<()>>>;

pub(crate) struct SubmissionService {
    #[cfg(test)]
    test_hooks: Arc<super::test_support::Hooks>,
    store: Arc<Store>,
    root: Arc<OwnedRoot>,
    catalog: Arc<Catalog>,
    prepared: Option<PreparedAdmission>,
    inputs: Arc<crate::inputs::InputService>,
    jobs: Arc<crate::jobs::JobsService>,
    validation: Arc<Semaphore>,
    keys: Mutex<KeyGates>,
}

impl SubmissionService {
    pub(crate) fn new(
        store: Arc<Store>,
        root: Arc<OwnedRoot>,
        catalog: Arc<Catalog>,
        prepared: Option<PreparedAdmission>,
        inputs: Arc<crate::inputs::InputService>,
        jobs: Arc<crate::jobs::JobsService>,
    ) -> Self {
        Self {
            #[cfg(test)]
            test_hooks: super::test_support::for_root(root.path()),
            store,
            root,
            catalog,
            prepared,
            inputs,
            jobs,
            validation: Arc::new(Semaphore::new(2)),
            keys: Mutex::new(BTreeMap::new()),
        }
    }

    async fn probe(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: SubmittedJobRequest,
    ) -> Result<Option<AcceptanceReceipt>, SubmissionError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || match request {
            SubmittedJobRequest::Legacy(r) => store.probe_job_binding(auth, key, r),
            SubmittedJobRequest::Execution(r) => store.probe_execution_binding(auth, key, r),
        })
        .await
        .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?
    }

    pub(crate) async fn submit(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: JobRequest,
    ) -> Result<AcceptanceReceipt, SubmissionError> {
        self.submit_request(auth, key, SubmittedJobRequest::Legacy(request))
            .await
    }
    pub(crate) async fn submit_execution(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: dissect3d_api::ExecutionJobRequest,
    ) -> Result<AcceptanceReceipt, SubmissionError> {
        self.submit_request(auth, key, SubmittedJobRequest::Execution(request))
            .await
    }
    /// WE-003 exact linked retry. Replay of a retained binding never consults
    /// readiness or reconciliation; fresh work requires both.
    pub(crate) async fn retry_execution(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        source: dissect3d_api::JobId,
    ) -> Result<dissect3d_api::ExecutionAcceptance, SubmissionError> {
        let prerequisites = crate::store::retry::RetryPrerequisites {
            prepared: self.prepared.clone(),
            reconciled: self.inputs.is_reconciled() && self.jobs.is_reconciled(),
        };
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || store.retry_job(auth, key, source, prerequisites))
            .await
            .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?
    }
    /// WE-001: an original Stage 3 body under the negotiated header replays
    /// its retained binding exactly. It never creates fresh work on an
    /// execution-enabled engine.
    pub(crate) async fn replay_legacy(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: JobRequest,
    ) -> Result<AcceptanceReceipt, SubmissionError> {
        self.probe(auth, key, SubmittedJobRequest::Legacy(request))
            .await?
            .ok_or_else(|| ErrorCode::IncompatibleContract.into())
    }
    async fn submit_request(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: SubmittedJobRequest,
    ) -> Result<AcceptanceReceipt, SubmissionError> {
        request
            .encoded_size()
            .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?;
        #[cfg(test)]
        if self
            .test_hooks
            .expire_unreferenced
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64;
                store.claim_input_cleanup_at(now + crate::inputs::policy::UPLOAD_TTL_MS + 1)
            })
            .await
            .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))??;
        }
        let gate = {
            let mut keys = self
                .keys
                .lock()
                .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?;
            keys.retain(|_, gate| gate.strong_count() != 0);
            let identity = (
                auth.client_id().as_str().to_owned(),
                key.as_str().to_owned(),
            );
            if let Some(gate) = keys.get(&identity).and_then(Weak::upgrade) {
                gate
            } else {
                if keys.len() >= 64 {
                    return Err(ErrorCode::CapacityExceeded.into());
                }
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                keys.insert(identity, Arc::downgrade(&gate));
                gate
            }
        };
        // This finite coalescing wait saves validation slots; only SQLite can
        // bind the key. A dropped caller never cancels an actor commit.
        let _gate = tokio::time::timeout(Duration::from_secs(3), gate.lock_owned())
            .await
            .map_err(|_| SubmissionError::from(ErrorCode::CapacityExceeded))?;
        if let Some(receipt) = self
            .probe(auth.clone(), key.clone(), request.clone())
            .await?
        {
            return Ok(receipt);
        }
        let result = self.fresh(auth.clone(), key.clone(), request.clone()).await;
        if result.is_err() {
            #[cfg(test)]
            self.test_hooks.failure().await;
            // Another validator may have committed while this one failed. Its
            // retained binding takes precedence over obsolete fresh prerequisites.
            if let Some(receipt) = self.probe(auth, key, request).await? {
                return Ok(receipt);
            }
        }
        result
    }

    async fn fresh(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: SubmittedJobRequest,
    ) -> Result<AcceptanceReceipt, SubmissionError> {
        if !self.inputs.is_reconciled() || !self.jobs.is_reconciled() {
            return Err(ErrorCode::EngineRecovering.into());
        }
        if request.version() == 1 && !request.base().required_features.is_empty() {
            return Err(ErrorCode::RequiredFeatureUnsupported.into());
        }
        let permit = self
            .validation
            .clone()
            .try_acquire_owned()
            .map_err(|_| SubmissionError::from(ErrorCode::CapacityExceeded))?;
        let prepared = self
            .prepared
            .clone()
            .ok_or_else(|| SubmissionError::from(ErrorCode::NotPrepared))?;
        let store = self.store.clone();
        let root = self.root.clone();
        let catalog = self.catalog.clone();
        #[cfg(test)]
        let test_hooks = self.test_hooks.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let ids = request
                .base()
                .inputs
                .values()
                .flatten()
                .map(|input| input.input_id.clone())
                .collect();
            let pins = store.pin_verified_inputs(auth.clone(), ids)?;
            let mut readers: BTreeMap<String, Box<dyn Read + Send>> = BTreeMap::new();
            for identity in &pins.identities {
                let path =
                    RelativePath::parse(format!("inputs/data/{}.bin", identity.input_id.as_str()))
                        .map_err(|_| SubmissionError::from(ErrorCode::StorageUnavailable))?;
                let reader = root
                    .open_immutable_input(&path)
                    .map_err(|_| SubmissionError::from(ErrorCode::StorageIntegrityFault))?;
                readers.insert(identity.input_id.as_str().to_owned(), Box::new(reader));
            }
            let size = request
                .encoded_size()
                .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?;
            let candidate = match &request {
                SubmittedJobRequest::Legacy(r) => {
                    build_candidate(&catalog, &prepared, r, size, pins, readers)
                }
                SubmittedJobRequest::Execution(r) => super::admission::build_execution_candidate(
                    &catalog, &prepared, r, size, pins, readers,
                ),
            }
            .map_err(admission_error)?;
            #[cfg(test)]
            if !test_hooks.before_commit() {
                return Err(ErrorCode::StoreUnavailable.into());
            }
            match request {
                SubmittedJobRequest::Legacy(r) => store.accept_job(auth, key, r, candidate),
                SubmittedJobRequest::Execution(r) => {
                    store.accept_execution_job(auth, key, r, candidate)
                }
            }
        })
        .await
        .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?
    }
}

fn admission_error(error: AdmissionError) -> SubmissionError {
    match error {
        AdmissionError::InvalidRequest => ErrorCode::InvalidRequest,
        AdmissionError::UnsupportedSelection => ErrorCode::IncompatibleProfile,
        AdmissionError::UnsupportedParameter => ErrorCode::UnsupportedParameter,
        AdmissionError::RequiredFeatureUnsupported => ErrorCode::RequiredFeatureUnsupported,
        AdmissionError::InvalidInput => ErrorCode::InvalidInput,
        AdmissionError::InputUnavailable => ErrorCode::InputUnavailable,
        AdmissionError::NotPrepared => ErrorCode::NotPrepared,
        AdmissionError::StorageIntegrityFault => ErrorCode::StorageIntegrityFault,
        AdmissionError::CapacityExceeded => ErrorCode::CapacityExceeded,
    }
    .into()
}

pub(crate) fn capability() -> dissect3d_api::SubmissionCapability {
    let mut capability = crate::inputs::policy::capability();
    capability.operations = ["inputs.create", "jobs.submit", "jobs.list", "jobs.show"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for (key, value) in [
        ("job_input_bytes_max", 1_073_741_824),
        ("queued_jobs_max", 128),
        ("submission_bindings_max", 65_536),
        ("submission_binding_bytes_max", 16_384),
        ("captured_input_bytes_max", 17_179_869_184),
        ("job_control_bytes_max", 65_536),
        ("job_metadata_bytes_max", 262_144),
        ("job_inputs_max", 64),
        ("job_roles_max", 16),
        ("job_list_default", 20),
        ("job_list_max", 100),
        ("job_cursor_bytes_max", 1024),
    ] {
        capability.limits.insert(key.to_owned(), value);
    }
    capability
}
