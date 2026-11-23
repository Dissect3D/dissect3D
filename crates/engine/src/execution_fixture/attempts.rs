//! WE-P06/3 attempt source for the explicitly prepared r2 package: the
//! controller's eligibility and attempt preparation from verified prepared
//! support, its readiness facts and the job's exact captured resolution.
//!
//! Only the captured `ResolvedJob` bytes from the Store are read; nothing is
//! re-resolved, remapped or re-read from a source. A job whose captured
//! selection or readiness is not exactly this prepared profile (for example an
//! r1 job) stays blocked with its place, and is never remapped to r2. Each
//! attempt re-verifies the installed worker before launch, writes its private
//! files and hands the worker only inherited read-only handles and one staging
//! folder. The worker is launched only through the contained platform launcher.
use super::preparation::PreparedExecutionFixture;
use super::{ADAPTER_ID, ADAPTER_REVISION, FEATURES, FixtureParameters, STAGES};
use crate::execution::attempt_files::{AttemptInput, prepare_attempt_files};
use crate::execution::controller::{AttemptSource, PreparedAttempt};
use crate::execution::launcher::PlatformLauncher;
use crate::execution::legality::WorkerExpectation;
use crate::execution::scheduler::Eligibility;
use crate::execution::types::{AttemptPlan, SupervisionLimits};
use crate::store::execution::{DispatchRecord, QueuedCandidate};
use crate::submission::admission::PreparedAdmission;
use dissect3d_api::{InputIdentity, ResolvedJob};
use dissect3d_platform::{OwnedRoot, RelativePath};
use std::sync::Arc;

/// The one resource the CPU fixture profile reserves (WE-002).
pub(crate) const CPU_RESOURCE: &str = "cpu:fixture";
/// The fixture's single input role.
const MESH_ROLE: &str = "mesh";
/// Safe blocker for a captured job this prepared profile cannot execute.
pub(crate) const NOT_EXECUTABLE: &str = "profile_not_executable";

/// What one captured job needs from its resolution.
struct Captured {
    input: InputIdentity,
    parameters: FixtureParameters,
}

pub(crate) struct FixtureAttempts {
    fixture: PreparedExecutionFixture,
    admission: PreparedAdmission,
    root: Arc<OwnedRoot>,
    limits: SupervisionLimits,
}

impl FixtureAttempts {
    /// `root` is the prepared engine data root the fixture was loaded from.
    pub(crate) fn new(fixture: PreparedExecutionFixture, root: Arc<OwnedRoot>) -> Self {
        let admission = PreparedAdmission::from_verified_fixture(&fixture.readiness);
        Self {
            fixture,
            admission,
            root,
            limits: SupervisionLimits::CONTRACT,
        }
    }

    /// Test-only: tighter supervision bounds, never above the contract.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: SupervisionLimits) -> Self {
        assert!(limits.within_contract(), "test limits above the contract");
        self.limits = limits;
        self
    }

    /// The captured job, if it is exactly this prepared profile.
    fn captured(&self, resolved_json: &str) -> Option<Captured> {
        let resolved: ResolvedJob = serde_json::from_str(resolved_json).ok()?;
        if !self.admission.covers(&resolved) {
            return None;
        }
        let [(role, inputs)] =
            <[_; 1]>::try_from(resolved.inputs.into_iter().collect::<Vec<_>>()).ok()?;
        let [input] = <[_; 1]>::try_from(inputs).ok()?;
        if role != MESH_ROLE {
            return None;
        }
        let parameters = serde_json::to_vec(&resolved.effective_parameters).ok()?;
        let parameters = FixtureParameters::parse(&parameters)?;
        Some(Captured { input, parameters })
    }
}

impl AttemptSource for FixtureAttempts {
    type Launcher = PlatformLauncher;

    fn eligibility(&self, candidate: &QueuedCandidate) -> Eligibility {
        match self.captured(&candidate.resolved_json) {
            Some(_) => Eligibility::Ready {
                resources: vec![CPU_RESOURCE.to_owned()],
            },
            None => Eligibility::Blocked(NOT_EXECUTABLE),
        }
    }

    fn prepare(&self, record: &DispatchRecord) -> Result<PreparedAttempt<PlatformLauncher>, ()> {
        let Captured { input, parameters } = self.captured(&record.resolved_json).ok_or(())?;
        // Re-verifies the installed worker (and guardian) bytes first.
        let mut command = self.fixture.command(&self.root).map_err(|_| ())?;
        let path = RelativePath::parse(format!("inputs/data/{}.bin", input.input_id.as_str()))
            .map_err(|_| ())?;
        // The worker's inherited view shares this open's file offset on Unix
        // (a duplicated descriptor), so publication re-verifies the input
        // through its own independent open, never through this one.
        let worker_view = self.root.open_immutable_input(&path).map_err(|_| ())?;
        let input_reader = self.root.open_immutable_input(&path).map_err(|_| ())?;
        let handles = prepare_attempt_files(
            &self.root,
            &record.attempt_id,
            &self.fixture.resolution_document,
            &parameters.to_document(),
            &[AttemptInput {
                role: MESH_ROLE,
                reader: &worker_view,
                sha256: input.sha256.as_str(),
                byte_length: input.byte_length,
            }],
            &mut command,
        )
        .map_err(|_| ())?;
        let plan = AttemptPlan {
            expectation: WorkerExpectation {
                worker_build_sha256: self.fixture.worker_sha256.clone(),
                adapter_id: ADAPTER_ID.into(),
                adapter_revision: ADAPTER_REVISION.into(),
                required_features: FEATURES.iter().map(|f| (*f).to_owned()).collect(),
                resolution_sha256: handles.resolution_sha256,
            },
            resolution_handle: handles.resolution_handle,
            inputs: handles.inputs,
            output_staging_handle: handles.output_staging_handle,
            effective_parameters_handle: handles.effective_parameters_handle,
            stages: STAGES,
            limits: self.limits,
        };
        Ok(PreparedAttempt {
            plan,
            launcher: PlatformLauncher::new(command),
            staging: handles.staging,
            input,
            input_reader,
        })
    }
}
