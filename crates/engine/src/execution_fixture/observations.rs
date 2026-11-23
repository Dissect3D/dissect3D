//! WE-P06/6 discovery facts of the explicit execution host: the verified
//! prepared profile from the readiness snapshot built at `load()`, and the
//! controller's loaded workers. Nothing here infers readiness or loaded
//! state; both come from their engine owners.
use crate::execution::loaded::{LoadedProfile, LoadedWorkers};
use crate::submission_fixture::PreparedReadiness;
use crate::support::live_facts::{ExecutionHostFacts, LoadedFacts, LoadedLookup, PreparedProfile};
use std::sync::Arc;

impl LoadedLookup for LoadedWorkers {
    fn loaded(&self, profile: &PreparedProfile) -> LoadedFacts {
        let held = self.for_profile(&LoadedProfile {
            support_ref: profile.support_ref.clone(),
            task_id: profile.task.id().to_owned(),
            task_version: profile.task.version().to_owned(),
            runtime_ref: profile.runtime_ref.clone(),
            variant: profile.variant.clone(),
        });
        let Some(first) = held.first() else {
            return LoadedFacts::NotLoaded;
        };
        let since_ms = first.since_ms;
        let mut allocation_ids: Vec<String> =
            held.iter().flat_map(|w| w.resources.clone()).collect();
        allocation_ids.sort();
        allocation_ids.dedup();
        if held.iter().any(|w| w.cleanup_unconfirmed) {
            LoadedFacts::Unconfirmed {
                since_ms,
                allocation_ids,
            }
        } else {
            LoadedFacts::Loaded {
                since_ms,
                allocation_ids,
            }
        }
    }
}

/// The execution host's observation source.
pub(crate) fn host_facts(
    readiness: &PreparedReadiness,
    loaded: Arc<LoadedWorkers>,
) -> ExecutionHostFacts {
    let resolved = &readiness.resolved;
    ExecutionHostFacts::new(
        PreparedProfile {
            support_ref: resolved.support_ref.clone(),
            task: resolved.task.clone(),
            runtime_ref: resolved.runtime_ref.clone(),
            variant: resolved.variant.clone(),
            realization: readiness.snapshot.runtime_realization.clone(),
            check_id: readiness.snapshot.check_id.clone(),
            fingerprint: readiness.snapshot.fingerprint.as_str().to_owned(),
        },
        loaded,
    )
}
