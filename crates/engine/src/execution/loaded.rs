//! Workers the controller holds loaded (WE-P06/6). A worker counts as loaded
//! from its supervisor's first `executing` phase (the worker acknowledged its
//! load) until whole-tree cleanup of that attempt is confirmed. Preparation
//! or a dispatch alone never counts. When cleanup is uncertain the entry
//! stays, marked unconfirmed: a held allocation is never reported released
//! on a guess. Restart reconciliation of such entries is WE-P07.
use dissect3d_api::ResolvedJob;
use std::collections::HashMap;
use std::sync::Mutex;

/// The exact selection a loaded worker serves.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LoadedProfile {
    pub(crate) support_ref: String,
    pub(crate) task_id: String,
    pub(crate) task_version: String,
    pub(crate) runtime_ref: String,
    pub(crate) variant: String,
}
impl LoadedProfile {
    /// The profile of a captured resolution; `None` if it cannot be read.
    pub(crate) fn of_resolution(resolved_json: &str) -> Option<Self> {
        let resolved: ResolvedJob = serde_json::from_str(resolved_json).ok()?;
        let selection = resolved.selection;
        Some(Self {
            support_ref: selection.support_ref,
            task_id: selection.task.id,
            task_version: selection.task.version,
            runtime_ref: selection.runtime_ref,
            variant: selection.variant,
        })
    }
}

/// One held worker as discovery may report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LoadedWorker {
    pub(crate) profile: LoadedProfile,
    /// When the load acknowledgement was observed (Unix ms).
    pub(crate) since_ms: u64,
    /// The reserved resources the attempt holds.
    pub(crate) resources: Vec<String>,
    /// The attempt ended but its cleanup is not confirmed.
    pub(crate) cleanup_unconfirmed: bool,
}

/// Loaded workers by attempt ID.
#[derive(Debug, Default)]
pub(crate) struct LoadedWorkers(Mutex<HashMap<String, LoadedWorker>>);
impl LoadedWorkers {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, LoadedWorker>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// The attempt's worker acknowledged its load. Repeats keep the first time.
    pub(crate) fn loaded(&self, attempt_id: &str, profile: LoadedProfile, resources: Vec<String>) {
        self.map()
            .entry(attempt_id.to_owned())
            .or_insert_with(|| LoadedWorker {
                profile,
                since_ms: now_ms(),
                resources,
                cleanup_unconfirmed: false,
            });
    }
    /// Whole-tree cleanup of the attempt is established: nothing is held.
    pub(crate) fn cleaned(&self, attempt_id: &str) {
        self.map().remove(attempt_id);
    }
    /// The attempt ended with uncertain cleanup: keep it, marked unconfirmed.
    pub(crate) fn cleanup_unconfirmed(&self, attempt_id: &str) {
        if let Some(worker) = self.map().get_mut(attempt_id) {
            worker.cleanup_unconfirmed = true;
        }
    }
    /// Whether any ended worker's cleanup is still unconfirmed.
    pub(crate) fn any_unconfirmed(&self) -> bool {
        self.map().values().any(|worker| worker.cleanup_unconfirmed)
    }
    /// Held workers serving `profile`.
    pub(crate) fn for_profile(&self, profile: &LoadedProfile) -> Vec<LoadedWorker> {
        let mut found: Vec<_> = self
            .map()
            .values()
            .filter(|worker| &worker.profile == profile)
            .cloned()
            .collect();
        found.sort_by_key(|worker| worker.since_ms);
        found
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(variant: &str) -> LoadedProfile {
        LoadedProfile {
            support_ref: "s@r".into(),
            task_id: "t".into(),
            task_version: "1.0".into(),
            runtime_ref: "rt@r".into(),
            variant: variant.into(),
        }
    }

    #[test]
    fn only_confirmed_cleanup_clears_a_loaded_worker() {
        let workers = LoadedWorkers::default();
        workers.loaded("a1", profile("v"), vec!["cpu:fixture".into()]);
        let first = workers.for_profile(&profile("v"));
        workers.loaded("a1", profile("v"), vec![]);
        assert_eq!(workers.for_profile(&profile("v")), first, "first load kept");
        assert!(workers.for_profile(&profile("other")).is_empty());
        assert!(!workers.any_unconfirmed());
        workers.cleanup_unconfirmed("a1");
        assert!(workers.any_unconfirmed());
        let held = workers.for_profile(&profile("v"));
        assert_eq!(held.len(), 1);
        assert!(held[0].cleanup_unconfirmed);
        assert_eq!(held[0].resources, vec!["cpu:fixture".to_owned()]);
        workers.cleaned("a1");
        assert!(workers.for_profile(&profile("v")).is_empty());
        // Unknown attempts change nothing.
        workers.cleanup_unconfirmed("a2");
        assert!(workers.for_profile(&profile("v")).is_empty());
    }
}
