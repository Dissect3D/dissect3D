//! Discovery facts of an explicit execution host (WE-P06/6, SD-C06). Real
//! engine owners supply them: the verified prepared profile (installation and
//! readiness) and the dispatch controller's loaded workers. Installation,
//! readiness, authorization, loaded state and eligibility stay independent:
//! preparation never implies loaded, and loaded state clears only with
//! confirmed cleanup (the controller's rule).
use super::observations::{InspectionScope, ObservationFacts, ObservationSource, reason};
use dissect3d_api::TaskKey;
use std::sync::Arc;

/// The one verified, executable profile of the host.
#[derive(Clone, Debug)]
pub(crate) struct PreparedProfile {
    pub(crate) support_ref: String,
    pub(crate) task: TaskKey,
    pub(crate) runtime_ref: String,
    pub(crate) variant: String,
    /// The installed runtime realization the readiness check named.
    pub(crate) realization: String,
    pub(crate) check_id: String,
    pub(crate) fingerprint: String,
}

/// What the controller holds loaded for one exact selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LoadedFacts {
    NotLoaded,
    /// Held workers: the earliest load time and every reserved resource.
    Loaded {
        since_ms: u64,
        allocation_ids: Vec<String>,
    },
    /// An ended worker whose cleanup is not confirmed: still reported held.
    Unconfirmed {
        since_ms: u64,
        allocation_ids: Vec<String>,
    },
}

/// The controller's loaded workers, looked up by exact selection.
pub(crate) trait LoadedLookup: Send + Sync {
    fn loaded(&self, profile: &PreparedProfile) -> LoadedFacts;
}

pub(crate) struct ExecutionHostFacts {
    profile: PreparedProfile,
    loaded: Arc<dyn LoadedLookup>,
}
impl ExecutionHostFacts {
    pub(crate) fn new(profile: PreparedProfile, loaded: Arc<dyn LoadedLookup>) -> Self {
        Self { profile, loaded }
    }

    /// Installed, verified and executable: the facts of the prepared
    /// selection and of its runtime. Only unresolved fields still block.
    fn prepared(&self, base: ObservationFacts, now: u64) -> ObservationFacts {
        ObservationFacts {
            installation_status: "present".into(),
            realization: Some(self.profile.realization.clone()),
            readiness_status: "passed".into(),
            freshness: "current".into(),
            check_id: Some(self.profile.check_id.clone()),
            fingerprint: Some(self.profile.fingerprint.clone()),
            blockers: without(
                base.blockers.clone(),
                &["execution_unavailable", "not_prepared"],
            ),
            // The CPU fixture's only resource is the central one-slot
            // reservation; no hardware requirement is left unchecked.
            unknowns: Vec::new(),
            authorization_status: "allowed".into(),
            evaluation_required: false,
            authorization_reasons: Vec::new(),
            observed_at_ms: Some(now),
            ..base
        }
    }
}

fn without(
    reasons: Vec<dissect3d_api::ObservationReason>,
    codes: &[&str],
) -> Vec<dissect3d_api::ObservationReason> {
    reasons
        .into_iter()
        .filter(|reason| !codes.contains(&reason.code.as_str()))
        .collect()
}

impl ObservationSource for ExecutionHostFacts {
    fn facts(&self, scope: &InspectionScope) -> ObservationFacts {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let base = ObservationFacts::phase_two(scope);
        let profile = &self.profile;
        match scope {
            InspectionScope::Selection(selection)
                if selection.support_ref == profile.support_ref
                    && selection.task == profile.task
                    && selection.runtime_ref == profile.runtime_ref
                    && selection.variant == profile.variant =>
            {
                let (status, at, allocation_ids) = match self.loaded.loaded(profile) {
                    LoadedFacts::NotLoaded => ("not_loaded", now, Vec::new()),
                    LoadedFacts::Loaded {
                        since_ms,
                        allocation_ids,
                    } => ("loaded", since_ms, allocation_ids),
                    LoadedFacts::Unconfirmed {
                        since_ms,
                        allocation_ids,
                    } => ("unknown", since_ms, allocation_ids),
                };
                ObservationFacts {
                    loaded_status: status.into(),
                    loaded_at_ms: Some(at),
                    allocation_ids,
                    ..self.prepared(base, now)
                }
            }
            InspectionScope::Runtime { runtime_ref, .. } if runtime_ref == &profile.runtime_ref => {
                self.prepared(base, now)
            }
            // SD-C06: realization-scoped facts stay unknown until the
            // selection is complete; readiness and loaded keep their binding
            // values. Authorization is sourced independently.
            InspectionScope::Binding {
                support_ref, task, ..
            } if support_ref == &profile.support_ref && task == &profile.task => ObservationFacts {
                installation_status: "unknown".into(),
                blockers: without(
                    base.blockers.clone(),
                    &["execution_unavailable", "not_prepared"],
                ),
                authorization_status: "allowed".into(),
                evaluation_required: false,
                authorization_reasons: Vec::new(),
                observed_at_ms: Some(now),
                ..base
            },
            // Execution exists here, but this profile is not prepared.
            _ => ObservationFacts {
                blockers: without(base.blockers.clone(), &["execution_unavailable"]),
                authorization_reasons: vec![reason(
                    "not_prepared",
                    "execution_authorization",
                    "prepare_not_implemented",
                )],
                loaded_at_ms: matches!(scope, InspectionScope::Selection(_)).then_some(now),
                observed_at_ms: Some(now),
                ..base
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::InspectionSelection;
    use std::sync::Mutex;

    struct Fixed(Mutex<LoadedFacts>);
    impl LoadedLookup for Fixed {
        fn loaded(&self, _: &PreparedProfile) -> LoadedFacts {
            self.0.lock().unwrap().clone()
        }
    }

    fn host(loaded: LoadedFacts) -> (ExecutionHostFacts, Arc<Fixed>) {
        let lookup = Arc::new(Fixed(Mutex::new(loaded)));
        let facts = ExecutionHostFacts::new(
            PreparedProfile {
                support_ref: "s@r2".into(),
                task: TaskKey::new("t", "1.0").unwrap(),
                runtime_ref: "rt@r2".into(),
                variant: "v".into(),
                realization: "real".into(),
                check_id: "chk".into(),
                fingerprint: "f".repeat(64),
            },
            lookup.clone(),
        );
        (facts, lookup)
    }

    fn selection(support_ref: &str, unresolved: &[&str]) -> InspectionScope {
        InspectionScope::Selection(InspectionSelection {
            support_ref: support_ref.into(),
            task: TaskKey::new("t", "1.0").unwrap(),
            runtime_ref: "rt@r2".into(),
            variant: "v".into(),
            unresolved_paths: unresolved.iter().map(|p| (*p).to_owned()).collect(),
        })
    }

    fn codes(reasons: &[dissect3d_api::ObservationReason]) -> Vec<&str> {
        reasons.iter().map(|r| r.code.as_str()).collect()
    }

    #[test]
    fn the_prepared_selection_is_installed_ready_eligible_and_not_loaded() {
        let (host, _) = host(LoadedFacts::NotLoaded);
        let facts = host.facts(&selection("s@r2", &[]));
        assert_eq!(facts.installation_status, "present");
        assert_eq!(facts.realization.as_deref(), Some("real"));
        assert_eq!(
            (facts.readiness_status.as_str(), facts.freshness.as_str()),
            ("passed", "current")
        );
        assert_eq!(facts.check_id.as_deref(), Some("chk"));
        assert_eq!(facts.authorization_status, "allowed");
        assert!(facts.blockers.is_empty() && facts.unknowns.is_empty());
        assert_eq!(facts.eligibility_status(), "eligible");
        // Preparation never implies loaded.
        assert_eq!(facts.loaded_status, "not_loaded");
        assert!(facts.allocation_ids.is_empty());
        assert!(facts.observed_at_ms.is_some() && facts.loaded_at_ms.is_some());
        // An unresolved field still blocks.
        let unresolved = host.facts(&selection("s@r2", &["/parameters/x"]));
        assert_eq!(
            codes(&unresolved.blockers),
            ["required_feature_unsupported"]
        );
        assert_eq!(unresolved.eligibility_status(), "blocked");
    }

    #[test]
    fn loaded_follows_the_controller_and_uncertain_cleanup_stays_held() {
        let (host, lookup) = host(LoadedFacts::Loaded {
            since_ms: 7,
            allocation_ids: vec!["cpu:fixture".into()],
        });
        let facts = host.facts(&selection("s@r2", &[]));
        assert_eq!(facts.loaded_status, "loaded");
        assert_eq!(facts.loaded_at_ms, Some(7));
        assert_eq!(facts.allocation_ids, vec!["cpu:fixture".to_owned()]);
        *lookup.0.lock().unwrap() = LoadedFacts::Unconfirmed {
            since_ms: 7,
            allocation_ids: vec!["cpu:fixture".into()],
        };
        let facts = host.facts(&selection("s@r2", &[]));
        assert_eq!(facts.loaded_status, "unknown");
        assert_eq!(facts.allocation_ids, vec!["cpu:fixture".to_owned()]);
        *lookup.0.lock().unwrap() = LoadedFacts::NotLoaded;
        assert_eq!(
            host.facts(&selection("s@r2", &[])).loaded_status,
            "not_loaded"
        );
    }

    #[test]
    fn binding_runtime_and_other_scopes_keep_their_independent_facts() {
        let (host, _) = host(LoadedFacts::Loaded {
            since_ms: 1,
            allocation_ids: vec!["cpu:fixture".into()],
        });
        let binding = host.facts(&InspectionScope::Binding {
            support_ref: "s@r2".into(),
            task: TaskKey::new("t", "1.0").unwrap(),
            unresolved_paths: Vec::new(),
        });
        assert_eq!(binding.installation_status, "unknown");
        assert_eq!(binding.readiness_status, "not_checked");
        assert_eq!(binding.loaded_status, "unknown");
        assert!(binding.allocation_ids.is_empty() && binding.loaded_at_ms.is_none());
        assert!(!codes(&binding.blockers).contains(&"execution_unavailable"));

        let runtime = host.facts(&InspectionScope::Runtime {
            runtime_ref: "rt@r2".into(),
            unresolved_paths: Vec::new(),
        });
        assert_eq!(runtime.installation_status, "present");
        assert_eq!(runtime.eligibility_status(), "eligible");

        // Another profile: execution exists, the profile is not prepared.
        let other = host.facts(&selection("s@r1", &[]));
        assert_eq!(other.installation_status, "absent");
        assert_eq!(codes(&other.blockers), ["not_prepared"]);
        assert_eq!(other.loaded_status, "not_loaded");
        assert_eq!(other.eligibility_status(), "blocked");
        assert_eq!(codes(&other.authorization_reasons), ["not_prepared"]);
    }
}
