//! Independent operational facts and fail-closed eligibility explanations.

use super::{
    Catalog, DiscoveryError, InspectionSelection, ModelRecord, RuntimeRecord, Selection,
    TaskBindingRecord,
};
use dissect3d_api::{
    DiscoveryObservation, EligibilityObservation, EvidenceObservation,
    ExecutionAuthorizationObservation, InstallationObservation, LoadedObservation,
    ObservationReason, ObservationScope, ReadinessObservation, TaskKey,
};
use serde_json::{Value, json};

#[derive(Clone, Debug)]
pub(crate) enum InspectionScope {
    Selection(InspectionSelection),
    Binding {
        support_ref: String,
        task: TaskKey,
        unresolved_paths: Vec<String>,
    },
    Runtime {
        runtime_ref: String,
        unresolved_paths: Vec<String>,
    },
}

/// Snapshot supplied by real engine owners in later preparation/resource phases.
/// Phase 2 constructs only the explicit unavailable/absent values below.
#[derive(Clone, Debug)]
pub(crate) struct ObservationFacts {
    pub(crate) installation_status: String,
    pub(crate) realization: Option<String>,
    pub(crate) readiness_status: String,
    pub(crate) freshness: String,
    pub(crate) check_id: Option<String>,
    pub(crate) configuration_id: Option<String>,
    pub(crate) checked_at_ms: Option<u64>,
    pub(crate) fingerprint: Option<String>,
    pub(crate) findings: Vec<ObservationReason>,
    pub(crate) invalidation_reasons: Vec<ObservationReason>,
    pub(crate) blockers: Vec<ObservationReason>,
    pub(crate) unknowns: Vec<ObservationReason>,
    pub(crate) authorization_status: String,
    pub(crate) evaluation_required: bool,
    pub(crate) authorization_reasons: Vec<ObservationReason>,
    pub(crate) loaded_status: String,
    pub(crate) loaded_at_ms: Option<u64>,
    pub(crate) allocation_ids: Vec<String>,
    pub(crate) observed_at_ms: Option<u64>,
}

impl ObservationFacts {
    pub(crate) fn phase_two(scope: &InspectionScope) -> Self {
        let unresolved_binding = matches!(scope, InspectionScope::Binding { .. });
        let unresolved_paths = match scope {
            InspectionScope::Selection(selection) => &selection.unresolved_paths,
            InspectionScope::Binding {
                unresolved_paths, ..
            }
            | InspectionScope::Runtime {
                unresolved_paths, ..
            } => unresolved_paths,
        };
        let mut blockers = vec![
            reason(
                "execution_unavailable",
                "execution",
                "execution_not_implemented",
            ),
            reason("not_prepared", "installation", "prepare_not_implemented"),
        ];
        blockers.extend(unresolved_paths.iter().map(|path| {
            reason(
                "required_feature_unsupported",
                path,
                "review_supported_fields",
            )
        }));
        Self {
            installation_status: "absent".to_owned(),
            realization: None,
            readiness_status: "not_checked".to_owned(),
            freshness: "not_applicable".to_owned(),
            check_id: None,
            configuration_id: None,
            checked_at_ms: None,
            fingerprint: None,
            findings: Vec::new(),
            invalidation_reasons: Vec::new(),
            blockers,
            unknowns: vec![reason(
                "hardware_unknown",
                "hardware",
                "resource_checks_not_implemented",
            )],
            authorization_status: "unavailable".to_owned(),
            evaluation_required: !matches!(scope, InspectionScope::Runtime { .. }),
            authorization_reasons: vec![reason(
                "execution_unavailable",
                "execution_authorization",
                "execution_not_implemented",
            )],
            loaded_status: if unresolved_binding {
                "unknown"
            } else {
                "not_loaded"
            }
            .to_owned(),
            loaded_at_ms: None,
            allocation_ids: Vec::new(),
            observed_at_ms: None,
        }
    }

    pub(crate) fn eligibility_status(&self) -> &'static str {
        if !self.blockers.is_empty()
            || self.installation_status == "absent"
            || self.readiness_status == "failed"
            || self.authorization_status == "denied"
            || self.freshness == "stale"
        {
            "blocked"
        } else if !self.unknowns.is_empty()
            || self.installation_status == "unknown"
            || self.readiness_status == "unknown"
            || self.readiness_status == "not_checked"
            || self.authorization_status == "unknown"
            || self.authorization_status == "unavailable"
            || self.freshness == "unknown"
        {
            "unknown"
        } else if self.installation_status == "present"
            && self.readiness_status == "passed"
            && self.freshness == "current"
            && self.authorization_status == "allowed"
        {
            "eligible"
        } else {
            "unknown"
        }
    }
}

pub(crate) fn observe(
    scope: &InspectionScope,
    facts: &ObservationFacts,
    evidence: EvidenceObservation,
    tested_profiles: Vec<Value>,
) -> DiscoveryObservation {
    let (api_scope, selection) = match scope {
        InspectionScope::Selection(selection) => (
            ObservationScope::Selection,
            json!({
                "support_ref": selection.support_ref,
                "task": {"id": selection.task.id(), "version": selection.task.version()},
                "runtime_ref": selection.runtime_ref,
                "variant": selection.variant,
            }),
        ),
        InspectionScope::Binding {
            support_ref, task, ..
        } => (
            ObservationScope::Binding,
            json!({
                "support_ref": support_ref,
                "task": {"id": task.id(), "version": task.version()},
                "runtime_ref": null,
                "variant": null,
            }),
        ),
        InspectionScope::Runtime { runtime_ref, .. } => (
            ObservationScope::Runtime,
            json!({"runtime_ref": runtime_ref}),
        ),
    };
    let mut blockers = facts.blockers.clone();
    if matches!(scope, InspectionScope::Binding { .. }) {
        blockers.push(reason(
            "selection_required",
            "selection",
            "select_runtime_and_variant",
        ));
    }
    let eligibility = ObservationFacts {
        blockers: blockers.clone(),
        ..facts.clone()
    };
    DiscoveryObservation {
        scope: api_scope,
        selection,
        observed_at_ms: facts.observed_at_ms,
        evidence,
        tested_profiles,
        installation: InstallationObservation {
            status: facts.installation_status.clone(),
            realization: facts.realization.clone(),
        },
        readiness: ReadinessObservation {
            status: facts.readiness_status.clone(),
            freshness: facts.freshness.clone(),
            check_id: facts.check_id.clone(),
            configuration_id: facts.configuration_id.clone(),
            checked_at_ms: facts.checked_at_ms,
            fingerprint: facts.fingerprint.clone(),
            findings: facts.findings.clone(),
            invalidation_reasons: facts.invalidation_reasons.clone(),
        },
        eligibility: EligibilityObservation {
            status: eligibility.eligibility_status().to_owned(),
            blockers,
            unknowns: facts.unknowns.clone(),
        },
        execution_authorization: ExecutionAuthorizationObservation {
            status: facts.authorization_status.clone(),
            evaluation_required: facts.evaluation_required,
            reasons: facts.authorization_reasons.clone(),
        },
        loaded: (!matches!(scope, InspectionScope::Runtime { .. })).then(|| LoadedObservation {
            status: facts.loaded_status.clone(),
            observed_at_ms: facts.loaded_at_ms,
            allocation_ids: facts.allocation_ids.clone(),
        }),
    }
}

pub(crate) fn for_model_binding(
    catalog: &Catalog,
    model: &ModelRecord,
    task: &TaskBindingRecord,
    explicit: Option<&Selection>,
) -> Result<(InspectionScope, EvidenceObservation, Vec<Value>), DiscoveryError> {
    let make_scope = |selection: &Selection| inspection_selection(catalog, model, task, selection);
    let scope = if let Some(selection) = explicit {
        InspectionScope::Selection(make_scope(selection)?)
    } else {
        let defaults = Selection {
            support_ref: model.support_ref.clone(),
            task: task.task.clone(),
            runtime_ref: None,
            variant: None,
        };
        match make_scope(&defaults) {
            Ok(selection) => InspectionScope::Selection(selection),
            Err(DiscoveryError::AmbiguousSelection { .. } | DiscoveryError::NotFound) => {
                let mut unresolved_paths = model.unresolved_paths.clone();
                unresolved_paths.extend(task.unresolved_paths.clone());
                unresolved_paths.sort();
                unresolved_paths.dedup();
                InspectionScope::Binding {
                    support_ref: model.support_ref.clone(),
                    task: task.task.clone(),
                    unresolved_paths,
                }
            }
            Err(error) => return Err(error),
        }
    };
    let (selected_runtime, selected_variant) = match &scope {
        InspectionScope::Selection(selection) => (
            Some(selection.runtime_ref.as_str()),
            Some(selection.variant.as_str()),
        ),
        _ => (None, None),
    };
    let evidence = model_evidence(model);
    let tested_profiles = model.declaration["tested_profiles"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|profile| {
            profile["task"]["id"] == task.task.id()
                && profile["task"]["version"] == task.task.version()
                && selected_runtime.is_none_or(|v| profile["runtime_ref"] == v)
                && selected_variant.is_none_or(|v| profile["variant"] == v)
        })
        .cloned()
        .collect();
    Ok((scope, evidence, tested_profiles))
}

pub(crate) fn for_runtime(
    runtime: &RuntimeRecord,
) -> (InspectionScope, EvidenceObservation, Vec<Value>) {
    (
        InspectionScope::Runtime {
            runtime_ref: runtime.runtime_ref.clone(),
            unresolved_paths: runtime.unresolved_paths.clone(),
        },
        runtime_evidence(runtime),
        Vec::new(),
    )
}

fn inspection_selection(
    catalog: &Catalog,
    model: &ModelRecord,
    task: &TaskBindingRecord,
    selection: &Selection,
) -> Result<InspectionSelection, DiscoveryError> {
    if selection.task != task.task || catalog.model(&selection.support_ref).is_none() {
        return Err(DiscoveryError::NotFound);
    }
    let runtime_selector = selection
        .runtime_ref
        .as_deref()
        .or_else(|| model.declaration["default_runtime_ref"].as_str())
        .ok_or_else(|| ambiguous(&model.id))?;
    let runtime = catalog
        .runtime(runtime_selector)
        .ok_or(DiscoveryError::NotFound)?;
    let variant_id = selection
        .variant
        .as_deref()
        .or_else(|| model.declaration["default_variant"].as_str())
        .ok_or_else(|| ambiguous(&model.id))?;
    let variant = model.declaration["variants"]
        .as_array()
        .and_then(|variants| {
            variants
                .iter()
                .find(|candidate| candidate["id"] == variant_id)
        })
        .ok_or(DiscoveryError::NotFound)?;
    let compatible = model.declaration["runtime_refs"]
        .as_array()
        .is_some_and(|refs| {
            refs.iter()
                .any(|reference| reference == &runtime.runtime_ref)
        })
        && variant["runtime_refs"].as_array().is_some_and(|refs| {
            refs.iter()
                .any(|reference| reference == &runtime.runtime_ref)
        })
        && variant["task_keys"].as_array().is_some_and(|keys| {
            keys.iter()
                .any(|key| key["id"] == task.task.id() && key["version"] == task.task.version())
        });
    if !compatible {
        return Err(DiscoveryError::NotFound);
    }
    let mut unresolved_paths = model.unresolved_paths.clone();
    unresolved_paths.extend(task.unresolved_paths.clone());
    unresolved_paths.extend(runtime.unresolved_paths.clone());
    unresolved_paths.sort();
    unresolved_paths.dedup();
    Ok(InspectionSelection {
        support_ref: model.support_ref.clone(),
        task: task.task.clone(),
        runtime_ref: runtime.runtime_ref.clone(),
        variant: variant_id.to_owned(),
        unresolved_paths,
    })
}

fn ambiguous(id: &str) -> DiscoveryError {
    DiscoveryError::AmbiguousSelection {
        candidates: vec![id.to_owned()],
        candidates_truncated: false,
    }
}

fn model_evidence(model: &ModelRecord) -> EvidenceObservation {
    let records = model.declaration["evidence"].as_array();
    let ids = records
        .into_iter()
        .flatten()
        .filter_map(|item| item["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let mut limitations = if model.test_only {
        vec!["Synthetic only".to_owned()]
    } else {
        records
            .into_iter()
            .flatten()
            .flat_map(|item| item["limitations"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    limitations.sort();
    limitations.dedup();
    let status = if model.test_only {
        "incomplete"
    } else if ids.is_empty() {
        "unknown"
    } else if limitations.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    EvidenceObservation {
        status: status.to_owned(),
        ids,
        limitations,
    }
}

fn runtime_evidence(runtime: &RuntimeRecord) -> EvidenceObservation {
    let records = runtime.declaration["evidence"].as_array();
    let ids = records
        .into_iter()
        .flatten()
        .filter_map(|item| item["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let mut limitations = if runtime.test_only {
        vec!["Synthetic only".to_owned()]
    } else {
        records
            .into_iter()
            .flatten()
            .flat_map(|item| item["limitations"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    limitations.sort();
    limitations.dedup();
    let status = if runtime.test_only {
        "incomplete"
    } else if ids.is_empty() {
        "unknown"
    } else if limitations.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    EvidenceObservation {
        status: status.to_owned(),
        ids,
        limitations,
    }
}

fn reason(code: &str, field: &str, guidance: &str) -> ObservationReason {
    ObservationReason {
        code: code.to_owned(),
        field: field.to_owned(),
        guidance: guidance.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_do_not_collapse_into_ready() {
        let scope = InspectionScope::Selection(InspectionSelection {
            support_ref: "support@r1".to_owned(),
            task: TaskKey::new("task", "1.0").unwrap(),
            runtime_ref: "runtime@r1".to_owned(),
            variant: "variant".to_owned(),
            unresolved_paths: Vec::new(),
        });
        for (
            case_id,
            installation,
            readiness,
            freshness,
            authorization,
            loaded,
            blockers,
            unknowns,
            expected,
        ) in [
            (
                "SD-PHASE2",
                "absent",
                "not_checked",
                "not_applicable",
                "unavailable",
                "not_loaded",
                vec!["not_prepared"],
                vec!["hardware_unknown"],
                "blocked",
            ),
            (
                "SD-V17",
                "present",
                "passed",
                "stale",
                "allowed",
                "not_loaded",
                vec!["readiness_stale"],
                vec![],
                "blocked",
            ),
            (
                "SD-V19",
                "present",
                "not_checked",
                "unknown",
                "allowed",
                "not_loaded",
                vec![],
                vec!["hardware_unknown"],
                "unknown",
            ),
            (
                "SD-V20",
                "present",
                "passed",
                "current",
                "denied",
                "not_loaded",
                vec!["authorization_denied"],
                vec![],
                "blocked",
            ),
            (
                "SD-ELIGIBLE-FUTURE",
                "present",
                "passed",
                "current",
                "allowed",
                "not_loaded",
                vec![],
                vec![],
                "eligible",
            ),
        ] {
            let mut facts = ObservationFacts::phase_two(&scope);
            facts.installation_status = installation.to_owned();
            facts.readiness_status = readiness.to_owned();
            facts.freshness = freshness.to_owned();
            facts.authorization_status = authorization.to_owned();
            facts.loaded_status = loaded.to_owned();
            facts.blockers = blockers
                .iter()
                .map(|code| reason(code, "state", "resolve_state"))
                .collect();
            facts.unknowns = unknowns
                .iter()
                .map(|code| reason(code, "state", "check_state"))
                .collect();
            assert_eq!(facts.eligibility_status(), expected, "{case_id}");
            let observation = observe(
                &scope,
                &facts,
                EvidenceObservation {
                    status: "unknown".into(),
                    ids: vec![],
                    limitations: vec![],
                },
                vec![],
            );
            assert_eq!(observation.installation.status, installation, "{case_id}");
            assert_eq!(observation.readiness.status, readiness, "{case_id}");
            assert_eq!(observation.readiness.freshness, freshness, "{case_id}");
            assert_eq!(observation.eligibility.status, expected, "{case_id}");
            assert_eq!(
                observation.execution_authorization.status, authorization,
                "{case_id}"
            );
            assert_eq!(
                observation.loaded.as_ref().unwrap().status,
                loaded,
                "{case_id}"
            );
        }
    }

    #[test]
    fn evaluation_cannot_clear_hard_blockers() {
        let scope = InspectionScope::Runtime {
            runtime_ref: "runtime@r1".to_owned(),
            unresolved_paths: Vec::new(),
        };
        let mut facts = ObservationFacts::phase_two(&scope);
        facts.installation_status = "present".into();
        facts.readiness_status = "passed".into();
        facts.freshness = "current".into();
        facts.authorization_status = "allowed".into();
        facts.evaluation_required = true;
        facts.blockers = vec![
            reason("integrity_failed", "assets", "repair_assets"),
            reason("rights_denied", "rights", "review_rights"),
        ];
        assert_eq!(facts.eligibility_status(), "blocked", "SD-V18");
        let observation = observe(
            &scope,
            &facts,
            EvidenceObservation {
                status: "incomplete".into(),
                ids: vec![],
                limitations: vec![],
            },
            vec![],
        );
        assert_eq!(observation.eligibility.blockers.len(), 2, "SD-V18");
        assert!(observation.execution_authorization.evaluation_required);
    }
}
