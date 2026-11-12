// Step 2 supplementary regressions; protected packages/assertions stay unchanged.
mod selection_regressions {
    use super::*;
    use serde_json::json;

    const MODEL: &str = "test.mesh-copy@fixture-r1";
    const RUNTIME: &str = "test.cpu@fixture-r1";

    fn selection(version: &str, runtime: &str) -> Selection {
        Selection {
            support_ref: "test-current".into(),
            task: TaskKey::new("dissect3d.test.mesh-copy", version).unwrap(),
            runtime_ref: Some(runtime.into()),
            variant: Some("fixture".into()),
        }
    }

    fn profile(version: &str, runtime: &str) -> Value {
        json!({"id":"relationship-profile", "task":{"id":"dissect3d.test.mesh-copy",
            "version":version}, "runtime_ref":runtime, "variant":"fixture",
            "platform":"synthetic", "evidence_ids":[]})
    }

    fn package() -> ControlledPackage {
        let mut package = fixture_package();
        // Both task versions and both runtimes exist. Only v1/runtime1 is in the variant.
        let position = document_position(&package, "runtime", RUNTIME);
        let mut runtime: Value = serde_json::from_slice(&package.document_bytes[position]).unwrap();
        runtime["runtime_ref"] = json!("test.other@fixture-r1");
        let bytes = serde_json::to_vec(&runtime).unwrap();
        mutate_index(&mut package, |index| {
            let mut entry = index["documents"][position].clone();
            entry["ref"] = runtime["runtime_ref"].clone();
            entry["sha256"] = json!(digest(&bytes));
            entry["byte_length"] = json!(bytes.len());
            index["documents"].as_array_mut().unwrap().push(entry);
        });
        package.document_bytes.push(bytes);
        mutate_document(&mut package, "support", MODEL, |doc| {
            let mut task = doc["tasks"][0].clone();
            task["task"]["version"] = json!("2.0");
            doc["tasks"].as_array_mut().unwrap().push(task);
            doc["runtime_refs"]
                .as_array_mut()
                .unwrap()
                .push(json!("test.other@fixture-r1"));
            doc["tested_profiles"] = json!([profile("1.0", RUNTIME)]);
        });
        package
    }

    fn inspect(
        catalog: &Catalog,
        selected: &Selection,
    ) -> Result<
        (
            observations::InspectionScope,
            dissect3d_api::EvidenceObservation,
            Vec<Value>,
        ),
        DiscoveryError,
    > {
        let model = catalog.model(&selected.support_ref).unwrap();
        let binding = model
            .tasks
            .iter()
            .find(|binding| binding.task == selected.task)
            .unwrap();
        for_model_binding(catalog, model, binding, Some(selected))
    }

    #[test]
    fn variant_excludes_existing_task_profile() {
        let mut package = package();
        mutate_document(&mut package, "support", MODEL, |doc| {
            doc["tested_profiles"][0] = profile("2.0", RUNTIME);
        });
        assert_eq!(
            Catalog::from_packages(vec![package], DiscoveryLimits::default()).unwrap_err(),
            CatalogError::InvalidPackage
        );
        let catalog =
            Catalog::from_packages(vec![self::package()], DiscoveryLimits::default()).unwrap();
        let selected = selection("2.0", RUNTIME);
        assert!(matches!(
            catalog.resolve(&selected),
            Err(DiscoveryError::NotFound)
        ));
        assert!(matches!(
            inspect(&catalog, &selected),
            Err(DiscoveryError::NotFound)
        ));
    }

    #[test]
    fn variant_excludes_existing_runtime_profile() {
        let mut package = package();
        mutate_document(&mut package, "support", MODEL, |doc| {
            doc["tested_profiles"][0] = profile("1.0", "test.other@fixture-r1");
        });
        assert_eq!(
            Catalog::from_packages(vec![package], DiscoveryLimits::default()).unwrap_err(),
            CatalogError::InvalidPackage
        );
        let catalog =
            Catalog::from_packages(vec![self::package()], DiscoveryLimits::default()).unwrap();
        let selected = selection("1.0", "test.other@fixture-r1");
        assert!(matches!(
            catalog.resolve(&selected),
            Err(DiscoveryError::NotFound)
        ));
        assert!(matches!(
            inspect(&catalog, &selected),
            Err(DiscoveryError::NotFound)
        ));
    }

    #[test]
    fn exact_valid_combination_is_declaration_only() {
        let catalog = Catalog::from_packages(vec![package()], DiscoveryLimits::default()).unwrap();
        let selected = selection("1.0", RUNTIME);
        let resolved = catalog.resolve(&selected).unwrap();
        let (scope, evidence, profiles) = inspect(&catalog, &selected).unwrap();
        let observations::InspectionScope::Selection(exact) = &scope else {
            panic!("exact selection")
        };
        assert_eq!(exact.support_ref, resolved.support_ref);
        assert_eq!(exact.task, resolved.task);
        assert_eq!(exact.runtime_ref, resolved.runtime_ref);
        assert_eq!(exact.variant, resolved.variant);
        assert_eq!(profiles, vec![profile("1.0", RUNTIME)]);
        let facts = ObservationFacts::phase_two(&scope);
        let observation = observe(&scope, &facts, evidence, profiles);
        assert_eq!(observation.installation.status, "absent");
        assert_eq!(observation.readiness.status, "not_checked");
        assert_eq!(observation.execution_authorization.status, "unavailable");
        assert_eq!(observation.eligibility.status, "blocked");
        assert_eq!(observation.eligibility.unknowns[0].code, "hardware_unknown");
        assert_eq!(observation.loaded.unwrap().status, "not_loaded");
        assert!(catalog.model(MODEL).unwrap().test_only);
    }

    #[test]
    fn task_versions_do_not_merge_profile_evidence() {
        let mut package = package();
        mutate_document(&mut package, "support", MODEL, |doc| {
            doc["variants"][0]["task_keys"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"dissect3d.test.mesh-copy", "version":"2.0"}));
        });
        let catalog = Catalog::from_packages(vec![package], DiscoveryLimits::default()).unwrap();
        for version in ["1.0", "2.0"] {
            let selected = selection(version, RUNTIME);
            assert_eq!(catalog.resolve(&selected).unwrap().task.version(), version);
            let (_, _, profiles) = inspect(&catalog, &selected).unwrap();
            assert_eq!(profiles.len(), usize::from(version == "1.0"));
        }
    }

    #[test]
    fn evaluation_cannot_bypass_known_incompatibility() {
        let catalog = Catalog::from_packages(vec![package()], DiscoveryLimits::default()).unwrap();
        let selected = selection("2.0", RUNTIME);
        assert!(matches!(
            catalog.resolve(&selected),
            Err(DiscoveryError::NotFound)
        ));
        assert!(matches!(
            inspect(&catalog, &selected),
            Err(DiscoveryError::NotFound)
        ));
        // Exercise the existing pure observation boundary with otherwise positive facts.
        let model = catalog.model(MODEL).unwrap();
        let (scope, evidence, profiles) =
            for_model_binding(&catalog, model, &model.tasks[1], None).unwrap();
        let mut facts = ObservationFacts::phase_two(&scope);
        facts.installation_status = "present".into();
        facts.readiness_status = "passed".into();
        facts.freshness = "current".into();
        facts.authorization_status = "allowed".into();
        facts.evaluation_required = false;
        facts.blockers.clear();
        facts.unknowns.clear();
        let observation = observe(&scope, &facts, evidence, profiles);
        assert_eq!(observation.eligibility.status, "blocked");
        assert!(
            observation
                .eligibility
                .blockers
                .iter()
                .any(|reason| reason.code == "selection_required")
        );
    }

    #[test]
    fn unknown_required_semantics_stay_inspectable_unresolved() {
        for target in ["support", "task", "runtime"] {
            let mut package = package();
            if target == "runtime" {
                mutate_document(&mut package, "runtime", RUNTIME, |doc| {
                    doc["required_features"] = json!(["future-runtime"]);
                });
            } else {
                mutate_document(&mut package, "support", MODEL, |doc| {
                    if target == "task" {
                        doc["tasks"][0]["required_features"] = json!(["future-task"]);
                    } else {
                        doc["required_features"] = json!(["future-support"]);
                    }
                });
            }
            let catalog =
                Catalog::from_packages(vec![package.clone()], DiscoveryLimits::default()).unwrap();
            let selected = selection("1.0", RUNTIME);
            assert!(matches!(
                catalog.resolve(&selected),
                Err(DiscoveryError::RequiredFeatureUnsupported)
            ));
            let (scope, _, profiles) = inspect(&catalog, &selected).unwrap();
            let observations::InspectionScope::Selection(exact) = scope else {
                panic!("inspectable")
            };
            assert!(!exact.unresolved_paths.is_empty(), "{target}");
            assert_eq!(profiles.len(), 1);
            // Unknown semantics cannot hide a separately provable contradiction.
            mutate_document(&mut package, "support", MODEL, |doc| {
                doc["tested_profiles"][0] = profile("2.0", RUNTIME);
            });
            assert_eq!(
                Catalog::from_packages(vec![package], DiscoveryLimits::default()).unwrap_err(),
                CatalogError::InvalidPackage
            );
        }
    }
}
