//! Validation of support declarations into catalog records.

use super::*;

pub(super) fn validate_support(
    reference: &str,
    raw: &RawDocument,
    schemas: &BTreeMap<(String, String), SchemaRecord>,
    runtimes: &BTreeMap<String, RuntimeRecord>,
) -> Result<ModelRecord, CatalogError> {
    validate_support_inner(reference, raw, schemas, runtimes)
}

pub(super) fn validate_support_inner(
    reference: &str,
    raw: &RawDocument,
    schemas: &BTreeMap<(String, String), SchemaRecord>,
    runtimes: &BTreeMap<String, RuntimeRecord>,
) -> Result<ModelRecord, CatalogError> {
    let value = &raw.value;
    if !exact_keys(
        value,
        &[
            "schema_version",
            "required_features",
            "support_ref",
            "family",
            "implementation",
            "description",
            "limitations",
            "test_only",
            "code",
            "adapter",
            "tasks",
            "assets",
            "runtime_refs",
            "default_runtime_ref",
            "variants",
            "default_variant",
            "rights",
            "resources",
            "lifecycle",
            "tested_profiles",
            "evidence",
        ],
    ) || value["schema_version"] != "1.0"
        || value["support_ref"] != reference
    {
        return Err(CatalogError::InvalidPackage);
    }
    let test_only = value["test_only"]
        .as_bool()
        .ok_or(CatalogError::InvalidPackage)?;
    let mut unresolved_paths = Vec::new();
    if !feature_array(&value["required_features"])
        .ok_or(CatalogError::InvalidPackage)?
        .is_empty()
    {
        unresolved_paths.push("required_features".to_owned());
    }
    for name in ["family", "implementation", "description"] {
        text(&value[name], 4096).ok_or(CatalogError::InvalidPackage)?;
    }
    string_array(&value["limitations"], 1024).ok_or(CatalogError::InvalidPackage)?;
    validate_code(&value["code"])?;
    let adapter = &value["adapter"];
    require_keys(
        adapter,
        &[
            "id",
            "revision",
            "sha256",
            "interface_version",
            "required_worker_features",
        ],
    )?;
    let adapter_id = ident(&adapter["id"])?;
    nonempty_text(&adapter["revision"], 128).ok_or(CatalogError::InvalidPackage)?;
    digest_value(&adapter["sha256"])?;
    ident(&adapter["interface_version"])?;
    if !strings(&adapter["required_worker_features"])
        .ok_or(CatalogError::InvalidPackage)?
        .is_empty()
    {
        unresolved_paths.push("adapter.required_worker_features".to_owned());
    }

    let runtime_refs =
        string_array(&value["runtime_refs"], 1024).ok_or(CatalogError::InvalidPackage)?;
    if runtime_refs
        .iter()
        .any(|r| !valid_reference(r, false) || !runtimes.contains_key(r))
        || has_duplicates(&runtime_refs)
    {
        return Err(CatalogError::InvalidPackage);
    }
    let default_runtime = nullable_reference(&value["default_runtime_ref"])?;
    if default_runtime
        .as_ref()
        .is_some_and(|runtime| !runtime_refs.contains(runtime))
    {
        return Err(CatalogError::InvalidPackage);
    }

    let assets = array(&value["assets"], 1024).ok_or(CatalogError::InvalidPackage)?;
    let mut asset_ids = BTreeSet::new();
    for asset in assets {
        require_keys(
            asset,
            &[
                "id",
                "kind",
                "source",
                "revision",
                "sha256",
                "byte_length",
                "prerequisites",
                "rights_id",
            ],
        )?;
        let id = ident(&asset["id"])?;
        if !asset_ids.insert(id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        for key in ["kind", "source"] {
            text(&asset[key], 4096).ok_or(CatalogError::InvalidPackage)?;
        }
        nonempty_text(&asset["revision"], 128).ok_or(CatalogError::InvalidPackage)?;
        credential_free_provenance(&asset["source"])?;
        digest_value(&asset["sha256"])?;
        safe_integer(&asset["byte_length"]).ok_or(CatalogError::InvalidPackage)?;
        string_array(&asset["prerequisites"], 1024).ok_or(CatalogError::InvalidPackage)?;
        ident(&asset["rights_id"])?;
    }

    let rights = array(&value["rights"], 1024).ok_or(CatalogError::InvalidPackage)?;
    let mut right_ids = BTreeSet::new();
    let component_ids: BTreeSet<String> = asset_ids
        .iter()
        .cloned()
        .chain(std::iter::once(adapter_id.to_owned()))
        .collect();
    for right in rights {
        require_keys(
            right,
            &[
                "id",
                "component_ids",
                "license",
                "notices",
                "source",
                "access_prerequisites",
                "distribution",
                "unresolved",
            ],
        )?;
        let id = ident(&right["id"])?;
        if !right_ids.insert(id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        let components =
            string_array(&right["component_ids"], 1024).ok_or(CatalogError::InvalidPackage)?;
        if components
            .iter()
            .any(|component| !component_ids.contains(component))
        {
            return Err(CatalogError::InvalidPackage);
        }
        for key in ["license", "source"] {
            text(&right[key], 4096).ok_or(CatalogError::InvalidPackage)?;
        }
        credential_free_provenance(&right["source"])?;
        string_array(&right["notices"], 1024).ok_or(CatalogError::InvalidPackage)?;
        string_array(&right["access_prerequisites"], 1024).ok_or(CatalogError::InvalidPackage)?;
        string_array(&right["unresolved"], 1024).ok_or(CatalogError::InvalidPackage)?;
        if !matches!(
            right["distribution"].as_str(),
            Some("allowed" | "denied" | "unknown")
        ) {
            return Err(CatalogError::InvalidPackage);
        }
    }
    for asset in assets {
        if !right_ids.contains(asset["rights_id"].as_str().unwrap_or_default()) {
            return Err(CatalogError::InvalidPackage);
        }
    }
    validate_asset_graph(assets)?;

    let mut declared_tasks = Vec::new();
    let task_values = array(&value["tasks"], 1024).ok_or(CatalogError::InvalidPackage)?;
    let mut task_keys = BTreeSet::new();
    for (index, binding) in task_values.iter().enumerate() {
        require_keys(
            binding,
            &[
                "task",
                "pipeline",
                "input_schema",
                "parameter_schema",
                "output_schema",
                "constraints",
                "preprocessing",
                "required_features",
                "validator",
            ],
        )?;
        let task_obj = &binding["task"];
        require_keys(task_obj, &["id", "version"])?;
        let task = TaskKey::new(
            string(&task_obj["id"]).ok_or(CatalogError::InvalidPackage)?,
            string(&task_obj["version"]).ok_or(CatalogError::InvalidPackage)?,
        )
        .map_err(|_| CatalogError::InvalidPackage)?;
        if !task_keys.insert((task.id().to_owned(), task.version().to_owned())) {
            return Err(CatalogError::InvalidPackage);
        }
        let pipeline = &binding["pipeline"];
        require_keys(pipeline, &["id", "revision"])?;
        ident(&pipeline["id"])?;
        nonempty_text(&pipeline["revision"], 128).ok_or(CatalogError::InvalidPackage)?;
        let mut attached = Vec::new();
        let mut unresolved = unresolved_paths.clone();
        for (field, usage) in [
            ("input_schema", SchemaUse::Input),
            ("parameter_schema", SchemaUse::Parameters),
            ("output_schema", SchemaUse::Output),
        ] {
            let schema_ref = &binding[field];
            require_keys(schema_ref, &["id", "version", "sha256"])?;
            let id = ident(&schema_ref["id"])?;
            let version = version_value(&schema_ref["version"])?;
            let digest = digest_value(&schema_ref["sha256"])?;
            let schema = schemas
                .get(&(id.to_owned(), version.to_owned()))
                .ok_or(CatalogError::InvalidPackage)?;
            if schema.sha256 != digest {
                return Err(CatalogError::InvalidPackage);
            }
            validate_schema_use(schema, usage)?;
            attached.push(SchemaAttachment {
                document: schema.document.clone(),
                sha256: schema.sha256.clone(),
            });
            unresolved.extend(
                schema
                    .unresolved_paths
                    .iter()
                    .map(|path| format!("{field}.{path}")),
            );
        }
        validate_preprocessing(&binding["preprocessing"])?;
        if !feature_array(&binding["required_features"])
            .ok_or(CatalogError::InvalidPackage)?
            .is_empty()
        {
            unresolved.push(format!("tasks[{index}].required_features"));
        }
        let validator = &binding["validator"];
        require_keys(validator, &["id", "revision"])?;
        let validator_id = ident(&validator["id"])?;
        nonempty_text(&validator["revision"], 128).ok_or(CatalogError::InvalidPackage)?;
        let input_schema = schema_for_binding(binding, "input_schema", schemas)?;
        let parameter_schema = schema_for_binding(binding, "parameter_schema", schemas)?;
        let output_schema = schema_for_binding(binding, "output_schema", schemas)?;
        let known_validator = test_only
            && validator_id == dissect3d_api::TEST_OUTPUT_VALIDATOR_ID
            && validator["revision"] == dissect3d_api::TEST_OUTPUT_VALIDATOR_REVISION;
        if !known_validator {
            unresolved.push(format!("tasks[{index}].validator"));
        }
        validate_constraints(
            &binding["constraints"],
            &input_schema,
            &parameter_schema,
            &output_schema,
            known_validator,
            &mut unresolved,
            &format!("tasks[{index}].constraints"),
        )?;
        let task_id = digest(
            format!(
                "task\n{}@{}\n{}\n{}\n",
                task.id(),
                task.version(),
                reference,
                raw.digest
            )
            .as_bytes(),
        );
        let task_id = format!("tsk_{task_id}");
        let task_record = TaskBindingRecord {
            id: task_id,
            task: task.clone(),
            support_ref: reference.to_owned(),
            description: value["description"].as_str().unwrap_or_default().to_owned(),
            binding: binding.clone(),
            schemas: attached,
            unresolved_paths: unresolved,
        };
        declared_tasks.push((task, task_record));
    }

    let variants = array(&value["variants"], 1024).ok_or(CatalogError::InvalidPackage)?;
    let mut variant_ids = BTreeSet::new();
    for variant in variants {
        require_keys(
            variant,
            &[
                "id",
                "components",
                "offload",
                "task_keys",
                "runtime_refs",
                "constraints",
                "evidence_ids",
            ],
        )?;
        let variant_id = ident(&variant["id"])?;
        if !variant_ids.insert(variant_id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        if variant["offload"].as_bool().is_none() {
            return Err(CatalogError::InvalidPackage);
        }
        let variant_tasks =
            array(&variant["task_keys"], 1024).ok_or(CatalogError::InvalidPackage)?;
        let mut variant_task_keys = BTreeSet::new();
        for key in variant_tasks {
            require_keys(key, &["id", "version"])?;
            let parsed = TaskKey::new(
                string(&key["id"]).ok_or(CatalogError::InvalidPackage)?,
                string(&key["version"]).ok_or(CatalogError::InvalidPackage)?,
            )
            .map_err(|_| CatalogError::InvalidPackage)?;
            if !task_keys.contains(&(parsed.id().to_owned(), parsed.version().to_owned()))
                || !variant_task_keys.insert((parsed.id().to_owned(), parsed.version().to_owned()))
            {
                return Err(CatalogError::InvalidPackage);
            }
        }
        let variant_runtimes =
            string_array(&variant["runtime_refs"], 1024).ok_or(CatalogError::InvalidPackage)?;
        if variant_runtimes.iter().any(|r| !runtime_refs.contains(r))
            || has_duplicates(&variant_runtimes)
        {
            return Err(CatalogError::InvalidPackage);
        }
        string_array(&variant["evidence_ids"], 1024).ok_or(CatalogError::InvalidPackage)?;
        for component in array(&variant["components"], 1024).ok_or(CatalogError::InvalidPackage)? {
            require_keys(component, &["id", "precision", "quantization"])?;
            let component_id = ident(&component["id"])?;
            if !asset_ids.contains(component_id) && component_id != adapter_id {
                return Err(CatalogError::InvalidPackage);
            }
            text(&component["precision"], 4096).ok_or(CatalogError::InvalidPackage)?;
            if !component["quantization"].is_null() {
                require_keys(
                    &component["quantization"],
                    &["method", "revision", "parameters"],
                )?;
                text(&component["quantization"]["method"], 4096)
                    .ok_or(CatalogError::InvalidPackage)?;
                ident(&component["quantization"]["revision"])?;
                let params = component["quantization"]["parameters"]
                    .as_object()
                    .ok_or(CatalogError::InvalidPackage)?;
                if params.len() > 1024
                    || params
                        .iter()
                        .any(|(k, v)| !valid_name(k) || text(v, 4096).is_none())
                {
                    return Err(CatalogError::InvalidPackage);
                }
            }
        }
        validate_constraints(
            &variant["constraints"],
            &all_task_schema(&declared_tasks, "input_schema", schemas)?,
            &all_task_schema(&declared_tasks, "parameter_schema", schemas)?,
            &all_task_schema(&declared_tasks, "output_schema", schemas)?,
            test_only,
            &mut unresolved_paths,
            "variants.constraints",
        )?;
    }
    let default_variant = nullable_string(&value["default_variant"])?;
    if let Some(default) = &default_variant
        && !variant_ids.contains(default)
    {
        return Err(CatalogError::InvalidPackage);
    }
    if !test_only
        && (assets.is_empty()
            || rights.is_empty()
            || runtime_refs.is_empty()
            || variants.is_empty()
            || declared_tasks.is_empty())
    {
        return Err(CatalogError::InvalidPackage);
    }
    validate_resources_lifecycle(value)?;
    let evidence_ids = validate_evidence(&value["evidence"])?;
    let resource_evidence = string_array(&value["resources"]["evidence_ids"], 1024)
        .ok_or(CatalogError::InvalidPackage)?;
    if resource_evidence
        .iter()
        .any(|id| !evidence_ids.contains(id))
    {
        return Err(CatalogError::InvalidPackage);
    }
    validate_tested_profiles(value, &declared_tasks, &evidence_ids)?;
    for variant in variants {
        if string_array(&variant["evidence_ids"], 1024)
            .unwrap_or_default()
            .iter()
            .any(|id| !evidence_ids.contains(id))
        {
            return Err(CatalogError::InvalidPackage);
        }
    }
    for asset in assets {
        if string_array(&asset["prerequisites"], 1024)
            .unwrap_or_default()
            .iter()
            .any(|id| !asset_ids.contains(id))
        {
            return Err(CatalogError::InvalidPackage);
        }
    }
    let id = public_id("support", reference, &raw.digest, "mdl_");
    let mut attached_schemas = Vec::new();
    let mut attached_schema_refs = BTreeSet::new();
    for (_, task) in &declared_tasks {
        for schema in &task.schemas {
            let key = (
                schema.document["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                schema.document["version"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
            if attached_schema_refs.insert(key) {
                attached_schemas.push(schema.clone());
            }
        }
    }
    let model = ModelRecord {
        id,
        support_ref: reference.to_owned(),
        document_sha256: raw.digest.clone(),
        description: value["description"].as_str().unwrap_or_default().to_owned(),
        test_only,
        declaration: value.clone(),
        schemas: attached_schemas,
        #[cfg(test)]
        unresolved: declared_tasks
            .iter()
            .any(|(_, task)| !task.unresolved_paths.is_empty())
            || !unresolved_paths.is_empty(),
        unresolved_paths,
        tasks: declared_tasks.into_iter().map(|(_, task)| task).collect(),
    };
    #[derive(Serialize)]
    struct DetailSize<'a> {
        declaration: &'a Value,
        schemas: &'a [SchemaAttachment],
    }
    let detail = serde_json::to_vec(&DetailSize {
        declaration: &model.declaration,
        schemas: &model.schemas,
    })
    .map_err(|_| CatalogError::InvalidPackage)?;
    if detail.len() > 196_608 {
        return Err(CatalogError::LimitExceeded);
    }
    Ok(model)
}
