//! Strict package decoding, identity construction, declaration validation and resolution.

use super::{
    Catalog, CatalogError, ControlledPackage, DiscoveryLimits, ModelRecord, RuntimeRecord,
    SchemaRecord, TaskBindingRecord,
};
use super::{ObservationFacts, for_model_binding, for_runtime, observe};
use dissect3d_api::{
    ModelDetail, ModelSummary, RuntimeDetail, RuntimeSummary, SchemaAttachment, TaskBindingDetail,
    TaskKey, decode_json,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema_version: String,
    required_features: Vec<String>,
    documents: Vec<Document>,
    aliases: Vec<Alias>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    kind: String,
    #[serde(rename = "ref")]
    reference: String,
    sha256: String,
    byte_length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Alias {
    kind: String,
    name: String,
    target: String,
}

struct RawDocument {
    digest: String,
    bytes: Vec<u8>,
    value: Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SchemaUse {
    Input,
    Parameters,
    Output,
}

pub(super) fn build_catalog(
    packages: Vec<ControlledPackage>,
    limits: DiscoveryLimits,
) -> Result<Catalog, CatalogError> {
    let mut aggregate_bytes = 0usize;
    let mut documents = BTreeMap::<(String, String), RawDocument>::new();
    let mut aliases = BTreeMap::<(String, String), String>::new();
    let mut document_rows = BTreeSet::<String>::new();
    let mut alias_rows = BTreeSet::<String>::new();
    let mut record_count = 0usize;

    for package in packages {
        aggregate_bytes = aggregate_bytes
            .checked_add(package.index_bytes.len())
            .ok_or(CatalogError::LimitExceeded)?;
        let index: Index =
            decode_json(&package.index_bytes).map_err(|_| CatalogError::InvalidPackage)?;
        if index.schema_version != "1.0"
            || !index.required_features.is_empty()
            || index.documents.len() != package.document_bytes.len()
            || index.documents.len() > 1024
            || index.aliases.len() > 1024
        {
            return Err(CatalogError::InvalidPackage);
        }
        for (entry, bytes) in index.documents.into_iter().zip(package.document_bytes) {
            aggregate_bytes = aggregate_bytes
                .checked_add(bytes.len())
                .ok_or(CatalogError::LimitExceeded)?;
            if aggregate_bytes > limits.catalog_bytes_max {
                return Err(CatalogError::LimitExceeded);
            }
            if !matches!(entry.kind.as_str(), "support" | "runtime" | "schema")
                || !valid_reference(&entry.reference, entry.kind == "schema")
                || entry.sha256.len() != 64
                || !is_digest(&entry.sha256)
                || usize::try_from(entry.byte_length).ok() != Some(bytes.len())
                || digest(&bytes) != entry.sha256
            {
                return Err(CatalogError::InvalidPackage);
            }
            let value: Value = decode_json(&bytes).map_err(|_| CatalogError::InvalidPackage)?;
            if !bounded_value(&value, 0) {
                return Err(CatalogError::LimitExceeded);
            }
            let key = (entry.kind.clone(), entry.reference.clone());
            if let Some(existing) = documents.get(&key) {
                if existing.digest != entry.sha256 || existing.bytes != bytes {
                    return Err(CatalogError::ConflictingIdentity);
                }
            } else {
                document_rows.insert(format!(
                    "D\t{}\t{}\t{}\n",
                    entry.kind, entry.reference, entry.sha256
                ));
                documents.insert(
                    key,
                    RawDocument {
                        digest: entry.sha256,
                        bytes,
                        value,
                    },
                );
            }
        }
        for alias in index.aliases {
            let target_kind = match alias.kind.as_str() {
                "model" => "support",
                "runtime" => "runtime",
                _ => return Err(CatalogError::InvalidPackage),
            };
            if !valid_name(&alias.name)
                || ["mdl_", "rtp_", "tsk_"]
                    .iter()
                    .any(|prefix| alias.name.starts_with(prefix))
                || !valid_reference(&alias.target, false)
            {
                return Err(CatalogError::InvalidPackage);
            }
            let key = (alias.kind.clone(), alias.name.clone());
            if aliases.insert(key, alias.target.clone()).is_some() {
                return Err(CatalogError::ConflictingIdentity);
            }
            alias_rows.insert(format!(
                "A\t{}\t{}\t{}\n",
                alias.kind, alias.name, alias.target
            ));
            if !documents.contains_key(&(target_kind.to_owned(), alias.target)) {
                // Resolution is checked again after all package inputs have been read.
            }
        }
    }
    if aggregate_bytes > limits.catalog_bytes_max {
        return Err(CatalogError::LimitExceeded);
    }

    for ((kind, _), raw) in &documents {
        if kind == "support" || kind == "runtime" {
            record_count = record_count
                .checked_add(1)
                .ok_or(CatalogError::LimitExceeded)?;
        }
        let _ = raw;
    }
    if record_count > limits.records_max {
        return Err(CatalogError::LimitExceeded);
    }
    for ((kind, _), target) in &aliases {
        let expected = if kind == "model" {
            "support"
        } else {
            "runtime"
        };
        if !documents.contains_key(&(expected.to_owned(), target.clone())) {
            return Err(CatalogError::InvalidPackage);
        }
    }

    let mut schemas = BTreeMap::<(String, String), SchemaRecord>::new();
    for ((kind, reference), raw) in &documents {
        if kind != "schema" {
            continue;
        }
        let (id, version) = reference
            .split_once('@')
            .ok_or(CatalogError::InvalidPackage)?;
        if !exact_keys(
            &raw.value,
            &[
                "schema_version",
                "id",
                "version",
                "required_features",
                "schema",
            ],
        ) || raw.value["schema_version"] != "1.0"
            || raw.value["id"] != id
            || raw.value["version"] != version
        {
            return Err(CatalogError::InvalidPackage);
        }
        let mut unresolved = Vec::new();
        let features =
            feature_array(&raw.value["required_features"]).ok_or(CatalogError::InvalidPackage)?;
        if !features.is_empty() {
            unresolved.push("required_features".to_owned());
        }
        let schema = &raw.value["schema"];
        if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
            return Err(CatalogError::InvalidPackage);
        }
        validate_schema_refs(schema).map_err(|_| CatalogError::InvalidPackage)?;
        validate_schema_tree(schema, schema, &mut unresolved, "schema", 0)
            .map_err(|_| CatalogError::InvalidPackage)?;
        schemas.insert(
            (id.to_owned(), version.to_owned()),
            SchemaRecord {
                sha256: raw.digest.clone(),
                document: raw.value.clone(),
                unresolved_paths: unresolved,
            },
        );
    }

    let mut runtimes = BTreeMap::new();
    for ((kind, reference), raw) in &documents {
        if kind != "runtime" {
            continue;
        }
        let record = validate_runtime(reference, raw)?;
        if runtimes.insert(reference.clone(), record).is_some() {
            return Err(CatalogError::ConflictingIdentity);
        }
    }

    let mut models = BTreeMap::new();
    let mut tasks = BTreeMap::new();
    for ((kind, reference), raw) in &documents {
        if kind != "support" {
            continue;
        }
        let model = validate_support(reference, raw, &schemas, &runtimes)?;
        for task in &model.tasks {
            record_count = record_count
                .checked_add(1)
                .ok_or(CatalogError::LimitExceeded)?;
            if tasks.insert(task.id.clone(), task.clone()).is_some() {
                return Err(CatalogError::ConflictingIdentity);
            }
        }
        if models.insert(reference.clone(), model).is_some() {
            return Err(CatalogError::ConflictingIdentity);
        }
    }
    if record_count > limits.records_max {
        return Err(CatalogError::LimitExceeded);
    }
    let mut model_aliases = BTreeMap::new();
    let mut runtime_aliases = BTreeMap::new();
    for ((kind, name), target) in aliases {
        if kind == "model" {
            if model_aliases.insert(name, target).is_some() {
                return Err(CatalogError::ConflictingIdentity);
            }
        } else if runtime_aliases.insert(name, target).is_some() {
            return Err(CatalogError::ConflictingIdentity);
        }
    }
    let mut preimage = String::from("dissect3d-catalog-v1\n");
    for row in document_rows.into_iter().chain(alias_rows) {
        preimage.push_str(&row);
    }
    let catalog = Catalog {
        revision: digest(preimage.as_bytes()),
        models,
        runtimes,
        tasks,
        model_aliases,
        runtime_aliases,
        limits,
    };
    validate_detail_budgets(&catalog)?;
    Ok(catalog)
}

fn validate_detail_budgets(catalog: &Catalog) -> Result<(), CatalogError> {
    for model in catalog.models.values() {
        let mut observations = Vec::with_capacity(model.tasks.len());
        for binding in &model.tasks {
            let (scope, evidence, tested) = for_model_binding(catalog, model, binding, None)
                .map_err(|_| CatalogError::InvalidPackage)?;
            observations.push(observe(
                &scope,
                &ObservationFacts::phase_two(&scope),
                evidence,
                tested,
            ));
        }
        let item = ModelDetail {
            summary: ModelSummary {
                id: model.id.clone(),
                support_ref: model.support_ref.clone(),
                description: model.description.clone(),
                test_only: model.test_only,
                observations,
            },
            declaration: model.declaration.clone(),
            schemas: model.schemas.clone(),
        };
        ensure_detail_budget(&item, catalog.limits.detail_bytes_max)?;
    }
    for runtime in catalog.runtimes.values() {
        let (scope, evidence, tested) = for_runtime(runtime);
        let item = RuntimeDetail {
            summary: RuntimeSummary {
                id: runtime.id.clone(),
                runtime_ref: runtime.runtime_ref.clone(),
                description: runtime.description.clone(),
                test_only: runtime.test_only,
                observations: vec![observe(
                    &scope,
                    &ObservationFacts::phase_two(&scope),
                    evidence,
                    tested,
                )],
            },
            declaration: runtime.declaration.clone(),
        };
        ensure_detail_budget(&item, catalog.limits.detail_bytes_max)?;
    }
    for binding in catalog.tasks.values() {
        let model = catalog
            .models
            .get(&binding.support_ref)
            .ok_or(CatalogError::InvalidPackage)?;
        let (scope, evidence, tested) = for_model_binding(catalog, model, binding, None)
            .map_err(|_| CatalogError::InvalidPackage)?;
        let item = TaskBindingDetail {
            id: binding.id.clone(),
            task: binding.task.clone(),
            support_ref: binding.support_ref.clone(),
            description: binding.description.clone(),
            test_only: model.test_only,
            observations: vec![observe(
                &scope,
                &ObservationFacts::phase_two(&scope),
                evidence,
                tested,
            )],
            binding: binding.binding.clone(),
            schemas: binding.schemas.clone(),
        };
        ensure_detail_budget(&item, catalog.limits.detail_bytes_max)?;
    }
    Ok(())
}

fn ensure_detail_budget<T: Serialize>(item: &T, maximum: usize) -> Result<(), CatalogError> {
    match serde_json::to_vec(item) {
        Ok(bytes) if bytes.len() <= maximum => Ok(()),
        _ => Err(CatalogError::LimitExceeded),
    }
}

fn validate_support(
    reference: &str,
    raw: &RawDocument,
    schemas: &BTreeMap<(String, String), SchemaRecord>,
    runtimes: &BTreeMap<String, RuntimeRecord>,
) -> Result<ModelRecord, CatalogError> {
    validate_support_inner(reference, raw, schemas, runtimes)
}

fn validate_support_inner(
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
        let known_validator =
            test_only && validator_id == "dissect3d.test.validator" && validator["revision"] == "1";
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
    validate_tested_profiles(
        value,
        &declared_tasks,
        &variant_ids,
        &runtime_refs,
        &evidence_ids,
    )?;
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
    let detail = serde_json::to_vec(
        &serde_json::json!({"declaration":model.declaration,"schemas":model.schemas}),
    )
    .map_err(|_| CatalogError::InvalidPackage)?;
    if detail.len() > 196_608 {
        return Err(CatalogError::LimitExceeded);
    }
    Ok(model)
}

fn validate_runtime(reference: &str, raw: &RawDocument) -> Result<RuntimeRecord, CatalogError> {
    let value = &raw.value;
    require_keys(
        value,
        &[
            "schema_version",
            "required_features",
            "runtime_ref",
            "description",
            "test_only",
            "execution_kind",
            "interpreter",
            "dependencies",
            "platform_constraints",
            "asset_requirements",
            "checks",
            "rights",
            "limitations",
            "evidence",
        ],
    )?;
    if value["schema_version"] != "1.0" || value["runtime_ref"] != reference {
        return Err(CatalogError::InvalidPackage);
    }
    let test_only = value["test_only"]
        .as_bool()
        .ok_or(CatalogError::InvalidPackage)?;
    let kind = string(&value["execution_kind"]).ok_or(CatalogError::InvalidPackage)?;
    if !matches!(kind, "managed_python" | "native_test") {
        return Err(CatalogError::InvalidPackage);
    }
    if kind == "native_test" {
        if !test_only || !value["interpreter"].is_null() {
            return Err(CatalogError::InvalidPackage);
        }
    } else {
        require_keys(&value["interpreter"], &["version", "sha256"])?;
        nonempty_text(&value["interpreter"]["version"], 128).ok_or(CatalogError::InvalidPackage)?;
        digest_value(&value["interpreter"]["sha256"])?;
    }
    text(&value["description"], 4096).ok_or(CatalogError::InvalidPackage)?;
    let required_features =
        feature_array(&value["required_features"]).ok_or(CatalogError::InvalidPackage)?;
    let mut unresolved_paths = Vec::new();
    if !required_features.is_empty() {
        unresolved_paths.push("required_features".to_owned());
    }
    string_array(&value["limitations"], 1024).ok_or(CatalogError::InvalidPackage)?;
    let mut dependency_ids = BTreeSet::new();
    for dependency in array(&value["dependencies"], 1024).ok_or(CatalogError::InvalidPackage)? {
        require_keys(
            dependency,
            &["id", "version", "build", "sha256", "source", "rights_id"],
        )?;
        let id = ident(&dependency["id"])?;
        if !dependency_ids.insert(id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        for key in ["version", "build"] {
            nonempty_text(&dependency[key], 128).ok_or(CatalogError::InvalidPackage)?;
        }
        let rights_id = ident(&dependency["rights_id"])?;
        digest_value(&dependency["sha256"])?;
        text(&dependency["source"], 4096).ok_or(CatalogError::InvalidPackage)?;
        credential_free_provenance(&dependency["source"])?;
        if !value["rights"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|right| right["id"] == rights_id)
        {
            return Err(CatalogError::InvalidPackage);
        }
    }
    if kind == "managed_python" && value["dependencies"].as_array().is_none_or(Vec::is_empty) {
        return Err(CatalogError::InvalidPackage);
    }
    for constraint in
        array(&value["platform_constraints"], 1024).ok_or(CatalogError::InvalidPackage)?
    {
        require_keys(constraint, &["os", "architecture", "driver", "device"])?;
        for key in ["os", "architecture", "driver", "device"] {
            if !constraint[key].is_null() {
                text(&constraint[key], 4096).ok_or(CatalogError::InvalidPackage)?;
            }
        }
    }
    string_array(&value["asset_requirements"], 1024).ok_or(CatalogError::InvalidPackage)?;
    let mut check_ids = BTreeSet::new();
    for check in array(&value["checks"], 1024).ok_or(CatalogError::InvalidPackage)? {
        require_keys(check, &["id", "revision", "description"])?;
        let id = ident(&check["id"])?;
        if !check_ids.insert(id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        nonempty_text(&check["revision"], 128).ok_or(CatalogError::InvalidPackage)?;
        text(&check["description"], 4096).ok_or(CatalogError::InvalidPackage)?;
    }
    validate_runtime_rights(&value["rights"], &dependency_ids)?;
    validate_evidence(&value["evidence"])?;
    let id = public_id("runtime", reference, &raw.digest, "rtp_");
    let detail = serde_json::to_vec(value).map_err(|_| CatalogError::InvalidPackage)?;
    if detail.len() > 196_608 {
        return Err(CatalogError::LimitExceeded);
    }
    Ok(RuntimeRecord {
        id,
        runtime_ref: reference.to_owned(),
        document_sha256: raw.digest.clone(),
        description: value["description"].as_str().unwrap_or_default().to_owned(),
        test_only,
        declaration: value.clone(),
        unresolved_paths,
    })
}

fn validate_runtime_rights(
    value: &Value,
    dependency_ids: &BTreeSet<String>,
) -> Result<(), CatalogError> {
    let rights = array(value, 1024).ok_or(CatalogError::InvalidPackage)?;
    let mut ids = BTreeSet::new();
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
        if !ids.insert(id) {
            return Err(CatalogError::InvalidPackage);
        }
        let components =
            string_array(&right["component_ids"], 1024).ok_or(CatalogError::InvalidPackage)?;
        if components
            .iter()
            .any(|component| !dependency_ids.contains(component))
        {
            return Err(CatalogError::InvalidPackage);
        }
        text(&right["license"], 4096).ok_or(CatalogError::InvalidPackage)?;
        text(&right["source"], 4096).ok_or(CatalogError::InvalidPackage)?;
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
    Ok(())
}

fn validate_code(value: &Value) -> Result<(), CatalogError> {
    require_keys(
        value,
        &[
            "upstream_repository",
            "upstream_revision",
            "executed_repository",
            "executed_revision",
            "patches",
            "build_provenance",
        ],
    )?;
    for key in [
        "upstream_repository",
        "executed_repository",
        "build_provenance",
    ] {
        text(&value[key], 4096).ok_or(CatalogError::InvalidPackage)?;
        credential_free_provenance(&value[key])?;
    }
    for key in ["upstream_revision", "executed_revision"] {
        nonempty_text(&value[key], 128).ok_or(CatalogError::InvalidPackage)?;
    }
    for patch in array(&value["patches"], 1024).ok_or(CatalogError::InvalidPackage)? {
        require_keys(patch, &["id", "sha256"])?;
        ident(&patch["id"])?;
        digest_value(&patch["sha256"])?;
    }
    Ok(())
}

fn validate_preprocessing(value: &Value) -> Result<(), CatalogError> {
    let mut ids = BTreeSet::new();
    for item in array(value, 1024).ok_or(CatalogError::InvalidPackage)? {
        require_keys(item, &["id", "revision", "description"])?;
        let id = ident(&item["id"])?;
        if !ids.insert(id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        nonempty_text(&item["revision"], 128).ok_or(CatalogError::InvalidPackage)?;
        text(&item["description"], 4096).ok_or(CatalogError::InvalidPackage)?;
    }
    Ok(())
}

fn validate_resources_lifecycle(value: &Value) -> Result<(), CatalogError> {
    let resources = &value["resources"];
    require_keys(
        resources,
        &[
            "device",
            "ram_bytes",
            "vram_bytes",
            "workload",
            "evidence_ids",
        ],
    )?;
    text(&resources["device"], 4096).ok_or(CatalogError::InvalidPackage)?;
    for key in ["ram_bytes", "vram_bytes"] {
        if !resources[key].is_null() {
            safe_integer(&resources[key]).ok_or(CatalogError::InvalidPackage)?;
        }
    }
    let workload = text(&resources["workload"], 4096).ok_or(CatalogError::InvalidPackage)?;
    let resource_evidence =
        string_array(&resources["evidence_ids"], 1024).ok_or(CatalogError::InvalidPackage)?;
    if (!resources["ram_bytes"].is_null() || !resources["vram_bytes"].is_null())
        && (workload.is_empty() || resource_evidence.is_empty())
    {
        return Err(CatalogError::InvalidPackage);
    }
    let lifecycle = &value["lifecycle"];
    require_keys(
        lifecycle,
        &["cancellation", "progress", "reuse", "reset", "cleanup"],
    )?;
    for key in ["cancellation", "progress", "reset", "cleanup"] {
        text(&lifecycle[key], 4096).ok_or(CatalogError::InvalidPackage)?;
    }
    if lifecycle["reuse"].as_bool().is_none() {
        return Err(CatalogError::InvalidPackage);
    }
    Ok(())
}

fn validate_tested_profiles(
    value: &Value,
    tasks: &[(TaskKey, TaskBindingRecord)],
    variants: &BTreeSet<String>,
    runtimes: &[String],
    evidence_ids: &BTreeSet<String>,
) -> Result<(), CatalogError> {
    let mut profile_ids = BTreeSet::new();
    for profile in array(&value["tested_profiles"], 1024).ok_or(CatalogError::InvalidPackage)? {
        require_keys(
            profile,
            &[
                "id",
                "task",
                "runtime_ref",
                "variant",
                "platform",
                "evidence_ids",
            ],
        )?;
        let id = ident(&profile["id"])?;
        if !profile_ids.insert(id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        require_keys(&profile["task"], &["id", "version"])?;
        let task = TaskKey::new(
            string(&profile["task"]["id"]).ok_or(CatalogError::InvalidPackage)?,
            string(&profile["task"]["version"]).ok_or(CatalogError::InvalidPackage)?,
        )
        .map_err(|_| CatalogError::InvalidPackage)?;
        if !tasks.iter().any(|(key, _)| key == &task)
            || !runtimes.contains(
                &string(&profile["runtime_ref"])
                    .ok_or(CatalogError::InvalidPackage)?
                    .to_owned(),
            )
            || !variants.contains(string(&profile["variant"]).ok_or(CatalogError::InvalidPackage)?)
        {
            return Err(CatalogError::InvalidPackage);
        }
        text(&profile["platform"], 4096).ok_or(CatalogError::InvalidPackage)?;
        let profile_evidence =
            string_array(&profile["evidence_ids"], 1024).ok_or(CatalogError::InvalidPackage)?;
        if profile_evidence
            .iter()
            .any(|evidence| !evidence_ids.contains(evidence))
        {
            return Err(CatalogError::InvalidPackage);
        }
    }
    Ok(())
}

fn validate_evidence(value: &Value) -> Result<BTreeSet<String>, CatalogError> {
    let mut ids = BTreeSet::new();
    for item in array(value, 1024).ok_or(CatalogError::InvalidPackage)? {
        require_keys(
            item,
            &[
                "id",
                "scope",
                "procedure",
                "observed_result",
                "observed_at",
                "build",
                "hardware",
                "workload",
                "limitations",
                "invalidated_by",
            ],
        )?;
        let id = ident(&item["id"])?;
        if !ids.insert(id.to_owned()) {
            return Err(CatalogError::InvalidPackage);
        }
        for key in [
            "scope",
            "procedure",
            "observed_result",
            "build",
            "hardware",
            "workload",
        ] {
            text(&item[key], 4096).ok_or(CatalogError::InvalidPackage)?;
        }
        if !item["observed_at"].is_null()
            && (item["observed_at"]
                .as_str()
                .is_none_or(|v| !valid_rfc3339(v)))
        {
            return Err(CatalogError::InvalidPackage);
        }
        string_array(&item["limitations"], 1024).ok_or(CatalogError::InvalidPackage)?;
        string_array(&item["invalidated_by"], 1024).ok_or(CatalogError::InvalidPackage)?;
    }
    Ok(ids)
}

fn validate_asset_graph(assets: &[Value]) -> Result<(), CatalogError> {
    let refs: BTreeMap<&str, Vec<&str>> = assets
        .iter()
        .map(|asset| {
            (
                asset["id"].as_str().unwrap_or_default(),
                asset["prerequisites"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect(),
            )
        })
        .collect();
    fn visit<'a>(
        id: &'a str,
        refs: &BTreeMap<&'a str, Vec<&'a str>>,
        stack: &mut BTreeSet<&'a str>,
        done: &mut BTreeSet<&'a str>,
    ) -> bool {
        if done.contains(id) {
            return true;
        }
        if !stack.insert(id) {
            return false;
        }
        for next in refs.get(id).into_iter().flatten() {
            if !visit(next, refs, stack, done) {
                return false;
            }
        }
        stack.remove(id);
        done.insert(id);
        true
    }
    let mut done = BTreeSet::new();
    for id in refs.keys() {
        if !visit(id, &refs, &mut BTreeSet::new(), &mut done) {
            return Err(CatalogError::InvalidPackage);
        }
    }
    Ok(())
}

fn validate_constraints(
    value: &Value,
    input: &Value,
    params: &Value,
    output: &Value,
    known_validator: bool,
    unresolved: &mut Vec<String>,
    prefix: &str,
) -> Result<(), CatalogError> {
    let fields = [
        ("inputs", &input["properties"]),
        ("parameters", &params["properties"]),
        ("outputs", &output["properties"]),
    ];
    for (index, constraint) in array(value, 1024)
        .ok_or(CatalogError::InvalidPackage)?
        .iter()
        .enumerate()
    {
        require_keys(constraint, &["kind", "fields", "validator", "description"])?;
        let kind = text(&constraint["kind"], 128).ok_or(CatalogError::InvalidPackage)?;
        text(&constraint["description"], 4096).ok_or(CatalogError::InvalidPackage)?;
        let names =
            string_array(&constraint["fields"], 1024).ok_or(CatalogError::InvalidPackage)?;
        if names.iter().any(|name| {
            let Some((root, field)) = name.split_once('.') else {
                return true;
            };
            !matches!(root, "inputs" | "parameters" | "outputs")
                || !fields
                    .iter()
                    .find(|(key, _)| *key == root)
                    .is_some_and(|(_, values)| values.get(field).is_some())
        }) {
            return Err(CatalogError::InvalidPackage);
        }
        let validator = &constraint["validator"];
        require_keys(validator, &["id", "revision"])?;
        let validator_id = ident(&validator["id"])?;
        let validator_revision =
            nonempty_text(&validator["revision"], 128).ok_or(CatalogError::InvalidPackage)?;
        let known_kind = matches!(
            kind,
            "alignment" | "requires" | "mutually_exclusive" | "range_relation"
        );
        if known_kind {
            match kind {
                "alignment" | "requires" | "mutually_exclusive" if names.len() < 2 => {
                    return Err(CatalogError::InvalidPackage);
                }
                "range_relation" if names.len() != 2 => return Err(CatalogError::InvalidPackage),
                _ => {}
            }
            if kind == "range_relation" {
                for name in &names {
                    let (root, field) = name.split_once('.').ok_or(CatalogError::InvalidPackage)?;
                    let schema = fields
                        .iter()
                        .find(|(key, _)| *key == root)
                        .map(|(_, value)| *value)
                        .ok_or(CatalogError::InvalidPackage)?;
                    let property = schema.get(field).ok_or(CatalogError::InvalidPackage)?;
                    if !matches!(property["type"].as_str(), Some("integer" | "number")) {
                        return Err(CatalogError::InvalidPackage);
                    }
                }
            }
        }
        if !known_kind
            || !known_validator
            || validator_id != "dissect3d.test.validator"
            || validator_revision != "1"
        {
            unresolved.push(format!("{prefix}[{index}]"));
        }
    }
    Ok(())
}

fn schema_for_binding(
    binding: &Value,
    key: &str,
    schemas: &BTreeMap<(String, String), SchemaRecord>,
) -> Result<Value, CatalogError> {
    let reference = &binding[key];
    let id = string(&reference["id"]).ok_or(CatalogError::InvalidPackage)?;
    let version = string(&reference["version"]).ok_or(CatalogError::InvalidPackage)?;
    Ok(schemas
        .get(&(id.to_owned(), version.to_owned()))
        .ok_or(CatalogError::InvalidPackage)?
        .document["schema"]
        .clone())
}
fn all_task_schema(
    tasks: &[(TaskKey, TaskBindingRecord)],
    key: &str,
    schemas: &BTreeMap<(String, String), SchemaRecord>,
) -> Result<Value, CatalogError> {
    let mut props = Map::new();
    for (_, task) in tasks {
        let schema = task
            .schemas
            .iter()
            .find(|attachment| attachment.document["id"] == task.binding[key]["id"]);
        if let Some(schema) = schema
            && let Some(map) = schema.document["schema"]["properties"].as_object()
        {
            props.extend(map.clone());
        }
    }
    let _ = schemas;
    Ok(serde_json::json!({"properties":props}))
}

fn validate_schema_use(schema: &SchemaRecord, usage: SchemaUse) -> Result<(), CatalogError> {
    let root = &schema.document["schema"];
    if root["type"] != "object"
        || root["additionalProperties"] != false
        || root["properties"].as_object().is_none()
    {
        return Err(CatalogError::InvalidPackage);
    }
    let props = root["properties"]
        .as_object()
        .ok_or(CatalogError::InvalidPackage)?;
    for (name, property) in props {
        match usage {
            SchemaUse::Input => {
                if property["x-role"].as_str() != Some(name.as_str())
                    || string_array(&property["x-media-types"], 1024)
                        .is_none_or(|v| v.is_empty() || v.iter().any(String::is_empty))
                    || string_array(&property["x-representations"], 1024)
                        .is_none_or(|v| v.is_empty() || v.iter().any(String::is_empty))
                    || property["type"] != "array"
                    || property["items"].is_null()
                    || property["minItems"].as_u64().is_none()
                    || property["maxItems"].as_u64().is_none()
                {
                    return Err(CatalogError::InvalidPackage);
                }
            }
            SchemaUse::Output => {
                let policy = &property["x-output-policy"];
                if !exact_keys(policy, &["mandatory", "partial_allowed", "formats"])
                    || policy["mandatory"].as_bool().is_none()
                    || policy["partial_allowed"].as_bool().is_none()
                    || string_array(&policy["formats"], 1024)
                        .is_none_or(|v| v.is_empty() || v.iter().any(String::is_empty))
                {
                    return Err(CatalogError::InvalidPackage);
                }
            }
            SchemaUse::Parameters => {}
        }
    }
    Ok(())
}

fn validate_schema_tree(
    root: &Value,
    value: &Value,
    unresolved: &mut Vec<String>,
    path: &str,
    depth: usize,
) -> Result<(), ()> {
    if depth > 32 {
        return Err(());
    }
    let object = value.as_object().ok_or(())?;
    if object.len() > 1024 {
        return Err(());
    }
    const KNOWN: &[&str] = &[
        "$schema",
        "$defs",
        "$ref",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "const",
        "default",
        "title",
        "description",
        "x-role",
        "x-media-types",
        "x-representations",
        "x-output-policy",
    ];
    for (key, child) in object {
        if !KNOWN.contains(&key.as_str()) {
            unresolved.push(format!("{path}.{key}"));
        }
        match key.as_str() {
            "$schema" => {
                if child.as_str() != Some("https://json-schema.org/draft/2020-12/schema") {
                    return Err(());
                }
            }
            "$ref" => {
                if child.as_str().is_none() {
                    return Err(());
                }
            }
            "type" => {
                if !matches!(
                    child.as_str(),
                    Some("object" | "array" | "string" | "boolean" | "integer" | "number")
                ) {
                    return Err(());
                }
            }
            "properties" | "$defs" => {
                let map = child.as_object().ok_or(())?;
                if map.len() > 1024 {
                    return Err(());
                }
                for (name, sub) in map {
                    if !valid_name(name) {
                        return Err(());
                    }
                    validate_schema_tree(
                        root,
                        sub,
                        unresolved,
                        &format!("{path}.{key}.{name}"),
                        depth + 1,
                    )?;
                }
            }
            "items" => {
                validate_schema_tree(root, child, unresolved, &format!("{path}.items"), depth + 1)?
            }
            "required" => {
                let vals = strings(child).ok_or(())?;
                if has_duplicates(&vals) {
                    return Err(());
                }
            }
            "additionalProperties" => {
                if child.as_bool() != Some(false) {
                    return Err(());
                }
            }
            "minItems" | "maxItems" | "minLength" | "maxLength" => {
                if safe_integer(child).is_none() {
                    return Err(());
                }
            }
            "minimum" | "maximum" => {
                if child.as_f64().is_none() {
                    return Err(());
                }
            }
            "enum" => {
                let vals = child.as_array().filter(|a| !a.is_empty()).ok_or(())?;
                for i in 0..vals.len() {
                    if vals[..i].contains(&vals[i]) {
                        return Err(());
                    }
                }
            }
            "title" | "description" | "x-role" => {
                if child.as_str().is_none_or(|s| s.len() > 4096) {
                    return Err(());
                }
            }
            "x-media-types" | "x-representations" => {
                if strings(child).is_none_or(|a| a.is_empty()) {
                    return Err(());
                }
            }
            "x-output-policy"
                if !exact_keys(child, &["mandatory", "partial_allowed", "formats"])
                    || child["mandatory"].as_bool().is_none()
                    || child["partial_allowed"].as_bool().is_none()
                    || strings(&child["formats"]).is_none_or(|v| v.is_empty()) =>
            {
                return Err(());
            }
            _ => {}
        }
    }
    if object.get("type").and_then(Value::as_str) == Some("object") {
        if object.get("additionalProperties") != Some(&Value::Bool(false)) {
            return Err(());
        }
        let props = object
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(())?;
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && required
                .iter()
                .any(|name| name.as_str().is_none_or(|name| !props.contains_key(name)))
        {
            return Err(());
        }
    }
    if object.get("type").and_then(Value::as_str) == Some("array") && object.get("items").is_none()
    {
        return Err(());
    }
    for (min, max) in [
        ("minItems", "maxItems"),
        ("minLength", "maxLength"),
        ("minimum", "maximum"),
    ] {
        if let (Some(a), Some(b)) = (
            object.get(min).and_then(Value::as_f64),
            object.get(max).and_then(Value::as_f64),
        ) && a > b
        {
            return Err(());
        }
    }
    if let Some(default) = object.get("default") {
        match value_matches(root, value, default, 0, 0) {
            Some(false) => return Err(()),
            None => unresolved.push(format!("{path}.default")),
            Some(true) => {}
        }
    }
    if let Some(constant) = object.get("const")
        && value_matches(root, value, constant, 0, 0) == Some(false)
    {
        return Err(());
    }
    if let Some(values) = object.get("enum").and_then(Value::as_array)
        && object.get("type").is_some_and(|ty| {
            values
                .iter()
                .any(|v| !matches_type(ty.as_str().unwrap_or_default(), v))
        })
    {
        return Err(());
    }
    Ok(())
}

fn has_unknown_schema_keyword(root: &Value, value: &Value, edges: usize) -> bool {
    if edges > 16 {
        return true;
    }
    const KNOWN: &[&str] = &[
        "$schema",
        "$defs",
        "$ref",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "const",
        "default",
        "title",
        "description",
        "x-role",
        "x-media-types",
        "x-representations",
        "x-output-policy",
    ];
    let Some(object) = value.as_object() else {
        return false;
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix("#/$defs/")
            .and_then(|name| root.get("$defs")?.get(name))
            .is_none_or(|target| has_unknown_schema_keyword(root, target, edges + 1));
    }
    object.iter().any(|(key, child)| {
        !KNOWN.contains(&key.as_str())
            || match key.as_str() {
                "properties" | "$defs" => child.as_object().is_some_and(|items| {
                    items
                        .values()
                        .any(|sub| has_unknown_schema_keyword(root, sub, edges))
                }),
                "items" => has_unknown_schema_keyword(root, child, edges),
                "x-output-policy" => false,
                _ => false,
            }
    })
}

fn validate_schema_refs(root: &Value) -> Result<(), ()> {
    let defs = root
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    fn scan(
        value: &Value,
        defs: &Map<String, Value>,
        stack: &mut Vec<String>,
        edges: usize,
        depth: usize,
    ) -> Result<(), ()> {
        let object = value.as_object().ok_or(())?;
        // Count expanded containers, not reference hops or the $defs storage map.
        let depth = depth
            + usize::from(
                matches!(
                    object.get("type").and_then(Value::as_str),
                    Some("object" | "array")
                ) || object.contains_key("properties")
                    || object.contains_key("items"),
            );
        if depth > 32 {
            return Err(());
        }
        if let Some(reference) = object.get("$ref") {
            let reference = reference.as_str().ok_or(())?;
            let name = reference.strip_prefix("#/$defs/").ok_or(())?;
            if name.is_empty() || name.contains('/') || name.contains('~') || !valid_name(name) {
                return Err(());
            }
            let target = defs.get(name).ok_or(())?;
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "$ref" | "title" | "description"))
            {
                return Err(());
            }
            if edges >= 16 || stack.contains(&name.to_owned()) {
                return Err(());
            }
            stack.push(name.to_owned());
            scan(target, defs, stack, edges + 1, depth)?;
            stack.pop();
        }
        for (key, child) in object {
            if key == "$defs" {
                continue;
            }
            if matches!(key.as_str(), "properties" | "items") {
                if key == "properties" {
                    for sub in child.as_object().ok_or(())?.values() {
                        scan(sub, defs, stack, edges, depth)?;
                    }
                } else {
                    scan(child, defs, stack, edges, depth)?;
                }
            }
        }
        Ok(())
    }
    scan(root, &defs, &mut Vec::new(), 0, 0)?;
    for def in defs.values() {
        scan(def, &defs, &mut Vec::new(), 0, 0)?;
    }
    Ok(())
}

fn value_matches(
    root: &Value,
    schema: &Value,
    value: &Value,
    depth: usize,
    edges: usize,
) -> Option<bool> {
    if depth > 32 || edges > 16 {
        return Some(false);
    }
    let object = schema.as_object()?;
    // References are structurally checked before any const/default evaluation.
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let name = reference.strip_prefix("#/$defs/")?;
        let target = root.get("$defs")?.get(name)?;
        return value_matches(root, target, value, depth, edges + 1);
    }
    let mut unknown = has_unknown_schema_keyword(root, schema, edges);
    if let Some(ty) = object.get("type").and_then(Value::as_str)
        && !matches_type(ty, value)
    {
        return Some(false);
    }
    if let Some(c) = object.get("const")
        && c != value
    {
        return Some(false);
    }
    if let Some(list) = object.get("enum").and_then(Value::as_array)
        && !list.contains(value)
    {
        return Some(false);
    }
    if let Some(n) = value.as_f64()
        && (object
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|min| n < min)
            || object
                .get("maximum")
                .and_then(Value::as_f64)
                .is_some_and(|max| n > max))
    {
        return Some(false);
    }
    if let Some(s) = value.as_str() {
        let len = s.chars().count();
        if object
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| (len as u64) < min)
            || object
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|max| (len as u64) > max)
        {
            return Some(false);
        }
    }
    if let Some(items) = value.as_array() {
        if object
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|min| (items.len() as u64) < min)
            || object
                .get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|max| (items.len() as u64) > max)
        {
            return Some(false);
        }
        if let Some(item_schema) = object.get("items") {
            for item in items {
                match value_matches(root, item_schema, item, depth + 1, edges) {
                    Some(false) => return Some(false),
                    None => unknown = true,
                    Some(true) => {}
                }
            }
        }
    }
    if let Some(fields) = value.as_object() {
        if object.get("additionalProperties") == Some(&Value::Bool(false)) {
            let props = object.get("properties").and_then(Value::as_object)?;
            if fields.keys().any(|key| !props.contains_key(key)) {
                return Some(false);
            }
        }
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && required
                .iter()
                .filter_map(Value::as_str)
                .any(|key| !fields.contains_key(key))
        {
            return Some(false);
        }
        if let Some(props) = object.get("properties").and_then(Value::as_object) {
            for (key, subschema) in props {
                if let Some(item) = fields.get(key) {
                    match value_matches(root, subschema, item, depth + 1, edges) {
                        Some(false) => return Some(false),
                        None => unknown = true,
                        Some(true) => {}
                    }
                }
            }
        }
    }
    if unknown { None } else { Some(true) }
}

fn matches_type(name: &str, value: &Value) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.as_f64().is_some(),
        _ => false,
    }
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}
fn require_keys(value: &Value, keys: &[&str]) -> Result<(), CatalogError> {
    if exact_keys(value, keys) {
        Ok(())
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
fn array(value: &Value, max: usize) -> Option<&[Value]> {
    value
        .as_array()
        .filter(|items| items.len() <= max)
        .map(Vec::as_slice)
}
fn string(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !s.is_empty() && s.len() <= 4096)
}
fn text(value: &Value, max: usize) -> Option<&str> {
    value.as_str().filter(|s| s.len() <= max)
}
fn nonempty_text(value: &Value, max: usize) -> Option<&str> {
    text(value, max).filter(|s| !s.is_empty())
}
fn ident(value: &Value) -> Result<&str, CatalogError> {
    let value = string(value).ok_or(CatalogError::InvalidPackage)?;
    if valid_name(value) {
        Ok(value)
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
fn version_value(value: &Value) -> Result<&str, CatalogError> {
    let value = string(value).ok_or(CatalogError::InvalidPackage)?;
    let mut p = value.split('.');
    let valid = |v: &str| {
        !v.is_empty()
            && !(v.len() > 1 && v.starts_with('0'))
            && v.bytes().all(|b| b.is_ascii_digit())
            && v.parse::<u16>().is_ok()
    };
    if matches!((p.next(),p.next(),p.next()),(Some(a),Some(b),None)if valid(a)&&valid(b)) {
        Ok(value)
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
fn digest_value(value: &Value) -> Result<&str, CatalogError> {
    let value = string(value).ok_or(CatalogError::InvalidPackage)?;
    if is_digest(value) {
        Ok(value)
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
fn strings(value: &Value) -> Option<Vec<String>> {
    let items = array(value, 1024)?;
    items.iter().map(|v| Some(string(v)?.to_owned())).collect()
}
fn string_array(value: &Value, max: usize) -> Option<Vec<String>> {
    let items = array(value, max)?;
    items
        .iter()
        .map(|v| Some(text(v, 4096)?.to_owned()))
        .collect()
}
fn feature_array(value: &Value) -> Option<Vec<String>> {
    let values = strings(value)?;
    values.iter().all(|item| valid_name(item)).then_some(values)
}
fn nullable_string(value: &Value) -> Result<Option<String>, CatalogError> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(ident(value)?.to_owned()))
    }
}
fn nullable_reference(value: &Value) -> Result<Option<String>, CatalogError> {
    if value.is_null() {
        Ok(None)
    } else {
        let reference = string(value).ok_or(CatalogError::InvalidPackage)?;
        if valid_reference(reference, false) {
            Ok(Some(reference.to_owned()))
        } else {
            Err(CatalogError::InvalidPackage)
        }
    }
}
fn safe_integer(value: &Value) -> Option<u64> {
    let n = value.as_u64()?;
    (n <= 9_007_199_254_740_991).then_some(n)
}
fn has_duplicates(values: &[String]) -> bool {
    let mut set = BTreeSet::new();
    values.iter().any(|v| !set.insert(v))
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write;
        let _ = write!(result, "{byte:02x}");
    }
    result
}
fn public_id(kind: &str, reference: &str, document_digest: &str, prefix: &str) -> String {
    format!(
        "{prefix}{}",
        digest(format!("{kind}\n{reference}\n{document_digest}\n").as_bytes())
    )
}
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn valid_reference(value: &str, schema: bool) -> bool {
    let Some((name, revision)) = value.split_once('@') else {
        return false;
    };
    if !valid_name(name) || !valid_name(revision) {
        return false;
    }
    if !schema {
        return true;
    }
    let mut p = revision.split('.');
    let valid = |v: &str| {
        !v.is_empty()
            && !(v.len() > 1 && v.starts_with('0'))
            && v.bytes().all(|b| b.is_ascii_digit())
            && v.parse::<u16>().is_ok()
    };
    matches!((p.next(),p.next(),p.next()),(Some(a),Some(b),None)if valid(a)&&valid(b))
}
fn bounded_value(value: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(n) => n.as_f64().is_some_and(f64::is_finite),
        Value::String(s) => s.len() <= 4096,
        Value::Array(items) => {
            items.len() <= 1024 && items.iter().all(|v| bounded_value(v, depth + 1))
        }
        Value::Object(map) => {
            map.len() <= 1024
                && map
                    .iter()
                    .all(|(k, v)| k.len() <= 128 && bounded_value(v, depth + 1))
        }
    }
}

fn credential_free_provenance(value: &Value) -> Result<(), CatalogError> {
    let value = text(value, 4096).ok_or(CatalogError::InvalidPackage)?;
    if value.contains("://") {
        let parsed = url::Url::parse(value).map_err(|_| CatalogError::InvalidPackage)?;
        let authority = value
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
            .unwrap_or_default();
        if !parsed.username().is_empty() || parsed.password().is_some() || authority.contains('@') {
            return Err(CatalogError::InvalidPackage);
        }
    }
    Ok(())
}

fn valid_rfc3339(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b.last() != Some(&b'Z')
    {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let text = std::str::from_utf8(b.get(range)?).ok()?;
        if !text.bytes().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return false;
    };
    let fraction = if b.len() == 20 {
        true
    } else if b.get(19) == Some(&b'.') && b.len() > 21 {
        b[20..b.len() - 1].iter().all(u8::is_ascii_digit)
    } else {
        false
    };
    if !fraction || month == 0 || month > 12 || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day > 0 && day <= month_days
}
