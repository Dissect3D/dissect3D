//! Strict package decoding, identity construction, declaration validation and resolution.

use super::{
    Catalog, CatalogError, ControlledPackage, DiscoveryLimits, ModelRecord, RuntimeRecord,
    SchemaRecord, TaskBindingRecord,
};
use super::{ObservationFacts, for_model_binding, for_runtime, observe};
use dissect3d_api::DeclarationValue as Value;
use dissect3d_api::{
    ModelDetail, ModelSummary, RuntimeDetail, RuntimeSummary, SchemaAttachment, TaskBindingDetail,
    TaskKey, decode_json,
};
use serde::Deserialize;
use serde::Serialize;
type Map<K, V> = BTreeMap<K, V>;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

mod runtime_validation;
mod schema_validation;
mod section_validation;
mod support_validation;
mod values;
use runtime_validation::*;
use schema_validation::*;
use section_validation::*;
use support_validation::*;
use values::*;

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

#[cfg(test)]
mod reference_work_regressions {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_rights_sources_are_credential_free() {
        for (source, valid) in [
            ("https://example.org/license", true),
            ("https://user:secret@example.org/license", false),
            ("https://user@example.org/license", false),
            ("https://@example.org/license", false),
        ] {
            let rights: Value = json!([{
                "id":"license", "component_ids":[], "license":"MIT", "notices":[],
                "source":source, "access_prerequisites":[], "distribution":"unknown",
                "unresolved":[]
            }])
            .into();
            assert_eq!(
                validate_runtime_rights(&rights, &BTreeSet::new()).is_ok(),
                valid
            );
        }
    }

    #[test]
    fn shared_reference_graph_does_not_expand_every_path() {
        // A small acyclic document describes 8^12 paths. It must remain cheap
        // without reducing the accepted reference or container-depth limits.
        let mut defs = serde_json::Map::new();
        for level in 0..12 {
            let child = if level == 11 {
                json!({"type":"boolean"})
            } else {
                json!({"$ref":format!("#/$defs/node{}", level + 1)})
            };
            let props: serde_json::Map<String, serde_json::Value> = (0..8)
                .map(|index| (format!("child{index}"), child.clone()))
                .collect();
            defs.insert(
                format!("node{level}"),
                json!({
                    "type":"object", "properties":props, "additionalProperties":false
                }),
            );
        }
        let schema: Value = json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "type":"object", "properties":{"root":{"$ref":"#/$defs/node0"}},
            "additionalProperties":false, "$defs":defs, "default":{}
        })
        .into();
        assert!(validate_schema_refs(&schema).is_ok());
        let mut unresolved = Vec::new();
        assert!(validate_schema_tree(&schema, &schema, &mut unresolved, "schema", 0).is_ok());
        assert!(unresolved.is_empty());

        let mut unknown = schema;
        unknown["$defs"]["node11"]["properties"]["child0"]["future"] = Value::Bool(true);
        assert!(validate_schema_refs(&unknown).is_ok());
        assert!(validate_schema_tree(&unknown, &unknown, &mut unresolved, "schema", 0).is_ok());
        assert!(!unresolved.is_empty());
    }

    #[test]
    fn shared_targets_retain_each_paths_reference_and_container_limits() {
        let mut defs = serde_json::Map::new();
        defs.insert("shared".into(), json!({"type":"boolean"}));
        for index in 0..16 {
            let next = if index == 15 {
                "shared".into()
            } else {
                format!("node{}", index + 1)
            };
            defs.insert(
                format!("node{index}"),
                json!({"$ref":format!("#/$defs/{next}")}),
            );
        }
        // The shared target is first checked on a short path, then a path over 16 edges.
        let schema: Value = json!({"type":"object", "additionalProperties":false,
            "properties":{"a":{"$ref":"#/$defs/shared"},"b":{"$ref":"#/$defs/node0"}},
            "$defs":defs})
        .into();
        assert!(validate_schema_refs(&schema).is_err());

        let mut shared = json!({"type":"boolean"});
        for _ in 0..30 {
            shared = json!({"type":"array", "items":shared});
        }
        let schema: Value = json!({"type":"object", "additionalProperties":false,
            "properties":{"a":{"$ref":"#/$defs/shared"},"b":{"type":"array",
                "items":{"type":"array","items":{"$ref":"#/$defs/shared"}}}},
            "$defs":{"shared":shared}})
        .into();
        assert!(validate_schema_refs(&schema).is_err());
    }
}
