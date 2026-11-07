//! Exact immutable selection resolution for admission and submission paths.

use super::{
    AdapterIdentity, AssetIdentity, Catalog, CodeIdentity, DiscoveryError, PatchIdentity,
    ResolvedSelection, SchemaIdentity, Selection,
};
use serde_json::Value;

#[cfg_attr(
    all(not(unix), not(test), not(feature = "test-support")),
    expect(
        dead_code,
        reason = "This exact immutable handoff is implemented for later job admission."
    )
)]
pub(super) fn resolve(
    catalog: &Catalog,
    selection: &Selection,
) -> Result<ResolvedSelection, DiscoveryError> {
    let support_ref = catalog
        .model_aliases
        .get(&selection.support_ref)
        .map_or(selection.support_ref.as_str(), String::as_str);
    let model = catalog
        .models
        .get(support_ref)
        .ok_or(DiscoveryError::NotFound)?;
    let task = model
        .tasks
        .iter()
        .find(|task| task.task == selection.task)
        .ok_or(DiscoveryError::NotFound)?;

    if !model.unresolved_paths.is_empty() || !task.unresolved_paths.is_empty() {
        return Err(DiscoveryError::RequiredFeatureUnsupported);
    }

    let declaration = &model.declaration;
    let runtime_ref = selection
        .runtime_ref
        .as_deref()
        .or_else(|| declaration["default_runtime_ref"].as_str())
        .ok_or_else(|| DiscoveryError::AmbiguousSelection {
            candidates: vec![model.id.clone()],
            candidates_truncated: false,
        })?;
    let runtime_ref = catalog
        .runtime_aliases
        .get(runtime_ref)
        .map_or(runtime_ref, String::as_str);
    let runtime = catalog
        .runtimes
        .get(runtime_ref)
        .ok_or(DiscoveryError::NotFound)?;
    if !runtime.unresolved_paths.is_empty() {
        return Err(DiscoveryError::RequiredFeatureUnsupported);
    }

    let variant_id = selection
        .variant
        .as_deref()
        .or_else(|| declaration["default_variant"].as_str())
        .ok_or_else(|| DiscoveryError::AmbiguousSelection {
            candidates: vec![model.id.clone()],
            candidates_truncated: false,
        })?;
    let variant = declaration["variants"]
        .as_array()
        .and_then(|variants| variants.iter().find(|item| item["id"] == variant_id))
        .ok_or(DiscoveryError::NotFound)?;
    let runtime_compatible = declaration["runtime_refs"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item == runtime_ref))
        && variant["runtime_refs"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == runtime_ref));
    let task_compatible = variant["task_keys"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["id"] == selection.task.id() && item["version"] == selection.task.version()
        })
    });
    if !runtime_compatible || !task_compatible {
        return Err(DiscoveryError::NotFound);
    }

    let code = &model.declaration["code"];
    let code_identity = CodeIdentity {
        upstream_repository: string(&code["upstream_repository"], "code.upstream_repository"),
        upstream_revision: string(&code["upstream_revision"], "code.upstream_revision"),
        executed_repository: string(&code["executed_repository"], "code.executed_repository"),
        executed_revision: string(&code["executed_revision"], "code.executed_revision"),
        patches: code["patches"]
            .as_array()
            .expect("validated code patches are an array")
            .iter()
            .map(|patch| PatchIdentity {
                id: string(&patch["id"], "code.patch.id"),
                sha256: string(&patch["sha256"], "code.patch.sha256"),
            })
            .collect(),
        build_provenance: string(&code["build_provenance"], "code.build_provenance"),
    };
    let adapter = &model.declaration["adapter"];
    let adapter_identity = AdapterIdentity {
        id: string(&adapter["id"], "adapter.id"),
        revision: string(&adapter["revision"], "adapter.revision"),
        sha256: string(&adapter["sha256"], "adapter.sha256"),
        interface_version: string(&adapter["interface_version"], "adapter.interface_version"),
        required_worker_features: string_array(
            &adapter["required_worker_features"],
            "adapter.required_worker_features",
        ),
    };
    let assets = model.declaration["assets"]
        .as_array()
        .expect("validated support assets are an array")
        .iter()
        .map(|asset| AssetIdentity {
            id: string(&asset["id"], "asset.id"),
            kind: string(&asset["kind"], "asset.kind"),
            source: string(&asset["source"], "asset.source"),
            revision: string(&asset["revision"], "asset.revision"),
            sha256: string(&asset["sha256"], "asset.sha256"),
            byte_length: asset["byte_length"]
                .as_u64()
                .expect("validated asset byte_length is an unsigned integer"),
            prerequisites: string_array(&asset["prerequisites"], "asset.prerequisites"),
            rights_id: string(&asset["rights_id"], "asset.rights_id"),
        })
        .collect();
    let schemas = task
        .schemas
        .iter()
        .map(|schema| SchemaIdentity {
            id: string(&schema.document["id"], "schema.id"),
            version: string(&schema.document["version"], "schema.version"),
            sha256: schema.sha256.clone(),
        })
        .collect();

    Ok(ResolvedSelection {
        support_id: model.id.clone(),
        support_ref: model.support_ref.clone(),
        support_sha256: model.document_sha256.clone(),
        code: code_identity,
        adapter: adapter_identity,
        assets,
        task_binding_id: task.id.clone(),
        task: task.task.clone(),
        schemas,
        runtime_id: runtime.id.clone(),
        runtime_ref: runtime.runtime_ref.clone(),
        runtime_sha256: runtime.document_sha256.clone(),
        variant: variant_id.to_owned(),
    })
}

fn string(value: &Value, path: &str) -> String {
    value
        .as_str()
        .unwrap_or_else(|| panic!("validated catalog field {path} is a string"))
        .to_owned()
}

fn string_array(value: &Value, path: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("validated catalog field {path} is an array"))
        .iter()
        .map(|value| string(value, path))
        .collect()
}
