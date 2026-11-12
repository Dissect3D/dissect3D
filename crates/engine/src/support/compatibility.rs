//! Structural declaration relationships only; operational facts stay separate.

use dissect3d_api::DeclarationValue as Value;
use dissect3d_api::TaskKey;

pub(super) fn structurally_compatible(
    declaration: &Value,
    task: &TaskKey,
    runtime_ref: &str,
    variant_id: &str,
) -> bool {
    let Some(variant) = declaration["variants"]
        .as_array()
        .and_then(|variants| variants.iter().find(|variant| variant["id"] == variant_id))
    else {
        return false;
    };
    declaration["runtime_refs"]
        .as_array()
        .is_some_and(|refs| refs.iter().any(|reference| reference == runtime_ref))
        && variant["runtime_refs"]
            .as_array()
            .is_some_and(|refs| refs.iter().any(|reference| reference == runtime_ref))
        && variant["task_keys"].as_array().is_some_and(|keys| {
            keys.iter()
                .any(|key| key["id"] == task.id() && key["version"] == task.version())
        })
}
