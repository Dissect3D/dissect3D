//! Validation of shared declaration sections: code, preprocessing, resources,
//! tested profiles, evidence, asset graphs and constraints.

use super::*;

pub(super) fn validate_code(value: &Value) -> Result<(), CatalogError> {
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

pub(super) fn validate_preprocessing(value: &Value) -> Result<(), CatalogError> {
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

pub(super) fn validate_resources_lifecycle(value: &Value) -> Result<(), CatalogError> {
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

pub(super) fn validate_tested_profiles(
    value: &Value,
    tasks: &[(TaskKey, TaskBindingRecord)],
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
            || !super::super::compatibility::structurally_compatible(
                value,
                &task,
                string(&profile["runtime_ref"]).ok_or(CatalogError::InvalidPackage)?,
                string(&profile["variant"]).ok_or(CatalogError::InvalidPackage)?,
            )
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

pub(super) fn validate_evidence(value: &Value) -> Result<BTreeSet<String>, CatalogError> {
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

pub(super) fn validate_asset_graph(assets: &[Value]) -> Result<(), CatalogError> {
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

pub(super) fn validate_constraints(
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
            || validator_id != dissect3d_api::TEST_OUTPUT_VALIDATOR_ID
            || validator_revision != dissect3d_api::TEST_OUTPUT_VALIDATOR_REVISION
        {
            unresolved.push(format!("{prefix}[{index}]"));
        }
    }
    Ok(())
}
