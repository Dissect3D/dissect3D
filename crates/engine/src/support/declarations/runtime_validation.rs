//! Validation of runtime declarations and their redistribution rights.

use super::*;

pub(super) fn validate_runtime(
    reference: &str,
    raw: &RawDocument,
) -> Result<RuntimeRecord, CatalogError> {
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

pub(super) fn validate_runtime_rights(
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
    Ok(())
}
