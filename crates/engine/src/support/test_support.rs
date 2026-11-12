//! Synthetic declarations are compiled only into the isolated discovery test host.

use super::{Catalog, CatalogError, ControlledPackage, DiscoveryLimits};

pub(crate) fn catalog() -> Result<Catalog, CatalogError> {
    Catalog::from_packages(vec![fixture_package()], DiscoveryLimits::default())
}

fn fixture_package() -> ControlledPackage {
    ControlledPackage {
        index_bytes: include_bytes!("../../tests/fixtures/support-discovery/index.json").to_vec(),
        document_bytes: vec![
            include_bytes!("../../tests/fixtures/support-discovery/schema-0.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/schema-1.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/schema-2.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/schema-3.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/schema-4.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/schema-5.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/runtime-6.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/support-7.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/support-8.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/support-9.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/support-10.json").to_vec(),
            include_bytes!("../../tests/fixtures/support-discovery/support-11.json").to_vec(),
        ],
    }
}

// Separate supplementary fixture; accepted package bytes above remain unchanged.
pub(crate) fn selection_catalog() -> Result<Catalog, CatalogError> {
    use serde_json::{Value, json};

    let mut package = fixture_package();
    let mut model: Value = serde_json::from_slice(&package.document_bytes[7])
        .map_err(|_| CatalogError::InvalidPackage)?;
    let original = model["tasks"][0].clone();
    for version in ["2.0", "3.0"] {
        let mut binding = original.clone();
        binding["task"]["version"] = json!(version);
        model["tasks"].as_array_mut().unwrap().push(binding);
        model["variants"][0]["task_keys"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": original["task"]["id"], "version": version}));
    }
    let bytes = serde_json::to_vec(&model).map_err(|_| CatalogError::InvalidPackage)?;
    let mut index: Value =
        serde_json::from_slice(&package.index_bytes).map_err(|_| CatalogError::InvalidPackage)?;
    index["documents"][7]["sha256"] = json!(super::digest(&bytes));
    index["documents"][7]["byte_length"] = json!(bytes.len());
    package.document_bytes[7] = bytes;
    package.index_bytes = serde_json::to_vec(&index).map_err(|_| CatalogError::InvalidPackage)?;
    Catalog::from_packages(vec![package], DiscoveryLimits::default())
}
