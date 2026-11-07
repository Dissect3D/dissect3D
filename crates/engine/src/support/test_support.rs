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
