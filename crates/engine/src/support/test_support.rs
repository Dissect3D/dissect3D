//! Synthetic declarations are compiled only into the isolated discovery test host.

use super::{Catalog, CatalogError, ControlledPackage, DiscoveryLimits};

pub(crate) fn catalog() -> Result<Catalog, CatalogError> {
    Catalog::from_packages(vec![fixture_package()], DiscoveryLimits::default())
}

fn fixture_package() -> ControlledPackage {
    ControlledPackage {
        index_bytes: include_bytes!(
            "../../../../patompong-docs/tests/support-discovery/fixtures/index.json"
        )
        .to_vec(),
        document_bytes: vec![
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/schema-0.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/schema-1.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/schema-2.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/schema-3.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/schema-4.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/schema-5.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/runtime-6.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/support-7.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/support-8.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/support-9.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/support-10.json"
            )
            .to_vec(),
            include_bytes!(
                "../../../../patompong-docs/tests/support-discovery/fixtures/support-11.json"
            )
            .to_vec(),
        ],
    }
}
