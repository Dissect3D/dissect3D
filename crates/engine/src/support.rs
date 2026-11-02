//! Engine-owned immutable support catalog construction.

#[cfg(any(test, feature = "test-support"))]
mod declarations;
mod observations;
mod pagination;
mod resolver;
#[cfg(feature = "test-support")]
pub mod test_support;

use dissect3d_api::{SchemaAttachment, TaskKey};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) use observations::{ObservationFacts, for_model_binding, for_runtime, observe};
pub(crate) use pagination::{InventoryQuery, InventoryResult};

#[cfg(test)]
use serde::Deserialize;
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::collections::BTreeSet;

fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

#[cfg(test)]
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

#[cfg(test)]
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
    let mut parts = revision.split('.');
    let valid = |part: &str| {
        !part.is_empty()
            && !(part.len() > 1 && part.starts_with('0'))
            && part.bytes().all(|b| b.is_ascii_digit())
            && part.parse::<u16>().is_ok()
    };
    matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if valid(a) && valid(b))
}

/// Exact package bytes accepted only through engine-owned composition.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct ControlledPackage {
    pub(crate) index_bytes: Vec<u8>,
    pub(crate) document_bytes: Vec<Vec<u8>>,
}

/// Limits enforced while decoding and publishing one immutable inventory.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DiscoveryLimits {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) records_max: usize,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) catalog_bytes_max: usize,
    pub(crate) detail_bytes_max: usize,
    pub(crate) response_bytes_max: usize,
    pub(crate) cursor_bytes_max: usize,
    pub(crate) query_bytes_max: usize,
    pub(crate) page_default: u8,
    pub(crate) page_max: u8,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            #[cfg(any(test, feature = "test-support"))]
            records_max: 1024,
            #[cfg(any(test, feature = "test-support"))]
            catalog_bytes_max: 8_388_608,
            detail_bytes_max: 196_608,
            response_bytes_max: 262_144,
            cursor_bytes_max: 1024,
            query_bytes_max: 4096,
            page_default: 20,
            page_max: 100,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Catalog {
    pub(crate) revision: String,
    pub(crate) models: BTreeMap<String, ModelRecord>,
    pub(crate) runtimes: BTreeMap<String, RuntimeRecord>,
    pub(crate) tasks: BTreeMap<String, TaskBindingRecord>,
    pub(crate) model_aliases: BTreeMap<String, String>,
    pub(crate) runtime_aliases: BTreeMap<String, String>,
    pub(crate) limits: DiscoveryLimits,
}

#[derive(Clone, Debug)]
pub(crate) struct ModelRecord {
    pub(crate) id: String,
    pub(crate) support_ref: String,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained for exact selection identity capture when admission is implemented."
        )
    )]
    pub(crate) document_sha256: String,
    pub(crate) description: String,
    pub(crate) test_only: bool,
    pub(crate) declaration: Value,
    pub(crate) schemas: Vec<SchemaAttachment>,
    pub(crate) tasks: Vec<TaskBindingRecord>,
    #[cfg(test)]
    pub(crate) unresolved: bool,
    pub(crate) unresolved_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeRecord {
    pub(crate) id: String,
    pub(crate) runtime_ref: String,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Retained for exact selection identity capture when admission is implemented."
        )
    )]
    pub(crate) document_sha256: String,
    pub(crate) description: String,
    pub(crate) test_only: bool,
    pub(crate) declaration: Value,
    pub(crate) unresolved_paths: Vec<String>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
pub(crate) struct SchemaRecord {
    pub(crate) sha256: String,
    pub(crate) document: Value,
    pub(crate) unresolved_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct TaskBindingRecord {
    pub(crate) id: String,
    pub(crate) task: TaskKey,
    pub(crate) support_ref: String,
    pub(crate) description: String,
    pub(crate) binding: Value,
    pub(crate) schemas: Vec<SchemaAttachment>,
    pub(crate) unresolved_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct InspectionSelection {
    pub(crate) support_ref: String,
    pub(crate) task: TaskKey,
    pub(crate) runtime_ref: String,
    pub(crate) variant: String,
    pub(crate) unresolved_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Selection {
    pub(crate) support_ref: String,
    pub(crate) task: TaskKey,
    pub(crate) runtime_ref: Option<String>,
    pub(crate) variant: Option<String>,
}

/// Exact code provenance bound by one support release.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Consumed by future durable selection capture.")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CodeIdentity {
    pub(crate) upstream_repository: String,
    pub(crate) upstream_revision: String,
    pub(crate) executed_repository: String,
    pub(crate) executed_revision: String,
    pub(crate) patches: Vec<PatchIdentity>,
    pub(crate) build_provenance: String,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Consumed by future durable selection capture.")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PatchIdentity {
    pub(crate) id: String,
    pub(crate) sha256: String,
}

/// Adapter identity and its declared worker interface.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Consumed by future durable selection capture.")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdapterIdentity {
    pub(crate) id: String,
    pub(crate) revision: String,
    pub(crate) sha256: String,
    pub(crate) interface_version: String,
    pub(crate) required_worker_features: Vec<String>,
}

/// Exact model asset declaration, including provenance and rights binding.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Consumed by future durable selection capture.")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetIdentity {
    pub(crate) id: String,
    pub(crate) kind: String,
    pub(crate) source: String,
    pub(crate) revision: String,
    pub(crate) sha256: String,
    pub(crate) byte_length: u64,
    pub(crate) prerequisites: Vec<String>,
    pub(crate) rights_id: String,
}

/// Exact package-local schema identity attached to one task binding.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "Consumed by future durable selection capture.")
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SchemaIdentity {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) sha256: String,
}

/// Owned exact identities suitable for later durable selection capture.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "This handoff is consumed by future job admission, outside support discovery."
    )
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedSelection {
    pub(crate) support_id: String,
    pub(crate) support_ref: String,
    pub(crate) support_sha256: String,
    pub(crate) code: CodeIdentity,
    pub(crate) adapter: AdapterIdentity,
    pub(crate) assets: Vec<AssetIdentity>,
    pub(crate) task_binding_id: String,
    pub(crate) task: TaskKey,
    pub(crate) schemas: Vec<SchemaIdentity>,
    pub(crate) runtime_id: String,
    pub(crate) runtime_ref: String,
    pub(crate) runtime_sha256: String,
    pub(crate) variant: String,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CatalogError {
    InvalidPackage,
    ConflictingIdentity,
    LimitExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryError {
    NotFound,
    AmbiguousSelection {
        candidates: Vec<String>,
        candidates_truncated: bool,
    },
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Selection resolution is ready for later admission; discovery only inspects these declarations."
        )
    )]
    RequiredFeatureUnsupported,
    InvalidRequest,
    CursorExpired,
    TransferLimit,
}

impl Catalog {
    pub(crate) fn empty() -> Self {
        Self {
            revision: empty_revision(),
            models: BTreeMap::new(),
            runtimes: BTreeMap::new(),
            tasks: BTreeMap::new(),
            model_aliases: BTreeMap::new(),
            runtime_aliases: BTreeMap::new(),
            limits: DiscoveryLimits::default(),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_packages(
        packages: Vec<ControlledPackage>,
        limits: DiscoveryLimits,
    ) -> Result<Self, CatalogError> {
        declarations::build_catalog(packages, limits)
    }

    #[cfg(test)]
    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }

    pub(crate) fn model(&self, selector: &str) -> Option<&ModelRecord> {
        if let Some(model) = self.models.values().find(|model| model.id == selector) {
            return Some(model);
        }
        let reference = self
            .model_aliases
            .get(selector)
            .map_or(selector, String::as_str);
        self.models.get(reference)
    }

    pub(crate) fn runtime(&self, selector: &str) -> Option<&RuntimeRecord> {
        if let Some(runtime) = self
            .runtimes
            .values()
            .find(|runtime| runtime.id == selector)
        {
            return Some(runtime);
        }
        let reference = self
            .runtime_aliases
            .get(selector)
            .map_or(selector, String::as_str);
        self.runtimes.get(reference)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "This exact immutable handoff is implemented for later job admission."
        )
    )]
    pub(crate) fn resolve(
        &self,
        selection: &Selection,
    ) -> Result<ResolvedSelection, DiscoveryError> {
        resolver::resolve(self, selection)
    }
}

#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema_version: String,
    required_features: Vec<String>,
    documents: Vec<Document>,
    aliases: Vec<Alias>,
}

#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    kind: String,
    #[serde(rename = "ref")]
    reference: String,
    sha256: String,
    byte_length: u64,
}

#[cfg(test)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Alias {
    kind: String,
    name: String,
    target: String,
}

/// Validates package index identity against separately supplied exact bytes.
/// This is only the index and byte-integrity layer; declaration validation is
/// required before any catalog can be published.
#[cfg(test)]
pub(crate) fn index_revision(index_bytes: &[u8], documents: &[Vec<u8>]) -> Result<String, ()> {
    if index_bytes.len() > 8_388_608 {
        return Err(());
    }
    let index: Index = dissect3d_api::decode_json(index_bytes).map_err(|_| ())?;
    if index.schema_version != "1.0"
        || !index.required_features.is_empty()
        || index.documents.len() != documents.len()
        || index.documents.len() > 1024
        || index.aliases.len() > 1024
    {
        return Err(());
    }
    let mut total = index_bytes.len();
    let mut identities = BTreeMap::new();
    let mut rows = BTreeSet::new();
    for (entry, bytes) in index.documents.iter().zip(documents) {
        total = total.checked_add(bytes.len()).ok_or(())?;
        if total > 8_388_608
            || !matches!(entry.kind.as_str(), "support" | "runtime" | "schema")
            || !valid_reference(&entry.reference, entry.kind == "schema")
            || entry.byte_length != bytes.len() as u64
            || digest(bytes) != entry.sha256
        {
            return Err(());
        }
        let _: serde_json::Value = dissect3d_api::decode_json(bytes).map_err(|_| ())?;
        let key = (entry.kind.as_str(), entry.reference.as_str());
        if let Some(previous) = identities.insert(key, (entry.sha256.as_str(), bytes))
            && previous != (entry.sha256.as_str(), bytes)
        {
            return Err(());
        }
        rows.insert(format!(
            "D\t{}\t{}\t{}\n",
            entry.kind, entry.reference, entry.sha256
        ));
    }
    let mut aliases = BTreeSet::new();
    let mut alias_rows = BTreeSet::new();
    for alias in &index.aliases {
        let kind = match alias.kind.as_str() {
            "model" => "support",
            "runtime" => "runtime",
            _ => return Err(()),
        };
        if !valid_name(&alias.name)
            || ["mdl_", "rtp_", "tsk_"]
                .iter()
                .any(|prefix| alias.name.starts_with(prefix))
            || !aliases.insert((&alias.kind, &alias.name))
            || !identities.contains_key(&(kind, alias.target.as_str()))
        {
            return Err(());
        }
        alias_rows.insert(format!(
            "A\t{}\t{}\t{}\n",
            alias.kind, alias.name, alias.target
        ));
    }
    let mut preimage = String::from("dissect3d-catalog-v1\n");
    for row in rows.iter().chain(alias_rows.iter()) {
        preimage.push_str(row);
    }
    Ok(digest(preimage.as_bytes()))
}

/// The revision of an empty catalog is the hash of the catalog header.
pub(crate) fn empty_revision() -> String {
    digest(b"dissect3d-catalog-v1\n")
}

#[cfg(test)]
pub(crate) fn fixture_catalog() -> Catalog {
    tests::fixture_catalog()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_catalog_revision_matches_contract_vector() {
        assert_eq!(
            empty_revision(),
            "a08d0eebb9c0c86c19a40d5835de4f3c5e587203c9ead10f2a8b511a6212005e"
        );
    }

    #[test]
    fn index_rejects_changed_document_bytes() {
        let index = br#"{"schema_version":"1.0","required_features":[],"documents":[{"kind":"schema","ref":"test.mesh@1.0","sha256":"a7fd5e73397d976d4e72942e0d0a5e34bdd5ec62e16a3bbcaff748da0c0b7cd8","byte_length":394}],"aliases":[]}"#;
        let bytes = include_bytes!(
            "../../../patompong-docs/tests/support-discovery/fixtures/schema-0.json"
        )
        .to_vec();
        assert!(index_revision(index, std::slice::from_ref(&bytes)).is_ok());
        let mut changed = bytes;
        changed.push(b'\n');
        assert!(index_revision(index, &[changed]).is_err());
    }

    fn fixture_package() -> ControlledPackage {
        ControlledPackage {
            index_bytes: include_bytes!(
                "../../../patompong-docs/tests/support-discovery/fixtures/index.json"
            )
            .to_vec(),
            document_bytes: vec![
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/schema-0.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/schema-1.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/schema-2.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/schema-3.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/schema-4.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/schema-5.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/runtime-6.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/support-7.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/support-8.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/support-9.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/support-10.json"
                )
                .to_vec(),
                include_bytes!(
                    "../../../patompong-docs/tests/support-discovery/fixtures/support-11.json"
                )
                .to_vec(),
            ],
        }
    }

    pub(super) fn fixture_catalog() -> Catalog {
        Catalog::from_packages(vec![fixture_package()], DiscoveryLimits::default())
            .expect("accepted test fixture")
    }

    #[test]
    fn exact_bytes_bind_revision() {
        let catalog = Catalog::from_packages(vec![fixture_package()], DiscoveryLimits::default())
            .expect("accepted fixture catalog");
        assert_eq!(
            catalog.revision(),
            "b57f1eb8fe31b228e294bff06f9a10869f22f1af996ee5ed11b1381263c1f68b"
        );
        assert_eq!(
            catalog.model("test.mesh-copy@fixture-r1").unwrap().id,
            "mdl_6b32152ee6058b9b0babf6204080f368ce616aeffe1218012e780fffb44b0629"
        );
        let vectors: Value = serde_json::from_slice(include_bytes!(
            "../../../patompong-docs/tests/support-discovery/fixtures/vectors.json"
        ))
        .unwrap();
        for document in vectors["documents"].as_array().unwrap() {
            match document["kind"].as_str().unwrap() {
                "support" => assert_eq!(
                    catalog.model(document["ref"].as_str().unwrap()).unwrap().id,
                    document["public_id"]
                ),
                "runtime" => assert_eq!(
                    catalog
                        .runtime(document["ref"].as_str().unwrap())
                        .unwrap()
                        .id,
                    document["public_id"]
                ),
                _ => {}
            }
        }
        let mesh = catalog.model("test.mesh-copy@fixture-r1").unwrap();
        let mesh_task = mesh
            .tasks
            .iter()
            .find(|binding| binding.task.id() == "dissect3d.test.mesh-copy")
            .unwrap();
        let vector = vectors["documents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|document| document["ref"] == "test.mesh-copy@fixture-r1")
            .unwrap();
        assert_eq!(mesh_task.id, vector["task_id"]);
    }

    #[test]
    fn alias_never_is_execution_identity() {
        let catalog = Catalog::from_packages(vec![fixture_package()], DiscoveryLimits::default())
            .expect("accepted fixture catalog");
        let model = catalog.model("test-current").expect("direct model alias");
        assert_eq!(model.support_ref, "test.mesh-copy@fixture-r1");
        let resolved = catalog
            .resolve(&Selection {
                support_ref: "test-current".to_owned(),
                task: TaskKey::new("dissect3d.test.mesh-copy", "1.0").unwrap(),
                runtime_ref: None,
                variant: None,
            })
            .expect("explicit declaration defaults resolve");
        assert_eq!(
            resolved.support_id,
            "mdl_6b32152ee6058b9b0babf6204080f368ce616aeffe1218012e780fffb44b0629"
        );
        assert_eq!(resolved.support_ref, "test.mesh-copy@fixture-r1");
        assert_eq!(
            resolved.support_sha256,
            "059e35f8e72bf155f2114524f18afc2e0882a12359f7472510aa8ec8a2ead2c1"
        );
        assert_eq!(
            resolved.task_binding_id,
            "tsk_7de4c5a04b323471427329a18e64f35300b6b74ce24100dbe512cbd7e77b3e47"
        );
        assert_eq!(
            resolved.task,
            TaskKey::new("dissect3d.test.mesh-copy", "1.0").unwrap()
        );
        assert_eq!(
            resolved.schemas,
            vec![
                SchemaIdentity {
                    id: "test.mesh".to_owned(),
                    version: "1.0".to_owned(),
                    sha256: "a7fd5e73397d976d4e72942e0d0a5e34bdd5ec62e16a3bbcaff748da0c0b7cd8"
                        .to_owned(),
                },
                SchemaIdentity {
                    id: "test.parameters".to_owned(),
                    version: "1.0".to_owned(),
                    sha256: "2c5f4c1030d0ac3bb39eebc4292578cbfc9dba0dce685aa2aa6066db9bc948f5"
                        .to_owned(),
                },
                SchemaIdentity {
                    id: "test.output".to_owned(),
                    version: "1.0".to_owned(),
                    sha256: "fe9520c6e5ec4140d1e0e9f411177316c17a4ff1f6cd1534c78a89df49da0587"
                        .to_owned(),
                },
            ]
        );
        assert_eq!(
            resolved.runtime_id,
            "rtp_373d50148739a3658a018c18a2e1e9faa5c5745020a83fc474ab6ac93992c170"
        );
        assert_eq!(resolved.runtime_ref, "test.cpu@fixture-r1");
        assert_eq!(
            resolved.runtime_sha256,
            "0013e0ae39bc4445d7925d505bc6f9ea9eb6541c759571944cdb6bd09a99c335"
        );
        assert_eq!(resolved.variant, "fixture");
    }

    #[test]
    fn resolution_captures_code_adapter_and_asset_identities() {
        let mut package = fixture_package();
        let patch_sha256 = "c".repeat(64);
        let asset_sha256 = "b".repeat(64);
        mutate_document(
            &mut package,
            "support",
            "test.mesh-copy@fixture-r1",
            |document| {
                document["code"]["patches"] = serde_json::json!([
                    {"id":"test.patch","sha256":patch_sha256}
                ]);
                document["assets"] = serde_json::json!([
                    {
                        "id":"test.asset",
                        "kind":"weights",
                        "source":"test:asset",
                        "revision":"fixture-r1",
                        "sha256":asset_sha256,
                        "byte_length":1,
                        "prerequisites":[],
                        "rights_id":"test.asset.right"
                    }
                ]);
                document["rights"] = serde_json::json!([
                    {
                        "id":"test.asset.right",
                        "component_ids":["test.asset"],
                        "license":"synthetic",
                        "notices":[],
                        "source":"test:rights",
                        "access_prerequisites":[],
                        "distribution":"allowed",
                        "unresolved":[]
                    }
                ]);
            },
        );
        let catalog = Catalog::from_packages(vec![package], DiscoveryLimits::default())
            .expect("bounded synthetic asset declaration");
        let model = catalog.model("test.mesh-copy@fixture-r1").unwrap();
        let resolved = catalog
            .resolve(&Selection {
                support_ref: model.support_ref.clone(),
                task: TaskKey::new("dissect3d.test.mesh-copy", "1.0").unwrap(),
                runtime_ref: None,
                variant: None,
            })
            .expect("explicit defaults resolve exact identities");

        assert_eq!(resolved.support_sha256, model.document_sha256);
        assert_eq!(
            resolved.code,
            CodeIdentity {
                upstream_repository: "test:synthetic".to_owned(),
                upstream_revision: "fixture-r1".to_owned(),
                executed_repository: "test:synthetic".to_owned(),
                executed_revision: "fixture-r1".to_owned(),
                patches: vec![PatchIdentity {
                    id: "test.patch".to_owned(),
                    sha256: patch_sha256,
                }],
                build_provenance: "contract-only".to_owned(),
            }
        );
        assert_eq!(
            resolved.adapter,
            AdapterIdentity {
                id: "test.adapter".to_owned(),
                revision: "1".to_owned(),
                sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
                interface_version: "1.0".to_owned(),
                required_worker_features: Vec::new(),
            }
        );
        assert_eq!(
            resolved.assets,
            vec![AssetIdentity {
                id: "test.asset".to_owned(),
                kind: "weights".to_owned(),
                source: "test:asset".to_owned(),
                revision: "fixture-r1".to_owned(),
                sha256: asset_sha256,
                byte_length: 1,
                prerequisites: Vec::new(),
                rights_id: "test.asset.right".to_owned(),
            }]
        );
    }

    #[test]
    fn task_binding_preserves_mask_count_and_mesh_distinctions() {
        let catalog = Catalog::from_packages(vec![fixture_package()], DiscoveryLimits::default())
            .expect("accepted fixture catalog");
        let mask = catalog.model("test.mask@fixture-r1").unwrap();
        let count = catalog.model("test.count@fixture-r1").unwrap();
        assert_ne!(mask.tasks[0].id, count.tasks[0].id);
        assert_ne!(
            mask.tasks[0].binding["input_schema"],
            count.tasks[0].binding["input_schema"]
        );
        assert_eq!(mask.tasks[0].binding["task"]["id"], "dissect3d.test.shared");
        assert_eq!(
            count.tasks[0].binding["task"]["id"],
            "dissect3d.test.shared"
        );
    }

    #[test]
    fn unknown_required_schema_stays_inspectable_but_not_resolvable() {
        let catalog = Catalog::from_packages(vec![fixture_package()], DiscoveryLimits::default())
            .expect("bounded unknown schema remains inspectable");
        let model = catalog.model("test.complete@fixture-r1").unwrap();
        assert!(model.unresolved);
        assert!(
            model
                .schemas
                .iter()
                .any(|schema| { schema.document.to_string().contains("x-required-future") })
        );
        let result = catalog.resolve(&Selection {
            support_ref: model.support_ref.clone(),
            task: TaskKey::new("dissect3d.test.complete", "1.0").unwrap(),
            runtime_ref: None,
            variant: None,
        });
        assert_eq!(
            result,
            Err(DiscoveryError::RequiredFeatureUnsupported),
            "SD-V08"
        );
    }

    #[test]
    fn protected_catalog_cases_reject_unsafe_packages() {
        let mut bad_hash = fixture_package();
        let index = document_position(&bad_hash, "support", "test.mesh-copy@fixture-r1");
        bad_hash.document_bytes[index].push(b'\n');
        assert_eq!(
            Catalog::from_packages(vec![bad_hash], DiscoveryLimits::default()).unwrap_err(),
            CatalogError::InvalidPackage,
            "SD-V01"
        );

        let original = fixture_package();
        let mut conflicting = original.clone();
        mutate_document(
            &mut conflicting,
            "support",
            "test.mesh-copy@fixture-r1",
            |doc| {
                doc["description"] = serde_json::json!("conflicting bytes under the same release")
            },
        );
        assert_eq!(
            Catalog::from_packages(vec![original, conflicting], DiscoveryLimits::default())
                .unwrap_err(),
            CatalogError::ConflictingIdentity,
            "SD-V02"
        );

        let mut duplicate_member = fixture_package();
        let index = document_position(&duplicate_member, "support", "test.mesh-copy@fixture-r1");
        let mut bytes = duplicate_member.document_bytes[index].clone();
        let end = bytes.iter().rposition(|byte| *byte == b'}').unwrap();
        bytes.truncate(end);
        bytes.extend_from_slice(br#","family":"duplicate"}"#);
        bytes.push(b'\n');
        replace_document(&mut duplicate_member, index, bytes);
        assert!(
            Catalog::from_packages(vec![duplicate_member], DiscoveryLimits::default()).is_err(),
            "SD-V03"
        );

        let mut alias_chain = fixture_package();
        mutate_index(&mut alias_chain, |index| {
            let alias = index["aliases"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|alias| alias["name"] == "test-current")
                .unwrap();
            alias["target"] = serde_json::json!("test-other-alias");
        });
        assert!(
            Catalog::from_packages(vec![alias_chain], DiscoveryLimits::default()).is_err(),
            "SD-V04"
        );

        let mut invalid_default = fixture_package();
        mutate_document(
            &mut invalid_default,
            "schema",
            "test.parameters@1.0",
            |doc| {
                doc["schema"]["properties"]["hold_before_candidate"]["default"] =
                    serde_json::json!("false");
            },
        );
        assert!(
            Catalog::from_packages(vec![invalid_default], DiscoveryLimits::default()).is_err(),
            "SD-V05"
        );

        let mut remote_ref = fixture_package();
        mutate_document(&mut remote_ref, "schema", "test.parameters@1.0", |doc| {
            doc["schema"]["$defs"] = serde_json::json!({
                "remote": {"$ref":"https://example.invalid/schema.json"}
            });
            doc["schema"]["properties"]["hold_before_candidate"] =
                serde_json::json!({"$ref":"#/$defs/remote"});
        });
        assert!(
            Catalog::from_packages(vec![remote_ref], DiscoveryLimits::default()).is_err(),
            "SD-V06"
        );

        let mut absent_role = fixture_package();
        mutate_document(&mut absent_role, "support", "test.mask@fixture-r1", |doc| {
            doc["tasks"][0]["constraints"][0]["fields"][0] =
                serde_json::json!("inputs.missing_role");
        });
        assert!(
            Catalog::from_packages(vec![absent_role], DiscoveryLimits::default()).is_err(),
            "SD-V07"
        );

        let mut duplicate_task = fixture_package();
        mutate_document(
            &mut duplicate_task,
            "support",
            "test.mesh-copy@fixture-r1",
            |doc| {
                let duplicate = doc["tasks"][0].clone();
                doc["tasks"].as_array_mut().unwrap().push(duplicate);
            },
        );
        assert!(
            Catalog::from_packages(vec![duplicate_task], DiscoveryLimits::default()).is_err(),
            "SD-V16"
        );

        let mut unknown_index_feature = fixture_package();
        mutate_index(&mut unknown_index_feature, |index| {
            index["required_features"] = serde_json::json!(["future.package"]);
        });
        assert!(
            Catalog::from_packages(vec![unknown_index_feature], DiscoveryLimits::default())
                .is_err(),
            "SD-V15"
        );
    }

    #[test]
    fn protected_catalog_bounds_reject_before_publication() {
        let mut too_many = fixture_package();
        let index: Value = serde_json::from_slice(&too_many.index_bytes).unwrap();
        let support_refs = index["documents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["kind"] == "support")
            .map(|entry| entry["ref"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        for (model_index, support_ref) in support_refs.iter().enumerate() {
            let extra_tasks = if model_index < 4 { 203 } else { 202 };
            mutate_document(&mut too_many, "support", support_ref, |document| {
                let template = document["tasks"][0].clone();
                let base_id = template["task"]["id"].as_str().unwrap().to_owned();
                for ordinal in 0..extra_tasks {
                    let task_id = format!("{base_id}.extra{model_index}.{ordinal}");
                    let mut binding = template.clone();
                    binding["task"]["id"] = Value::String(task_id.clone());
                    binding["task"]["version"] = Value::String("1.0".to_owned());
                    document["tasks"].as_array_mut().unwrap().push(binding);
                    document["variants"][0]["task_keys"]
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::json!({"id":task_id,"version":"1.0"}));
                }
            });
        }
        let result = Catalog::from_packages(vec![too_many], DiscoveryLimits::default());
        assert!(
            matches!(result, Err(CatalogError::LimitExceeded)),
            "SD-V12 record count should reject 1025 records, result counts: {:?}",
            result.as_ref().ok().map(|catalog| (
                catalog.models.len(),
                catalog.runtimes.len(),
                catalog.tasks.len()
            ))
        );

        let mut too_large = fixture_package();
        let document_bytes = too_large.document_bytes.iter().map(Vec::len).sum::<usize>();
        let target_index_size = DiscoveryLimits::default().catalog_bytes_max + 1 - document_bytes;
        too_large.index_bytes.resize(target_index_size, b' ');
        assert_eq!(
            Catalog::from_packages(vec![too_large], DiscoveryLimits::default()).unwrap_err(),
            CatalogError::LimitExceeded,
            "SD-V12 aggregate byte count"
        );

        let mut oversized_detail = fixture_package();
        mutate_document(
            &mut oversized_detail,
            "support",
            "test.mesh-copy@fixture-r1",
            |doc| {
                doc["limitations"] = serde_json::json!(vec!["x".repeat(4096); 60]);
            },
        );
        assert_eq!(
            Catalog::from_packages(vec![oversized_detail], DiscoveryLimits::default()).unwrap_err(),
            CatalogError::LimitExceeded,
            "SD-V13"
        );
    }

    #[test]
    fn schema_reference_expansion_is_bounded() {
        let mut package = fixture_package();
        mutate_document(&mut package, "schema", "test.parameters@1.0", |doc| {
            let mut definitions = serde_json::Map::new();
            for ordinal in 0..17 {
                let value = if ordinal == 16 {
                    serde_json::json!({"type":"boolean"})
                } else {
                    serde_json::json!({"$ref":format!("#/$defs/node{}", ordinal + 1)})
                };
                definitions.insert(format!("node{ordinal}"), value);
            }
            doc["schema"]["$defs"] = Value::Object(definitions);
            doc["schema"]["properties"]["hold_before_candidate"] =
                serde_json::json!({"$ref":"#/$defs/node0"});
            doc["schema"]["properties"]["hold_before_candidate"]
                .as_object_mut()
                .unwrap()
                .remove("default");
        });
        assert!(
            Catalog::from_packages(vec![package], DiscoveryLimits::default()).is_err(),
            "SD-V14 reference expansion"
        );

        let mut deep_schema = fixture_package();
        mutate_document(&mut deep_schema, "schema", "test.parameters@1.0", |doc| {
            let mut nested = serde_json::json!({"type":"boolean"});
            for _ in 0..34 {
                nested = serde_json::json!({"type":"array","items":nested});
            }
            doc["schema"]["properties"]["hold_before_candidate"] = nested;
        });
        assert!(
            Catalog::from_packages(vec![deep_schema], DiscoveryLimits::default()).is_err(),
            "SD-V14 container depth"
        );
    }

    #[test]
    fn catalog_order_and_alias_revision_vectors_are_stable() {
        let ordered = fixture_package();
        let baseline =
            Catalog::from_packages(vec![ordered.clone()], DiscoveryLimits::default()).unwrap();
        let mut reversed = ordered;
        reversed.document_bytes.reverse();
        mutate_index(&mut reversed, |index| {
            index["documents"].as_array_mut().unwrap().reverse();
        });
        let reordered = Catalog::from_packages(vec![reversed], DiscoveryLimits::default()).unwrap();
        assert_eq!(baseline.revision, reordered.revision, "SD-V10");

        let old_selection = baseline
            .resolve(&Selection {
                support_ref: "test-current".into(),
                task: TaskKey::new("dissect3d.test.mesh-copy", "1.0").unwrap(),
                runtime_ref: None,
                variant: None,
            })
            .unwrap();
        let mut moved_alias = fixture_package();
        mutate_index(&mut moved_alias, |index| {
            let alias = index["aliases"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|alias| alias["name"] == "test-current")
                .unwrap();
            alias["target"] = serde_json::json!("test.mask@fixture-r1");
        });
        let moved = Catalog::from_packages(vec![moved_alias], DiscoveryLimits::default()).unwrap();
        let vectors: Value = serde_json::from_slice(include_bytes!(
            "../../../patompong-docs/tests/support-discovery/fixtures/vectors.json"
        ))
        .unwrap();
        assert_eq!(
            moved.model("test-current").unwrap().support_ref,
            "test.mask@fixture-r1"
        );
        assert_eq!(moved.revision, vectors["alias_moved"]["sha256"], "SD-V11");
        assert_eq!(old_selection.support_ref, "test.mesh-copy@fixture-r1");
        assert_eq!(
            old_selection.task_binding_id,
            baseline.model("test.mesh-copy@fixture-r1").unwrap().tasks[0].id
        );
    }

    #[test]
    fn missing_defaults_remain_an_unresolved_binding_scope() {
        let mut package = fixture_package();
        mutate_document(
            &mut package,
            "support",
            "test.mesh-copy@fixture-r1",
            |doc| {
                doc["default_runtime_ref"] = Value::Null;
                doc["default_variant"] = Value::Null;
            },
        );
        let catalog = Catalog::from_packages(vec![package], DiscoveryLimits::default()).unwrap();
        let model = catalog.model("test.mesh-copy@fixture-r1").unwrap();
        let binding = &model.tasks[0];
        for (runtime_ref, variant) in [
            (None, None),
            (Some("test.cpu@fixture-r1"), None),
            (None, Some("fixture")),
        ] {
            let result = catalog.resolve(&Selection {
                support_ref: model.support_ref.clone(),
                task: binding.task.clone(),
                runtime_ref: runtime_ref.map(str::to_owned),
                variant: variant.map(str::to_owned),
            });
            assert!(
                matches!(result, Err(DiscoveryError::AmbiguousSelection { .. })),
                "SD-V09 must not partially choose a selection: {result:?}"
            );
        }
        let (scope, evidence, tested) = for_model_binding(&catalog, model, binding, None).unwrap();
        let observation = observe(
            &scope,
            &ObservationFacts::phase_two(&scope),
            evidence,
            tested,
        );
        assert_eq!(
            observation.scope,
            dissect3d_api::ObservationScope::Binding,
            "SD-V09"
        );
        assert!(observation.selection["runtime_ref"].is_null());
        assert!(observation.selection["variant"].is_null());
        assert_eq!(observation.loaded.unwrap().status, "unknown");
        assert!(
            observation
                .eligibility
                .blockers
                .iter()
                .any(|blocker| blocker.code == "selection_required")
        );
    }

    fn document_position(package: &ControlledPackage, kind: &str, reference: &str) -> usize {
        let index: Value = serde_json::from_slice(&package.index_bytes).unwrap();
        index["documents"]
            .as_array()
            .unwrap()
            .iter()
            .position(|entry| entry["kind"] == kind && entry["ref"] == reference)
            .unwrap()
    }

    fn mutate_document(
        package: &mut ControlledPackage,
        kind: &str,
        reference: &str,
        mutate: impl FnOnce(&mut Value),
    ) {
        let index = document_position(package, kind, reference);
        let mut document: Value = serde_json::from_slice(&package.document_bytes[index]).unwrap();
        mutate(&mut document);
        replace_document(
            package,
            index,
            serde_json::to_vec(&document).expect("serialize changed document"),
        );
    }

    fn replace_document(package: &mut ControlledPackage, position: usize, bytes: Vec<u8>) {
        package.document_bytes[position] = bytes.clone();
        let mut index: Value = serde_json::from_slice(&package.index_bytes).unwrap();
        index["documents"][position]["sha256"] = Value::String(digest(&bytes));
        index["documents"][position]["byte_length"] = Value::from(bytes.len() as u64);
        package.index_bytes = serde_json::to_vec(&index).unwrap();
    }

    fn mutate_index(package: &mut ControlledPackage, mutate: impl FnOnce(&mut Value)) {
        let mut index: Value = serde_json::from_slice(&package.index_bytes).unwrap();
        mutate(&mut index);
        package.index_bytes = serde_json::to_vec(&index).unwrap();
    }
}
