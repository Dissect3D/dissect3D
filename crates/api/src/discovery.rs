//! Transport-neutral identities used by support discovery.

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;

/// A single bounded inventory page. Clients must validate it before use.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryPage<T> {
    pub api_version: String,
    pub catalog_revision: String,
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

/// Exact operation capability advertised by an engine's optional info member.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCapability {
    pub version: String,
    pub operations: Vec<String>,
    pub authorization_grant: String,
}

/// One bounded inventory detail response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryDetail<T> {
    pub api_version: String,
    pub catalog_revision: String,
    pub item: T,
}

/// Common finite page arguments.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PageQuery {
    pub limit: Option<u8>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelListQuery {
    pub page: PageQuery,
    /// Optional task identifier. When `task_version` is absent, matches every
    /// declared version for this identifier.
    pub task_id: Option<String>,
    pub task_version: Option<String>,
    pub loaded: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskListQuery {
    pub page: PageQuery,
    pub support_ref: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelLookup {
    pub selector: String,
    pub task: Option<TaskKey>,
    pub runtime_ref: Option<String>,
    pub variant: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeLookup {
    pub selector: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskLookup {
    pub selector: String,
    pub version: Option<String>,
    pub support_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSummary {
    pub id: String,
    pub support_ref: String,
    pub description: String,
    pub test_only: bool,
    pub observations: Vec<DiscoveryObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSummary {
    pub id: String,
    pub runtime_ref: String,
    pub description: String,
    pub test_only: bool,
    pub observations: Vec<DiscoveryObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSummary {
    pub id: String,
    pub task: TaskKey,
    pub support_ref: String,
    pub description: String,
    pub test_only: bool,
    pub observations: Vec<DiscoveryObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaAttachment {
    pub document: Value,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelDetail {
    #[serde(flatten)]
    pub summary: ModelSummary,
    pub declaration: Value,
    pub schemas: Vec<SchemaAttachment>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDetail {
    #[serde(flatten)]
    pub summary: RuntimeSummary,
    pub declaration: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBindingDetail {
    pub id: String,
    pub task: TaskKey,
    pub support_ref: String,
    pub description: String,
    pub test_only: bool,
    pub observations: Vec<DiscoveryObservation>,
    pub binding: Value,
    pub schemas: Vec<SchemaAttachment>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDetail {
    pub task: TaskKey,
    pub bindings: Vec<TaskBindingDetail>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationScope {
    Selection,
    Binding,
    Runtime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceObservation {
    pub status: String,
    pub ids: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationObservation {
    pub status: String,
    pub realization: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessObservation {
    pub status: String,
    pub freshness: String,
    pub check_id: Option<String>,
    pub configuration_id: Option<String>,
    pub checked_at_ms: Option<u64>,
    pub fingerprint: Option<String>,
    pub findings: Vec<ObservationReason>,
    pub invalidation_reasons: Vec<ObservationReason>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReason {
    pub code: String,
    pub field: String,
    pub guidance: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EligibilityObservation {
    pub status: String,
    pub blockers: Vec<ObservationReason>,
    pub unknowns: Vec<ObservationReason>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorizationObservation {
    pub status: String,
    pub evaluation_required: bool,
    pub reasons: Vec<ObservationReason>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadedObservation {
    pub status: String,
    pub observed_at_ms: Option<u64>,
    pub allocation_ids: Vec<String>,
}

/// Operational facts remain independent; their values never imply each other.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryObservation {
    pub scope: ObservationScope,
    pub selection: Value,
    pub observed_at_ms: Option<u64>,
    pub evidence: EvidenceObservation,
    pub tested_profiles: Vec<Value>,
    pub installation: InstallationObservation,
    pub readiness: ReadinessObservation,
    pub eligibility: EligibilityObservation,
    pub execution_authorization: ExecutionAuthorizationObservation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded: Option<LoadedObservation>,
}

impl<T> InventoryPage<T> {
    /// Checks the version, revision and continuation invariants.
    pub fn validate(&self) -> Result<(), &'static str> {
        let digest = self.catalog_revision.as_bytes();
        if self.api_version != "1.0"
            || digest.len() != 64
            || !digest
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || self.truncated != self.next_cursor.is_some()
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
            || (self.truncated && self.items.is_empty())
            || self.items.len() > 100
        {
            return Err("invalid inventory page");
        }
        Ok(())
    }
}

/// A task identifier and its explicit schema-independent version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskKey {
    id: String,
    version: String,
}

impl TaskKey {
    /// Constructs a key only when both components satisfy the discovery contract.
    pub fn new(id: &str, version: &str) -> Result<Self, &'static str> {
        let valid_name = !id.is_empty()
            && id.len() <= 128
            && id != "."
            && id != ".."
            && !["mdl_", "rtp_", "tsk_"]
                .iter()
                .any(|prefix| id.starts_with(prefix))
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        let mut parts = version.split('.');
        let valid_component = |part: &str| {
            !part.is_empty()
                && !(part.len() > 1 && part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.parse::<u16>().is_ok()
        };
        let valid_version = matches!((parts.next(), parts.next(), parts.next()),
            (Some(major), Some(minor), None) if valid_component(major) && valid_component(minor));
        if !valid_name || !valid_version {
            return Err("invalid task key");
        }
        Ok(Self {
            id: id.into(),
            version: version.into(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl<'de> Deserialize<'de> for TaskKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: String,
            version: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(&wire.id, &wire.version).map_err(de::Error::custom)
    }
}
