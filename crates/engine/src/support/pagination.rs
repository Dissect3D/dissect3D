//! Stable bounded inventory pages and restart-bound opaque cursors.

use super::observations::{ObservationFacts, for_model_binding, for_runtime, observe};
use super::{Catalog, DiscoveryError};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dissect3d_api::{InventoryPage, ModelSummary, RuntimeSummary, TaskSummary};
use serde_json::{Value, json};

#[derive(Clone, Debug)]
pub(crate) enum InventoryQuery {
    Models {
        limit: Option<u8>,
        cursor: Option<String>,
        task_id: Option<String>,
        task_version: Option<String>,
        loaded: Option<bool>,
    },
    Runtimes {
        limit: Option<u8>,
        cursor: Option<String>,
    },
    Tasks {
        limit: Option<u8>,
        cursor: Option<String>,
        support_ref: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum InventoryResult {
    Models(InventoryPage<ModelSummary>),
    Runtimes(InventoryPage<RuntimeSummary>),
    Tasks(InventoryPage<TaskSummary>),
}

#[derive(Clone, Debug)]
struct CursorState {
    instance_id: String,
    catalog_revision: String,
    collection: String,
    filters: Value,
    limit: u8,
    last_id: String,
}

struct PageContext<'a> {
    instance_id: &'a str,
    revision: &'a str,
    collection: &'a str,
    filters: Value,
    requested_limit: Option<u8>,
    cursor: Option<String>,
    limits: super::DiscoveryLimits,
}

impl Catalog {
    pub(crate) fn list(
        &self,
        instance_id: &str,
        query: InventoryQuery,
    ) -> Result<InventoryResult, DiscoveryError> {
        match query {
            InventoryQuery::Models {
                limit,
                cursor,
                task_id,
                task_version,
                loaded,
            } => {
                let filters = json!({
                    "task_id": task_id,
                    "task_version": task_version,
                    "loaded": loaded,
                });
                let ids = self
                    .models
                    .values()
                    .filter(|model| {
                        task_id.as_ref().is_none_or(|id| {
                            model.tasks.iter().any(|binding| {
                                binding.task.id() == id
                                    && task_version
                                        .as_ref()
                                        .is_none_or(|version| binding.task.version() == version)
                            })
                        }) && loaded != Some(true)
                    })
                    .map(|model| model.id.clone())
                    .collect::<Vec<_>>();
                let summaries = ids
                    .iter()
                    .map(|id| {
                        let model = self
                            .models
                            .values()
                            .find(|model| &model.id == id)
                            .ok_or(DiscoveryError::NotFound)?;
                        let mut observations = Vec::new();
                        for binding in &model.tasks {
                            let (scope, evidence, tested) =
                                for_model_binding(self, model, binding, None)?;
                            observations.push(observe(
                                &scope,
                                &ObservationFacts::phase_two(&scope),
                                evidence,
                                tested,
                            ));
                        }
                        Ok(ModelSummary {
                            id: model.id.clone(),
                            support_ref: model.support_ref.clone(),
                            description: model.description.clone(),
                            test_only: model.test_only,
                            observations,
                        })
                    })
                    .collect::<Result<Vec<_>, DiscoveryError>>()?;
                let page = make_page(
                    PageContext {
                        instance_id,
                        revision: &self.revision,
                        collection: "models",
                        filters,
                        requested_limit: limit,
                        cursor,
                        limits: self.limits,
                    },
                    summaries,
                    |item| item.id.clone(),
                )?;
                Ok(InventoryResult::Models(page))
            }
            InventoryQuery::Runtimes { limit, cursor } => {
                let filters = json!({});
                let items = self
                    .runtimes
                    .values()
                    .map(|runtime| {
                        let (scope, evidence, tested) = for_runtime(runtime);
                        let facts = ObservationFacts::phase_two(&scope);
                        RuntimeSummary {
                            id: runtime.id.clone(),
                            runtime_ref: runtime.runtime_ref.clone(),
                            description: runtime.description.clone(),
                            test_only: runtime.test_only,
                            observations: vec![observe(&scope, &facts, evidence, tested)],
                        }
                    })
                    .collect::<Vec<_>>();
                let page = make_page(
                    PageContext {
                        instance_id,
                        revision: &self.revision,
                        collection: "runtimes",
                        filters,
                        requested_limit: limit,
                        cursor,
                        limits: self.limits,
                    },
                    items,
                    |item| item.id.clone(),
                )?;
                Ok(InventoryResult::Runtimes(page))
            }
            InventoryQuery::Tasks {
                limit,
                cursor,
                support_ref,
            } => {
                let filters = json!({"support_ref": support_ref.clone()});
                let items = self
                    .tasks
                    .values()
                    .filter(|task| {
                        support_ref
                            .as_ref()
                            .is_none_or(|reference| reference == &task.support_ref)
                    })
                    .map(|task| {
                        let model = self
                            .models
                            .get(&task.support_ref)
                            .ok_or(DiscoveryError::NotFound)?;
                        let (scope, evidence, tested) = for_model_binding(self, model, task, None)?;
                        let observation = observe(
                            &scope,
                            &ObservationFacts::phase_two(&scope),
                            evidence,
                            tested,
                        );
                        Ok(TaskSummary {
                            id: task.id.clone(),
                            task: task.task.clone(),
                            support_ref: task.support_ref.clone(),
                            description: task.description.clone(),
                            test_only: model.test_only,
                            observations: vec![observation],
                        })
                    })
                    .collect::<Result<Vec<_>, DiscoveryError>>()?;
                let page = make_page(
                    PageContext {
                        instance_id,
                        revision: &self.revision,
                        collection: "tasks",
                        filters,
                        requested_limit: limit,
                        cursor,
                        limits: self.limits,
                    },
                    items,
                    |item| item.id.clone(),
                )?;
                Ok(InventoryResult::Tasks(page))
            }
        }
    }
}

fn make_page<T, F>(
    context: PageContext<'_>,
    mut items: Vec<T>,
    id: F,
) -> Result<InventoryPage<T>, DiscoveryError>
where
    T: serde::Serialize + Clone,
    F: Fn(&T) -> String,
{
    let PageContext {
        instance_id,
        revision,
        collection,
        filters,
        requested_limit,
        cursor,
        limits,
    } = context;
    let limit = requested_limit.unwrap_or(limits.page_default);
    if !(1..=limits.page_max).contains(&limit) {
        return Err(DiscoveryError::InvalidRequest);
    }
    items.sort_by_key(&id);
    let start = if let Some(token) = cursor {
        if token.len() > limits.cursor_bytes_max {
            return Err(DiscoveryError::InvalidRequest);
        }
        let state = decode_cursor(&token, limits)?;
        if state.instance_id != instance_id || state.catalog_revision != revision {
            return Err(DiscoveryError::CursorExpired);
        }
        if state.collection != collection || state.filters != filters || state.limit != limit {
            return Err(DiscoveryError::InvalidRequest);
        }
        let Some(index) = items.iter().position(|item| id(item) == state.last_id) else {
            return Err(DiscoveryError::InvalidRequest);
        };
        index + 1
    } else {
        0
    };
    let available = &items[start..];
    let mut selected = available
        .iter()
        .take(usize::from(limit))
        .cloned()
        .collect::<Vec<_>>();
    loop {
        let has_more = selected.len() < available.len();
        let next_cursor = if has_more {
            selected
                .last()
                .map(|last| {
                    encode_cursor(
                        CursorState {
                            instance_id: instance_id.to_owned(),
                            catalog_revision: revision.to_owned(),
                            collection: collection.to_owned(),
                            filters: filters.clone(),
                            limit,
                            last_id: id(last),
                        },
                        limits,
                    )
                })
                .transpose()?
        } else {
            None
        };
        let page = InventoryPage {
            api_version: "1.0".to_owned(),
            catalog_revision: revision.to_owned(),
            items: selected.clone(),
            truncated: next_cursor.is_some(),
            next_cursor,
        };
        let encoded = serde_json::to_vec(&page).map_err(|_| DiscoveryError::TransferLimit)?;
        if encoded.len() <= limits.response_bytes_max {
            return Ok(page);
        }
        if selected.pop().is_none() || selected.is_empty() {
            return Err(DiscoveryError::TransferLimit);
        }
    }
}

fn encode_cursor(
    state: CursorState,
    limits: super::DiscoveryLimits,
) -> Result<String, DiscoveryError> {
    let instance =
        serde_json::to_string(&state.instance_id).map_err(|_| DiscoveryError::InvalidRequest)?;
    let revision = serde_json::to_string(&state.catalog_revision)
        .map_err(|_| DiscoveryError::InvalidRequest)?;
    let last_id =
        serde_json::to_string(&state.last_id).map_err(|_| DiscoveryError::InvalidRequest)?;
    let filters = match state.collection.as_str() {
        "models" => format!(
            "{{\"task_id\":{},\"task_version\":{},\"loaded\":{}}}",
            option_string(&state.filters["task_id"])?,
            option_string(&state.filters["task_version"])?,
            option_bool(&state.filters["loaded"])?
        ),
        "runtimes" => "{}".to_owned(),
        "tasks" => format!(
            "{{\"support_ref\":{}}}",
            option_string(&state.filters["support_ref"])?
        ),
        _ => return Err(DiscoveryError::InvalidRequest),
    };
    let bytes = format!(
        "{{\"version\":\"1.0\",\"instance_id\":{instance},\"catalog_revision\":{revision},\"collection\":{},\"filters\":{filters},\"limit\":{},\"order\":\"id_asc\",\"last_id\":{last_id}}}",
        serde_json::to_string(&state.collection).map_err(|_| DiscoveryError::InvalidRequest)?,
        state.limit,
    );
    let encoded = URL_SAFE_NO_PAD.encode(bytes.as_bytes());
    if encoded.len() > limits.cursor_bytes_max {
        return Err(DiscoveryError::TransferLimit);
    }
    Ok(encoded)
}

fn decode_cursor(
    token: &str,
    limits: super::DiscoveryLimits,
) -> Result<CursorState, DiscoveryError> {
    if token.is_empty()
        || token.len() > limits.cursor_bytes_max
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(DiscoveryError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| DiscoveryError::InvalidRequest)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(DiscoveryError::InvalidRequest);
    }
    let value: Value =
        dissect3d_api::decode_json(&bytes).map_err(|_| DiscoveryError::InvalidRequest)?;
    if !exact_keys(
        &value,
        &[
            "version",
            "instance_id",
            "catalog_revision",
            "collection",
            "filters",
            "limit",
            "order",
            "last_id",
        ],
    ) || value["version"] != "1.0"
        || value["order"] != "id_asc"
    {
        return Err(DiscoveryError::InvalidRequest);
    }
    let collection = value["collection"]
        .as_str()
        .ok_or(DiscoveryError::InvalidRequest)?
        .to_owned();
    let filters = &value["filters"];
    match collection.as_str() {
        "models" if exact_keys(filters, &["task_id", "task_version", "loaded"]) => {
            if !filters["task_id"].is_null()
                && filters["task_id"].as_str().is_none_or(|s| !valid_name(s))
                || !filters["task_version"].is_null()
                    && (filters["task_id"].is_null()
                        || filters["task_version"]
                            .as_str()
                            .is_none_or(|s| !valid_version(s)))
                || (!filters["loaded"].is_null() && filters["loaded"].as_bool().is_none())
            {
                return Err(DiscoveryError::InvalidRequest);
            }
        }
        "runtimes" if exact_keys(filters, &[]) => {}
        "tasks" if exact_keys(filters, &["support_ref"]) => {
            if !filters["support_ref"].is_null()
                && filters["support_ref"]
                    .as_str()
                    .is_none_or(|s| !valid_reference(s))
            {
                return Err(DiscoveryError::InvalidRequest);
            }
        }
        _ => return Err(DiscoveryError::InvalidRequest),
    }
    let instance_id = value["instance_id"]
        .as_str()
        .filter(|s| is_instance_id(s))
        .ok_or(DiscoveryError::InvalidRequest)?
        .to_owned();
    let catalog_revision = value["catalog_revision"]
        .as_str()
        .filter(|s| is_digest(s))
        .ok_or(DiscoveryError::InvalidRequest)?
        .to_owned();
    let limit = value["limit"]
        .as_u64()
        .and_then(|v| u8::try_from(v).ok())
        .filter(|v| (1..=limits.page_max).contains(v))
        .ok_or(DiscoveryError::InvalidRequest)?;
    let last_id = value["last_id"]
        .as_str()
        .filter(|s| match collection.as_str() {
            "models" => s.starts_with("mdl_") && is_public_id(s),
            "runtimes" => s.starts_with("rtp_") && is_public_id(s),
            "tasks" => s.starts_with("tsk_") && is_public_id(s),
            _ => false,
        })
        .ok_or(DiscoveryError::InvalidRequest)?
        .to_owned();
    let state = CursorState {
        instance_id,
        catalog_revision,
        collection,
        filters: filters.clone(),
        limit,
        last_id,
    };
    if encode_cursor(state.clone(), limits)? != token {
        return Err(DiscoveryError::InvalidRequest);
    }
    Ok(state)
}

fn option_string(value: &Value) -> Result<String, DiscoveryError> {
    if value.is_null() {
        Ok("null".to_owned())
    } else {
        serde_json::to_string(value.as_str().ok_or(DiscoveryError::InvalidRequest)?)
            .map_err(|_| DiscoveryError::InvalidRequest)
    }
}
fn option_bool(value: &Value) -> Result<String, DiscoveryError> {
    if value.is_null() {
        Ok("null".to_owned())
    } else {
        value
            .as_bool()
            .map(|v| v.to_string())
            .ok_or(DiscoveryError::InvalidRequest)
    }
}
fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn valid_reference(value: &str) -> bool {
    let Some((name, revision)) = value.split_once('@') else {
        return false;
    };
    valid_name(name) && valid_name(revision)
}
fn valid_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid = |p: &str| {
        !p.is_empty()
            && !(p.len() > 1 && p.starts_with('0'))
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok()
    };
    matches!((parts.next(),parts.next(),parts.next()),(Some(a),Some(b),None)if valid(a)&&valid(b))
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_public_id(value: &str) -> bool {
    value.len() == 68
        && value[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_instance_id(value: &str) -> bool {
    value.strip_prefix("eng_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[cfg(test)]
mod tests {
    use super::super::DiscoveryLimits;
    use super::*;
    use serde_json::Value;

    #[test]
    fn cursor_is_canonical_and_binds_filters_limit_and_instance() {
        let state = CursorState {
            instance_id: "eng_0123456789abcdef0123456789abcdef".into(),
            catalog_revision: "a08d0eebb9c0c86c19a40d5835de4f3c5e587203c9ead10f2a8b511a6212005e"
                .into(),
            collection: "models".into(),
            filters: json!({"task_id":null,"task_version":null,"loaded":null}),
            limit: 1,
            last_id: "mdl_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        };
        let encoded = encode_cursor(state.clone(), DiscoveryLimits::default()).unwrap();
        let decoded = decode_cursor(&encoded, DiscoveryLimits::default()).unwrap();
        assert_eq!(decoded.instance_id, state.instance_id);
        assert_eq!(decoded.last_id, state.last_id);
        assert!(decode_cursor(&(encoded.clone() + "="), DiscoveryLimits::default()).is_err());
        assert!(decode_cursor("***", DiscoveryLimits::default()).is_err());
    }

    #[test]
    fn cursor_matches_the_protected_wire_vector() {
        let state = CursorState {
            instance_id: "eng_0123456789abcdef0123456789abcdef".into(),
            catalog_revision: "b57f1eb8fe31b228e294bff06f9a10869f22f1af996ee5ed11b1381263c1f68b"
                .into(),
            collection: "models".into(),
            filters: json!({"task_id":null,"task_version":null,"loaded":null}),
            limit: 1,
            last_id: "mdl_6b32152ee6058b9b0babf6204080f368ce616aeffe1218012e780fffb44b0629".into(),
        };
        let vectors: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/support-discovery/vectors.json"
        ))
        .unwrap();
        let encoded = encode_cursor(state, DiscoveryLimits::default()).unwrap();
        assert_eq!(encoded, vectors["cursor"]["encoded"]);
        assert_eq!(
            decode_cursor(&encoded, DiscoveryLimits::default())
                .unwrap()
                .limit,
            1
        );
    }

    #[test]
    fn catalog_pages_continue_once_and_expire_on_restart() {
        let catalog = super::super::fixture_catalog();
        let instance = "eng_0123456789abcdef0123456789abcdef";
        let first = catalog
            .list(
                instance,
                InventoryQuery::Models {
                    limit: Some(1),
                    cursor: None,
                    task_id: None,
                    task_version: None,
                    loaded: None,
                },
            )
            .unwrap();
        let InventoryResult::Models(first) = first else {
            panic!("model inventory returned another collection");
        };
        assert_eq!(first.items.len(), 1);
        assert!(first.truncated);
        let token = first.next_cursor.clone().unwrap();
        let first_id = first.items[0].id.clone();
        let mut all_ids = vec![first_id.clone()];
        let mut cursor = Some(token.clone());
        while let Some(current) = cursor.take() {
            let page = catalog
                .list(
                    instance,
                    InventoryQuery::Models {
                        limit: Some(1),
                        cursor: Some(current),
                        task_id: None,
                        task_version: None,
                        loaded: None,
                    },
                )
                .unwrap();
            let InventoryResult::Models(page) = page else {
                panic!("model inventory returned another collection");
            };
            all_ids.extend(page.items.iter().map(|item| item.id.clone()));
            cursor = page.next_cursor;
        }
        assert_eq!(all_ids.len(), 5);
        assert_eq!(
            all_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            5
        );
        assert_eq!(all_ids, {
            let mut sorted = all_ids.clone();
            sorted.sort();
            sorted
        });

        let changed_instance = catalog.list(
            "eng_ffffffffffffffffffffffffffffffff",
            InventoryQuery::Models {
                limit: Some(1),
                cursor: Some(token.clone()),
                task_id: None,
                task_version: None,
                loaded: None,
            },
        );
        assert_eq!(changed_instance.unwrap_err(), DiscoveryError::CursorExpired);

        let mut changed_catalog = catalog.clone();
        changed_catalog.revision = "0".repeat(64);
        assert_eq!(
            changed_catalog
                .list(
                    instance,
                    InventoryQuery::Models {
                        limit: Some(1),
                        cursor: Some(token.clone()),
                        task_id: None,
                        task_version: None,
                        loaded: None,
                    }
                )
                .unwrap_err(),
            DiscoveryError::CursorExpired
        );
        assert_eq!(
            catalog
                .list(
                    instance,
                    InventoryQuery::Models {
                        limit: Some(2),
                        cursor: Some(token.clone()),
                        task_id: None,
                        task_version: None,
                        loaded: None,
                    }
                )
                .unwrap_err(),
            DiscoveryError::InvalidRequest
        );
        assert_eq!(
            catalog
                .list(
                    instance,
                    InventoryQuery::Models {
                        limit: Some(1),
                        cursor: Some(token.clone()),
                        task_id: Some("dissect3d.test.shared".into()),
                        task_version: Some("1.0".into()),
                        loaded: None,
                    }
                )
                .unwrap_err(),
            DiscoveryError::InvalidRequest
        );
        assert_eq!(
            catalog
                .list(
                    instance,
                    InventoryQuery::Runtimes {
                        limit: Some(1),
                        cursor: Some(token),
                    }
                )
                .unwrap_err(),
            DiscoveryError::InvalidRequest
        );

        let absent_filter = catalog
            .list(
                instance,
                InventoryQuery::Models {
                    limit: Some(5),
                    cursor: None,
                    task_id: Some("dissect3d.unknown".into()),
                    task_version: None,
                    loaded: None,
                },
            )
            .unwrap();
        let InventoryResult::Models(absent_filter) = absent_filter else {
            panic!("model inventory returned another collection");
        };
        assert!(absent_filter.items.is_empty());
        assert!(absent_filter.next_cursor.is_none());
    }

    #[test]
    fn cursors_reject_missing_last_ids_and_duplicate_members() {
        let catalog = super::super::fixture_catalog();
        let instance = "eng_0123456789abcdef0123456789abcdef";
        let InventoryResult::Models(first) = catalog
            .list(
                instance,
                InventoryQuery::Models {
                    limit: Some(1),
                    cursor: None,
                    task_id: None,
                    task_version: None,
                    loaded: None,
                },
            )
            .unwrap()
        else {
            panic!("model inventory returned another collection");
        };
        let token = first.next_cursor.unwrap();
        let mut state = decode_cursor(&token, DiscoveryLimits::default()).unwrap();
        state.last_id = format!("mdl_{}", "0".repeat(64));
        let missing = encode_cursor(state, DiscoveryLimits::default()).unwrap();
        assert_eq!(
            catalog
                .list(
                    instance,
                    InventoryQuery::Models {
                        limit: Some(1),
                        cursor: Some(missing),
                        task_id: None,
                        task_version: None,
                        loaded: None,
                    }
                )
                .unwrap_err(),
            DiscoveryError::InvalidRequest
        );

        let duplicate = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"version":"1.0","version":"1.0"}"#);
        assert_eq!(
            catalog
                .list(
                    instance,
                    InventoryQuery::Models {
                        limit: Some(1),
                        cursor: Some(duplicate),
                        task_id: None,
                        task_version: None,
                        loaded: None,
                    }
                )
                .unwrap_err(),
            DiscoveryError::InvalidRequest
        );
    }

    #[test]
    fn serialized_page_budget_packs_or_rejects_at_the_boundary() {
        let ids = [
            format!("mdl_{}", "1".repeat(64)),
            format!("mdl_{}", "2".repeat(64)),
        ];
        let items = ids
            .iter()
            .map(|id| json!({"id":id,"payload":"x".repeat(1200)}))
            .collect::<Vec<_>>();
        let limits = DiscoveryLimits::default();
        let one = make_page(
            PageContext {
                instance_id: "eng_0123456789abcdef0123456789abcdef",
                revision: &"a".repeat(64),
                collection: "models",
                filters: json!({"task_id":null,"task_version":null,"loaded":null}),
                requested_limit: Some(1),
                cursor: None,
                limits,
            },
            items.clone(),
            |item| item["id"].as_str().unwrap().to_owned(),
        )
        .unwrap();
        let exact_boundary = serde_json::to_vec(&one).unwrap().len();
        let mut packed_limits = limits;
        packed_limits.response_bytes_max = exact_boundary;
        let packed = make_page(
            PageContext {
                instance_id: "eng_0123456789abcdef0123456789abcdef",
                revision: &"a".repeat(64),
                collection: "models",
                filters: json!({"task_id":null,"task_version":null,"loaded":null}),
                requested_limit: Some(2),
                cursor: None,
                limits: packed_limits,
            },
            items.clone(),
            |item| item["id"].as_str().unwrap().to_owned(),
        )
        .unwrap();
        assert_eq!(packed.items.len(), 1);
        assert!(packed.truncated);
        assert_eq!(serde_json::to_vec(&packed).unwrap().len(), exact_boundary);

        packed_limits.response_bytes_max -= 1;
        assert_eq!(
            make_page(
                PageContext {
                    instance_id: "eng_0123456789abcdef0123456789abcdef",
                    revision: &"a".repeat(64),
                    collection: "models",
                    filters: json!({"task_id":null,"task_version":null,"loaded":null}),
                    requested_limit: Some(2),
                    cursor: None,
                    limits: packed_limits,
                },
                items,
                |item| item["id"].as_str().unwrap().to_owned(),
            )
            .unwrap_err(),
            DiscoveryError::TransferLimit
        );
    }
}
