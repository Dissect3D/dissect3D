//! Authenticated, bounded read routes for the engine-owned support catalog.

use super::{AuthorizedRequest, ServiceState, access};
use crate::support::{
    Catalog, DiscoveryError, InventoryQuery, InventoryResult, ModelRecord, ObservationFacts,
    Selection, TaskBindingRecord, for_model_binding, for_runtime, observe,
};
use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use dissect3d_api::{
    DiscoveryObservation, ErrorCode, InventoryDetail, ModelDetail, ModelListQuery, ModelSummary,
    PageQuery, RuntimeDetail, RuntimeSummary, TaskBindingDetail, TaskDetail, TaskKey,
    TaskListQuery,
};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) fn routes() -> Router<Arc<ServiceState>> {
    Router::new()
        .route("/v1/models", get(models_list))
        .route("/v1/models/{selector}", get(model_detail))
        .route("/v1/runtimes", get(runtimes_list))
        .route("/v1/runtimes/{selector}", get(runtime_detail))
        .route("/v1/tasks", get(tasks_list))
        .route("/v1/tasks/{selector}", get(task_detail))
}

async fn models_list(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    let params = match query_params(
        request.uri().query(),
        &["limit", "cursor", "task_id", "task_version", "loaded"],
        state.catalog.limits.query_bytes_max,
    ) {
        Ok(params) => params,
        Err(error) => return discovery_error(error),
    };
    let query = match model_list_query(&params) {
        Ok(query) => query,
        Err(error) => return discovery_error(error),
    };
    let result = state.catalog.list(
        authorized.identity.instance_id.as_str(),
        InventoryQuery::Models {
            limit: query.page.limit,
            cursor: query.page.cursor,
            task_id: query.task_id,
            task_version: query.task_version,
            loaded: query.loaded,
        },
    );
    match result {
        Ok(InventoryResult::Models(page)) => {
            success_response(&page, state.catalog.limits.response_bytes_max)
        }
        Ok(_) => discovery_error(DiscoveryError::InvalidRequest),
        Err(error) => discovery_error(error),
    }
}

async fn runtimes_list(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    let params = match query_params(
        request.uri().query(),
        &["limit", "cursor"],
        state.catalog.limits.query_bytes_max,
    ) {
        Ok(params) => params,
        Err(error) => return discovery_error(error),
    };
    let page = match page_query(&params) {
        Ok(page) => page,
        Err(error) => return discovery_error(error),
    };
    match state.catalog.list(
        authorized.identity.instance_id.as_str(),
        InventoryQuery::Runtimes {
            limit: page.limit,
            cursor: page.cursor,
        },
    ) {
        Ok(InventoryResult::Runtimes(page)) => {
            success_response(&page, state.catalog.limits.response_bytes_max)
        }
        Ok(_) => discovery_error(DiscoveryError::InvalidRequest),
        Err(error) => discovery_error(error),
    }
}

async fn tasks_list(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    let params = match query_params(
        request.uri().query(),
        &["limit", "cursor", "support_ref"],
        state.catalog.limits.query_bytes_max,
    ) {
        Ok(params) => params,
        Err(error) => return discovery_error(error),
    };
    let query: TaskListQuery = match task_list_query(&params) {
        Ok(query) => query,
        Err(error) => return discovery_error(error),
    };
    match state.catalog.list(
        authorized.identity.instance_id.as_str(),
        InventoryQuery::Tasks {
            limit: query.page.limit,
            cursor: query.page.cursor,
            support_ref: query.support_ref,
        },
    ) {
        Ok(InventoryResult::Tasks(page)) => {
            success_response(&page, state.catalog.limits.response_bytes_max)
        }
        Ok(_) => discovery_error(DiscoveryError::InvalidRequest),
        Err(error) => discovery_error(error),
    }
}

async fn model_detail(State(state): State<Arc<ServiceState>>, request: Request<Body>) -> Response {
    let selector = match path_selector(request.uri().path(), "/v1/models/") {
        Ok(selector) if valid_model_selector(&selector) => selector,
        _ => return discovery_error(DiscoveryError::InvalidRequest),
    };
    let params = match query_params(
        request.uri().query(),
        &["task_id", "task_version", "runtime_ref", "variant"],
        state.catalog.limits.query_bytes_max,
    ) {
        Ok(params) => params,
        Err(error) => return discovery_error(error),
    };
    let selection = match model_selection(&params, &selector, &state.catalog) {
        Ok(selection) => selection,
        Err(error) => return discovery_error(error),
    };
    let Some(model) = state.catalog.model(&selector) else {
        return discovery_error(DiscoveryError::NotFound);
    };
    let observations = match model_observations(&state.catalog, model, selection.as_ref()) {
        Ok(observations) => observations,
        Err(error) => return discovery_error(error),
    };
    let item = ModelDetail {
        summary: ModelSummary {
            id: model.id.clone(),
            support_ref: model.support_ref.clone(),
            description: model.description.clone(),
            test_only: model.test_only,
            observations,
        },
        declaration: model.declaration.clone(),
        schemas: model.schemas.clone(),
    };
    detail_response(&state.catalog, item, state.catalog.limits.detail_bytes_max)
}

async fn runtime_detail(
    State(state): State<Arc<ServiceState>>,
    request: Request<Body>,
) -> Response {
    let selector = match path_selector(request.uri().path(), "/v1/runtimes/") {
        Ok(selector) if valid_runtime_selector(&selector) => selector,
        _ => return discovery_error(DiscoveryError::InvalidRequest),
    };
    if let Err(error) = query_params(
        request.uri().query(),
        &[],
        state.catalog.limits.query_bytes_max,
    ) {
        return discovery_error(error);
    }
    let Some(runtime) = state.catalog.runtime(&selector) else {
        return discovery_error(DiscoveryError::NotFound);
    };
    let (scope, evidence, tested) = for_runtime(runtime);
    let observations = vec![observe(
        &scope,
        &ObservationFacts::phase_two(&scope),
        evidence,
        tested,
    )];
    let item = RuntimeDetail {
        summary: RuntimeSummary {
            id: runtime.id.clone(),
            runtime_ref: runtime.runtime_ref.clone(),
            description: runtime.description.clone(),
            test_only: runtime.test_only,
            observations,
        },
        declaration: runtime.declaration.clone(),
    };
    detail_response(&state.catalog, item, state.catalog.limits.detail_bytes_max)
}

async fn task_detail(State(state): State<Arc<ServiceState>>, request: Request<Body>) -> Response {
    let selector = match path_selector(request.uri().path(), "/v1/tasks/") {
        Ok(selector) if valid_task_selector(&selector) => selector,
        _ => return discovery_error(DiscoveryError::InvalidRequest),
    };
    let params = match query_params(
        request.uri().query(),
        &["version", "support_ref"],
        state.catalog.limits.query_bytes_max,
    ) {
        Ok(params) => params,
        Err(error) => return discovery_error(error),
    };
    let version = match params.get("version") {
        Some(version) if valid_task_version(version) => Some(version.as_str()),
        Some(_) => return discovery_error(DiscoveryError::InvalidRequest),
        None => None,
    };
    let support_ref = match params.get("support_ref") {
        Some(reference) if valid_reference(reference) => Some(reference.as_str()),
        Some(_) => return discovery_error(DiscoveryError::InvalidRequest),
        None => None,
    };
    let bindings = match task_bindings(&state.catalog, &selector, version, support_ref) {
        Ok(bindings) => bindings,
        Err(error) => return discovery_error(error),
    };
    let task = bindings.first().map(|binding| binding.task.clone());
    let Some(task) = task else {
        return discovery_error(DiscoveryError::NotFound);
    };
    let mut details = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let Some(model) = state.catalog.models.get(&binding.support_ref) else {
            return discovery_error(DiscoveryError::NotFound);
        };
        let (scope, evidence, tested) =
            match for_model_binding(&state.catalog, model, binding, None) {
                Ok(parts) => parts,
                Err(error) => return discovery_error(error),
            };
        let observation = observe(
            &scope,
            &ObservationFacts::phase_two(&scope),
            evidence,
            tested,
        );
        let detail = TaskBindingDetail {
            id: binding.id.clone(),
            task: binding.task.clone(),
            support_ref: binding.support_ref.clone(),
            description: binding.description.clone(),
            test_only: model.test_only,
            observations: vec![observation],
            binding: binding.binding.clone(),
            schemas: binding.schemas.clone(),
        };
        if encoded_len(&detail).is_none_or(|bytes| bytes > state.catalog.limits.detail_bytes_max) {
            return discovery_error(DiscoveryError::TransferLimit);
        }
        details.push(detail);
    }
    detail_response(
        &state.catalog,
        TaskDetail {
            task,
            bindings: details,
        },
        state.catalog.limits.response_bytes_max,
    )
}

fn model_list_query(params: &BTreeMap<String, String>) -> Result<ModelListQuery, DiscoveryError> {
    let task_id = params.get("task_id").cloned();
    let task_version = params.get("task_version").cloned();
    if task_id.as_deref().is_some_and(|id| !valid_task_id(id))
        || task_version
            .as_deref()
            .is_some_and(|version| !valid_task_version(version))
        || (task_version.is_some() && task_id.is_none())
    {
        return Err(DiscoveryError::InvalidRequest);
    }
    let loaded = match params.get("loaded").map(String::as_str) {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return Err(DiscoveryError::InvalidRequest),
    };
    Ok(ModelListQuery {
        page: page_query(params)?,
        task_id,
        task_version,
        loaded,
    })
}

fn task_list_query(params: &BTreeMap<String, String>) -> Result<TaskListQuery, DiscoveryError> {
    let support_ref = match params.get("support_ref") {
        Some(reference) if valid_reference(reference) => Some(reference.clone()),
        Some(_) => return Err(DiscoveryError::InvalidRequest),
        None => None,
    };
    Ok(TaskListQuery {
        page: page_query(params)?,
        support_ref,
    })
}

pub(super) fn page_query(params: &BTreeMap<String, String>) -> Result<PageQuery, DiscoveryError> {
    let limit = match params.get("limit") {
        Some(value) => {
            if value.is_empty()
                || value.len() > 3
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err(DiscoveryError::InvalidRequest);
            }
            let parsed = value
                .parse::<u8>()
                .map_err(|_| DiscoveryError::InvalidRequest)?;
            if !(1..=100).contains(&parsed) {
                return Err(DiscoveryError::InvalidRequest);
            }
            Some(parsed)
        }
        None => None,
    };
    Ok(PageQuery {
        limit,
        cursor: params.get("cursor").cloned(),
    })
}

fn model_selection(
    params: &BTreeMap<String, String>,
    selector: &str,
    catalog: &Catalog,
) -> Result<Option<Selection>, DiscoveryError> {
    let task_id = params.get("task_id");
    let task_version = params.get("task_version");
    let runtime_ref = params.get("runtime_ref");
    let variant = params.get("variant");
    if task_id.is_some() != task_version.is_some()
        || (task_id.is_none() && (runtime_ref.is_some() || variant.is_some()))
    {
        return Err(DiscoveryError::InvalidRequest);
    }
    if task_id.is_none() {
        return Ok(None);
    }
    let task = TaskKey::new(task_id.unwrap(), task_version.unwrap())
        .map_err(|_| DiscoveryError::InvalidRequest)?;
    if runtime_ref.is_some_and(|value| !valid_runtime_selector(value))
        || variant.is_some_and(|value| !valid_name(value))
    {
        return Err(DiscoveryError::InvalidRequest);
    }
    let model = catalog.model(selector).ok_or(DiscoveryError::NotFound)?;
    if !model.tasks.iter().any(|binding| binding.task == task) {
        return Err(DiscoveryError::NotFound);
    }
    Ok(Some(Selection {
        support_ref: model.support_ref.clone(),
        task,
        runtime_ref: runtime_ref.cloned(),
        variant: variant.cloned(),
    }))
}

fn model_observations(
    catalog: &Catalog,
    model: &ModelRecord,
    selection: Option<&Selection>,
) -> Result<Vec<DiscoveryObservation>, DiscoveryError> {
    let mut observations = Vec::with_capacity(if selection.is_some() {
        1
    } else {
        model.tasks.len()
    });
    if let Some(selection) = selection {
        let binding = model
            .tasks
            .iter()
            .find(|binding| binding.task == selection.task)
            .ok_or(DiscoveryError::NotFound)?;
        let (scope, evidence, tested) =
            for_model_binding(catalog, model, binding, Some(selection))?;
        observations.push(observe(
            &scope,
            &ObservationFacts::phase_two(&scope),
            evidence,
            tested,
        ));
    } else {
        for binding in &model.tasks {
            let (scope, evidence, tested) = for_model_binding(catalog, model, binding, None)?;
            observations.push(observe(
                &scope,
                &ObservationFacts::phase_two(&scope),
                evidence,
                tested,
            ));
        }
    }
    Ok(observations)
}

fn task_bindings<'a>(
    catalog: &'a Catalog,
    selector: &str,
    version: Option<&str>,
    support_ref: Option<&str>,
) -> Result<Vec<&'a TaskBindingRecord>, DiscoveryError> {
    if is_public_id(selector, "tsk_") {
        let Some(binding) = catalog.tasks.get(selector) else {
            return Err(DiscoveryError::NotFound);
        };
        if version.is_some_and(|version| version != binding.task.version())
            || support_ref.is_some_and(|reference| reference != binding.support_ref)
        {
            return Err(DiscoveryError::InvalidRequest);
        }
        return Ok(vec![binding]);
    }
    let mut matches = catalog
        .tasks
        .values()
        .filter(|binding| {
            binding.task.id() == selector
                && version.is_none_or(|version| binding.task.version() == version)
                && support_ref.is_none_or(|reference| binding.support_ref == reference)
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(DiscoveryError::NotFound);
    }
    let versions = matches
        .iter()
        .map(|binding| binding.task.version())
        .collect::<BTreeSet<_>>();
    if version.is_none() && versions.len() > 1 {
        matches.sort_by(|left, right| left.id.cmp(&right.id));
        let candidates = matches
            .iter()
            .take(17)
            .map(|binding| binding.id.clone())
            .collect::<Vec<_>>();
        let truncated = candidates.len() > 16;
        return Err(DiscoveryError::AmbiguousSelection {
            candidates: candidates.into_iter().take(16).collect(),
            candidates_truncated: truncated,
        });
    }
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(matches)
}

fn detail_response<T: Serialize>(catalog: &Catalog, item: T, detail_limit: usize) -> Response {
    if encoded_len(&item).is_none_or(|bytes| bytes > detail_limit) {
        return discovery_error(DiscoveryError::TransferLimit);
    }
    let envelope = InventoryDetail {
        api_version: "1.0".to_owned(),
        catalog_revision: catalog.revision.clone(),
        item,
    };
    success_response(&envelope, catalog.limits.response_bytes_max)
}

fn success_response<T: Serialize>(value: &T, maximum: usize) -> Response {
    let Some(bytes) = serde_json::to_vec(value).ok() else {
        return discovery_error(DiscoveryError::TransferLimit);
    };
    if bytes.len() > maximum {
        return discovery_error(DiscoveryError::TransferLimit);
    }
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn encoded_len<T: Serialize>(value: &T) -> Option<usize> {
    serde_json::to_vec(value).ok().map(|bytes| bytes.len())
}

fn discovery_error(error: DiscoveryError) -> Response {
    match error {
        DiscoveryError::NotFound => {
            access::discovery_error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound, None)
        }
        DiscoveryError::AmbiguousSelection {
            candidates,
            candidates_truncated,
        } => {
            let details = json!({
                "candidates": candidates.into_iter().take(16).collect::<Vec<_>>(),
                "candidates_truncated": candidates_truncated,
                "guidance": "select_version_or_support",
            });
            access::discovery_error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::AmbiguousSelection,
                Some(details),
            )
        }
        DiscoveryError::RequiredFeatureUnsupported => access::discovery_error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::RequiredFeatureUnsupported,
            Some(json!({"guidance":"review_supported_fields"})),
        ),
        DiscoveryError::InvalidRequest => {
            access::error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false)
        }
        DiscoveryError::CursorExpired => access::discovery_error_response(
            StatusCode::CONFLICT,
            ErrorCode::InventoryCursorExpired,
            Some(json!({"guidance":"restart_listing"})),
        ),
        DiscoveryError::TransferLimit => access::discovery_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::TransferLimit,
            Some(json!({"guidance":"select_support_or_reduce_page"})),
        ),
    }
}

pub(super) fn query_params(
    raw: Option<&str>,
    allowed: &[&str],
    maximum: usize,
) -> Result<BTreeMap<String, String>, DiscoveryError> {
    let Some(raw) = raw else {
        return Ok(BTreeMap::new());
    };
    if raw.len() > maximum {
        return Err(DiscoveryError::TransferLimit);
    }
    if raw.is_empty() {
        return Err(DiscoveryError::InvalidRequest);
    }
    let mut params = BTreeMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            return Err(DiscoveryError::InvalidRequest);
        }
        let (raw_key, raw_value) = pair.split_once('=').ok_or(DiscoveryError::InvalidRequest)?;
        let key = decode_component(raw_key, true)?;
        let value = decode_component(raw_value, true)?;
        if key.is_empty()
            || value.is_empty()
            || !allowed.contains(&key.as_str())
            || params.insert(key, value).is_some()
        {
            return Err(DiscoveryError::InvalidRequest);
        }
    }
    Ok(params)
}

fn path_selector(path: &str, prefix: &str) -> Result<String, DiscoveryError> {
    let raw = path
        .strip_prefix(prefix)
        .ok_or(DiscoveryError::InvalidRequest)?;
    if raw.is_empty() || raw.contains('/') {
        return Err(DiscoveryError::InvalidRequest);
    }
    let decoded = decode_component(raw, false)?;
    if decoded.is_empty()
        || decoded == "."
        || decoded == ".."
        || decoded.contains('/')
        || decoded.contains('\\')
    {
        return Err(DiscoveryError::InvalidRequest);
    }
    Ok(decoded)
}

fn decode_component(raw: &str, plus_as_space: bool) -> Result<String, DiscoveryError> {
    let input = raw.as_bytes();
    let mut bytes = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'%' => {
                let Some(pair) = input.get(index + 1..index + 3) else {
                    return Err(DiscoveryError::InvalidRequest);
                };
                let high = hex(pair[0]).ok_or(DiscoveryError::InvalidRequest)?;
                let low = hex(pair[1]).ok_or(DiscoveryError::InvalidRequest)?;
                bytes.push((high << 4) | low);
                index += 3;
            }
            b'+' if plus_as_space => {
                bytes.push(b' ');
                index += 1;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    let value = String::from_utf8(bytes).map_err(|_| DiscoveryError::InvalidRequest)?;
    if value.chars().any(char::is_control) || value.contains('\\') || value.contains('/') {
        return Err(DiscoveryError::InvalidRequest);
    }
    Ok(value)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_task_id(value: &str) -> bool {
    valid_name(value)
        && !["mdl_", "rtp_", "tsk_"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

fn valid_task_version(value: &str) -> bool {
    TaskKey::new("task", value).is_ok()
}

fn valid_reference(value: &str) -> bool {
    let Some((name, revision)) = value.split_once('@') else {
        return false;
    };
    valid_name(name) && valid_name(revision)
}

fn valid_model_selector(value: &str) -> bool {
    is_public_id(value, "mdl_")
        || valid_reference(value)
        || (valid_name(value) && !value.starts_with("mdl_"))
}

fn valid_runtime_selector(value: &str) -> bool {
    is_public_id(value, "rtp_")
        || valid_reference(value)
        || (valid_name(value) && !value.starts_with("rtp_"))
}

fn valid_task_selector(value: &str) -> bool {
    is_public_id(value, "tsk_") || valid_task_id(value)
}

fn is_public_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_query_parser_normalizes_and_rejects_ambiguous_encodings() {
        assert_eq!(
            query_params(
                Some("task%5Fid=dissect3d.test%2Emesh-copy"),
                &["task_id"],
                4096
            )
            .unwrap()["task_id"],
            "dissect3d.test.mesh-copy"
        );
        for query in [
            "task_id=a&task_id=b",
            "task_id",
            "task_id=",
            "unknown=x",
            "task_id=a%2Fb",
            "task_id=%GG",
        ] {
            assert!(
                query_params(Some(query), &["task_id"], 4096).is_err(),
                "{query}"
            );
        }
        let plus = query_params(Some("task_id=a+b"), &["task_id"], 4096).unwrap();
        assert!(model_list_query(&plus).is_err());
    }

    #[test]
    fn path_selector_decodes_once_and_rejects_slash_and_controls() {
        assert_eq!(
            path_selector("/v1/models/test.mesh-copy%40fixture-r1", "/v1/models/").unwrap(),
            "test.mesh-copy@fixture-r1"
        );
        for path in ["/v1/models/%2F", "/v1/models/%0A"] {
            assert!(path_selector(path, "/v1/models/").is_err());
        }
        let encoded_twice = path_selector("/v1/models/%252F", "/v1/models/").unwrap();
        assert!(!valid_model_selector(&encoded_twice));
    }
}
