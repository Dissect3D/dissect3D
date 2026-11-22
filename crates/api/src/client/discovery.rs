//! Read-only model, runtime and task discovery operations, with capability,
//! page and selector validation.

use super::*;

impl Client {
    /// List model support records using one validated inventory page.
    pub async fn models(
        &self,
        query: ModelListQuery,
    ) -> Result<InventoryPage<ModelSummary>, ClientError> {
        validate_page_query(&query.page)?;
        if query
            .task_id
            .as_deref()
            .is_some_and(|id| !valid_task_id(id))
            || query
                .task_version
                .as_deref()
                .is_some_and(|version| TaskKey::new("task", version).is_err())
            || (query.task_version.is_some() && query.task_id.is_none())
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = String::from("/v1/models");
        let mut first = true;
        push_page_query(&mut path, &mut first, &query.page);
        if let Some(task_id) = query.task_id.as_deref() {
            push_query(&mut path, &mut first, "task_id", task_id);
        }
        if let Some(task_version) = query.task_version.as_deref() {
            push_query(&mut path, &mut first, "task_version", task_version);
        }
        if let Some(loaded) = query.loaded {
            push_query(
                &mut path,
                &mut first,
                "loaded",
                if loaded { "true" } else { "false" },
            );
        }
        self.check_discovery_operation("models.list").await?;
        let page: InventoryPage<ModelSummary> = self.get(&path).await?;
        validate_page(&page, query.page.limit, |item| {
            valid_public_id(&item.id, "mdl_")
        })?;
        Ok(page)
    }

    /// List the current loaded-model inventory (empty until worker support exists).
    pub async fn models_loaded(
        &self,
        page: PageQuery,
    ) -> Result<InventoryPage<ModelSummary>, ClientError> {
        self.models(ModelListQuery {
            page,
            loaded: Some(true),
            ..Default::default()
        })
        .await
    }

    /// Read one model declaration and its attached schemas.
    pub async fn model(
        &self,
        lookup: ModelLookup,
    ) -> Result<InventoryDetail<ModelDetail>, ClientError> {
        if !valid_model_selector(&lookup.selector)
            || (lookup.task.is_none() && (lookup.runtime_ref.is_some() || lookup.variant.is_some()))
            || lookup
                .runtime_ref
                .as_deref()
                .is_some_and(|value| !valid_runtime_selector(value))
            || lookup
                .variant
                .as_deref()
                .is_some_and(|value| !valid_name(value))
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = format!("/v1/models/{}", encode_component(&lookup.selector));
        let mut first = true;
        if let Some(task) = &lookup.task {
            push_query(&mut path, &mut first, "task_id", task.id());
            push_query(&mut path, &mut first, "task_version", task.version());
        }
        if let Some(runtime_ref) = lookup.runtime_ref.as_deref() {
            push_query(&mut path, &mut first, "runtime_ref", runtime_ref);
        }
        if let Some(variant) = lookup.variant.as_deref() {
            push_query(&mut path, &mut first, "variant", variant);
        }
        self.check_discovery_operation("models.show").await?;
        let detail: InventoryDetail<ModelDetail> = self.get(&path).await?;
        validate_detail(&detail)?;
        if !valid_public_id(&detail.item.summary.id, "mdl_") {
            return Err(ClientError::InvalidResponse);
        }
        Ok(detail)
    }

    /// List runtime profiles using one validated inventory page.
    pub async fn runtimes(
        &self,
        page: PageQuery,
    ) -> Result<InventoryPage<RuntimeSummary>, ClientError> {
        validate_page_query(&page)?;
        let mut path = String::from("/v1/runtimes");
        let mut first = true;
        push_page_query(&mut path, &mut first, &page);
        self.check_discovery_operation("runtimes.list").await?;
        let page_response: InventoryPage<RuntimeSummary> = self.get(&path).await?;
        validate_page(&page_response, page.limit, |item| {
            valid_public_id(&item.id, "rtp_")
        })?;
        Ok(page_response)
    }

    /// Read one runtime declaration.
    pub async fn runtime(
        &self,
        lookup: RuntimeLookup,
    ) -> Result<InventoryDetail<RuntimeDetail>, ClientError> {
        if !valid_runtime_selector(&lookup.selector) {
            return Err(ClientError::InvalidMaterial);
        }
        self.check_discovery_operation("runtimes.show").await?;
        let path = format!("/v1/runtimes/{}", encode_component(&lookup.selector));
        let detail: InventoryDetail<RuntimeDetail> = self.get(&path).await?;
        validate_detail(&detail)?;
        if !valid_public_id(&detail.item.summary.id, "rtp_") {
            return Err(ClientError::InvalidResponse);
        }
        Ok(detail)
    }

    /// List support-specific task bindings using one validated page.
    pub async fn tasks(
        &self,
        query: TaskListQuery,
    ) -> Result<InventoryPage<TaskSummary>, ClientError> {
        validate_page_query(&query.page)?;
        if query
            .support_ref
            .as_deref()
            .is_some_and(|reference| !valid_reference(reference))
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = String::from("/v1/tasks");
        let mut first = true;
        push_page_query(&mut path, &mut first, &query.page);
        if let Some(support_ref) = query.support_ref.as_deref() {
            push_query(&mut path, &mut first, "support_ref", support_ref);
        }
        self.check_discovery_operation("tasks.list").await?;
        let page: InventoryPage<TaskSummary> = self.get(&path).await?;
        validate_page(&page, query.page.limit, |item| {
            valid_public_id(&item.id, "tsk_")
        })?;
        Ok(page)
    }

    /// Read one textual task key or one opaque support-specific binding ID.
    pub async fn task(
        &self,
        lookup: TaskLookup,
    ) -> Result<InventoryDetail<TaskDetail>, ClientError> {
        if !valid_task_selector(&lookup.selector)
            || lookup
                .version
                .as_deref()
                .is_some_and(|version| TaskKey::new("task", version).is_err())
            || lookup
                .support_ref
                .as_deref()
                .is_some_and(|reference| !valid_reference(reference))
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = format!("/v1/tasks/{}", encode_component(&lookup.selector));
        let mut first = true;
        if let Some(version) = lookup.version.as_deref() {
            push_query(&mut path, &mut first, "version", version);
        }
        if let Some(support_ref) = lookup.support_ref.as_deref() {
            push_query(&mut path, &mut first, "support_ref", support_ref);
        }
        self.check_discovery_operation("tasks.show").await?;
        let detail: InventoryDetail<TaskDetail> = self.get(&path).await?;
        validate_detail(&detail)?;
        if detail.item.bindings.is_empty()
            || detail
                .item
                .bindings
                .iter()
                .any(|binding| !valid_public_id(&binding.id, "tsk_"))
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(detail)
    }
}

impl Client {
    async fn check_discovery_operation(&self, operation: &str) -> Result<(), ClientError> {
        let info = self.info().await?;
        validate_discovery_capability(&info.granted_operations, info.discovery.as_ref(), operation)
    }
}

pub(super) fn validate_discovery_capability(
    grants: &[String],
    capability: Option<&DiscoveryCapability>,
    operation: &str,
) -> Result<(), ClientError> {
    if !grants.iter().any(|grant| grant == "engine.info") {
        return Err(ClientError::Rejected(ErrorCode::Forbidden));
    }
    let Some(capability) = capability else {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    };
    if capability.version != API_VERSION || capability.authorization_grant != "engine.info" {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    if !capability
        .operations
        .iter()
        .any(|provided| provided == operation)
    {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    }
    let expected = [
        "models.list",
        "models.show",
        "runtimes.list",
        "runtimes.show",
        "tasks.list",
        "tasks.show",
    ];
    let provided = capability
        .operations
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if provided.len() != expected.len()
        || expected
            .iter()
            .any(|operation| !provided.contains(operation))
    {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    Ok(())
}

fn validate_page_query(query: &PageQuery) -> Result<(), ClientError> {
    if query.limit.is_some_and(|limit| !(1..=100).contains(&limit))
        || query
            .cursor
            .as_deref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
    {
        return Err(ClientError::InvalidMaterial);
    }
    Ok(())
}

fn validate_page<T, F>(
    page: &InventoryPage<T>,
    requested_limit: Option<u8>,
    valid_id: F,
) -> Result<(), ClientError>
where
    F: Fn(&T) -> bool,
{
    page.validate().map_err(|_| ClientError::InvalidResponse)?;
    let maximum = usize::from(requested_limit.unwrap_or(20));
    if page.items.len() > maximum || page.items.iter().any(|item| !valid_id(item)) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

fn validate_detail<T>(detail: &InventoryDetail<T>) -> Result<(), ClientError> {
    if detail.api_version != API_VERSION || !valid_digest(&detail.catalog_revision) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

fn push_page_query(path: &mut String, first: &mut bool, page: &PageQuery) {
    if let Some(limit) = page.limit {
        push_query(path, first, "limit", &limit.to_string());
    }
    if let Some(cursor) = page.cursor.as_deref() {
        push_query(path, first, "cursor", cursor);
    }
}

pub(super) fn valid_name(value: &str) -> bool {
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

fn valid_reference(value: &str) -> bool {
    let Some((name, revision)) = value.split_once('@') else {
        return false;
    };
    valid_name(name) && valid_name(revision)
}

fn valid_model_selector(value: &str) -> bool {
    valid_public_id(value, "mdl_")
        || valid_reference(value)
        || (valid_name(value) && !value.starts_with("mdl_"))
}

fn valid_runtime_selector(value: &str) -> bool {
    valid_public_id(value, "rtp_")
        || valid_reference(value)
        || (valid_name(value) && !value.starts_with("rtp_"))
}

fn valid_task_selector(value: &str) -> bool {
    valid_public_id(value, "tsk_") || valid_task_id(value)
}
