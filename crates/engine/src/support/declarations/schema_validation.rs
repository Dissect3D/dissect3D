//! Task schema selection, schema-use and schema-tree validation, and value matching.

use super::*;

pub(super) fn schema_for_binding(
    binding: &Value,
    key: &str,
    schemas: &BTreeMap<(String, String), SchemaRecord>,
) -> Result<Value, CatalogError> {
    let reference = &binding[key];
    let id = string(&reference["id"]).ok_or(CatalogError::InvalidPackage)?;
    let version = string(&reference["version"]).ok_or(CatalogError::InvalidPackage)?;
    Ok(schemas
        .get(&(id.to_owned(), version.to_owned()))
        .ok_or(CatalogError::InvalidPackage)?
        .document["schema"]
        .clone())
}
pub(super) fn all_task_schema(
    tasks: &[(TaskKey, TaskBindingRecord)],
    key: &str,
    schemas: &BTreeMap<(String, String), SchemaRecord>,
) -> Result<Value, CatalogError> {
    let mut props = Map::new();
    for (_, task) in tasks {
        let schema = task
            .schemas
            .iter()
            .find(|attachment| attachment.document["id"] == task.binding[key]["id"]);
        if let Some(schema) = schema
            && let Some(map) = schema.document["schema"]["properties"].as_object()
        {
            props.extend(map.clone());
        }
    }
    let _ = schemas;
    Ok(Value::Object(BTreeMap::from([(
        "properties".into(),
        Value::Object(props),
    )])))
}

pub(super) fn validate_schema_use(
    schema: &SchemaRecord,
    usage: SchemaUse,
) -> Result<(), CatalogError> {
    let root = &schema.document["schema"];
    if root["type"] != "object"
        || root["additionalProperties"] != false
        || root["properties"].as_object().is_none()
    {
        return Err(CatalogError::InvalidPackage);
    }
    let props = root["properties"]
        .as_object()
        .ok_or(CatalogError::InvalidPackage)?;
    for (name, property) in props {
        match usage {
            SchemaUse::Input => {
                if property["x-role"].as_str() != Some(name.as_str())
                    || string_array(&property["x-media-types"], 1024)
                        .is_none_or(|v| v.is_empty() || v.iter().any(String::is_empty))
                    || string_array(&property["x-representations"], 1024)
                        .is_none_or(|v| v.is_empty() || v.iter().any(String::is_empty))
                    || property["type"] != "array"
                    || property["items"].is_null()
                    || property["minItems"].as_u64().is_none()
                    || property["maxItems"].as_u64().is_none()
                {
                    return Err(CatalogError::InvalidPackage);
                }
            }
            SchemaUse::Output => {
                let policy = &property["x-output-policy"];
                if !exact_keys(policy, &["mandatory", "partial_allowed", "formats"])
                    || policy["mandatory"].as_bool().is_none()
                    || policy["partial_allowed"].as_bool().is_none()
                    || string_array(&policy["formats"], 1024)
                        .is_none_or(|v| v.is_empty() || v.iter().any(String::is_empty))
                {
                    return Err(CatalogError::InvalidPackage);
                }
            }
            SchemaUse::Parameters => {}
        }
    }
    Ok(())
}

pub(super) fn validate_schema_tree(
    root: &Value,
    value: &Value,
    unresolved: &mut Vec<String>,
    path: &str,
    depth: usize,
) -> Result<(), ()> {
    if depth > 32 {
        return Err(());
    }
    let object = value.as_object().ok_or(())?;
    if object.len() > 1024 {
        return Err(());
    }
    const KNOWN: &[&str] = &[
        "$schema",
        "$defs",
        "$ref",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "const",
        "default",
        "title",
        "description",
        "x-role",
        "x-media-types",
        "x-representations",
        "x-output-policy",
    ];
    for (key, child) in object {
        if !KNOWN.contains(&key.as_str()) {
            unresolved.push(format!("{path}.{key}"));
        }
        match key.as_str() {
            "$schema" => {
                if child.as_str() != Some("https://json-schema.org/draft/2020-12/schema") {
                    return Err(());
                }
            }
            "$ref" => {
                if child.as_str().is_none() {
                    return Err(());
                }
            }
            "type" => {
                if !matches!(
                    child.as_str(),
                    Some("object" | "array" | "string" | "boolean" | "integer" | "number")
                ) {
                    return Err(());
                }
            }
            "properties" | "$defs" => {
                let map = child.as_object().ok_or(())?;
                if map.len() > 1024 {
                    return Err(());
                }
                for (name, sub) in map {
                    if !valid_name(name) {
                        return Err(());
                    }
                    validate_schema_tree(
                        root,
                        sub,
                        unresolved,
                        &format!("{path}.{key}.{name}"),
                        depth + 1,
                    )?;
                }
            }
            "items" => {
                validate_schema_tree(root, child, unresolved, &format!("{path}.items"), depth + 1)?
            }
            "required" => {
                let vals = strings(child).ok_or(())?;
                if has_duplicates(&vals) {
                    return Err(());
                }
            }
            "additionalProperties" => {
                if child.as_bool() != Some(false) {
                    return Err(());
                }
            }
            "minItems" | "maxItems" | "minLength" | "maxLength" => {
                if safe_integer(child).is_none() {
                    return Err(());
                }
            }
            "minimum" | "maximum" => {
                if child.as_f64().is_none() {
                    return Err(());
                }
            }
            "enum" => {
                let vals = child.as_array().filter(|a| !a.is_empty()).ok_or(())?;
                for i in 0..vals.len() {
                    if vals[..i].contains(&vals[i]) {
                        return Err(());
                    }
                }
            }
            "title" | "description" | "x-role" => {
                if child.as_str().is_none_or(|s| s.len() > 4096) {
                    return Err(());
                }
            }
            "x-media-types" | "x-representations" => {
                if strings(child).is_none_or(|a| a.is_empty()) {
                    return Err(());
                }
            }
            "x-output-policy"
                if !exact_keys(child, &["mandatory", "partial_allowed", "formats"])
                    || child["mandatory"].as_bool().is_none()
                    || child["partial_allowed"].as_bool().is_none()
                    || strings(&child["formats"]).is_none_or(|v| v.is_empty()) =>
            {
                return Err(());
            }
            _ => {}
        }
    }
    if object.get("type").and_then(Value::as_str) == Some("object") {
        if object.get("additionalProperties") != Some(&Value::Bool(false)) {
            return Err(());
        }
        let props = object
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(())?;
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && required
                .iter()
                .any(|name| name.as_str().is_none_or(|name| !props.contains_key(name)))
        {
            return Err(());
        }
    }
    if object.get("type").and_then(Value::as_str) == Some("array") && object.get("items").is_none()
    {
        return Err(());
    }
    for (min, max) in [
        ("minItems", "maxItems"),
        ("minLength", "maxLength"),
        ("minimum", "maximum"),
    ] {
        if let (Some(a), Some(b)) = (object.get(min), object.get(max)) {
            let ordering = a
                .as_number()
                .ok_or(())?
                .compare(b.as_number().ok_or(())?)
                .ok_or(())?;
            if ordering == std::cmp::Ordering::Greater {
                return Err(());
            }
        }
    }
    if let Some(default) = object.get("default") {
        match value_matches(root, value, default, 0, 0) {
            Some(false) => return Err(()),
            None => unresolved.push(format!("{path}.default")),
            Some(true) => {}
        }
    }
    if let Some(constant) = object.get("const")
        && value_matches(root, value, constant, 0, 0) == Some(false)
    {
        return Err(());
    }
    if let Some(values) = object.get("enum").and_then(Value::as_array)
        && object.get("type").is_some_and(|ty| {
            values
                .iter()
                .any(|v| !matches_type(ty.as_str().unwrap_or_default(), v))
        })
    {
        return Err(());
    }
    Ok(())
}

fn has_unknown_schema_keyword(root: &Value, value: &Value, edges: usize) -> bool {
    unknown_schema_keyword(root, value, edges, &mut BTreeMap::new())
}

fn unknown_schema_keyword(
    root: &Value,
    value: &Value,
    edges: usize,
    checked: &mut BTreeMap<(String, usize), bool>,
) -> bool {
    if edges > 16 {
        return true;
    }
    const KNOWN: &[&str] = &[
        "$schema",
        "$defs",
        "$ref",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "const",
        "default",
        "title",
        "description",
        "x-role",
        "x-media-types",
        "x-representations",
        "x-output-policy",
    ];
    let Some(object) = value.as_object() else {
        return false;
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let Some(name) = reference.strip_prefix("#/$defs/") else {
            return true;
        };
        let key = (name.to_owned(), edges);
        if let Some(unknown) = checked.get(&key) {
            return *unknown;
        }
        let unknown = root
            .get("$defs")
            .and_then(|defs| defs.get(name))
            .is_none_or(|target| unknown_schema_keyword(root, target, edges + 1, checked));
        checked.insert(key, unknown);
        return unknown;
    }
    object.iter().any(|(key, child)| {
        !KNOWN.contains(&key.as_str())
            || match key.as_str() {
                "properties" | "$defs" => child.as_object().is_some_and(|items| {
                    items
                        .values()
                        .any(|sub| unknown_schema_keyword(root, sub, edges, checked))
                }),
                "items" => unknown_schema_keyword(root, child, edges, checked),
                "x-output-policy" => false,
                _ => false,
            }
    })
}

pub(super) fn validate_schema_refs(root: &Value) -> Result<(), ()> {
    let defs = root
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    fn scan(
        value: &Value,
        defs: &Map<String, Value>,
        stack: &mut Vec<String>,
        edges: usize,
        depth: usize,
        checked: &mut BTreeSet<(String, usize, usize)>,
    ) -> Result<(), ()> {
        let object = value.as_object().ok_or(())?;
        // Count expanded containers, not reference hops or the $defs storage map.
        let depth = depth
            + usize::from(
                matches!(
                    object.get("type").and_then(Value::as_str),
                    Some("object" | "array")
                ) || object.contains_key("properties")
                    || object.contains_key("items"),
            );
        if depth > 32 {
            return Err(());
        }
        if let Some(reference) = object.get("$ref") {
            let reference = reference.as_str().ok_or(())?;
            let name = reference.strip_prefix("#/$defs/").ok_or(())?;
            if name.is_empty() || name.contains('/') || name.contains('~') || !valid_name(name) {
                return Err(());
            }
            let target = defs.get(name).ok_or(())?;
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "$ref" | "title" | "description"))
            {
                return Err(());
            }
            if edges >= 16 || stack.contains(&name.to_owned()) {
                return Err(());
            }
            // A shared definition has the same result at the same remaining
            // edge/container budgets. Check cycles before consulting this cache.
            let key = (name.to_owned(), edges, depth);
            if checked.contains(&key) {
                return Ok(());
            }
            stack.push(name.to_owned());
            scan(target, defs, stack, edges + 1, depth, checked)?;
            stack.pop();
            checked.insert(key);
        }
        for (key, child) in object {
            if key == "$defs" {
                continue;
            }
            if matches!(key.as_str(), "properties" | "items") {
                if key == "properties" {
                    for sub in child.as_object().ok_or(())?.values() {
                        scan(sub, defs, stack, edges, depth, checked)?;
                    }
                } else {
                    scan(child, defs, stack, edges, depth, checked)?;
                }
            }
        }
        Ok(())
    }
    let mut checked = BTreeSet::new();
    scan(root, &defs, &mut Vec::new(), 0, 0, &mut checked)?;
    for def in defs.values() {
        scan(def, &defs, &mut Vec::new(), 0, 0, &mut checked)?;
    }
    Ok(())
}

fn value_matches(
    root: &Value,
    schema: &Value,
    value: &Value,
    depth: usize,
    edges: usize,
) -> Option<bool> {
    if depth > 32 || edges > 16 {
        return Some(false);
    }
    let object = schema.as_object()?;
    // References are structurally checked before any const/default evaluation.
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let name = reference.strip_prefix("#/$defs/")?;
        let target = root.get("$defs")?.get(name)?;
        return value_matches(root, target, value, depth, edges + 1);
    }
    let mut unknown = has_unknown_schema_keyword(root, schema, edges);
    if let Some(ty) = object.get("type").and_then(Value::as_str)
        && !matches_type(ty, value)
    {
        return Some(false);
    }
    if let Some(c) = object.get("const")
        && c != value
    {
        return Some(false);
    }
    if let Some(list) = object.get("enum").and_then(Value::as_array)
        && !list.contains(value)
    {
        return Some(false);
    }
    if let Some(n) = value.as_number() {
        for (key, rejected) in [
            ("minimum", std::cmp::Ordering::Less),
            ("maximum", std::cmp::Ordering::Greater),
        ] {
            if let Some(bound) = object.get(key)
                && n.compare(bound.as_number()?)? == rejected
            {
                return Some(false);
            }
        }
    }
    if let Some(s) = value.as_str() {
        let len = s.chars().count();
        if object
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| (len as u64) < min)
            || object
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|max| (len as u64) > max)
        {
            return Some(false);
        }
    }
    if let Some(items) = value.as_array() {
        if object
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|min| (items.len() as u64) < min)
            || object
                .get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|max| (items.len() as u64) > max)
        {
            return Some(false);
        }
        if let Some(item_schema) = object.get("items") {
            for item in items {
                match value_matches(root, item_schema, item, depth + 1, edges) {
                    Some(false) => return Some(false),
                    None => unknown = true,
                    Some(true) => {}
                }
            }
        }
    }
    if let Some(fields) = value.as_object() {
        if object.get("additionalProperties") == Some(&Value::Bool(false)) {
            let props = object.get("properties").and_then(Value::as_object)?;
            if fields.keys().any(|key| !props.contains_key(key)) {
                return Some(false);
            }
        }
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && required
                .iter()
                .filter_map(Value::as_str)
                .any(|key| !fields.contains_key(key))
        {
            return Some(false);
        }
        if let Some(props) = object.get("properties").and_then(Value::as_object) {
            for (key, subschema) in props {
                if let Some(item) = fields.get(key) {
                    match value_matches(root, subschema, item, depth + 1, edges) {
                        Some(false) => return Some(false),
                        None => unknown = true,
                        Some(true) => {}
                    }
                }
            }
        }
    }
    if unknown { None } else { Some(true) }
}

fn matches_type(name: &str, value: &Value) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.as_f64().is_some(),
        _ => false,
    }
}
