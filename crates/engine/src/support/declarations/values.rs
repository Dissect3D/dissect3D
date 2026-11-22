//! Bounded value accessors, identifier and digest helpers, and identity construction.

use super::*;

pub(super) fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}
pub(super) fn require_keys(value: &Value, keys: &[&str]) -> Result<(), CatalogError> {
    if exact_keys(value, keys) {
        Ok(())
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
pub(super) fn array(value: &Value, max: usize) -> Option<&[Value]> {
    value
        .as_array()
        .filter(|items| items.len() <= max)
        .map(Vec::as_slice)
}
pub(super) fn string(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !s.is_empty() && s.len() <= 4096)
}
pub(super) fn text(value: &Value, max: usize) -> Option<&str> {
    value.as_str().filter(|s| s.len() <= max)
}
pub(super) fn nonempty_text(value: &Value, max: usize) -> Option<&str> {
    text(value, max).filter(|s| !s.is_empty())
}
pub(super) fn ident(value: &Value) -> Result<&str, CatalogError> {
    let value = string(value).ok_or(CatalogError::InvalidPackage)?;
    if valid_name(value) {
        Ok(value)
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
pub(super) fn version_value(value: &Value) -> Result<&str, CatalogError> {
    let value = string(value).ok_or(CatalogError::InvalidPackage)?;
    let mut p = value.split('.');
    let valid = |v: &str| {
        !v.is_empty()
            && !(v.len() > 1 && v.starts_with('0'))
            && v.bytes().all(|b| b.is_ascii_digit())
            && v.parse::<u16>().is_ok()
    };
    if matches!((p.next(),p.next(),p.next()),(Some(a),Some(b),None)if valid(a)&&valid(b)) {
        Ok(value)
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
pub(super) fn digest_value(value: &Value) -> Result<&str, CatalogError> {
    let value = string(value).ok_or(CatalogError::InvalidPackage)?;
    if is_digest(value) {
        Ok(value)
    } else {
        Err(CatalogError::InvalidPackage)
    }
}
pub(super) fn strings(value: &Value) -> Option<Vec<String>> {
    let items = array(value, 1024)?;
    items.iter().map(|v| Some(string(v)?.to_owned())).collect()
}
pub(super) fn string_array(value: &Value, max: usize) -> Option<Vec<String>> {
    let items = array(value, max)?;
    items
        .iter()
        .map(|v| Some(text(v, 4096)?.to_owned()))
        .collect()
}
pub(super) fn feature_array(value: &Value) -> Option<Vec<String>> {
    let values = strings(value)?;
    values.iter().all(|item| valid_name(item)).then_some(values)
}
pub(super) fn nullable_string(value: &Value) -> Result<Option<String>, CatalogError> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(ident(value)?.to_owned()))
    }
}
pub(super) fn nullable_reference(value: &Value) -> Result<Option<String>, CatalogError> {
    if value.is_null() {
        Ok(None)
    } else {
        let reference = string(value).ok_or(CatalogError::InvalidPackage)?;
        if valid_reference(reference, false) {
            Ok(Some(reference.to_owned()))
        } else {
            Err(CatalogError::InvalidPackage)
        }
    }
}
pub(super) fn safe_integer(value: &Value) -> Option<u64> {
    let n = value.as_u64()?;
    (n <= 9_007_199_254_740_991).then_some(n)
}
pub(super) fn has_duplicates(values: &[String]) -> bool {
    let mut set = BTreeSet::new();
    values.iter().any(|v| !set.insert(v))
}
pub(super) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write;
        let _ = write!(result, "{byte:02x}");
    }
    result
}
pub(super) fn public_id(
    kind: &str,
    reference: &str,
    document_digest: &str,
    prefix: &str,
) -> String {
    format!(
        "{prefix}{}",
        digest(format!("{kind}\n{reference}\n{document_digest}\n").as_bytes())
    )
}
pub(super) fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub(super) fn valid_reference(value: &str, schema: bool) -> bool {
    let Some((name, revision)) = value.split_once('@') else {
        return false;
    };
    if !valid_name(name) || !valid_name(revision) {
        return false;
    }
    if !schema {
        return true;
    }
    let mut p = revision.split('.');
    let valid = |v: &str| {
        !v.is_empty()
            && !(v.len() > 1 && v.starts_with('0'))
            && v.bytes().all(|b| b.is_ascii_digit())
            && v.parse::<u16>().is_ok()
    };
    matches!((p.next(),p.next(),p.next()),(Some(a),Some(b),None)if valid(a)&&valid(b))
}
pub(super) fn bounded_value(value: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(n) => n.as_f64().is_some_and(f64::is_finite),
        Value::String(s) => s.len() <= 4096,
        Value::Array(items) => {
            items.len() <= 1024 && items.iter().all(|v| bounded_value(v, depth + 1))
        }
        Value::Object(map) => {
            map.len() <= 1024
                && map
                    .iter()
                    .all(|(k, v)| k.len() <= 128 && bounded_value(v, depth + 1))
        }
    }
}

pub(super) fn credential_free_provenance(value: &Value) -> Result<(), CatalogError> {
    let value = text(value, 4096).ok_or(CatalogError::InvalidPackage)?;
    if value.contains("://") {
        let parsed = url::Url::parse(value).map_err(|_| CatalogError::InvalidPackage)?;
        let authority = value
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
            .unwrap_or_default();
        if !parsed.username().is_empty() || parsed.password().is_some() || authority.contains('@') {
            return Err(CatalogError::InvalidPackage);
        }
    }
    Ok(())
}

pub(super) fn valid_rfc3339(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b.last() != Some(&b'Z')
    {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let text = std::str::from_utf8(b.get(range)?).ok()?;
        if !text.bytes().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return false;
    };
    let fraction = if b.len() == 20 {
        true
    } else if b.get(19) == Some(&b'.') && b.len() > 21 {
        b[20..b.len() - 1].iter().all(u8::is_ascii_digit)
    } else {
        false
    };
    if !fraction || month == 0 || month > 12 || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day > 0 && day <= month_days
}
