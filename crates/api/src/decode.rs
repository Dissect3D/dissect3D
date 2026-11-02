//! Bounded decoding for closed API and configuration records.
//!
//! Decode into a strict intermediate tree before constructing the requested
//! record. Building a `serde_json::Value` directly would silently keep only
//! one occurrence of a repeated object key, making signed or security-sensitive
//! records ambiguous to different consumers.

use std::collections::BTreeSet;

use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use thiserror::Error;

const MAX_JSON_DEPTH: usize = 32;

/// A safe decoding failure that does not include the rejected input.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// JSON syntax, duplicate-key or nesting-limit failure.
    #[error("invalid or unsupported JSON")]
    Json(#[from] serde_json::Error),
    /// The JSON value did not match the requested record.
    #[error("JSON value does not match the expected record")]
    Record(serde_json::Error),
}

/// Decode one complete JSON value, rejecting duplicate keys and excess nesting.
pub fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed { depth: 0 }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    // Keep record validation separate so syntax/duplicate/depth failures and
    // schema mismatches can be reported as the same safe public categories.
    serde_json::from_value(value.into_json()).map_err(DecodeError::Record)
}

#[derive(Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(std::collections::BTreeMap<String, Self>),
}

impl StrictValue {
    fn into_json(self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::Number(value) => serde_json::Value::Number(value),
            Self::String(value) => serde_json::Value::String(value),
            Self::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(Self::into_json).collect())
            }
            Self::Object(values) => serde_json::Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, value.into_json()))
                    .collect(),
            ),
        }
    }
}

struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor { depth: self.depth })
    }
}

struct StrictValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value within the supported depth")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(StrictValue::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = self.child_depth::<A::Error>()?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed { depth })? {
            values.push(value);
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let depth = self.child_depth::<A::Error>()?;
        let mut keys = BTreeSet::new();
        let mut values = std::collections::BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate object member"));
            }
            let value = map.next_value_seed(StrictValueSeed { depth })?;
            values.insert(key, value);
        }
        Ok(StrictValue::Object(values))
    }
}

impl StrictValueVisitor {
    fn child_depth<E>(&self) -> Result<usize, E>
    where
        E: serde::de::Error,
    {
        // Count containers rather than scalar leaves; this bounds recursive
        // parser work without rejecting ordinary flat records.
        if self.depth >= MAX_JSON_DEPTH {
            Err(E::custom("JSON nesting limit exceeded"))
        } else {
            Ok(self.depth + 1)
        }
    }
}
