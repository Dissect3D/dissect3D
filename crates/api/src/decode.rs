//! Bounded decoding for closed API and configuration records.
//!
//! Validate the JSON structure before constructing the requested record.
//! Building a `serde_json::Value` directly would silently keep only
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
    StrictValueSeed { depth: 0 }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    // Decode the original bytes after the structural guard: declaration and
    // submission raw-number fields must retain their exact numeric tokens.
    serde_json::from_slice(bytes).map_err(DecodeError::Record)
}

struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = ();

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
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value within the supported depth")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.is_finite() {
            Ok(())
        } else {
            Err(E::custom("non-finite JSON number"))
        }
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = self.child_depth::<A::Error>()?;
        while sequence
            .next_element_seed(StrictValueSeed { depth })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let depth = self.child_depth::<A::Error>()?;
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate object member"));
            }
            map.next_value_seed(StrictValueSeed { depth })?;
        }
        Ok(())
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
