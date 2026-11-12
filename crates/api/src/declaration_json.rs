//! Lossless declaration JSON, scoped away from core records and submission values.
//! Numeric tokens are retained; comparison never converts them through binary floats.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::{Index, IndexMut};

#[derive(Clone, Debug, PartialEq)]
pub enum DeclarationValue {
    Null,
    Bool(bool),
    Number(DeclarationNumber),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

#[derive(Clone, Debug)]
pub struct DeclarationNumber(String);

struct Decimal {
    negative: bool,
    digits: String,
    power: i64,
}

impl Decimal {
    fn parse(token: &str) -> Option<Self> {
        let (mantissa, power) = match token.find(['e', 'E']) {
            Some(index) => (&token[..index], token[index + 1..].parse::<i64>().ok()?),
            None => (token, 0),
        };
        let negative = mantissa.starts_with('-');
        let unsigned = mantissa.strip_prefix('-').unwrap_or(mantissa);
        let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
        let mut digits = format!("{whole}{fraction}");
        let first = digits.bytes().position(|byte| byte != b'0');
        let Some(first) = first else {
            return Some(Self {
                negative: false,
                digits: "0".into(),
                power: 0,
            });
        };
        digits.drain(..first);
        let trailing = digits.len() - digits.trim_end_matches('0').len();
        digits.truncate(digits.len() - trailing);
        let power = power
            .checked_sub(i64::try_from(fraction.len()).ok()?)?
            .checked_add(i64::try_from(trailing).ok()?)?;
        power.checked_add(i64::try_from(digits.len()).ok()?)?;
        Some(Self {
            negative,
            digits,
            power,
        })
    }

    fn compare(&self, other: &Self) -> Ordering {
        if self.digits == "0" || other.digits == "0" {
            return match (self.digits == "0", other.digits == "0") {
                (true, true) => Ordering::Equal,
                (true, false) => {
                    if other.negative {
                        Ordering::Greater
                    } else {
                        Ordering::Less
                    }
                }
                _ => {
                    if self.negative {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                }
            };
        }
        if self.negative != other.negative {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        // Compare magnitude first, then aligned significant digits. Never expand an exponent.
        let magnitude = self.power + self.digits.len() as i64;
        let other_magnitude = other.power + other.digits.len() as i64;
        let mut order = magnitude.cmp(&other_magnitude);
        if order == Ordering::Equal {
            for index in 0..self.digits.len().max(other.digits.len()) {
                order = self
                    .digits
                    .as_bytes()
                    .get(index)
                    .unwrap_or(&b'0')
                    .cmp(other.digits.as_bytes().get(index).unwrap_or(&b'0'));
                if order != Ordering::Equal {
                    break;
                }
            }
        }
        if self.negative {
            order.reverse()
        } else {
            order
        }
    }
}

impl DeclarationNumber {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        Some(Decimal::parse(&self.0)?.compare(&Decimal::parse(&other.0)?))
    }
    pub fn is_integer_token(&self) -> bool {
        !self.0.contains(['.', 'e', 'E'])
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.is_integer_token()
            .then(|| self.0.parse().ok())
            .flatten()
    }
    pub fn as_u64(&self) -> Option<u64> {
        if self.0 == "-0" {
            return Some(0);
        }
        self.is_integer_token()
            .then(|| self.0.parse().ok())
            .flatten()
    }
    /// Only the existing finite-number admission limit uses binary floating point.
    pub fn as_f64(&self) -> Option<f64> {
        self.0.parse::<f64>().ok().filter(|n| n.is_finite())
    }
}

impl PartialEq for DeclarationNumber {
    fn eq(&self, other: &Self) -> bool {
        self.is_integer_token() == other.is_integer_token()
            && self.compare(other) == Some(Ordering::Equal)
    }
}

impl Serialize for DeclarationValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::String(value) => serializer.serialize_str(value),
            Self::Number(value) => RawValue::from_string(value.0.clone())
                .map_err(serde::ser::Error::custom)?
                .serialize(serializer),
            Self::Array(values) => values.serialize(serializer),
            Self::Object(values) => values.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for DeclarationValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Seed(0).deserialize(deserializer)
    }
}

struct Seed(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = DeclarationValue;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        let raw = <&RawValue>::deserialize(deserializer)?;
        let text = raw.get();
        match text.as_bytes().first() {
            Some(b'{' | b'[') => {
                if self.0 >= 32 {
                    return Err(serde::de::Error::custom("declaration nesting limit"));
                }
                let mut decoder = serde_json::Deserializer::from_str(text);
                let value =
                    serde::Deserializer::deserialize_any(&mut decoder, Container(self.0 + 1))
                        .map_err(serde::de::Error::custom)?;
                decoder.end().map_err(serde::de::Error::custom)?;
                Ok(value)
            }
            Some(b'-' | b'0'..=b'9') => {
                // RawValue has already checked JSON grammar; checked decimal arithmetic
                // bounds comparison work without imposing submission's separate limits.
                Decimal::parse(text)
                    .ok_or_else(|| serde::de::Error::custom("unsupported numeric exponent"))?;
                Ok(DeclarationValue::Number(DeclarationNumber(text.into())))
            }
            Some(b'"') => serde_json::from_str(text)
                .map(DeclarationValue::String)
                .map_err(serde::de::Error::custom),
            Some(b't' | b'f') => serde_json::from_str(text)
                .map(DeclarationValue::Bool)
                .map_err(serde::de::Error::custom),
            _ => Ok(DeclarationValue::Null),
        }
    }
}

struct Container(usize);
impl<'de> Visitor<'de> for Container {
    type Value = DeclarationValue;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("declaration JSON container")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(Seed(self.0))? {
            values.push(value);
        }
        Ok(DeclarationValue::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut values = BTreeMap::new();
        while let Some(key) = access.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate declaration member"));
            }
            values.insert(key, access.next_value_seed(Seed(self.0))?);
        }
        Ok(DeclarationValue::Object(values))
    }
}

impl DeclarationValue {
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_object()?.get(key)
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Self>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(v) = self {
            Some(*v)
        } else {
            None
        }
    }
    pub fn as_number(&self) -> Option<&DeclarationNumber> {
        if let Self::Number(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number()?.as_i64()
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number()?.as_u64()
    }
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number()?.as_f64()
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
    pub fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }
}

impl Index<&str> for DeclarationValue {
    type Output = Self;
    fn index(&self, key: &str) -> &Self {
        self.get(key).unwrap_or(&Self::Null)
    }
}
impl Index<usize> for DeclarationValue {
    type Output = Self;
    fn index(&self, index: usize) -> &Self {
        self.as_array()
            .and_then(|v| v.get(index))
            .unwrap_or(&Self::Null)
    }
}
impl IndexMut<&str> for DeclarationValue {
    fn index_mut(&mut self, key: &str) -> &mut Self {
        if matches!(self, Self::Null) {
            *self = Self::Object(BTreeMap::new());
        }
        match self {
            Self::Object(map) => map.entry(key.into()).or_insert(Self::Null),
            _ => panic!("object index on non-object declaration"),
        }
    }
}
impl From<i32> for DeclarationValue {
    fn from(value: i32) -> Self {
        Self::Number(DeclarationNumber(value.to_string()))
    }
}
impl std::fmt::Display for DeclarationValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&serde_json::to_string(self).map_err(|_| std::fmt::Error)?)
    }
}
impl PartialEq<str> for DeclarationValue {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Some(other)
    }
}
impl PartialEq<&str> for DeclarationValue {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}
impl PartialEq<String> for DeclarationValue {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}
impl PartialEq<&String> for DeclarationValue {
    fn eq(&self, other: &&String) -> bool {
        self == other.as_str()
    }
}
impl PartialEq<bool> for DeclarationValue {
    fn eq(&self, other: &bool) -> bool {
        self.as_bool() == Some(*other)
    }
}
// Interoperability for existing fixture assertions, without changing their bytes.
impl From<serde_json::Value> for DeclarationValue {
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(v) => Self::Bool(v),
            serde_json::Value::String(v) => Self::String(v),
            serde_json::Value::Number(v) => Self::Number(DeclarationNumber(v.to_string())),
            serde_json::Value::Array(v) => Self::Array(v.into_iter().map(Self::from).collect()),
            serde_json::Value::Object(v) => {
                Self::Object(v.into_iter().map(|(k, v)| (k, Self::from(v))).collect())
            }
        }
    }
}
impl PartialEq<serde_json::Value> for DeclarationValue {
    fn eq(&self, other: &serde_json::Value) -> bool {
        self == &Self::from(other.clone())
    }
}
