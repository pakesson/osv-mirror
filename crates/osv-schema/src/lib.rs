//! OSV advisory JSON types and validation.
//!
//! Deserialize with Serde or [`from_json`] to read records and preserve additive
//! fields. Use [`Vulnerability::validate_for_ingestion`] before indexing and
//! [`validate_json`] to check a document against the pinned publication schema.

mod validation;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub use validation::{ValidationError, from_json, is_indexable_id, timestamp_key, validate_json};

/// The upstream OSV specification implemented by this crate.
pub const SCHEMA_VERSION: &str = "1.9.2";

/// An omitted `schema_version` is interpreted as this version.
pub const DEFAULT_SCHEMA_VERSION: &str = "1.0.0";

/// A JSON field that permits both a value and explicit null.
///
/// Use with `Option` to distinguish omission from null when round-tripping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Nullable<T> {
    Null,
    Value(T),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<T>::deserialize(deserializer).map(|value| value.map_or(Self::Null, Self::Value))
    }
}

impl<T> Nullable<T> {
    pub fn as_value(&self) -> Option<&T> {
        match self {
            Self::Null => None,
            Self::Value(value) => Some(value),
        }
    }
}

/// The fields needed to store an advisory by ID without indexing its ranges.
#[derive(Debug, Deserialize)]
pub struct IndexMetadata {
    pub id: String,
    pub modified: String,
    pub withdrawn: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub schema_version: Option<String>,
    pub aliases: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    /// RFC 3339 text, preserving the supplied fractional precision.
    pub modified: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub schema_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub aliases: Option<Nullable<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub severity: Option<Nullable<Vec<Severity>>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub affected: Option<Nullable<Vec<Affected>>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub references: Option<Nullable<Vec<Reference>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credits: Option<Vec<Credit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Vulnerability {
    pub fn effective_schema_version(&self) -> &str {
        self.schema_version
            .as_deref()
            .unwrap_or(DEFAULT_SCHEMA_VERSION)
    }

    /// Affected entries, treating omission and explicit null as an empty list.
    pub fn affected_entries(&self) -> &[Affected] {
        self.affected
            .as_ref()
            .and_then(Nullable::as_value)
            .map_or(&[], Vec::as_slice)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Affected {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub severity: Option<Nullable<Vec<Severity>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<Range>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// The full ecosystem name, including any release or other suffix.
    pub ecosystem: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// Known range types are `SEMVER`, `ECOSYSTEM`, and `GIT`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A range event. Validation enforces the single-boundary rule for known ranges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub introduced: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub fixed: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub last_affected: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub limit: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Severity {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub score: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub url: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credit {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
