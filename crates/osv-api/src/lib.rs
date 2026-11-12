//! Shared OSV.dev REST types and an asynchronous client.
//!
//! Disable the default `client` feature to use the wire types without the HTTP
//! transport. Experimental request and response types live in [`experimental`].

pub mod experimental;

#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
pub use client::{Client, ClientBuilder, Error};

pub use osv_schema::Vulnerability;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The maximum number of queries accepted in one batch request.
pub const MAX_BATCH_QUERIES: usize = 1_000;

/// Package selector for an API query.
///
/// Use a PURL or an ecosystem and name. The API also accepts a name without an
/// ecosystem when a version is supplied.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPackage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Query {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<QueryPackage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

impl Query {
    pub fn for_commit(commit: impl Into<String>) -> Self {
        Self {
            commit: Some(commit.into()),
            ..Self::default()
        }
    }

    pub fn for_package(ecosystem: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            package: Some(QueryPackage {
                ecosystem: Some(ecosystem.into()),
                name: Some(name.into()),
                ..QueryPackage::default()
            }),
            ..Self::default()
        }
    }

    pub fn for_purl(purl: impl Into<String>) -> Self {
        Self {
            package: Some(QueryPackage {
                purl: Some(purl.into()),
                ..QueryPackage::default()
            }),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchQuery {
    #[serde(default)]
    pub queries: Vec<Query>,
}

/// A full or summarized page. OSV.dev can omit an empty `vulns` list or return
/// a continuation token without any matches on that page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct QueryPage<T> {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulns: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

pub type QueryResponse = QueryPage<Vulnerability>;
pub type BatchQueryResult = QueryPage<VulnerabilitySummary>;

/// Batch queries return only these two fields for each match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub id: String,
    pub modified: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchQueryResponse {
    /// One result per input query, in the order sent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<BatchQueryResult>,
}

/// The Google RPC status object returned by the REST gateway on errors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcStatus {
    pub code: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<Value>,
}
