//! Wire types and client methods for the OSV.dev experimental routes.

use serde::{Deserialize, Serialize};

use crate::QueryPackage;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_hashes: Vec<FileHash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    pub file_path: String,
    /// OSV.dev defaults to `MD5` when this field is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_type: Option<String>,
    /// Raw digest bytes, encoded as base64 in JSON.
    #[serde(with = "hash_bytes")]
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VersionMatchList {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<VersionMatch>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VersionMatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(
        rename = "repoInfo",
        alias = "repo_info",
        skip_serializing_if = "Option::is_none"
    )]
    pub repo_info: Option<VersionRepositoryInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osv_identifier: Option<QueryPackage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe23: Option<String>,
    #[serde(
        default,
        with = "optional_int64",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_file_matches: Option<i64>,
    #[serde(
        default,
        with = "optional_int64",
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_diff_files: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRepositoryInformation {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFindingList {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalid_records: Vec<ImportFinding>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFinding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bug_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ImportFindingType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt: Option<String>,
}

/// ProtoJSON emits enum names for known values and numbers for unknown ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ImportFindingType {
    Name(String),
    Number(i32),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UbuntuPackageMappingQuery {
    pub ecosystem: String,
    pub binary_names: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UbuntuPackageMappingResponse {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<SourcePackages>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePackages {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
}

#[cfg(feature = "client")]
use crate::{Client, Error};

/// Access the experimental routes using an existing client's configuration.
#[cfg(feature = "client")]
#[derive(Clone, Copy, Debug)]
pub struct ExperimentalClient<'a>(pub(crate) &'a Client);

#[cfg(feature = "client")]
impl ExperimentalClient<'_> {
    pub async fn determine_version(&self, query: &VersionQuery) -> Result<VersionMatchList, Error> {
        self.0
            .post(&["v1experimental", "determineversion"], query)
            .await
    }

    pub async fn import_findings(&self, source: &str) -> Result<ImportFindingList, Error> {
        self.0
            .get(&["v1experimental", "importfindings"], "source", source)
            .await
    }

    pub async fn ubuntu_binary_to_source(
        &self,
        query: &UbuntuPackageMappingQuery,
    ) -> Result<UbuntuPackageMappingResponse, Error> {
        let response: UbuntuPackageMappingResponse = self
            .0
            .post(&["v1experimental", "ubuntu", "binary-to-source"], query)
            .await?;
        crate::client::check_result_count(query.binary_names.len(), response.results.len())?;
        Ok(response)
    }
}

mod hash_bytes {
    use base64::Engine;
    use base64::alphabet;
    use base64::engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose,
    };
    use serde::{Deserialize, Deserializer, Serializer, de};

    const CONFIG: GeneralPurposeConfig =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
    const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD
            .decode(&text)
            .or_else(|_| URL_SAFE.decode(&text))
            .map_err(de::Error::custom)
    }
}

mod optional_int64 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireInt64 {
        Text(String),
        Number(i64),
    }

    pub fn serialize<S: Serializer>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(number) => serializer.collect_str(number),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i64>, D::Error> {
        Option::<WireInt64>::deserialize(deserializer)?
            .map(|value| match value {
                WireInt64::Text(text) => text.parse().map_err(de::Error::custom),
                WireInt64::Number(number) => Ok(number),
            })
            .transpose()
    }
}
