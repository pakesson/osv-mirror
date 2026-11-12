use std::sync::LazyLock;

use chrono::DateTime;
use packageurl::PackageUrl;
use semver::Version;
use serde_json::Value;
use thiserror::Error;

use crate::{Range, Vulnerability};

// Unmodified OSV Schema 1.9.2 from references/osv-schema/validation/schema.json.
static JSON_SCHEMA: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(include_str!("../spec/schema.json"))
        .expect("bundled OSV JSON Schema must be valid JSON");
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("bundled OSV JSON Schema must compile")
});

/// An invalid OSV document or record, with the location of the failure.
#[derive(Debug, Error)]
#[error("{path}: {message}")]
pub struct ValidationError {
    /// A JSON Pointer for validation errors or a Serde path for decode errors.
    /// The document root is displayed as `$`.
    pub path: String,
    pub message: String,
}

impl ValidationError {
    fn at(path: impl Into<String>, message: impl Into<String>) -> Self {
        let path = path.into();
        Self {
            path: if path.is_empty() || path == "." {
                "$".into()
            } else {
                path
            },
            message: message.into(),
        }
    }
}

/// Deserialize exactly one OSV advisory with field paths on decode errors.
///
/// Call [`Vulnerability::validate_for_ingestion`] before indexing the result.
pub fn from_json(json: &str) -> Result<Vulnerability, ValidationError> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let record = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        ValidationError::at(error.path().to_string(), error.inner().to_string())
    })?;
    deserializer
        .end()
        .map_err(|error| ValidationError::at("$", error.to_string()))?;
    Ok(record)
}

/// Validate original JSON against the bundled OSV JSON Schema and additional
/// specification rules for IDs, timestamps, versions, PURLs and range events.
///
/// Validate the original JSON to catch fields rejected by the publication schema.
pub fn validate_json(document: &Value) -> Result<(), ValidationError> {
    JSON_SCHEMA.validate(document).map_err(|error| {
        ValidationError::at(error.instance_path().to_string(), error.to_string())
    })?;
    let record: Vulnerability = serde_path_to_error::deserialize(document).map_err(|error| {
        ValidationError::at(error.path().to_string(), error.inner().to_string())
    })?;
    record.validate_for_ingestion()?;

    for (index, affected) in record.affected_entries().iter().enumerate() {
        if let Some(purl) = affected
            .package
            .as_ref()
            .and_then(|package| package.purl.as_deref())
        {
            let path = format!("/affected/{index}/package/purl");
            let parsed = purl.parse::<PackageUrl<'static>>().map_err(|error| {
                ValidationError::at(&path, format!("invalid package URL: {error}"))
            })?;
            if parsed.version().is_some() {
                return Err(ValidationError::at(
                    path,
                    "package URL must omit its version",
                ));
            }
        }
    }

    Ok(())
}

impl Vulnerability {
    /// Check the fields used by ingestion while accepting additive OSV 1.x data.
    ///
    /// Unknown ecosystem and range kinds are retained. An indexer must treat
    /// unsupported kinds as unevaluable when they could affect a query.
    pub fn validate_for_ingestion(&self) -> Result<(), ValidationError> {
        if self.id.is_empty()
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b":_.-".contains(&byte))
        {
            return Err(ValidationError::at(
                "/id",
                "expected a non-empty ID using ASCII letters, digits, ':', '_', '.' or '-'",
            ));
        }

        let version = Version::parse(self.effective_schema_version())
            .map_err(|error| ValidationError::at("/schema_version", error.to_string()))?;
        if version.major != 1 {
            return Err(ValidationError::at(
                "/schema_version",
                format!("unsupported OSV schema version {version}; expected 1.x"),
            ));
        }

        validate_timestamp("/modified", &self.modified)?;
        if let Some(published) = &self.published {
            validate_timestamp("/published", published)?;
        }
        if let Some(withdrawn) = &self.withdrawn {
            validate_timestamp("/withdrawn", withdrawn)?;
        }

        for (affected_index, affected) in self.affected_entries().iter().enumerate() {
            if let Some(package) = &affected.package {
                for (field, value) in [("ecosystem", &package.ecosystem), ("name", &package.name)] {
                    if value.trim().is_empty() {
                        return Err(ValidationError::at(
                            format!("/affected/{affected_index}/package/{field}"),
                            "expected a non-empty string",
                        ));
                    }
                }
            }

            for (range_index, range) in affected
                .ranges
                .as_deref()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                range.validate_for_ingestion(affected_index, range_index)?;
            }
        }

        Ok(())
    }
}

fn validate_timestamp(path: &str, timestamp: &str) -> Result<(), ValidationError> {
    if timestamp.as_bytes().get(10) == Some(&b'T')
        && timestamp.ends_with('Z')
        && DateTime::parse_from_rfc3339(timestamp).is_ok()
    {
        Ok(())
    } else {
        Err(ValidationError::at(
            path,
            "expected an RFC 3339 timestamp in UTC ending in 'Z'",
        ))
    }
}

impl Range {
    fn validate_for_ingestion(
        &self,
        affected_index: usize,
        range_index: usize,
    ) -> Result<(), ValidationError> {
        let path = format!("/affected/{affected_index}/ranges/{range_index}");
        if self.kind.trim().is_empty() {
            return Err(ValidationError::at(
                format!("{path}/type"),
                "expected a non-empty range type",
            ));
        }
        if !matches!(self.kind.as_str(), "SEMVER" | "ECOSYSTEM" | "GIT") {
            return Ok(());
        }

        if self.kind == "GIT"
            && self
                .repo
                .as_deref()
                .is_none_or(|repo| repo.trim().is_empty())
        {
            return Err(ValidationError::at(
                format!("{path}/repo"),
                "GIT ranges require a repository",
            ));
        }

        let mut has_introduced = false;
        let mut has_fixed = false;
        let mut has_last_affected = false;
        for (event_index, event) in self.events.iter().enumerate() {
            let mut boundaries = [
                ("introduced", event.introduced.as_deref()),
                ("fixed", event.fixed.as_deref()),
                ("last_affected", event.last_affected.as_deref()),
                ("limit", event.limit.as_deref()),
            ]
            .into_iter()
            .filter_map(|(field, value)| value.map(|value| (field, value)));

            let boundary = boundaries.next();
            let Some((field, value)) = boundary.filter(|_| boundaries.next().is_none()) else {
                return Err(ValidationError::at(
                    format!("{path}/events/{event_index}"),
                    "expected exactly one of introduced, fixed, last_affected or limit",
                ));
            };

            if !self.valid_boundary(field, value) {
                return Err(ValidationError::at(
                    format!("{path}/events/{event_index}/{field}"),
                    format!("invalid {} range boundary", self.kind),
                ));
            }

            has_introduced |= field == "introduced";
            has_fixed |= field == "fixed";
            has_last_affected |= field == "last_affected";
        }

        if !has_introduced {
            return Err(ValidationError::at(
                format!("{path}/events"),
                "expected at least one introduced event",
            ));
        }
        if has_fixed && has_last_affected {
            return Err(ValidationError::at(
                format!("{path}/events"),
                "fixed and last_affected events are mutually exclusive",
            ));
        }

        Ok(())
    }

    fn valid_boundary(&self, field: &str, value: &str) -> bool {
        if (field == "introduced" && value == "0") || (field == "limit" && value == "*") {
            return true;
        }

        match self.kind.as_str() {
            "SEMVER" => Version::parse(value).is_ok(),
            "GIT" => {
                matches!(value.len(), 40 | 64)
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
            _ => !value.trim().is_empty(),
        }
    }
}
