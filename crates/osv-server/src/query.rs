use axum::Json;
use axum::extract::{State, rejection::JsonRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use osv_api::{
    BatchQuery, BatchQueryResponse, MAX_BATCH_QUERIES, Query, QueryPage, VulnerabilitySummary,
};
use osv_store::{PackageQuery, PackageSearch};
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::{ServerState, rpc_error};

const PAGE_SIZE: usize = 1_000;
const BATCH_RESULTS: usize = 3_000;
const SCAN_LIMIT: usize = 4_096;
const JSON_BUDGET: usize = 32 * 1024 * 1024 - 4_096;

pub(crate) async fn single(
    State(state): State<ServerState>,
    query: Result<Json<Query>, JsonRejection>,
) -> Response {
    let result = state
        .run_query(move |store| {
            let query = parse(json(query)?)?;
            store.with_package_search(|search| {
                let page = page(search, &query, PAGE_SIZE, SCAN_LIMIT, Some(JSON_BUDGET))?;
                let vulns = page
                    .vulns
                    .into_iter()
                    .map(|entry| {
                        RawValue::from_string(entry.json.expect("full query requests JSON"))
                            .map_err(osv_store::Error::from)
                    })
                    .collect::<Result<_, _>>()?;
                Ok(Json(QueryPage {
                    vulns,
                    next_page_token: page.next_page_token,
                })
                .into_response())
            })
        })
        .await;
    result.unwrap_or_else(QueryError::response)
}

pub(crate) async fn batch(
    State(state): State<ServerState>,
    batch: Result<Json<BatchQuery>, JsonRejection>,
) -> Response {
    let result = state
        .run_query(move |store| {
            let queries = json(batch)?.queries;
            if queries.len() > MAX_BATCH_QUERIES {
                return Err(QueryError::invalid("too many queries"));
            }
            let queries = queries
                .into_iter()
                .enumerate()
                .map(|(index, query)| parse(query).map_err(|error| error.at_index(index)))
                .collect::<Result<Vec<_>, _>>()?;
            let count = queries.len().max(1);
            let limit = PAGE_SIZE.min(BATCH_RESULTS / count);
            let scan = SCAN_LIMIT.min((16_384 / count).max(32));
            store.with_package_search(|search| {
                let results = queries
                    .iter()
                    .enumerate()
                    .map(|(index, query)| {
                        let page = page(search, query, limit, scan, None)
                            .map_err(|error| error.at_index(index))?;
                        let vulns = page
                            .vulns
                            .into_iter()
                            .map(|entry| VulnerabilitySummary {
                                id: entry.id,
                                modified: entry.modified,
                            })
                            .collect();
                        Ok(QueryPage {
                            vulns,
                            next_page_token: page.next_page_token,
                        })
                    })
                    .collect::<Result<_, QueryError>>()?;
                Ok(Json(BatchQueryResponse { results }).into_response())
            })
        })
        .await;
    result.unwrap_or_else(QueryError::response)
}

struct Parsed {
    query: Option<PackageQuery>,
    token: Option<String>,
}

fn parse(query: Query) -> Result<Parsed, QueryError> {
    let has_version = query.version.is_some();
    let version = query.version.unwrap_or_default();
    if let Some(commit) = query.commit {
        if has_version {
            return Err(QueryError::invalid(
                "commit and version are mutually exclusive",
            ));
        }
        if commit.is_empty()
            || commit.len() % 2 != 0
            || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(QueryError::invalid("invalid hash"));
        }
        return Err(QueryError::unsupported(
            "commit queries require a local commit index",
        ));
    }

    let package = query
        .package
        .ok_or_else(|| QueryError::invalid("invalid query"))?;
    let mut name = package.name.unwrap_or_default();
    let mut ecosystem = package.ecosystem.unwrap_or_default();
    let mut version = version;
    if let Some(purl) = package.purl.filter(|purl| !purl.is_empty()) {
        if !name.is_empty() {
            return Err(QueryError::invalid("name specified in a PURL query"));
        }
        if !ecosystem.is_empty() {
            return Err(QueryError::invalid("ecosystem specified in a PURL query"));
        }
        let purl = purl
            .parse::<PackageUrl<'static>>()
            .map_err(|_| QueryError::invalid("invalid PURL"))?;
        if let Some(purl_version) = purl.version() {
            if !version.is_empty() {
                return Err(QueryError::invalid(
                    "version specified in params and PURL query",
                ));
            }
            version = purl_version.into();
        }
        let Some((mapped_ecosystem, mapped_name)) = map_purl(&purl) else {
            if query
                .page_token
                .as_deref()
                .is_some_and(|token| !token.is_empty())
            {
                return Err(QueryError::invalid("invalid cursor"));
            }
            return Ok(Parsed {
                query: None,
                token: query.page_token,
            });
        };
        ecosystem = mapped_ecosystem;
        name = mapped_name;
    }
    if name.is_empty() || (ecosystem.is_empty() && version.is_empty()) {
        return Err(QueryError::invalid("invalid query"));
    }
    if !ecosystem.is_empty() && !osv_store::known_ecosystem(&ecosystem) {
        return Err(QueryError::invalid("invalid ecosystem"));
    }
    if osv_store::base_ecosystem(&ecosystem) == "GIT" {
        return Err(QueryError::unsupported(
            "Git repository queries are not available yet",
        ));
    }
    if [&name, &ecosystem, &version]
        .iter()
        .any(|field| field.len() > 4_096 || field.contains('\0'))
    {
        return Err(QueryError::invalid("invalid query field"));
    }
    Ok(Parsed {
        query: Some(PackageQuery::new(&name, &ecosystem, &version)),
        token: query.page_token,
    })
}

fn map_purl(purl: &PackageUrl<'_>) -> Option<(String, String)> {
    let namespace = purl.namespace().unwrap_or_default();
    let eco = match (purl.ty(), namespace) {
        ("bitnami", _) => "Bitnami",
        ("cran", _) => "CRAN",
        ("conan", _) => "ConanCenter",
        ("hackage", _) => "Hackage",
        ("hex", _) => "Hex",
        ("julia", _) => "Julia",
        ("nuget", _) => "NuGet",
        ("generic", _) => "OSS-Fuzz",
        ("pub", _) => "Pub",
        ("pypi", _) => "PyPI",
        ("gem", _) => "RubyGems",
        ("swift", _) => "SwiftURL",
        ("cargo", _) => "crates.io",
        ("npm", _) => "npm",
        ("opam", _) => "opam",
        ("golang", _) => "Go",
        ("maven" | "gradle", _) => "Maven",
        ("composer", _) => "Packagist",
        ("deb", "debian") => "Debian",
        ("deb", "ubuntu") => "Ubuntu",
        ("deb", "echo") => "Echo",
        ("dhi", _) | ("apk" | "deb", "dhi") => "Docker Hardened Images",
        ("apk", "chainguard") => "Chainguard",
        ("apk", "minimos") => "MinimOS",
        ("apk", "wolfi") => "Wolfi",
        ("apk", "alpine") => "Alpine",
        ("apk", "alpaquita") => "Alpaquita",
        ("apk", "bellsoft-hardened-containers") => "BellSoft Hardened Containers",
        ("rpm", "almalinux") => "AlmaLinux",
        ("rpm", "azure-linux") => "Azure Linux",
        ("rpm", "mageia") => "Mageia",
        ("rpm", "openeuler") => "openEuler",
        ("rpm", "opensuse") => "openSUSE",
        ("rpm", "redhat") => "Red Hat",
        ("rpm", "rocky-linux") => "Rocky Linux",
        ("rpm", "suse") => "SUSE",
        _ => return None,
    };
    let mut ecosystem = eco.to_owned();
    let mut name = purl.name().to_owned();
    match eco {
        "Maven" if !namespace.is_empty() => name = format!("{namespace}:{name}"),
        "Go" | "npm" | "Hex" | "SwiftURL" | "Packagist" if !namespace.is_empty() => {
            name = format!("{namespace}/{name}");
        }
        _ => {}
    }
    if eco == "Go"
        && let Some(subpath) = purl.subpath()
    {
        name.push('/');
        name.push_str(subpath);
    }
    if eco == "Debian"
        && let Some(distro) = purl.qualifiers().get("distro")
    {
        let distro = distro.to_ascii_lowercase();
        let release = match distro.as_str() {
            "buzz" => "1.1",
            "rex" => "1.2",
            "bo" => "1.3",
            "hamm" => "2",
            "slink" => "2.1",
            "potato" => "2.2",
            "woody" => "3",
            "sarge" => "3.1",
            "etch" => "4",
            "lenny" => "5",
            "squeeze" => "6",
            "wheezy" => "7",
            "jessie" => "8",
            "stretch" => "9",
            "buster" => "10",
            "bullseye" => "11",
            "bookworm" => "12",
            "trixie" => "13",
            "forky" => "14",
            "duke" => "15",
            _ => &distro,
        };
        ecosystem.push(':');
        ecosystem.push_str(release);
    }
    if eco == "Packagist"
        && let Some(repository) = purl.qualifiers().get("repository_url")
    {
        ecosystem.push(':');
        ecosystem.push_str(repository);
    }
    Some((ecosystem, name))
}

#[derive(Deserialize, Serialize)]
struct Cursor {
    snapshot: String,
    revision: i64,
    query: String,
    after: String,
}

fn page(
    search: &PackageSearch<'_>,
    parsed: &Parsed,
    limit: usize,
    scan: usize,
    budget: Option<usize>,
) -> Result<QueryPage<osv_store::PackageMatch>, QueryError> {
    let Some(query) = &parsed.query else {
        return Ok(QueryPage {
            vulns: Vec::new(),
            next_page_token: None,
        });
    };
    let mut hash = Sha256::new();
    for part in query.identity() {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    let fingerprint = format!("{:x}", hash.finalize());
    let after = if let Some(token) = parsed.token.as_deref().filter(|token| !token.is_empty()) {
        let cursor = (token.len() <= 4_096)
            .then(|| URL_SAFE_NO_PAD.decode(token).ok())
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<Cursor>(&bytes).ok())
            .filter(|cursor| cursor.query == fingerprint && !cursor.after.is_empty())
            .ok_or_else(|| QueryError::invalid("invalid cursor"))?;
        if cursor.snapshot != search.snapshot || cursor.revision != search.revision {
            return Err(osv_store::Error::StalePage.into());
        }
        cursor.after
    } else {
        String::new()
    };
    let page = search.page(query, &after, limit, scan, budget)?;
    let next_page_token = page.next_after.map(|after| {
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Cursor {
                snapshot: search.snapshot.clone(),
                revision: search.revision,
                query: fingerprint,
                after,
            })
            .expect("cursor contains only JSON strings and integers"),
        )
    });
    Ok(QueryPage {
        vulns: page.matches,
        next_page_token,
    })
}

struct QueryError(StatusCode, i32, String);

impl QueryError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, 3, message.into())
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self(StatusCode::NOT_IMPLEMENTED, 12, message.into())
    }

    fn at_index(mut self, index: usize) -> Self {
        self.2 = format!("error in query at index {index}: {}", self.2);
        self
    }

    fn response(self) -> Response {
        rpc_error(self.0, self.1, self.2)
    }
}

impl From<osv_store::Error> for QueryError {
    fn from(error: osv_store::Error) -> Self {
        match error {
            osv_store::Error::UnsupportedMatch { .. } => Self::unsupported(error.to_string()),
            osv_store::Error::StalePage => Self::invalid("stale cursor; restart pagination"),
            osv_store::Error::ResponseTooLarge => {
                Self(StatusCode::PAYLOAD_TOO_LARGE, 8, error.to_string())
            }
            _ => {
                tracing::error!(%error, "package query failed");
                Self(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    13,
                    "error querying vulnerabilities".into(),
                )
            }
        }
    }
}

fn json<T>(value: Result<Json<T>, JsonRejection>) -> Result<T, QueryError> {
    value.map(|Json(value)| value).map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            QueryError(
                StatusCode::PAYLOAD_TOO_LARGE,
                8,
                "query request exceeds the body limit".into(),
            )
        } else {
            QueryError::invalid("invalid query JSON")
        }
    })
}

impl ServerState {
    async fn run_query(
        self,
        operation: impl FnOnce(&osv_store::Store) -> Result<Response, QueryError> + Send + 'static,
    ) -> Result<Response, QueryError> {
        let permit = self
            .workers
            .acquire_owned()
            .await
            .expect("worker semaphore stays open");
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(&self.store)
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "package query worker failed");
            QueryError(
                StatusCode::INTERNAL_SERVER_ERROR,
                13,
                "error querying vulnerabilities".into(),
            )
        })?
    }
}
