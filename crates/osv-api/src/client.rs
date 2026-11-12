use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use reqwest::{RequestBuilder, StatusCode, Url, header};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::experimental::ExperimentalClient;
use crate::{
    BatchQuery, BatchQueryResponse, MAX_BATCH_QUERIES, Query, QueryResponse, RpcStatus,
    Vulnerability, VulnerabilitySummary,
};

const DEFAULT_BASE_URL: &str = "https://api.osv.dev";
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Failures returned by the client. HTTP errors preserve the status and body,
/// including gateway or proxy responses that have no Google RPC status object.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid OSV base URL: {0}")]
    InvalidBaseUrl(String),
    #[error("invalid OSV path parameter {parameter}")]
    InvalidPathParameter { parameter: &'static str },
    #[error("cannot build OSV HTTP client")]
    Build(#[source] reqwest::Error),
    #[error("OSV HTTP request failed")]
    Transport(#[source] reqwest::Error),
    #[error("cannot read OSV HTTP {status} response body")]
    ReadBody {
        status: StatusCode,
        retry_after: Option<Duration>,
        #[source]
        source: reqwest::Error,
    },
    #[error("OSV API returned HTTP {status}")]
    Http {
        status: StatusCode,
        rpc_status: Option<RpcStatus>,
        body: Vec<u8>,
        retry_after: Option<Duration>,
    },
    #[error("cannot decode OSV JSON response")]
    Decode(#[source] serde_json::Error),
    #[error("OSV batch has {actual} queries, exceeding the {MAX_BATCH_QUERIES}-query limit")]
    BatchTooLarge { actual: usize },
    #[error("OSV API returned {actual} results for {expected} inputs")]
    ResultCount { expected: usize, actual: usize },
    #[error("OSV API repeated a pagination token")]
    RepeatedPageToken { query_index: Option<usize> },
}

#[derive(Clone, Debug)]
pub struct ClientBuilder {
    base_url: String,
    connect_timeout: Duration,
    timeout: Duration,
    max_retries: usize,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.into(),
            connect_timeout: Duration::from_secs(10),
            timeout: Duration::from_secs(60),
            max_retries: 2,
        }
    }
}

impl ClientBuilder {
    /// Set the HTTP(S) endpoint and an optional path prefix.
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the deadline for an individual attempt, including its response body.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set how many transient failures to retry after the first attempt.
    pub fn max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn build(self) -> Result<Client, Error> {
        let base_url =
            Url::parse(&self.base_url).map_err(|error| Error::InvalidBaseUrl(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(Error::InvalidBaseUrl(
                "expected an HTTP(S) URL without credentials, query or fragment".into(),
            ));
        }

        let http = reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .map_err(Error::Build)?;

        Ok(Client {
            base_url,
            http,
            max_retries: self.max_retries,
        })
    }
}

/// Asynchronous OSV.dev client. Clones share the underlying connection pool.
#[derive(Clone, Debug)]
pub struct Client {
    base_url: Url,
    http: reqwest::Client,
    max_retries: usize,
}

impl Client {
    pub fn new() -> Result<Self, Error> {
        Self::builder().build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn experimental(&self) -> ExperimentalClient<'_> {
        ExperimentalClient(self)
    }

    pub async fn get_vulnerability(&self, id: &str) -> Result<Vulnerability, Error> {
        self.get(&["v1", "vulns"], "id", id).await
    }

    /// Fetch a single page, including its continuation token if present.
    pub async fn query(&self, query: &Query) -> Result<QueryResponse, Error> {
        self.post(&["v1", "query"], query).await
    }

    /// Follow all continuation tokens, starting at the page given by the query.
    pub async fn query_all(&self, query: &Query) -> Result<Vec<Vulnerability>, Error> {
        let mut query = query.clone();
        let mut seen = seen_tokens(&query);
        let mut vulns = Vec::new();

        loop {
            let response = self.query(&query).await?;
            vulns.extend(response.vulns);
            match next_token(response.next_page_token, &mut seen, None)? {
                Some(token) => query.page_token = Some(token),
                None => return Ok(vulns),
            }
        }
    }

    /// Fetch one page for each query in a batch of at most 1,000 inputs.
    pub async fn query_batch(&self, batch: &BatchQuery) -> Result<BatchQueryResponse, Error> {
        if batch.queries.len() > MAX_BATCH_QUERIES {
            return Err(Error::BatchTooLarge {
                actual: batch.queries.len(),
            });
        }
        let response: BatchQueryResponse = self.post(&["v1", "querybatch"], batch).await?;
        check_result_count(batch.queries.len(), response.results.len())?;
        Ok(response)
    }

    /// Split larger batches and follow each query's tokens independently.
    /// The outer vector has one entry per input query, in the original order.
    pub async fn query_batch_all(
        &self,
        queries: &[Query],
    ) -> Result<Vec<Vec<VulnerabilitySummary>>, Error> {
        let mut matches = vec![Vec::new(); queries.len()];

        for (chunk, queries) in queries.chunks(MAX_BATCH_QUERIES).enumerate() {
            let offset = chunk * MAX_BATCH_QUERIES;
            let mut pending: Vec<_> = queries
                .iter()
                .enumerate()
                .map(|(index, query)| (offset + index, seen_tokens(query)))
                .collect();
            let mut batch = BatchQuery {
                queries: queries.to_vec(),
            };

            while !pending.is_empty() {
                let response = self.query_batch(&batch).await?;
                let mut next = Vec::new();
                let mut next_queries = Vec::new();
                for (((index, mut seen), mut query), result) in
                    pending.into_iter().zip(batch.queries).zip(response.results)
                {
                    matches[index].extend(result.vulns);
                    if let Some(token) = next_token(result.next_page_token, &mut seen, Some(index))?
                    {
                        query.page_token = Some(token);
                        next.push((index, seen));
                        next_queries.push(query);
                    }
                }
                pending = next;
                batch = BatchQuery {
                    queries: next_queries,
                };
            }
        }

        Ok(matches)
    }

    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        path: &[&str],
        parameter: &'static str,
        value: &str,
    ) -> Result<T, Error> {
        if matches!(value, "" | "." | "..") {
            return Err(Error::InvalidPathParameter { parameter });
        }
        let url = self.endpoint(path.iter().copied().chain([value]));
        self.send(|| self.http.get(url.clone())).await
    }

    pub(crate) async fn post<T: DeserializeOwned>(
        &self,
        path: &[&str],
        body: &impl Serialize,
    ) -> Result<T, Error> {
        let url = self.endpoint(path.iter().copied());
        self.send(|| self.http.post(url.clone()).json(body)).await
    }

    fn endpoint<'a>(&self, path: impl IntoIterator<Item = &'a str>) -> Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("validated HTTP(S) URLs have path segments")
            .pop_if_empty()
            .extend(path);
        url
    }

    async fn send<T: DeserializeOwned>(
        &self,
        request: impl Fn() -> RequestBuilder,
    ) -> Result<T, Error> {
        let mut retries = 0;
        loop {
            let error = match send_once(request()).await {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            if retries == self.max_retries {
                return Err(error);
            }
            let Some(delay) = retry_delay(&error, retries) else {
                return Err(error);
            };
            tokio::time::sleep(delay).await;
            retries += 1;
        }
    }
}

async fn send_once<T: DeserializeOwned>(request: RequestBuilder) -> Result<T, Error> {
    let response = request
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(Error::Transport)?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|header| header.to_str().ok())
        .and_then(parse_retry_after);
    let body = response.bytes().await.map_err(|source| Error::ReadBody {
        status,
        retry_after,
        source,
    })?;

    if !status.is_success() {
        return Err(Error::Http {
            status,
            rpc_status: serde_json::from_slice(&body).ok(),
            body: body.to_vec(),
            retry_after,
        });
    }
    serde_json::from_slice(&body).map_err(Error::Decode)
}

pub(crate) fn check_result_count(expected: usize, actual: usize) -> Result<(), Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(Error::ResultCount { expected, actual })
    }
}

fn seen_tokens(query: &Query) -> HashSet<String> {
    query
        .page_token
        .iter()
        .filter(|token| !token.is_empty())
        .cloned()
        .collect()
}

fn next_token(
    token: Option<String>,
    seen: &mut HashSet<String>,
    query_index: Option<usize>,
) -> Result<Option<String>, Error> {
    if let Some(token) = token.filter(|token| !token.is_empty()) {
        if !seen.insert(token.clone()) {
            return Err(Error::RepeatedPageToken { query_index });
        }
        Ok(Some(token))
    } else {
        Ok(None)
    }
}

fn parse_retry_after(header: &str) -> Option<Duration> {
    let header = header.trim();
    if let Ok(seconds) = header.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(header).ok()?;
    Some(date.duration_since(SystemTime::now()).unwrap_or_default())
}

fn retry_delay(error: &Error, retries: usize) -> Option<Duration> {
    let retry_after = match error {
        Error::Transport(source)
            if source.is_connect() || source.is_timeout() || source.is_request() =>
        {
            None
        }
        Error::ReadBody {
            status,
            retry_after,
            ..
        } if status.is_success() || retryable_status(*status) => *retry_after,
        Error::Http {
            status,
            retry_after,
            ..
        } if retryable_status(*status) => *retry_after,
        _ => return None,
    };

    if let Some(delay) = retry_after {
        // Respect a longer server-supplied delay by returning the error to the caller.
        return (delay <= MAX_RETRY_DELAY).then_some(delay);
    }
    Some(Duration::from_millis(200 * (1 << retries.min(5))).min(MAX_RETRY_DELAY))
}

fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}
