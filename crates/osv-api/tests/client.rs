#![cfg(feature = "client")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode, header};
use osv_api::experimental::{FileHash, ImportFindingType, UbuntuPackageMappingQuery, VersionQuery};
use osv_api::{BatchQuery, Client, Error, MAX_BATCH_QUERIES, Query};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const MODIFIED: &str = "2026-11-12T00:00:00Z";

struct Exchange {
    method: Method,
    path: String,
    request: Option<Value>,
    status: StatusCode,
    response: String,
    retry_after: Option<&'static str>,
    delay: Duration,
}

impl Exchange {
    fn get(path: &str, response: Value) -> Self {
        Self::new(Method::GET, path, None, response)
    }

    fn post(path: &str, request: Value, response: Value) -> Self {
        Self::new(Method::POST, path, Some(request), response)
    }

    fn new(method: Method, path: &str, request: Option<Value>, response: Value) -> Self {
        Self {
            method,
            path: path.into(),
            request,
            status: StatusCode::OK,
            response: response.to_string(),
            retry_after: None,
            delay: Duration::ZERO,
        }
    }
}

struct MockServer {
    base_url: String,
    exchanges: Arc<Mutex<VecDeque<Exchange>>>,
    task: JoinHandle<()>,
}

impl MockServer {
    async fn start(exchanges: impl IntoIterator<Item = Exchange>) -> Self {
        let exchanges = Arc::new(Mutex::new(exchanges.into_iter().collect::<VecDeque<_>>()));
        let router = Router::new().fallback({
            let exchanges = Arc::clone(&exchanges);
            move |request: Request<Body>| {
                let exchange = exchanges
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected request");
                async move {
                    assert_eq!(request.method(), exchange.method);
                    assert_eq!(request.uri().to_string(), exchange.path);
                    assert_eq!(request.headers()[header::ACCEPT], "application/json");
                    if exchange.request.is_some() {
                        assert_eq!(request.headers()[header::CONTENT_TYPE], "application/json");
                    }
                    let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
                    let actual: Option<Value> =
                        (!body.is_empty()).then(|| serde_json::from_slice(&body).unwrap());
                    assert_eq!(actual, exchange.request);

                    if !exchange.delay.is_zero() {
                        tokio::time::sleep(exchange.delay).await;
                    }
                    let mut response = Response::builder()
                        .status(exchange.status)
                        .header(header::CONTENT_TYPE, "application/json");
                    if let Some(retry_after) = exchange.retry_after {
                        response = response.header(header::RETRY_AFTER, retry_after);
                    }
                    response.body(Body::from(exchange.response)).unwrap()
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            base_url,
            exchanges,
            task,
        }
    }

    fn client(&self) -> Client {
        Client::builder().base_url(&self.base_url).build().unwrap()
    }

    fn assert_finished(&self) {
        assert!(
            self.exchanges.lock().unwrap().is_empty(),
            "expected requests were not sent"
        );
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn advisory(id: &str) -> Value {
    json!({"id": id, "modified": MODIFIED})
}

#[tokio::test]
async fn get_encodes_a_path_parameter_under_the_base_prefix() {
    let mock = MockServer::start([Exchange::get(
        "/proxy/osv/v1/vulns/OSV-a%2Fb%3Fc%23d%25e",
        advisory("OSV-1"),
    )])
    .await;
    let client = Client::builder()
        .base_url(format!("{}/proxy/osv/", mock.base_url))
        .build()
        .unwrap();
    assert_eq!(
        client.get_vulnerability("OSV-a/b?c#d%e").await.unwrap().id,
        "OSV-1"
    );
    assert!(matches!(
        client.get_vulnerability("..").await,
        Err(Error::InvalidPathParameter { parameter: "id" })
    ));
    mock.assert_finished();
}

#[tokio::test]
async fn query_all_follows_tokens_and_preserves_full_records() {
    let request = json!({"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "3.1.4"});
    let mut first_request = request.clone();
    first_request["page_token"] = json!("initial");
    let mut second_request = request.clone();
    second_request["page_token"] = json!("+/opaque==");
    let mut third_request = request;
    third_request["page_token"] = json!("third");
    let mut first_record = advisory("OSV-1");
    first_record["future_field"] = json!({"items": [null, 42]});

    let mock = MockServer::start([
        Exchange::post(
            "/v1/query",
            first_request,
            json!({"vulns": [first_record], "next_page_token": "+/opaque=="}),
        ),
        Exchange::post(
            "/v1/query",
            second_request,
            json!({"next_page_token": "third"}),
        ),
        Exchange::post(
            "/v1/query",
            third_request,
            json!({"vulns": [advisory("OSV-2")], "next_page_token": ""}),
        ),
    ])
    .await;

    let mut query = Query::for_package("PyPI", "jinja2");
    query.version = Some("3.1.4".into());
    query.page_token = Some("initial".into());
    let result = mock.client().query_all(&query).await.unwrap();
    assert_eq!(
        result
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        ["OSV-1", "OSV-2"]
    );
    assert_eq!(
        result[0].extra["future_field"],
        json!({"items": [null, 42]})
    );
    mock.assert_finished();
}

#[tokio::test]
async fn batch_all_splits_and_follows_each_cursor_in_original_input_order() {
    let queries: Vec<_> = (0..=MAX_BATCH_QUERIES)
        .map(|index| Query::for_commit(format!("{index:040x}")))
        .collect();
    let wire_queries: Vec<_> = (0..=MAX_BATCH_QUERIES)
        .map(|index| json!({"commit": format!("{index:040x}")}))
        .collect();
    let mut first_results = vec![json!({}); MAX_BATCH_QUERIES];
    first_results[3] = json!({"next_page_token": "shared"});
    first_results[7] = json!({"vulns": [advisory("OSV-7")], "next_page_token": "shared"});
    let mut cursor_three = wire_queries[3].clone();
    cursor_three["page_token"] = json!("shared");
    let mut cursor_seven = wire_queries[7].clone();
    cursor_seven["page_token"] = json!("shared");
    let mut last_query = wire_queries[MAX_BATCH_QUERIES].clone();
    last_query["page_token"] = json!("last");

    let mock = MockServer::start([
        Exchange::post(
            "/v1/querybatch",
            json!({"queries": wire_queries[..MAX_BATCH_QUERIES]}),
            json!({"results": first_results}),
        ),
        Exchange::post(
            "/v1/querybatch",
            json!({"queries": [cursor_three, cursor_seven]}),
            json!({"results": [{"vulns": [advisory("OSV-3")]}, {"vulns": [advisory("OSV-8")]}]}),
        ),
        Exchange::post(
            "/v1/querybatch",
            json!({"queries": [wire_queries[MAX_BATCH_QUERIES]]}),
            json!({"results": [{"next_page_token": "last"}]}),
        ),
        Exchange::post(
            "/v1/querybatch",
            json!({"queries": [last_query]}),
            json!({"results": [{"vulns": [advisory("OSV-1000")]}]}),
        ),
    ])
    .await;

    let client = mock.client();
    assert!(
        matches!(client.query_batch(&BatchQuery { queries: queries.clone() }).await,
        Err(Error::BatchTooLarge { actual }) if actual == MAX_BATCH_QUERIES + 1)
    );
    let result = client.query_batch_all(&queries).await.unwrap();
    assert_eq!(result.len(), MAX_BATCH_QUERIES + 1);
    assert!(
        result[0].is_empty() && result[4].is_empty() && result[MAX_BATCH_QUERIES - 1].is_empty()
    );
    assert_eq!(result[3][0].id, "OSV-3");
    assert_eq!(result[3][0].modified, MODIFIED);
    assert_eq!(
        result[7]
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        ["OSV-7", "OSV-8"]
    );
    assert_eq!(result[MAX_BATCH_QUERIES][0].id, "OSV-1000");
    assert!(client.query_batch_all(&[]).await.unwrap().is_empty());
    mock.assert_finished();
}

#[tokio::test]
async fn pagination_rejects_cycles_and_incomplete_batch_responses() {
    let mock = MockServer::start([
        Exchange::post(
            "/v1/query",
            json!({"commit": "aaa", "page_token": "same"}),
            json!({"next_page_token": "same"}),
        ),
        Exchange::post(
            "/v1/querybatch",
            json!({"queries": [{"commit": "aaa"}, {"commit": "bbb"}]}),
            json!({"results": [{}]}),
        ),
        Exchange::post(
            "/v1/querybatch",
            json!({"queries": [{"commit": "aaa", "page_token": "same"}]}),
            json!({"results": [{"next_page_token": "same"}]}),
        ),
    ])
    .await;

    let client = mock.client();
    let mut query = Query::for_commit("aaa");
    query.page_token = Some("same".into());
    assert!(matches!(
        client.query_all(&query).await,
        Err(Error::RepeatedPageToken { query_index: None })
    ));
    assert!(matches!(
        client
            .query_batch_all(&[Query::for_commit("aaa"), Query::for_commit("bbb")])
            .await,
        Err(Error::ResultCount {
            expected: 2,
            actual: 1
        })
    ));
    assert!(matches!(
        client.query_batch_all(&[query]).await,
        Err(Error::RepeatedPageToken {
            query_index: Some(0)
        })
    ));
    mock.assert_finished();
}

#[tokio::test]
async fn experimental_routes_use_the_documented_methods_paths_and_fields() {
    let mock = MockServer::start([
        Exchange::post("/v1experimental/determineversion",
            json!({"name": "example", "file_hashes": [{"file_path": "src/a.c", "hash_type": "MD5", "hash": "AAAAAAAAAAAAAAAAAAAAAA=="}]}),
            json!({"matches": [{"score": 1, "repoInfo": {"type": "GIT", "tag": "v1"},
                "osv_identifier": {"name": "example", "ecosystem": "OSS-Fuzz"},
                "minimum_file_matches": "617"}]})),
        Exchange::get("/v1experimental/importfindings/source%2Fname",
            json!({"invalid_records": [{"bug_id": "OSV-1", "source": "source/name",
                "findings": ["IMPORT_FINDING_TYPE_INVALID_JSON", -1],
                "first_seen": MODIFIED, "last_attempt": MODIFIED}]})),
        Exchange::post("/v1experimental/ubuntu/binary-to-source",
            json!({"ecosystem": "Ubuntu:24.04:LTS", "binary_names": ["libcurl4", "unmapped"]}),
            json!({"results": [{"source_names": ["curl"]}, {}]})),
    ]).await;
    let client = mock.client();
    let experimental = client.experimental();

    let versions = experimental
        .determine_version(&VersionQuery {
            name: Some("example".into()),
            file_hashes: vec![FileHash {
                file_path: "src/a.c".into(),
                hash_type: Some("MD5".into()),
                hash: vec![0; 16],
            }],
        })
        .await
        .unwrap();
    let version = &versions.matches[0];
    assert_eq!(version.minimum_file_matches, Some(617));
    assert_eq!(
        version.repo_info.as_ref().unwrap().tag.as_deref(),
        Some("v1")
    );
    assert_eq!(
        version
            .osv_identifier
            .as_ref()
            .unwrap()
            .ecosystem
            .as_deref(),
        Some("OSS-Fuzz")
    );

    let findings = experimental.import_findings("source/name").await.unwrap();
    assert_eq!(findings.invalid_records[0].bug_id.as_deref(), Some("OSV-1"));
    assert_eq!(
        findings.invalid_records[0].findings,
        [
            ImportFindingType::Name("IMPORT_FINDING_TYPE_INVALID_JSON".into()),
            ImportFindingType::Number(-1),
        ]
    );

    let mapping = experimental
        .ubuntu_binary_to_source(&UbuntuPackageMappingQuery {
            ecosystem: "Ubuntu:24.04:LTS".into(),
            binary_names: vec!["libcurl4".into(), "unmapped".into()],
        })
        .await
        .unwrap();
    assert_eq!(mapping.results[0].source_names, ["curl"]);
    assert!(mapping.results[1].source_names.is_empty());
    mock.assert_finished();
}

#[tokio::test]
async fn preserves_rpc_details_and_plain_http_error_bodies() {
    let details = json!({"@type": "type.googleapis.com/google.rpc.BadRequest", "value": 123});
    let payload = json!({"code": 5, "message": "Vulnerability not found", "details": [details]});
    let mut missing = Exchange::get("/v1/vulns/OSV-missing", payload.clone());
    missing.status = StatusCode::NOT_FOUND;
    let mut invalid = Exchange::post("/v1/query", json!({}), json!({}));
    invalid.status = StatusCode::BAD_REQUEST;
    invalid.response = "proxy rejected the request".into();
    let mock = MockServer::start([missing, invalid]).await;

    let client = mock.client();
    let Error::Http {
        status,
        rpc_status: Some(rpc_status),
        body,
        ..
    } = client.get_vulnerability("OSV-missing").await.unwrap_err()
    else {
        panic!("expected RPC status")
    };
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(rpc_status.code, 5);
    assert_eq!(rpc_status.details, [details]);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), payload);

    let Error::Http {
        status,
        rpc_status: None,
        body,
        ..
    } = client.query(&Query::default()).await.unwrap_err()
    else {
        panic!("expected raw HTTP error")
    };
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, b"proxy rejected the request");
    mock.assert_finished();
}

#[tokio::test]
async fn retries_transient_post_errors_with_a_limit_and_respects_retry_after() {
    let request = json!({"commit": "abc"});
    let mut rate_limit = Exchange::post("/v1/query", request.clone(), json!({}));
    rate_limit.status = StatusCode::TOO_MANY_REQUESTS;
    rate_limit.retry_after = Some("0");
    let mut unavailable = Exchange::post("/v1/query", request.clone(), json!({"code": 14}));
    unavailable.status = StatusCode::SERVICE_UNAVAILABLE;
    unavailable.retry_after = Some("0");
    let mut later = Exchange::post("/v1/query", request.clone(), json!({"code": 14}));
    later.status = StatusCode::SERVICE_UNAVAILABLE;
    later.retry_after = Some("60");
    let mock = MockServer::start([
        rate_limit,
        Exchange::post("/v1/query", request.clone(), json!({})),
        unavailable,
        later,
    ])
    .await;
    let query = Query::for_commit("abc");
    assert!(mock.client().query(&query).await.unwrap().vulns.is_empty());

    let client = Client::builder()
        .base_url(&mock.base_url)
        .max_retries(0)
        .build()
        .unwrap();
    assert!(matches!(
        client.query(&query).await,
        Err(Error::Http {
            status: StatusCode::SERVICE_UNAVAILABLE,
            ..
        })
    ));
    assert!(
        matches!(mock.client().query(&query).await, Err(Error::Http { retry_after: Some(delay), .. }) if delay == Duration::from_secs(60))
    );
    mock.assert_finished();
}

#[tokio::test]
async fn retries_a_timed_out_attempt_but_does_not_retry_invalid_success_json() {
    let mut slow = Exchange::get("/v1/vulns/OSV-1", advisory("OSV-1"));
    slow.delay = Duration::from_secs(2);
    let mut malformed = Exchange::get("/v1/vulns/OSV-2", advisory("OSV-2"));
    malformed.response = "this is not JSON".into();
    let mock = MockServer::start([
        slow,
        Exchange::get("/v1/vulns/OSV-1", advisory("OSV-1")),
        malformed,
    ])
    .await;
    let client = Client::builder()
        .base_url(&mock.base_url)
        .timeout(Duration::from_millis(400))
        .max_retries(1)
        .build()
        .unwrap();

    assert_eq!(client.get_vulnerability("OSV-1").await.unwrap().id, "OSV-1");
    assert!(matches!(
        client.get_vulnerability("OSV-2").await,
        Err(Error::Decode(_))
    ));
    mock.assert_finished();
}

#[tokio::test]
#[ignore = "requires network access to api.osv.dev"]
async fn live_osv_dev() {
    let client = Client::new().unwrap();
    let id = "GHSA-jfh8-c2jp-5v3q";
    let mut query = Query::for_package("Maven", "org.apache.logging.log4j:log4j-core");
    query.version = Some("2.14.1".into());

    assert_eq!(client.get_vulnerability(id).await.unwrap().id, id);
    assert!(
        client
            .query_all(&query)
            .await
            .unwrap()
            .iter()
            .any(|record| record.id == id)
    );
    assert!(
        client.query_batch_all(&[query]).await.unwrap()[0]
            .iter()
            .any(|record| record.id == id)
    );
}
