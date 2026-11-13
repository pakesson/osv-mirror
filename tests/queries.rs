use axum::http::StatusCode;
use osv_api::{Client, Error, Query, QueryPackage};
use osv_store::{Advisory, SnapshotWriter, Store, SyncWriter, Validators};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::TcpListener;

fn advisory(id: &str, affected: Value) -> Value {
    json!({"id": id, "modified": "2026-11-12T00:00:00Z", "affected": affected})
}

fn affected(eco: &str, name: &str, kind: &str, events: Value) -> Value {
    json!({"package": {"ecosystem": eco, "name": name}, "ranges": [{"type":kind,"events":events}]})
}

fn versioned(eco: &str, name: &str, version: &str) -> Query {
    Query {
        version: Some(version.into()),
        ..Query::for_package(eco, name)
    }
}

#[tokio::test]
async fn queries_match_packages_ranges_and_wire_contract() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("mirror.sqlite");
    let mut writer = SnapshotWriter::new(&path).unwrap();
    let mut withdrawn = advisory(
        "OSV-withdrawn",
        json!([{"package":{"ecosystem":"PyPI","name":"Demo_Pkg"}}]),
    );
    withdrawn["withdrawn"] = json!("2026-11-12T00:00:00Z");
    let mut python = advisory(
        "OSV-python",
        json!([
            affected(
                "PyPI",
                "Demo_Pkg",
                "ECOSYSTEM",
                json!([{"introduced":"0"},{"fixed":"2.0rc1"}])
            ),
            affected(
                "PyPI",
                "demo-pkg",
                "ECOSYSTEM",
                json!([{"introduced":"1.0"},{"last_affected":"1.1"}])
            ),
            affected(
                "PyPI",
                "different",
                "ECOSYSTEM",
                json!([{"introduced":"0"}])
            )
        ]),
    );
    python["references"] = json!([{"type":"WEB"}]); // Optional metadata is outside the matching projection.
    let records = [
        python.clone(),
        withdrawn,
        advisory(
            "OSV-rust",
            json!([affected(
                "crates.io",
                "Foo_bar",
                "SEMVER",
                json!([
                    {"limit":"3.0.0"},{"fixed":"1.0.0"},{"introduced":"2.0.0"},{"introduced":"0"},{"fixed":"4.0.0"}
                ])
            )]),
        ),
        advisory(
            "OSV-last",
            json!([affected(
                "npm",
                "@scope/demo",
                "SEMVER",
                json!([
                    {"last_affected":"1.0.0"},{"introduced":"0"},{"introduced":"2.0.0"},{"last_affected":"2.1.0"}
                ])
            )]),
        ),
        advisory(
            "OSV-deb",
            json!([affected(
                "Debian:12",
                "demo",
                "ECOSYSTEM",
                json!([
                    {"introduced":"0"},{"fixed":"1:2.0-1+deb12u2"}
                ])
            )]),
        ),
        advisory(
            "OSV-apk",
            json!([affected(
                "Alpine:v3.21",
                "demo",
                "ECOSYSTEM",
                json!([
                    {"introduced":"0"},{"fixed":"2.0-r10"}
                ])
            )]),
        ),
        advisory(
            "OSV-rpm",
            json!([affected(
                "Red Hat:rhel:9",
                "demo",
                "ECOSYSTEM",
                json!([
                    {"introduced":"0"},{"fixed":"1:2.0-3.el9"}
                ])
            )]),
        ),
        advisory(
            "OSV-unhandled",
            json!([affected(
                "Android",
                "device",
                "ECOSYSTEM",
                json!([
                    {"introduced":"0"},{"fixed":"2025-01-01"}
                ])
            )]),
        ),
        advisory(
            "OSV-wildcard",
            json!([{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"*"}}]),
        ),
        advisory(
            "OSV-nuget",
            json!([{"package":{"ecosystem":"NuGet","name":"Demo.Net"},"versions":["1.0.0.0"]}]),
        ),
        advisory(
            "OSV-maven",
            json!([affected(
                "Maven",
                "org.example:demo",
                "ECOSYSTEM",
                json!([
                    {"introduced":"0"},{"fixed":"1.2-final"}
                ])
            )]),
        ),
    ];
    for record in records {
        writer
            .insert(&Advisory::parse(&record.to_string()).unwrap())
            .unwrap();
    }
    writer.publish().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = osv_server::router(Store::open(&path).unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = Client::builder().base_url(&url).build().unwrap();

    let cases = [
        (
            Query::for_purl("pkg:pypi/DEMO.Pkg@2.0b1"),
            Some("OSV-python"),
        ),
        (versioned("PyPI", "demo_pkg", "2.0rc1"), None),
        (Query::for_package("PyPI", "demo__pkg"), Some("OSV-python")),
        (versioned("", "demo-pkg", "1.1"), Some("OSV-python")),
        (
            versioned("crates.io", "FOO_BAR", "v2.0.0+build"),
            Some("OSV-rust"),
        ),
        (versioned("crates.io", "foo-bar", "1.0.0"), None),
        (versioned("crates.io", "foo-bar", "3.0.0"), None),
        (
            Query::for_purl("pkg:npm/%40scope/demo@1.0.0"),
            Some("OSV-last"),
        ),
        (versioned("npm", "@scope/demo", "1.0.1"), None),
        (
            Query::for_purl("pkg:deb/debian/demo@1:2.0-1+deb12u1?distro=bookworm"),
            Some("OSV-deb"),
        ),
        (versioned("Debian:13", "demo", "1:2.0-1+deb12u1"), None),
        (versioned("Alpine:v3.21", "demo", "2.0-r9"), Some("OSV-apk")),
        (versioned("Alpine:v3.21", "demo", "2.0-r10"), None),
        (versioned("Alpine", "demo", "2.0-r9"), None),
        (
            versioned("Red Hat:rhel:9", "demo", "1:2.0-2.el9"),
            Some("OSV-rpm"),
        ),
        (versioned("Red Hat:rhel:9", "demo", "1:2.0-3.el9"), None),
        (
            Query::for_package("Ubuntu:24.04", "anything"),
            Some("OSV-wildcard"),
        ),
        (versioned("NuGet", "DEMO.NET", "1.0"), Some("OSV-nuget")),
        (
            Query::for_purl("pkg:maven/org.example/demo@1.2-rc1"),
            Some("OSV-maven"),
        ),
        (Query::for_purl("pkg:unknown/demo@1.0"), None),
    ];
    let queries = cases
        .iter()
        .map(|(query, _)| query.clone())
        .collect::<Vec<_>>();
    let result = client.query_batch_all(&queries).await.unwrap();
    for ((query, expected), matches) in cases.iter().zip(result) {
        assert_eq!(
            matches
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            expected.iter().copied().collect::<Vec<_>>(),
            "{query:?}"
        );
    }

    let http = reqwest::Client::new();
    let single: Value = http
        .post(format!("{url}/v1/query"))
        .json(&Query::for_package("PyPI", "demo.pkg"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(single, json!({"vulns":[python]}));
    let batch: Value = http.post(format!("{url}/v1/querybatch"))
        .json(&json!({"queries":[Query::for_package("PyPI","demo-pkg"), Query::for_package("PyPI","nope")]}))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(
        batch,
        json!({"results":[{"vulns":[{"id":"OSV-python","modified":"2026-11-12T00:00:00Z"}]},{}]})
    );

    for (query, expected, code) in [
        (
            versioned("Android", "device", "2024-01-01"),
            StatusCode::NOT_IMPLEMENTED,
            12,
        ),
        (Query::for_commit("deadbeef"), StatusCode::BAD_REQUEST, 3),
        (versioned("pypi", "demo", "1"), StatusCode::BAD_REQUEST, 3),
        (
            Query {
                version: Some("2".into()),
                ..Query::for_purl("pkg:pypi/demo@1")
            },
            StatusCode::BAD_REQUEST,
            3,
        ),
        (
            Query {
                package: Some(QueryPackage {
                    name: Some("foo".into()),
                    ..QueryPackage::default()
                }),
                ..Query::default()
            },
            StatusCode::BAD_REQUEST,
            3,
        ),
    ] {
        assert!(
            matches!(client.query(&query).await, Err(Error::Http { status, rpc_status: Some(rpc), .. }) if status == expected && rpc.code == code),
            "{query:?}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn query_tokens_bind_to_normalized_input_and_data_revision() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("mirror.sqlite");
    let mut writer = SnapshotWriter::new(&path).unwrap();
    let ids = (0..1001).map(|i| format!("OSV-{i:04}")).collect::<Vec<_>>();
    for id in &ids {
        let record = advisory(
            id,
            json!([{"package":{"ecosystem":"PyPI","name":"many_pkg"},"versions":["1"]}]),
        );
        writer
            .insert(&Advisory::parse(&record.to_string()).unwrap())
            .unwrap();
    }
    writer.publish().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let client = Client::builder().base_url(&url).build().unwrap();
    let router = osv_server::router(Store::open(&path).unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let mut query = Query::for_package("PyPI", "Many.Pkg");
    let first = client.query(&query).await.unwrap();
    assert_eq!(first.vulns.len(), 1000);
    query.page_token = first.next_page_token;
    assert!(query.page_token.is_some());
    let mut equivalent = Query::for_package("PyPI", "many-pkg");
    equivalent.page_token.clone_from(&query.page_token);
    let last = client.query(&equivalent).await.unwrap();
    assert_eq!(last.vulns[0].id, ids[1000]);
    assert!(last.next_page_token.is_none());
    // A batch can allocate fewer results per query. The continuation helper
    // sends only the inputs that still have pages.
    let mut mixed = vec![Query::for_package("PyPI", "many-pkg"); 4];
    mixed[1] = Query::for_package("PyPI", "no-such-package");
    let paged = client.query_batch_all(&mixed).await.unwrap();
    assert!(paged[1].is_empty());
    for index in [0, 2, 3] {
        assert_eq!(
            paged[index]
                .iter()
                .map(|entry| &entry.id)
                .collect::<Vec<_>>(),
            ids.iter().collect::<Vec<_>>()
        );
    }
    let bad = Query {
        version: Some("1".into()),
        ..query.clone()
    };
    assert!(matches!(
        client.query(&bad).await,
        Err(Error::Http {
            status: StatusCode::BAD_REQUEST,
            ..
        })
    ));
    assert!(matches!(
        client
            .query_batch(&osv_api::BatchQuery {
                queries: vec![Query::default(); 1001]
            })
            .await,
        Err(Error::BatchTooLarge { .. })
    ));
    let response = reqwest::Client::new()
        .post(format!("{url}/v1/querybatch"))
        .json(&json!({"queries": vec![Query::default(); 1001]}))
        .send()
        .await;
    assert_eq!(response.unwrap().status(), StatusCode::BAD_REQUEST);

    let mut update = SyncWriter::open(&path, "https://example.com/modified_id.csv").unwrap();
    let old = "2026-11-12T00:00:00";
    let new = "2026-11-13T00:00:00";
    update
        .load_inventory::<osv_store::Error>(ids.iter().enumerate().map(|(i, id)| {
            Ok((
                id.clone(),
                "PyPI".into(),
                if i == 0 { new } else { old }.into(),
            ))
        }))
        .unwrap();
    update.plan().unwrap();
    let replacement = json!({"id":ids[0],"modified":format!("{new}Z"),"affected":[{"package":{"ecosystem":"PyPI","name":"moved"}}]});
    update
        .stage(&[(ids[0].clone(), replacement.to_string())])
        .unwrap();
    update
        .finish(Some(("digest", &Validators::default())))
        .unwrap();

    assert!(
        matches!(client.query(&query).await, Err(Error::Http { status: StatusCode::BAD_REQUEST, rpc_status: Some(rpc), .. }) if rpc.message.contains("stale cursor"))
    );
    assert_eq!(
        client
            .query_all(&Query::for_package("PyPI", "many-pkg"))
            .await
            .unwrap()
            .len(),
        1000
    );
    assert_eq!(
        client
            .query_all(&Query::for_package("PyPI", "moved"))
            .await
            .unwrap()[0]
            .id,
        ids[0]
    );
    server.abort();
}
