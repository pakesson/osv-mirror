use std::path::Path;
use std::process::Command;

use axum::http::StatusCode;
use osv_api::{BatchQuery, Client, Error, Query};
use osv_store::{Advisory, SnapshotWriter, Store, SyncWriter, Validators};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::TcpListener;

const REPO: &str = "https://github.com/Owner/Project.git/";
const OTHER: &str = "https://github.com/owner/other";

fn git(path: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}

fn commit(path: &Path, label: &str) -> String {
    std::fs::write(path.join(label), label).unwrap();
    git(path, &["add", label]);
    git(path, &["commit", "-m", label]);
    git(path, &["rev-parse", "HEAD"])
}

fn range(repo: &str, events: Value, tags: &[&str]) -> Value {
    json!({"ranges": [{"type":"GIT","repo":repo,"events":events}],"versions":tags})
}

fn advisory(id: &str, affected: Value) -> Value {
    json!({"id":id,"modified":"2026-11-12T00:00:00Z","affected":affected})
}

fn git_commit(hash: &str) -> Query {
    Query {
        package: Query::for_package("GIT", REPO).package,
        ..Query::for_commit(hash)
    }
}

fn tag(repo: &str, version: &str) -> Query {
    Query {
        version: Some(version.into()),
        ..Query::for_package("GIT", repo)
    }
}

#[tokio::test]
async fn git_tags_and_commits_use_the_same_wire_routes() {
    let dir = tempdir().unwrap();
    let mirror = dir.path().join("repo");
    std::fs::create_dir(&mirror).unwrap();
    git(&mirror, &["init", "-b", "main"]);
    git(&mirror, &["config", "user.name", "OSV Test"]);
    git(&mirror, &["config", "user.email", "osv@example.org"]);
    git(&mirror, &["config", "commit.gpgsign", "false"]);
    let root = commit(&mirror, "root");
    let introduced = commit(&mirror, "regression");
    git(&mirror, &["branch", "maintenance"]);
    let main_affected = commit(&mirror, "main-affected");
    let fixed = commit(&mirror, "fix");
    let fixed_descendant = commit(&mirror, "fixed-descendant");
    git(&mirror, &["checkout", "maintenance"]);
    let branch_affected = commit(&mirror, "branch-affected");
    git(&mirror, &["cherry-pick", &fixed]);
    let cherry = git(&mirror, &["rev-parse", "HEAD"]);
    assert_ne!(fixed, cherry);

    let db = dir.path().join("osv.sqlite");
    let mut snapshot = SnapshotWriter::new(&db).unwrap();
    let fixed_events = json!([{"fixed":cherry},{"introduced":introduced},{"fixed":fixed}]);
    let first = advisory(
        "OSV-fixed",
        json!([
            range(REPO, fixed_events, &["Project-release"]),
            range(OTHER, json!([{"introduced":"0"}]), &["other-only"]),
        ]),
    );
    let limited = advisory(
        "OSV-limit",
        json!([range(
            REPO,
            json!([{"introduced":"0"},{"limit":fixed}]),
            &[]
        ),]),
    );
    let last = advisory(
        "OSV-last",
        json!([range(
            REPO,
            json!([{"introduced":introduced},{"last_affected":branch_affected}]),
            &[]
        ),]),
    );
    let mut withdrawn = advisory(
        "OSV-withdrawn",
        json!([range(
            REPO,
            json!([{"introduced":"0"}]),
            &["Project-release"]
        ),]),
    );
    withdrawn["withdrawn"] = json!("2026-11-12T00:00:00Z");
    for record in [&first, &limited, &last, &withdrawn] {
        snapshot
            .insert(&Advisory::parse(&record.to_string()).unwrap())
            .unwrap();
    }
    snapshot.publish().unwrap();
    let store = Store::open(&db).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = osv_server::router(Store::open(&db).unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = Client::builder()
        .base_url(&url)
        .max_retries(0)
        .build()
        .unwrap();

    let repository = "http://GITHUB.com/owner/%70roject";
    let tagged = client.query_all(&tag(repository, "release")).await.unwrap();
    assert_eq!(
        tagged.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
        ["OSV-fixed"]
    );
    assert!(
        client
            .query_all(&tag(repository, "other-only"))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        client
            .query_all(&Query::for_package("GIT", repository))
            .await
            .unwrap()
            .len(),
        3
    );
    assert!(matches!(
        client.query(&git_commit(&introduced)).await,
        Err(Error::Http {
            status: StatusCode::SERVICE_UNAVAILABLE,
            ..
        })
    ));

    let report = store.index_git(REPO, &mirror).unwrap();
    assert_eq!((report.commits, report.ranges), (7, 3));
    let queries = [
        (&root, vec!["OSV-limit"]),
        (&introduced, vec!["OSV-fixed", "OSV-last", "OSV-limit"]),
        (&main_affected, vec!["OSV-fixed", "OSV-limit"]),
        (&branch_affected, vec!["OSV-fixed", "OSV-last"]),
        (&fixed, vec![]),
        (&fixed_descendant, vec![]),
        (&cherry, vec![]),
    ];
    let mut mixed = queries
        .iter()
        .map(|(sha, _)| git_commit(sha))
        .collect::<Vec<_>>();
    mixed.push(tag(REPO, "release"));
    let batch = client.query_batch_all(&mixed).await.unwrap();
    for ((_, expected), actual) in queries.into_iter().zip(&batch) {
        assert_eq!(
            actual.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
            expected
        );
    }
    assert_eq!(batch.last().unwrap()[0].id, "OSV-fixed");

    assert!(matches!(client.query_batch(&BatchQuery { queries: vec![
        tag(REPO, "release"), Query::for_commit(&introduced)
    ] }).await, Err(Error::Http { status: StatusCode::SERVICE_UNAVAILABLE, rpc_status: Some(rpc), .. })
        if rpc.message.contains("index 1")));

    store.index_git(OTHER, &mirror).unwrap();
    assert_eq!(
        client
            .query_all(&Query::for_commit(introduced.to_uppercase()))
            .await
            .unwrap()
            .len(),
        3
    );
    assert!(matches!(
        client.query(&git_commit(&"a".repeat(40))).await,
        Err(Error::Http {
            status: StatusCode::SERVICE_UNAVAILABLE,
            ..
        })
    ));

    // A stale index becomes unavailable after the data revision changes.
    let mut sync = SyncWriter::open(&db, "https://example.org/modified_id.csv").unwrap();
    let new = "2026-11-13T00:00:00";
    let old = "2026-11-12T00:00:00";
    sync.load_inventory::<osv_store::Error>(
        ["OSV-fixed", "OSV-limit", "OSV-last", "OSV-withdrawn"]
            .into_iter()
            .map(|id| {
                Ok((
                    id.into(),
                    "GIT".into(),
                    if id == "OSV-fixed" { new } else { old }.into(),
                ))
            }),
    )
    .unwrap();
    sync.plan().unwrap();
    let mut bad = first;
    bad["modified"] = json!(format!("{new}Z"));
    bad["affected"][0]["ranges"][0]["events"] = json!([{"introduced": "a".repeat(40)}]);
    sync.stage(&[("OSV-fixed".into(), bad.to_string())])
        .unwrap();
    sync.finish(Some(("digest", &Validators::default())))
        .unwrap();

    assert!(
        store
            .index_git(REPO, &mirror)
            .unwrap_err()
            .to_string()
            .contains("missing from reachable")
    );
    assert!(matches!(
        client.query(&git_commit(&introduced)).await,
        Err(Error::Http {
            status: StatusCode::SERVICE_UNAVAILABLE,
            ..
        })
    ));
    assert_eq!(
        client.query_all(&tag(REPO, "release")).await.unwrap().len(),
        1
    );
    server.abort();
}
