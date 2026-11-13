use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use osv_store::{Advisory, Lookup, Reconciliation, SnapshotWriter, Store, SyncWriter};
use osv_sync::{SyncError, sync};
use tempfile::tempdir;
use tokio::net::TcpListener;

const OLD: &str = "2026-10-01T00:00:00Z";
const TIED: &str = "2026-11-01T00:00:00.123456789012Z";
const NEXT: &str = "2026-11-01T00:00:00.123456789013Z";

fn body(id: &str, modified: &str, extra: &str) -> String {
    format!(r#"{{"id":"{id}","modified":"{modified}"{extra}}}"#)
}

#[derive(Default)]
struct Export {
    csv: String,
    version: u64,
    generation: Option<u64>,
    bodies: HashMap<String, String>,
    requested: Vec<String>,
    conditionals: Vec<Option<String>>,
    refresh: Option<(String, u64)>,
    transient: Option<String>,
}

#[tokio::test]
async fn reconciles_live_snapshots_and_rolls_back_failed_updates() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("osv.sqlite");
    let mut snapshot = SnapshotWriter::new(&database).unwrap();
    for (id, extra) in [
        ("OSV-tie", ""),
        ("OSV-moved", r#","aliases":["OLD-ALIAS"]"#),
        ("OSV-removed", r#","aliases":["REMOVE-ALIAS"]"#),
        ("OSV-retained", ""),
    ] {
        snapshot
            .insert(&Advisory::parse(&body(id, TIED, extra)).unwrap())
            .unwrap();
    }
    snapshot.publish().unwrap();
    let store = Store::open(&database).unwrap();

    let export = Arc::new(Mutex::new(Export::default()));
    let router = Router::new().fallback({
        let export = Arc::clone(&export);
        move |request: Request<Body>| {
            let export = Arc::clone(&export);
            async move {
                let mut export = export.lock().unwrap();
                let path = request.uri().path();
                if path == "/mirror/modified_id.csv" {
                    let conditional = request
                        .headers()
                        .get(header::IF_NONE_MATCH)
                        .map(|value| value.to_str().unwrap().to_owned());
                    export.conditionals.push(conditional.clone());
                    if request.headers().contains_key(header::CACHE_CONTROL)
                        && export
                            .requested
                            .iter()
                            .filter(|path| path.ends_with("/OSV-failing.json"))
                            .count()
                            >= 6
                        && let Some((csv, version)) = export.refresh.take()
                    {
                        export.csv = csv;
                        export.version = version;
                    }
                    let tag = format!("\"{}\"", export.version);
                    let response = Response::builder().header(header::ETAG, &tag).header(
                        "x-goog-generation",
                        export.generation.unwrap_or(export.version),
                    );
                    if conditional.as_deref() == Some(tag.as_str()) {
                        return response
                            .status(StatusCode::NOT_MODIFIED)
                            .body(Body::empty())
                            .unwrap();
                    }
                    return response.body(Body::from(export.csv.clone())).unwrap();
                }
                export.requested.push(path.into());
                if export.transient.as_deref() == Some(path) {
                    export.transient = None;
                    return Response::builder().status(404).body(Body::empty()).unwrap();
                }
                match export.bodies.get(path) {
                    Some(body) => Response::new(Body::from(body.clone())),
                    None => Response::builder().status(404).body(Body::empty()).unwrap(),
                }
            }
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/mirror/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let moved = body(
        "OSV-moved",
        NEXT,
        r#","withdrawn":"2026-11-02T00:00:00Z","aliases":["NEW-ALIAS"]"#,
    );
    let late = body("OSV-late", OLD, "");
    let initial = format!(
        "{NEXT},A old/OSV-moved\n{NEXT},[EMPTY]/OSV-moved\n{TIED},Go/OSV-tie\n{TIED},Go/OSV-removed\n{TIED},Go/OSV-retained\n{OLD},Go/OSV-late\n"
    );
    {
        let mut export = export.lock().unwrap();
        export.csv = initial.clone();
        export.version = 1;
        export
            .bodies
            .insert("/mirror/[EMPTY]/OSV-moved.json".into(), moved.clone());
        export
            .bodies
            .insert("/mirror/Go/OSV-late.json".into(), late.clone());
        export.transient = Some("/mirror/Go/OSV-late.json".into());
    }
    let report = sync(&database, &base).await.unwrap();
    assert_eq!((report.updated, report.removed, report.revision), (2, 0, 1));
    assert_eq!(store.lookup("OSV-late").unwrap(), Lookup::Found(late));
    assert_eq!(store.lookup("OSV-moved").unwrap(), Lookup::Found(moved));
    assert_eq!(store.lookup("OLD-ALIAS").unwrap(), Lookup::Missing);
    assert_eq!(
        store.lookup("NEW-ALIAS").unwrap(),
        Lookup::Aliases(vec!["OSV-moved".into()])
    );
    {
        let export = export.lock().unwrap();
        assert_eq!(export.requested.len(), 4, "{:?}", export.requested);
        assert!(export.requested.iter().any(|path| path.contains("A%20old")));
    }
    let replay = sync(&database, &base).await.unwrap();
    assert_eq!(replay.reconciliation, Reconciliation::Unchanged);
    assert_eq!(replay.revision, 1);

    let missing = initial.replace(&format!("{TIED},Go/OSV-removed\n"), "");
    {
        let mut export = export.lock().unwrap();
        export.csv = missing.clone();
        export.version = 2;
    }
    let report = sync(&database, &base).await.unwrap();
    assert_eq!((report.removed, report.pending_absences), (0, 1));
    {
        let mut export = export.lock().unwrap();
        export.version = 3; // Different ETag, same generation and inventory.
        export.generation = Some(2);
    }
    let report = sync(&database, &base).await.unwrap();
    assert_eq!((report.removed, report.pending_absences), (0, 1));
    assert_eq!(report.reconciliation, Reconciliation::Unchanged);

    {
        let mut export = export.lock().unwrap();
        export.csv = format!("{TIED},Go/OSV-tie\n");
        export.version = 4;
        export.generation = None;
    }
    let report = sync(&database, &base).await.unwrap();
    assert!(matches!(
        report.reconciliation,
        Reconciliation::Incomplete { .. }
    ));
    assert_eq!((report.removed, report.pending_absences), (0, 0));
    assert!(matches!(
        store.lookup("OSV-removed").unwrap(),
        Lookup::Found(_)
    ));

    let reappearance = initial.replace("Go/OSV-removed", "Other/OSV-removed");
    {
        let mut export = export.lock().unwrap();
        export.csv = missing.clone();
        export.version = 5;
    }
    assert_eq!(sync(&database, &base).await.unwrap().pending_absences, 1);
    {
        let mut export = export.lock().unwrap();
        export.csv = reappearance;
        export.version = 6;
    }
    assert_eq!(sync(&database, &base).await.unwrap().pending_absences, 0);

    {
        let mut export = export.lock().unwrap();
        export.csv = missing.clone();
        export.version = 7;
    }
    assert_eq!(sync(&database, &base).await.unwrap().pending_absences, 1);

    let candidate = format!("{missing}{NEXT},Go/OSV-failing\n");
    {
        let mut export = export.lock().unwrap();
        export.csv = candidate.clone();
        export.version = 8;
        export.bodies.insert(
            "/mirror/Go/OSV-failing.json".into(),
            body("OSV-failing", OLD, ""),
        );
    }
    assert!(matches!(
        sync(&database, &base).await,
        Err(SyncError::Advisory { .. })
    ));
    assert!(matches!(
        store.lookup("OSV-removed").unwrap(),
        Lookup::Found(_)
    ));
    assert_eq!(store.lookup("OSV-failing").unwrap(), Lookup::Missing);
    let feed = format!("{base}modified_id.csv");
    let writer = SyncWriter::open(&database, &feed).unwrap();
    assert_eq!(writer.state().validators.etag.as_deref(), Some("\"7\""));
    assert_eq!(writer.state().revision, 1);
    assert!(matches!(
        SyncWriter::open(&database, &feed),
        Err(osv_store::Error::InUse(_))
    ));
    drop(writer);

    {
        let mut export = export.lock().unwrap();
        export.refresh = Some((candidate.replace("Go/OSV-failing", "New%/OSV-failing"), 9));
        export.bodies.insert(
            "/mirror/New%25/OSV-failing.json".into(),
            body("OSV-failing", "2026-11-02T00:00:00Z", ""),
        );
    }
    let report = sync(&database, &base).await.unwrap();
    assert_eq!(
        (
            report.updated,
            report.removed,
            report.pending_absences,
            report.revision
        ),
        (1, 1, 0, 2)
    );
    assert_eq!(store.lookup("OSV-removed").unwrap(), Lookup::Missing);
    assert_eq!(store.lookup("REMOVE-ALIAS").unwrap(), Lookup::Missing);
    assert!(matches!(
        store.lookup("OSV-failing").unwrap(),
        Lookup::Found(_)
    ));
    assert_eq!(sync(&database, &base).await.unwrap().revision, 2);
    {
        let mut export = export.lock().unwrap();
        assert_eq!(
            export.conditionals.last().unwrap().as_deref(),
            Some("\"9\"")
        );
        export.version = 8;
    }
    assert!(matches!(
        sync(&database, &base).await,
        Err(SyncError::Store(osv_store::Error::StaleInventory))
    ));
    {
        let mut export = export.lock().unwrap();
        export.version = 10;
        export.csv = format!("{TIED},Go/OSV-tie");
    }
    assert!(matches!(
        sync(&database, &base).await,
        Err(SyncError::InvalidInventory(_))
    ));

    // An identical CSV published as a new GCS generation can confirm a
    // removal even when the content-based ETag remains the same.
    {
        let mut export = export.lock().unwrap();
        export.csv = format!(
            "{TIED},Go/OSV-tie\n{NEXT},[EMPTY]/OSV-moved\n{OLD},Go/OSV-late\n{NEXT},New%/OSV-failing\n"
        );
    }
    assert_eq!(sync(&database, &base).await.unwrap().pending_absences, 1);
    assert_eq!(sync(&database, &base).await.unwrap().pending_absences, 1);
    export.lock().unwrap().generation = Some(11);
    let report = sync(&database, &base).await.unwrap();
    assert_eq!(
        (report.removed, report.pending_absences, report.revision),
        (1, 0, 3)
    );
    assert_eq!(store.lookup("OSV-retained").unwrap(), Lookup::Missing);
    server.abort();
}
