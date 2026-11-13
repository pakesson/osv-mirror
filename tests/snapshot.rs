use std::fs;
use std::io::Write;
use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::http::{Response, StatusCode, header};
use axum::routing::get;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use osv_api::Client;
use osv_store::{Lookup, Store};
use osv_sync::{DownloadError, download_zip, import_zip};
use rawzip::{CompressionMethod, ZipArchiveWriter};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const ACTIVE: &str =
    r#"{"id":"OSV-1","modified":"2026-11-12T12:00:00Z","aliases":["CVE-1","ALIAS-ONLY"]}"#;
const WITHDRAWN: &str = r#"{ "id":"OSV-2", "modified":"2026-11-12T12:00:01Z", "withdrawn":"2026-11-12T12:00:01Z", "aliases":["CVE-1"], "future":{"details":42} }"#;
const NONCONFORMING: &str = r#"{"id":"OSV-3 legacy","modified":"2026-11-12T12:00:00Z","references":[{"type":"WEB"}],"affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"1.2"}]}]}]}"#;

fn fixture_zip(entries: &[(&str, &str, CompressionMethod)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut archive = ZipArchiveWriter::new(&mut bytes);
    for &(name, json, method) in entries {
        let (mut entry, config) = archive
            .new_file(name)
            .compression_method(method)
            .start()
            .unwrap();
        let descriptor = if method == CompressionMethod::DEFLATE {
            let encoder = DeflateEncoder::new(&mut entry, Compression::fast());
            let mut writer = config.wrap(encoder);
            writer.write_all(json.as_bytes()).unwrap();
            let (encoder, descriptor) = writer.finish().unwrap();
            encoder.finish().unwrap();
            descriptor
        } else {
            let mut writer = config.wrap(&mut entry);
            writer.write_all(json.as_bytes()).unwrap();
            writer.finish().unwrap().1
        };
        entry.finish(descriptor).unwrap();
    }
    archive.finish().unwrap();
    bytes
}

struct Server {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(router: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { address, task }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn download_import_and_serve_fixture() {
    let zip_bytes = fixture_zip(&[
        ("OSV-1.json", ACTIVE, CompressionMethod::STORE),
        ("OSV-2.json", WITHDRAWN, CompressionMethod::DEFLATE),
        ("OSV-3 legacy.json", NONCONFORMING, CompressionMethod::STORE),
    ]);
    let length = zip_bytes.len() as u64;
    let source =
        Server::start(Router::new().route("/all.zip", get(move || async { zip_bytes }))).await;
    let directory = tempdir().unwrap();
    let zip = directory.path().join("all.zip");
    let database = directory.path().join("osv.sqlite");

    assert_eq!(
        download_zip(&source.url("/all.zip"), &zip).await.unwrap(),
        length
    );
    let database_path = database.clone();
    let report = tokio::task::spawn_blocking(move || import_zip(&zip, &database_path))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.advisories, 3);
    assert_eq!(report.entries, 3);
    assert_eq!(
        report.uncompressed_bytes,
        (ACTIVE.len() + WITHDRAWN.len() + NONCONFORMING.len()) as u64
    );

    let api = Server::start(osv_server::router(Store::open(&database).unwrap())).await;
    let client = Client::builder().base_url(api.url("")).build().unwrap();
    assert_eq!(client.get_vulnerability("OSV-1").await.unwrap().id, "OSV-1");
    assert!(
        client
            .get_vulnerability("OSV-2")
            .await
            .unwrap()
            .withdrawn
            .is_some()
    );

    let raw = reqwest::get(api.url("/v1/vulns/OSV-2")).await.unwrap();
    assert_eq!(raw.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(raw.bytes().await.unwrap().as_ref(), WITHDRAWN.as_bytes());
    let raw = reqwest::get(api.url("/v1/vulns/OSV-3%20legacy"))
        .await
        .unwrap();
    assert_eq!(raw.status(), StatusCode::OK);
    assert_eq!(
        raw.bytes().await.unwrap().as_ref(),
        NONCONFORMING.as_bytes()
    );

    for (id, message) in [
        (
            "ALIAS-ONLY",
            "Vulnerability not found, but the following aliases were: CVE-1 OSV-1 OSV-2",
        ),
        ("MISSING", "Vulnerability not found"),
    ] {
        let error = client.get_vulnerability(id).await.unwrap_err();
        assert!(matches!(
            error,
            osv_api::Error::Http { status: StatusCode::NOT_FOUND, rpc_status: Some(rpc), .. }
            if rpc.code == 5 && rpc.message == message
        ));
    }

    let long_id = client
        .get_vulnerability(&"A".repeat(101))
        .await
        .unwrap_err();
    assert!(matches!(long_id, osv_api::Error::Http {
        status: StatusCode::BAD_REQUEST, rpc_status: Some(rpc), ..
    } if rpc.code == 3 && rpc.message == "ID is too long"));
    let missing = reqwest::get(api.url("/v1/vulns/")).await.unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        missing.json::<osv_api::RpcStatus>().await.unwrap().message,
        "ID is required"
    );
}

#[tokio::test]
async fn failed_downloads_preserve_previous_zip() {
    let existing = fixture_zip(&[("OSV-1.json", ACTIVE, CompressionMethod::STORE)]);
    let corrupt_checksum = existing.clone();
    let source = Server::start(
        Router::new()
            .route("/missing", get(|| async { StatusCode::NOT_FOUND }))
            .route("/partial", get(|| async { StatusCode::PARTIAL_CONTENT }))
            .route("/invalid", get(|| async { "not a zip" }))
            .route(
                "/checksum",
                get(move || async move {
                    Response::builder()
                        .header(
                            "x-goog-hash",
                            "crc32c=ignored, md5=AAAAAAAAAAAAAAAAAAAAAA==",
                        )
                        .body(Body::from(corrupt_checksum))
                        .unwrap()
                }),
            ),
    )
    .await;
    let directory = tempdir().unwrap();
    let zip = directory.path().join("all.zip");
    fs::write(&zip, &existing).unwrap();

    for path in ["/missing", "/partial", "/invalid", "/checksum"] {
        let error = download_zip(&source.url(path), &zip).await.unwrap_err();
        match path {
            "/missing" => assert!(matches!(
                error,
                DownloadError::Status(StatusCode::NOT_FOUND)
            )),
            "/partial" => assert!(matches!(
                error,
                DownloadError::Status(StatusCode::PARTIAL_CONTENT)
            )),
            "/invalid" => assert!(matches!(error, DownloadError::InvalidZip(_))),
            _ => assert!(matches!(error, DownloadError::Checksum)),
        }
        assert_eq!(fs::read(&zip).unwrap(), existing);
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/all.zip", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\ntruncated",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    assert!(download_zip(&url, &zip).await.is_err());
    task.await.unwrap();
    assert_eq!(fs::read(&zip).unwrap(), existing);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn full_rebuild_selects_latest_duplicate_and_protects_the_previous_database() {
    let directory = tempdir().unwrap();
    let zip = directory.path().join("all.zip");
    let database = directory.path().join("osv.sqlite");
    let older =
        r#"{"id":"OSV-1","modified":"2026-11-12T12:00:00.123456789011Z","aliases":["OLD"]}"#;
    let newest =
        r#"{"id":"OSV-1","modified":"2026-11-12T12:00:00.123456789012Z","aliases":["NEW"]}"#;
    let equivalent =
        r#"{ "aliases":["NEW"],"modified":"2026-11-12T12:00:00.1234567890120Z","id":"OSV-1" }"#;
    fs::write(
        &zip,
        fixture_zip(&[
            ("OSV-1.json", older, CompressionMethod::STORE),
            ("OSV-1.json", newest, CompressionMethod::DEFLATE),
            ("OSV-1.json", equivalent, CompressionMethod::STORE),
            ("OSV-1.json", older, CompressionMethod::STORE),
        ]),
    )
    .unwrap();
    let report = import_zip(&zip, &database).unwrap();
    assert_eq!((report.entries, report.advisories), (4, 1));
    let store = Store::open(&database).unwrap();
    assert_eq!(store.lookup("OSV-1").unwrap(), Lookup::Found(newest.into()));
    assert_eq!(store.lookup("OLD").unwrap(), Lookup::Missing);
    assert_eq!(
        store.lookup("NEW").unwrap(),
        Lookup::Aliases(vec!["OSV-1".into()])
    );
    assert!(matches!(
        import_zip(&zip, &database),
        Err(osv_sync::ImportError::Store(osv_store::Error::InUse(_)))
    ));
    drop(store);

    let original = fs::read(&database).unwrap();
    let conflict = older.replace("OLD", "DIFFERENT");
    for (name, json, message) in [
        ("OSV-1.json", conflict.as_str(), "conflicting records"),
        ("subdir/OSV-2.json", WITHDRAWN, "root-level"),
        ("OSV-3.json", WITHDRAWN, "does not match"),
        (
            "OSV-2.json",
            r#"{"id":"OSV-2","modified":null}"#,
            "modified",
        ),
    ] {
        fs::write(
            &zip,
            fixture_zip(&[
                ("OSV-1.json", newest, CompressionMethod::STORE),
                ("OSV-1.json", older, CompressionMethod::STORE),
                (name, json, CompressionMethod::STORE),
            ]),
        )
        .unwrap();
        let error = import_zip(&zip, &database).unwrap_err().to_string();
        assert!(error.contains(message), "{error}");
        assert_eq!(fs::read(&database).unwrap(), original);
    }

    let mut corrupted = fixture_zip(&[("OSV-1.json", ACTIVE, CompressionMethod::STORE)]);
    let position = corrupted
        .windows(ACTIVE.len())
        .position(|bytes| bytes == ACTIVE.as_bytes())
        .unwrap();
    corrupted[position] = b'!';
    fs::write(&zip, corrupted).unwrap();
    assert!(
        import_zip(&zip, &database)
            .unwrap_err()
            .to_string()
            .contains("checksum")
    );
    assert_eq!(fs::read(&database).unwrap(), original);

    fs::write(
        &zip,
        fixture_zip(&[("OSV-2.json", WITHDRAWN, CompressionMethod::STORE)]),
    )
    .unwrap();
    import_zip(&zip, &database).unwrap();
    let store = Store::open(&database).unwrap();
    assert_eq!(store.lookup("OSV-1").unwrap(), Lookup::Missing);
    assert_eq!(
        store.lookup("OSV-2").unwrap(),
        Lookup::Found(WITHDRAWN.into())
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
}
