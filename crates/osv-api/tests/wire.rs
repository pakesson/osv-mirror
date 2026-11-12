use osv_api::experimental::{FileHash, VersionMatch};
use osv_api::{BatchQueryResponse, Query, QueryResponse};
use serde_json::json;

#[test]
fn stable_wire_types_support_purls_and_empty_or_token_only_pages() {
    assert_eq!(
        serde_json::to_value(Query::for_purl("pkg:pypi/jinja2@3.1.4")).unwrap(),
        json!({"package": {"purl": "pkg:pypi/jinja2@3.1.4"}})
    );

    let page: QueryResponse = serde_json::from_value(json!({"next_page_token": "opaque"})).unwrap();
    assert!(page.vulns.is_empty());
    assert_eq!(page.next_page_token.as_deref(), Some("opaque"));
    assert_eq!(
        serde_json::to_value(page).unwrap(),
        json!({"next_page_token": "opaque"})
    );

    let batch: BatchQueryResponse = serde_json::from_value(json!({"results": [{}, {
        "vulns": [{"id": "OSV-1", "modified": "2026-11-12T00:00:00Z"}]
    }]}))
    .unwrap();
    assert!(batch.results[0].vulns.is_empty());
    assert_eq!(batch.results[1].vulns[0].id, "OSV-1");
    assert_eq!(
        serde_json::to_value(batch).unwrap(),
        json!({"results": [{}, {
            "vulns": [{"id": "OSV-1", "modified": "2026-11-12T00:00:00Z"}]
        }]})
    );
}

#[test]
fn experimental_wire_types_handle_protojson_bytes_and_int64s() {
    let hash: FileHash =
        serde_json::from_value(json!({"file_path": "a.c", "hash": "-_8"})).unwrap();
    assert_eq!(hash.hash, [251, 255]);
    assert_eq!(
        serde_json::to_value(hash).unwrap(),
        json!({"file_path": "a.c", "hash": "+/8="})
    );

    let version: VersionMatch = serde_json::from_value(json!({
        "repo_info": {"type": "GIT"},
        "minimum_file_matches": "9223372036854775807",
        "estimated_diff_files": 14
    }))
    .unwrap();
    assert_eq!(version.minimum_file_matches, Some(i64::MAX));
    assert_eq!(version.estimated_diff_files, Some(14));
    assert_eq!(
        serde_json::to_value(version).unwrap(),
        json!({
            "repoInfo": {"type": "GIT"},
            "minimum_file_matches": "9223372036854775807",
            "estimated_diff_files": "14"
        })
    );
    assert!(
        serde_json::from_value::<VersionMatch>(json!({"minimum_file_matches": "bad"})).is_err()
    );
}
