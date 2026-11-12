use osv_schema::{DEFAULT_SCHEMA_VERSION, Nullable, SCHEMA_VERSION, from_json, validate_json};
use serde_json::{Value, json};

const FULL: &str = include_str!("fixtures/full.json");

fn document() -> Value {
    json!({"id": "OSV-2020-1", "modified": "2020-05-05T11:12:13.123Z"})
}

#[test]
fn latest_schema_fixture_round_trips() {
    let record = from_json(FULL).unwrap();
    let expected: Value = serde_json::from_str(FULL).unwrap();

    assert_eq!(record.effective_schema_version(), SCHEMA_VERSION);
    assert_eq!(record.modified, "2026-11-12T13:14:15.123456789012Z");
    assert_eq!(
        record.severity.as_ref().unwrap().as_value().unwrap()[0]
            .source
            .as_deref(),
        Some("NVD")
    );
    let affected = record.affected_entries();
    let ranges = affected[0].ranges.as_ref().unwrap();
    assert_eq!(
        ranges[0].database_specific.as_ref().unwrap()["note"]["reviewed"],
        true
    );
    assert!(affected[2].package.is_none());

    assert_eq!(serde_json::to_value(&record).unwrap(), expected);
    assert_eq!(
        serde_json::from_value::<osv_schema::Vulnerability>(expected.clone()).unwrap(),
        record
    );
    validate_json(&expected).unwrap();
}

#[test]
fn omitted_version_and_nullable_lists_round_trip() {
    let legacy = document();
    let record = from_json(&legacy.to_string()).unwrap();
    assert_eq!(record.schema_version, None);
    assert_eq!(record.effective_schema_version(), DEFAULT_SCHEMA_VERSION);
    assert_eq!(record.affected, None);
    assert_eq!(serde_json::to_value(&record).unwrap(), legacy);
    validate_json(&legacy).unwrap();

    let mut nullable = legacy;
    for field in ["aliases", "affected", "references", "severity"] {
        nullable[field] = Value::Null;
    }
    let record = from_json(&nullable.to_string()).unwrap();
    assert_eq!(record.affected, Some(Nullable::Null));
    assert!(record.affected_entries().is_empty());
    assert_eq!(serde_json::to_value(&record).unwrap(), nullable);
    validate_json(&nullable).unwrap();

    nullable["affected"] = json!([{"severity": null}]);
    let record = from_json(&nullable.to_string()).unwrap();
    assert_eq!(serde_json::to_value(&record).unwrap(), nullable);
    validate_json(&nullable).unwrap();
}

#[test]
fn tolerant_reader_preserves_additive_fields_at_each_level() {
    let mut future: Value = serde_json::from_str(FULL).unwrap();
    future["schema_version"] = json!("1.99.0");
    future["future"] = serde_json::from_str("18446744073709551616.123456789").unwrap();
    future["severity"][0]["source"] = json!("NEW_SOURCE");
    future["severity"][0]["new_score"] = json!([null, {"scale": "future"}]);
    future["affected"][0]["extra_affected"] = json!(true);
    future["affected"][0]["package"]["ecosystem"] = json!("Future:Release");
    future["affected"][0]["package"]["namespace"] = json!("namespace");
    future["affected"][0]["ranges"][0]["new_range_field"] = json!(null);
    future["affected"][0]["ranges"][0]["events"][0]["event_data"] = json!({"status": "new"});
    future["affected"][0]["ranges"][1]["type"] = json!("NEW_RANGE_TYPE");
    future["affected"][0]["ranges"][1]["events"] = json!([{"new_event": {"version": 2}}]);
    future["references"][0]["type"] = json!("NEW_REFERENCE_TYPE");
    future["references"][0]["reference_data"] = json!(23);
    future["credits"][0]["type"] = json!("NEW_CREDIT_TYPE");
    future["credits"][0]["credit_data"] = json!("new credit field");

    let record = from_json(&future.to_string()).unwrap();
    record.validate_for_ingestion().unwrap();
    assert_eq!(serde_json::to_value(&record).unwrap(), future);
    assert!(validate_json(&future).is_err());
}

#[test]
fn malformed_index_fields_report_their_paths() {
    for (field, value) in [
        ("id", "OSV-2020/path"),
        ("schema_version", "2.0.0"),
        ("schema_version", "v1.9.2"),
        ("modified", "2026-02-30T12:00:00Z"),
        ("withdrawn", "2026-11-12T13:00:00+01:00"),
    ] {
        let mut invalid = document();
        invalid[field] = json!(value);
        let record = from_json(&invalid.to_string()).unwrap();
        let error = record.validate_for_ingestion().unwrap_err();
        assert_eq!(error.path, format!("/{field}"));
        assert!(validate_json(&invalid).is_err());
    }

    let malformed_package = json!({
        "id": "OSV-2020-1",
        "modified": "2020-05-05T11:12:13Z",
        "affected": [{"package": {"name": "example", "ecosystem": 23}}]
    });
    let error = from_json(&malformed_package.to_string()).unwrap_err();
    assert_eq!(error.path, "affected[0].package.ecosystem");

    let mut malformed_event = document();
    malformed_event["affected"] = json!([{
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": null}]}]
    }]);
    let error = from_json(&malformed_event.to_string()).unwrap_err();
    assert_eq!(error.path, "affected[0].ranges[0].events[0].fixed");

    let error = from_json(&format!("{} {{}}", document())).unwrap_err();
    assert!(error.message.contains("trailing characters"));
}

#[test]
fn validates_range_boundaries_and_combinations() {
    for (events, error_path) in [
        (json!([{"fixed": "1.0.0"}]), "/events"),
        (json!([{"introduced": "0", "fixed": "1.0.0"}]), "/events/0"),
        (
            json!([{"introduced": "0"}, {"fixed": "1.0.0"}, {"last_affected": "0.9.0"}]),
            "/events",
        ),
        (
            json!([{"introduced": "0"}, {"fixed": "v1.0.0"}]),
            "/events/1/fixed",
        ),
        (
            json!([{"introduced": "0"}, {"limit": "0"}]),
            "/events/1/limit",
        ),
    ] {
        let mut invalid = document();
        invalid["affected"] = json!([{"ranges": [{"type": "SEMVER", "events": events}]}]);
        let record = from_json(&invalid.to_string()).unwrap();
        let error = record.validate_for_ingestion().unwrap_err();
        assert_eq!(error.path, format!("/affected/0/ranges/0{error_path}"));
        assert!(validate_json(&invalid).is_err());
    }
}

#[test]
fn strict_validation_applies_schema_and_prose() {
    let mut invalid = document();
    invalid["references"] = json!([{"type": "WEB", "url": "relative/path"}]);
    assert_eq!(
        validate_json(&invalid).unwrap_err().path,
        "/references/0/url"
    );

    let mut invalid = document();
    invalid["affected"] = json!([{"package": {
        "ecosystem": "crates.io",
        "name": "example",
        "purl": "pkg:cargo/example@1.0.0"
    }}]);
    let error = validate_json(&invalid).unwrap_err();
    assert_eq!(error.path, "/affected/0/package/purl");
    assert!(error.message.contains("omit its version"));

    let mut invalid = document();
    invalid["id"] = json!("OSV-2020-1?");
    assert_eq!(validate_json(&invalid).unwrap_err().path, "/id");
}

#[test]
fn ingestion_accepts_the_documented_git_limit_sentinel() {
    let mut advisory = document();
    advisory["affected"] = json!([{"ranges": [{
        "type": "GIT",
        "repo": "https://example.com/repo.git",
        "events": [{"introduced": "0"}, {"limit": "*"}]
    }]}]);
    let record = from_json(&advisory.to_string()).unwrap();
    record.validate_for_ingestion().unwrap();

    // The upstream JSON Schema restricts explicit GIT limits to hash strings or 0.
    assert_eq!(
        validate_json(&advisory).unwrap_err().path,
        "/affected/0/ranges/0/events/1"
    );
}
