//! Wire-serialization conformance — what the library SERIALIZES.
//!
//! The rest of the suite leans on deserialization; this file pins the
//! emit side, where the absent-vs-null convention (BUG-03) and the
//! closed-schema rules (BUG-06) live. It uses only core types, so it
//! runs under every feature set, including `--no-default-features`.

use acdp::types::body::{Body, DataPeriod, Signature};
use acdp::types::capabilities::Limits;
use acdp::types::publish::{PublishRequest, WireError, WireErrorBody};
use acdp::types::search::{SearchResponse, SearchResult};
use acdp::types::{CtxId, DataRef, LineageId, PublishResponse, Status};
use serde_json::json;

fn match_summary() -> serde_json::Value {
    json!({
        "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
        "lineage_id": "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "agent_id": "did:web:agents.example.com:test",
        "title": "x",
        "type": "data_snapshot",
        "created_at": "2026-01-01T00:00:00.000Z",
        "status": "active"
    })
}

/// BUG-03 — a `SearchResponse` with no optional fields omits them; it
/// never serializes `total_estimate` / `next_cursor` as JSON `null`
/// (`acdp-search-response.schema.json` types both as non-nullable).
#[test]
fn search_response_omits_none_fields() {
    let r = SearchResponse {
        matches: vec![],
        total_estimate: None,
        next_cursor: None,
    };
    let v = serde_json::to_value(&r).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 1, "only `matches` must be present, got {obj:?}");
    assert!(!obj.contains_key("total_estimate"));
    assert!(!obj.contains_key("next_cursor"));
}

/// BUG-03 — a `SearchResult` with no `summary` / `domain` omits them.
#[test]
fn search_result_omits_none_summary_and_domain() {
    let r: SearchResult = serde_json::from_value(match_summary()).unwrap();
    let v = serde_json::to_value(&r).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("summary"),
        "summary: None MUST be omitted"
    );
    assert!(!obj.contains_key("domain"), "domain: None MUST be omitted");
}

/// BUG-03 / schema-005 — a `null` `next_cursor` is rejected: the field
/// is a bare string, so the only conformant "no next page" form is to
/// omit the key.
#[test]
fn search_response_rejects_null_next_cursor() {
    let raw = json!({"matches": [], "next_cursor": null});
    assert!(
        serde_json::from_value::<SearchResponse>(raw).is_err(),
        "schema-005: next_cursor:null MUST be rejected"
    );
}

/// pub-007 — a `PublishResponse` serializes to exactly five
/// registry-assigned keys: no echoed `content_hash` / `signature` / body.
#[test]
fn publish_response_has_exactly_5_keys() {
    let resp = PublishResponse {
        registry_receipt: None,
        ctx_id: CtxId("acdp://registry.example.com/12345678-1234-4321-8123-123456781234".into()),
        lineage_id: LineageId(
            "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
        ),
        version: 1,
        created_at: chrono::Utc::now(),
        status: Status::Active,
    };
    let v = serde_json::to_value(&resp).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["created_at", "ctx_id", "lineage_id", "status", "version"],
        "PublishResponse MUST serialize exactly 5 registry-assigned keys"
    );
}

/// A `WireError` with no `details` omits the key rather than emitting null.
#[test]
fn wire_error_omits_details_when_absent() {
    let e = WireError {
        error: WireErrorBody {
            code: "not_found".into(),
            message: "no such context".into(),
            details: None,
        },
    };
    let v = serde_json::to_value(&e).unwrap();
    assert!(
        !v["error"].as_object().unwrap().contains_key("details"),
        "WireErrorBody.details: None MUST be omitted"
    );
}

/// WIRE-02 — `acdp-error.schema.json` types `details` as `"type": "object"`.
/// An explicit `"details": null` (or any non-object) MUST be rejected.
#[test]
fn wire_error_rejects_null_and_non_object_details() {
    let null_details = r#"{"error":{"code":"not_found","message":"x","details":null}}"#;
    assert!(
        serde_json::from_str::<WireError>(null_details).is_err(),
        "WireErrorBody.details: explicit null MUST be rejected"
    );
    let string_details = r#"{"error":{"code":"not_found","message":"x","details":"oops"}}"#;
    assert!(
        serde_json::from_str::<WireError>(string_details).is_err(),
        "WireErrorBody.details: a non-object value MUST be rejected"
    );
    // A real object is accepted.
    let ok = r#"{"error":{"code":"not_found","message":"x","details":{"key_id":"k"}}}"#;
    assert!(serde_json::from_str::<WireError>(ok).is_ok());
}

/// WIRE-01 — `DataRef` optional fields are typed as bare values in
/// `acdp-data-ref.schema.json`, not nullable. An explicit `null` MUST
/// be rejected on each.
#[test]
fn data_ref_rejects_null_on_bare_typed_optional_fields() {
    for field in [
        r#""description":null"#,
        r#""size_bytes":null"#,
        r#""format":null"#,
        r#""schema_version":null"#,
        r#""content_hash":null"#,
        r#""location":null"#,
        r#""embedded":null"#,
    ] {
        let json = format!(r#"{{"type":"raw_data","location":"https://x.example/d",{field}}}"#);
        assert!(
            serde_json::from_str::<acdp::types::data_ref::DataRef>(&json).is_err(),
            "DataRef MUST reject explicit null: {field}"
        );
    }
}

/// WIRE-03 — `Limits.idempotency_key_ttl_seconds` is a bare integer in
/// the capabilities schema, not nullable.
#[test]
fn limits_rejects_null_idempotency_ttl() {
    let json = r#"{"max_payload_bytes":1048576,"max_embedded_bytes":65536,"idempotency_key_ttl_seconds":null}"#;
    assert!(
        serde_json::from_str::<acdp::types::capabilities::Limits>(json).is_err(),
        "Limits.idempotency_key_ttl_seconds: explicit null MUST be rejected"
    );
}

/// BUG-06 / schema-008 — the closed `signature` object rejects an
/// unknown field.
#[test]
fn signature_rejects_unknown_field() {
    let bad = json!({
        "algorithm": "ed25519",
        "key_id": "did:web:agents.example.com:test#key-1",
        "value": "AAAA",
        "extra": "x"
    });
    assert!(
        serde_json::from_value::<Signature>(bad).is_err(),
        "schema-008: an unknown signature field MUST be rejected"
    );
}

/// BUG-06 / schema-009 — the closed `data_period` object rejects an
/// unknown field.
#[test]
fn data_period_rejects_unknown_field() {
    let bad = json!({
        "start": "2026-01-01T00:00:00.000Z",
        "end": "2026-12-31T23:59:59.000Z",
        "extra": "x"
    });
    assert!(
        serde_json::from_value::<DataPeriod>(bad).is_err(),
        "schema-009: an unknown data_period field MUST be rejected"
    );
}

/// schema-010 — since 0.20.0 the `limits` sub-object is open: an unknown
/// field is tolerated and kept in `extensions`, and survives a round trip.
#[test]
fn limits_tolerates_and_keeps_unknown_field() {
    let doc = json!({
        "max_payload_bytes": 1_048_576u64,
        "max_embedded_bytes": 65_536u64,
        "extra": "x"
    });
    let limits: Limits = serde_json::from_value(doc.clone())
        .expect("schema-010: an unknown limits field MUST be tolerated");
    assert_eq!(limits.extensions.get("extra"), Some(&json!("x")));
    assert_eq!(serde_json::to_value(&limits).unwrap(), doc);
}

/// Opening `limits` does not loosen its known fields: a wrong type or an
/// explicit `null` on a known key is still rejected.
#[test]
fn limits_known_fields_stay_typed() {
    for bad in [
        json!({"max_payload_bytes": "big", "max_embedded_bytes": 65_536u64}),
        json!({"max_payload_bytes": 1_048_576u64, "max_embedded_bytes": 65_536u64,
               "max_reads_per_minute": null}),
        json!({"max_payload_bytes": 1_048_576u64, "max_embedded_bytes": 65_536u64,
               "max_reads_per_minute": 1.5}),
    ] {
        assert!(
            serde_json::from_value::<Limits>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}

// ── Absent-vs-null on Body / PublishRequest bare-typed Option fields ────────

/// The bare-typed optional producer fields (`description`, `summary`,
/// `tags`, `domain`, `schema_uri`, `acdp_version`) follow the absent-vs-
/// null convention (RFC-ACDP-0005 §2.2.1): a `null` wire value is
/// schema-invalid for any field typed as a bare value, so a strict
/// consumer MUST reject `null` rather than coerce it to absent.
///
/// `supersedes` is the one v0.1.0 producer field declared `["string",
/// "null"]` (RFC-ACDP-0002 §3.1), so a `null` IS conformant for it —
/// the test fixture below uses it to express "first version".
fn minimal_publish_request_with_extra(extra: &str) -> String {
    format!(
        r#"{{
            "version": 1,
            "supersedes": null,
            "agent_id": "did:web:agents.example.com:test",
            "contributors": [],
            "title": "t",
            "type": "data_snapshot",
            "data_refs": [],
            "derived_from": [],
            "visibility": "public",
            "content_hash": "sha256:0",
            "signature": {{
              "algorithm": "ed25519",
              "key_id": "did:web:agents.example.com:test#key-1",
              "value": "{sig}"
            }}{extra}
          }}"#,
        sig = "A".repeat(88),
        extra = extra
    )
}

fn minimal_body_with_extra(extra: &str) -> String {
    format!(
        r#"{{
            "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
            "lineage_id": "lin:sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "origin_registry": "registry.example.com",
            "created_at": "2026-05-18T00:00:00.000Z",
            "content_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "signature": {{
              "algorithm": "ed25519",
              "key_id": "did:web:agents.example.com:test#key-1",
              "value": "{sig}"
            }},
            "version": 1,
            "supersedes": null,
            "agent_id": "did:web:agents.example.com:test",
            "contributors": [],
            "title": "t",
            "type": "data_snapshot",
            "data_refs": [],
            "derived_from": [],
            "visibility": "public"{extra}
          }}"#,
        sig = "A".repeat(88),
        extra = extra
    )
}

const NULLABLE_BARE_FIELDS: &[&str] = &[
    "description",
    "summary",
    "domain",
    "schema_uri",
    "acdp_version",
    "tags",
];

#[test]
fn publish_request_rejects_null_on_bare_typed_optional_fields() {
    for field in NULLABLE_BARE_FIELDS {
        let body = minimal_publish_request_with_extra(&format!(r#", "{field}": null"#));
        let res: Result<PublishRequest, _> = serde_json::from_str(&body);
        assert!(
            res.is_err(),
            "PublishRequest MUST reject `{field}: null`, got {res:?}"
        );
    }
}

#[test]
fn publish_request_baseline_no_extras_parses() {
    let body = minimal_publish_request_with_extra("");
    serde_json::from_str::<PublishRequest>(&body)
        .expect("baseline PublishRequest must still deserialize without optional fields");
}

#[test]
fn publish_request_supersedes_null_still_accepted() {
    // RFC-ACDP-0002 §3.1 — `supersedes` is the one v0.1.0 producer
    // field declared `["string","null"]`. `null` MUST stay legal.
    let body = minimal_publish_request_with_extra("");
    let req: PublishRequest = serde_json::from_str(&body).unwrap();
    assert!(req.supersedes.is_none());
}

#[test]
fn body_rejects_null_on_bare_typed_optional_fields() {
    for field in NULLABLE_BARE_FIELDS {
        let body = minimal_body_with_extra(&format!(r#", "{field}": null"#));
        let res: Result<Body, _> = serde_json::from_str(&body);
        assert!(
            res.is_err(),
            "Body MUST reject `{field}: null`, got {res:?}"
        );
    }
}

#[test]
fn body_baseline_no_extras_parses() {
    let body = minimal_body_with_extra("");
    serde_json::from_str::<Body>(&body)
        .expect("baseline Body must still deserialize without optional fields");
}

/// BUG-05 / can-010 — `DataRef` is open at its schema root; an unknown
/// producer-controlled field survives the deserialize → serialize
/// round-trip so `content_hash` recomputation stays stable.
#[test]
fn data_ref_preserves_unknown_field() {
    let dr: DataRef = serde_json::from_value(json!({
        "type": "raw_data",
        "location": "https://data.example.com/x.csv",
        "future_producer_field": "keep me"
    }))
    .unwrap();
    let back = serde_json::to_value(&dr).unwrap();
    assert_eq!(
        back["future_producer_field"], "keep me",
        "BUG-05: an unknown DataRef field MUST survive the round-trip"
    );
}
