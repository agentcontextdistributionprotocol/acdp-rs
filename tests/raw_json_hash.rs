//! RFC-ACDP-0001 §5.7 "Hash verification over raw JSON" (REQUIRED) —
//! `can-013`, acdp-rs#385.
//!
//! A conformant producer may spell a timestamp any RFC 3339 way on the
//! wire (§5.3 makes `.mmmZ` the emission form, but consumers MUST
//! accept any date-time on input). The signature binds the bytes the
//! producer hashed, so the consumer must recompute `content_hash` over
//! the body *as received*, not over a typed re-serialization that
//! normalizes the spelling.

use acdp::crypto::{compute_content_hash, SigningKey};
use acdp::error::AcdpError;
use acdp::producer::Producer;
use acdp::types::{Body, ContentHash, ContextType, CtxId, DataPeriod, FullContext, LineageId};
use acdp::verify::{
    verify_body_offline, verify_body_value_offline, verify_context_hash, verify_typed_body_hash,
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

const SEED: [u8; 32] = [7u8; 32];

fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

/// A signed did:key data-snapshot body as typed JSON.
fn base_body_value() -> Value {
    let producer = Producer::new_did_key(SigningKey::from_bytes(&SEED));
    let req = producer
        .publish_request()
        .acdp_version("0.4.0")
        .title("BTC Price Snapshot")
        .context_type(ContextType::DataSnapshot)
        .expires_at(at("2026-12-31T23:59:59Z"))
        .data_period(DataPeriod {
            start: at("2026-01-01T00:00:00Z"),
            end: at("2026-12-31T23:59:59Z"),
        })
        .build()
        .unwrap();
    let body = Body::from_publish_request(
        &req,
        CtxId("acdp://registry.example.com/9f1e2d3c-5a6b-4c7d-8e9f-0a1b2c3d4e5f".into()),
        LineageId(
            "lin:sha256:6af6229c1c6a4a119695c77e47f6554941aebce3d25ba8567e2ae6ffbb6059cb".into(),
        ),
        "registry.example.com",
        at("2026-05-02T08:00:00.000Z"),
    );
    serde_json::to_value(&body).unwrap()
}

/// Re-hash and re-sign `body` over its raw JSON, exactly as a
/// third-party producer that never round-trips through chrono would.
fn resign_raw(mut body: Value) -> Value {
    body["content_hash"] = json!("sha256:00");
    let hash = compute_content_hash(&body).unwrap();
    let sig = SigningKey::from_bytes(&SEED).sign_content_hash(&hash);
    body["content_hash"] = json!(hash.as_str());
    body["signature"]["value"] = json!(sig);
    body
}

fn respelled(expires_at: &str, start: &str, end: &str) -> Value {
    let mut v = base_body_value();
    v["expires_at"] = json!(expires_at);
    v["data_period"] = json!({ "start": start, "end": end });
    resign_raw(v)
}

fn full_context(body: &Value) -> FullContext {
    serde_json::from_value(json!({
        "body": body,
        "registry_state": { "status": "active" },
    }))
    .unwrap()
}

/// can-013: the canonical whole-second `.000Z` spelling verifies — on
/// the raw path, the offline path, and (since 0.15.0 emits `.000Z`)
/// the typed path too.
#[test]
fn can_013_whole_second_millis_spelling_verifies() {
    let body = respelled(
        "2026-12-31T23:59:59.000Z",
        "2026-01-01T00:00:00.000Z",
        "2026-12-31T23:59:59.000Z",
    );
    let ctx = full_context(&body);
    assert_eq!(ctx.raw_body.as_ref(), Some(&body));
    verify_context_hash(&ctx).expect("raw path");
    verify_typed_body_hash(&ctx.body).expect("typed path");
    verify_body_value_offline(&body).expect("offline raw path");
    verify_body_offline(&ctx.body).expect("offline typed path");
}

/// Any other valid RFC 3339 spelling (`+00:00` offset, a two-digit
/// fraction) is only reproducible from the raw bytes.
#[test]
fn non_canonical_rfc3339_spelling_verifies_only_over_raw_json() {
    let body = respelled(
        "2026-12-31T23:59:59+00:00",
        "2026-01-01T00:00:00.50Z",
        "2026-12-31T23:59:59.000+00:00",
    );
    let ctx = full_context(&body);
    verify_context_hash(&ctx).expect("raw path must reproduce the producer's bytes");
    verify_body_value_offline(&body).expect("offline raw path");

    // The typed re-serialization respells the instants → it cannot.
    assert!(matches!(
        verify_typed_body_hash(&ctx.body),
        Err(AcdpError::HashMismatch { .. })
    ));
    let mut no_raw = ctx.clone();
    no_raw.raw_body = None;
    assert!(matches!(
        verify_context_hash(&no_raw),
        Err(AcdpError::HashMismatch { .. })
    ));
}

/// Bodies from acdp-rs ≤ 0.14.5 producers hashed whole seconds without
/// the fraction (`…:59Z`). They keep verifying on every path.
#[test]
fn legacy_whole_second_spelling_still_verifies() {
    let body = respelled(
        "2026-12-31T23:59:59Z",
        "2026-01-01T00:00:00Z",
        "2026-12-31T23:59:59Z",
    );
    let ctx = full_context(&body);
    verify_context_hash(&ctx).expect("raw path");
    verify_typed_body_hash(&ctx.body).expect("typed legacy fallback");
    verify_body_offline(&ctx.body).expect("offline typed legacy fallback");
    verify_body_value_offline(&body).expect("offline raw path");
}

/// Mutating the typed body after parse is NOT masked by the untouched
/// raw bytes: the raw path is only used while it describes the body.
#[test]
fn mutation_after_parse_is_detected() {
    let body = respelled(
        "2026-12-31T23:59:59+00:00",
        "2026-01-01T00:00:00.000Z",
        "2026-12-31T23:59:59.000Z",
    );
    let mut ctx = full_context(&body);
    ctx.body.title = "Tampered".into();
    assert!(matches!(
        verify_context_hash(&ctx),
        Err(AcdpError::HashMismatch { .. })
    ));
}

/// Tampering the raw bytes themselves fails the raw path.
#[test]
fn tampered_raw_body_fails() {
    let mut body = respelled(
        "2026-12-31T23:59:59.000Z",
        "2026-01-01T00:00:00.000Z",
        "2026-12-31T23:59:59.000Z",
    );
    body["expires_at"] = json!("2027-12-31T23:59:59.000Z");
    let ctx = full_context(&body);
    assert!(matches!(
        verify_context_hash(&ctx),
        Err(AcdpError::HashMismatch { .. })
    ));
    assert!(verify_body_value_offline(&body).is_err());
}

/// Producers emit the §5.3 canonical `.mmmZ` form, including for whole
/// seconds, and the hash they sign is over that spelling.
#[test]
fn producer_emits_canonical_millis_for_whole_seconds() {
    let v = base_body_value();
    assert_eq!(v["expires_at"], "2026-12-31T23:59:59.000Z");
    assert_eq!(v["data_period"]["start"], "2026-01-01T00:00:00.000Z");
    assert_eq!(v["data_period"]["end"], "2026-12-31T23:59:59.000Z");
    let hash = compute_content_hash(&v).unwrap();
    assert_eq!(v["content_hash"], json!(hash.as_str()));
    let _: ContentHash = hash;
    verify_body_value_offline(&v).expect("producer output verifies over raw JSON");
}
