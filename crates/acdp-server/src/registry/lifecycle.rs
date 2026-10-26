//! Lifecycle endpoint request validation (ACDP 0.3, RFC-ACDP-0013 §6
//! step 2) — the envelope layer for `POST /contexts/{ctx_id}/retract`
//! and `POST /contexts/{ctx_id}/republish`.
//!
//! The request body is a CLOSED JSON object with exactly one member,
//! `event`. A request that attempts to supply or alter **body content**
//! through a lifecycle endpoint — a `body` member, or any envelope
//! member named after a body field — MUST be rejected with the
//! **`immutable_field`** wire code (HTTP 400), activated in 0.3.0 from
//! the reservation held since v0.1.0 (RFC-ACDP-0007 §5, RFC-ACDP-0009
//! §2.1): bodies are immutable, and lifecycle endpoints mutate registry
//! state only. The distinct code exists so producers learn the
//! *category* error, not a generic validation failure (fixture
//! `lc-002`). Any other unknown envelope member is a plain
//! `schema_violation` against the closed request shape.

use acdp_primitives::error::AcdpError;
use acdp_types::lifecycle::LifecycleEvent;

/// The wire names of every [`Body`](acdp_types::body::Body) field
/// (RFC-ACDP-0002 §3.1). An envelope member with one of these names is
/// an attempt to modify immutable body content (`immutable_field`); the
/// set matches the struct in `acdp-types/src/body.rs` — extend both
/// together (the registry-assigned and integrity fields are included:
/// none of them is writable through a lifecycle endpoint either).
const BODY_FIELD_NAMES: &[&str] = &[
    "body",
    // Registry-assigned identity fields.
    "ctx_id",
    "lineage_id",
    "origin_registry",
    "created_at",
    // Integrity fields.
    "content_hash",
    "signature",
    // Producer-controlled fields.
    "version",
    "supersedes",
    "agent_id",
    "contributors",
    "title",
    "type",
    "data_refs",
    "derived_from",
    "visibility",
    "audience",
    "acdp_version",
    "description",
    "summary",
    "tags",
    "domain",
    "expires_at",
    "data_period",
    "metadata",
    "schema_uri",
    "anchors",
    // RFC-ACDP-0021 §6.3.
    "key_attestation",
];

/// Validate a raw lifecycle request body against the closed
/// `{"event": {…}}` envelope (RFC-ACDP-0013 §6 step 2) and parse the
/// event through the closed §4 schema.
///
/// Returns the parsed event together with the RAW event JSON — signature
/// verification must hash the event exactly as received
/// (`LifecycleEvent::preimage_hash_of_value`), never a re-serialization.
///
/// Errors:
/// - [`AcdpError::ImmutableField`] — the envelope carries a `body`
///   member or a member named after a body field (fixture `lc-002`
///   scenarios A/B). Checked before the generic closed-shape rejection
///   so the category error wins.
/// - [`AcdpError::SchemaViolation`] — any other unknown envelope
///   member, a missing/non-object `event`, or an event violating the
///   closed §4 schema (including an unsigned producer event's later
///   checks — see the server's endpoint pipeline).
pub fn parse_lifecycle_request(
    raw: &serde_json::Value,
) -> Result<(LifecycleEvent, serde_json::Value), AcdpError> {
    let map = raw.as_object().ok_or_else(|| {
        AcdpError::SchemaViolation("lifecycle request body must be a JSON object".into())
    })?;

    for key in map.keys() {
        if key == "event" {
            continue;
        }
        if BODY_FIELD_NAMES.contains(&key.as_str()) {
            return Err(AcdpError::ImmutableField(format!(
                "lifecycle request member '{key}' attempts to supply or alter immutable \
                 body content — bodies are immutable and lifecycle endpoints mutate \
                 registry state only (RFC-ACDP-0013 §6 step 2)"
            )));
        }
        return Err(AcdpError::SchemaViolation(format!(
            "lifecycle request has unknown member '{key}' — the request body is a closed \
             object with exactly one member, 'event' (RFC-ACDP-0013 §6)"
        )));
    }

    let raw_event = map.get("event").ok_or_else(|| {
        AcdpError::SchemaViolation(
            "lifecycle request is missing the required 'event' member (RFC-ACDP-0013 §6)".into(),
        )
    })?;
    let event = LifecycleEvent::from_value(raw_event)?;
    Ok((event, raw_event.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_event() -> serde_json::Value {
        json!({
            "event_id": "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f",
            "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
            "event_type": "retracted",
            "occurred_at": "2026-07-04T09:15:42.000Z",
            "actor": "did:web:agents.example.com:test-producer",
            "reason": "underlying data source found to be fabricated",
            "signature": {
                "algorithm": "ed25519",
                "key_id": "did:web:agents.example.com:test-producer#key-1",
                "value": "AA=="
            }
        })
    }

    #[test]
    fn valid_envelope_parses() {
        let (event, raw) = parse_lifecycle_request(&json!({ "event": valid_event() })).unwrap();
        assert_eq!(event.event_id, "018f6d0a-7b2e-4c4d-9e1f-3a5b7c9d1e2f");
        assert_eq!(raw, valid_event());
    }

    /// lc-002 scenario A: a `body` member is the category error.
    #[test]
    fn body_member_is_immutable_field() {
        let err = parse_lifecycle_request(&json!({
            "event": valid_event(),
            "body": { "title": "Corrected title" }
        }))
        .unwrap_err();
        assert!(matches!(err, AcdpError::ImmutableField(_)), "got {err:?}");
    }

    /// lc-002 scenario B: a body-field-named member (here `summary`) is
    /// the same category error — NOT a generic schema_violation.
    #[test]
    fn body_field_named_member_is_immutable_field() {
        let err = parse_lifecycle_request(&json!({
            "event": valid_event(),
            "summary": "please update the summary too"
        }))
        .unwrap_err();
        assert!(matches!(err, AcdpError::ImmutableField(_)), "got {err:?}");
    }

    /// `anchors` (RFC-ACDP-0016) is a `Body` field like any other — an
    /// envelope member named `anchors` MUST be `immutable_field`, not a
    /// generic `schema_violation`. Regression test: this field was added
    /// to `Body` (PR #169) without being added to `BODY_FIELD_NAMES`.
    #[test]
    fn anchors_field_named_member_is_immutable_field() {
        let err = parse_lifecycle_request(&json!({
            "event": valid_event(),
            "anchors": [{"scheme": "macp.commitment", "content_hash": "sha256:aa"}]
        }))
        .unwrap_err();
        assert!(matches!(err, AcdpError::ImmutableField(_)), "got {err:?}");
    }

    /// An unknown member NOT naming body content is a plain
    /// schema_violation against the closed envelope (lc-002 note).
    #[test]
    fn non_body_unknown_member_is_schema_violation() {
        let err = parse_lifecycle_request(&json!({
            "event": valid_event(),
            "note": "hello"
        }))
        .unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)), "got {err:?}");
    }

    #[test]
    fn missing_event_member_rejected() {
        let err = parse_lifecycle_request(&json!({})).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
        let err = parse_lifecycle_request(&json!([1, 2])).unwrap_err();
        assert!(matches!(err, AcdpError::SchemaViolation(_)));
    }
}
