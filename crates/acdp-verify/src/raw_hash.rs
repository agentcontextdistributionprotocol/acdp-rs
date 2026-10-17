//! `content_hash` recomputation over the bytes the producer signed —
//! RFC-ACDP-0001 §5.7 "Hash verification over raw JSON" (REQUIRED).
//!
//! Two paths:
//!
//! - **Raw** ([`verify_context_hash`], [`verify_raw_body_hash`]): the
//!   `body` object exactly as received (kept on
//!   [`FullContext::raw_body`]) is hashed. This is the normative path
//!   and reproduces any valid producer spelling, e.g. the canonical
//!   whole-second `…:59.000Z` that a typed `chrono` round-trip used to
//!   respell (`can-013`, acdp-rs#385).
//! - **Typed** ([`verify_typed_body_hash`], [`verify_typed_content_hash`]):
//!   for callers that hold only a typed [`Body`] / [`PublishRequest`].
//!   The canonical rendering (§5.3) is tried first; on mismatch, the
//!   pre-0.15.0 acdp-rs rendering of the same instants (whole-second
//!   producer timestamps without the `.000` fraction) is tried once, so
//!   bodies published by older acdp-rs producers keep verifying. Both
//!   renderings describe the identical typed content, so accepting
//!   either does not widen what the signature binds.
//!
//! The raw path is used only while the raw value still *describes* the
//! typed body (re-parsing it yields the same typed content). A caller
//! that mutates `ctx.body` after deserialization therefore falls back
//! to the typed path and gets the `HashMismatch` the mutation deserves,
//! instead of having it masked by the untouched raw bytes.

use acdp_crypto::verify_content_hash;
use acdp_primitives::error::AcdpError;
use acdp_types::body::{Body, FullContext};
use acdp_types::primitives::ContentHash;
use acdp_types::publish::PublishRequest;
use serde_json::Value;

/// Producer-controlled timestamp paths inside ProducerContent, as
/// `(top-level key, optional nested key)`.
const PRODUCER_TIMESTAMP_PATHS: &[(&str, Option<&str>)] = &[
    ("expires_at", None),
    ("data_period", Some("start")),
    ("data_period", Some("end")),
];

/// Recompute `content_hash` for a retrieved context, hashing the raw
/// received body when available (RFC-ACDP-0001 §5.7).
pub fn verify_context_hash(ctx: &FullContext) -> Result<(), AcdpError> {
    match &ctx.raw_body {
        Some(raw) => verify_raw_body_hash(raw, &ctx.body),
        None => verify_typed_body_hash(&ctx.body),
    }
}

/// Recompute `content_hash` over `raw` (the body object as received)
/// when it describes `body`; otherwise fall back to
/// [`verify_typed_body_hash`].
pub fn verify_raw_body_hash(raw: &Value, body: &Body) -> Result<(), AcdpError> {
    if raw_describes_body(raw, body) {
        verify_content_hash(raw, &body.content_hash)
    } else {
        verify_typed_body_hash(body)
    }
}

/// `true` when re-parsing `raw` yields exactly the typed `body`
/// (compared through the canonical typed serialization).
pub fn raw_describes_body(raw: &Value, body: &Body) -> bool {
    let Ok(reparsed) = serde_json::from_value::<Body>(raw.clone()) else {
        return false;
    };
    match (serde_json::to_value(&reparsed), serde_json::to_value(body)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Typed-path `content_hash` check for a [`Body`] (no raw JSON held).
pub fn verify_typed_body_hash(body: &Body) -> Result<(), AcdpError> {
    verify_typed_content_hash(&serde_json::to_value(body)?, &body.content_hash)
}

/// Typed-path `content_hash` check for a [`PublishRequest`].
pub fn verify_typed_publish_request_hash(req: &PublishRequest) -> Result<(), AcdpError> {
    verify_typed_content_hash(&serde_json::to_value(req)?, &req.content_hash)
}

/// Check `expected` against the canonical typed rendering `value`, then
/// against the legacy whole-second rendering of the same content.
pub fn verify_typed_content_hash(value: &Value, expected: &ContentHash) -> Result<(), AcdpError> {
    match verify_content_hash(value, expected) {
        Err(mismatch @ AcdpError::HashMismatch { .. }) => match legacy_rendering(value) {
            Some(legacy) if verify_content_hash(&legacy, expected).is_ok() => Ok(()),
            _ => Err(mismatch),
        },
        other => other,
    }
}

/// The pre-0.15.0 acdp-rs rendering: whole-second producer timestamps
/// without the `.000` fraction. `None` when no timestamp differs.
fn legacy_rendering(value: &Value) -> Option<Value> {
    let mut out = value.clone();
    let mut changed = false;
    for (key, nested) in PRODUCER_TIMESTAMP_PATHS {
        let slot = match nested {
            None => out.get_mut(*key),
            Some(n) => out.get_mut(*key).and_then(|v| v.get_mut(*n)),
        };
        if let Some(Value::String(s)) = slot {
            if let Some(stem) = s.strip_suffix(".000Z") {
                *s = format!("{stem}Z");
                changed = true;
            }
        }
    }
    changed.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_rendering_rewrites_only_whole_second_producer_timestamps() {
        let v = json!({
            "expires_at": "2026-12-31T23:59:59.000Z",
            "data_period": {"start": "2026-01-01T00:00:00.000Z", "end": "2026-03-31T23:59:59.999Z"},
            "created_at": "2026-01-01T00:00:00.000Z",
        });
        let l = legacy_rendering(&v).unwrap();
        assert_eq!(l["expires_at"], "2026-12-31T23:59:59Z");
        assert_eq!(l["data_period"]["start"], "2026-01-01T00:00:00Z");
        assert_eq!(l["data_period"]["end"], "2026-03-31T23:59:59.999Z");
        // created_at is excluded from ProducerContent — left untouched.
        assert_eq!(l["created_at"], "2026-01-01T00:00:00.000Z");
        assert!(legacy_rendering(&json!({"expires_at": "2026-12-31T23:59:59.123Z"})).is_none());
    }
}
