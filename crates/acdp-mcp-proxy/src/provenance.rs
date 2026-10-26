//! The `io.acdp/provenance` `_meta` value (RFC-ACDP-0019 §6–§7).

use acdp::{
    types::{primitives::ContentHash, CtxId},
    AcdpError,
};
use serde_json::{json, Map, Value};

use crate::record::Salt;

/// The `_meta` key the proxy adds to a `CallToolResult`.
pub const META_KEY: &str = "io.acdp/provenance";

/// §6 published value `{ctx_id, content_hash, registry, salt?}`.
/// `registry` is the `ctx_id` authority, which is the body's
/// `origin_registry`.
pub fn published(ctx_id: &CtxId, content_hash: &ContentHash, salt: Option<&Salt>) -> Value {
    let mut v = Map::new();
    v.insert("ctx_id".into(), ctx_id.as_str().into());
    v.insert("content_hash".into(), content_hash.as_str().into());
    v.insert("registry".into(), ctx_id.authority().into());
    if let Some(s) = salt {
        v.insert("salt".into(), s.to_base64url().into());
    }
    Value::Object(v)
}

/// §7 failure value `{failed: true, error?}`.
pub fn failed(error: Option<&str>) -> Value {
    match error {
        Some(code) => json!({ "failed": true, "error": code }),
        None => json!({ "failed": true }),
    }
}

/// Add `value` under [`META_KEY`] unless upstream already set that key,
/// in which case the result is left untouched (§6). Every other member
/// and `_meta` key is kept as is. Returns whether the key was added.
pub fn attach(result: &mut Map<String, Value>, value: Value) -> bool {
    let meta = result
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(meta) = meta else {
        // A non-object `_meta` is upstream's to keep; adding a key would
        // mean replacing it.
        return false;
    };
    if meta.contains_key(META_KEY) {
        return false;
    }
    meta.insert(META_KEY.into(), value);
    true
}

/// §7 fail-closed: the upstream content is withheld and replaced by one
/// text item naming the failure, with the failure value in `_meta`.
pub fn fail_closed_result(tool: &str, failure: Value) -> Map<String, Value> {
    let text = format!(
        "ACDP provenance publishing failed for tool '{tool}'; the result was withheld \
         (RFC-ACDP-0019 §7)."
    );
    let mut meta = Map::new();
    meta.insert(META_KEY.into(), failure);
    let mut out = Map::new();
    out.insert("content".into(), json!([{ "type": "text", "text": text }]));
    out.insert("isError".into(), true.into());
    out.insert("_meta".into(), Value::Object(meta));
    out
}

/// The registry's `error.code` when the registry answered the publish
/// with an ACDP error envelope; `None` for transport failures (refused,
/// timed out, SSRF-refused) and unreadable responses (§7).
pub fn registry_error_code(e: &AcdpError) -> Option<String> {
    use AcdpError as E;
    let code = match e {
        E::Registry(w) => {
            return (w.error.code != "unknown").then(|| w.error.code.clone());
        }
        // Locally raised SchemaViolations: SSRF refusals and a success
        // body that does not parse as a publish response.
        E::SchemaViolation(m)
            if e.is_ssrf_policy_refusal() || m.starts_with("malformed registry response") =>
        {
            return None;
        }
        E::InvalidSignature(_) => "invalid_signature",
        E::RemoteHashMismatch(_) => "hash_mismatch",
        E::DataRefHashMismatch(_) => "data_ref_hash_mismatch",
        E::SchemaViolation(_) => "schema_violation",
        E::NotAuthorized(_) => "not_authorized",
        E::NotFound(_) => "not_found",
        E::RateLimited(_) => "rate_limited",
        E::PayloadTooLarge(_) => "payload_too_large",
        E::EmbeddedTooLarge(_) => "embedded_too_large",
        E::KeyResolution(_) => "key_resolution_failed",
        E::KeyResolutionUnreachable(_) => "key_resolution_unreachable",
        E::KeyNotAuthorized(_) => "key_not_authorized",
        E::UnsupportedAlgorithm(_) => "unsupported_algorithm",
        E::UnsupportedMediaType(_) => "unsupported_media_type",
        E::NotImplemented(_) => "not_implemented",
        E::CursorExpired => "cursor_expired",
        E::InvalidCursor(_) => "invalid_cursor",
        E::DuplicatePublish(_) => "duplicate_publish",
        E::CrossRegistryResolutionFailed(_) => "cross_registry_resolution_failed",
        E::InvalidReceipt(_) => "invalid_receipt",
        E::InvalidLogProof(_) => "invalid_log_proof",
        E::InvalidWitnessCosignature(_) => "invalid_witness_cosignature",
        E::ImmutableField(_) => "immutable_field",
        E::InvalidLifecycleTransition(_) => "invalid_lifecycle_transition",
        E::RegistryInternal(_) => "internal_error",
        E::SupersededTarget { .. } => "superseded_target",
        _ => return None,
    };
    Some(code.to_owned())
}
